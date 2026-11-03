"""End-to-end run: fetch → parse → reconcile → filter → validate → write."""

import argparse
import hashlib
import json
import os
import sys
import time

from . import binfmt, outputs
from . import ranges as R
from .config import CATEGORIES, FLAGS, ConfigError, load_feeds
from .fetch import fetch_all
from .filters import AddressFilter, load_allowlist
from .parse import parse_feed
from .reconcile import UPSTREAM_STALE_DAYS, category_stats, check_run, decide

MANIFEST_VERSION = 1


def load_previous(directory):
    """Return ``(feeds_by_name, manifest)`` from a previous release, if present."""
    feeds, manifest = {}, {}
    if not directory:
        return feeds, manifest
    bin_path = os.path.join(directory, "blocklist.bin")
    if os.path.exists(bin_path):
        try:
            _, feeds = binfmt.read(bin_path)
        except (ValueError, IndexError, OSError) as exc:  # corrupt or truncated file
            print(f"warning: ignoring unreadable {bin_path}: {exc}")
    manifest_path = os.path.join(directory, "manifest.json")
    if os.path.exists(manifest_path):
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    return feeds, manifest


def build(feeds, fetched, previous_feeds, previous_manifest, address_filter, now):
    """Pure processing step; returns everything the writers need."""
    previous_state = previous_manifest.get("feeds", {})
    decisions, records, feed_report = {}, [], {}

    for feed in feeds:
        result = fetched[feed.name]
        parsed = parse_feed(result.lines, feed.regex) if result.ok else None
        if parsed is not None:
            parsed.v4 = address_filter.apply(R.V4, parsed.v4)
            parsed.v6 = address_filter.apply(R.V6, parsed.v6)
        previous = previous_feeds.get(feed.name)
        if previous is not None:  # previous data predates the current filters
            previous.v4 = address_filter.apply(R.V4, R.merge(previous.v4))
            previous.v6 = address_filter.apply(R.V6, R.merge(previous.v6))
        decision = decide(parsed, result.error, previous, previous_state.get(feed.name, {}))
        decisions[feed.name] = decision

        records.append(
            binfmt.FeedRecord(
                name=feed.name,
                v4=decision.v4,
                v6=decision.v6,
                base_score=feed.base_score,
                confidence=feed.confidence,
                categories=feed.categories,
                flags=feed.flags,
            )
        )
        report = {
            "status": decision.status,
            "ranges_v4": len(decision.v4),
            "ranges_v6": len(decision.v6),
            "addresses_v4": R.address_count(decision.v4),
            "stale_runs": decision.stale_runs,
        }
        if decision.reason:
            report["reason"] = decision.reason
        if parsed is not None:
            report["invalid"] = parsed.invalid
            report["too_broad"] = parsed.too_broad
        if result.last_modified:
            age = (now - result.last_modified) / 86400
            report["upstream_modified"] = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(result.last_modified)
            )
            if age > UPSTREAM_STALE_DAYS:
                report["upstream_stale_days"] = int(age)
        feed_report[feed.name] = report

    categories = {}
    for category in CATEGORIES:
        members = [r for r in records if category in r.categories]
        if not members:
            continue
        v4 = R.merge([rng for r in members for rng in r.v4])
        v6 = R.merge([rng for r in members for rng in r.v6])
        categories[category] = (v4, v6, R.to_cidrs(v4, R.V4), R.to_cidrs(v6, R.V6))

    stats = {name: category_stats(c4, c6, v4) for name, (v4, _, c4, c6) in categories.items()}
    problems = check_run(decisions, stats, previous_manifest)
    return records, feed_report, categories, stats, problems


def content_hash(records):
    """Hash of the published data, independent of the generation timestamp."""
    return hashlib.sha256(binfmt.dumps(0, records, CATEGORIES, FLAGS)).hexdigest()


def write_outputs(out_dir, timestamp, records, feed_report, categories, stats):
    os.makedirs(out_dir, exist_ok=True)
    binfmt.write(os.path.join(out_dir, "blocklist.bin"), timestamp, records, CATEGORIES, FLAGS)
    for name, (_, _, cidrs_v4, cidrs_v6) in categories.items():
        base = os.path.join(out_dir, name)
        outputs.write_list(f"{base}.ipset", name, cidrs_v4 + cidrs_v6, timestamp)
        outputs.write_list(f"{base}.v4.ipset", name, cidrs_v4, timestamp, "IPv4")
        outputs.write_list(f"{base}.v6.ipset", name, cidrs_v6, timestamp, "IPv6")
        outputs.write_ipset_restore(f"{base}.restore", name, cidrs_v4, cidrs_v6)
        outputs.write_nft(f"{base}.nft", name, cidrs_v4, cidrs_v6, timestamp)

    files = {}
    for filename in sorted(os.listdir(out_dir)):
        if filename == "manifest.json":
            continue
        with open(os.path.join(out_dir, filename), "rb") as fh:
            data = fh.read()
        files[filename] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "binary_format_version": binfmt.VERSION,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)),
        "timestamp": timestamp,
        "content_hash": content_hash(records),
        "summary": {
            "feeds": len(feed_report),
            "ok": sum(r["status"] == "ok" for r in feed_report.values()),
            "stale": sum(r["status"] == "stale" for r in feed_report.values()),
            "failed": sum(r["status"] == "failed" for r in feed_report.values()),
        },
        "categories": stats,
        "feeds": feed_report,
        "files": files,
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return manifest


def run(args):
    try:
        feeds = load_feeds(args.feeds)
        allowlist = load_allowlist(args.allowlist)
    except (ConfigError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    previous_feeds, previous_manifest = load_previous(args.previous)
    print(f"Downloading {len(feeds)} feeds...")
    fetched = fetch_all(feeds, workers=args.workers)

    now = time.time()
    records, feed_report, categories, stats, problems = build(
        feeds, fetched, previous_feeds, previous_manifest, AddressFilter(allowlist), now
    )

    for name, report in feed_report.items():
        line = f"  {report['status']:6} {name}: {report['ranges_v4']} v4 / {report['ranges_v6']} v6 ranges"
        if "reason" in report:
            line += f" ({report['reason']})"
        if "upstream_stale_days" in report:
            line += f" [upstream not modified for {report['upstream_stale_days']} days]"
        print(line)
    for name, s in stats.items():
        print(f"  category {name}: {s['entries_v4']} v4 + {s['entries_v6']} v6 entries")

    if problems and not args.force:
        print("Refusing to publish:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print("Re-run with --force to publish anyway.", file=sys.stderr)
        return 2

    manifest = write_outputs(args.out, int(now), records, feed_report, categories, stats)
    s = manifest["summary"]
    print(f"Wrote {args.out}/ — {s['ok']} ok, {s['stale']} stale, {s['failed']} failed feeds")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Aggregate IP threat feeds into blocklists.")
    parser.add_argument("--feeds", default="feeds.json")
    parser.add_argument("--allowlist", default="allowlist.txt")
    parser.add_argument("--previous", help="directory holding the last release's blocklist.bin and manifest.json")
    parser.add_argument("--out", default="data")
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--force", action="store_true", help="publish even if validation fails")
    return run(parser.parse_args(argv))
