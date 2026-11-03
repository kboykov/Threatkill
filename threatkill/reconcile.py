"""Decide, per feed and per category, whether fresh data is trustworthy.

A feed that fails to download, comes back empty or suddenly shrinks keeps
the previous run's data for a limited number of runs instead of silently
disappearing from every output. Category totals are then compared with the
previous manifest so a broken run fails before anything is published.
"""

from dataclasses import dataclass

from . import ranges as R

# Feed level
MAX_STALE_RUNS = 7  # reuse previous data for a failed/empty feed this many runs
SHRINK_RATIO = 0.5  # fresh data smaller than this share of the previous run is suspicious
SHRINK_GRACE_RUNS = 2  # after this many suspicious runs in a row, accept the smaller list
SHRINK_MIN_ENTRIES = 50  # ignore shrinkage on tiny feeds
# Upstreams whose Last-Modified header is older than this are reported as stale
UPSTREAM_STALE_DAYS = 180

# Category level (guards against a broken run reaching consumers)
CATEGORY_MIN_RATIO = 0.4  # fail if a category keeps less than 40% of its entries
CATEGORY_MAX_RATIO = 3.0  # fail if a category more than triples
CATEGORY_MIN_ENTRIES = 100
MAX_FAILED_FEED_SHARE = 0.25  # fail if more than a quarter of the feeds produced nothing


@dataclass
class Decision:
    v4: list
    v6: list
    status: str  # ok | stale | failed
    reason: str = ""
    stale_runs: int = 0

    @property
    def entries(self):
        return len(self.v4) + len(self.v6)


def decide(fresh, error, previous, previous_state):
    """Choose the data to publish for one feed.

    ``fresh`` is a ``ParsedFeed`` (or None when the download failed), ``previous``
    the feed's ranges from the last release (or None) and ``previous_state`` its
    entry from the last manifest (or {}).
    """
    stale_runs = int(previous_state.get("stale_runs", 0))
    prev_entries = len(previous.v4) + len(previous.v6) if previous else 0

    if fresh is None or fresh.entries == 0:
        reason = error or "no valid entries"
        if prev_entries and stale_runs < MAX_STALE_RUNS:
            return Decision(previous.v4, previous.v6, "stale", reason, stale_runs + 1)
        return Decision([], [], "failed", reason, stale_runs + 1)

    if (
        prev_entries >= SHRINK_MIN_ENTRIES
        and fresh.entries < prev_entries * SHRINK_RATIO
        and stale_runs < SHRINK_GRACE_RUNS
    ):
        reason = f"shrank from {prev_entries} to {fresh.entries} entries"
        return Decision(previous.v4, previous.v6, "stale", reason, stale_runs + 1)

    return Decision(fresh.v4, fresh.v6, "ok")


def category_stats(cidrs_v4, cidrs_v6, ranges_v4):
    return {
        "entries_v4": len(cidrs_v4),
        "entries_v6": len(cidrs_v6),
        "addresses_v4": R.address_count(ranges_v4),
    }


def check_run(decisions, categories, previous_manifest):
    """Return a list of problems that should stop publication."""
    problems = []
    failed = [name for name, d in decisions.items() if d.status == "failed"]
    if decisions and len(failed) / len(decisions) > MAX_FAILED_FEED_SHARE:
        problems.append(f"{len(failed)} of {len(decisions)} feeds failed: {', '.join(sorted(failed))}")

    previous = (previous_manifest or {}).get("categories", {})
    for name, stats in categories.items():
        before = previous.get(name)
        if not before:
            continue
        old = before.get("entries_v4", 0) + before.get("entries_v6", 0)
        new = stats["entries_v4"] + stats["entries_v6"]
        if old < CATEGORY_MIN_ENTRIES:
            continue
        ratio = new / old
        if ratio < CATEGORY_MIN_RATIO or ratio > CATEGORY_MAX_RATIO:
            problems.append(f"category {name} changed from {old} to {new} entries ({ratio:.0%})")
    return problems
