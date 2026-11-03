import io
import json
import os
import re
import struct
import tempfile
import unittest

from threatkill import binfmt, outputs
from threatkill import ranges as R
from threatkill.config import CATEGORIES, FLAGS, ConfigError, load_feeds, parse_feeds
from threatkill.fetch import FetchResult
from threatkill.filters import AddressFilter, load_allowlist
from threatkill.parse import ParsedFeed, parse_entry, parse_feed
from threatkill.pipeline import build, write_outputs
from threatkill.reconcile import MAX_STALE_RUNS, Decision, check_run, decide

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IP = lambda text: int(__import__("ipaddress").ip_address(text))  # noqa: E731
def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


GENERIC = r"^(?![#;/])([0-9a-fA-F:.]+(?:/\d+)?)"


def feed_entry(**overrides):
    entry = {
        "name": "test_feed",
        "url": "https://example.com/list.txt",
        "regex": GENERIC,
        "categories": ["attacks"],
        "flags": ["is_scanner"],
        "base_score": 0.9,
        "confidence": 0.8,
    }
    entry.update(overrides)
    return entry


class RangeTests(unittest.TestCase):
    def test_merge_overlapping_and_adjacent(self):
        self.assertEqual(R.merge([(5, 9), (1, 3), (4, 4), (20, 30), (25, 26)]), [(1, 9), (20, 30)])

    def test_subtract(self):
        self.assertEqual(R.subtract([(0, 100)], [(10, 20), (50, 60)]), [(0, 9), (21, 49), (61, 100)])
        self.assertEqual(R.subtract([(10, 20)], [(0, 100)]), [])
        self.assertEqual(R.subtract([(0, 5), (10, 15)], [(3, 12)]), [(0, 2), (13, 15)])
        self.assertEqual(R.subtract([(0, 5)], []), [(0, 5)])

    def test_intersect(self):
        self.assertEqual(R.intersect([(0, 10), (20, 30)], [(5, 25)]), [(5, 10), (20, 25)])

    def test_to_cidrs_per_family(self):
        self.assertEqual(R.to_cidrs([(IP("1.2.3.0"), IP("1.2.3.255"))], R.V4), ["1.2.3.0/24"])
        # a small integer must stay IPv6 when the family says so
        self.assertEqual(R.to_cidrs([(1, 1)], R.V6), ["::1/128"])


class ParseTests(unittest.TestCase):
    def test_entries(self):
        self.assertEqual(parse_entry("1.2.3.4"), (4, IP("1.2.3.4"), IP("1.2.3.4")))
        self.assertEqual(parse_entry("1.2.3.4/24"), (4, IP("1.2.3.0"), IP("1.2.3.255")))
        self.assertEqual(parse_entry("1.2.3.4 - 1.2.3.9"), (4, IP("1.2.3.4"), IP("1.2.3.9")))
        self.assertEqual(parse_entry("2001:db8::1")[0], 6)
        self.assertEqual(parse_entry("::ffff:8.8.8.8"), (4, IP("8.8.8.8"), IP("8.8.8.8")))
        self.assertIsNone(parse_entry("1.2.3.9-1.2.3.4"))
        self.assertIsNone(parse_entry("1.2.3.4-::1"))
        self.assertIsNone(parse_entry("deadbeef"))
        self.assertIsNone(parse_entry("1.2.3"))

    def test_feed_rejects_broad_and_invalid(self):
        lines = ["# comment", "8.8.8.8", "0.0.0.0/1", "not-an-ip", "2a00::/8", "9.9.9.0/24", "2a00:1450::1"]
        parsed = parse_feed(lines, re.compile(r"^(?!#)(\S+)"))
        self.assertEqual(parsed.too_broad, 2)
        self.assertEqual(parsed.invalid, 1)
        self.assertEqual(len(parsed.v4), 2)
        self.assertEqual(len(parsed.v6), 1)

    def test_alternation_groups(self):
        parsed = parse_feed(['"1.1.1.1:443"', "[2a00:1450::5]:80"], re.compile(r'"([\d.]+):\d+"|\[([0-9a-f:]+)\]'))
        self.assertEqual((len(parsed.v4), len(parsed.v6)), (1, 1))


class FilterTests(unittest.TestCase):
    def test_bogons_removed(self):
        f = AddressFilter()
        v4 = R.merge([(IP("10.0.0.0"), IP("10.255.255.255")), (IP("127.0.0.1"), IP("127.0.0.1")),
                      (IP("8.8.8.8"), IP("8.8.8.8")), (IP("224.0.0.0"), IP("255.255.255.255"))])
        self.assertEqual(f.apply(R.V4, v4), [(IP("8.8.8.8"), IP("8.8.8.8"))])
        v6 = R.merge([(IP("::1"), IP("::1")), (IP("fe80::1"), IP("fe80::1")),
                      (IP("2001:db8::1"), IP("2001:db8::1")), (IP("2a00:1450::1"), IP("2a00:1450::1"))])
        self.assertEqual(f.apply(R.V6, v6), [(IP("2a00:1450::1"), IP("2a00:1450::1"))])

    def test_partial_overlap_is_trimmed(self):
        f = AddressFilter()
        self.assertEqual(
            R.to_cidrs(f.apply(R.V4, [(IP("172.15.255.0"), IP("172.16.0.255"))]), R.V4),
            ["172.15.255.0/24"],
        )

    def test_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "allow.txt")
            with open(path, "w") as fh:
                fh.write("# office\n203.0.114.0/24  # vpn\n2a00:1450::/32\n")
            allow = load_allowlist(path)
            f = AddressFilter(allow)
            self.assertEqual(f.apply(R.V4, [(IP("203.0.114.5"), IP("203.0.114.5"))]), [])
            self.assertEqual(f.apply(R.V6, [(IP("2a00:1450::1"), IP("2a00:1450::1"))]), [])
            with open(path, "w") as fh:
                fh.write("bogus\n")
            with self.assertRaises(ValueError):
                load_allowlist(path)
        self.assertEqual(load_allowlist("/nonexistent/allow.txt"), {R.V4: [], R.V6: []})


class BinaryFormatTests(unittest.TestCase):
    def test_roundtrip_v2(self):
        record = binfmt.FeedRecord(
            name="x", v4=[(1, 1), (IP("8.8.8.0"), IP("8.8.8.255"))], v6=[(1, 1), (IP("2a00::"), IP("2a00::ff"))],
            base_score=0.95, confidence=0.5, categories=("attacks", "spam"), flags=("is_tor",),
        )
        ts, feeds = binfmt.loads(binfmt.dumps(1234567890123, [record], CATEGORIES, FLAGS))
        self.assertEqual(ts, 1234567890123)
        self.assertEqual(feeds["x"], record)

    def test_reads_v1(self):
        out = io.BytesIO()
        out.write(struct.pack("<IH", 1700000000, 1))
        out.write(bytes([3]) + b"old")
        mixed = [(IP("1.0.0.1"), IP("1.0.0.1")), (IP("2a00::1"), IP("2a00::1"))]
        binfmt._write_ranges(out, mixed)
        ts, feeds = binfmt.loads(out.getvalue())
        self.assertEqual(ts, 1700000000)
        self.assertEqual(feeds["old"].v4, [mixed[0]])
        self.assertEqual(feeds["old"].v6, [mixed[1]])


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.previous = binfmt.FeedRecord("f", v4=[(i * 10, i * 10) for i in range(100)])

    def fresh(self, n):
        return ParsedFeed(v4=[(i * 10, i * 10) for i in range(n)])

    def test_ok(self):
        self.assertEqual(decide(self.fresh(90), None, self.previous, {}).status, "ok")

    def test_failed_download_reuses_previous(self):
        d = decide(None, "HTTPError 410", self.previous, {"stale_runs": 2})
        self.assertEqual((d.status, d.stale_runs, len(d.v4)), ("stale", 3, 100))

    def test_gives_up_after_max_stale_runs(self):
        d = decide(None, "timeout", self.previous, {"stale_runs": MAX_STALE_RUNS})
        self.assertEqual((d.status, d.entries), ("failed", 0))

    def test_shrink_then_accept(self):
        self.assertEqual(decide(self.fresh(10), None, self.previous, {}).status, "stale")
        self.assertEqual(decide(self.fresh(10), None, self.previous, {"stale_runs": 2}).status, "ok")

    def test_no_previous(self):
        self.assertEqual(decide(None, "boom", None, {}).status, "failed")

    def test_check_run(self):
        decisions = {f"f{i}": Decision([], [], "failed" if i < 3 else "ok") for i in range(10)}
        self.assertTrue(check_run(decisions, {}, {}))
        ok = {f"f{i}": Decision([], [], "ok") for i in range(10)}
        prev = {"categories": {"attacks": {"entries_v4": 1000, "entries_v6": 0}}}
        self.assertTrue(check_run(ok, {"attacks": {"entries_v4": 300, "entries_v6": 0}}, prev))
        self.assertFalse(check_run(ok, {"attacks": {"entries_v4": 900, "entries_v6": 0}}, prev))
        self.assertFalse(check_run(ok, {"attacks": {"entries_v4": 300, "entries_v6": 0}}, {}))


class ConfigTests(unittest.TestCase):
    def test_repository_feeds_are_valid(self):
        self.assertTrue(load_feeds(os.path.join(ROOT, "feeds.json")))

    def test_rejections(self):
        bad = [
            feed_entry(url="http://example.com"),
            feed_entry(regex="(unclosed"),
            feed_entry(regex="no-group"),
            feed_entry(categories=[]),
            feed_entry(categories=["nope"]),
            feed_entry(flags=["is_nope"]),
            feed_entry(base_score=2),
            feed_entry(name="Bad Name"),
            feed_entry(typo_key=1),
        ]
        for entry in bad:
            with self.assertRaises(ConfigError, msg=entry):
                parse_feeds([entry])
        with self.assertRaises(ConfigError):
            parse_feeds([feed_entry(), feed_entry()])
        self.assertEqual(len(parse_feeds([feed_entry(url="http://x", allow_http=True)])), 1)


class OutputTests(unittest.TestCase):
    def test_restore_and_nft(self):
        with tempfile.TemporaryDirectory() as tmp:
            restore = os.path.join(tmp, "a.restore")
            outputs.write_ipset_restore(restore, "infrastructure", ["1.2.3.0/24"], ["2a00::/32"])
            text = _read(restore).splitlines()
            self.assertIn("add tk_infrastructure_v4_new 1.2.3.0/24", text)
            self.assertIn("swap tk_infrastructure_v6_new tk_infrastructure_v6", text)
            self.assertTrue(all(len(line.split()[1]) <= 31 for line in text))
            nft = os.path.join(tmp, "a.nft")
            outputs.write_nft(nft, "attacks", ["1.2.3.0/24", "5.6.7.8/32"], [], 0)
            body = _read(nft)
            self.assertIn("add element inet threatkill attacks_v4 { 1.2.3.0/24, 5.6.7.8/32 }", body)
            self.assertIn("type ipv6_addr", body)
            self.assertNotIn("add element inet threatkill attacks_v6", body)


class PipelineTests(unittest.TestCase):
    def test_end_to_end(self):
        feeds = parse_feeds([
            feed_entry(name="good", categories=["attacks"]),
            feed_entry(name="down", categories=["attacks", "spam"]),
        ])
        fetched = {
            "good": FetchResult(lines=["8.8.8.8", "10.1.2.3", "2a00:1450::1", "0.0.0.0/1"]),
            "down": FetchResult(error="HTTPError: 503"),
        }
        previous = {"down": binfmt.FeedRecord("down", v4=[(IP("9.9.9.9"), IP("9.9.9.9")), (IP("127.0.0.1"), IP("127.0.0.1"))])}
        records, report, categories, stats, problems = build(feeds, fetched, previous, {}, AddressFilter(), 0)
        self.assertEqual(report["good"]["status"], "ok")
        self.assertEqual(report["good"]["too_broad"], 1)
        self.assertEqual(report["down"]["status"], "stale")
        self.assertEqual(categories["attacks"][2], ["8.8.8.8/32", "9.9.9.9/32"])
        self.assertEqual(categories["attacks"][3], ["2a00:1450::1/128"])
        self.assertEqual(categories["spam"][2], ["9.9.9.9/32"])
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_outputs(tmp, 1700000000, records, report, categories, stats)
            self.assertEqual(manifest["summary"], {"feeds": 2, "ok": 1, "stale": 1, "failed": 0})
            on_disk = json.loads(_read(os.path.join(tmp, "manifest.json")))
            self.assertEqual(on_disk["content_hash"], manifest["content_hash"])
            self.assertIn("attacks.nft", on_disk["files"])
            _, decoded = binfmt.read(os.path.join(tmp, "blocklist.bin"))
            self.assertEqual(decoded["good"].categories, ("attacks",))


if __name__ == "__main__":
    unittest.main()
