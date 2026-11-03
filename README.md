```
 _____ _                    _    _  _ _
|_   _| |_  _ _ ___ __ _  | | _(_)| | |
  | | | ' \| '_/ -_) _` | | |/ / || | |
  |_| |_||_|_| \___\__,_| |_/\_\_||_|_|
```

> Block malicious traffic at the source — 89 maintained feeds, 7 threat categories, updated daily.

---

## What is this?

**Threatkill** is an automated IP threat intelligence aggregator. Every day it pulls from open-source security feeds, validates and deduplicates the data, strips addresses that must never be blocked, and publishes ready-to-use firewall lists alongside a compact binary database.

No vendor lock-in. No API keys. Drop the files into your firewall and go.

---

## Downloads

Everything is published as assets of the latest [GitHub release](https://github.com/kboykov/Threatkill/releases/latest). Generated data is no longer committed to the repository, so old `raw.githubusercontent.com/.../master/data/...` links no longer work. Use the release URLs below.

| Asset | Format | Use case |
|---|---|---|
| `<category>.restore` | `ipset restore` script | Linux ipset/iptables: atomic reload of IPv4 and IPv6 sets |
| `<category>.nft` | `nft -f` script | nftables: atomic reload of IPv4 and IPv6 sets |
| `<category>.v4.ipset` / `.v6.ipset` | Plain CIDR list, one family | Firewalls that take a URL list (FortiGate, pfSense, OPNsense, MikroTik…) |
| `<category>.ipset` | Plain CIDR list, IPv4 + IPv6 | Backwards-compatible combined list |
| `blocklist.bin` | Binary (delta-encoded, per feed) | Programmatic lookups and scoring |
| `manifest.json` | JSON | Per-feed status, category totals, SHA-256 of every file |

Categories:

| Category | Contents | Example feeds |
|---|---|---|
| `attacks` | Scanners, brute-force, web attackers | AbuseIPDB, DShield, FireHOL L1/L2, blocklist.de, CINS |
| `malware` | Malware C2, exploit hosts, phishing | Feodo Tracker, ThreatFox, HaGeZi TIF |
| `botnet` | Botnet command & control | cybercrime-tracker, curbengh botnet, Threatview C2 |
| `anonymizer` | Tor nodes, VPN servers, open proxies | Tor Project, NordVPN, Mullvad, ProtonVPN, proxy lists |
| `spam` | Spam networks and forum abusers | Spamhaus DROP/DROPv6, StopForumSpam, sblam |
| `compromised` | Compromised and hijacked hosts | Emerging Threats compromised |
| `infrastructure` | Datacenters, CDNs, cloud providers | AWS, GCP, Cloudflare, DigitalOcean |

> `infrastructure` and `anonymizer` are context, not verdicts. Together they cover hundreds of millions of addresses, including the clouds and CDNs your own users and services depend on. Use them for scoring or for specific services (e.g. admin panels), not as a global inbound drop.

```bash
BASE=https://github.com/kboykov/Threatkill/releases/latest/download
curl -fsSLO $BASE/attacks.restore
curl -fsSLO $BASE/manifest.json
```

---

## Quick Start

### Linux — ipset / iptables

`ipset -exist restore` builds a fresh set next to the live one and swaps them atomically, so the firewall never sees a half-loaded or empty list. It loads hundreds of thousands of entries in seconds, unlike a per-entry `ipset add` loop.

```bash
apt-get install ipset

curl -fsSLo /tmp/attacks.restore \
  https://github.com/kboykov/Threatkill/releases/latest/download/attacks.restore \
  && ipset -exist restore < /tmp/attacks.restore

# Sets are named tk_<category>_v4 and tk_<category>_v6
iptables  -I INPUT -m set --match-set tk_attacks_v4 src -j DROP
ip6tables -I INPUT -m set --match-set tk_attacks_v6 src -j DROP
```

If the download fails, `&&` skips the restore and the previous set stays in place. Re-run the same two commands from cron to refresh.

### nftables

Each `.nft` file creates (if needed) and refills `<category>_v4` and `<category>_v6` sets in table `inet threatkill`, in a single transaction.

```bash
curl -fsSLo /tmp/attacks.nft \
  https://github.com/kboykov/Threatkill/releases/latest/download/attacks.nft \
  && nft -f /tmp/attacks.nft
```

Then reference the sets from your ruleset (only once):

```bash
nft add chain inet threatkill input '{ type filter hook input priority -10; policy accept; }'
nft add rule inet threatkill input ip  saddr @attacks_v4 drop
nft add rule inet threatkill input ip6 saddr @attacks_v6 drop
```

### Python — binary database

The reader in [`threatkill/binfmt.py`](threatkill/binfmt.py) has no dependencies:

```python
import bisect, ipaddress
from threatkill.binfmt import read

timestamp, feeds = read("blocklist.bin")

def lookup(ip):
    addr = ipaddress.ip_address(ip)
    n, hits = int(addr), []
    for feed in feeds.values():
        ranges = feed.v4 if addr.version == 4 else feed.v6
        i = bisect.bisect_right(ranges, (n, float("inf"))) - 1
        if i >= 0 and ranges[i][0] <= n <= ranges[i][1]:
            hits.append((feed.name, feed.base_score, feed.categories))
    return hits

print(lookup("1.0.68.149"))
```

---

## Safety

Every run goes through these checks before anything is published:

- **Never-block filter.** Private, loopback, link-local, CGNAT, multicast, reserved and documentation ranges (RFC 1918/6598/6890 etc.) are removed from every feed. For IPv6 only global unicast (`2000::/3`) is kept. Add your own addresses to [`allowlist.txt`](allowlist.txt) to exclude them from all outputs.
- **Breadth limit.** A single upstream entry wider than IPv4 `/8` or IPv6 `/16` is discarded as an error.
- **Per-feed fallback.** If a feed fails to download, returns nothing, or shrinks by more than half overnight, the previous release's data for that feed is reused. Empty or failed feeds fall back for up to 7 runs. Sudden shrinkage is accepted after 2 consecutive runs, in case it's genuine. The status is recorded in `manifest.json` and the release notes.
- **Run-level guard.** The run fails without publishing if more than 25% of feeds fail, or if any category drops below 40% or grows past 300% of its previous size. A maintainer can override this with the `force` input of the workflow.
- **No-op releases are skipped.** A release is only created when the data actually changed.

---

## Feed Configuration

Sources are defined in [`feeds.json`](feeds.json) and validated on every run:

```json
{
    "name": "abuseipdb_s100",
    "url": "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-120d.ipv4",
    "description": "AbuseIPDB 100% confidence abusers (120 days)",
    "regex": "^(?![#;/])([0-9a-fA-F:.]+(?:/\\d+)?)",
    "base_score": 0.95,
    "confidence": 1.0,
    "flags": ["is_scanner"],
    "categories": ["attacks"]
}
```

| Field | Type | Description |
|---|---|---|
| `name` | string | Unique identifier, `[a-z0-9_]` |
| `url` | string | Source URL; must be `https://` unless `"allow_http": true` |
| `regex` | string | Pattern with at least one capture group; the first non-empty group is the IP/CIDR/range |
| `base_score` | float 0–1 | Threat severity weight (stored in `blocklist.bin`) |
| `confidence` | float 0–1 | Source reliability (stored in `blocklist.bin`) |
| `flags` | string[] | Threat type indicators (stored in `blocklist.bin`) |
| `categories` | string[] | Required; which category outputs receive this feed |
| `provider_name` | string | Optional, for VPN provider lists |

Feeds whose upstream stopped updating are removed. The 2026-11 audit dropped 39 sources: dead endpoints (URLhaus now requires an API key, C2-Tracker is archived), hpHosts (frozen since 2019), and lists not refreshed in over a year. Upstreams that send a `Last-Modified` header older than 180 days are flagged in each release's notes.

---

## How It Works

```
feeds.json ──► fetch (10 workers, retries) ──► parse (regex → IPv4 / IPv6 ranges)
                                                   │
                                                   ▼
                                    never-block filter + allowlist
                                                   │
                                previous release ──►  per-feed fallback
                                                   │
                                                   ▼
                                     merge per category ──► run-level guard
                                                   │
           ┌───────────────┬───────────────┬───────┴───────┬──────────────┐
           ▼               ▼               ▼               ▼              ▼
     blocklist.bin   <cat>.restore     <cat>.nft    <cat>[.v4|.v6].ipset  manifest.json
```

Run it locally with only the Python standard library (3.10+):

```bash
python aggregator.py --previous path/to/last-release --out data
python -m unittest discover -s tests -t .
```

### Binary Format (version 2)

```
[4 bytes] "TKBL" magic
[u8]      format version (2)
[u64 LE]  Unix timestamp
[u8]      category count, then per category: [u8 len][UTF-8 name]
[u8]      flag count,     then per flag:     [u8 len][UTF-8 name]
[u16 LE]  feed count
  per feed:
    [u8 len][UTF-8 name]
    [u8]      base_score × 100
    [u8]      confidence × 100
    [u64 LE]  category bitmask
    [u64 LE]  flag bitmask
    [u32 LE]  IPv4 range count, then per range: [varint start − previous start][varint end − start]
    [u32 LE]  IPv6 range count, same encoding
```

IPv4 and IPv6 are stored separately, so a lookup can't confuse `::5` with `0.0.0.5`. Files without the magic are version 1 (released before November 2026) and are still readable by `threatkill.binfmt.read`.

---

## Stats

Current numbers for every category and feed are in each release's `manifest.json` and release notes. As of November 2026:

| Metric | Value |
|---|---|
| Feeds | 89 |
| CIDR entries (all categories) | ~3.6M |
| `blocklist.bin` size | ~14 MB |
| Update frequency | Daily (scheduled at 00:00 UTC; GitHub often starts it a few hours later) |

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
