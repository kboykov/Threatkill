```
 _____ _                    _    _  _ _
|_   _| |_  _ _ ___ __ _  | | _(_)| | |
  | | | ' \| '_/ -_) _` | | |/ / || | |
  |_| |_||_|_| \___\__,_| |_/\_\_||_|_|
```

> Block malicious traffic at the source — 128 feeds, 7 threat categories, updated daily.

---

## What is this?

**Threatkill** is an automated IP threat intelligence aggregator. Every day it pulls from 128 open-source security feeds, deduplicates and merges the data, and publishes ready-to-use firewall lists alongside a compact binary database.

No vendor lock-in. No API keys. Drop the files into your firewall and go.

---

## Downloads

Each release contains the full binary database and one ipset file per threat category.

| Asset | Format | Use case |
|---|---|---|
| `blocklist.bin` | Binary (delta-encoded) | Programmatic lookups, scoring |
| `attacks.ipset` | Plain CIDR list | Scanners, brute-force, web attacks |
| `malware.ipset` | Plain CIDR list | C2 servers, exploit hosts, phishing |
| `botnet.ipset` | Plain CIDR list | Botnet command & control nodes |
| `anonymizer.ipset` | Plain CIDR list | Tor, VPNs, open proxies |
| `spam.ipset` | Plain CIDR list | Spam networks, forum abusers |
| `compromised.ipset` | Plain CIDR list | Hijacked/compromised hosts |
| `infrastructure.ipset` | Plain CIDR list | Datacenters, CDNs, cloud ranges |

```bash
# Always points to the latest release
BASE=https://github.com/kboykov/Threatkill/releases/latest/download

wget $BASE/attacks.ipset
wget $BASE/malware.ipset
wget $BASE/blocklist.bin
```

---

## Quick Start

### Linux — ipset / iptables

```bash
# Install ipset if needed
apt-get install ipset

# Create a set and load a category
ipset create threatkill_attacks hash:net maxelem 1000000
awk '!/^#/' attacks.ipset | while read cidr; do
  ipset add threatkill_attacks "$cidr" 2>/dev/null
done

# Drop inbound traffic from known attackers
iptables -I INPUT -m set --match-set threatkill_attacks src -j DROP
```

### nftables

```nft
table inet threatkill {
  set attacks {
    type ipv4_addr
    flags interval
    auto-merge
  }

  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr @attacks drop
  }
}
```

```bash
# Populate the set
awk '!/^#/' attacks.ipset | sed 's/^/add element inet threatkill attacks { /' \
  | sed 's/$/ }/' | nft -f -
```

### Python — binary database

```python
import struct, ipaddress

def read_varint(f):
    result = shift = 0
    while True:
        byte = f.read(1)[0]
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result
        shift += 7

def load_blocklist(path="blocklist.bin"):
    feeds = {}
    with open(path, "rb") as f:
        timestamp = struct.unpack("<I", f.read(4))[0]
        for _ in range(struct.unpack("<H", f.read(2))[0]):
            name = f.read(struct.unpack("<B", f.read(1))[0]).decode()
            ranges, cur = [], 0
            for _ in range(struct.unpack("<I", f.read(4))[0]):
                cur += read_varint(f)
                ranges.append((cur, cur + read_varint(f)))
            feeds[name] = ranges
    return feeds, timestamp

def lookup(feeds, ip):
    n = int(ipaddress.ip_address(ip))
    return [name for name, ranges in feeds.items()
            if any(s <= n <= e for s, e in ranges)]

feeds, ts = load_blocklist()
print(lookup(feeds, "1.0.68.149"))
# ['abuseipdb_s100', 'firehol_level1', ...]
```

---

## Threat Categories

Feeds are tagged with categories and flags in `feeds.json`. The aggregator uses the `categories` field to group IPs into separate ipset outputs.

| Category | Flags included | Example feeds |
|---|---|---|
| `attacks` | `is_scanner`, `is_brute_force`, `is_web_attacker` | AbuseIPDB, DShield, FireHOL L1/L2, blocklist.de |
| `malware` | `is_malware`, `is_phishing` | Feodo Tracker, ThreatFox, C2 Tracker, URLhaus |
| `botnet` | `is_botnet`, `is_c2_server` | ET BotCC, cybercrime, iblocklist Zeus/SpyEye |
| `anonymizer` | `is_tor`, `is_vpn`, `is_proxy`, `is_anonymizer` | Tor Project, NordVPN, Mullvad, ProtonVPN |
| `spam` | `is_spammer`, `is_forum_spammer` | Spamhaus DROP, CleanTalk, nixspam |
| `compromised` | `is_compromised` | Emerging Threats compromised, ET compromised |
| `infrastructure` | `is_datacenter`, `is_cdn`, `is_cloud`, `is_anycast` | AWS, GCP, Cloudflare, DigitalOcean |

---

## Feed Configuration

All 128 sources are defined in `feeds.json`. Each entry looks like:

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
| `name` | string | Unique feed identifier |
| `url` | string | Remote source URL |
| `regex` | string | Pattern to extract IPs/CIDRs from raw content |
| `base_score` | float 0–1 | Threat severity weight |
| `confidence` | float 0–1 | Source reliability |
| `flags` | string[] | Specific threat type indicators |
| `categories` | string[] | Output grouping — determines which `.ipset` file receives these IPs |

---

## How It Works

```
1. feeds.json        — 128 source definitions with regex, score, flags, categories
        │
        ▼
2. aggregator.py     — parallel download (10 workers), regex parse, IP→int conversion
        │
        ▼
3. process_feeds()   — deduplicate + sort ranges per feed
        │
        ├──► blocklist.bin          (all feeds, delta-encoded binary)
        │
        └──► merge by category
                  │
                  ├──► attacks.ipset
                  ├──► malware.ipset
                  ├──► botnet.ipset
                  ├──► anonymizer.ipset
                  ├──► spam.ipset
                  ├──► compromised.ipset
                  └──► infrastructure.ipset
```

`blocklist.bin` stores each feed separately with delta-encoded varint ranges, keeping the file small (~12 MB for 128 feeds) and enabling per-feed lookups. The ipset files merge all ranges across feeds sharing a category into the minimal set of CIDRs using `ipaddress.summarize_address_range`.

### Binary Format

```
[u32 LE]  Unix timestamp
[u16 LE]  Number of feeds
  per feed:
    [u8]    Name length
    [bytes] Feed name (UTF-8)
    [u32]   Number of ranges
      per range:
        [varint] start − previous_start  (delta)
        [varint] end − start             (size)
```

---

## Stats

| Metric | Value |
|---|---|
| Feeds | 128 |
| Total entries | ~5.0M |
| IPv4 addresses | ~4.7M |
| CIDR ranges | ~552K |
| IPv6 entries | ~6K |
| Binary file size | ~12 MB |
| Update frequency | Daily (00:00 UTC) |

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
