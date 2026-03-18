<div align="center">

# 🔒 Threatkill

Threat intelligence aggregator that collects, processes, and serves IP reputation data from 128 security feeds into optimized category ipset files and a binary format for fast lookups.

<p align="center">
<img src="https://img.shields.io/github/actions/workflow/status/kboykov/Threatkill/aggregate-feeds.yml?label=Build&style=for-the-badge" alt="GitHub Workflow Status">
<img src="https://img.shields.io/badge/feeds-128-blue?style=for-the-badge" alt="Feed Count">
<img src="https://img.shields.io/badge/dataset-5.0M_entries-blue?style=for-the-badge" alt="Dataset Size">
<img src="https://img.shields.io/badge/IPs-4.4M-green?style=for-the-badge" alt="Individual IPs">
<img src="https://img.shields.io/badge/ranges-552K-orange?style=for-the-badge" alt="CIDR Ranges">
</p>

<p align="center">
<a href="https://github.com/kboykov/Threatkill/releases/latest/download/blocklist.bin"><img src="https://img.shields.io/badge/download-blocklist.bin_(12MB)-red?style=for-the-badge&logo=download&logoColor=white" alt="Download Threat Data"></a>
</p>

</div>

## 🚀 Key Features

- ✅ Fast IP lookups in <1ms using binary search
- ✅ 5.0M+ IPs and CIDR ranges from 128 threat intelligence feeds
- ✅ Malware C&C servers, botnets, spam networks, compromised hosts
- ✅ VPN providers, Tor nodes, datacenter/hosting ASNs
- ✅ Per-category ipset files for direct firewall integration
- ✅ Optimized binary format with delta encoding for minimal memory footprint
- ✅ Support for both IPv4 and IPv6
- ✅ Automated daily updates via GitHub Actions

## 📥 Downloads

### Binary Blocklist

Full dataset in delta-encoded binary format (~12MB), suitable for programmatic lookups across all 128 feeds.

```bash
wget https://github.com/kboykov/Threatkill/releases/latest/download/blocklist.bin
```

### Category ipset Files

Individual plain-text ipset files, one per threat category. Each file contains deduplicated, merged CIDR ranges from all feeds tagged with that category.

| File | Description |
|---|---|
| `attacks.ipset` | Scanners, brute-force attackers, web attackers |
| `malware.ipset` | Malware C&C servers, exploit hosts, phishing |
| `botnet.ipset` | Botnet command & control infrastructure |
| `anonymizer.ipset` | Tor nodes, VPN servers, open proxies |
| `spam.ipset` | Spammers and forum spam networks |
| `compromised.ipset` | Compromised/hijacked hosts |
| `infrastructure.ipset` | Datacenters, CDNs, cloud providers |

```bash
# Example: download the attacks ipset
wget https://github.com/kboykov/Threatkill/releases/latest/download/attacks.ipset

# Load directly into Linux ipset
ipset create threatkill_attacks hash:net
ipset restore < attacks.ipset
```

## 📊 Architecture

```
feeds.json ──────────> aggregator.py ──────────> blocklist.bin
  (128 feeds)           (processor)              (binary, all feeds)
                             │
                             └──────────────────> attacks.ipset
                                                  malware.ipset
                                                  botnet.ipset
                                                  anonymizer.ipset
                                                  spam.ipset
                                                  compromised.ipset
                                                  infrastructure.ipset
```

## 📖 Overview

Threatkill downloads threat intelligence from 128 sources (malware C&C servers, botnets, spam networks, VPN providers, Tor nodes, AbuseIPDB, etc.) and processes them into two output formats:

1. **`blocklist.bin`** — a compact binary file with delta-encoded integer ranges for fast programmatic lookups across all feeds
2. **`<category>.ipset` files** — plain-text CIDR lists grouped by threat category for direct use with firewall tools like `ipset`, `nftables`, or `iptables`

IP addresses and CIDR ranges are stored as sorted, merged integer ranges. The category ipset files deduplicate and merge overlapping ranges across all feeds that share a category tag.

## 📁 Data Models

### feeds.json

Configuration file defining all 128 threat intelligence sources. Each feed is an independent object with complete metadata.

**Structure**: Array of feed objects

```json
[
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
]
```

**Required Fields**:

- `name`: Unique identifier for the feed
- `url`: Download URL for the threat list
- `description`: Human-readable description
- `regex`: Pattern to extract IPs/CIDRs from feed content
- `base_score`: Threat severity (0.0–1.0)
- `confidence`: Data reliability (0.0–1.0)
- `flags`: Boolean threat indicators — `is_anycast`, `is_botnet`, `is_brute_force`, `is_c2_server`, `is_cdn`, `is_cloud`, `is_compromised`, `is_datacenter`, `is_forum_spammer`, `is_malware`, `is_phishing`, `is_proxy`, `is_scanner`, `is_spammer`, `is_tor`, `is_vpn`, `is_web_attacker`
- `categories`: Threat categories used to group ipset output — `anonymizer`, `attacks`, `botnet`, `compromised`, `infrastructure`, `malware`, `spam`

**Optional Fields**:

- `provider_name`: VPN/hosting provider name

### blocklist.bin

Processed binary output containing all 128 feeds with delta-encoded IP ranges.

**Structure**:

```
[4 bytes: timestamp (u32 LE)]
[2 bytes: feed count (u16 LE)]
For each feed:
  [1 byte: name length (u8)]
  [N bytes: feed name (UTF-8)]
  [4 bytes: range count (u32 LE)]
  For each range:
    [varint: from_delta (start - previous start)]
    [varint: range_size (end - start)]
```

**Integer Conversion**:

- IPv4: `10.0.0.1` → `167772161`
- IPv6: `2001:db8::1` → `42540766411282592856903984951653826561`
- CIDR: `10.0.0.0/27` → `(167772160, 167772191)` (network to broadcast)
- Single IP: stored as range with size 0

### \<category\>.ipset

Plain-text files, one per category. Ranges from all feeds sharing a category are merged and deduplicated, then converted back to minimal CIDR notation using `ipaddress.summarize_address_range`.

**Format**:

```
# Category : attacks
# Generated: 2026-03-18 12:00:00 UTC
# Entries  : 381042
1.0.68.149/32
1.0.138.92/32
...
10.0.0.0/8
```

## ⚙️ aggregator.py

Downloads and processes all feeds in parallel, writing both the binary blocklist and category ipset files.

**Pipeline**:

1. Load `feeds.json` and build a `feed → categories` index
2. Download all feeds in parallel (ThreadPoolExecutor, 10 workers)
3. Parse each feed line with its configured regex
4. Convert IPs/CIDRs to `(start_int, end_int)` ranges
5. Sort and deduplicate ranges per feed → write `blocklist.bin`
6. Group ranges by category, merge overlapping ranges → write `<category>.ipset`

**Key Functions**:

| Function | Purpose |
|---|---|
| `download_all_feeds` | Parallel feed downloads with retry logic |
| `process_feeds` | Converts IP strings to sorted integer range lists |
| `merge_ranges` | Merges overlapping/adjacent ranges across feeds |
| `ranges_to_cidrs` | Converts integer ranges back to CIDR notation |
| `write_ipset_file` | Writes a category ipset file with header |
| `write_varint` | Variable-length integer encoder for binary output |

**Usage**:

```bash
python aggregator.py
```

**Output**: `blocklist.bin` (all feeds, binary) + one `<category>.ipset` per category tag found in `feeds.json`

## 🐍 Python Lookup Examples

### Binary Blocklist Loader

```python
import struct
import ipaddress
from typing import Dict, List, Tuple, Optional


def read_varint(f) -> int:
    result = shift = 0
    while True:
        byte = f.read(1)[0]
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result
        shift += 7


def binary_search(ranges: List[Tuple], target: int) -> Optional[int]:
    left, right = 0, len(ranges) - 1
    while left <= right:
        mid = (left + right) // 2
        start, end = ranges[mid]
        if start <= target <= end:
            return mid
        elif target < start:
            right = mid - 1
        else:
            left = mid + 1
    return None


class BlocklistLoader:
    def __init__(self, path: str = "blocklist.bin"):
        self.feeds: Dict[str, List[Tuple[int, int]]] = {}
        self.timestamp: int = 0
        self._load(path)

    def _load(self, path: str):
        with open(path, "rb") as f:
            self.timestamp = struct.unpack("<I", f.read(4))[0]
            feed_count = struct.unpack("<H", f.read(2))[0]

            for _ in range(feed_count):
                name_len = struct.unpack("<B", f.read(1))[0]
                feed_name = f.read(name_len).decode("utf-8")
                range_count = struct.unpack("<I", f.read(4))[0]

                ranges = []
                current = 0
                for _ in range(range_count):
                    current += read_varint(f)
                    size = read_varint(f)
                    ranges.append((current, current + size))

                self.feeds[feed_name] = ranges

    def check_ip(self, ip: str) -> List[str]:
        target = int(ipaddress.ip_address(ip))
        return [
            feed_name for feed_name, ranges in self.feeds.items()
            if binary_search(ranges, target) is not None
        ]


blocklist = BlocklistLoader()
print(blocklist.check_ip("8.8.8.8"))
```

### Reputation Scoring

```python
import json


with open("feeds.json") as f:
    sources = {feed["name"]: feed for feed in json.load(f)}


def check_ip_with_reputation(blocklist: BlocklistLoader, ip: str) -> dict:
    matches = blocklist.check_ip(ip)
    if not matches:
        return {"ip": ip, "score": 0.0, "feeds": []}

    flags = {}
    category_scores: Dict[str, List[float]] = {}

    for list_name in matches:
        source = sources.get(list_name)
        if not source:
            continue
        for flag in source.get("flags", []):
            flags[flag] = True
        if source.get("provider_name"):
            flags["vpn_provider"] = source["provider_name"]
        for category in source.get("categories", []):
            category_scores.setdefault(category, []).append(source.get("base_score", 0.5))

    total = 0.0
    for scores in category_scores.values():
        combined = 1.0
        for s in sorted(scores, reverse=True):
            combined *= 1.0 - s
        total += 1.0 - combined

    return {"ip": ip, "score": min(total / 1.5, 1.0), "feeds": matches, **flags}


result = check_ip_with_reputation(blocklist, "8.8.8.8")
print(json.dumps(result, indent=2))
```

### ipset File Lookup

```python
import ipaddress

def load_ipset(path: str) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass
    return networks

def ip_in_ipset(ip: str, networks) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in networks)

attacks = load_ipset("attacks.ipset")
print(ip_in_ipset("1.0.68.149", attacks))  # True
```

## ⚡ Performance Characteristics

**Dataset Statistics**:

- Total feeds: 128
- Individual IPs: ~4.7M (4.4M IPv4 + ~319K from AbuseIPDB + 6K IPv6)
- CIDR ranges: 552K (545K IPv4, 7K IPv6)
- Binary file size: ~12MB (varint delta-encoded)

**Lookup Complexity**:

- Binary blocklist: O(log n) per feed, <1ms for all 128 feeds
- ipset files: direct kernel-space lookup when loaded via `ipset` tool

## 💡 Use Cases

- **Firewall Rules**: Load `attacks.ipset` or `malware.ipset` directly into `ipset` / `nftables`
- **API Rate Limiting**: Block known malicious IPs at the application layer
- **Fraud Detection**: Flag VPN/proxy/datacenter traffic with `anonymizer.ipset`
- **Security Analytics**: Enrich logs with threat intelligence from `blocklist.bin`
- **Access Control**: Restrict Tor exit nodes using `anonymizer.ipset`
- **Compliance**: Block traffic from sanctioned or high-risk networks

## 📜 License

Licensed under the Apache License, Version 2.0.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
