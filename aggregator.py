import json
import os
import time
import ipaddress
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import struct
import re


def parse_ip(ip_str):
    try:
        if "/" in ip_str:
            return ipaddress.ip_network(ip_str, strict=False)
        return ipaddress.ip_address(ip_str)
    except ValueError:
        return None


def parse_line(line, regex):
    matches = re.findall(regex, line)
    results = []
    for match in matches:
        if isinstance(match, str):
            results.append(match)
        elif isinstance(match, tuple):
            results.append(next((group for group in match if group), None))
    return results


def download_source(url, timeout=30):
    for attempt in range(1, 4):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                content = response.read().decode("utf-8", errors="ignore")
                return content.splitlines()
        except Exception as error:
            print(f"Error downloading {url} (attempt {attempt}/3): {error}")
            if attempt < 3:
                time.sleep(1)
    return []


def download_single_list(source):
    ips = []

    for line in download_source(source["url"]):
        ips.extend(parse_line(line, source["regex"]))

    return source["name"], ips


def download_all_feeds(sources):
    feeds = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(download_single_list, source): source for source in sources
        }
        for future in as_completed(futures):
            name, ips = future.result()
            feeds[name] = ips
            print(f"Downloaded {name}: {len(ips)} entries")
    return feeds


def write_varint(f, value):
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        f.write(bytes([byte]))
        if value == 0:
            break


def merge_ranges(ranges):
    if not ranges:
        return []
    sorted_ranges = sorted(ranges)
    merged = [list(sorted_ranges[0])]
    for start, end in sorted_ranges[1:]:
        if start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [tuple(r) for r in merged]


def process_feeds(feeds):
    processed = {}
    for list_name, ip_strings in feeds.items():
        ranges = []

        for ip_str in ip_strings:
            if not ip_str:
                continue
            if "-" in ip_str and ip_str.count("-") == 1:
                parts = ip_str.split("-")
                try:
                    start = int(ipaddress.ip_address(parts[0].strip()))
                    end = int(ipaddress.ip_address(parts[1].strip()))
                    if start <= end:
                        ranges.append((start, end))
                    continue
                except ValueError:
                    pass
            parsed = parse_ip(ip_str)
            if parsed is None:
                continue
            if isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                start = int(parsed.network_address)
                end = int(parsed.broadcast_address)
                ranges.append((start, end))
            elif isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                addr = int(parsed)
                ranges.append((addr, addr))

        processed[list_name] = merge_ranges(ranges)
    return processed


_IPV4_MAX = (1 << 32) - 1


def ranges_to_cidrs(ranges):
    cidrs = []
    for start, end in ranges:
        # Split ranges that straddle the IPv4/IPv6 integer boundary
        # to avoid mismatched-type errors in summarize_address_range
        sub_ranges = (
            [(start, _IPV4_MAX), (_IPV4_MAX + 1, end)]
            if start <= _IPV4_MAX < end
            else [(start, end)]
        )
        for s, e in sub_ranges:
            try:
                start_addr = ipaddress.ip_address(s)
                end_addr = ipaddress.ip_address(e)
                for network in ipaddress.summarize_address_range(start_addr, end_addr):
                    cidrs.append(str(network))
            except Exception:
                continue
    return cidrs


def write_ipset_file(filename, category, cidrs, timestamp):
    with open(filename, "w") as f:
        f.write(f"# Category : {category}\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp))} UTC\n")
        f.write(f"# Entries  : {len(cidrs)}\n")
        for cidr in cidrs:
            f.write(cidr + "\n")


def main():
    with open("feeds.json") as file:
        sources = json.load(file)

    feed_categories = {source["name"]: source.get("categories", []) for source in sources}

    print("Downloading feeds...")
    feeds = download_all_feeds(sources)

    print("Processing feeds...")
    processed = process_feeds(feeds)

    timestamp = int(time.time())

    os.makedirs("data", exist_ok=True)

    with open("data/blocklist.bin", "wb") as f:
        f.write(struct.pack("<I", timestamp))
        f.write(struct.pack("<H", len(processed)))

        for list_name, ranges in processed.items():
            name_bytes = list_name.encode("utf-8")
            f.write(struct.pack("<B", len(name_bytes)))
            f.write(name_bytes)
            f.write(struct.pack("<I", len(ranges)))

            prev_from = 0
            for start, end in ranges:
                from_delta = start - prev_from
                range_size = end - start

                write_varint(f, from_delta)
                write_varint(f, range_size)

                prev_from = start

    print(f"Saved data/blocklist.bin with {len(processed)} feeds")

    # Build per-category range sets
    category_ranges = defaultdict(list)
    for feed_name, ranges in processed.items():
        for cat in feed_categories.get(feed_name, []):
            category_ranges[cat].extend(ranges)

    print("Writing category ipset files...")
    for category, ranges in sorted(category_ranges.items()):
        merged = merge_ranges(ranges)
        cidrs = ranges_to_cidrs(merged)
        filename = f"data/{category}.ipset"
        write_ipset_file(filename, category, cidrs, timestamp)
        print(f"Saved {filename} ({len(cidrs)} entries)")


if __name__ == "__main__":
    main()
