"""Integer range arithmetic for IP address sets.

A range is an inclusive ``(start, end)`` tuple of integers. Every function
here works on one address family at a time; IPv4 and IPv6 ranges are never
mixed in the same list.
"""

import ipaddress

V4 = 4
V6 = 6
MAX = {V4: (1 << 32) - 1, V6: (1 << 128) - 1}
_ADDRESS = {V4: ipaddress.IPv4Address, V6: ipaddress.IPv6Address}


def merge(ranges):
    """Sort ranges and merge any that overlap or touch."""
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            if end > merged[-1][1]:
                merged[-1][1] = end
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


def subtract(ranges, holes):
    """Remove ``holes`` from ``ranges``. Both inputs must already be merged."""
    result = []
    i = 0
    for start, end in ranges:
        while i < len(holes) and holes[i][1] < start:
            i += 1
        j = i
        cur = start
        while j < len(holes) and holes[j][0] <= end:
            hole_start, hole_end = holes[j]
            if hole_start > cur:
                result.append((cur, hole_start - 1))
            cur = max(cur, hole_end + 1)
            if cur > end:
                break
            j += 1
        if cur <= end:
            result.append((cur, end))
    return result


def intersect(ranges, keep):
    """Keep only the parts of ``ranges`` inside ``keep``. Both must be merged."""
    result = []
    i = j = 0
    while i < len(ranges) and j < len(keep):
        start = max(ranges[i][0], keep[j][0])
        end = min(ranges[i][1], keep[j][1])
        if start <= end:
            result.append((start, end))
        if ranges[i][1] < keep[j][1]:
            i += 1
        else:
            j += 1
    return result


def address_count(ranges):
    return sum(end - start + 1 for start, end in ranges)


def from_networks(networks):
    """Build a merged range list from CIDR strings of a single family."""
    ranges = []
    for text in networks:
        net = ipaddress.ip_network(text)
        ranges.append((int(net.network_address), int(net.broadcast_address)))
    return merge(ranges)


def to_cidrs(ranges, version):
    """Convert merged ranges to the minimal list of CIDR strings."""
    address = _ADDRESS[version]
    cidrs = []
    for start, end in ranges:
        for net in ipaddress.summarize_address_range(address(start), address(end)):
            cidrs.append(str(net))
    return cidrs
