"""Turn raw feed text into per-family integer ranges."""

import ipaddress
from dataclasses import dataclass, field

from . import ranges as R
from .filters import MAX_ENTRY_SIZE


def _address(text):
    addr = ipaddress.ip_address(text.strip())
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr


def parse_entry(text):
    """Parse ``a.b.c.d``, ``a.b.c.d/nn``, ``start-end`` or the IPv6 forms.

    Returns ``(version, start, end)`` or ``None`` when ``text`` is not an
    address. IPv4-mapped IPv6 addresses are returned as IPv4.
    """
    text = text.strip()
    if not text:
        return None
    try:
        if text.count("-") == 1:
            first, last = (_address(part) for part in text.split("-"))
            if first.version != last.version or int(first) > int(last):
                return None
            return first.version, int(first), int(last)
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            if net.version == 6 and net.prefixlen >= 96 and net.network_address.ipv4_mapped:
                net = ipaddress.ip_network(
                    f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}", strict=False
                )
            return net.version, int(net.network_address), int(net.broadcast_address)
        addr = _address(text)
        return addr.version, int(addr), int(addr)
    except ValueError:
        return None


@dataclass
class ParsedFeed:
    v4: list = field(default_factory=list)
    v6: list = field(default_factory=list)
    matches: int = 0
    invalid: int = 0
    too_broad: int = 0

    @property
    def entries(self):
        return len(self.v4) + len(self.v6)


def extract(line, regex):
    """Return the strings ``regex`` captures in ``line`` (first non-empty group)."""
    found = []
    for match in regex.findall(line):
        if isinstance(match, tuple):
            match = next((group for group in match if group), "")
        if match:
            found.append(match)
    return found


def parse_feed(lines, regex):
    """Extract, validate and merge every address in ``lines``."""
    parsed = ParsedFeed()
    buckets = {R.V4: [], R.V6: []}
    for line in lines:
        for text in extract(line, regex):
            parsed.matches += 1
            entry = parse_entry(text)
            if entry is None:
                parsed.invalid += 1
                continue
            version, start, end = entry
            if end - start + 1 > MAX_ENTRY_SIZE[version]:
                parsed.too_broad += 1
                continue
            buckets[version].append((start, end))
    parsed.v4 = R.merge(buckets[R.V4])
    parsed.v6 = R.merge(buckets[R.V6])
    return parsed
