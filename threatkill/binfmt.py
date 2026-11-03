"""Reader and writer for ``blocklist.bin``.

Version 2 layout (all integers little-endian)::

    magic        4 bytes  b"TKBL"
    version      u8       2
    timestamp    u64      Unix time of generation
    n_categories u8, then per category: u8 length + UTF-8 name
    n_flags      u8, then per flag:     u8 length + UTF-8 name
    n_feeds      u16
    per feed:
        u8 length + UTF-8 name
        u8   base_score  (0-100)
        u8   confidence  (0-100)
        u64  category bitmask (bit i = categories[i])
        u64  flag bitmask     (bit i = flags[i])
        u32  IPv4 range count, then per range: varint start delta, varint size
        u32  IPv6 range count, then per range: varint start delta, varint size

``start delta`` is the distance from the previous range's start within the
same family (the first is relative to 0); ``size`` is ``end - start``.

Version 1 (no magic, written before November 2026) stored IPv4 and IPv6 in a
single integer space. ``read`` still understands it so the previous release
can be used as a fallback; IPv6 values below 2**32 cannot be told apart from
IPv4 in that format and are read as IPv4.
"""

import io
import struct
from dataclasses import dataclass, field

from . import ranges as R

MAGIC = b"TKBL"
VERSION = 2


@dataclass
class FeedRecord:
    name: str
    v4: list = field(default_factory=list)
    v6: list = field(default_factory=list)
    base_score: float = 0.0
    confidence: float = 0.0
    categories: tuple = ()
    flags: tuple = ()


def _write_varint(out, value):
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.write(bytes((byte | 0x80,)))
        else:
            out.write(bytes((byte,)))
            return


def _read_varint(stream):
    result = shift = 0
    while True:
        chunk = stream.read(1)
        if not chunk:
            raise ValueError("truncated varint")
        byte = chunk[0]
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result
        shift += 7


def _write_name(out, name):
    data = name.encode("utf-8")
    if len(data) > 255:
        raise ValueError(f"name too long: {name!r}")
    out.write(struct.pack("<B", len(data)))
    out.write(data)


def _read_name(stream):
    return stream.read(stream.read(1)[0]).decode("utf-8")


def _write_ranges(out, ranges):
    out.write(struct.pack("<I", len(ranges)))
    previous = 0
    for start, end in ranges:
        _write_varint(out, start - previous)
        _write_varint(out, end - start)
        previous = start


def _read_ranges(stream):
    (count,) = struct.unpack("<I", stream.read(4))
    ranges, current = [], 0
    for _ in range(count):
        current += _read_varint(stream)
        ranges.append((current, current + _read_varint(stream)))
    return ranges


def _mask(values, table):
    mask = 0
    for value in values:
        mask |= 1 << table.index(value)
    return mask


def _unmask(mask, table):
    return tuple(name for bit, name in enumerate(table) if mask >> bit & 1)


def dumps(timestamp, feeds, categories, flags):
    """Serialise ``feeds`` (a list of ``FeedRecord``) to bytes."""
    if len(categories) > 64 or len(flags) > 64:
        raise ValueError("at most 64 categories and 64 flags are supported")
    out = io.BytesIO()
    out.write(MAGIC)
    out.write(struct.pack("<BQ", VERSION, timestamp))
    for table in (categories, flags):
        out.write(struct.pack("<B", len(table)))
        for name in table:
            _write_name(out, name)
    out.write(struct.pack("<H", len(feeds)))
    for feed in feeds:
        _write_name(out, feed.name)
        out.write(
            struct.pack(
                "<BBQQ",
                round(feed.base_score * 100),
                round(feed.confidence * 100),
                _mask(feed.categories, categories),
                _mask(feed.flags, flags),
            )
        )
        _write_ranges(out, feed.v4)
        _write_ranges(out, feed.v6)
    return out.getvalue()


def loads(data):
    """Parse bytes from either format version. Returns ``(timestamp, {name: FeedRecord})``."""
    stream = io.BytesIO(data)
    if data[:4] != MAGIC:
        return _loads_v1(stream)
    stream.read(4)
    version, timestamp = struct.unpack("<BQ", stream.read(9))
    if version != VERSION:
        raise ValueError(f"unsupported blocklist.bin version {version}")
    categories = [_read_name(stream) for _ in range(stream.read(1)[0])]
    flags = [_read_name(stream) for _ in range(stream.read(1)[0])]
    (count,) = struct.unpack("<H", stream.read(2))
    feeds = {}
    for _ in range(count):
        name = _read_name(stream)
        score, confidence, category_mask, flag_mask = struct.unpack("<BBQQ", stream.read(18))
        v4 = _read_ranges(stream)
        v6 = _read_ranges(stream)
        feeds[name] = FeedRecord(
            name=name,
            v4=v4,
            v6=v6,
            base_score=score / 100,
            confidence=confidence / 100,
            categories=_unmask(category_mask, categories),
            flags=_unmask(flag_mask, flags),
        )
    return timestamp, feeds


def _loads_v1(stream):
    timestamp, count = struct.unpack("<IH", stream.read(6))
    feeds = {}
    for _ in range(count):
        name = _read_name(stream)
        mixed = _read_ranges(stream)
        v4 = [(s, min(e, R.MAX[R.V4])) for s, e in mixed if s <= R.MAX[R.V4]]
        v6 = [(max(s, R.MAX[R.V4] + 1), e) for s, e in mixed if e > R.MAX[R.V4]]
        feeds[name] = FeedRecord(name=name, v4=v4, v6=v6)
    return timestamp, feeds


def write(path, timestamp, feeds, categories, flags):
    data = dumps(timestamp, feeds, categories, flags)
    with open(path, "wb") as fh:
        fh.write(data)
    return data


def read(path):
    with open(path, "rb") as fh:
        return loads(fh.read())
