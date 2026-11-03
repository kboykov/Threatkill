"""Writers for the per-category output files."""

import time

IPSET_MAXELEM = 16777216  # constant so `create -exist` matches across runs
NFT_TABLE = "threatkill"
NFT_CHUNK = 4096


def _stamp(timestamp):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(timestamp))


def write_list(path, category, cidrs, timestamp, family=None):
    """Plain CIDR list with a short comment header."""
    label = category if family is None else f"{category} ({family})"
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# Category : {label}\n")
        fh.write(f"# Generated: {_stamp(timestamp)} UTC\n")
        fh.write(f"# Entries  : {len(cidrs)}\n")
        for cidr in cidrs:
            fh.write(cidr + "\n")


def ipset_name(category, family, suffix=""):
    # ipset names are limited to 31 characters
    return f"tk_{category}_{family}{suffix}"


def write_ipset_restore(path, category, cidrs_v4, cidrs_v6):
    """Script for ``ipset -exist restore`` that atomically swaps in new sets."""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for family, inet, cidrs in (("v4", "inet", cidrs_v4), ("v6", "inet6", cidrs_v6)):
            live = ipset_name(category, family)
            new = ipset_name(category, family, "_new")
            params = f"hash:net family {inet} hashsize 1024 maxelem {IPSET_MAXELEM}"
            fh.write(f"create {live} {params}\n")
            fh.write(f"create {new} {params}\n")
            fh.write(f"flush {new}\n")
            for cidr in cidrs:
                fh.write(f"add {new} {cidr}\n")
            fh.write(f"swap {new} {live}\n")
            fh.write(f"destroy {new}\n")


def write_nft(path, category, cidrs_v4, cidrs_v6, timestamp):
    """Script for ``nft -f`` that (re)fills ``inet threatkill`` sets in one transaction."""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# Threatkill {category}, generated {_stamp(timestamp)} UTC\n")
        fh.write(f"add table inet {NFT_TABLE}\n")
        for family, kind, cidrs in (("v4", "ipv4_addr", cidrs_v4), ("v6", "ipv6_addr", cidrs_v6)):
            name = f"{category}_{family}"
            fh.write(
                f"add set inet {NFT_TABLE} {name} "
                f"{{ type {kind}; flags interval; auto-merge; }}\n"
            )
            fh.write(f"flush set inet {NFT_TABLE} {name}\n")
            for i in range(0, len(cidrs), NFT_CHUNK):
                chunk = ", ".join(cidrs[i : i + NFT_CHUNK])
                fh.write(f"add element inet {NFT_TABLE} {name} {{ {chunk} }}\n")
