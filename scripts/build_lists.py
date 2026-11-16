#!/usr/bin/env python3
"""Turn public threat feeds into lists a UniFi gateway can import.

UniFi Dynamic Network Lists want a plain file: one IP or CIDR per line, a
single address family, no comments, at most 100,000 entries. This script
downloads every feed in feeds.conf, cleans it into that shape, and writes:

    lists/<feed>-v4.txt, lists/<feed>-v6.txt     one feed on its own
    lists/combined-<group>-v4.txt, ...-v6.txt    every feed in a group, merged
    lists/SOURCES.md                             where each list came from

Standard library only. Run it from anywhere: python3 scripts/build_lists.py
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FEEDS_FILE = ROOT / "feeds.conf"
ALLOW_FILE = ROOT / "allowlist.txt"
OUT_DIR = ROOT / "lists"

MAX_ENTRIES = 100_000          # UniFi's cap for one dynamic list
MAX_BYTES = 50 * 1024 * 1024   # refuse absurdly large downloads
MIN_PREFIX = {4: 8, 6: 19}     # refuse networks broader than this
FORMATS = {"text", "range", "spamhaus-json"}
GROUPS = {"core", "inbound", "none"}
USER_AGENT = "unifi-threat-feeds/1.0 (scheduled list builder)"

# Address space that must never reach a firewall block list. Some feeds
# (FireHOL Level 1 for one) include these "bogons", and blocking them on a
# home or office gateway can cut off the LAN, an upstream modem, or CGNAT.
RESERVED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
    "::/8", "64:ff9b::/96", "2001:db8::/32", "fc00::/7", "fe80::/10",
    "ff00::/8",
)]

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class FeedError(Exception):
    pass


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

def load_feeds() -> dict[str, dict]:
    feeds: dict[str, dict] = {}
    for num, raw in enumerate(FEEDS_FILE.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 4:
            sys.exit(f"feeds.conf line {num}: expected 4 columns, got {len(parts)}")
        name, group, fmt, url = parts
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) or name.startswith("combined"):
            sys.exit(f"feeds.conf line {num}: bad feed name '{name}'")
        if group not in GROUPS:
            sys.exit(f"feeds.conf line {num}: unknown group '{group}'")
        if fmt not in FORMATS:
            sys.exit(f"feeds.conf line {num}: unknown format '{fmt}'")
        if not url.startswith("https://"):
            sys.exit(f"feeds.conf line {num}: url must start with https://")
        feed = feeds.setdefault(name, {"group": group, "sources": []})
        if feed["group"] != group:
            sys.exit(f"feeds.conf line {num}: '{name}' is in two different groups")
        feed["sources"].append((fmt, url))
    if not feeds:
        sys.exit("feeds.conf has no feeds turned on")
    return feeds


def load_allowlist() -> list[Network]:
    if not ALLOW_FILE.exists():
        return []
    allow = []
    for num, raw in enumerate(ALLOW_FILE.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        net = to_network(line)
        if net is None:
            sys.exit(f"allowlist.txt line {num}: '{line}' is not an IP or CIDR")
        allow.append(net)
    return allow


# --------------------------------------------------------------------------
# Download and parse
# --------------------------------------------------------------------------

def fetch(url: str) -> str:
    last = None
    for attempt in range(3):
        if attempt:
            time.sleep(5 * attempt)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise FeedError("download is larger than 50 MB")
            return data.decode("utf-8", errors="replace")
        except FeedError:
            raise
        except Exception as exc:  # network errors, HTTP errors, timeouts
            last = exc
    raise FeedError(f"download failed: {last}")


def to_network(token: str) -> Network | None:
    try:
        return ipaddress.ip_network(token.strip(), strict=False)
    except ValueError:
        return None


def parse(fmt: str, body: str) -> tuple[list[Network], str]:
    """Return (networks, upstream notice). Raises FeedError on junk input."""
    nets: list[Network] = []
    notice = ""
    seen = bad = 0

    for raw in body.splitlines():
        if fmt == "spamhaus-json":
            line = raw.strip()
            if not line:
                continue
            seen += 1
            try:
                row = json.loads(line)
            except ValueError:
                bad += 1
                continue
            if row.get("type") == "metadata":
                stamp = row.get("timestamp")
                when = (datetime.fromtimestamp(stamp, timezone.utc)
                        .strftime("%Y-%m-%d %H:%M UTC")
                        if isinstance(stamp, (int, float)) else "unknown date")
                notice = f"{row.get('copyright', '')}, data of {when}".strip(", ")
                seen -= 1
                continue
            net = to_network(str(row.get("cidr", "")))
            if net is None:
                bad += 1
            else:
                nets.append(net)
            continue

        line = re.split(r"[#;]", raw, maxsplit=1)[0].strip()
        if not line:
            continue
        seen += 1
        tokens = re.split(r"[\s,]+", line)

        if fmt == "range":
            try:
                first = ipaddress.ip_address(tokens[0])
                last = ipaddress.ip_address(tokens[1])
                nets.extend(ipaddress.summarize_address_range(first, last))
            except (ValueError, TypeError, IndexError):
                bad += 1
            continue

        net = to_network(tokens[0])
        if net is None:
            bad += 1
        else:
            nets.append(net)

    if not nets:
        raise FeedError("no usable addresses found")
    # An error page or a changed format shows up as mostly unreadable lines.
    if bad > seen / 2:
        raise FeedError(f"{bad} of {seen} lines were not addresses")
    return nets, notice


# --------------------------------------------------------------------------
# Clean
# --------------------------------------------------------------------------

def is_safe(net: Network) -> bool:
    if net.prefixlen < MIN_PREFIX[net.version]:
        return False
    return not any(net.version == r.version and net.overlaps(r) for r in RESERVED)


def carve(nets: list[Network], allow: list[Network]) -> list[Network]:
    """Remove allowlisted space, splitting larger networks around it."""
    for hole in allow:
        kept: list[Network] = []
        for net in nets:
            if net.version != hole.version or not net.overlaps(hole):
                kept.append(net)
            elif net.subnet_of(hole):
                continue
            else:
                kept.extend(net.address_exclude(hole))
        nets = kept
    return nets


def clean(nets: list[Network], allow: list[Network]) -> dict[int, list[Network]]:
    """Filter, carve, dedupe and merge. Returns {4: [...], 6: [...]}."""
    out: dict[int, list[Network]] = {}
    for version in (4, 6):
        chosen = [n for n in nets if n.version == version and is_safe(n)]
        chosen = carve(chosen, allow)
        out[version] = list(ipaddress.collapse_addresses(chosen))
    return out


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------

def list_files(name: str, version: int) -> list[Path]:
    base = f"{name}-v{version}"
    first = OUT_DIR / f"{base}.txt"
    parts = sorted(OUT_DIR.glob(f"{base}-part*.txt"),
                   key=lambda p: int(re.search(r"part(\d+)", p.name).group(1)))
    return ([first] if first.exists() else []) + parts


def show(net: Network) -> str:
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


def write_list(name: str, version: int, nets: list[Network]) -> list[str]:
    """Write nets, splitting past the UniFi cap. Returns the file names."""
    base = f"{name}-v{version}"
    chunks = [nets[i:i + MAX_ENTRIES] for i in range(0, len(nets), MAX_ENTRIES)]
    written: list[Path] = []
    for index, chunk in enumerate(chunks, 1):
        path = OUT_DIR / (f"{base}.txt" if index == 1 else f"{base}-part{index}.txt")
        path.write_text("\n".join(show(n) for n in chunk) + "\n")
        written.append(path)
    for stale in list_files(name, version):
        if stale not in written:
            stale.unlink()
    return [p.name for p in written]


def read_previous(name: str) -> dict[int, list[Network]] | None:
    """Load the last published copy of a feed, or None if there is none."""
    found: dict[int, list[Network]] = {4: [], 6: []}
    for version in (4, 6):
        for path in list_files(name, version):
            for line in path.read_text().split():
                net = to_network(line)
                if net is not None:
                    found[version].append(net)
    return found if found[4] or found[6] else None


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    feeds = load_feeds()
    allow = load_allowlist()
    OUT_DIR.mkdir(exist_ok=True)

    rows: list[dict] = []
    by_group: dict[str, list[Network]] = {}
    failures: list[str] = []

    for name, feed in feeds.items():
        row = {"name": name, "group": feed["group"], "notice": "",
               "urls": [u for _, u in feed["sources"]], "files": []}
        try:
            raw: list[Network] = []
            notices = []
            for fmt, url in feed["sources"]:
                nets, notice = parse(fmt, fetch(url))
                raw.extend(nets)
                if notice:
                    notices.append(notice)
            result = clean(raw, allow)
            if not result[4] and not result[6]:
                raise FeedError("nothing left after filtering")
            row["status"] = "ok"
            row["notice"] = "; ".join(dict.fromkeys(notices))
            for version in (4, 6):
                row["files"] += write_list(name, version, result[version])
        except FeedError as exc:
            # Keep whatever was published last time rather than emptying the
            # list: an empty file would silently switch the protection off.
            failures.append(f"{name}: {exc}")
            print(f"::warning title=Feed failed::{name}: {exc}")
            result = read_previous(name)
            row["status"] = "FAILED, kept previous copy" if result else "FAILED, no data"
            if result is None:
                result = {4: [], 6: []}
            else:
                for version in (4, 6):
                    row["files"] += [p.name for p in list_files(name, version)]

        row["v4"], row["v6"] = len(result[4]), len(result[6])
        rows.append(row)
        print(f"{name:18} {row['status']:28} v4={row['v4']:>6} v6={row['v6']:>5}")
        if feed["group"] != "none":
            by_group.setdefault(feed["group"], []).extend(result[4] + result[6])

    for group in sorted(by_group):
        name = f"combined-{group}"
        merged = clean(by_group[group], allow)
        row = {"name": name, "group": group, "status": "ok", "notice": "",
               "urls": [], "files": [], "v4": len(merged[4]), "v6": len(merged[6])}
        for version in (4, 6):
            row["files"] += write_list(name, version, merged[version])
        rows.append(row)
        print(f"{name:18} {'ok':28} v4={row['v4']:>6} v6={row['v6']:>5}")

    # Drop files left behind by feeds that were removed from feeds.conf.
    known = {f for row in rows for f in row["files"]} | {"SOURCES.md"}
    for path in OUT_DIR.glob("*"):
        if path.is_file() and path.name not in known:
            path.unlink()

    write_sources(rows)
    write_summary(rows, failures)

    if len(failures) == len(feeds):
        print("Every feed failed. Nothing was updated.")
        return 1
    return 0


def write_sources(rows: list[dict]) -> None:
    lines = [
        "# Sources",
        "",
        "These lists are cleaned copies of third-party threat feeds. Each feed",
        "remains the work of its publisher and is subject to that publisher's",
        "terms of use. The list files carry no comments because UniFi cannot",
        "parse them, so the credits live here instead.",
        "",
        "| List | Group | IPv4 entries | IPv6 entries | Status | Source |",
        "| --- | --- | ---: | ---: | --- | --- |",
    ]
    for row in rows:
        source = "<br>".join(row["urls"]) if row["urls"] else "merged from the feeds in this group"
        if row["notice"]:
            source += f"<br>{row['notice']}"
        lines.append(f"| {row['name']} | {row['group']} | {row['v4']} | {row['v6']} "
                     f"| {row['status']} | {source} |")
    lines += [
        "",
        "Spamhaus DROP data is provided by The Spamhaus Project. Terms:",
        "https://www.spamhaus.org/drop/terms/",
        "",
    ]
    (OUT_DIR / "SOURCES.md").write_text("\n".join(lines))


def write_summary(rows: list[dict], failures: list[str]) -> None:
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return
    lines = ["| List | IPv4 | IPv6 | Status |", "| --- | ---: | ---: | --- |"]
    lines += [f"| {r['name']} | {r['v4']} | {r['v6']} | {r['status']} |" for r in rows]
    if failures:
        lines += ["", "**Failed feeds**", ""] + [f"- {f}" for f in failures]
    with open(target, "a") as handle:
        handle.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
