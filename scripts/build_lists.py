#!/usr/bin/env python3
"""Turn public threat feeds into lists a UniFi gateway can import.

UniFi Dynamic Network Lists want a plain file: one entry per line, a single
type (IPv4, IPv6 or domain), no comments, at most 100,000 entries. This
script downloads every URL in feeds.conf, works out what kind of feed it is,
and writes:

    lists/<feed>-v4.txt, -v6.txt, -domains.txt   one feed on its own
    lists/combined-core-v4.txt, ...              feeds merged by group
    lists/SOURCES.md                             what each list came from

Usage:
    build_lists.py                    rebuild everything in feeds.conf
    build_lists.py check URL...       show what a URL would produce
    build_lists.py add URL...         test the URLs, then add them to feeds.conf
    build_lists.py remove URL|NAME... take feeds out of feeds.conf

Standard library only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FEEDS_FILE = ROOT / "feeds.conf"
ALLOW_FILE = ROOT / "allowlist.txt"
OUT_DIR = ROOT / "lists"

MAX_ENTRIES = 100_000          # UniFi's cap for one dynamic list
MAX_BYTES = 50 * 1024 * 1024   # refuse absurdly large downloads
MIN_PREFIX = {4: 8, 6: 19}     # refuse networks broader than this
KINDS = ("v4", "v6", "domains")
FORMATS = {"auto", "text", "range", "json"}
GROUPS = {"auto", "core", "inbound", "none"}
USER_AGENT = "unifi-threat-feeds/1.1 (scheduled list builder)"

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

# The address a hosts-file blocklist points its domains at.
SINKHOLES = {"0.0.0.0", "127.0.0.1", "::", "::1", "0"}
NOT_DOMAINS = {"localhost.localdomain", "local.localdomain"}
DOMAIN_RE = re.compile(
    r"(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})")
SECRET_RE = re.compile(r"[?&](api[_-]?key|apikey|token|key|secret|auth|password)=", re.I)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class FeedError(Exception):
    pass


@dataclass
class Parsed:
    """What one downloaded feed turned out to contain."""
    kind: str                       # "ip" or "domain"
    style: str                      # how it was written: "JSON", "hosts file", ...
    nets: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    notice: str = ""                # copyright line carried by the feed, if any

    @property
    def label(self) -> str:
        return f"{'IPs' if self.kind == 'ip' else 'domains'}, {self.style}"


@dataclass
class Entry:
    """One line of feeds.conf."""
    line: int                       # index into the file's lines
    url: str
    name: str
    group: str                      # "auto", "core", "inbound" or "none"
    fmt: str


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def to_network(token: str) -> Network | None:
    try:
        return ipaddress.ip_network(token.strip(), strict=False)
    except ValueError:
        return None


def plain_ip(token: str):
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


def url_host(token: str) -> str | None:
    try:
        return urllib.parse.urlsplit(token).hostname
    except ValueError:
        return None


def token_network(token: str) -> Network | None:
    """An IP or CIDR, also accepting ip:port, [v6]:port and URLs on an IP."""
    net = to_network(token)
    if net is not None:
        return net
    match = (re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}", token)
             or re.fullmatch(r"\[([0-9a-fA-F:]+)\](?::\d{1,5})?", token))
    if match:
        return to_network(match.group(1))
    if "://" in token:
        host = url_host(token)
        return to_network(host) if host else None
    return None


def as_domain(token: str) -> str | None:
    name = token.strip().strip("\"'").lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if name in NOT_DOMAINS or not DOMAIN_RE.fullmatch(name):
        return None
    return name


def token_domain(token: str) -> str | None:
    if "://" in token:
        host = url_host(token)
        return as_domain(host) if host else None
    return as_domain(token)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def auto_name(url: str) -> str:
    """Pick a feed name from a URL: the site (or repository) plus the file."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    segments = [s for s in parts.path.split("/") if s]
    stem = segments[-1] if segments else ""
    stem = slug(re.sub(r"\.[A-Za-z0-9]{1,6}$", "", stem))
    labels = host.split(".")
    site = labels[-2] if len(labels) >= 2 else host
    if host.endswith("githubusercontent.com") and len(segments) >= 2:
        site = segments[1]          # the repository name says more than the host
    site = slug(site)
    if not stem:
        name = site
    elif site and site in stem:
        name = stem
    else:
        name = f"{site}-{stem}"
    name = name[:40].strip("-") or "feed"
    return f"feed-{name}" if name.startswith("combined") else name


def unique(name: str, used: set[str]) -> str:
    if name not in used:
        return name
    count = 2
    while f"{name}-{count}" in used:
        count += 1
    return f"{name}-{count}"


def normalize_url(url: str) -> str:
    """Turn a GitHub file page link into the raw link that serves the file."""
    match = re.fullmatch(r"https://github\.com/([^/]+)/([^/]+)/(?:blob|raw)/(.+)", url)
    if match:
        return "https://raw.githubusercontent.com/{}/{}/{}".format(*match.groups())
    return url


def url_problem(url: str) -> str | None:
    if not url.startswith("https://") or not url_host(url):
        return "must be a full https:// URL"
    if SECRET_RE.search(url):
        return ("looks like it carries an API key or token. feeds.conf is "
                "public, so the key would be too")
    return None


def note(kind: str, message: str) -> None:
    """Print a message GitHub Actions shows as an annotation."""
    print(f"::{kind}::{message}")


def summary(lines: list[str]) -> None:
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a") as handle:
            handle.write("\n".join(lines) + "\n\n")


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

def load_config() -> list[Entry]:
    entries: list[Entry] = []
    pending: list[tuple[int, str, dict]] = []
    seen: set[str] = set()

    for index, raw in enumerate(FEEDS_FILE.read_text().splitlines()):
        if raw.lstrip().startswith("#"):
            continue
        tokens = re.split(r"\s#", raw, maxsplit=1)[0].split()
        if not tokens:
            continue
        where = f"feeds.conf line {index + 1}"
        url, options = tokens[0], {}
        if not url.startswith("https://") and tokens[-1].startswith("https://"):
            sys.exit(f"{where}: the URL now goes first, as in\n"
                     f"  {tokens[-1]}  name={tokens[0]}")
        problem = url_problem(url)
        if problem:
            sys.exit(f"{where}: {url} {problem}")
        for token in tokens[1:]:
            key, _, value = token.partition("=")
            if key not in ("name", "group", "format") or not value:
                sys.exit(f"{where}: '{token}' is not name=, group= or format=")
            options[key] = value
        name = options.get("name")
        if name is not None and (not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name)
                                 or name.startswith("combined")):
            sys.exit(f"{where}: bad feed name '{name}'")
        if options.get("group", "auto") not in GROUPS:
            sys.exit(f"{where}: group must be one of {', '.join(sorted(GROUPS))}")
        if options.get("format", "auto") not in FORMATS:
            sys.exit(f"{where}: format must be one of {', '.join(sorted(FORMATS))}")
        if url in seen:
            note("warning", f"{where}: {url} is listed twice, second copy ignored")
            continue
        seen.add(url)
        pending.append((index, url, options))

    # Named feeds claim their names first, so a derived name never collides.
    used = {opts["name"] for _, _, opts in pending if "name" in opts}
    for index, url, opts in pending:
        name = opts.get("name")
        if name is None:
            name = unique(auto_name(url), used)
            used.add(name)
        entries.append(Entry(index, url, name, opts.get("group", "auto"),
                             opts.get("format", "auto")))

    groups: dict[str, str] = {}
    for entry in entries:
        if groups.setdefault(entry.name, entry.group) != entry.group:
            sys.exit(f"feeds.conf: '{entry.name}' is given two different groups")
    return entries


def load_allowlist() -> tuple[list[Network], set[str]]:
    nets: list[Network] = []
    domains: set[str] = set()
    if not ALLOW_FILE.exists():
        return nets, domains
    for num, raw in enumerate(ALLOW_FILE.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        net = to_network(line)
        domain = None if net is not None else as_domain(line)
        if net is not None:
            nets.append(net)
        elif domain:
            domains.add(domain)
        else:
            sys.exit(f"allowlist.txt line {num}: '{line}' is not an IP, CIDR or domain")
    return nets, domains


# --------------------------------------------------------------------------
# Download
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


# --------------------------------------------------------------------------
# Work out what a feed is, and read it
# --------------------------------------------------------------------------

def parse(body: str, fmt: str = "auto") -> Parsed:
    """Detect the feed's format and contents. Raises FeedError on junk."""
    body = body.lstrip("﻿")
    looks_json = body.lstrip()[:1] in ("{", "[")
    if fmt == "json" or (fmt == "auto" and looks_json):
        parsed = parse_json(body)
        if parsed is not None:
            return parsed
        if fmt == "json":
            raise FeedError("not valid JSON")
    return parse_text(body, force_range=(fmt == "range"))


def parse_json(body: str) -> Parsed | None:
    """Read one JSON document or one JSON object per line.

    Every string that is an IP or CIDR is taken, wherever it sits in the
    structure. Domains are not read from JSON: there is no way to tell a
    listed domain from a link in the metadata.
    """
    try:
        documents = [json.loads(body)]
    except ValueError:
        documents, bad = [], 0
        lines = [line for line in body.splitlines() if line.strip()]
        for line in lines:
            try:
                documents.append(json.loads(line))
            except ValueError:
                bad += 1
        if not documents or bad > len(lines) / 2:
            return None

    nets: list[Network] = []
    notices: list[str] = []

    def walk(value) -> None:
        if isinstance(value, dict):
            if isinstance(value.get("copyright"), str):
                stamp = value.get("timestamp")
                when = (datetime.fromtimestamp(stamp, timezone.utc)
                        .strftime("%Y-%m-%d %H:%M UTC")
                        if isinstance(stamp, (int, float)) else "unknown date")
                notices.append(f"{value['copyright']}, data of {when}")
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str):
            net = to_network(value)
            if net is not None:
                nets.append(net)

    for document in documents:
        walk(document)
    if not nets:
        raise FeedError("the JSON holds no IP addresses")
    return Parsed("ip", "JSON", nets=nets, notice="; ".join(dict.fromkeys(notices)))


def expand_range(first, last) -> list[Network] | None:
    if first.version != last.version or int(last) < int(first):
        return None
    limit = 2 ** 24 if first.version == 4 else 2 ** 109
    if int(last) - int(first) + 1 > limit:
        return None
    return list(ipaddress.summarize_address_range(first, last))


def parse_text(body: str, force_range: bool = False) -> Parsed:
    """Read a line-based feed, whatever its dialect.

    Understands plain IP/CIDR lists, CSV with an address column, start/end
    ranges, hosts files, adblock rules, dnsmasq rules, plain domain lists
    and URL lists. A file is treated as either IPs or domains, whichever
    most of its lines are, so a stray line of the other sort is dropped.
    """
    ip_lines: list[tuple[Network | None, list[Network] | None, bool]] = []
    domain_lines: list[str] = []
    styles: dict[str, int] = {}
    data = ranges = 0

    def add_domain(name: str, style: str) -> None:
        domain_lines.append(name)
        styles[style] = styles.get(style, 0) + 1

    for raw in body.splitlines():
        line = raw.strip()
        if (not line or line[0] in "#;![" or line.startswith("//")
                or line.startswith("@@")):
            continue
        if "://" not in line:
            line = re.split(r"[#;]", line, maxsplit=1)[0].strip()
            if not line:
                continue
        data += 1

        # adblock: ||example.com^
        if line.startswith("||"):
            match = re.fullmatch(r"\|\|([^\^/$|]+)\^?(\$.*)?", line)
            if match:
                net = to_network(match.group(1))
                name = as_domain(match.group(1))
                if net is not None:
                    ip_lines.append((net, None, False))
                elif name:
                    add_domain(name, "adblock rules")
            continue

        # dnsmasq: address=/example.com/0.0.0.0
        match = re.match(r"(?:address|server|local)=/([^/]+)/", line)
        if match:
            name = as_domain(match.group(1))
            if name:
                add_domain(name, "dnsmasq rules")
            continue

        tokens = [t.strip("\"'") for t in re.split(r"[\s,]+", line)]
        tokens = [t for t in tokens if t]
        if not tokens:
            continue

        # start and end of a range: "a b", "a-b" or "a - b"
        first = last = None
        if "-" in tokens[0] and not tokens[0].startswith("-"):
            left, _, right = tokens[0].partition("-")
            first, last = plain_ip(left), plain_ip(right)
        elif len(tokens) >= 3 and tokens[1] == "-":
            first, last = plain_ip(tokens[0]), plain_ip(tokens[2])
        elif len(tokens) >= 2:
            first, last = plain_ip(tokens[0]), plain_ip(tokens[1])
        if first is not None and last is not None:
            span = expand_range(first, last)
            ip_lines.append((to_network(str(first)), span, True))
            ranges += span is not None
            continue

        # hosts file: 0.0.0.0 example.com
        if tokens[0] in SINKHOLES and len(tokens) >= 2:
            names = [n for n in map(as_domain, tokens[1:]) if n]
            if names:
                for name in names:
                    add_domain(name, "hosts file")
                continue

        net = next((n for n in map(token_network, tokens) if n is not None), None)
        if net is not None:
            ip_lines.append((net, None, False))
            continue

        for token in tokens[:3]:
            name = token_domain(token)
            if name:
                add_domain(name, "URL list" if "://" in token else "plain list")
                break

    found = len(ip_lines) + len(domain_lines)
    if not found:
        raise FeedError("no addresses or domains found")
    # An error page or a changed layout shows up as mostly unreadable lines.
    if found < data / 2:
        raise FeedError(f"only {found} of {data} lines could be read")

    if len(domain_lines) > len(ip_lines):
        style = max(styles, key=styles.get)
        return Parsed("domain", style, domains=domain_lines)

    # Two addresses on a line only mean "from here to there" when nearly the
    # whole file reads as sensible ranges. Otherwise (a source and destination
    # column, say) the first address is the entry.
    use_ranges = force_range or (ranges and ranges >= 0.9 * len(ip_lines))
    nets: list[Network] = []
    for single, span, is_range in ip_lines:
        if use_ranges and is_range:
            nets.extend(span or [])     # a reversed or oversized range is dropped
        elif single is not None:
            nets.append(single)
    if not nets:
        raise FeedError("no usable addresses found")
    return Parsed("ip", "start-end ranges" if use_ranges else "plain list", nets=nets)


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


def clean(nets: list[Network], domains: list[str],
          allow_nets: list[Network], allow_domains: set[str]) -> dict[str, list]:
    """Filter, dedupe and merge. Returns {"v4": [...], "v6": [...], "domains": [...]}."""
    out: dict[str, list] = {}
    for version in (4, 6):
        chosen = [n for n in nets if n.version == version and is_safe(n)]
        chosen = carve(chosen, allow_nets)
        out[f"v{version}"] = list(ipaddress.collapse_addresses(chosen))

    def allowed(name: str) -> bool:
        return any(name == a or name.endswith("." + a) for a in allow_domains)

    out["domains"] = sorted({d for d in domains if not allowed(d)})
    return out


def guess_group(data: dict[str, list]) -> str | None:
    """core for lists of networks, inbound for lists of single hosts.

    Network feeds (Spamhaus DROP and the like) name whole ranges under
    criminal control and are safe to block both ways. Host feeds are single
    machines caught misbehaving, which is only reliable for inbound traffic.
    """
    nets = data["v4"] + data["v6"]
    if not nets:
        return None
    wide = sum(1 for n in nets if n.prefixlen <= (24 if n.version == 4 else 64))
    return "core" if wide * 2 >= len(nets) else "inbound"


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------

def list_files(name: str, kind: str) -> list[Path]:
    base = f"{name}-{kind}"
    first = OUT_DIR / f"{base}.txt"
    parts = sorted(OUT_DIR.glob(f"{base}-part*.txt"),
                   key=lambda p: int(re.search(r"part(\d+)", p.name).group(1)))
    return ([first] if first.exists() else []) + parts


def show(item) -> str:
    if isinstance(item, str):
        return item
    return str(item.network_address) if item.prefixlen == item.max_prefixlen else str(item)


def write_list(name: str, kind: str, items: list) -> list[str]:
    """Write one list, splitting past the UniFi cap. Returns the file names."""
    base = f"{name}-{kind}"
    chunks = [items[i:i + MAX_ENTRIES] for i in range(0, len(items), MAX_ENTRIES)]
    written: list[Path] = []
    for index, chunk in enumerate(chunks, 1):
        path = OUT_DIR / (f"{base}.txt" if index == 1 else f"{base}-part{index}.txt")
        path.write_text("\n".join(show(i) for i in chunk) + "\n")
        written.append(path)
    for stale in list_files(name, kind):
        if stale not in written:
            stale.unlink()
    return [p.name for p in written]


def read_previous(name: str) -> dict[str, list] | None:
    """Load the last published copy of a feed, or None if there is none."""
    found: dict[str, list] = {kind: [] for kind in KINDS}
    for kind in KINDS:
        for path in list_files(name, kind):
            for line in path.read_text().split():
                item = line if kind == "domains" else to_network(line)
                if item is not None:
                    found[kind].append(item)
    return found if any(found.values()) else None


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def build() -> int:
    entries = load_config()
    if not entries:
        sys.exit("feeds.conf has no feeds turned on")
    allow_nets, allow_domains = load_allowlist()
    OUT_DIR.mkdir(exist_ok=True)

    feeds: dict[str, list[Entry]] = {}
    for entry in entries:
        feeds.setdefault(entry.name, []).append(entry)

    rows: list[dict] = []
    merged: dict[str, dict[str, list]] = {}
    failures: list[str] = []

    for name, sources in feeds.items():
        wanted = sources[0].group
        row = {"name": name, "urls": [s.url for s in sources], "files": [],
               "notice": "", "detected": ""}
        try:
            nets, domains, labels, notices = [], [], [], []
            for source in sources:
                parsed = parse(fetch(source.url), source.fmt)
                nets += parsed.nets
                domains += parsed.domains
                labels.append(parsed.label)
                if parsed.notice:
                    notices.append(parsed.notice)
            data = clean(nets, domains, allow_nets, allow_domains)
            if not any(data.values()):
                raise FeedError("nothing left after filtering")
            row["status"] = "ok"
            row["detected"] = "; ".join(dict.fromkeys(labels))
            row["notice"] = "; ".join(dict.fromkeys(notices))
            for kind in KINDS:
                row["files"] += write_list(name, kind, data[kind])
        except FeedError as exc:
            # Keep whatever was published last time rather than emptying the
            # list: an empty file would silently switch the protection off.
            failures.append(f"{name}: {exc}")
            note("warning title=Feed failed", f"{name}: {exc}")
            data = read_previous(name)
            row["status"] = "FAILED, kept previous copy" if data else "FAILED, no data"
            if data is None:
                data = {kind: [] for kind in KINDS}
            else:
                for kind in KINDS:
                    row["files"] += [p.name for p in list_files(name, kind)]

        group = guess_group(data) if wanted == "auto" else wanted
        shown = []
        if data["v4"] or data["v6"]:
            shown.append(f"{group} (auto)" if wanted == "auto" else group)
            if group in ("core", "inbound"):
                bucket = merged.setdefault(group, {kind: [] for kind in KINDS})
                bucket["v4"] += data["v4"]
                bucket["v6"] += data["v6"]
        if data["domains"]:
            shown.append("none" if wanted == "none" else "domains")
            if wanted != "none":
                bucket = merged.setdefault("domains", {kind: [] for kind in KINDS})
                bucket["domains"] += data["domains"]
        row["group"] = ", ".join(dict.fromkeys(shown)) or "-"
        row.update({kind: len(data[kind]) for kind in KINDS})
        rows.append(row)
        print(f"{name:22} {row['status']:27} {row['group']:16} "
              f"v4={row['v4']:>6} v6={row['v6']:>5} domains={row['domains']:>7}")

    for group in sorted(merged):
        prefix = "combined" if group == "domains" else f"combined-{group}"
        bucket = merged[group]
        data = clean(bucket["v4"] + bucket["v6"], bucket["domains"],
                     allow_nets, allow_domains)
        row = {"name": f"combined-{group}", "group": group, "status": "ok",
               "notice": "", "detected": "merged", "urls": [], "files": []}
        for kind in KINDS:
            row["files"] += write_list(prefix, kind, data[kind])
        row.update({kind: len(data[kind]) for kind in KINDS})
        rows.append(row)
        print(f"{row['name']:22} {'ok':27} {group:16} "
              f"v4={row['v4']:>6} v6={row['v6']:>5} domains={row['domains']:>7}")

    # Drop files left behind by feeds that were removed from feeds.conf.
    known = {f for row in rows for f in row["files"]} | {"SOURCES.md"}
    for path in OUT_DIR.glob("*"):
        if path.is_file() and path.name not in known:
            path.unlink()

    write_sources(rows)
    lines = ["| List | Detected | Group | IPv4 | IPv6 | Domains | Status |",
             "| --- | --- | --- | ---: | ---: | ---: | --- |"]
    lines += [f"| {r['name']} | {r['detected']} | {r['group']} | {r['v4']} "
              f"| {r['v6']} | {r['domains']} | {r['status']} |" for r in rows]
    if failures:
        lines += ["", "**Failed feeds**", ""] + [f"- {f}" for f in failures]
    summary(lines)

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
        "| List | Detected | Group | IPv4 | IPv6 | Domains | Status | Source |",
        "| --- | --- | --- | ---: | ---: | ---: | --- | --- |",
    ]
    for row in rows:
        source = "<br>".join(row["urls"]) if row["urls"] else "merged from the feeds in this group"
        if row["notice"]:
            source += f"<br>{row['notice']}"
        lines.append(f"| {row['name']} | {row['detected']} | {row['group']} | {row['v4']} "
                     f"| {row['v6']} | {row['domains']} | {row['status']} | {source} |")
    lines += [
        "",
        "Spamhaus DROP data is provided by The Spamhaus Project. Terms:",
        "https://www.spamhaus.org/drop/terms/",
        "",
    ]
    (OUT_DIR / "SOURCES.md").write_text("\n".join(lines))


def describe(url: str, allow_nets, allow_domains) -> tuple[Parsed, dict, list[str]]:
    """Download a URL and describe what it would produce."""
    parsed = parse(fetch(url))
    data = clean(parsed.nets, parsed.domains, allow_nets, allow_domains)
    if not any(data.values()):
        raise FeedError("nothing left after filtering")
    group = "domains" if parsed.kind == "domain" else guess_group(data)
    read = len(parsed.nets) + len(parsed.domains)
    kept = ", ".join(f"{len(data[k])} {k}" for k in KINDS if data[k])
    sample = ", ".join(show(i) for k in KINDS for i in data[k][:3])
    report = [
        f"{url}",
        f"  detected   {parsed.label}",
        f"  entries    {read} read, kept {kept}",
        f"  group      {group}",
        f"  sample     {sample}",
    ]
    return parsed, data, report


def split_args(values: list[str]) -> list[str]:
    """Accept URLs as separate arguments or as one space-separated string."""
    parts = [part for value in values for part in value.split()]
    return list(dict.fromkeys(normalize_url(part) for part in parts))


def cmd_check(urls: list[str]) -> int:
    allow_nets, allow_domains = load_allowlist()
    failed = 0
    out = []
    for url in urls:
        try:
            problem = url_problem(url)
            if problem:
                raise FeedError(problem)
            _, _, report = describe(url, allow_nets, allow_domains)
            report.insert(1, f"  name       {auto_name(url)}")
        except FeedError as exc:
            failed += 1
            note("error title=Feed rejected", f"{url}: {exc}")
            report = [url, f"  REJECTED   {exc}"]
        print("\n".join(report) + "\n")
        out += report + [""]
    summary(["```"] + out + ["```"])
    return 1 if failed else 0


def cmd_add(urls: list[str], group: str) -> int:
    entries = load_config()
    allow_nets, allow_domains = load_allowlist()
    known = {e.url for e in entries}
    used = {e.name for e in entries}
    new_lines, out, failed = [], [], 0

    for url in urls:
        if url in known:
            print(f"{url}\n  already in feeds.conf, skipped\n")
            continue
        try:
            problem = url_problem(url)
            if problem:
                raise FeedError(problem)
            _, _, report = describe(url, allow_nets, allow_domains)
        except FeedError as exc:
            failed += 1
            note("error title=Feed rejected", f"{url}: {exc}")
            report = [url, f"  REJECTED   {exc}"]
        else:
            name = unique(auto_name(url), used)
            used.add(name)
            known.add(url)
            report.insert(1, f"  name       {name}")
            new_lines.append(f"{url}  name={name}"
                             + (f"  group={group}" if group != "auto" else ""))
        print("\n".join(report) + "\n")
        out += report + [""]

    summary(["```"] + out + ["```"])
    if failed:
        print("Nothing was added because at least one URL was rejected.")
        return 1
    if new_lines:
        text = FEEDS_FILE.read_text()
        if not text.endswith("\n"):
            text += "\n"
        FEEDS_FILE.write_text(text + "\n".join(new_lines) + "\n")
        print(f"Added {len(new_lines)} feed(s) to feeds.conf.")
    return 0


def cmd_remove(targets: list[str]) -> int:
    entries = load_config()
    missing = [t for t in targets if not any(t in (e.url, e.name) for e in entries)]
    if missing:
        for target in missing:
            note("error title=Not found", f"{target} is not a URL or name in feeds.conf")
        return 1
    drop = {e.line for e in entries if e.url in targets or e.name in targets}
    lines = FEEDS_FILE.read_text().splitlines()
    FEEDS_FILE.write_text("\n".join(l for i, l in enumerate(lines) if i not in drop) + "\n")
    gone = sorted({e.name for e in entries if e.line in drop})
    print(f"Removed {len(drop)} line(s): {', '.join(gone)}")
    summary([f"Removed: {', '.join(gone)}"])
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("build", help="rebuild every list (the default)")
    check = sub.add_parser("check", help="show what a URL would produce")
    check.add_argument("urls", nargs="+")
    add = sub.add_parser("add", help="test URLs, then add them to feeds.conf")
    add.add_argument("urls", nargs="+")
    add.add_argument("--group", default="auto", choices=sorted(GROUPS))
    remove = sub.add_parser("remove", help="take feeds out of feeds.conf")
    remove.add_argument("targets", nargs="+", metavar="URL_OR_NAME")
    args = parser.parse_args()

    if args.command == "check":
        return cmd_check(split_args(args.urls))
    if args.command == "add":
        return cmd_add(split_args(args.urls), args.group)
    if args.command == "remove":
        return cmd_remove(split_args(args.targets))
    return build()


if __name__ == "__main__":
    sys.exit(main())
