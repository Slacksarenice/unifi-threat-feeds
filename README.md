# unifi-threat-feeds

Public IP blocklists, converted into files a UniFi gateway can import as
Dynamic Network Lists. A GitHub Action rebuilds them once a day.

UniFi Network 11 can load a network list from a URL, but it is strict about
the file: one IP or CIDR per line, no comments, IPv4 and IPv6 kept in
separate lists, and no more than 100,000 entries. Most of the well-known
feeds are not published that way. Spamhaus DROP is JSON, FireHOL has a
comment header and includes private ranges, DShield is a tab-separated
table. This repo downloads them, converts them, and commits the output to
[`lists/`](lists).

## Lists

There are two merged lists, each in an IPv4 and an IPv6 file. These are the
ones to use unless you want to pick feeds individually.

| List | Size | What is in it |
| --- | --- | --- |
| `combined-core` | about 4,600 networks | Spamhaus DROP, FireHOL Level 1, Emerging Threats block IPs, DShield, Feodo Tracker |
| `combined-inbound` | about 31,000 hosts | IPsum level 3, blocklist.de, CINS Army, Emerging Threats compromised IPs, Binary Defense, GreenSnow |

```
https://raw.githubusercontent.com/Slacksarenice/unifi-threat-feeds/main/lists/combined-core-v4.txt
https://raw.githubusercontent.com/Slacksarenice/unifi-threat-feeds/main/lists/combined-core-v6.txt
https://raw.githubusercontent.com/Slacksarenice/unifi-threat-feeds/main/lists/combined-inbound-v4.txt
https://raw.githubusercontent.com/Slacksarenice/unifi-threat-feeds/main/lists/combined-inbound-v6.txt
```

The core list is made of whole networks that are run by or leased to
criminal operations. False positives are rare, so it is reasonable to block
it in both directions.

The inbound list is individual hosts that were recently seen scanning or
brute-forcing. Those addresses get reassigned and are often shared, so it
is meant for traffic coming in from the internet. Blocking LAN clients from
reaching them tends to break legitimate sites now and then.

Every feed is also published separately as `lists/<feed>-v4.txt` and
`lists/<feed>-v6.txt`, for example `spamhaus-drop-v4.txt`. Current entry
counts and the status of the last build are in
[`lists/SOURCES.md`](lists/SOURCES.md).

## Using them on a UniFi gateway

Requires UniFi Network 11.0.83 or newer on UniFi OS 6.0.10 or newer, with
the zone-based firewall.

Create one network list per file under Networks > Network Lists > Create
New. Set Type to IP with the matching address family, set Source to
Dynamic, paste the raw URL, and choose a 24 hour refresh. Open the list
afterwards to make sure the entries loaded.

A list does nothing until a firewall policy uses it. Add Block policies
above any allow rules that cover the same traffic:

| Source zone | Destination zone | List used as | Lists |
| --- | --- | --- | --- |
| External | Internal | source | core, inbound |
| External | Gateway | source | core, inbound |
| Internal | External | destination | core |

Logging on these policies is worth enabling for the first few days.

## Feeds

Feeds are defined in [`feeds.conf`](feeds.conf), one per line: name, group,
format, URL. Comment a line out to drop a feed, or add a line for a new
one. The supported formats are `text` (one IP or CIDR per line, with `#`
and `;` comments ignored), `range` (start and end address in the first two
columns), and `spamhaus-json`. The group decides which combined list a feed
is merged into: `core`, `inbound`, or `none`.

[`allowlist.txt`](allowlist.txt) holds addresses that must never be
published. They are removed from every list, and if a feed lists a larger
network around one of them, that network is split so the rest of it stays
blocked. It ships with a few public DNS resolvers. If you fork this, add
your own public IP.

Pushing a change to either file triggers a rebuild.

## Build details

[`scripts/build_lists.py`](scripts/build_lists.py) does the work. It needs
Python 3.10 or newer and nothing outside the standard library:

```
python3 scripts/build_lists.py
```

Things it does besides reformatting:

- Drops private and reserved address space. FireHOL Level 1 lists ranges
  such as 10.0.0.0/8 and 192.168.0.0/16, which can cut off an upstream
  modem or a CGNAT link if a gateway blocks them.
- Rejects anything wider than a /8 (IPv4) or a /19 (IPv6), so a broken feed
  cannot block most of the internet.
- Merges adjacent addresses into CIDR blocks. The merged blocks cover
  exactly the same addresses as the input.
- Keeps the previous copy of a feed when its download fails or comes back
  as something other than a list of addresses. The failure shows up as a
  warning on the workflow run and in `SOURCES.md`.
- Splits any list that grows past 100,000 entries into `-part2`, `-part3`
  and so on.

The workflow in
[`.github/workflows/update-feeds.yml`](.github/workflows/update-feeds.yml)
runs at 03:17 UTC and only commits when something changed.

## Credits

The data belongs to the projects that publish it, and each has its own
terms of use:

- [Spamhaus DROP](https://www.spamhaus.org/drop/) ([terms](https://www.spamhaus.org/drop/terms/))
- [FireHOL IP lists](https://iplists.firehol.org/)
- [Emerging Threats](https://rules.emergingthreats.net/)
- [DShield](https://www.dshield.org/)
- [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/)
- [IPsum](https://github.com/stamparm/ipsum)
- [blocklist.de](https://www.blocklist.de/)
- [CINS Army](https://cinsscore.com/)
- [Binary Defense](https://www.binarydefense.com/)
- [GreenSnow](https://greensnow.co/)

Spamhaus asks for attribution and for no more than one download per day.
The build runs once daily, and the copyright notice from the Spamhaus feed
is carried into `lists/SOURCES.md` because the list files themselves cannot
hold comments.
