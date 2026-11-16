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

There are three merged lists, each in an IPv4 and an IPv6 file. These are
the ones to use unless you want to pick feeds individually.

| List | Size | What is in it |
| --- | --- | --- |
| `combined-core` | about 4,600 networks | Spamhaus DROP, FireHOL Level 1, Emerging Threats block IPs, DShield, Feodo Tracker |
| `combined-inbound` | about 31,000 hosts | IPsum level 3, blocklist.de, CINS Army, Emerging Threats compromised IPs, Binary Defense, GreenSnow |
| `combined-all` | about 34,500 entries | Core and inbound together, for policies on traffic coming in |

```
https://raw.githubusercontent.com/Slacksarenice/unifi-threat-feeds/main/lists/combined-all-v4.txt
https://raw.githubusercontent.com/Slacksarenice/unifi-threat-feeds/main/lists/combined-all-v6.txt
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

A list does nothing until a firewall policy uses it, and a policy covers
one zone pair, one list and one address family. To keep the number of
policies down, use `combined-all` for traffic coming in and `combined-core`
for traffic going out. Add Block policies above any allow rules that cover
the same traffic:

| Source zone | Destination zone | List used as | List |
| --- | --- | --- | --- |
| each internal zone | External | destination | `combined-core` |
| External | Gateway | source | `combined-all` |
| External | each zone with a port forward | source | `combined-all` |

The first row is the one that matters on every network. The other two only
do something where the gateway already lets traffic in: a VPN server or
other service on the gateway itself, or a port forward. Everything else
arriving from External is dropped by the default policy before a blocklist
would be consulted. The IPv6 files can be skipped on a network that does not
use IPv6.

Logging on these policies is worth enabling for the first few days.

## Feeds

[`feeds.conf`](feeds.conf) is a list of URLs, one per line. A bare URL is
all a feed needs. On each run the build downloads it and works out:

- the format: JSON, a plain list, CSV with an address column, start-end
  ranges, a hosts file, adblock or dnsmasq rules, or a list of URLs
- the type: IPv4, IPv6 or domains, with one output file per type
- the group: `core` when most entries are networks (/24 or larger),
  `inbound` when they are single hosts, `domains` for domain feeds
- the name, from the site or repository plus the file name

The result of that detection is shown per feed in `lists/SOURCES.md`.

Any of it can be pinned by adding `name=`, `group=` or `format=` after the
URL. Lines that share a name are merged into one feed, which is how the
Spamhaus IPv4 and IPv6 files end up as `spamhaus-drop`. Feodo Tracker is
pinned to `core` because it is a list of single hosts that would otherwise
be filed under `inbound`, and the reason to carry it is to stop LAN clients
from reaching botnet controllers.

### Adding and removing feeds

Editing `feeds.conf` and pushing works. So does the Actions tab: open
**Update threat feeds**, press **Run workflow**, and pick an action.

| Action | What it does |
| --- | --- |
| `rebuild` | Rebuilds every list now |
| `add` | Downloads each URL, checks that it parses, then adds it to `feeds.conf` and rebuilds. If any URL fails, nothing is added |
| `remove` | Removes feeds by URL or by name, rebuilds, and deletes their files |
| `test` | Reports what each URL would produce (type, format, entry count, group, a few sample entries) without changing anything |

URLs go in the second field, separated by spaces. The run summary shows
what was detected. A link to a file page on github.com is rewritten to its
raw form.

The same commands work from a checkout:

```
python3 scripts/build_lists.py check https://example.com/list.txt
python3 scripts/build_lists.py add https://example.com/list.txt
python3 scripts/build_lists.py remove example-list
```

Do not add a URL that contains an API key or token. This repo is public,
so the key would be too, and `add` refuses URLs that look like they carry
one.

### Domain feeds

A feed made of domains is written to `lists/<feed>-domains.txt` and merged
into `lists/combined-domains.txt`. None are enabled by default. In UniFi a
domain list is created with Type set to Domain. Keep in mind that a
firewall policy using a domain list blocks the addresses those names
resolve to, so a domain hosted behind a shared CDN can take unrelated sites
down with it.

### Allowlist

[`allowlist.txt`](allowlist.txt) holds addresses and domains that must
never be published. IPs are removed from every list, and if a feed lists a
larger network around one of them, that network is split so the rest of it
stays blocked. A domain entry also covers its subdomains. The file ships
with a few public DNS resolvers. If you fork this, add your own public IP.

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
  as something other than a list of addresses or domains. The failure shows up as a
  warning on the workflow run and in `SOURCES.md`.
- Splits any list that grows past 100,000 entries into `-part2`, `-part3`
  and so on.

The workflow in
[`.github/workflows/update-feeds.yml`](.github/workflows/update-feeds.yml)
runs at 03:17 UTC and only commits when something changed. Every run
downloads every feed again, so manual runs are best kept occasional.

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
