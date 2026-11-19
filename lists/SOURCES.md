# Sources

These lists are cleaned copies of third-party threat feeds. Each feed
remains the work of its publisher and is subject to that publisher's
terms of use. The list files carry no comments because UniFi cannot
parse them, so the credits live here instead.

| List | Detected | Group | IPv4 | IPv6 | Domains | Status | Source |
| --- | --- | --- | ---: | ---: | ---: | --- | --- |
| spamhaus-drop | IPs, JSON | core (auto) | 1612 | 84 | 0 | ok | https://www.spamhaus.org/drop/drop_v4.json<br>https://www.spamhaus.org/drop/drop_v6.json<br>(c) 2026 The Spamhaus Project SLU, data of 2026-11-18 12:56 UTC; (c) 2026 The Spamhaus Project SLU, data of 2026-11-19 02:56 UTC |
| firehol-level1 | IPs, plain list | core (auto) | 4622 | 0 | 0 | ok | https://iplists.firehol.org/files/firehol_level1.netset |
| et-block-ips | IPs, plain list | core (auto) | 1628 | 0 | 0 | ok | https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt |
| dshield | IPs, start-end ranges | core (auto) | 20 | 0 | 0 | ok | https://feeds.dshield.org/block.txt |
| feodo-tracker | IPs, plain list | core | 5 | 0 | 0 | ok | https://feodotracker.abuse.ch/downloads/ipblocklist.txt |
| ipsum-level3 | IPs, plain list | inbound (auto) | 13967 | 0 | 0 | ok | https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt |
| blocklist-de | IPs, plain list | inbound (auto) | 16584 | 307 | 0 | ok | https://lists.blocklist.de/lists/all.txt |
| cins-army | IPs, plain list | inbound (auto) | 13560 | 0 | 0 | ok | https://cinsscore.com/list/ci-badguys.txt |
| et-compromised | IPs, plain list | inbound (auto) | 582 | 0 | 0 | ok | https://rules.emergingthreats.net/blockrules/compromised-ips.txt |
| binarydefense | IPs, plain list | inbound (auto) | 707 | 0 | 0 | ok | https://www.binarydefense.com/banlist.txt |
| greensnow | IPs, plain list | inbound (auto) | 2053 | 0 | 0 | ok | https://blocklist.greensnow.co/greensnow.txt |
| combined-all | merged | all | 36699 | 391 | 0 | ok | merged from the feeds in this group |
| combined-core | merged | core | 4640 | 84 | 0 | ok | merged from the feeds in this group |
| combined-inbound | merged | inbound | 33524 | 307 | 0 | ok | merged from the feeds in this group |

Spamhaus DROP data is provided by The Spamhaus Project. Terms:
https://www.spamhaus.org/drop/terms/
