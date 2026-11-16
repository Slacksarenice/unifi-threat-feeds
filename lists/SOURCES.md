# Sources

These lists are cleaned copies of third-party threat feeds. Each feed
remains the work of its publisher and is subject to that publisher's
terms of use. The list files carry no comments because UniFi cannot
parse them, so the credits live here instead.

| List | Detected | Group | IPv4 | IPv6 | Domains | Status | Source |
| --- | --- | --- | ---: | ---: | ---: | --- | --- |
| spamhaus-drop | IPs, JSON | core (auto) | 1621 | 84 | 0 | ok | https://www.spamhaus.org/drop/drop_v4.json<br>https://www.spamhaus.org/drop/drop_v6.json<br>(c) 2026 The Spamhaus Project SLU, data of 2026-11-14 13:56 UTC; (c) 2026 The Spamhaus Project SLU, data of 2026-11-13 15:56 UTC |
| firehol-level1 | IPs, plain list | core (auto) | 4634 | 0 | 0 | ok | https://iplists.firehol.org/files/firehol_level1.netset |
| et-block-ips | IPs, plain list | core (auto) | 1643 | 0 | 0 | ok | https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt |
| dshield | IPs, start-end ranges | core (auto) | 19 | 0 | 0 | ok | https://feeds.dshield.org/block.txt |
| feodo-tracker | IPs, plain list | core | 5 | 0 | 0 | ok | https://feodotracker.abuse.ch/downloads/ipblocklist.txt |
| ipsum-level3 | IPs, plain list | inbound (auto) | 13013 | 0 | 0 | ok | https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt |
| blocklist-de | IPs, plain list | inbound (auto) | 12709 | 226 | 0 | ok | https://lists.blocklist.de/lists/all.txt |
| cins-army | IPs, plain list | inbound (auto) | 13845 | 0 | 0 | ok | https://cinsscore.com/list/ci-badguys.txt |
| et-compromised | IPs, plain list | inbound (auto) | 578 | 0 | 0 | ok | https://rules.emergingthreats.net/blockrules/compromised-ips.txt |
| binarydefense | IPs, plain list | inbound (auto) | 1069 | 0 | 0 | ok | https://www.binarydefense.com/banlist.txt |
| greensnow |  | - | 0 | 0 | 0 | FAILED, no data | https://blocklist.greensnow.co/greensnow.txt |
| combined-all | merged | all | 34483 | 310 | 0 | ok | merged from the feeds in this group |
| combined-core | merged | core | 4644 | 84 | 0 | ok | merged from the feeds in this group |
| combined-inbound | merged | inbound | 30929 | 226 | 0 | ok | merged from the feeds in this group |

Spamhaus DROP data is provided by The Spamhaus Project. Terms:
https://www.spamhaus.org/drop/terms/
