# UniFi threat feeds

A GitHub Action that downloads public threat feeds once a day, cleans them
into the plain format UniFi Dynamic Network Lists need, and commits the
results to this repo so every list has a stable URL.

UniFi wants one IP or CIDR per line, one address family per list, no
comments, and at most 100,000 entries. Most feeds do not ship that way
(Spamhaus DROP is JSON, FireHOL has comment headers and private ranges,
DShield is a table), so the script converts them.

## Setup

1. Create a new **public** repository on GitHub. It has to be public so the
   gateway can download the files without a login.
2. Upload the contents of this folder, keeping the folder structure
   (`.github/workflows/update-feeds.yml` must stay at that exact path).
3. Open the **Actions** tab. The first run starts on its own after the
   upload. If it does not, pick **Update threat feeds** and press
   **Run workflow**.
4. When the run finishes, a `lists/` folder appears. Your URLs look like:

   ```
   https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/lists/combined-core-v4.txt
   ```

After that it runs every day at 03:17 UTC and commits only when a list
changed.

## What you get

| File | Contents | Block direction |
| --- | --- | --- |
| `combined-core-v4.txt`, `combined-core-v6.txt` | Spamhaus DROP, FireHOL Level 1, Emerging Threats block IPs, DShield, Feodo Tracker, merged and deduplicated | Both |
| `combined-inbound-v4.txt`, `combined-inbound-v6.txt` | IPsum level 3, blocklist.de, CINS Army, Emerging Threats compromised, Binary Defense, GreenSnow, merged and deduplicated | Inbound only |
| `spamhaus-drop-v4.txt`, `spamhaus-drop-v6.txt` | Spamhaus DROP on its own | Both |
| `<feed>-v4.txt`, `<feed>-v6.txt` | Every other feed on its own | See its group |
| `SOURCES.md` | Entry counts, status and credits for every list | |

The simplest setup uses just the four `combined-*` files.

The **core** lists are whole networks run by criminal operations, with very
few false positives. The **inbound** lists are single hosts caught scanning
or brute-forcing. Those addresses get reassigned and shared, so blocking
your own users from reaching them is more likely to break something than
help.

## Add the lists in UniFi

Needs UniFi Network 11.0.83 or later, UniFi OS 6.0.10 or later, and the
zone-based firewall.

For each file you want:

1. **Networks > Network Lists > Create New**
2. **Type** IP (pick IPv4 or IPv6 to match the file), **Source** Dynamic
3. Paste the raw URL, set refresh to **24 hours**, save
4. Open the list and check that entries loaded

Then add Block policies in the firewall policy table, above any allow rules
for the same traffic:

| List | Source zone | Destination zone | List goes in |
| --- | --- | --- | --- |
| core and inbound | External | Internal | Source |
| core and inbound | External | Gateway | Source |
| core only | Internal | External | Destination |

Turn on logging for the policies at first so you can see what they catch.

## Change which feeds are used

Edit `feeds.conf`. Each line is `name group format url`. Put a `#` in front
of a line to turn a feed off, or add a line to add one. The comments at the
top of the file explain the columns. Committing the change triggers a
rebuild.

## Keep an address from ever being blocked

Add it to `allowlist.txt`, one IP or CIDR per line. The script carves it out
of every list, even when a feed lists a larger network around it. Add your
own public IP and anything you cannot afford to lose access to.

## Safety behavior

- **A failed feed keeps its last good copy.** If a download fails or returns
  junk, the previous file stays in place and the run shows a warning. An
  empty list would silently turn the protection off.
- **Private and reserved ranges are removed.** FireHOL Level 1 includes
  ranges such as 10.0.0.0/8 and 192.168.0.0/16. Blocking those on a gateway
  can cut off an upstream modem or a carrier NAT link.
- **Very broad networks are refused** (wider than /8 for IPv4, /19 for
  IPv6), so a bad feed cannot block the whole internet.
- **Lists over 100,000 entries are split** into `-part2`, `-part3` files.
  Add each part as its own Network List.
- **Adjacent addresses are merged** into CIDR blocks that cover exactly the
  same addresses, which keeps the entry count down.

## Run it locally

```
python3 scripts/build_lists.py
```

Python 3.10 or later, no packages to install.

## Credits and terms

Every feed belongs to its publisher and comes with its own terms of use.
This repo republishes cleaned copies, so read the terms for each feed you
leave turned on in `feeds.conf` and turn off any you are not comfortable
republishing. Spamhaus asks for credit and for no more than one download a
day; `lists/SOURCES.md` carries the credit and the schedule respects the
limit. Spamhaus terms: https://www.spamhaus.org/drop/terms/
