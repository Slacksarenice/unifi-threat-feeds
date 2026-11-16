#!/usr/bin/env python3
"""Create the UniFi firewall policies that put threat feed lists to use.

A UniFi block policy covers one zone pair, one list and one address family,
so blocking a few lists across every zone means clicking through dozens of
near-identical policies. This script asks the gateway for its zones and IP
lists, shows the policies it would create, and creates them once you confirm.

    python3 unifi_policies.py                 answer a few questions
    python3 unifi_policies.py --dry-run       show the plan, change nothing
    python3 unifi_policies.py --remove        delete the policies it created

Needs Python 3.8 or newer and nothing else. It talks to the official UniFi
Network API on your gateway with an API key, which you create under
Settings > Control Plane > Integrations. The key is used for this run only
and is never written to disk.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKER = "Created by the unifi-threat-feeds helper"
PREFIX = "ThreatFeed"
IP_LIST_TYPES = {"IPV4_ADDRESSES": "IPV4", "IPV6_ADDRESSES": "IPV6"}
FAMILY_LABEL = {"IPV4_ADDRESSES": "IPv4", "IPV6_ADDRESSES": "IPv6"}


class ApiError(Exception):
    pass


class Api:
    """Minimal client for the UniFi Network integration API."""

    def __init__(self, gateway: str, api_key: str, api_path: str, insecure: bool):
        gateway = gateway.strip().rstrip("/")
        if "://" not in gateway:
            gateway = "https://" + gateway
        self.base = gateway + "/" + api_path.strip("/")
        self.api_key = api_key
        self.context = ssl.create_default_context()
        if insecure:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        self.site = ""

    def call(self, method: str, path: str, query: dict | None = None, body=None):
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        headers = {"X-API-KEY": self.api_key, "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30, context=self.context) as response:
                text = response.read().decode() or "{}"
                return json.loads(text)
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")
            try:
                detail = json.loads(detail).get("message") or detail
            except ValueError:
                pass
            if error.code in (401, 403):
                detail = f"{detail} (check the API key)"
            raise ApiError(f"{method} {path} failed with HTTP {error.code}: {detail}") from None
        except urllib.error.URLError as error:
            reason = error.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise ApiError(
                    "The gateway's certificate is not trusted. That is normal for a "
                    "gateway using its built-in certificate.\n"
                    "Run again with --insecure to skip the certificate check.") from None
            raise ApiError(f"Could not reach {self.base}: {reason}") from None

    def everything(self, path: str) -> list:
        """Read every page of a list endpoint."""
        items: list = []
        while True:
            page = self.call("GET", path, {"offset": len(items), "limit": 200})
            items += page.get("data", [])
            if not page.get("data") or len(items) >= page.get("totalCount", 0):
                return items

    def site_path(self, rest: str) -> str:
        return f"/v1/sites/{self.site}{rest}"


def count(number: int) -> str:
    return "1 policy" if number == 1 else f"{number} policies"


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        sys.exit("\nNo answer given. Use the command line options to run without prompts.")


def confirm(question: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    return ask(f"{question} [y/N] ").lower() in ("y", "yes")


def split_names(values: list[str] | None) -> list[str]:
    """Accept names repeated or comma-separated: --outbound "A,B" --outbound C."""
    names = [part.strip() for value in values or [] for part in value.split(",")]
    return [name for name in names if name]


def find_by_name(items: list[dict], names: list[str], what: str) -> list[dict]:
    lookup = {item["name"].lower(): item for item in items}
    missing = [name for name in names if name.lower() not in lookup]
    if missing:
        known = ", ".join(sorted(item["name"] for item in items)) or "none"
        sys.exit(f"No {what} named: {', '.join(missing)}\nThe gateway has: {known}")
    return [lookup[name.lower()] for name in names]


def pick_lists(lists: list[dict], question: str) -> list[dict]:
    while True:
        answer = ask(question)
        if not answer:
            return []
        try:
            numbers = [int(part) for part in answer.replace(",", " ").split()]
            if all(1 <= number <= len(lists) for number in numbers):
                return [lists[number - 1] for number in dict.fromkeys(numbers)]
        except ValueError:
            pass
        print(f"  Enter numbers from 1 to {len(lists)}, separated by spaces.")


def choose_site(api: Api, wanted: str | None) -> dict:
    sites = api.everything("/v1/sites")
    if not sites:
        sys.exit("The gateway reported no sites.")
    if wanted:
        matches = [s for s in sites
                   if wanted.lower() in (s["name"].lower(), s.get("internalReference", "").lower())]
        if not matches:
            sys.exit(f"No site named {wanted}. Sites: {', '.join(s['name'] for s in sites)}")
        return matches[0]
    if len(sites) == 1:
        return sites[0]
    print("Sites:")
    for number, site in enumerate(sites, 1):
        print(f"  {number}. {site['name']}")
    while True:
        answer = ask("Which site? ")
        if answer.isdigit() and 1 <= int(answer) <= len(sites):
            return sites[int(answer) - 1]


def build_plan(zones: list[dict], outbound: list[dict], inbound: list[dict],
               out_zones: list[dict], in_zones: list[dict], logging: bool) -> list[dict]:
    external = next((z for z in zones if z["name"].lower() == "external"), None)
    if external is None:
        sys.exit("The gateway has no zone named External, so there is nothing to plan.")
    plan = []

    def add(source: dict, destination: dict, item: dict, direction: str) -> None:
        match = {"type": "IP_ADDRESS",
                 "ipAddressFilter": {"type": "TRAFFIC_MATCHING_LIST",
                                     "trafficMatchingListId": item["id"],
                                     "matchOpposite": False}}
        body = {
            "enabled": True,
            "name": f"{PREFIX} {source['name']} to {destination['name']} - {item['name']}",
            "description": MARKER,
            "action": {"type": "BLOCK"},
            "source": {"zoneId": source["id"]},
            "destination": {"zoneId": destination["id"]},
            "ipProtocolScope": {"ipVersion": IP_LIST_TYPES[item["type"]]},
            "loggingEnabled": logging,
        }
        if direction == "out":
            body["destination"]["trafficFilter"] = match
        else:
            body["source"]["trafficFilter"] = match
            # Only refuse connections the listed address tries to open. Replies
            # to connections started from inside still get through, so a host on
            # an inbound list is not cut off from clients that reach out to it.
            body["connectionStateFilter"] = ["NEW", "INVALID"]
        plan.append({"body": body, "source": source, "destination": destination,
                     "list": item, "direction": direction})

    for item in outbound:
        for zone in out_zones:
            add(zone, external, item, "out")
    for item in inbound:
        for zone in in_zones:
            add(external, zone, item, "in")
    return plan


def show_plan(plan: list[dict], existing: set[str]) -> list[dict]:
    todo = [entry for entry in plan if entry["body"]["name"] not in existing]
    width = max((len(f"{e['source']['name']} to {e['destination']['name']}") for e in plan),
                default=0)
    for entry in plan:
        pair = f"{entry['source']['name']} to {entry['destination']['name']}"
        side = "destination" if entry["direction"] == "out" else "source"
        family = FAMILY_LABEL[entry["list"]["type"]]
        state = "  (already exists, skipped)" if entry["body"]["name"] in existing else ""
        print(f"  {pair:<{width}}  block {side} in \"{entry['list']['name']}\" ({family}){state}")
    return todo


def move_to_top(api: Api, source: dict, destination: dict, new_ids: list[str]) -> None:
    query = {"sourceFirewallZoneId": source["id"], "destinationFirewallZoneId": destination["id"]}
    path = api.site_path("/firewall/policies/ordering")
    order = api.call("GET", path, query)["orderedFirewallPolicyIds"]
    before = new_ids + [i for i in order.get("beforeSystemDefined", []) if i not in new_ids]
    after = [i for i in order.get("afterSystemDefined", []) if i not in new_ids]
    api.call("PUT", path, query, {"orderedFirewallPolicyIds": {
        "beforeSystemDefined": before, "afterSystemDefined": after}})


def remove(api: Api, assume_yes: bool, dry_run: bool) -> int:
    policies = [p for p in api.everything(api.site_path("/firewall/policies"))
                if p.get("description") == MARKER]
    if not policies:
        print("No policies created by this helper were found.")
        return 0
    print(f"Policies created by this helper ({len(policies)}):")
    for policy in policies:
        print(f"  {policy['name']}")
    if dry_run:
        print("\nDry run: nothing was deleted.")
        return 0
    if not confirm(f"\nDelete {count(len(policies))}?", assume_yes):
        print("Nothing was deleted.")
        return 0
    failed = 0
    for policy in policies:
        try:
            api.call("DELETE", api.site_path(f"/firewall/policies/{policy['id']}"))
        except ApiError as error:
            failed += 1
            print(f"  FAILED {policy['name']}: {error}")
    print(f"Deleted {count(len(policies) - failed)}." + (f" {failed} failed." if failed else ""))
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create UniFi block policies for threat feed lists, one per zone pair.")
    parser.add_argument("--gateway", default=os.environ.get("UNIFI_GATEWAY"),
                        help="gateway address, for example 192.168.1.1 (or set UNIFI_GATEWAY)")
    parser.add_argument("--api-key", default=os.environ.get("UNIFI_API_KEY"),
                        help="UniFi API key (or set UNIFI_API_KEY; asked for if missing)")
    parser.add_argument("--site", help="site name, when the gateway has more than one")
    parser.add_argument("--outbound", "--out", action="append", metavar="LIST",
                        help="list to block as a destination, from your zones to External")
    parser.add_argument("--inbound", "--in", action="append", metavar="LIST",
                        help="list to block as a source, from External to your zones")
    parser.add_argument("--outbound-zones", action="append", metavar="ZONES",
                        help="zones to protect outbound (default: all but External and Gateway)")
    parser.add_argument("--inbound-zones", action="append", metavar="ZONES",
                        help="zones to protect inbound (default: all but External)")
    parser.add_argument("--remove", action="store_true",
                        help="delete the policies this helper created")
    parser.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    parser.add_argument("--log", action="store_true", help="turn on logging for the new policies")
    parser.add_argument("--no-reorder", action="store_true",
                        help="leave new policies where the gateway puts them")
    parser.add_argument("--insecure", action="store_true",
                        help="skip the TLS certificate check (gateways use a self-signed one)")
    parser.add_argument("--api-path", default="/proxy/network/integration",
                        help=argparse.SUPPRESS)
    args = parser.parse_args()

    gateway = args.gateway or ask("Gateway address (for example 192.168.1.1): ")
    api_key = args.api_key or getpass.getpass("API key (input is hidden): ").strip()
    if not gateway or not api_key:
        sys.exit("A gateway address and an API key are both required.")

    api = Api(gateway, api_key, args.api_path, args.insecure)
    version = api.call("GET", "/v1/info").get("applicationVersion", "unknown")
    site = choose_site(api, args.site)
    api.site = site["id"]
    print(f"Connected to UniFi Network {version}, site \"{site['name']}\".\n")

    if args.remove:
        return remove(api, args.yes, args.dry_run)

    zones = api.everything(api.site_path("/firewall/zones"))
    lists = [item for item in api.everything(api.site_path("/traffic-matching-lists"))
             if item.get("type") in IP_LIST_TYPES]
    print("Zones: " + ", ".join(zone["name"] for zone in zones))
    if not lists:
        sys.exit("\nThe gateway reported no IP lists. Create them first under "
                 "Networks > Network Lists, then run this again.")
    print("IP lists:")
    for number, item in enumerate(lists, 1):
        print(f"  {number}. {item['name']} ({FAMILY_LABEL[item['type']]})")
    print()

    out_names, in_names = split_names(args.outbound), split_names(args.inbound)
    if out_names or in_names:
        outbound = find_by_name(lists, out_names, "IP list")
        inbound = find_by_name(lists, in_names, "IP list")
    else:
        print("Outbound: stops your devices reaching listed addresses. Use the core lists.")
        outbound = pick_lists(lists, "Lists to block outbound (numbers, Enter for none): ")
        print("Inbound: stops listed addresses reaching you. Use the all or inbound lists.")
        inbound = pick_lists(lists, "Lists to block inbound (numbers, Enter for none): ")
        print()
    if not outbound and not inbound:
        print("No lists chosen, so there is nothing to do.")
        return 0

    out_zone_names, in_zone_names = split_names(args.outbound_zones), split_names(args.inbound_zones)
    out_zones = (find_by_name(zones, out_zone_names, "zone") if out_zone_names else
                 [z for z in zones if z["name"].lower() not in ("external", "gateway")])
    in_zones = (find_by_name(zones, in_zone_names, "zone") if in_zone_names else
                [z for z in zones if z["name"].lower() != "external"])

    plan = build_plan(zones, outbound, inbound, out_zones, in_zones, args.log)
    existing = {p["name"] for p in api.everything(api.site_path("/firewall/policies"))}
    print(f"Plan ({count(len(plan))}):")
    todo = show_plan(plan, existing)
    print()
    if not todo:
        print("Every policy in the plan already exists.")
        return 0
    if args.dry_run:
        print(f"Dry run: {count(len(todo))} would be created. Nothing was changed.")
        return 0
    if not confirm(f"Create {count(len(todo))}?", args.yes):
        print("Nothing was changed.")
        return 0

    created: dict[tuple[str, str], list] = {}
    failed = 0
    for entry in todo:
        try:
            policy = api.call("POST", api.site_path("/firewall/policies"), body=entry["body"])
        except ApiError as error:
            failed += 1
            print(f"  FAILED {entry['body']['name']}: {error}")
            continue
        pair = (entry["source"]["id"], entry["destination"]["id"])
        created.setdefault(pair, [entry["source"], entry["destination"]]).append(policy["id"])
        print(f"  created {entry['body']['name']}")

    if not args.no_reorder:
        for source, destination, *ids in created.values():
            try:
                move_to_top(api, source, destination, ids)
            except ApiError as error:
                print(f"  Could not move the {source['name']} to {destination['name']} "
                      f"policies to the top: {error}")
                print("  They were created. Check their position in the policy table.")

    total = sum(len(value) - 2 for value in created.values())
    print(f"\nCreated {count(total)}." + (f" {failed} failed." if failed else ""))
    print("Run again with --remove to delete them.")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ApiError as error:
        sys.exit(f"Error: {error}")
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
