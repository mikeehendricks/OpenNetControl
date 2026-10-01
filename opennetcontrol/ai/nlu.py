"""Deterministic natural-language understanding (offline fallback & LLM cross-check).

Output is always an *intent*: a dict of {type, filters, op?, params?}. No CLI is ever produced here.
"""
from __future__ import annotations

import re

VENDOR_ALIASES = {
    "cisco": "cisco", "catalyst": "cisco", "nexus": "cisco", "nx-os": "cisco", "nxos": "cisco", "ios-xe": "cisco", "iosxe": "cisco",
    "fortinet": "fortinet", "fortigate": "fortinet", "fortios": "fortinet", "forti": "fortinet",
    "palo alto": "paloalto", "paloalto": "paloalto", "palo-alto": "paloalto", "pan-os": "paloalto", "panos": "paloalto", "palo": "paloalto",
    "mikrotik": "mikrotik", "routeros": "mikrotik", "mikro": "mikrotik",
    "ruckus": "ruckus", "unleashed": "ruckus", "icx": "ruckus",
    "aruba": "aruba", "aos-cx": "aruba", "aoscx": "aruba", "instant": "aruba", "hpe": "aruba",
}
PLATFORM_ALIASES = {"nx-os": "cisco_nxos", "nxos": "cisco_nxos", "nexus": "cisco_nxos", "ios-xe": "cisco_iosxe", "iosxe": "cisco_iosxe",
                    "icx": "ruckus_icx", "unleashed": "ruckus_unleashed", "aos-cx": "aruba_aoscx", "aoscx": "aruba_aoscx", "instant": "aruba_instant"}
ROLE_WORDS = {"firewall": "firewall", "firewalls": "firewall", "fw": "firewall", "switch": "switch", "switches": "switch",
              "router": "router", "routers": "router", "access point": "wireless", "access points": "wireless", "aps": "wireless",
              "ap": "wireless", "wireless": "wireless", "wifi": "wireless", "wi-fi": "wireless", "wlan": "wireless"}

IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"


def extract_filters(msg: str, sites: list[str], names: list[str]) -> dict:
    low = msg.lower()
    f: dict = {}
    for a, v in sorted(VENDOR_ALIASES.items(), key=lambda kv: -len(kv[0])):
        if re.search(rf"(?<![\w-]){re.escape(a)}(?![\w-])", low):
            f["vendor"] = v
            if a in PLATFORM_ALIASES:
                f["platform"] = PLATFORM_ALIASES[a]
            break
    for a, v in sorted(ROLE_WORDS.items(), key=lambda kv: -len(kv[0])):
        if re.search(rf"(?<![\w-]){re.escape(a)}(?![\w-])", low):
            f["role"] = v
            break
    for s in sites:
        norm = re.sub(r"[-_ ]+", "[-_ ]?", re.escape(s.lower()).replace(r"\-", "-"))
        if re.search(rf"(?<![\w-]){norm}(?![\w-])", low) or any(len(p) > 3 and re.search(rf"(?<![\w-]){re.escape(p.lower())}(?![\w-])", low) for p in re.split(r"[-_ ]", s)):
            f["site"] = s
            break
    hit = [n for n in names if re.search(rf"(?<![\w-]){re.escape(n.lower())}(?![\w-])", low)]
    if hit:
        f["names"] = hit
    if re.search(r"\b(all|every|each|entire|whole)\b", low):
        f["all"] = True
    return f


def _target_text(msg: str) -> str:
    m = re.search(r"\b(?:on|for|across|in|at)\s+(.+)$", msg, re.I)
    return m.group(1) if m else msg


def parse(msg: str, sites: list[str], names: list[str]) -> dict:
    m_ = msg.strip().rstrip("?.! ")
    low = m_.lower()
    filt = extract_filters(m_, sites, names)

    def change(op, params):
        tgt = extract_filters(_target_text(m_), sites, names)
        if not (tgt.keys() & {"vendor", "role", "site", "names", "all", "platform"}):
            tgt = filt
        return {"type": "change", "op": op, "params": params, "filters": tgt}

    # ---- changes
    m = re.search(r"\bvlan\s+(\d{1,4})(?:\s+(?:named|called|name)\s+\"?([\w-]+)\"?)?", low)
    if m and re.search(r"\b(create|add|make|define|new)\b", low):
        return change("create_vlan", {"vlan_id": int(m.group(1)), "vlan_name": m.group(2) or f"VLAN{m.group(1)}"})
    m = re.search(rf"\bblock(?:ing)?\s+(?:ip\s+|address\s+|host\s+)?({IPV4}(?:/\d{{1,2}})?)", low)
    if m:
        p = m.group(1)
        return change("block_ip", {"prefix": p if "/" in p else p + "/32"})
    m = re.search(rf"\broute\s+({IPV4}/\d{{1,2}})\s+(?:via|next-?hop|gateway|through)\s+({IPV4})", low)
    if m and re.search(r"\b(add|create|set|install)\b", low):
        return change("add_static_route", {"prefix": m.group(1), "nexthop": m.group(2)})
    m = re.search(r"\b(shut\s*down|disable|turn off|bring down)\s+(?:the\s+)?(?:interface|port|link)\s+([\w/.:-]+)", m_, re.I)
    if m:
        return change("interface_admin", {"interface": m.group(2), "enabled": False})
    m = re.search(r"\b(enable|bring up|turn on|no shutdown)\s+(?:the\s+)?(?:interface|port|link)\s+([\w/.:-]+)", m_, re.I)
    if m:
        return change("interface_admin", {"interface": m.group(2), "enabled": True})
    m = re.search(r"\b(?:describe|label|description)\b.*?\b(?:interface|port)\s+([\w/.:-]+).*?\b(?:as|to|:)\s+\"?([\w .,:/@#()+=-]{1,80}?)\"?\s*(?:$|\s+on\s+)", m_, re.I)
    if m:
        return change("set_interface_description", {"interface": m.group(1), "description": m.group(2).strip()})
    m = re.search(rf"\bntp(?:\s+server)?\s+({IPV4})", low)
    if m and re.search(r"\b(add|set|configure|use)\b", low):
        return change("set_ntp", {"server": m.group(1)})
    if re.search(r"\b(disable|turn off|remove|stop|block)\b.*\btelnet\b", low):
        return change("disable_telnet", {})
    m = re.search(r"\b(disable|enable|turn off|turn on)\s+(?:the\s+)?ssid\s+(?:\"([^\"]+)\"|([\w.-]+))", m_, re.I)
    if m:
        return change("set_ssid_state", {"ssid": m.group(2) or m.group(3), "enabled": m.group(1).lower() in ("enable", "turn on")})

    # ---- read-only
    if re.fullmatch(r"(help|\?|what can you do|commands|hi|hello)", low):
        return {"type": "help", "filters": {}}
    if re.search(r"\b(why|root cause|diagnos|investigat|troubleshoot|explain|rca|what happened|what's wrong with|whats wrong with)\b", low):
        return {"type": "explain", "filters": filt}
    if re.search(r"\b(compliance|compliant|insecure|harden|vulnerab|telnet|snmp|audit findings|security (posture|risk|issue)|weak|exposed|risk)\b", low):
        return {"type": "compliance", "filters": filt}
    if re.search(r"\b(incident|alert|problem|issue|outage|wrong|broken|fault|failing|failure)s?\b", low):
        return {"type": "incidents", "filters": filt}
    if re.search(r"\binterfaces?\b.*\bdown\b|\bdown\b.*\b(interfaces?|ports?|links?)\b", low):
        return {"type": "interfaces_down", "filters": filt}
    if re.search(r"\b(unreachable|offline|not responding|down|dead)\b", low):
        return {"type": "unreachable", "filters": filt}
    if re.search(r"\b(cpu|memory|ram|load|busy|utili[sz]ation|hottest|top)\b", low):
        return {"type": "resources", "filters": filt}
    if re.search(r"\b(version|firmware|software|release|model|serial)\b", low):
        return {"type": "versions", "filters": filt}
    if re.search(r"\b(topology|neighbou?r|neighbou?rs|connected to|uplink|path|lldp)\b", low):
        return {"type": "topology", "filters": filt}
    if re.search(r"\b(how many|count|number of|summary|overview|status|health)\b", low) and not filt.get("names"):
        return {"type": "summary", "filters": filt}
    if re.search(r"\b(config|configuration|backup|running)\b", low) and filt.get("names"):
        return {"type": "config", "filters": filt}
    if re.search(r"\b(show|list|get|display|find|which|what|inventory|devices?|tell me about|info)\b", low) or filt:
        return {"type": "inventory", "filters": filt}
    return {"type": "unknown", "filters": filt}
