"""Fortinet FortiOS (FortiGate) driver - CLI over SSH."""
from __future__ import annotations

import re

from ..models import Facts, Iface, Neighbor
from ..validation import stable_id
from .base import Driver, dhms_to_s, mask_to_prefix

# FortiOS prints this literal for "no address"; it is parsed device data, not a socket bind.
NOADDR = "0.0.0.0"  # nosec B104


class FortiOS(Driver):
    vendor = "fortinet"
    platform = "fortinet_fortios"
    label = "Fortinet FortiOS"
    roles = ("firewall",)
    capabilities = {"block_ip", "interface_admin", "set_interface_description", "add_static_route", "set_ntp",
                    "disable_telnet"}
    paging = []
    cmds = {"status": "get system status", "perf": "get system performance status",
            "phys": "get system interface physical", "lldp": "get system lldp neighbors-summary", "ifcfg": "show system interface",
            "config": "show full-configuration"}
    config_enter = []
    config_exit = []
    save = []     # FortiOS applies on `end`; there is no separate save
    error_re = re.compile(r"Command fail|Unknown action|command parse error|Return code -\d+|value parse error|object check error", re.I)
    prompt_re = r"[\w.\-]+ (\([\w\- ]+\) )?[#$] ?$"

    def parse(self, o):
        f = Facts()
        s = o["status"]
        m = re.search(r"Version: (\S+) v([\w.]+)", s)
        if m:
            f.model, f.version = m.group(1), m.group(2)
        m = re.search(r"Serial-Number: (\S+)", s); f.serial = m.group(1) if m else ""
        m = re.search(r"Hostname: (\S+)", s); f.hostname = m.group(1) if m else ""
        m = re.search(r"Uptime: (.+)", s); f.uptime_s = dhms_to_s(m.group(1)) if m else 0
        m = re.search(r"CPU states: .*?(\d+)% idle", o["perf"]); f.cpu_pct = 100 - float(m.group(1)) if m else 0
        m = re.search(r"Memory: \d+k total, \d+k used \(([\d.]+)%\)", o["perf"]); f.mem_pct = float(m.group(1)) if m else 0
        oper = {}
        for m in re.finditer(r"==\[(\S+)\]\s+mode: \w+ ip: ([\d.]+) [\d.]+ status: (up|down)", o["phys"]):
            oper[m.group(1)] = (m.group(2), m.group(3) == "up")
        telnet = False
        for blk in re.finditer(r'edit "([^"]+)"\n(.*?)\n\s*next', o["ifcfg"], re.S):
            name, body = blk.group(1), blk.group(2)
            ip, up = oper.get(name, ("", False))
            if "telnet" in (re.search(r"set allowaccess (.*)", body) or [None, ""])[1].split():
                telnet = True
                f.extra.setdefault("telnet_ifaces", []).append(name)
            d = re.search(r'set description "([^"]*)"', body)
            f.interfaces.append(Iface(name, admin_up="set status down" not in body, oper_up=up,
                                      ip="" if ip in ("", NOADDR) else ip,
                                      description=d.group(1) if d else ""))
        f.telnet_enabled = telnet
        for m in re.finditer(r"^(port\S+|wan\S*|lan\S*|internal\S*)\s+(\S+)\s+(\S+)\s*$", o["lldp"], re.M):
            f.neighbors.append(Neighbor(m.group(1), m.group(3), m.group(2)))
        f.ntp_servers = re.findall(r'set server "([\d.]+)"', o["config"])
        return f

    def _render(self, op, p, facts):
        if op == "block_ip":
            n, m = mask_to_prefix(p["prefix"]); obj = f"ONC-BLOCK-{n}-{p['prefix'].split('/')[1]}"
            pol = 9001
            apply = ["config firewall address", f'edit "{obj}"', f"set subnet {n} {m}", "next", "end",
                     "config firewall addrgrp", 'edit "ONC-BLOCKLIST"', f'append member "{obj}"', "next", "end",
                     "config firewall policy", f"edit {pol}", 'set name "ONC-BLOCKLIST-DENY"', 'set srcintf "any"',
                     'set dstintf "any"', 'set srcaddr "ONC-BLOCKLIST"', 'set dstaddr "all"', "set action deny",
                     'set schedule "always"', 'set service "ALL"', "set logtraffic all", "next", "end"]
            undo = ["config firewall addrgrp", 'edit "ONC-BLOCKLIST"', f'unselect member "{obj}"', "next", "end",
                    "config firewall address", f'delete "{obj}"', "end"]
            return apply, undo
        if op == "interface_admin":
            a, b = ("up", "down") if p["enabled"] else ("down", "up")
            mk = lambda s: ["config system interface", f'edit "{p["interface"]}"', f"set status {s}", "next", "end"]
            return mk(a), mk(b)
        if op == "set_interface_description":
            return (["config system interface", f'edit "{p["interface"]}"', f'set description "{p["description"]}"', "next", "end"],
                    ["config system interface", f'edit "{p["interface"]}"', 'unset description', "next", "end"])
        if op == "add_static_route":
            n, m = mask_to_prefix(p["prefix"]); rid = stable_id(p["prefix"] + p["nexthop"])
            return (["config router static", f"edit {rid}", f"set dst {n} {m}", f"set gateway {p['nexthop']}", "next", "end"],
                    ["config router static", f"delete {rid}", "end"])
        if op == "set_ntp":
            mk = lambda: ["config system ntp", "set ntpsync enable", "set type custom", "config ntpserver",
                          f"edit {stable_id(p['server'], 100, 800)}", f'set server "{p["server"]}"', "next", "end", "end"]
            return mk(), ["config system ntp", "config ntpserver", f"delete {stable_id(p['server'], 100, 800)}", "end", "end"]
        if op == "disable_telnet":
            ifs = (facts.extra.get("telnet_ifaces", []) if facts else [])
            def mk(allow): return sum([["config system interface", f'edit "{i}"', f"set allowaccess {allow}", "next", "end"] for i in ifs], [])
            return mk("ping https ssh"), mk("ping https ssh telnet")
        return super()._render(op, p, facts)
