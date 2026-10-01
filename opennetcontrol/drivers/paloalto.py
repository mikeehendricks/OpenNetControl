"""Palo Alto Networks PAN-OS driver - CLI over SSH (candidate config + commit)."""
from __future__ import annotations

import re

from ..models import Facts, Iface, Neighbor
from ..validation import stable_id
from .base import Driver, dhms_to_s


class PanOS(Driver):
    vendor = "paloalto"
    platform = "paloalto_panos"
    label = "Palo Alto PAN-OS"
    roles = ("firewall",)
    capabilities = {"block_ip", "interface_admin", "set_interface_description", "add_static_route", "set_ntp"}
    paging = ["set cli pager off", "set cli config-output-format set"]
    cmds = {"info": "show system info", "res": "show system resources", "ifaces": "show interface all",
            "lldp": "show lldp neighbors all", "config": "show config running"}
    config_enter = ["configure"]
    config_exit = ["exit"]
    save = []      # commit happens inside apply() below, while still in configure mode
    error_re = re.compile(r"Invalid syntax|Unknown command|Server error|Validation Error|Commit failed|not a valid", re.I)
    prompt_re = r"[\w.\-]+@[\w.\-]+(\([\w\- ]+\))?[#>] ?$"

    def parse(self, o):
        f = Facts()
        i = o["info"]
        g = lambda k: (re.search(rf"^{k}: (.*)$", i, re.M) or [None, ""])[1].strip()
        f.hostname, f.model, f.serial, f.version = g("hostname"), g("model"), g("serial"), g("sw-version")
        f.uptime_s = dhms_to_s(g("uptime"))
        m = re.search(r"([\d.]+) id", o["res"]); f.cpu_pct = round(100 - float(m.group(1)), 1) if m else 0
        m = re.search(r"KiB Mem :\s+(\d+) total,\s+\d+ free,\s+(\d+) used", o["res"])
        f.mem_pct = round(100 * int(m.group(2)) / int(m.group(1)), 1) if m else 0
        for m in re.finditer(r"^(ethernet\S+|ae\d+|vlan\S*|loopback\S*|tunnel\S*)\s+\d+\s+\S+/\S+/(up|down|unknown)\s+\S+", o["ifaces"], re.M):
            f.interfaces.append(Iface(m.group(1), admin_up=True, oper_up=m.group(2) == "up"))
        for ifc in f.interfaces:
            d = re.search(rf"set network interface ethernet {re.escape(ifc.name)} comment (.+)", o["config"])
            if d: ifc.description = d.group(1).strip('"')
            if re.search(rf"set network interface ethernet {re.escape(ifc.name)} link-state down", o["config"]):
                ifc.admin_up = False
        for m in re.finditer(r"^(\S+)\s+\S+\s+(\S+)\s+(\S+)\s*$", o["lldp"], re.M):
            if m.group(1).startswith("ethernet"):
                f.neighbors.append(Neighbor(m.group(1), m.group(3), m.group(2)))
        f.telnet_enabled = False
        m = re.search(r"primary-ntp-server ntp-server-address (\S+)", o["config"])
        if m: f.ntp_servers.append(m.group(1))
        return f

    def apply(self, session, lines, ignore_errors=False):
        # PAN-OS needs an explicit commit while still in configure mode.
        return super().apply(session, lines + ["commit"], ignore_errors)

    def _render(self, op, p, facts):
        if op == "block_ip":
            obj = "ONC-" + p["prefix"].replace("/", "_")
            apply = [f"set address {obj} ip-netmask {p['prefix']}", f"set address-group ONC-BLOCKLIST static {obj}",
                     "set rulebase security rules ONC-BLOCK from any to any source ONC-BLOCKLIST destination any "
                     "application any service any action deny",
                     "move rulebase security rules ONC-BLOCK top"]     # must precede any broader allow rule
            undo = [f"delete address-group ONC-BLOCKLIST static {obj}", f"delete address {obj}"]
            return apply, undo
        if op == "interface_admin":
            a, b = ("up", "down") if p["enabled"] else ("down", "up")
            base = f"set network interface ethernet {p['interface']} link-state"
            return [f"{base} {a}"], [f"{base} {b}"]
        if op == "set_interface_description":
            base = f"network interface ethernet {p['interface']} comment"
            return [f'set {base} "{p["description"]}"'], [f"delete {base}"]
        if op == "add_static_route":
            rn = "ONC-" + str(stable_id(p["prefix"] + p["nexthop"]))
            base = f"network virtual-router default routing-table ip static-route {rn}"
            return ([f"set {base} destination {p['prefix']} nexthop ip-address {p['nexthop']}"], [f"delete {base}"])
        if op == "set_ntp":
            base = "deviceconfig system ntp-servers primary-ntp-server ntp-server-address"
            return [f"set {base} {p['server']}"], [f"delete {base}"]
        return super()._render(op, p, facts)
