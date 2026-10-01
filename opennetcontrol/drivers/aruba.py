"""HPE Aruba drivers: AOS-CX switches and Aruba Instant (IAP) Wi-Fi - CLI over SSH."""
from __future__ import annotations

import re

from ..models import Facts, Iface, Neighbor
from .base import Driver, dhms_to_s


class ArubaCX(Driver):
    vendor = "aruba"
    platform = "aruba_aoscx"
    label = "Aruba AOS-CX"
    roles = ("switch",)
    capabilities = {"create_vlan", "set_interface_description", "interface_admin", "add_static_route", "set_ntp",
                    "disable_telnet"}
    paging = ["no page"]
    cmds = {"version": "show version", "system": "show system", "res": "show system resource-utilization",
            "ifaces": "show interface brief", "lldp": "show lldp neighbor-info", "vlans": "show vlan",
            "config": "show running-config"}
    config_enter = ["configure terminal"]
    config_exit = ["end"]
    save = ["write memory"]
    error_re = re.compile(r"^% |Unknown command|Invalid|Incomplete", re.I | re.M)

    def parse(self, o):
        f = Facts()
        v = o["version"]
        m = re.search(r"^Version\s*:\s*(\S+)", v, re.M); f.version = m.group(1) if m else ""
        m = re.search(r"^Product Name\s*:\s*(\S+)", v, re.M); f.model = m.group(1) if m else ""
        m = re.search(r"^Serial Nbr\s*:\s*(\S+)", v, re.M); f.serial = m.group(1) if m else ""
        s = o["system"]
        m = re.search(r"^Hostname\s*:\s*(\S+)", s, re.M); f.hostname = m.group(1) if m else ""
        m = re.search(r"^Uptime\s*:\s*(.+)$", s, re.M); f.uptime_s = dhms_to_s(m.group(1)) if m else 0
        m = re.search(r"CPU avg\s*:\s*(\d+)%", o["res"]); f.cpu_pct = float(m.group(1)) if m else 0
        m = re.search(r"Memory usage\s*:\s*(\d+)%", o["res"]); f.mem_pct = float(m.group(1)) if m else 0
        for m in re.finditer(r"^(\d+/\d+/\d+)\s+\d+\s+\S+\s+\S+\s+(yes|no)\s+(up|down)\b", o["ifaces"], re.M):
            f.interfaces.append(Iface(m.group(1), admin_up=m.group(2) == "yes", oper_up=m.group(3) == "up"))
        for m in re.finditer(r"^(\d+/\d+/\d+)\s+\S+\s+(\S+)\s+\S+\s+\d+\s+(\S+)\s*$", o["lldp"], re.M):
            f.neighbors.append(Neighbor(m.group(1), m.group(3), m.group(2)))
        for m in re.finditer(r"^(\d+)\s+(\S+)\s+(?:up|down)\s", o["vlans"], re.M):
            f.vlans[int(m.group(1))] = m.group(2)
        cfg = o["config"]
        cur = None
        for line in cfg.splitlines():
            m = re.match(r"^interface (\S+)$", line)
            if m: cur = m.group(1); continue
            if line.startswith("    description ") and cur:
                for i in f.interfaces:
                    if i.name == cur: i.description = line.strip()[12:]
            elif not line.startswith(" "): cur = None
        f.telnet_enabled = bool(re.search(r"^telnet server vrf", cfg, re.M))
        f.ntp_servers = re.findall(r"^ntp server (\S+)", cfg, re.M)
        return f

    def _render(self, op, p, facts):
        if op == "create_vlan":
            return ([f"vlan {p['vlan_id']}", f"name {p['vlan_name']}", "exit"], [f"no vlan {p['vlan_id']}"])
        if op == "set_interface_description":
            return ([f"interface {p['interface']}", f"description {p['description']}", "exit"],
                    [f"interface {p['interface']}", "no description", "exit"])
        if op == "interface_admin":
            a, b = ("no shutdown", "shutdown") if p["enabled"] else ("shutdown", "no shutdown")
            return ([f"interface {p['interface']}", a, "exit"], [f"interface {p['interface']}", b, "exit"])
        if op == "add_static_route":
            return ([f"ip route {p['prefix']} {p['nexthop']}"], [f"no ip route {p['prefix']} {p['nexthop']}"])
        if op == "set_ntp":
            return ([f"ntp server {p['server']}"], [f"no ntp server {p['server']}"])
        if op == "disable_telnet":
            return (["no telnet server vrf mgmt"], ["telnet server vrf mgmt"])
        return super()._render(op, p, facts)


class ArubaInstant(Driver):
    vendor = "aruba"
    platform = "aruba_instant"
    label = "Aruba Instant (IAP)"
    roles = ("wireless",)
    capabilities = {"set_ssid_state", "set_ntp"}
    paging = ["no paging"]
    cmds = {"version": "show version", "summary": "show summary", "wlan": "show wlan", "nbr": "show lldp neighbor",
            "config": "show running-config"}
    config_enter = ["configure terminal"]
    config_exit = ["end"]
    save = ["commit apply"]
    error_re = re.compile(r"^% |Invalid|Parse error|Unknown", re.I | re.M)

    def parse(self, o):
        f = Facts()
        v = o["version"]
        m = re.search(r"Version (\S+)", v); f.version = m.group(1) if m else ""
        m = re.search(r"AP model: (\S+)", v); f.model = m.group(1) if m else ""
        s = o["summary"]
        g = lambda k: (re.search(rf"^{k}\s*:\s*(.*)$", s, re.M) or [None, ""])[1].strip()
        f.hostname, f.serial = g("Name"), g("Serial Number")
        f.uptime_s = dhms_to_s(g("Uptime"))
        f.clients, f.aps = int(g("Clients") or 0), int(g("Access Points") or 0)
        f.cpu_pct, f.mem_pct = float(g("CPU").rstrip("%") or 0), float(g("Memory").rstrip("%") or 0)
        f.interfaces.append(Iface("eth0", True, True))
        for m in re.finditer(r"^(\S[^\n]*?)\s{2,}(enable|disable)\s*$", o["wlan"], re.M):
            if m.group(1) != "Name":
                f.ssids[m.group(1).strip()] = m.group(2) == "enable"
        for m in re.finditer(r"^(\S+)\s+(\S+)\s+(\S+)\s*$", o["nbr"], re.M):
            if m.group(1) != "Local":
                f.neighbors.append(Neighbor(m.group(1), m.group(3), m.group(2)))
        f.ntp_servers = re.findall(r"^ntp-server (\S+)", o["config"], re.M)
        f.telnet_enabled = False
        return f

    def _render(self, op, p, facts):
        if op == "set_ssid_state":
            a, b = ("no shutdown", "shutdown") if p["enabled"] else ("shutdown", "no shutdown")
            return ([f"wlan ssid-profile {p['ssid']}", a, "exit"], [f"wlan ssid-profile {p['ssid']}", b, "exit"])
        if op == "set_ntp":
            return ([f"ntp-server {p['server']}"], [f"no ntp-server {p['server']}"])
        return super()._render(op, p, facts)
