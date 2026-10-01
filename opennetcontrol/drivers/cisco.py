"""Cisco IOS-XE (Catalyst / ISR / Cat9k) and NX-OS (Nexus) drivers - CLI over SSH."""
from __future__ import annotations

import re

from ..models import Facts, Iface, Neighbor
from .base import Driver, dhms_to_s, to_int, mask_to_prefix


def _ios_cfg(cfg: str, f: Facts):
    cur = None
    for line in cfg.splitlines():
        m = re.match(r"^vlan (\d+)$", line)
        if m:
            cur = ("vlan", int(m.group(1)))
            f.vlans.setdefault(int(m.group(1)), f"VLAN{int(m.group(1)):04d}")
            continue
        m = re.match(r"^interface (\S+)", line)
        if m:
            cur = ("if", m.group(1))
            continue
        if line.startswith(" name ") and cur and cur[0] == "vlan":
            f.vlans[cur[1]] = line.strip()[5:]
        elif line.startswith(" description ") and cur and cur[0] == "if":
            for i in f.interfaces:
                if i.name == cur[1]:
                    i.description = line.strip()[12:]
        elif not line.startswith(" "):
            cur = None
        m = re.match(r"^ntp server (\S+)", line)
        if m:
            f.ntp_servers.append(m.group(1))
        if re.match(r"^snmp-server community public\b", line):
            f.snmp_public = True


class CiscoIOSXE(Driver):
    vendor = "cisco"
    platform = "cisco_iosxe"
    label = "Cisco IOS-XE"
    roles = ("switch", "router")
    capabilities = {"create_vlan", "set_interface_description", "interface_admin", "add_static_route",
                    "set_ntp", "disable_telnet", "block_ip"}
    paging = ["terminal length 0"]
    cmds = {"version": "show version", "ifaces": "show ip interface brief",
            "cpu": "show processes cpu | include CPU utilization",
            "mem": "show processes memory | include Processor Pool", "lldp": "show lldp neighbors",
            "config": "show running-config"}
    config_enter = ["configure terminal"]
    config_exit = ["end"]
    save = ["write memory"]

    def parse(self, o):
        f = Facts()
        v = o["version"]
        m = re.search(r"Version ([\w.()]+)", v); f.version = m.group(1) if m else ""
        m = re.search(r"^cisco (\S+)", v, re.M); f.model = m.group(1) if m else ""
        m = re.search(r"Processor board ID (\S+)", v); f.serial = m.group(1) if m else ""
        m = re.search(r"^(\S+) uptime is (.+)$", v, re.M)
        if m:
            f.hostname, f.uptime_s = m.group(1), dhms_to_s(m.group(2))
        for m in re.finditer(r"^(\S+)\s+(\S+)\s+\w+\s+\w+\s+(administratively down|up|down)\s+(up|down)\s*$", o["ifaces"], re.M):
            f.interfaces.append(Iface(m.group(1), admin_up=m.group(3) != "administratively down",
                                      oper_up=m.group(3) == "up" and m.group(4) == "up",
                                      ip="" if m.group(2) == "unassigned" else m.group(2)))
        m = re.search(r"five seconds: (\d+)%", o["cpu"]); f.cpu_pct = float(m.group(1)) if m else 0
        m = re.search(r"Total:\s+(\d+)\s+Used:\s+(\d+)", o["mem"])
        f.mem_pct = round(100 * int(m.group(2)) / int(m.group(1)), 1) if m else 0
        for m in re.finditer(r"^(\S+)\s+(\S+)\s+\d+\s+[A-Z,]+\s+(\S+)\s*$", o["lldp"], re.M):
            if m.group(1) != "Device":
                f.neighbors.append(Neighbor(m.group(2), m.group(1), m.group(3)))
        cfg = o["config"]
        _ios_cfg(cfg, f)
        vt = re.search(r"^line vty[^\n]*\n((?: [^\n]*\n)+)", cfg, re.M)
        f.telnet_enabled = bool(vt and re.search(r"transport input .*\btelnet\b|transport input all", vt.group(1)))
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
            n, m = mask_to_prefix(p["prefix"])
            return ([f"ip route {n} {m} {p['nexthop']}"], [f"no ip route {n} {m} {p['nexthop']}"])
        if op == "block_ip":
            n, m = mask_to_prefix(p["prefix"])
            return ([f"ip route {n} {m} Null0"], [f"no ip route {n} {m} Null0"])
        if op == "set_ntp":
            return ([f"ntp server {p['server']}"], [f"no ntp server {p['server']}"])
        if op == "disable_telnet":
            return (["line vty 0 15", "transport input ssh", "exit"], ["line vty 0 15", "transport input ssh telnet", "exit"])
        return super()._render(op, p, facts)


class CiscoNXOS(Driver):
    vendor = "cisco"
    platform = "cisco_nxos"
    label = "Cisco NX-OS"
    roles = ("switch",)
    capabilities = {"create_vlan", "set_interface_description", "interface_admin", "add_static_route",
                    "set_ntp", "disable_telnet"}
    paging = ["terminal length 0"]
    cmds = {"version": "show version", "ifaces": "show interface status", "res": "show system resources",
            "lldp": "show lldp neighbors", "config": "show running-config"}
    config_enter = ["configure terminal"]
    config_exit = ["end"]
    save = ["copy running-config startup-config"]

    def parse(self, o):
        f = Facts()
        v = o["version"]
        m = re.search(r"NXOS: version (\S+)", v); f.version = m.group(1) if m else ""
        m = re.search(r"^\s*cisco (Nexus\S* \S+)", v, re.M); f.model = m.group(1) if m else ""
        m = re.search(r"Processor Board ID (\S+)", v); f.serial = m.group(1) if m else ""
        m = re.search(r"Device name: (\S+)", v); f.hostname = m.group(1) if m else ""
        m = re.search(r"Kernel uptime is (.+)", v); f.uptime_s = dhms_to_s(m.group(1)) if m else 0
        for m in re.finditer(r"^(Eth\S+)\s+(.*?)\s+(connected|notconnect|disabled|sfpAbsent|err-disabled)\s+\d+", o["ifaces"], re.M):
            f.interfaces.append(Iface(m.group(1), admin_up=m.group(3) != "disabled", oper_up=m.group(3) == "connected",
                                      description="" if m.group(2) == "--" else m.group(2)))
        m = re.search(r"([\d.]+)% idle", o["res"]); f.cpu_pct = round(100 - float(m.group(1)), 1) if m else 0
        m = re.search(r"Memory usage:\s+(\d+)K total,\s+(\d+)K used", o["res"])
        f.mem_pct = round(100 * int(m.group(2)) / int(m.group(1)), 1) if m else 0
        for m in re.finditer(r"^(\S+)\s+(Eth\S+)\s+\d+\s+[A-Z]+\s+(\S+)\s*$", o["lldp"], re.M):
            f.neighbors.append(Neighbor(m.group(2), m.group(1), m.group(3)))
        cfg = o["config"]
        _ios_cfg(cfg, f)
        f.telnet_enabled = bool(re.search(r"^feature telnet\b", cfg, re.M))
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
            return (["no feature telnet"], ["feature telnet"])
        return super()._render(op, p, facts)
