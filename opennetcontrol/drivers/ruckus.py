"""Ruckus drivers: ICX switches (FastIron) and Unleashed / SmartZone-managed Wi-Fi (CLI over SSH)."""
from __future__ import annotations

import re

from ..models import Facts, Iface, Neighbor
from .base import Driver, dhms_to_s, mask_to_prefix


class RuckusICX(Driver):
    vendor = "ruckus"
    platform = "ruckus_icx"
    label = "Ruckus ICX (FastIron)"
    roles = ("switch",)
    capabilities = {"create_vlan", "set_interface_description", "interface_admin", "add_static_route", "set_ntp",
                    "disable_telnet"}
    paging = ["skip-page-display"]
    cmds = {"version": "show version", "ifaces": "show interfaces brief", "cpu": "show cpu", "mem": "show memory",
            "lldp": "show lldp neighbors", "vlans": "show vlan", "name": "show running-config | include hostname",
            "config": "show running-config"}
    config_enter = ["configure terminal"]
    config_exit = ["end"]
    save = ["write memory"]
    error_re = re.compile(r"^Invalid input|Error -|Incomplete command|Unrecognized", re.I | re.M)

    def parse(self, o):
        f = Facts()
        v = o["version"]
        m = re.search(r"SW: Version (\S+)", v); f.version = m.group(1) if m else ""
        m = re.search(r"HW: \w+ (ICX\S+)", v); f.model = m.group(1) if m else ""
        m = re.search(r"Serial\s+#:\s*(\S+)", v); f.serial = m.group(1) if m else ""
        m = re.search(r"System uptime is (.+)", v); f.uptime_s = dhms_to_s(m.group(1)) if m else 0
        m = re.search(r"hostname (\S+)", o["name"]); f.hostname = m.group(1) if m else ""
        for m in re.finditer(r"^(\d+/\d+/\d+)\s+(Up|Down|Disable)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\d+\s+\d+\s+\S+\s*(.*)$", o["ifaces"], re.M):
            f.interfaces.append(Iface(m.group(1), admin_up=m.group(2) != "Disable", oper_up=m.group(2) == "Up",
                                      description=m.group(3).strip()))
        m = re.search(r"Last 5 Min ([\d.]+) percent busy", o["cpu"]); f.cpu_pct = float(m.group(1)) if m else 0
        m = re.search(r"(\d+)% used", o["mem"]); f.mem_pct = float(m.group(1)) if m else 0
        for m in re.finditer(r"^(\d+/\d+/\d+)\s+\S+\s+(\S+)\s+\S+\s+(\S+)\s*$", o["lldp"], re.M):
            f.neighbors.append(Neighbor(m.group(1), m.group(3), m.group(2)))
        for m in re.finditer(r"PORT-VLAN (\d+), Name ([^,]+),", o["vlans"]):
            f.vlans[int(m.group(1))] = m.group(2)
        f.telnet_enabled = "no telnet server" not in o["config"]
        for m in re.finditer(r"^ server (\S+)", o["config"], re.M):
            f.ntp_servers.append(m.group(1))
        return f

    def _render(self, op, p, facts):
        if op == "create_vlan":
            return ([f"vlan {p['vlan_id']} name {p['vlan_name']} by port", "exit"], [f"no vlan {p['vlan_id']}"])
        if op == "set_interface_description":
            return ([f"interface ethernet {p['interface']}", f"port-name {p['description']}", "exit"],
                    [f"interface ethernet {p['interface']}", "no port-name", "exit"])
        if op == "interface_admin":
            a, b = ("enable", "disable") if p["enabled"] else ("disable", "enable")
            return ([f"interface ethernet {p['interface']}", a, "exit"], [f"interface ethernet {p['interface']}", b, "exit"])
        if op == "add_static_route":
            return ([f"ip route {p['prefix']} {p['nexthop']}"], [f"no ip route {p['prefix']} {p['nexthop']}"])
        if op == "set_ntp":
            return (["ntp", f"server {p['server']}", "exit"], ["ntp", f"no server {p['server']}", "exit"])
        if op == "disable_telnet":
            return (["no telnet server"], ["telnet server"])
        return super()._render(op, p, facts)


class RuckusUnleashed(Driver):
    vendor = "ruckus"
    platform = "ruckus_unleashed"
    label = "Ruckus Unleashed / Wi-Fi"
    roles = ("wireless",)
    capabilities = {"set_ssid_state", "set_ntp"}
    paging = []
    cmds = {"sys": "show sysinfo", "wlan": "show wlan all", "nbr": "show lldp neighbors", "config": "show config"}
    config_enter = ["config"]
    config_exit = ["end"]
    save = []
    error_re = re.compile(r"The command .* is not|Invalid|Unknown|Error:", re.I)

    def parse(self, o):
        f = Facts()
        s = o["sys"]
        g = lambda k: (re.search(rf"^\s*{k}=\s*(.*)$", s, re.M) or [None, ""])[1].strip()
        f.hostname, f.model, f.serial, f.version = g("Name"), g("Model"), g("Serial Number"), g("Version")
        f.uptime_s = dhms_to_s(g("Uptime"))
        f.clients, f.aps = int(g("Num of Client Devices") or 0), int(g("Num of APs") or 0)
        f.cpu_pct, f.mem_pct = float(g("CPU Utilization").rstrip("%") or 0), float(g("Memory Utilization").rstrip("%") or 0)
        f.interfaces.append(Iface("eth0", True, True))
        for m in re.finditer(r"^\s*Name= (.+?)\s+Status= (Enabled|Disabled)", o["wlan"], re.M):
            f.ssids[m.group(1)] = m.group(2) == "Enabled"
        for m in re.finditer(r"^(\S+)\s+(\S+)\s+(\S+)\s*$", o["nbr"], re.M):
            if m.group(1) != "Local":
                f.neighbors.append(Neighbor(m.group(1), m.group(3), m.group(2)))
        for m in re.finditer(r"ntp-server (\S+)", o["config"]):
            f.ntp_servers.append(m.group(1))
        f.telnet_enabled = False
        return f

    def _render(self, op, p, facts):
        if op == "set_ssid_state":
            a, b = ("no shutdown", "shutdown") if p["enabled"] else ("shutdown", "no shutdown")
            return ([f"wlan {p['ssid']}", a, "exit"], [f"wlan {p['ssid']}", b, "exit"])
        if op == "set_ntp":
            return ([f"ntp-server {p['server']}"], [f"no ntp-server {p['server']}"])
        return super()._render(op, p, facts)
