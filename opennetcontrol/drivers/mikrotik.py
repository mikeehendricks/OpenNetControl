"""MikroTik RouterOS (v6/v7) driver - CLI over SSH. RouterOS applies changes immediately."""
from __future__ import annotations

import re

from ..models import Facts, Iface, Neighbor
from .base import Driver, dhms_to_s


def _kv(line: str) -> dict:
    return {k: (v1 or v2) for k, v1, v2 in re.findall(r'([\w-]+)=(?:"([^"]*)"|(\S*))', line)}


def _mem(s: str) -> float:
    m = re.match(r"([\d.]+)\s*(KiB|MiB|GiB)", s or "")
    return float(m.group(1)) * {"KiB": 1, "MiB": 1024, "GiB": 1048576}[m.group(2)] if m else 0


class RouterOS(Driver):
    vendor = "mikrotik"
    platform = "mikrotik_routeros"
    label = "MikroTik RouterOS"
    roles = ("router", "switch", "firewall")
    capabilities = {"create_vlan", "set_interface_description", "interface_admin", "add_static_route", "set_ntp",
                    "disable_telnet", "block_ip"}
    paging = []
    cmds = {"res": "/system resource print", "rb": "/system routerboard print", "id": "/system identity print",
            "ifaces": "/interface print terse", "nbr": "/ip neighbor print terse", "svc": "/ip service print terse",
            "vlans": "/interface vlan print terse", "config": "/export terse"}
    config_enter = []
    config_exit = []
    save = []
    error_re = re.compile(r"bad command name|syntax error|failure:|no such item|expected|invalid value|input does not match", re.I)
    prompt_re = r"\[[\w.@\-]+\] ?(/[\w /-]*)?> ?$"

    def parse(self, o):
        f = Facts()
        r = o["res"]
        g = lambda k, s=r: (re.search(rf"^\s*{k}: (.*)$", s, re.M) or [None, ""])[1].strip()
        f.version = g("version").split(" ")[0]
        f.uptime_s = dhms_to_s(g("uptime"))
        f.cpu_pct = float(g("cpu-load").rstrip("%") or 0)
        tot, free = _mem(g("total-memory")), _mem(g("free-memory"))
        f.mem_pct = round(100 * (tot - free) / tot, 1) if tot else 0
        f.model = g("board-name") or g("model", o["rb"])
        f.serial = g("serial-number", o["rb"])
        f.hostname = g("name", o["id"])
        for line in o["ifaces"].splitlines():
            m = re.match(r"^\s*\d+\s+([A-Z]*)\s+(.*)$", line)
            if not m:
                continue
            flags, kv = m.group(1), _kv(m.group(2))
            if kv.get("type") not in ("ether", "wlan", "bridge", "vlan", "sfp"):
                pass
            if "name" in kv:
                f.interfaces.append(Iface(kv["name"], admin_up="X" not in flags, oper_up="R" in flags,
                                          description=kv.get("comment", "")))
        for line in o["nbr"].splitlines():
            kv = _kv(line)
            if kv.get("identity"):
                f.neighbors.append(Neighbor(kv.get("interface", ""), kv["identity"], kv.get("interface-name", "")))
        f.telnet_enabled = False
        for line in o["svc"].splitlines():
            m = re.match(r"^\s*\d+\s+([A-Z]*)\s+(.*)$", line)
            if m and _kv(m.group(2)).get("name") == "telnet" and "X" not in m.group(1):
                f.telnet_enabled = True
        for line in o["vlans"].splitlines():
            kv = _kv(line)
            if kv.get("vlan-id", "").isdigit():
                f.vlans[int(kv["vlan-id"])] = kv.get("comment") or kv.get("name", "")
        m = re.search(r"/system ntp client.*?servers=(\S+)", o["config"])
        if m: f.ntp_servers = m.group(1).split(",")
        return f

    def _render(self, op, p, facts):
        if op == "create_vlan":
            n = f"vlan{p['vlan_id']}"
            return ([f"/interface vlan add name={n} vlan-id={p['vlan_id']} interface=bridge1 comment={p['vlan_name']}"],
                    [f"/interface vlan remove [find name={n}]"])
        if op == "set_interface_description":
            return ([f'/interface set [find name={p["interface"]}] comment="{p["description"]}"'],
                    [f'/interface set [find name={p["interface"]}] comment=""'])
        if op == "interface_admin":
            a, b = ("enable", "disable") if p["enabled"] else ("disable", "enable")
            return [f"/interface {a} [find name={p['interface']}]"], [f"/interface {b} [find name={p['interface']}]"]
        if op == "add_static_route":
            return ([f"/ip route add dst-address={p['prefix']} gateway={p['nexthop']} comment=ONC"],
                    [f"/ip route remove [find dst-address={p['prefix']} gateway={p['nexthop']}]"])
        if op == "set_ntp":
            return ([f"/system ntp client set enabled=yes servers={p['server']}"], ["/system ntp client set servers=\"\""])
        if op == "disable_telnet":
            return (["/ip service disable telnet"], ["/ip service enable telnet"])
        if op == "block_ip":
            pr = p["prefix"]
            apply = [f"/ip firewall address-list add list=ONC-BLOCKLIST address={pr} comment=ONC",
                     ":if ([:len [/ip firewall filter find comment=ONC-BLOCKLIST]] = 0) do={/ip firewall filter add chain=forward src-address-list=ONC-BLOCKLIST action=drop comment=ONC-BLOCKLIST place-before=0}"]
            return apply, [f"/ip firewall address-list remove [find list=ONC-BLOCKLIST address={pr}]"]
        return super()._render(op, p, facts)
