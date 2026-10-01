"""Simulator: MikroTik RouterOS."""
from __future__ import annotations

import re

from .base import SimDevice


class RouterOsSim(SimDevice):
    platform = "mikrotik_routeros"
    role = "router"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.services = {"telnet": True, "ssh": True, "www": False, "winbox": True, "api": False}
        self.addr_list: list[tuple[str, str]] = []
        self.filter_rules: list[str] = []
        self.vlan_if: dict[str, tuple[int, str]] = {}
        self.ntp_servers = ""
        self.ntp_enabled = False
        self.comments: dict[str, str] = {}
        for i in self.ifaces: self.comments[i["name"]] = i["desc"]

    def prompt(self):
        return f"[admin@{self.name}] > "

    def uptime_str(self):
        d, h, m, s = self.uptime_dhms()
        return f"{d//7}w{d%7}d{h}h{m}m{s}s"

    def _exec(self, line):
        if line == "/system resource print":
            tot = 1024.0
            return (f"                   uptime: {self.uptime_str()}\n                  version: {self.version} (stable)\n"
                    f"              free-memory: {tot*(100-self.mem)/100:.1f}MiB\n             total-memory: {tot:.1f}MiB\n"
                    f"                 cpu-load: {int(self.cpu)}%\n               board-name: {self.model}")
        if line == "/system routerboard print":
            return f"       routerboard: yes\n             model: {self.model}\n     serial-number: {self.serial}"
        if line == "/system identity print":
            return f"  name: {self.name}"
        if line == "/interface print terse":
            rows = []
            for n, i in enumerate(self.ifaces):
                fl = "X" if not i["admin"] else ("R" if i["link"] else "")
                c = f' comment="{self.comments[i["name"]]}"' if self.comments.get(i["name"]) else ""
                rows.append(f" {n}  {fl:<2} name={i['name']} default-name={i['name']} type=ether mtu=1500{c}")
            return "\n".join(rows)
        if line == "/ip neighbor print terse":
            return "\n".join(f" {n}  interface={l} address=10.0.0.1 mac-address=AA:BB:CC:00:00:0{n} identity={h} platform=MikroTik interface-name={r}"
                             for n, (l, h, r) in enumerate(self.live_neighbors()))
        if line == "/ip service print terse":
            return "\n".join(f" {n}  {'' if on else 'X':<2} name={s} port={ {'telnet':23,'ssh':22,'www':80,'winbox':8291,'api':8728}[s] }"
                             for n, (s, on) in enumerate(self.services.items()))
        if line == "/interface vlan print terse":
            return "\n".join(f" {n}  R  name={nm} mtu=1500 interface=bridge1 vlan-id={v} comment={c}"
                             for n, (nm, (v, c)) in enumerate(self.vlan_if.items()))
        if line == "/export terse":
            L = [f"# RouterOS {self.version}", f"/system identity set name={self.name}"]
            for i in self.ifaces:
                if self.comments.get(i["name"]): L.append(f'/interface set [find name={i["name"]}] comment="{self.comments[i["name"]]}"')
                if not i["admin"]: L.append(f"/interface set [find name={i['name']}] disabled=yes")
            L += [f"/interface vlan add name={nm} vlan-id={v} interface=bridge1 comment={c}" for nm, (v, c) in self.vlan_if.items()]
            L += [f"/ip route add dst-address={n} gateway={nh} comment=ONC" for n, nh in self.routes]
            L += [f"/ip firewall address-list add address={a} list={l} comment=ONC" for l, a in self.addr_list]
            L += [f"/ip firewall filter add {r}" for r in self.filter_rules]
            L += [f"/system ntp client set enabled={'yes' if self.ntp_enabled else 'no'} servers={self.ntp_servers}"]
            L += ["/user add name=admin password=SECRETPASS group=full"]
            return "\n".join(L) + "\n"
        m = re.match(r'^/interface set \[find name=(\S+)\] comment="(.*)"$', line)
        if m:
            if not self.find_if(m.group(1)): return ""
            self.comments[m.group(1)] = m.group(2); self.find_if(m.group(1))["desc"] = m.group(2); return ""
        m = re.match(r"^/interface (enable|disable) \[find name=(\S+)\]$", line)
        if m:
            i = self.find_if(m.group(2))
            if i: i["admin"] = m.group(1) == "enable"
            return ""
        m = re.match(r"^/interface vlan add name=(\S+) vlan-id=(\d+) interface=(\S+) comment=(\S+)$", line)
        if m:
            self.vlan_if[m.group(1)] = (int(m.group(2)), m.group(4)); self.vlans[int(m.group(2))] = m.group(4); return ""
        m = re.match(r"^/interface vlan remove \[find name=(\S+)\]$", line)
        if m:
            v = self.vlan_if.pop(m.group(1), None)
            if v: self.vlans.pop(v[0], None)
            return ""
        m = re.match(r"^/ip route add dst-address=(\S+) gateway=(\S+)", line)
        if m: self.routes.append((m.group(1), m.group(2))); return ""
        m = re.match(r"^/ip route remove \[find dst-address=(\S+) gateway=(\S+)\]$", line)
        if m:
            if (m.group(1), m.group(2)) in self.routes: self.routes.remove((m.group(1), m.group(2)))
            return ""
        m = re.match(r'^/system ntp client set (?:enabled=yes )?servers=(.*)$', line)
        if m:
            self.ntp_servers = m.group(1).strip('"'); self.ntp_enabled = "enabled=yes" in line
            self.ntp = [s for s in self.ntp_servers.split(",") if s]; return ""
        m = re.match(r"^/ip service (enable|disable) (\S+)$", line)
        if m:
            if m.group(2) not in self.services: return "failure: no such item"
            self.services[m.group(2)] = m.group(1) == "enable"; self.telnet = self.services["telnet"]; return ""
        m = re.match(r"^/ip firewall address-list add list=(\S+) address=(\S+)", line)
        if m: self.addr_list.append((m.group(1), m.group(2))); self.blocked.append(m.group(2)); return ""
        m = re.match(r"^/ip firewall address-list remove \[find list=(\S+) address=(\S+)\]$", line)
        if m:
            if (m.group(1), m.group(2)) in self.addr_list: self.addr_list.remove((m.group(1), m.group(2)))
            if m.group(2) in self.blocked: self.blocked.remove(m.group(2))
            return ""
        if line.startswith(":if (") and "ONC-BLOCKLIST" in line and "filter add" in line:
            if not self.filter_rules: self.filter_rules.append("chain=forward src-address-list=ONC-BLOCKLIST action=drop comment=ONC-BLOCKLIST")
            return ""
        if line.startswith("/system reboot") or line.startswith("/system reset-configuration"):
            return self.do_reload()
        return f"bad command name {line.split()[0] if line else ''} (line 1 column 1)"
