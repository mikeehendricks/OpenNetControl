"""Simulators for IOS-style CLIs: Cisco IOS-XE, Cisco NX-OS, Ruckus ICX, Aruba AOS-CX."""
from __future__ import annotations

import ipaddress
import re

from .base import SimDevice


class IosFamily(SimDevice):
    cfg_mode_names = {"config": "config", "if": "config-if", "vlan": "config-vlan", "line": "config-line", "ntp": "config-ntp"}
    host_var = "name"

    def prompt(self):
        if not self.ctx:
            return f"{self.name}# "
        return f"{self.name}({self.cfg_mode_names[self.ctx[-1][0]]})# "

    def _exec(self, line):
        if line in ("end",):
            self.ctx = []
            return ""
        if line == "exit":
            if self.ctx: self.ctx.pop()
            return ""
        if not self.ctx:
            return self.exec_mode(line)
        return self.cfg_mode(line)

    def exec_mode(self, line):
        if line in ("terminal length 0", "skip-page-display", "no page", "terminal pager 0"):
            return ""
        if line in ("configure terminal", "configure", "conf t"):
            self.ctx = [("config", None)]
            return ""
        if line in ("write memory", "copy running-config startup-config"):
            return "[OK]"
        if line.startswith("reload"):
            return self.do_reload()
        if line.startswith("show "):
            out = self.show(line[5:])
            return out if out is not None else self.invalid(line)
        return self.invalid(line)

    def show(self, what):  # pragma: no cover
        raise NotImplementedError

    def cfg_mode(self, line):  # pragma: no cover
        raise NotImplementedError

    # shared config handling
    def route_add(self, net, nh, add=True):
        if add and (net, nh) not in self.routes: self.routes.append((net, nh))
        if not add and (net, nh) in self.routes: self.routes.remove((net, nh))


# ------------------------------------------------------------------ Cisco IOS-XE
class IosXeSim(IosFamily):
    platform = "cisco_iosxe"

    def show(self, what):
        if what == "version":
            d, h, m, _ = self.uptime_dhms()
            return (f"Cisco IOS XE Software, Version {self.version}\ncisco {self.model} (X86) processor with 1331432K/6147K bytes of memory.\n"
                    f"Processor board ID {self.serial}\n{self.name} uptime is {d//7} weeks, {d%7} days, {h} hours, {m} minutes")
        if what == "ip interface brief":
            rows = ["Interface              IP-Address      OK? Method Status                Protocol"]
            for i in self.ifaces:
                st = "administratively down" if not i["admin"] else ("up" if i["link"] else "down")
                rows.append(f"{i['name']:<22} {i['ip'] or 'unassigned':<15} YES {'manual' if i['ip'] else 'unset':<6} {st:<21} {'up' if self.oper(i) else 'down'}")
            return "\n".join(rows)
        if what == "processes cpu":
            return f"CPU utilization for five seconds: {self.cpu}%/1%; one minute: {self.cpu}%; five minutes: {self.cpu}%"
        if what == "processes memory":
            tot = 3925760000
            return f"Processor Pool Total: {tot:>11} Used: {int(tot*self.mem/100):>11} Free: {tot-int(tot*self.mem/100):>11}"
        if what == "lldp neighbors":
            rows = ["Device ID           Local Intf     Hold-time  Capability      Port ID"]
            for l, h, r in self.live_neighbors():
                rows.append(f"{h:<19} {l:<14} 120        B,R             {r}")
            return "\n".join(rows)
        if what == "running-config":
            return self.running_config()
        return None

    def running_config(self):
        L = ["Building configuration...", "", f"hostname {self.name}", "!"]
        for v, n in sorted(self.vlans.items()):
            if v != 1: L += [f"vlan {v}", f" name {n}", "!"]
        for i in self.ifaces:
            L.append(f"interface {i['name']}")
            if i["desc"]: L.append(f" description {i['desc']}")
            if i["ip"]: L.append(f" ip address {i['ip']} 255.255.255.0")
            if not i["admin"]: L.append(" shutdown")
            L.append("!")
        L += [f"ntp server {s}" for s in self.ntp]
        for pfx, nh in self.routes:
            net = ipaddress.IPv4Network(pfx)
            L.append(f"ip route {net.network_address} {net.netmask} {nh}")
        if self.snmp_public: L.append("snmp-server community public RO")
        L += ["enable secret 9 $9$Xk3jQ8x0NtopSecretHash", "line vty 0 15",
              " transport input ssh telnet" if self.telnet else " transport input ssh", "end", ""]
        return "\n".join(L)

    def cfg_mode(self, line):
        kind = self.ctx[-1][0]
        if kind == "config":
            m = re.match(r"^interface (\S+)$", line)
            if m:
                i = self.find_if(m.group(1))
                if not i: return "% Invalid interface"
                self.ctx.append(("if", i)); return ""
            m = re.match(r"^(no )?vlan (\d+)$", line)
            if m:
                v = int(m.group(2))
                if m.group(1): self.vlans.pop(v, None); return ""
                self.vlans.setdefault(v, f"VLAN{v:04d}"); self.ctx.append(("vlan", v)); return ""
            m = re.match(r"^(no )?ntp server ([\d.]+)$", line)
            if m:
                (self.ntp.remove(m.group(2)) if m.group(1) and m.group(2) in self.ntp else
                 (None if m.group(1) or m.group(2) in self.ntp else self.ntp.append(m.group(2))))
                return ""
            m = re.match(r"^(no )?ip route ([\d.]+) ([\d.]+) (\S+)$", line)
            if m:
                plen = ipaddress.IPv4Network(f"0.0.0.0/{m.group(3)}").prefixlen
                self.route_add(f"{m.group(2)}/{plen}", m.group(4), not m.group(1)); return ""
            if line == "line vty 0 15":
                self.ctx.append(("line", None)); return ""
            return self.invalid(line)
        if kind == "vlan":
            m = re.match(r"^name (\S+)$", line)
            if m: self.vlans[self.ctx[-1][1]] = m.group(1); return ""
            return self.invalid(line)
        if kind == "if":
            i = self.ctx[-1][1]
            if line == "shutdown": i["admin"] = False; return ""
            if line == "no shutdown": i["admin"] = True; return ""
            if line.startswith("description "): i["desc"] = line[12:]; return ""
            if line == "no description": i["desc"] = ""; return ""
            return self.invalid(line)
        if kind == "line":
            m = re.match(r"^transport input (.+)$", line)
            if m: self.telnet = "telnet" in m.group(1) or "all" in m.group(1); return ""
            return self.invalid(line)
        return self.invalid(line)


# ------------------------------------------------------------------ Cisco NX-OS
class NxosSim(IosXeSim):
    platform = "cisco_nxos"

    def show(self, what):
        if what == "version":
            d, h, m, s = self.uptime_dhms()
            return (f"Cisco Nexus Operating System (NX-OS) Software\n  NXOS: version {self.version}\n  cisco {self.model} Chassis\n"
                    f"  Processor Board ID {self.serial}\n  Device name: {self.name}\nKernel uptime is {d} day(s), {h} hour(s), {m} minute(s), {s} second(s)")
        if what == "interface status":
            rows = ["Port          Name               Status    Vlan      Duplex  Speed   Type"]
            for i in self.ifaces:
                st = "disabled" if not i["admin"] else ("connected" if i["link"] else "notconnect")
                rows.append(f"{i['name'].replace('Ethernet','Eth'):<13} {(i['desc'] or '--'):<18} {st:<9} 1         full    10G     10Gbase-SR")
            return "\n".join(rows)
        if what == "system resources":
            tot = 16401296; used = int(tot * self.mem / 100)
            return (f"CPU states  :   {self.cpu/2:.2f}% user,   {self.cpu/2:.2f}% kernel,   {100-self.cpu:.2f}% idle\n"
                    f"Memory usage:  {tot}K total,  {used}K used,  {tot-used}K free")
        if what == "lldp neighbors":
            rows = ["Device ID            Local Intf      Hold-time  Capability  Port ID"]
            for l, h, r in self.live_neighbors():
                rows.append(f"{h:<20} {l.replace('Ethernet','Eth'):<15} 120        BR          {r}")
            return "\n".join(rows)
        if what == "running-config":
            L = [f"hostname {self.name}"]
            if self.telnet: L.append("feature telnet")
            L.append("!")
            for v, n in sorted(self.vlans.items()):
                if v != 1: L += [f"vlan {v}", f"  name {n}"]
            for i in self.ifaces:
                L.append(f"interface {i['name']}")
                if i["desc"]: L.append(f"  description {i['desc']}")
                if not i["admin"]: L.append("  shutdown")
            L += [f"ntp server {s}" for s in self.ntp]
            L += [f"ip route {n} {nh}" for n, nh in self.routes]
            if self.snmp_public: L.append("snmp-server community public group network-operator")
            return "\n".join(L) + "\n"
        return None

    def cfg_mode(self, line):
        kind = self.ctx[-1][0]
        if kind == "config":
            if line == "no feature telnet": self.telnet = False; return ""
            if line == "feature telnet": self.telnet = True; return ""
            m = re.match(r"^(no )?ip route ([\d.]+)/(\d+) (\S+)$", line)
            if m: self.route_add(f"{m.group(2)}/{m.group(3)}", m.group(4), not m.group(1)); return ""
        return super().cfg_mode(line)


# ------------------------------------------------------------------ Ruckus ICX
class IcxSim(IosFamily):
    platform = "ruckus_icx"

    def _exec(self, line):
        if line.startswith("enable") and self.ctx and self.ctx[-1][0] == "if":
            pass
        return super()._exec(line)

    def show(self, what):
        if what == "version":
            d, h, m, s = self.uptime_dhms()
            return (f"  UNIT 1: compiled on Jan 10 2024 at 14:00:00 labeled as SPR09010\n  SW: Version {self.version}\n"
                    f"  HW: Stackable {self.model}\n  Serial  #:{self.serial}\n  System uptime is {d} day(s) {h} hour(s) {m} minute(s) {s} second(s)")
        if what == "interfaces brief":
            rows = ["Port    Link    State   Dupl Speed Trunk Tag Pvid Pri MAC             Name"]
            for n, i in enumerate(self.ifaces, 1):
                link = "Disable" if not i["admin"] else ("Up" if i["link"] else "Down")
                st = "Forward" if link == "Up" else "None"
                rows.append(f"{i['name']:<7} {link:<7} {st:<7} {'Full' if link=='Up' else 'None'} {'1G' if link=='Up' else 'None'}  None  No  1    0   748e.f8aa.{n:04x}  {i['desc']}".rstrip())
            return "\n".join(rows)
        if what == "cpu":
            return f"SLOT #: 1 CPU UTILIZATION\nLast 5 Min {self.cpu:.2f} percent busy"
        if what == "memory":
            tot = 1073741824
            return f"Total DRAM: {tot} bytes\nDynamic memory: {tot} bytes total, {tot-int(tot*self.mem/100)} bytes free, {self.mem}% used"
        if what == "lldp neighbors":
            rows = ["Lcl Port  Chassis ID       Port ID          Port Description System Name"]
            for l, h, r in self.live_neighbors():
                rows.append(f"{l:<9} 748e.f8bb.0001   {r:<16} -                {h}")
            return "\n".join(rows)
        if what == "vlan":
            return "\n".join(f"PORT-VLAN {v}, Name {n}, Priority Level0, Spanning tree Off" for v, n in sorted(self.vlans.items()))
        if what == "running-config":
            L = ["Current configuration:", "!", f"ver {self.version}", "!", f"hostname {self.name}", "!"]
            for v, n in sorted(self.vlans.items()):
                if v != 1: L += [f"vlan {v} name {n} by port", "!"]
            if self.ntp: L += ["ntp"] + [f" server {s}" for s in self.ntp] + ["!"]
            for i in self.ifaces:
                if i["desc"] or not i["admin"]:
                    L.append(f"interface ethernet {i['name']}")
                    if i["desc"]: L.append(f" port-name {i['desc']}")
                    if not i["admin"]: L.append(" disable")
                    L.append("!")
            if not self.telnet: L.append("no telnet server")
            L += [f"ip route {n} {nh}" for n, nh in self.routes]
            L.append("end")
            return "\n".join(L) + "\n"
        return None

    def cfg_mode(self, line):
        kind = self.ctx[-1][0]
        if kind == "config":
            m = re.match(r"^vlan (\d+) name (\S+) by port$", line)
            if m: self.vlans[int(m.group(1))] = m.group(2); self.ctx.append(("vlan", int(m.group(1)))); return ""
            m = re.match(r"^no vlan (\d+)$", line)
            if m: self.vlans.pop(int(m.group(1)), None); return ""
            m = re.match(r"^interface ethernet (\S+)$", line)
            if m:
                i = self.find_if(m.group(1))
                if not i: return "Error - invalid stack unit or slot number"
                self.ctx.append(("if", i)); return ""
            if line == "ntp": self.ctx.append(("ntp", None)); return ""
            if line == "no telnet server": self.telnet = False; return ""
            if line == "telnet server": self.telnet = True; return ""
            m = re.match(r"^(no )?ip route ([\d.]+)/(\d+) (\S+)$", line)
            if m: self.route_add(f"{m.group(2)}/{m.group(3)}", m.group(4), not m.group(1)); return ""
            return self.invalid(line)
        if kind == "ntp":
            m = re.match(r"^(no )?server ([\d.]+)$", line)
            if m:
                if m.group(1) and m.group(2) in self.ntp: self.ntp.remove(m.group(2))
                elif not m.group(1) and m.group(2) not in self.ntp: self.ntp.append(m.group(2))
                return ""
        if kind == "if":
            i = self.ctx[-1][1]
            if line == "disable": i["admin"] = False; return ""
            if line == "enable": i["admin"] = True; return ""
            m = re.match(r"^port-name (.+)$", line)
            if m: i["desc"] = m.group(1); return ""
            if line == "no port-name": i["desc"] = ""; return ""
        return self.invalid(line)

    def invalid(self, line):
        return f"Invalid input -> {line.split()[0] if line else ''}\nType ? for a list"


# ------------------------------------------------------------------ Aruba AOS-CX
class CxSim(IosFamily):
    platform = "aruba_aoscx"

    def show(self, what):
        if what == "version":
            return ("-----------------------------------------------------------------------------\nArubaOS-CX\n"
                    "(c) Copyright 2017-2023 Hewlett Packard Enterprise Development LP\n"
                    "-----------------------------------------------------------------------------\n"
                    f"Version      : {self.version}\nBuild Date   : 2024-01-15 10:11:12 PST\nProduct Name : {self.model}\nSerial Nbr   : {self.serial}")
        if what == "system":
            d, h, m, _ = self.uptime_dhms()
            return f"Hostname : {self.name}\nUptime   : {d} days, {h} hours, {m} minutes\nContact  :"
        if what == "system resource-utilization":
            return f"System Resource Utilization\nCPU avg : {int(self.cpu)}%\nMemory usage : {int(self.mem)}%"
        if what == "interface brief":
            rows = ["Port   Native  Mode   Type      Enabled Status  Reason             Speed  Description",
                    "       VLAN                                                       (Mb/s)"]
            for i in self.ifaces:
                rows.append(f"{i['name']:<6} 1       access 1GbT      {'yes' if i['admin'] else 'no':<7} {'up' if self.oper(i) else 'down':<7} {'' if self.oper(i) else 'Administratively_down' if not i['admin'] else 'No_link':<18} {'1000' if self.oper(i) else '--':<6} {i['desc']}")
            return "\n".join(rows)
        if what == "lldp neighbor-info":
            rows = ["LOCAL-PORT  CHASSIS-ID         PORT-ID  PORT-DESC  TTL  SYS-NAME"]
            for l, h, r in self.live_neighbors():
                rows.append(f"{l:<11} 74:8e:f8:00:00:01  {r:<8} -          120  {h}")
            return "\n".join(rows)
        if what == "vlan":
            rows = ["VLAN  Name            Status  Reason  Type    Interfaces"]
            for v, n in sorted(self.vlans.items()):
                rows.append(f"{v:<5} {n if v != 1 else 'DEFAULT_VLAN_1':<15} up      ok      {'default' if v==1 else 'static'}")
            return "\n".join(rows)
        if what == "running-config":
            L = [f"hostname {self.name}"]
            L += [f"ntp server {s}" for s in self.ntp]
            if self.telnet: L.append("telnet server vrf mgmt")
            for v, n in sorted(self.vlans.items()):
                if v != 1: L += [f"vlan {v}", f"    name {n}"]
            for i in self.ifaces:
                L.append(f"interface {i['name']}")
                if not i["admin"]: L.append("    shutdown")
                else: L.append("    no shutdown")
                if i["desc"]: L.append(f"    description {i['desc']}")
            L += [f"ip route {n} {nh}" for n, nh in self.routes]
            return "\n".join(L) + "\n"
        return None

    def cfg_mode(self, line):
        kind = self.ctx[-1][0]
        if kind == "config":
            m = re.match(r"^interface (\S+)$", line)
            if m:
                i = self.find_if(m.group(1))
                if not i: return "% Unknown interface"
                self.ctx.append(("if", i)); return ""
            m = re.match(r"^vlan (\d+)$", line)
            if m: v = int(m.group(1)); self.vlans.setdefault(v, f"VLAN{v}"); self.ctx.append(("vlan", v)); return ""
            m = re.match(r"^no vlan (\d+)$", line)
            if m: self.vlans.pop(int(m.group(1)), None); return ""
            m = re.match(r"^(no )?ntp server ([\d.]+)$", line)
            if m:
                if m.group(1) and m.group(2) in self.ntp: self.ntp.remove(m.group(2))
                elif not m.group(1) and m.group(2) not in self.ntp: self.ntp.append(m.group(2))
                return ""
            if line == "no telnet server vrf mgmt": self.telnet = False; return ""
            if line == "telnet server vrf mgmt": self.telnet = True; return ""
            m = re.match(r"^(no )?ip route ([\d.]+)/(\d+) (\S+)$", line)
            if m: self.route_add(f"{m.group(2)}/{m.group(3)}", m.group(4), not m.group(1)); return ""
            return self.invalid(line)
        if kind == "vlan":
            m = re.match(r"^name (\S+)$", line)
            if m: self.vlans[self.ctx[-1][1]] = m.group(1); return ""
        if kind == "if":
            i = self.ctx[-1][1]
            if line == "shutdown": i["admin"] = False; return ""
            if line == "no shutdown": i["admin"] = True; return ""
            if line.startswith("description "): i["desc"] = line[12:]; return ""
            if line == "no description": i["desc"] = ""; return ""
        return self.invalid(line)
