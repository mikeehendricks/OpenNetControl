"""Simulators: Fortinet FortiOS, Palo Alto PAN-OS."""
from __future__ import annotations

import copy
import re

from .base import SimDevice


class FortiSim(SimDevice):
    platform = "fortinet_fortios"
    role = "firewall"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.addresses: dict[str, str] = {}
        self.addrgrps: dict[str, list[str]] = {}
        self.policies: dict[str, dict] = {}
        self.sroutes: dict[str, dict] = {}
        self.ntps: dict[str, str] = {}
        self.allow: dict[str, list[str]] = {i["name"]: ["ping", "https", "ssh"] + (["telnet"] if self.telnet else []) for i in self.ifaces}
        self.path: list[tuple[str, str]] = []

    def prompt(self):
        if not self.path:
            return f"{self.name} # "
        sec = [x[1] for x in self.path if x[0] == "config"]
        return f"{self.name} ({sec[-1].split()[-1] if sec else ''}) # "

    # ---- show
    def _exec(self, line):
        if self.path or re.match(r"^(config|edit|set|unset|append|unselect|delete|next|end)\b", line):
            return self.cfg(line)
        if line == "get system status":
            d, h, m, _ = self.uptime_dhms()
            return (f"Version: {self.model} v{self.version},build2662,240312 (GA.M)\nSerial-Number: {self.serial}\nHostname: {self.name}\n"
                    f"Operation Mode: NAT\nUptime: {d} days {h} hours {m} minutes")
        if line == "get system performance status":
            tot = 4046608
            return (f"CPU states: {int(self.cpu/2)}% user {int(self.cpu/2)}% system 0% nice {100-int(self.cpu)}% idle 0% iowait 0% irq 0% softirq\n"
                    f"Memory: {tot}k total, {int(tot*self.mem/100)}k used ({self.mem:.1f}%), {tot-int(tot*self.mem/100)}k free")
        if line == "get system interface physical":
            rows = ["== [onboard]"]
            for i in self.ifaces:
                rows.append(f"        ==[{i['name']}]\n                mode: static ip: {i['ip'] or '0.0.0.0'} 255.255.255.0 status: {'up' if self.oper(i) else 'down'} type: physical netmask: 24")
            return "\n".join(rows)
        if line == "get system lldp neighbors-summary":
            return "Local-Port Remote-Port System-Name\n" + "\n".join(f"{l} {r} {h}" for l, h, r in self.live_neighbors())
        if line == "show system interface":
            L = ["config system interface"]
            for i in self.ifaces:
                L += [f'    edit "{i["name"]}"', '        set vdom "root"']
                if i["ip"]: L.append(f"        set ip {i['ip']} 255.255.255.0")
                L.append(f"        set allowaccess {' '.join(self.allow[i['name']])}")
                if not i["admin"]: L.append("        set status down")
                if i["desc"]: L.append(f'        set description "{i["desc"]}"')
                L.append("    next")
            L.append("end")
            return "\n".join(L)
        if line == "show full-configuration":
            L = [self._exec("show system interface")]
            for n, s in self.addresses.items(): L += ["config firewall address", f'    edit "{n}"', f"        set subnet {s}", "    next", "end"]
            for n, mem in self.addrgrps.items(): L += ["config firewall addrgrp", f'    edit "{n}"', "        set member " + " ".join(f'"{m}"' for m in mem), "    next", "end"]
            for rid, r in self.sroutes.items(): L += ["config router static", f"    edit {rid}", f"        set dst {r['dst']}", f"        set gateway {r['gw']}", "    next", "end"]
            if self.ntps:
                L += ["config system ntp", "    set ntpsync enable", "    set type custom", "    config ntpserver"]
                for i, s in self.ntps.items(): L += [f"        edit {i}", f'            set server "{s}"', "        next"]
                L += ["    end", "end"]
            L += ["config system admin", '    edit "admin"', "        set password ENC SH2xxxxxxxxSECRETxxxxxxxx", "    next", "end"]
            return "\n".join(L) + "\n"
        if line.startswith("execute "):
            if re.search(r"reboot|shutdown|factoryreset", line): return self.do_reload()
        return "Unknown action 0"

    # ---- config tree
    def cfg(self, line):
        tok = line.split(None, 1)
        cmd, rest = tok[0], (tok[1] if len(tok) > 1 else "")
        sec = " ".join(x[1] for x in self.path if x[0] == "config")
        ent = next((x[1] for x in reversed(self.path) if x[0] == "edit"), None)
        q = lambda s: s.strip().strip('"')
        if cmd == "config":
            self.path.append(("config", rest)); return ""
        if cmd == "edit":
            e = q(rest)
            if sec == "system interface" and e not in self.allow:
                return "object check error: unable to create interface\ncommand parse error"
            self.path.append(("edit", e)); return ""
        if cmd == "next":
            if self.path and self.path[-1][0] == "edit": self.path.pop()
            return ""
        if cmd == "end":
            while self.path:
                if self.path.pop()[0] == "config": break
            return ""
        if cmd == "delete":
            e = q(rest)
            {"firewall address": self.addresses, "router static": self.sroutes, "system ntp ntpserver": self.ntps,
             "firewall policy": self.policies}.get(sec, {}).pop(e, None)
            return ""
        i = next((x for x in self.ifaces if x["name"] == ent), None) if sec == "system interface" else None
        if cmd in ("set", "unset", "append", "unselect"):
            if sec == "system interface" and i:
                k, _, v = rest.partition(" ")
                if k == "status": i["admin"] = (v == "up"); return ""
                if k == "description": i["desc"] = q(v) if cmd == "set" else ""; return ""
                if k == "allowaccess":
                    self.allow[i["name"]] = v.split(); self.telnet = any("telnet" in a for a in self.allow.values()); return ""
                return ""
            if sec == "firewall address" and cmd == "set" and rest.startswith("subnet"):
                self.addresses[ent] = rest.split(None, 1)[1]; return ""
            if sec == "firewall addrgrp":
                mem = self.addrgrps.setdefault(ent, [])
                m = q(rest.split(None, 1)[1]) if " " in rest else ""
                if cmd == "append" and m not in mem:
                    if m not in self.addresses: return "object check error: entry not found\ncommand parse error"
                    mem.append(m)
                if cmd == "unselect" and m in mem: mem.remove(m)
                return ""
            if sec == "firewall policy":
                self.policies.setdefault(ent, {})[rest.split()[0]] = rest; return ""
            if sec == "router static":
                r = self.sroutes.setdefault(ent, {})
                if rest.startswith("dst"): r["dst"] = rest.split(None, 1)[1]
                if rest.startswith("gateway"): r["gw"] = rest.split()[1]
                return ""
            if sec == "system ntp ntpserver" and rest.startswith("server"):
                self.ntps[ent] = q(rest.split(None, 1)[1]); return ""
            return ""
        return "Unknown action 0"

    def _blocked(self):
        return list(self.addresses)


class PanSim(SimDevice):
    platform = "paloalto_panos"
    role = "firewall"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.candidate: list[str] = []      # set-format commands
        self.running: list[str] = [f"set deviceconfig system hostname {self.name}",
                                   "set mgt-config users admin phash $1$abcdefgh$SECRETHASHxxxxxxxxxxxx"]
        for i in self.ifaces:
            if i["ip"]: self.running.append(f"set network interface ethernet {i['name']} layer3 ip {i['ip']}/24")
        self.candidate = list(self.running)
        self.mode = "op"

    def prompt(self):
        return f"admin@{self.name}{'#' if self.mode == 'cfg' else '>'} "

    def _exec(self, line):
        if self.mode == "op":
            if line in ("set cli pager off", "set cli config-output-format set"): return ""
            if line == "configure": self.mode = "cfg"; return "Entering configuration mode"
            if line == "show system info":
                d, h, m, s = self.uptime_dhms()
                return (f"hostname: {self.name}\nip-address: {self.ip}\nmodel: {self.model}\nserial: {self.serial}\n"
                        f"sw-version: {self.version}\nuptime: {d} days, {h}:{m:02d}:{s:02d}")
            if line == "show system resources":
                tot = 8000000; used = int(tot * self.mem / 100)
                return (f"top - 10:00:00 up {self.uptime_dhms()[0]} days\n%Cpu(s):  {self.cpu/2:.1f} us,  {self.cpu/2:.1f} sy,  0.0 ni, {100-self.cpu:.1f} id,  0.0 wa\n"
                        f"KiB Mem :  {tot} total,  {tot-used} free,  {used} used,  1000 buff/cache")
            if line == "show interface all":
                rows = [f"total configured hardware interfaces: {len(self.ifaces)}",
                        "name                    id    speed/duplex/state            mac address",
                        "-" * 80]
                for n, i in enumerate(self.ifaces, 16):
                    rows.append(f"{i['name']:<23} {n:<5} {'1000/full/up' if self.oper(i) else '[n/a]/[n/a]/down':<29} 00:1b:17:00:00:{n:02x}")
                return "\n".join(rows)
            if line == "show lldp neighbors all":
                rows = ["Local Interface  Remote Chassis      Remote Port   System Name"]
                for l, h, r in self.live_neighbors():
                    rows.append(f"{l:<16} 00:aa:bb:cc:dd:ee   {r:<13} {h}")
                return "\n".join(rows)
            if line == "show config running":
                return "\n".join(self.running)
            if re.match(r"^request system (restart|shutdown)|^request restart", line): return self.do_reload()
            return "Unknown command: " + line
        # configuration mode
        if line == "exit":
            self.mode = "op"
            if self.candidate != self.running: pass   # uncommitted changes are discarded on exit in this sim
            return ""
        if line == "commit":
            self.running = list(self.candidate); self._sync(); return "Configuration committed successfully"
        m = re.match(r"^set (.+)$", line)
        if m:
            body = m.group(1)
            if body.startswith("address-group ") and " static " in body:
                obj = body.split(" static ")[1].strip()
                if not any(l.startswith(f"set address {obj} ") for l in self.candidate):
                    return "Validation Error: address-group -> static: object not found"
            if body.startswith("network interface ethernet "):
                name = body.split()[3]
                if not self.find_if(name): return "Invalid syntax."
            if body.startswith("network interface ethernet") and " comment " in body:
                self.candidate = [l for l in self.candidate if not l.startswith(body.split(" comment ")[0] + " comment ")]
            if body.startswith("network interface ethernet") and "link-state" in body:
                self.candidate = [l for l in self.candidate if "link-state" not in l or body.split(" link-state")[0] not in l]
            if body.startswith("deviceconfig system ntp-servers primary"):
                self.candidate = [l for l in self.candidate if "primary-ntp-server" not in l]
            if line not in self.candidate: self.candidate.append(line)
            return ""
        if re.match(r"^move rulebase security rules \S+ top$", line):
            return ""
        m = re.match(r"^delete (.+)$", line)
        if m:
            body = m.group(1)
            self.candidate = [l for l in self.candidate if not (l == "set " + body or l.startswith("set " + body + " "))]
            return ""
        return "Invalid syntax."

    def _sync(self):
        for i in self.ifaces:
            i["admin"] = not any(f"ethernet {i['name']} link-state down" in l for l in self.running)
            d = [l for l in self.running if f"ethernet {i['name']} comment " in l]
            i["desc"] = d[0].split(" comment ", 1)[1].strip('"') if d else ""
        self.ntp = [l.rsplit(" ", 1)[1] for l in self.running if "primary-ntp-server" in l]
        self.blocked = [l.split()[2] for l in self.running if l.startswith("set address ")]

    def invalid(self, line):
        return "Invalid syntax."
