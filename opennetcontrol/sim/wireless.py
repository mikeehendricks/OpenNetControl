"""Simulators: Ruckus Unleashed, Aruba Instant."""
from __future__ import annotations

import re

from .base import SimDevice


class UnleashedSim(SimDevice):
    platform = "ruckus_unleashed"
    role = "wireless"

    def prompt(self):
        return f"ruckus{'(config)' if self.ctx else ''}# "

    def _exec(self, line):
        if line == "end": self.ctx = []; return ""
        if line == "exit":
            if self.ctx: self.ctx.pop()
            return ""
        if not self.ctx:
            if line == "config": self.ctx = [("config", None)]; return ""
            if line == "show sysinfo":
                d, h, m, s = self.uptime_dhms()
                return (f"System Overview:\n  Name= {self.name}\n  IP Address= {self.ip}\n  Model= {self.model}\n  Serial Number= {self.serial}\n"
                        f"  Version= {self.version}\n  Uptime= {d} days, {h}:{m:02d}:{s:02d}\n  CPU Utilization= {int(self.cpu)}%\n  Memory Utilization= {int(self.mem)}%\n"
                        f"Devices:\n  Num of APs= {self.aps}\n  Num of Client Devices= {self.clients}")
            if line == "show wlan all":
                return "WLAN Service:\n" + "\n".join(f"  Name= {n}   Status= {'Enabled' if on else 'Disabled'}" for n, on in self.ssids.items())
            if line == "show lldp neighbors":
                return "Local Remote-Port System\n" + "\n".join(f"{l} {r} {h}" for l, h, r in self.live_neighbors())
            if line == "show config":
                return "\n".join([f"hostname {self.name}"] + [f"ntp-server {s}" for s in self.ntp] + ["admin-password SECRET123"])
            if line in ("reboot", "reset factory"): return self.do_reload()
            return f"The command '{line}' is not recognized"
        kind = self.ctx[-1][0]
        if kind == "config":
            m = re.match(r"^wlan (.+)$", line)
            if m:
                if m.group(1) not in self.ssids: return "Error: WLAN not found"
                self.ctx.append(("wlan", m.group(1))); return ""
            m = re.match(r"^(no )?ntp-server ([\d.]+)$", line)
            if m:
                if m.group(1) and m.group(2) in self.ntp: self.ntp.remove(m.group(2))
                elif not m.group(1) and m.group(2) not in self.ntp: self.ntp.append(m.group(2))
                return ""
        if kind == "wlan":
            if line == "shutdown": self.ssids[self.ctx[-1][1]] = False; return ""
            if line == "no shutdown": self.ssids[self.ctx[-1][1]] = True; return ""
        return f"The command '{line}' is not recognized"


class InstantSim(SimDevice):
    platform = "aruba_instant"
    role = "wireless"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.cand_ssids = dict(self.ssids)
        self.cand_ntp = list(self.ntp)

    def prompt(self):
        return f"{self.name}{'(config)' if self.ctx else ''}# "

    def _exec(self, line):
        if line == "end": self.ctx = []; return ""
        if line == "exit":
            if self.ctx: self.ctx.pop()
            return ""
        if not self.ctx:
            if line == "no paging": return ""
            if line == "configure terminal": self.ctx = [("config", None)]; return ""
            if line == "commit apply":
                self.ssids = dict(self.cand_ssids); self.ntp = list(self.cand_ntp); return "committed"
            if line == "show version":
                return f"Aruba Operating System Software.\nArubaOS (MODEL: 515), Version {self.version}\nAP model: {self.model}"
            if line == "show summary":
                d, h, m, _ = self.uptime_dhms()
                return (f"Name                 : {self.name}\nSerial Number        : {self.serial}\nUptime               : {d} days {h} hours {m} minutes\n"
                        f"Clients              : {self.clients}\nAccess Points        : {self.aps}\nCPU                  : {int(self.cpu)}%\nMemory               : {int(self.mem)}%")
            if line == "show wlan":
                return "Name        Status\n" + "\n".join(f"{n}   {'enable' if on else 'disable'}" for n, on in self.ssids.items())
            if line == "show lldp neighbor":
                return "Local Remote-Port System\n" + "\n".join(f"{l} {r} {h}" for l, h, r in self.live_neighbors())
            if line == "show running-config":
                return "\n".join([f"hostname {self.name}"] + [f"ntp-server {s}" for s in self.ntp] + ["mgmt-user admin SECRETHASH"])
            if line in ("reload", "factory_reset"): return self.do_reload()
            return "% Invalid input"
        kind = self.ctx[-1][0]
        if kind == "config":
            m = re.match(r"^wlan ssid-profile (.+)$", line)
            if m:
                if m.group(1) not in self.cand_ssids: return "% Invalid input: profile not found"
                self.ctx.append(("wlan", m.group(1))); return ""
            m = re.match(r"^(no )?ntp-server ([\d.]+)$", line)
            if m:
                if m.group(1) and m.group(2) in self.cand_ntp: self.cand_ntp.remove(m.group(2))
                elif not m.group(1) and m.group(2) not in self.cand_ntp: self.cand_ntp.append(m.group(2))
                return ""
        if kind == "wlan":
            if line == "shutdown": self.cand_ssids[self.ctx[-1][1]] = False; return ""
            if line == "no shutdown": self.cand_ssids[self.ctx[-1][1]] = True; return ""
        return "% Invalid input"
