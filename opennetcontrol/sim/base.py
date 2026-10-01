"""Stateful network-device simulators. They emulate vendor CLI dialects (modes, error messages,
save/commit semantics) so drivers can be exercised end-to-end without lab hardware."""
from __future__ import annotations

import time
from ..policy import canon_if


class SimDevice:
    platform = ""
    role = "switch"
    vendor_banner = ""

    def __init__(self, name, ip, model, version, serial, ifaces=(), neighbors=(), uptime_s=86400 * 20,
                 cpu=5, mem=40, role=None, ssids=(), clients=0, aps=0):
        self.name, self.ip, self.model, self.version, self.serial = name, ip, model, version, serial
        self.boot = time.time() - uptime_s
        self.cpu, self.mem = cpu, mem
        self.ifaces = [dict(name=n, admin=True, link=True, ip=i, desc=d) for (n, i, d) in ifaces]
        self.neighbors = list(neighbors)          # (local_if, remote_host, remote_if)
        self.vlans = {1: "default"}
        self.telnet = True
        self.snmp_public = False
        self.ntp: list[str] = []
        self.routes: list[tuple[str, str]] = []
        self.ssids = {s: True for s in ssids}
        self.clients, self.aps = clients, aps
        self.reachable = True
        self.reloaded = False
        self.fleet: dict[str, "SimDevice"] = {}
        self.history: list[str] = []
        self.ctx: list = []
        self.role = role or self.role
        self.blocked: list[str] = []
        self.saved_vlans = None
        self.reject_next: str | None = None   # fault injection: reject a command containing this text
        if role:
            self.role = role

    # -- helpers --
    @property
    def uptime(self) -> int:
        return int(time.time() - self.boot)

    def find_if(self, name):
        k = canon_if(name)
        for i in self.ifaces:
            if canon_if(i["name"]) == k:
                return i
        return None

    def oper(self, i) -> bool:
        return i["admin"] and i["link"]

    def live_neighbors(self):
        out = []
        for (lif, rh, rif) in self.neighbors:
            i = self.find_if(lif)
            r = self.fleet.get(rh)
            if i and self.oper(i) and (r is None or (r.reachable and not r.reloaded)):
                out.append((lif, rh, rif))
        return out

    def uptime_dhms(self):
        u = self.uptime
        return u // 86400, u % 86400 // 3600, u % 3600 // 60, u % 60

    # -- public --
    def prompt(self) -> str:  # pragma: no cover
        return f"{self.name}# "

    def execute(self, line: str) -> str:
        if not self.reachable or self.reloaded:
            raise ConnectionError("device unreachable")
        line = line.strip()
        self.history.append(line)
        if self.reject_next and self.reject_next in line:
            return self.invalid(line)
        filt = None
        if " | include " in line:
            line, filt = line.split(" | include ", 1)
        out = self._exec(line.strip())
        if filt:
            out = "\n".join(l for l in out.splitlines() if filt in l)
        return out

    def invalid(self, line):
        return "% Invalid input detected at '^' marker."

    def _exec(self, line):  # pragma: no cover
        raise NotImplementedError

    def do_reload(self):
        self.reloaded = True
        return "Proceeding with reload..."
