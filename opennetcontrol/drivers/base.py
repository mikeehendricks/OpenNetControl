"""Driver framework. A driver = how to *talk* to a platform (CLI dialect, config-mode, save/commit
semantics), how to *parse* its output into normalised Facts, and how to *render* vendor-neutral
operations (and their inverse) into native configuration.
"""
from __future__ import annotations

import re
from typing import Callable

from ..models import Facts, UnsupportedOperation, ApplyError


def to_int(s, default=0):
    try:
        return int(float(s))
    except (TypeError, ValueError):
        return default


def dhms_to_s(text: str) -> int:
    """'3 weeks, 2 days, 4 hours, 11 minutes' / '12 day(s) 3 hour(s)' / '1w2d3h4m5s' / '12 days 4:33:12'."""
    t = text.lower()
    total = 0
    mult = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    for n, u in re.findall(r"(\d+)\s*(week|day|hour|minute|second|w|d|h|m|s)", t):
        total += int(n) * mult[u[0]]
    m = re.search(r"(\d+):(\d+):(\d+)", t)
    if m:
        total += int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
    return total


class Driver:
    vendor = ""
    platform = ""
    label = ""
    roles: tuple[str, ...] = ("switch",)
    capabilities: set[str] = set()
    paging: list[str] = []
    cmds: dict[str, str] = {}              # key -> show command (must include "config")
    config_enter: list[str] = []
    config_exit: list[str] = []
    save: list[str] = []
    error_re = re.compile(r"^% |invalid|unknown command|syntax error", re.I | re.M)
    prompt_re = r"[\w@.\-\[\]() /:~]*[#>$] ?$"

    # ---- to be provided by subclasses -------------------------------------------------
    def parse(self, out: dict[str, str]) -> Facts:  # pragma: no cover
        raise NotImplementedError

    def _render(self, op: str, p: dict, facts: Facts | None) -> tuple[list[str], list[str]]:
        """Return (apply_lines, undo_lines)."""
        raise UnsupportedOperation(op)

    # ---- common ------------------------------------------------------------------------
    def render(self, op: str, p: dict, facts: Facts | None = None) -> tuple[list[str], list[str]]:
        if op not in self.capabilities:
            raise UnsupportedOperation(f"{self.label} does not support '{op}'")
        return self._render(op, p, facts)

    def is_error(self, output: str) -> bool:
        return bool(self.error_re.search(output or ""))

    def collect(self, session) -> Facts:
        out = {k: session.run(c) for k, c in self.cmds.items()}
        f = self.parse(out)
        f.extra["config_len"] = len(out.get("config", ""))
        return f

    def get_config(self, session) -> str:
        return session.run(self.cmds["config"])

    def apply(self, session, lines: list[str], ignore_errors: bool = False) -> list[str]:
        outs = []
        for c in self.config_enter:
            session.run(c)
        try:
            for ln in lines:
                o = session.run(ln)
                outs.append(o)
                if self.is_error(o) and not ignore_errors:
                    raise ApplyError(ln, o)
        finally:
            for c in self.config_exit:
                session.run(c)
        for c in self.save:
            o = session.run(c)
            if self.is_error(o) and not ignore_errors:
                raise ApplyError(c, o)
        return outs

    def verify(self, op: str, p: dict, facts: Facts, config: str, undo: bool = False) -> bool:
        """Did the change take effect (or, with undo=True, was it reverted)?"""
        ok = True
        if op == "create_vlan":
            ok = (p["vlan_id"] in facts.vlans)
            return (not ok) if undo else ok
        if op == "interface_admin":
            want = p["enabled"] if not undo else (not p["enabled"])
            for i in facts.interfaces:
                if _same_if(i.name, p["interface"]):
                    return i.admin_up == want
            return False
        if op == "disable_telnet":
            return (facts.telnet_enabled is True) if undo else (facts.telnet_enabled is False)
        if op == "set_ssid_state":
            want = p["enabled"] if not undo else (not p["enabled"])
            return facts.ssids.get(p["ssid"]) == want
        token = {"set_interface_description": p.get("description"), "block_ip": p.get("prefix", "").split("/")[0],
                 "add_static_route": p.get("prefix", "").split("/")[0], "set_ntp": p.get("server")}.get(op)
        if token:
            present = token in config
            return (not present) if undo else present
        return True


def _same_if(a: str, b: str) -> bool:
    from ..policy import canon_if
    return canon_if(a) == canon_if(b)


def mask_to_prefix(prefix: str) -> tuple[str, str]:
    import ipaddress
    n = ipaddress.IPv4Network(prefix)
    return str(n.network_address), str(n.netmask)
