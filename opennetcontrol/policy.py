"""Guardrails. Defence-in-depth: these checks run on the *rendered* commands and the intent,
regardless of who (human, API client or AI) asked for the change.
"""
from __future__ import annotations

import ipaddress
import re

# Anything matching is never sent to a device by this platform.
DENY_PATTERNS = [
    r"\breload\b", r"\breboot\b", r"\bfactory[- ]?reset\b", r"\bfactoryreset\b", r"\bzeroize\b",
    r"\berase\b", r"\bformat\b", r"\bwrite\s+erase\b", r"\bdelete\s+(flash|bootflash|nvram|/force)",
    r"\bcopy\s+\S+\s+(startup|flash)", r"reset-configuration", r"\bexec(ute)?\s+(factoryreset|reboot|shutdown)\b",
    r"\brequest\s+system\s+(zeroize|restart|shutdown|private-data-reset)",
    r"\bboot\s+system\b", r"\bno\s+ip\s+routing\b", r"\baaa\b", r"\busername\b", r"\bpassword\b",
    r"\benable\s+secret\b", r"\bcrypto\s+key\b", r"\bdebug\b", r"\bsystem\s+reset\b",
    r"/system\s+(reboot|shutdown|reset|script|scheduler)", r"/user\b", r"\bfetch\b", r"/tool\b",
    r"[;&|`$<>\\]", r"\bsnmp-server\s+community\b(?!.*\bno\b)",
]
_DENY = [re.compile(p, re.I) for p in DENY_PATTERNS]

DESTRUCTIVE_INTENT = re.compile(
    r"\b(reload|reboot|restart|power[- ]?cycle|erase|wipe|factory[- ]?reset|format|zeroize|"
    r"delete\s+(all|everything|the\s+config|config)|shut\s*down\s+(all|every)|disable\s+all\s+interfaces|"
    r"reset\s+(to\s+default|the\s+device|config)|rm\s+-rf|drop\s+database)\b", re.I)

INJECTION_HINTS = re.compile(
    r"(ignore (all |any )?(previous|prior|above) (instructions|rules)|disregard (the )?(policy|guardrails)|"
    r"you are now|system prompt|developer mode|bypass (the )?(approval|guardrail|policy))", re.I)


class PolicyViolation(Exception):
    pass


def check_lines(lines: list[str]) -> None:
    for ln in lines:
        if len(ln) > 400:
            raise PolicyViolation("command too long")
        if "\n" in ln or "\r" in ln or "\x00" in ln:
            raise PolicyViolation("control characters in command")
        for rx in _DENY:
            if rx.search(ln):
                raise PolicyViolation(f"command blocked by guardrail: '{ln[:80]}'")


def check_op(op: str, params: dict, device: dict, protected_ips: set[str]) -> None:
    """Semantic safety rules for a single op on a single device."""
    if op == "block_ip":
        net = ipaddress.IPv4Network(params["prefix"])
        if net.prefixlen < 16:
            raise PolicyViolation("refusing to block a prefix shorter than /16")
        if net.is_loopback or net.is_multicast or net.is_unspecified or net.is_link_local:
            raise PolicyViolation("refusing to block loopback/multicast/unspecified/link-local space")
        for ip in protected_ips:
            try:
                if ipaddress.IPv4Address(ip) in net:
                    raise PolicyViolation(f"blocking {net} would cut off managed/controller address {ip}")
            except ipaddress.AddressValueError:
                continue
    elif op == "add_static_route":
        net = ipaddress.IPv4Network(params["prefix"])
        if net.prefixlen < 8:
            raise PolicyViolation("refusing to add a route shorter than /8 (incl. default route)")
        for ip in protected_ips:
            try:
                if ipaddress.IPv4Address(ip) in net and net.prefixlen < 24:
                    raise PolicyViolation(f"route {net} would override path to managed address {ip}")
            except ipaddress.AddressValueError:
                continue
    elif op == "interface_admin" and not params["enabled"]:
        prot = {canon_if(x) for x in device.get("protected_ifaces", [])}
        if canon_if(params["interface"]) in prot:
            raise PolicyViolation(f"interface {params['interface']} is protected (management/uplink) and cannot be disabled")


def canon_if(name: str) -> str:
    """Canonical interface key so 'GigabitEthernet1/0/1' == 'Gi1/0/1'."""
    m = re.match(r"^([A-Za-z-]+)\s*([\d/.:]+.*)$", name.strip())
    if not m:
        return name.strip().lower()
    return m.group(1)[:2].lower() + m.group(2).lower()
