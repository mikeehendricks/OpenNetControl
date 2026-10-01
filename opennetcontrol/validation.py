"""Strict input validation. Everything that can reach a device CLI passes through here.

Design rule: allow-list characters; never try to "escape" CLI input.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import zlib

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
VLAN_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._:-]{0,39}$")
DESC_RE = re.compile(r"^[A-Za-z0-9 _.,:/@#()+=-]{0,80}$")
SSID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}$")
NAME_RE = re.compile(r"^[A-Za-z0-9 _.-]{1,64}$")


class ValidationError(ValueError):
    pass


def _s(v, field: str, maxlen: int = 200) -> str:
    if not isinstance(v, str):
        raise ValidationError(f"{field} must be a string")
    if len(v) > maxlen:
        raise ValidationError(f"{field} too long")
    if any(ord(c) < 32 or ord(c) == 127 for c in v):
        raise ValidationError(f"{field} contains control characters")
    return v


def hostname(v, field="hostname") -> str:
    v = _s(v, field, 63)
    if not HOSTNAME_RE.match(v):
        raise ValidationError(f"{field} has invalid characters")
    return v


def name(v, field="name") -> str:
    v = _s(v, field, 64)
    if not NAME_RE.match(v):
        raise ValidationError(f"{field} has invalid characters")
    return v


def vlan_id(v) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValidationError("vlan_id must be an integer")
    if isinstance(v, bool) or not 2 <= n <= 4094 or 1002 <= n <= 1005:
        raise ValidationError("vlan_id must be 2-4094 (1002-1005 reserved)")
    return n


def vlan_name(v) -> str:
    v = _s(v, "vlan_name", 32)
    if not VLAN_NAME_RE.match(v):
        raise ValidationError("vlan_name allows letters, digits, _ and - only")
    return v


def iface(v) -> str:
    v = _s(v, "interface", 40)
    if not IFACE_RE.match(v):
        raise ValidationError("interface name has invalid characters")
    return v


def description(v) -> str:
    v = _s(v, "description", 80)
    if not DESC_RE.match(v):
        raise ValidationError("description has invalid characters")
    return v


def ssid(v) -> str:
    v = _s(v, "ssid", 32)
    if not SSID_RE.match(v):
        raise ValidationError("ssid has invalid characters")
    return v


def ipv4(v, field="address") -> str:
    v = _s(v, field, 15)
    try:
        return str(ipaddress.IPv4Address(v))
    except ValueError:
        raise ValidationError(f"{field} must be a valid IPv4 address")


def prefix(v, field="prefix") -> str:
    v = _s(v, field, 18)
    try:
        net = ipaddress.IPv4Network(v, strict=True)
    except ValueError:
        raise ValidationError(f"{field} must be a valid IPv4 prefix (a.b.c.d/len, host bits zero)")
    return str(net)


def boolean(v, field="value") -> bool:
    if isinstance(v, bool):
        return v
    raise ValidationError(f"{field} must be true or false")


def stable_id(text: str, base: int = 9000, span: int = 900) -> int:
    """Deterministic numeric id so that an `undo` can address what `apply` created."""
    return base + (zlib.crc32(text.encode()) % span)


# ---- network target safety (SSRF defence) ----------------------------------------------
def check_target_address(addr: str, allow_loopback: bool = False) -> str:
    """Management addresses must be hostnames/IPs that are not loopback/link-local/metadata."""
    addr = _s(addr, "address", 253)
    if not re.match(r"^[A-Za-z0-9._:-]{1,253}$", addr):
        raise ValidationError("address has invalid characters")
    try:
        infos = {i[4][0] for i in socket.getaddrinfo(addr, None)}
    except socket.gaierror:
        raise ValidationError("address does not resolve")
    for ip in infos:
        ipo = ipaddress.ip_address(ip.split("%")[0])
        if ipo.is_loopback and allow_loopback:
            continue
        if ipo.is_loopback or ipo.is_link_local or ipo.is_multicast or ipo.is_unspecified or ipo.is_reserved:
            raise ValidationError("address is not an allowed management target")
    return addr
