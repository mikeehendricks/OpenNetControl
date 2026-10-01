"""Catalogue of vendor-neutral operations the platform (and the AI agent) may perform.

The AI never emits CLI. It can only select one of these operations and supply validated
parameters; each vendor driver renders the CLI deterministically.
"""
from __future__ import annotations

from . import validation as v

OPS: dict[str, dict] = {
    "create_vlan": {"risk": "medium", "desc": "Create a VLAN", "params": {"vlan_id": v.vlan_id, "vlan_name": v.vlan_name}},
    "set_interface_description": {"risk": "low", "desc": "Set an interface description",
                                  "params": {"interface": v.iface, "description": v.description}},
    "interface_admin": {"risk": "high", "desc": "Enable/disable an interface",
                        "params": {"interface": v.iface, "enabled": v.boolean}},
    "block_ip": {"risk": "high", "desc": "Block an IPv4 address/prefix", "params": {"prefix": v.prefix}},
    "add_static_route": {"risk": "high", "desc": "Add a static route", "params": {"prefix": v.prefix, "nexthop": v.ipv4}},
    "set_ntp": {"risk": "low", "desc": "Add an NTP server", "params": {"server": v.ipv4}},
    "disable_telnet": {"risk": "medium", "desc": "Disable Telnet management access", "params": {}},
    "set_ssid_state": {"risk": "medium", "desc": "Enable/disable a wireless SSID",
                       "params": {"ssid": v.ssid, "enabled": v.boolean}},
}


def validate_op(op: str, params: dict) -> dict:
    if op not in OPS:
        raise v.ValidationError(f"unknown operation '{op}'")
    if not isinstance(params, dict):
        raise v.ValidationError("params must be an object")
    spec = OPS[op]["params"]
    extra = set(params) - set(spec)
    if extra:
        raise v.ValidationError(f"unexpected parameters: {sorted(extra)}")
    clean = {}
    for k, fn in spec.items():
        if k not in params:
            raise v.ValidationError(f"missing parameter '{k}'")
        clean[k] = fn(params[k])
    return clean
