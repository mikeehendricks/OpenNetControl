"""Normalised, vendor-neutral data model used across the platform."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Iface:
    name: str
    admin_up: bool = True
    oper_up: bool = True
    ip: str = ""
    description: str = ""
    speed: str = ""


@dataclass
class Neighbor:
    local_if: str
    remote_host: str
    remote_if: str = ""


@dataclass
class Facts:
    hostname: str = ""
    model: str = ""
    version: str = ""
    serial: str = ""
    uptime_s: int = 0
    cpu_pct: float = 0.0
    mem_pct: float = 0.0
    interfaces: list[Iface] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    vlans: dict[int, str] = field(default_factory=dict)
    telnet_enabled: bool | None = None
    snmp_public: bool = False
    ntp_servers: list[str] = field(default_factory=list)
    ssids: dict[str, bool] = field(default_factory=dict)
    clients: int = 0
    aps: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["vlans"] = {str(k): v for k, v in self.vlans.items()}
        return d


class DriverError(Exception):
    """Raised by drivers for any device-side failure."""


class UnsupportedOperation(DriverError):
    pass


class ApplyError(DriverError):
    def __init__(self, line: str, output: str):
        super().__init__(f"device rejected '{line}': {output.strip()[:200]}")
        self.line = line
        self.output = output
