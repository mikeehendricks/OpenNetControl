from .base import Driver
from .cisco import CiscoIOSXE, CiscoNXOS
from .fortinet import FortiOS
from .paloalto import PanOS
from .mikrotik import RouterOS
from .ruckus import RuckusICX, RuckusUnleashed
from .aruba import ArubaCX, ArubaInstant

DRIVERS: dict[str, Driver] = {d.platform: d for d in (
    CiscoIOSXE(), CiscoNXOS(), FortiOS(), PanOS(), RouterOS(), RuckusICX(), RuckusUnleashed(), ArubaCX(), ArubaInstant())}

VENDORS = {"cisco": "Cisco", "fortinet": "Fortinet", "paloalto": "Palo Alto Networks", "mikrotik": "MikroTik",
           "ruckus": "Ruckus", "aruba": "HPE Aruba"}


def get_driver(platform: str) -> Driver:
    try:
        return DRIVERS[platform]
    except KeyError:
        raise KeyError(f"unsupported platform '{platform}'")
