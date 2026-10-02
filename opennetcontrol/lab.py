"""Demo / lab fleet built from simulators. Used for demos, tests and the optional SSH lab server."""
from __future__ import annotations

from .sim import (IosXeSim, NxosSim, IcxSim, CxSim, FortiSim, PanSim, RouterOsSim, UnleashedSim, InstantSim)

LAB: dict[str, object] = {}


def _g(prefix, n, ip=""):
    return [(f"{prefix}{i}", ip, "") for i in range(1, n + 1)]


def build_lab() -> list[dict]:
    """Create simulators, wire them together, and return inventory records for them."""
    LAB.clear()
    spec = []

    def add(sim, site, role=None, tags=""):
        LAB[sim.name] = sim
        spec.append(dict(name=sim.name, address=sim.name, vendor="", platform=sim.platform, site=site,
                         role=role or sim.role, tags=tags, transport="sim", mgmt_ip=sim.ip))

    # ---------- HQ (Manila)
    add(PanSim("hq-fw1", "10.10.0.1", "PA-3220", "10.2.8", "0123456789",
               ifaces=[("ethernet1/1", "198.51.100.2", "isp-uplink"), ("ethernet1/2", "10.10.1.1", "to-core"), ("ethernet1/3", "", "dmz")],
               neighbors=[("ethernet1/2", "hq-core1", "Te1/1/1")], cpu=18, mem=44), "HQ-Manila")
    add(FortiSim("hq-fw2", "10.10.0.2", "FortiGate-200F", "7.4.4", "FG200FTK22000123",
                 ifaces=[("port1", "10.10.2.1", "to-core"), ("port2", "203.0.113.2", "wan2-backup"), ("port3", "", "")],
                 neighbors=[("port1", "hq-core1", "Te1/1/2")], cpu=22, mem=51), "HQ-Manila")
    add(IosXeSim("hq-core1", "10.10.0.11", "C9500-24Y4C", "17.09.04a", "FCW2301L0AB",
                 ifaces=[("TenGigabitEthernet1/1/1", "10.10.1.2", "to-hq-fw1"), ("TenGigabitEthernet1/1/2", "10.10.2.2", "to-hq-fw2"),
                         ("TenGigabitEthernet1/1/3", "", "to-hq-dist1"), ("TenGigabitEthernet1/1/4", "", "to-hq-dc1"), ("TenGigabitEthernet1/1/5", "", "to-hq-dist2")],
                 neighbors=[("Te1/1/1", "hq-fw1", "ethernet1/2"), ("Te1/1/2", "hq-fw2", "port1"), ("Te1/1/3", "hq-dist1", "1/1/48"),
                            ("Te1/1/4", "hq-dc1", "Eth1/48"), ("Te1/1/5", "hq-dist2", "1/1/48")], cpu=14, mem=38), "HQ-Manila", tags="core")
    LAB["hq-core1"].telnet = True
    add(CxSim("hq-dist1", "10.10.0.21", "JL663A", "FL.10.13.1000", "SG12345678",
              ifaces=[("1/1/1", "", "to-ap1"), ("1/1/2", "", "users"), ("1/1/3", "", "users"), ("1/1/48", "", "uplink-core")],
              neighbors=[("1/1/48", "hq-core1", "Te1/1/3"), ("1/1/1", "hq-ap1", "eth0")], cpu=9, mem=33), "HQ-Manila")
    LAB["hq-dist1"].telnet = False
    add(IcxSim("hq-dist2", "10.10.0.22", "ICX7150-48-POE", "09.0.10T213", "CRH2301K00A",
               ifaces=[("1/1/1", "", "to-ap2"), ("1/1/2", "", "voip"), ("1/1/3", "", "voip"), ("1/1/48", "", "uplink-core")],
               neighbors=[("1/1/48", "hq-core1", "Te1/1/5"), ("1/1/1", "hq-ap2", "eth0")], cpu=11, mem=47), "HQ-Manila")
    add(NxosSim("hq-dc1", "10.10.0.31", "Nexus9000 C93180YC-FX", "10.3(4a)", "FDO22330ABC",
                ifaces=[("Ethernet1/1", "", "esx-host1"), ("Ethernet1/2", "", "esx-host2"), ("Ethernet1/48", "", "uplink-core")],
                neighbors=[("Eth1/48", "hq-core1", "Te1/1/4")], cpu=27, mem=61), "HQ-Manila")
    add(InstantSim("hq-ap1", "10.10.0.101", "AP-515", "8.10.0.7", "CNK1234567", ssids=("Corp-WiFi", "Guest", "IoT"),
                   ifaces=[("eth0", "", "")], neighbors=[("eth0", "hq-dist1", "1/1/1")], clients=64, aps=4, cpu=21, mem=44), "HQ-Manila")
    add(UnleashedSim("hq-ap2", "10.10.0.102", "R650", "200.15.6.212.123", "512345678901", ssids=("HQ-Staff", "HQ-Guest"),
                     ifaces=[("eth0", "", "")], neighbors=[("eth0", "hq-dist2", "1/1/1")], clients=41, aps=3, cpu=17, mem=39), "HQ-Manila")
    # ---------- Branch Cebu
    add(FortiSim("cebu-fw1", "10.20.0.1", "FortiGate-100F", "7.2.8", "FG100FTK20012345",
                 ifaces=[("port1", "192.0.2.10", "isp1"), ("port2", "10.20.1.1", "lan"), ("port3", "", "")],
                 neighbors=[("port2", "cebu-sw1", "1/1/48")], cpu=31, mem=55), "Branch-Cebu")
    add(CxSim("cebu-sw1", "10.20.0.11", "JL677A", "FL.10.12.1000", "SG87654321",
              ifaces=[("1/1/1", "", "to-ap"), ("1/1/2", "", "users"), ("1/1/3", "", "users"), ("1/1/48", "", "uplink-fw")],
              neighbors=[("1/1/48", "cebu-fw1", "port2"), ("1/1/1", "cebu-ap1", "eth0")], cpu=8, mem=29), "Branch-Cebu")
    LAB["cebu-sw1"].telnet = True
    add(UnleashedSim("cebu-ap1", "10.20.0.101", "R550", "200.15.6.212.123", "512345678902", ssids=("Cebu-Staff", "Cebu-Guest"),
                     ifaces=[("eth0", "", "")], neighbors=[("eth0", "cebu-sw1", "1/1/1")], clients=23, aps=2, cpu=12, mem=35), "Branch-Cebu")
    # ---------- Branch Davao & remote sites (MikroTik heavy)
    add(RouterOsSim("davao-rtr1", "10.30.0.1", "RB5009UG+S+", "7.14.3", "HF1234567",
                    ifaces=[("ether1", "", "isp-fiber"), ("ether2", "", "lan-trunk"), ("ether3", "", "backup-lte"), ("ether4", "", "")],
                    neighbors=[("ether2", "davao-sw1", "1/1/48")], cpu=12, mem=33), "Branch-Davao")
    add(IcxSim("davao-sw1", "10.30.0.11", "ICX7150-24P", "09.0.10T213", "CRH2302K11B",
               ifaces=[("1/1/1", "", "to-ap"), ("1/1/2", "", "users"), ("1/1/24", "", "")],
               neighbors=[("1/1/1", "davao-ap1", "eth0"), ("1/1/24", "davao-rtr1", "ether2")], cpu=6, mem=40), "Branch-Davao")
    LAB["davao-sw1"].neighbors[1] = ("1/1/24", "davao-rtr1", "ether2")
    add(InstantSim("davao-ap1", "10.30.0.101", "AP-505", "8.10.0.7", "CNK7654321", ssids=("Davao-Staff", "Guest"),
                   ifaces=[("eth0", "", "")], neighbors=[("eth0", "davao-sw1", "1/1/1")], clients=17, aps=1, cpu=9, mem=31), "Branch-Davao")
    add(RouterOsSim("clark-edge1", "10.40.0.1", "hAP ax3", "7.15.1", "HF9988776",
                    ifaces=[("ether1", "", "isp"), ("ether2", "", "lan"), ("ether3", "", "")], neighbors=[], cpu=44, mem=58), "Remote-Clark")
    LAB["clark-edge1"].telnet = True
    LAB["clark-edge1"].services["telnet"] = True
    # wiring: fleet back-references + mark interface names in neighbor lists to real names
    for s in LAB.values():
        s.fleet = LAB
    LAB["hq-core1"].snmp_public = True
    LAB["cebu-fw1"].allow["port1"].append("telnet") if hasattr(LAB["cebu-fw1"], "allow") else None
    LAB["cebu-fw1"].telnet = True
    # Davao router neighbour discovery
    LAB["davao-rtr1"].neighbors = [("ether2", "davao-sw1", "1/1/24")]
    return spec


def set_power(name: str, up: bool):
    """Fault injection: power a device off/on and flap the links facing it."""
    s = LAB[name]
    s.reachable = up
    for o in LAB.values():
        for (lif, rh, rif) in o.neighbors:
            if rh == name:
                i = o.find_if(lif)
                if i:
                    i["link"] = up


def set_cpu(name: str, pct: float):
    LAB[name].cpu = pct


def link_fault(name: str, ifname: str, down: bool = True):
    i = LAB[name].find_if(ifname)
    if not i:
        raise KeyError(ifname)
    i["link"] = not down


# ---- traffic / degradation fault injection (drives the predictive-monitoring demo)
def _traffic(name: str):
    from .sim.telemetry import TrafficModel
    s = LAB[name]
    if s.traffic is None:
        s.traffic = TrafficModel(s)
    return s.traffic


def degrade(name: str, ifname: str, kind: str, start_in_s: float = 0.0, **kw) -> bool:
    return _traffic(name).inject(ifname, kind, start_in_s=start_in_s, **kw)


def heal(name: str, ifname: str) -> bool:
    return _traffic(name).heal(ifname)


DEMO_DEGRADATIONS = (
    # (device, interface, kind, start_in_s after the 6 h backfill begins, parameters)
    ("hq-core1", "TenGigabitEthernet1/1/2", "errors", 3600, dict(per_min=1.0, growth_per_h=12.0)),
    ("hq-fw2", "port1", "errors", 3600, dict(per_min=0.8, growth_per_h=9.0)),          # far end of the same link -> "shared cable" cause
    ("hq-dist2", "1/1/48", "optic", 1800, dict(db_per_h=1.4)),
    ("cebu-sw1", "1/1/48", "utilization", 3600, dict(per_h=0.09)),
    ("davao-sw1", "1/1/2", "flap", 7200, dict(per_h=3.0, growth_per_h=2.0)),
    ("hq-fw1", "ethernet1/3", "silent", 16200, {}),
)
