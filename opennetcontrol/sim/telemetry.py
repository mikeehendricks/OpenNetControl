"""Interface-traffic model for the simulators.

Counters are integrated lazily (60 s steps) from per-interface profiles: a diurnal load curve plus
injectable degradations (CRC-error ramp, optical-power decay, utilisation growth, flapping, silent traffic
loss).  Output is rendered in a vendor-flavoured CLI dialect for each platform so that the real driver
parsers are exercised end-to-end.  Deterministic given the interface name (seeded RNG)."""
from __future__ import annotations

import math
import random
import re
import zlib
from dataclasses import dataclass, field

from .clock import CLOCK

G = 1_000_000_000
STEP = 60.0


def _poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0:
        return 0
    if lam > 30:
        return max(0, int(round(rng.gauss(lam, math.sqrt(lam)))))
    l, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= l:
            return k
        k += 1


@dataclass
class Profile:
    speed: int = G
    base: float = 0.05               # mean utilisation (fraction of speed)
    diurnal: float = 0.35            # relative day/night swing
    phase: float = 0.0
    noise: float = 0.06
    in_ratio: float = 0.7
    has_optic: bool = False
    rx0: float = -4.5
    low_warn: float = -12.0
    low_alarm: float = -14.0
    # injected faults (absolute simulation timestamps; None = inactive)
    err_t0: float | None = None
    err_pm0: float = 0.0             # errors/min at onset
    err_growth: float = 0.0          # extra errors/min per hour
    optic_t0: float | None = None
    optic_db_per_h: float = 0.0
    growth_t0: float | None = None
    growth_per_h: float = 0.0        # absolute utilisation fraction per hour
    flap_t0: float | None = None
    flap0_per_h: float = 0.0
    flap_growth: float = 0.0
    silent_t0: float | None = None


def default_profile(platform: str, name: str, desc: str) -> Profile:
    d = (desc or "").lower()
    n = name.lower()
    up10 = n.startswith(("tengig", "te")) or "uplink" in d or n in ("ethernet1/48",)
    speed = 10 * G if up10 else G
    seed = zlib.crc32(f"{platform}/{name}".encode())
    # deterministic simulation noise, never used for security purposes
    r = random.Random(seed)  # nosec B311
    if not d:
        base = 0.002
    elif "uplink" in d or d.startswith("to-") or "isp" in d or "trunk" in d:
        base = 0.22 + 0.1 * r.random()
        if speed == G:
            base += 0.1
    elif d.startswith(("esx", "wan")):
        base = 0.12 * r.random() + 0.04
    else:
        base = 0.03 + 0.07 * r.random()
    return Profile(speed=speed, base=base, phase=r.random(), has_optic=speed >= 10 * G or "uplink" in d)


@dataclass
class IfTraffic:
    name: str
    p: Profile
    t: float
    rng: random.Random
    in_o: int = 0
    out_o: int = 0
    in_e: int = 0
    out_e: int = 0
    in_d: int = 0
    out_d: int = 0
    resets: int = 0
    rx: float = -4.5
    dead: bool = False
    util: float = 0.0

    def advance(self, to: float, iface: dict) -> None:
        if to - self.t > 14 * 86400:      # never integrate absurd spans
            self.t = to - 14 * 86400
        while self.t < to - 1e-6:
            dt = min(STEP, to - self.t)
            self._step(dt, self.t + dt / 2, iface)
            self.t += dt

    def _step(self, dt: float, tm: float, iface: dict) -> None:
        p, rng = self.p, self.rng
        # ---- optics
        if p.has_optic:
            drop = p.optic_db_per_h * max(0.0, tm - p.optic_t0) / 3600 if p.optic_t0 is not None else 0.0
            self.rx = max(-40.0, p.rx0 - drop + rng.gauss(0, 0.04))
            if self.rx < p.low_alarm - 4.0 and not self.dead:      # below receiver sensitivity: hard link loss
                self.dead = True
                iface["link"] = False
        up = iface["admin"] and iface["link"]
        if not up:
            self.util = 0.0
            return
        # ---- load
        u = p.base * (1 + p.diurnal * math.sin(2 * math.pi * (tm / 86400 - p.phase))) * (1 + rng.gauss(0, p.noise))
        if p.growth_t0 is not None and tm >= p.growth_t0:
            u += p.growth_per_h * (tm - p.growth_t0) / 3600
        if p.silent_t0 is not None and tm >= p.silent_t0:
            u *= 0.01
        u = min(1.0, max(0.0, u))
        self.util = u
        out_bps = u * p.speed
        self.out_o += int(out_bps / 8 * dt)
        self.in_o += int(out_bps * p.in_ratio / 8 * dt)
        # ---- errors (background noise is tiny so that healthy ports do not look sick)
        pm = 0.01
        if p.err_t0 is not None and tm >= p.err_t0:
            pm += p.err_pm0 + p.err_growth * (tm - p.err_t0) / 3600
        if p.has_optic and self.rx < p.low_alarm:
            pm += 40 * (p.low_alarm - self.rx)
        self.in_e += _poisson(rng, pm * dt / 60)
        if u > 0.92:
            self.out_d += _poisson(rng, 2000 * (u - 0.92) / 0.08 * dt / 60)
        if p.flap_t0 is not None and tm >= p.flap_t0:
            self.resets += _poisson(rng, (p.flap0_per_h + p.flap_growth * (tm - p.flap_t0) / 3600) * dt / 3600)


class TrafficModel:
    """Attached to a SimDevice as `.traffic`."""

    def __init__(self, sim):
        self.sim = sim
        self.ifs: dict[str, IfTraffic] = {}
        self.seed_counters = True

    def get(self, name: str) -> IfTraffic | None:
        iface = self.sim.find_if(name)
        if not iface:
            return None
        key = iface["name"]
        t = self.ifs.get(key)
        if t is None:
            prof = default_profile(self.sim.platform, key, iface["desc"])
            # deterministic simulation noise, never used for security purposes
            rng = random.Random(zlib.crc32(f"{self.sim.name}/{key}".encode()))  # nosec B311
            t = IfTraffic(key, prof, CLOCK.now(), rng, rx=prof.rx0)
            # a device that has been up for a while already carries a history of traffic
            base = int(prof.speed / 8 * prof.base * min(self.sim.uptime, 7 * 86400))
            t.in_o, t.out_o = int(base * prof.in_ratio), base
            self.ifs[key] = t
        return t

    def sync(self):
        now = CLOCK.now()
        out = []
        for i in self.sim.ifaces:
            t = self.get(i["name"])
            t.advance(now, i)
            out.append((i, t))
        return out

    # ---- fault injection (demo / tests)
    def inject(self, ifname: str, kind: str, start_in_s: float = 0.0, **kw) -> bool:
        t = self.get(ifname)
        if t is None:
            return False
        t0 = CLOCK.now() + start_in_s
        p = t.p
        if kind == "errors":
            p.err_t0, p.err_pm0, p.err_growth = t0, kw.get("per_min", 1.0), kw.get("growth_per_h", 20.0)
        elif kind == "optic":
            p.has_optic = True
            p.optic_t0, p.optic_db_per_h = t0, kw.get("db_per_h", 0.8)
        elif kind == "utilization":
            p.growth_t0, p.growth_per_h = t0, kw.get("per_h", 0.04)
        elif kind == "flap":
            p.flap_t0, p.flap0_per_h, p.flap_growth = t0, kw.get("per_h", 2.0), kw.get("growth_per_h", 2.0)
        elif kind == "silent":
            p.silent_t0 = t0
        else:
            return False
        return True

    def heal(self, ifname: str) -> bool:
        t = self.get(ifname)
        if t is None:
            return False
        keep = Profile(speed=t.p.speed, base=t.p.base, phase=t.p.phase, has_optic=t.p.has_optic, in_ratio=t.p.in_ratio)
        t.p = keep
        t.dead = False
        iface = self.sim.find_if(ifname)
        iface["link"] = True
        return True


# ============================================================================ formatters
def _spd_kbit(p: Profile) -> int:
    return p.speed // 1000


def _pk(b: int) -> int:
    return b // 800


def fmt_iosxe(rows) -> str:
    out = []
    for i, t in rows:
        oper = i["admin"] and i["link"]
        st = "up" if oper else ("administratively down" if not i["admin"] else "down")
        out += [f"{i['name']} is {st}, line protocol is {'up' if oper else 'down'} (connected)" if oper else f"{i['name']} is {st}, line protocol is down (notconnect)",
                f"  Description: {i['desc']}" if i["desc"] else "  Hardware is Gigabit Ethernet",
                f"  MTU 1500 bytes, BW {_spd_kbit(t.p)} Kbit/sec, DLY 10 usec,",
                f"  {_pk(t.in_o)} packets input, {t.in_o} bytes, 0 no buffer",
                f"     {t.in_e} input errors, {t.in_e} CRC, 0 frame, 0 overrun, 0 ignored",
                f"  {_pk(t.out_o)} packets output, {t.out_o} bytes, 0 underruns",
                f"     {t.out_e} output errors, 0 collisions, {t.resets} interface resets",
                f"  Input queue: 0/75/{t.in_d}/0 (size/max/drops/flushes); Total output drops: {t.out_d}", ""]
    return "\n".join(out)


def fmt_nxos(rows) -> str:
    out = []
    for i, t in rows:
        oper = i["admin"] and i["link"]
        out += [f"{i['name']} is {'up' if oper else 'down'}", f"admin state is {'up' if i['admin'] else 'down'},",
                f"  Description: {i['desc']}" if i["desc"] else "  Hardware: 1000/10000 Ethernet",
                f"  MTU 1500 bytes, BW {_spd_kbit(t.p)} Kbit, DLY 10 usec",
                "  RX", f"    {_pk(t.in_o)} unicast packets  0 multicast packets  0 broadcast packets",
                f"    {_pk(t.in_o)} input packets  {t.in_o} bytes",
                f"    {t.in_e} input error  0 short frame  0 overrun   0 underrun  0 ignored",
                f"    0 runt  0 giant  {t.in_e} CRC  0 no buffer", f"    0 input with dribble  {t.in_d} input discard",
                "  TX", f"    {_pk(t.out_o)} output packets  {t.out_o} bytes",
                f"    {t.out_e} output error  0 collision  0 deferred  0 late collision",
                f"    0 lost carrier  0 no carrier  0 babble  {t.out_d} output discard", f"  {t.resets} interface resets", ""]
    return "\n".join(out)


def fmt_icx(rows) -> str:
    out = ["Port        In Octets      Out Octets     In Errors  Out Errors  In Drops  Out Drops  Link Resets  Speed"]
    for i, t in rows:
        sp = f"{t.p.speed // G}G" if t.p.speed >= G else "100M"
        out.append(f"{i['name']:<11} {t.in_o:<14} {t.out_o:<14} {t.in_e:<10} {t.out_e:<11} {t.in_d:<9} {t.out_d:<10} {t.resets:<12} {sp}")
    return "\n".join(out)


def fmt_cx(rows) -> str:
    out = []
    for i, t in rows:
        oper = i["admin"] and i["link"]
        out += [f"Interface {i['name']} is {'up' if oper else 'down'}", f" Admin state is {'up' if i['admin'] else 'down'}",
                f" Description: {i['desc']}", f" Link speed: {t.p.speed // 1_000_000} Mb/s", f" Link transitions: {t.resets}",
                " Rx", f"   {_pk(t.in_o)} input packets   {t.in_o} bytes", f"   {t.in_e} input error    {t.in_d} dropped",
                " Tx", f"   {_pk(t.out_o)} output packets  {t.out_o} bytes", f"   {t.out_e} output error    {t.out_d} dropped", ""]
    return "\n".join(out)


def fmt_forti(rows) -> str:
    out = []
    for n, (i, t) in enumerate(rows):
        oper = i["admin"] and i["link"]
        out += [f"if={i['name']} family=00 type=1 index={n + 3} mtu=1500 link={0 if oper else 1} master=0 speed={t.p.speed // 1_000_000}",
                f"ref=14 state={'start' if i['admin'] else 'stop'} present fw_flags=0 flags={'up ' if oper else ''}broadcast run multicast",
                f"stat: rxp={_pk(t.in_o)} txp={_pk(t.out_o)} rxb={t.in_o} txb={t.out_o} rxe={t.in_e} txe={t.out_e} rxd={t.in_d} txd={t.out_d} mc=0 collision=0 @ time={int(CLOCK.now())}",
                "re: rxl=0 rxo=0 rxc=0 rxf=0 rxfi=0 rxmi=0", f"te: txa=0 txf=0 txc={t.resets} txi=0", ""]
    return "\n".join(out)


def fmt_pan(rows) -> str:
    sep = "-" * 79
    out = [sep, "Hardware interfaces:", sep]
    for i, t in rows:
        out += [f"interface: {i['name']}", sep,
                f"bytes received                      {t.in_o}", f"bytes transmitted                   {t.out_o}",
                f"packets received                    {_pk(t.in_o)}", f"packets transmitted                 {_pk(t.out_o)}",
                f"receive errors                      {t.in_e}", f"transmit errors                     {t.out_e}",
                f"receive packets dropped             {t.in_d}", f"transmit packets dropped            {t.out_d}",
                f"link state changes                  {t.resets}", f"link speed (Mbps)                   {t.p.speed // 1_000_000}", sep]
    return "\n".join(out)


def fmt_mikrotik(rows) -> str:
    out = ["Flags: D - DYNAMIC; R - RUNNING; S - SLAVE", " #    NAME      RX-BYTE        TX-BYTE        RX-ERROR  TX-ERROR  RX-DROP  TX-DROP  LINK-DOWNS  SPEED"]
    for n, (i, t) in enumerate(rows):
        fl = "X " if not i["admin"] else ("R " if i["link"] else "  ")
        out.append(f"{n:>2} {fl}{i['name']:<9} {t.in_o:<14} {t.out_o:<14} {t.in_e:<9} {t.out_e:<9} {t.in_d:<8} {t.out_d:<8} {t.resets:<11} {t.p.speed // G}Gbps")
    return "\n".join(out)


def fmt_unleashed(rows) -> str:
    out = ["Ethernet Statistics:"]
    for i, t in rows:
        out += [f"  {i['name']}:", f"    RX bytes= {t.in_o}", f"    TX bytes= {t.out_o}", f"    RX errors= {t.in_e}", f"    TX errors= {t.out_e}",
                f"    RX dropped= {t.in_d}", f"    TX dropped= {t.out_d}", f"    Link flaps= {t.resets}", f"    Speed= {t.p.speed // 1_000_000}"]
    return "\n".join(out)


def fmt_instant(rows) -> str:
    out = []
    for i, t in rows:
        out += [f"{i['name']}   Link encap:Ethernet  HWaddr 00:0B:86:00:00:01",
                f"       RX packets:{_pk(t.in_o)} errors:{t.in_e} dropped:{t.in_d} overruns:0 frame:0",
                f"       TX packets:{_pk(t.out_o)} errors:{t.out_e} dropped:{t.out_d} overruns:0 carrier:{t.resets}",
                f"       RX bytes:{t.in_o} ({t.in_o // 1048576} MB)  TX bytes:{t.out_o} ({t.out_o // 1048576} MB)", ""]
    return "\n".join(out)


# ---- optics
def _optic_rows(rows):
    return [(i, t) for i, t in rows if t.p.has_optic]


def opt_iosxe(rows) -> str:
    out = []
    for i, t in _optic_rows(rows):
        p = t.p
        out += [f"{i['name']}", f"  Rx Power  : {t.rx:.2f} dBm  [Low Alarm {p.low_alarm:.2f}  Low Warn {p.low_warn:.2f}  High Warn 1.00  High Alarm 2.00]", ""]
    return "\n".join(out)


def opt_nxos(rows) -> str:
    out = []
    for i, t in _optic_rows(rows):
        p = t.p
        out += [i["name"], "    transceiver is present", "    type is 10Gbase-SR",
                "    Temperature   31.20 C   75.00 C  -5.00 C   70.00 C   0.00 C",
                f"    Rx Power    {t.rx:>7.2f} dBm   2.00 dBm  {p.low_alarm:.2f} dBm  1.00 dBm  {p.low_warn:.2f} dBm", ""]
    return "\n".join(out)


def opt_icx(rows) -> str:
    out = ["Port    Temperature    Tx Power               Rx Power                  Tx Bias Current"]
    for i, t in _optic_rows(rows):
        p = t.p
        st = "Low-Alarm" if t.rx < p.low_alarm else ("Low-Warn" if t.rx < p.low_warn else "Normal")
        out.append(f"{i['name']}  33.2000 C  -2.5000 dBm  Normal  {t.rx:.4f} dBm  {st}  6.0 mA  Normal")
    return "\n".join(out)


def opt_cx(rows) -> str:
    out = []
    for i, t in _optic_rows(rows):
        p = t.p
        out += [f"Interface {i['name']}", f"  Rx Power            : {t.rx:.2f} dBm", f"  Rx Power Low Warn   : {p.low_warn:.2f} dBm",
                f"  Rx Power Low Alarm  : {p.low_alarm:.2f} dBm", ""]
    return "\n".join(out)


COMMANDS: dict[str, dict[str, object]] = {
    "cisco_iosxe": {"show interfaces": fmt_iosxe, "show interfaces transceiver detail": opt_iosxe},
    "cisco_nxos": {"show interface": fmt_nxos, "show interface transceiver details": opt_nxos},
    "ruckus_icx": {"show statistics": fmt_icx, "show optic": opt_icx},
    "aruba_aoscx": {"show interface": fmt_cx, "show interface transceiver detail": opt_cx},
    "fortinet_fortios": {"diagnose netlink interface list": fmt_forti},
    "paloalto_panos": {"show counter interface all": fmt_pan},
    "mikrotik_routeros": {"/interface print stats": fmt_mikrotik},
    "ruckus_unleashed": {"show eth-counters": fmt_unleashed},
    "aruba_instant": {"show interface counters": fmt_instant},
}


def handle(sim, line: str) -> str | None:
    fn = COMMANDS.get(sim.platform, {}).get(line)
    if fn is None or sim.ctx:
        return None
    tm = getattr(sim, "traffic", None)
    if tm is None:
        tm = sim.traffic = TrafficModel(sim)
    return fn(tm.sync())
