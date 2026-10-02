"""Interface-counter parsers, one per vendor dialect.

Device output is untrusted input: every parser tolerates garbage, caps the number of interfaces,
validates names and clamps numbers.  A parser never raises on malformed text - it returns what it understood."""
from __future__ import annotations

import itertools
import re
from typing import Callable

from ..models import Counters

MAX_IFACES = 512
MAX_COUNTER = 2 ** 64 - 1
_NAME_OK = re.compile(r"^[A-Za-z0-9][\w./:\-]{0,63}$")
_NUM = re.compile(r"\d{1,20}")


def _n(v) -> int:
    try:
        i = int(str(v).strip())
    except (TypeError, ValueError):
        return 0
    return min(max(i, 0), MAX_COUNTER)


def _f(v) -> float | None:
    try:
        x = float(str(v).strip())
    except (TypeError, ValueError):
        return None
    if x != x or x in (float("inf"), float("-inf")):
        return None
    return max(-60.0, min(40.0, x))


def _ok(name: str) -> bool:
    return bool(_NAME_OK.match(name or ""))


def _collect(items: list[Counters]) -> list[Counters]:
    seen, out = set(), []
    for c in items:
        if c.name in seen or not _ok(c.name):
            continue
        seen.add(c.name)
        out.append(c)
        if len(out) >= MAX_IFACES:
            break
    return out


MAX_TEXT = 4 * 1024 * 1024


def _blocks(text: str, start_re: re.Pattern) -> list[tuple[re.Match, str]]:
    text = (text or "")[:MAX_TEXT]
    ms = list(itertools.islice(start_re.finditer(text), MAX_IFACES * 2 + 1))     # bounded work whatever the device sends
    return [(m, text[m.end(): ms[k + 1].start() if k + 1 < len(ms) else len(text)]) for k, m in enumerate(ms)]


def _g(pat: str, s: str, flags=re.I | re.M):
    m = re.search(pat, s, flags)
    return m.group(1) if m else None


# --------------------------------------------------------------------------- Cisco IOS-XE
def iosxe_counters(text: str) -> list[Counters]:
    out = []
    for m, b in _blocks(text, re.compile(r"^(\S+) is (?:administratively down|up|down)\b[^\n]*$", re.M)):
        c = Counters(m.group(1))
        bw = _g(r"\bBW (\d{1,12}) Kbit", b)
        c.speed_bps = _n(bw) * 1000 if bw else 0
        c.in_octets = _n(_g(r"packets input, (\d+) bytes", b))
        c.out_octets = _n(_g(r"packets output, (\d+) bytes", b))
        c.in_errors = _n(_g(r"(\d+) input errors", b))
        c.out_errors = _n(_g(r"(\d+) output errors", b))
        c.resets = _n(_g(r"(\d+) interface resets", b))
        c.out_discards = _n(_g(r"Total output drops: (\d+)", b))
        c.in_discards = _n(_g(r"Input queue: \d+/\d+/(\d+)/", b))
        out.append(c)
    return _collect(out)


def iosxe_optics(text: str) -> list[Counters]:
    out = []
    for m, b in _blocks(text, re.compile(r"^([A-Za-z][\w./:\-]*)\s*$", re.M)):
        r = _g(r"Rx Power\s*:\s*(-?\d+(?:\.\d+)?) dBm", b)
        if r is None:
            continue
        out.append(Counters(m.group(1), rx_dbm=_f(r), rx_low_alarm=_f(_g(r"Low Alarm (-?\d+(?:\.\d+)?)", b)),
                            rx_low_warn=_f(_g(r"Low Warn (-?\d+(?:\.\d+)?)", b))))
    return out


# --------------------------------------------------------------------------- Cisco NX-OS
def nxos_counters(text: str) -> list[Counters]:
    out = []
    for m, b in _blocks(text, re.compile(r"^(\S+) is (?:up|down|administratively down)[^\n]*$", re.M)):
        c = Counters(m.group(1))
        bw = _g(r"\bBW (\d{1,12}) Kbit", b)
        c.speed_bps = _n(bw) * 1000 if bw else 0
        c.in_octets = _n(_g(r"input packets\s+(\d+) bytes", b))
        c.out_octets = _n(_g(r"output packets\s+(\d+) bytes", b))
        c.in_errors = _n(_g(r"(\d+) input error", b))
        c.out_errors = _n(_g(r"(\d+) output error", b))
        c.in_discards = _n(_g(r"(\d+) input discard", b))
        c.out_discards = _n(_g(r"(\d+) output discard", b))
        c.resets = _n(_g(r"(\d+) interface resets", b))
        out.append(c)
    return _collect(out)


def nxos_optics(text: str) -> list[Counters]:
    out = []
    for m, b in _blocks(text, re.compile(r"^((?:Ethernet|Eth)\S*)\s*$", re.M)):
        mm = re.search(r"Rx Power\s+(-?\d+(?:\.\d+)?) dBm\s+(-?\d+(?:\.\d+)?) dBm\s+(-?\d+(?:\.\d+)?) dBm\s+(-?\d+(?:\.\d+)?) dBm\s+(-?\d+(?:\.\d+)?) dBm", b)
        if mm:      # current, high alarm, low alarm, high warn, low warn
            out.append(Counters(m.group(1), rx_dbm=_f(mm.group(1)), rx_low_alarm=_f(mm.group(3)), rx_low_warn=_f(mm.group(5))))
    return out


# --------------------------------------------------------------------------- generic "table with header" (ICX, MikroTik)
def _lines(text: str) -> list[str]:
    return (text or "")[:MAX_TEXT].split("\n", MAX_IFACES * 2 + 100)[:MAX_IFACES * 2 + 100]


def _speed_tok(tok: str) -> int:
    m = re.match(r"(?i)^(\d+(?:\.\d+)?)\s*([kmgt])(?:bps|b/s|bit)?$", tok or "")
    if not m:
        return 0
    return int(float(m.group(1)) * {"k": 10 ** 3, "m": 10 ** 6, "g": 10 ** 9, "t": 10 ** 12}[m.group(2).lower()])


def icx_counters(text: str) -> list[Counters]:
    lines = _lines(text)
    hdr = next((i for i, l in enumerate(lines) if re.match(r"^\s*Port\s{2,}In Octets", l)), None)
    if hdr is None:
        return []
    cols = [c.strip().lower() for c in re.split(r"\s{2,}", lines[hdr].strip())]
    out = []
    for l in lines[hdr + 1:]:
        tok = l.split()
        if len(tok) < 3:
            continue
        # columns are whitespace separated single tokens; "Speed" is the last one
        row = dict(zip(cols, tok))
        c = Counters(tok[0], in_octets=_n(row.get("in octets")), out_octets=_n(row.get("out octets")),
                     in_errors=_n(row.get("in errors")), out_errors=_n(row.get("out errors")),
                     in_discards=_n(row.get("in drops")), out_discards=_n(row.get("out drops")),
                     resets=_n(row.get("link resets")), speed_bps=_speed_tok(row.get("speed", "")))
        out.append(c)
    return _collect(out)


def icx_optics(text: str) -> list[Counters]:
    out = []
    for l in _lines(text):
        m = re.match(r"^(\d+/\d+/\d+)\s+.*?(-?\d+\.\d+) dBm\s+(Normal|Low-Warn|Low-Alarm|High-Warn|High-Alarm)\s", l)
        if not m:
            continue
        # the first dBm on the row is Tx; Rx is the second
        dbm = re.findall(r"(-?\d+\.\d+) dBm", l)
        if len(dbm) >= 2:
            out.append(Counters(m.group(1), rx_dbm=_f(dbm[1])))
    return out


def mikrotik_counters(text: str) -> list[Counters]:
    lines = _lines(text)
    hdr = next((i for i, l in enumerate(lines) if re.search(r"\bNAME\b", l) and re.search(r"RX-BYTE", l)), None)
    if hdr is None:
        return []
    cols = lines[hdr].split()
    cols = [c.lower() for c in cols if c != "#"]
    out = []
    for l in lines[hdr + 1:]:
        tok = l.split()
        if tok and tok[0].isdigit():
            tok = tok[1:]
        if tok and re.fullmatch(r"[DXRSIC]{1,4}", tok[0]):
            tok = tok[1:]
        if len(tok) < 2:
            continue
        row = dict(zip(cols, tok))
        out.append(Counters(row["name"], in_octets=_n(row.get("rx-byte")), out_octets=_n(row.get("tx-byte")),
                            in_errors=_n(row.get("rx-error")), out_errors=_n(row.get("tx-error")),
                            in_discards=_n(row.get("rx-drop")), out_discards=_n(row.get("tx-drop")),
                            resets=_n(row.get("link-downs")), speed_bps=_speed_tok(row.get("speed", ""))))
    return _collect(out)


# --------------------------------------------------------------------------- Aruba AOS-CX
def cx_counters(text: str) -> list[Counters]:
    out = []
    for m, b in _blocks(text, re.compile(r"^Interface (\S+) is (?:up|down)[^\n]*$", re.M)):
        c = Counters(m.group(1))
        sp = _g(r"Link speed:\s*(\d+) Mb/s", b)
        c.speed_bps = _n(sp) * 1_000_000 if sp else 0
        c.resets = _n(_g(r"Link transitions:\s*(\d+)", b))
        rx, _, tx = b.partition("\n Tx")
        c.in_octets = _n(_g(r"input packets\s+(\d+) bytes", rx))
        c.in_errors = _n(_g(r"(\d+) input error", rx))
        c.in_discards = _n(_g(r"(\d+) dropped", rx))
        c.out_octets = _n(_g(r"output packets\s+(\d+) bytes", tx))
        c.out_errors = _n(_g(r"(\d+) output error", tx))
        c.out_discards = _n(_g(r"(\d+) dropped", tx))
        out.append(c)
    return _collect(out)


def cx_optics(text: str) -> list[Counters]:
    out = []
    for m, b in _blocks(text, re.compile(r"^Interface (\S+)\s*$", re.M)):
        r = _g(r"^\s*Rx Power\s*:\s*(-?\d+(?:\.\d+)?) dBm", b)
        if r is None:
            continue
        out.append(Counters(m.group(1), rx_dbm=_f(r), rx_low_warn=_f(_g(r"Rx Power Low Warn\s*:\s*(-?\d+(?:\.\d+)?)", b)),
                            rx_low_alarm=_f(_g(r"Rx Power Low Alarm\s*:\s*(-?\d+(?:\.\d+)?)", b))))
    return out


# --------------------------------------------------------------------------- FortiOS
def forti_counters(text: str) -> list[Counters]:
    out = []
    for m, b in _blocks(text, re.compile(r"^if=(\S+)[^\n]*$", re.M)):
        head = text[m.start(): m.end()]
        kv = dict(re.findall(r"\b(\w+)=(\d+)", b))
        sp = _g(r"\bspeed=(\d+)", head)
        out.append(Counters(m.group(1), in_octets=_n(kv.get("rxb")), out_octets=_n(kv.get("txb")),
                            in_errors=_n(kv.get("rxe")), out_errors=_n(kv.get("txe")), in_discards=_n(kv.get("rxd")),
                            out_discards=_n(kv.get("txd")), resets=_n(kv.get("txc")),
                            speed_bps=_n(sp) * 1_000_000 if sp else 0))
    return _collect(out)


# --------------------------------------------------------------------------- PAN-OS
def pan_counters(text: str) -> list[Counters]:
    out = []
    for m, b in _blocks(text, re.compile(r"^interface:\s*(\S+)\s*$", re.M)):
        g = lambda k: _n(_g(rf"^{k}\s+(\d+)\s*$", b))
        sp = _g(r"^link speed \(Mbps\)\s+(\d+)", b)
        out.append(Counters(m.group(1), in_octets=g("bytes received"), out_octets=g("bytes transmitted"), in_errors=g("receive errors"),
                            out_errors=g("transmit errors"), in_discards=g("receive packets dropped"),
                            out_discards=g("transmit packets dropped"), resets=g("link state changes"),
                            speed_bps=_n(sp) * 1_000_000 if sp else 0))
    return _collect(out)


# --------------------------------------------------------------------------- Ruckus Unleashed / Aruba Instant
def unleashed_counters(text: str) -> list[Counters]:
    out = []
    for m, b in _blocks(text, re.compile(r"^\s{2}(\S+):\s*$", re.M)):
        g = lambda k: _n(_g(rf"^\s*{k}=\s*(\d+)", b))
        out.append(Counters(m.group(1), in_octets=g("RX bytes"), out_octets=g("TX bytes"), in_errors=g("RX errors"), out_errors=g("TX errors"),
                            in_discards=g("RX dropped"), out_discards=g("TX dropped"), resets=g("Link flaps"),
                            speed_bps=g("Speed") * 1_000_000))
    return _collect(out)


def instant_counters(text: str) -> list[Counters]:
    out = []
    for m, b in _blocks(text, re.compile(r"^([A-Za-z][\w.\-]*)\s+Link encap:[^\n]*$", re.M)):
        rxm = re.search(r"^\s*RX packets:\d+ errors:(\d+) dropped:(\d+)", b, re.M)
        txm = re.search(r"^\s*TX packets:\d+ errors:(\d+) dropped:(\d+) overruns:\d+ carrier:(\d+)", b, re.M)
        by = re.search(r"RX bytes:(\d+).*?TX bytes:(\d+)", b)
        out.append(Counters(m.group(1), in_octets=_n(by.group(1)) if by else 0, out_octets=_n(by.group(2)) if by else 0,
                            in_errors=_n(rxm.group(1)) if rxm else 0, in_discards=_n(rxm.group(2)) if rxm else 0,
                            out_errors=_n(txm.group(1)) if txm else 0, out_discards=_n(txm.group(2)) if txm else 0,
                            resets=_n(txm.group(3)) if txm else 0))
    return _collect(out)


PARSERS: dict[tuple[str, str], Callable[[str], list[Counters]]] = {
    ("cisco_iosxe", "counters"): iosxe_counters, ("cisco_iosxe", "optics"): iosxe_optics,
    ("cisco_nxos", "counters"): nxos_counters, ("cisco_nxos", "optics"): nxos_optics,
    ("ruckus_icx", "counters"): icx_counters, ("ruckus_icx", "optics"): icx_optics,
    ("aruba_aoscx", "counters"): cx_counters, ("aruba_aoscx", "optics"): cx_optics,
    ("fortinet_fortios", "counters"): forti_counters,
    ("paloalto_panos", "counters"): pan_counters,
    ("mikrotik_routeros", "counters"): mikrotik_counters,
    ("ruckus_unleashed", "counters"): unleashed_counters,
    ("aruba_instant", "counters"): instant_counters,
}

COMMANDS: dict[str, dict[str, str]] = {
    "cisco_iosxe": {"counters": "show interfaces", "optics": "show interfaces transceiver detail"},
    "cisco_nxos": {"counters": "show interface", "optics": "show interface transceiver details"},
    "ruckus_icx": {"counters": "show statistics", "optics": "show optic"},
    "aruba_aoscx": {"counters": "show interface", "optics": "show interface transceiver detail"},
    "fortinet_fortios": {"counters": "diagnose netlink interface list"},
    "paloalto_panos": {"counters": "show counter interface all"},
    "mikrotik_routeros": {"counters": "/interface print stats"},
    "ruckus_unleashed": {"counters": "show eth-counters"},
    "aruba_instant": {"counters": "show interface counters"},
}


def merge(parts: dict[str, list[Counters]]) -> list[Counters]:
    """counters is authoritative for the interface list; optics only decorate matching ports."""
    base = {c.name: c for c in parts.get("counters", [])}
    for o in parts.get("optics", []):
        c = base.get(o.name)
        if c is None:
            continue
        c.rx_dbm, c.rx_low_warn, c.rx_low_alarm = o.rx_dbm, o.rx_low_warn, o.rx_low_alarm
    return list(base.values())
