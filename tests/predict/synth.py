"""Synthetic interface-telemetry generator used to unit-test and benchmark the predictive engine.

Deliberately independent of the device simulators (no circularity): it produces 5-minute bucket Series
with a diurnal load curve, noise, bursts, benign error blips and optical drift, plus optional injected faults
whose ground-truth failure time is known."""
from __future__ import annotations

import math
import random
from dataclasses import dataclass

from opennetcontrol.ai.predict import Series, BUCKET

T0 = 1_700_000_000 - (1_700_000_000 % 86400)       # midnight UTC


@dataclass
class Truth:
    kind: str | None             # fault kind or None (healthy)
    onset: float | None = None   # when the fault starts
    failure: float | None = None # when it crosses the impact threshold (None = immediate / n/a)


def make(seed: int, hours: float, fault: str | None = None, fault_at_h: float | None = None, speed: int = 10 ** 9,
         hard: bool = True) -> tuple[Series, Truth, float]:
    """returns (full series, truth, bucket count). `hard` adds diurnal swings up to 80 %, bursts and benign blips."""
    r = random.Random(seed)
    n = int(hours * 3600 / BUCKET)
    base = r.uniform(0.02, 0.45)
    amp = r.uniform(0.1, 0.8 if hard else 0.4)
    ph = r.random()
    noise = r.uniform(0.03, 0.15)
    rx0 = r.gauss(-4.5, 1.2)
    has_optic = r.random() < 0.5 or fault == "optic"
    onset_h = fault_at_h if fault_at_h is not None else r.uniform(hours * 0.45, hours * 0.7)
    onset = T0 + onset_h * 3600
    truth = Truth(fault, onset if fault else None)
    p = {}
    if fault == "errors":
        p = dict(r0=r.uniform(0.5, 3), g=r.uniform(8, 60))
        truth.failure = onset + (100 - p["r0"]) / p["g"] * 3600
    elif fault == "optic":
        p = dict(rate=r.uniform(0.25, 1.5))
        truth.failure = onset + (rx0 + 14) / p["rate"] * 3600
    elif fault == "util":
        p = dict(g=r.uniform(0.04, 0.12))
        truth.failure = onset + max(0.0, 0.9 - base) / p["g"] * 3600
    elif fault == "flap":
        p = dict(rate=r.uniform(4, 15))
        truth.failure = onset
    elif fault == "silent":
        truth.failure = onset
    t = [T0 + i * BUCKET for i in range(n)]
    util, bps, err, disc, flaps, rx = [], [], [], [], [], []
    burst_left, burst_mul = 0, 1.0
    blip_bucket = r.randrange(n) if (hard and r.random() < 0.15) else -1
    drift_amp = r.uniform(0, 0.3)
    for i, ti in enumerate(t):
        h = (ti - T0) / 3600
        d = 1 + amp * math.sin(2 * math.pi * (h / 24 - ph))
        if burst_left == 0 and hard and r.random() < 0.004:
            burst_left, burst_mul = r.randint(1, 3), r.uniform(1.4, 3.0)
        m = burst_mul if burst_left > 0 else 1.0
        burst_left = max(0, burst_left - 1)
        u = base * d * m * (1 + r.gauss(0, noise))
        hh = h - onset_h
        if fault == "util" and hh > 0:
            u += p["g"] * hh
        if fault == "silent" and hh > 0:
            u *= 0.01
        u = min(1.0, max(0.0, u))
        util.append(u)
        bps.append(u * speed)
        e = 0.01 * r.random() * 2 if r.random() < 0.05 else 0.0
        if i == blip_bucket:
            e = r.uniform(0.2, 1.0)
        if fault == "errors" and hh > 0:
            e += max(0, p["r0"] + p["g"] * hh) * (1 + r.gauss(0, 0.1))
        err.append(max(0.0, e))
        disc.append(2000 * (u - 0.92) / 0.08 if u > 0.92 else 0.0)
        f = 1.0 if r.random() < 0.003 else 0.0
        if fault == "flap" and hh > 0:
            f += sum(1 for _ in range(int(p["rate"] / 12 + r.random())))
        flaps.append(f)
        if has_optic:
            v = rx0 + drift_amp * math.sin(2 * math.pi * h / 24) + r.gauss(0, 0.05)
            if fault == "optic" and hh > 0:
                v -= p["rate"] * hh
            rx.append(max(-40, v))
        else:
            rx.append(None)
    s = Series(t, util, bps, err, disc, flaps, rx, [1.0] * n, speed=speed, low_warn=-12.0, low_alarm=-14.0)
    return s, truth, n


def cut(s: Series, upto: int) -> Series:
    k = lambda a: a[:upto]
    return Series(k(s.t), k(s.util), k(s.bps), k(s.err), k(s.disc), k(s.flaps), k(s.rx), k(s.up), s.speed, s.low_warn, s.low_alarm)
