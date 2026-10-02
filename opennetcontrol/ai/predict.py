"""Predictive interface-health engine.

Honest description: this is *statistical online learning*, not deep learning and not an LLM.  For every
interface it learns a robust baseline (median / MAD, hour-of-day profile once >=26 h of history exist),
tests for significant trends (Mann-Kendall), fits robust slopes (Theil-Sen), locates the onset of a change
(CUSUM) and extrapolates to the time at which an impact threshold would be crossed (ETA).  Everything is
explainable: each finding carries the numbers it was derived from.

Pure functions, standard library only, no I/O - easy to test and benchmark on synthetic data.
Input series are 5-minute buckets; invalid values (None / NaN / inf) are dropped defensively."""
from __future__ import annotations

import math
from dataclasses import dataclass, field

BUCKET = 300
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
KINDS = ("errors", "optic", "utilization", "flaps", "traffic", "discards")


@dataclass
class Params:
    util_warn: float = 0.90           # utilisation level considered saturated
    err_crit_pm: float = 100.0        # errors/min considered service-impacting
    err_min_pm: float = 0.1           # mean errors/min in the last hour to call it "persistent"
    optic_warn: float = -12.0         # fallbacks if the module reports no thresholds (typical SR optic)
    optic_alarm: float = -14.0
    horizon_h: float = 72.0           # do not forecast further than this
    min_confidence: float = 0.5
    flap_per_h: float = 3.0
    min_points: int = 12              # one hour of data before any trend claim


@dataclass
class Series:
    t: list[float]                    # bucket start (epoch s), ascending
    util: list[float | None]
    bps: list[float | None]           # max(in,out) bits/s
    err: list[float | None]           # errors per minute (bucket mean)
    disc: list[float | None]          # discards per minute
    flaps: list[float | None]         # link flaps in the bucket
    rx: list[float | None]            # optical receive power dBm
    up: list[float | None]            # fraction of samples in bucket with link up (0..1)
    speed: int = 0
    low_warn: float | None = None
    low_alarm: float | None = None


@dataclass
class Finding:
    kind: str
    severity: str
    confidence: float
    title: str
    detail: str
    eta_ts: float | None = None
    eta_low: float | None = None
    eta_high: float | None = None
    evidence: dict = field(default_factory=dict)


# ============================================================================ statistics
def _clean(vs):
    return [v for v in vs if v is not None and isinstance(v, (int, float)) and math.isfinite(v)]


def median(xs):
    xs = sorted(xs)
    n = len(xs)
    if not n:
        return 0.0
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def mad_sigma(xs):
    if not xs:
        return 0.0
    m = median(xs)
    return 1.4826 * median([abs(x - m) for x in xs])


def pct(xs, q):
    xs = sorted(xs)
    if not xs:
        return 0.0
    k = (len(xs) - 1) * q
    f, c = math.floor(k), math.ceil(k)
    return xs[f] if f == c else xs[f] + (xs[c] - xs[f]) * (k - f)


@dataclass
class Trend:
    slope: float        # units per hour
    intercept: float    # value at t=0 of the x axis passed in (hours)
    z: float
    p: float
    r2: float
    n: int


def trend(th: list[float], vs: list[float], max_pts: int = 120) -> Trend | None:
    """Theil-Sen slope + Mann-Kendall significance.  th is in hours."""
    pts = [(a, b) for a, b in zip(th, vs) if b is not None and math.isfinite(b)]
    n0 = len(pts)
    if n0 < 4:
        return None
    if n0 > max_pts:                       # stride-subsample, always keeping the newest point
        step = n0 / max_pts
        pts = [pts[min(n0 - 1, int(i * step))] for i in range(max_pts)]
        pts[-1] = (th[-1], vs[-1]) if th and vs else pts[-1]
    n = len(pts)
    slopes, S = [], 0
    for i in range(n - 1):
        ti, vi = pts[i]
        for j in range(i + 1, n):
            tj, vj = pts[j]
            d = vj - vi
            S += (d > 0) - (d < 0)
            if tj > ti:
                slopes.append(d / (tj - ti))
    if not slopes:
        return None
    slope = median(slopes)
    icpt = median([v - slope * t for t, v in pts])
    # variance with tie correction
    counts: dict[float, int] = {}
    for _, v in pts:
        counts[v] = counts.get(v, 0) + 1
    var = n * (n - 1) * (2 * n + 5) / 18 - sum(c * (c - 1) * (2 * c + 5) / 18 for c in counts.values() if c > 1)
    if var <= 0:
        z = 0.0
    else:
        z = (S - 1) / math.sqrt(var) if S > 0 else ((S + 1) / math.sqrt(var) if S < 0 else 0.0)
    p = math.erfc(abs(z) / math.sqrt(2))
    mean = sum(v for _, v in pts) / n
    sst = sum((v - mean) ** 2 for _, v in pts)
    ssr = sum((v - (icpt + slope * t)) ** 2 for t, v in pts)
    r2 = max(0.0, min(1.0, 1 - ssr / sst)) if sst > 0 else 0.0
    return Trend(slope, icpt, z, p, r2, n)


def cusum_onset(ts: list[float], xs: list[float], k_sigma=0.5, h_sigma=5.0, rel=0.05, floor=0.02) -> float | None:
    """Earliest time at which the series shifted upward relative to its robust baseline (median of the first half)."""
    if len(xs) < 8:
        return None
    base = xs[: max(4, len(xs) // 2)]
    mu, sd = median(base), max(mad_sigma(base), floor, rel * abs(median(base)))
    s, start = 0.0, None
    for t, x in zip(ts, xs):
        s2 = max(0.0, s + (x - mu - k_sigma * sd))
        if s == 0.0 and s2 > 0.0:
            start = t
        if s2 == 0.0:
            start = None
        s = s2
        if s > h_sigma * sd:
            return start if start is not None else t
    return None


def _conf(tr: Trend, n_needed: int, persistence: float = 1.0) -> float:
    strength = 0.5 * min(1.0, abs(tr.z) / 5.0) + 0.5 * tr.r2
    suff = min(1.0, tr.n / max(1, n_needed))
    return round(max(0.0, min(0.99, 0.55 * strength + 0.25 * suff + 0.2 * persistence)), 2)


def _sev_from_eta(eta_h: float | None, now_breached: bool = False) -> str:
    if now_breached:
        return "critical"
    if eta_h is None:
        return "low"
    if eta_h <= 6:
        return "high"
    if eta_h <= 24:
        return "medium"
    return "low"


def _fmt_eta(h: float) -> str:
    if h < 1:
        return f"~{max(1, int(round(h * 60)))} min"
    if h < 48:
        return f"~{h:.1f} h"
    return f"~{h / 24:.1f} days"


def _valid(s: Series, xs, i):
    """True if bucket i should be used: link up for most of the bucket and value present."""
    v = xs[i]
    u = s.up[i] if i < len(s.up) else 1.0
    return v is not None and math.isfinite(v) and (u is None or u >= 0.5)


def _pairs(s: Series, xs):
    return [(s.t[i], xs[i]) for i in range(len(s.t)) if _valid(s, xs, i)]


# ============================================================================ detectors
def d_errors(s: Series, now: float, P: Params) -> Finding | None:
    pr = _pairs(s, s.err)
    if len(pr) < P.min_points:
        return None
    last = pr[-12:]
    nz = sum(1 for _, v in last if v > 0)
    mean_last = sum(v for _, v in last) / len(last)
    if nz < 6 or mean_last < P.err_min_pm:
        return None
    win = pr[-60:]                                         # last 5 h
    th = [(t - now) / 3600 for t, _ in win]
    vs = [v for _, v in win]
    cur = max(0.0, median([v for _, v in pr[-3:]]))
    onset = cusum_onset([t for t, _ in win], vs)
    # change-point aware: fit the slope on the data since the change began, otherwise the flat history drags the estimate toward zero
    k0 = next((i for i, (t, _) in enumerate(win) if onset is not None and t >= onset), 0)
    k0 = max(0, k0 - 1)
    tr = trend(th[k0:], vs[k0:]) if len(win) - k0 >= 8 else trend(th, vs)
    growing = tr is not None and tr.p < 0.01 and tr.slope > 0
    eta = eta_lo = eta_hi = None
    if growing and cur < P.err_crit_pm:
        slope = tr.slope
        eta = (P.err_crit_pm - cur) / slope
        # optimistic/pessimistic: slope +/-30 %
        eta_lo, eta_hi = (P.err_crit_pm - cur) / (slope * 1.3), (P.err_crit_pm - cur) / (slope * 0.7)
        if eta > P.horizon_h:
            eta = eta_lo = eta_hi = None
    breached = cur >= P.err_crit_pm
    sev = _sev_from_eta(eta, breached) if (growing or breached) else ("medium" if mean_last >= 1 else "low")
    if not growing and not breached and sev == "low" and nz >= 9:
        sev = "medium"
    conf = _conf(tr, 36, min(1.0, nz / 12)) if tr else round(0.5 + 0.05 * min(nz, 12) / 12, 2)
    if not growing:
        conf = min(conf, 0.7)
    title = "Rising interface errors" if growing else "Persistent interface errors"
    det = f"Input errors have been non-zero in {nz} of the last 12 samples (5 min each), averaging {mean_last:.1f}/min now"
    if onset:
        det += f"; the change began about {_fmt_ago(now - onset)} ago"
    if eta is not None:
        det += f". At the current growth (+{tr.slope:.1f}/min per hour) it reaches the service-impacting level of {P.err_crit_pm:.0f}/min in {_fmt_eta(eta)}"
    det += ". Typical causes: damaged/dirty cable or fibre, failing SFP, duplex or speed mismatch."
    return Finding("errors", sev, conf, title, det, now + eta * 3600 if eta else None,
                   now + eta_lo * 3600 if eta_lo else None, now + eta_hi * 3600 if eta_hi else None,
                   {"current_per_min": round(cur, 2), "mean_last_hour": round(mean_last, 2), "nonzero_samples": nz,
                    "slope_per_min_per_h": round(tr.slope, 3) if tr else None, "mk_p": round(tr.p, 5) if tr else None,
                    "onset_ts": onset, "threshold_per_min": P.err_crit_pm})


def d_optic(s: Series, now: float, P: Params) -> Finding | None:
    pr = _pairs(s, s.rx)
    if len(pr) < P.min_points:
        return None
    warn = s.low_warn if s.low_warn is not None else P.optic_warn
    alarm = s.low_alarm if s.low_alarm is not None else P.optic_alarm
    if alarm > warn:
        warn, alarm = alarm, warn
    cur = median([v for _, v in pr[-3:]])
    win = pr[-72:]                                         # last 6 h
    th = [(t - now) / 3600 for t, _ in win]
    vs = [v for _, v in win]
    onset = cusum_onset([t for t, _ in win], [-v for v in vs], rel=0.0, floor=0.05)
    k0 = max(0, next((i for i, (t, _) in enumerate(win) if onset is not None and t >= onset), 0) - 1)
    if len(win) - k0 >= 8:
        th, vs = th[k0:], vs[k0:]
    tr = trend(th, vs)
    sigma = mad_sigma([v - (tr.intercept + tr.slope * t) for t, v in zip(th, vs)]) if tr else 0.0
    drop = -(tr.slope * (th[-1] - th[0])) if tr else 0.0
    declining = tr is not None and tr.p < 0.01 and tr.slope <= -0.05 and drop >= max(0.5, 3 * sigma)
    if cur < alarm:
        return Finding("optic", "critical", 0.95, "Optical receive power below alarm threshold",
                       f"Receive power is {cur:.1f} dBm, below the module's low-alarm level ({alarm:.1f} dBm). The link is at or near failure; "
                       "clean/replace the transceiver or inspect the fibre path.", None, None, None,
                       {"rx_dbm": round(cur, 2), "low_warn": warn, "low_alarm": alarm, "slope_db_per_h": round(tr.slope, 3) if tr else None})
    if not declining and cur >= warn:
        return None
    eta = eta_lo = eta_hi = None
    if declining:
        target = alarm
        eta = (cur - target) / -tr.slope
        eta_lo, eta_hi = (cur - target) / (-tr.slope * 1.3), (cur - target) / (-tr.slope * 0.7)
        if eta > P.horizon_h:
            eta = eta_lo = eta_hi = None
    if not declining:                                      # below warning but stable
        return Finding("optic", "medium", 0.7, "Optical receive power below warning threshold",
                       f"Receive power is {cur:.1f} dBm (warning level {warn:.1f} dBm) and stable. Margin is thin; plan to clean or replace the optic.",
                       None, None, None, {"rx_dbm": round(cur, 2), "low_warn": warn, "low_alarm": alarm})
    sev = _sev_from_eta(eta)
    if cur < warn and sev == "low":
        sev = "medium"
    det = (f"Receive power has fallen {drop:.1f} dB over the last {(th[-1] - th[0]):.1f} h ({tr.slope:.2f} dB/h), now {cur:.1f} dBm. "
           f"Low-alarm level is {alarm:.1f} dBm" + (f"; at this rate it is reached in {_fmt_eta(eta)}" if eta else "") +
           ". Typical causes: dirty or bent fibre, ageing transceiver, failing patch connector.")
    return Finding("optic", sev, _conf(tr, 48), "Optical signal degrading", det,
                   now + eta * 3600 if eta else None, now + eta_lo * 3600 if eta_lo else None, now + eta_hi * 3600 if eta_hi else None,
                   {"rx_dbm": round(cur, 2), "slope_db_per_h": round(tr.slope, 3), "drop_db": round(drop, 2), "mk_p": round(tr.p, 6),
                    "low_warn": warn, "low_alarm": alarm})


def _hour_profile(pr, cutoff):
    by: dict[int, list[float]] = {}
    for t, v in pr:
        if t < cutoff:
            by.setdefault(int(t // 3600) % 24, []).append(v)
    return {h: median(v) for h, v in by.items() if len(v) >= 6}        # >= 6 samples (30 min) per hour slot


def d_util(s: Series, now: float, P: Params) -> Finding | None:
    if not s.speed:
        return None
    pr = _pairs(s, s.util)
    if len(pr) < P.min_points:
        return None
    cur = median([v for _, v in pr[-3:]])
    if sum(1 for _, v in pr[-6:] if v >= P.util_warn) >= 4:
        return Finding("utilization", "high", 0.9, "Interface saturated",
                       f"Utilisation has been at or above {P.util_warn * 100:.0f}% for most of the last 30 minutes (now {cur * 100:.0f}%). Queue drops are likely.",
                       None, None, None, {"util": round(cur, 3), "threshold": P.util_warn})
    span_h = (pr[-1][0] - pr[0][0]) / 3600
    win = pr[-72:]                                         # last 6 h
    th = [(t - now) / 3600 for t, _ in win]
    vs = [v for _, v in win]
    seasonal = None
    if span_h >= 26:
        prof = _hour_profile(pr, now - 4 * 3600)
        if len(prof) >= 20:
            seasonal = prof
    if seasonal:
        ok = [(a, t_, v - seasonal[int(t_ // 3600) % 24]) for a, (t_, v) in zip(th, win) if int(t_ // 3600) % 24 in seasonal]
        if len(ok) < P.min_points:
            return None
        tr = trend([o[0] for o in ok], [o[2] for o in ok])
        if tr is None or tr.p >= 0.01 or tr.slope < 0.01 or ok[-1][2] < 0.04:
            return None
        resid_now = median([o[2] for o in ok[-3:]])

        def fc(h):
            tt = now + h * 3600
            return seasonal.get(int(tt // 3600) % 24, cur - resid_now) + resid_now + tr.slope * h
    else:
        tr = trend(th, vs)
        if tr is None or tr.p >= 0.01 or tr.slope < 0.03 or tr.r2 < 0.75 or len(win) < 24:
            return None
        half = len(win) // 2                               # reject decelerating (diurnal) ramps: second half must keep the slope
        t2 = trend(th[half:], vs[half:])
        if t2 is None or t2.slope < 0.6 * tr.slope:
            return None

        def fc(h):
            return cur + tr.slope * h
    eta = None
    h = 0.25
    while h <= P.horizon_h:
        if fc(h) >= P.util_warn:
            eta = h
            break
        h += 0.25
    if eta is None:
        return None
    if not seasonal and eta > 8:
        return None        # <26 h of history: a daily ramp is indistinguishable from growth unless the crossing is imminent
    sev = _sev_from_eta(eta)
    det = (f"Utilisation is {cur * 100:.0f}% and rising {tr.slope * 100:.1f} percentage points per hour"
           + (" above its normal daily pattern" if seasonal else "") +
           f". Projected to reach {P.util_warn * 100:.0f}% in {_fmt_eta(eta)}; expect queue drops and latency beyond that. Consider a bigger link, LAG, or QoS/traffic engineering.")
    return Finding("utilization", sev, _conf(tr, 48), "Link heading for saturation", det, now + eta * 3600,
                   now + eta * 0.75 * 3600, now + eta * 1.3 * 3600,
                   {"util": round(cur, 3), "slope_pp_per_h": round(tr.slope * 100, 2), "mk_p": round(tr.p, 6), "seasonal": bool(seasonal),
                    "threshold": P.util_warn, "forecast": [[round(now + x * 3600), round(min(1.0, fc(x)), 3)] for x in (0, eta / 2, eta)]})


def d_flaps(s: Series, now: float, P: Params) -> Finding | None:
    pairs = [(s.t[i], s.flaps[i]) for i in range(len(s.t)) if s.flaps[i] is not None and math.isfinite(s.flaps[i])]
    # also derive transitions from the up series (devices without a flap counter)
    last_h = [v for t, v in pairs if t >= now - 3600]
    prev_h = [v for t, v in pairs if now - 7200 <= t < now - 3600]
    f1, f0 = sum(last_h), sum(prev_h)
    if len(last_h) < 6 or f1 < P.flap_per_h:
        return None
    rising = f1 > f0 * 1.3
    sev = "high" if f1 >= 2 * P.flap_per_h or rising else "medium"
    conf = round(min(0.95, 0.55 + 0.04 * min(f1, 10) + (0.1 if rising else 0)), 2)
    return Finding("flaps", sev, conf, "Interface instability (link flapping)",
                   f"The link changed state {int(f1)} times in the last hour (previous hour: {int(f0)})" + ("; the rate is increasing" if rising else "") +
                   ". Flapping precedes hard failure and causes routing/STP churn. Check cable, transceiver, duplex, and the far-end port.",
                   None, None, None, {"flaps_last_hour": int(f1), "flaps_prev_hour": int(f0), "threshold_per_h": P.flap_per_h})


def d_traffic(s: Series, now: float, P: Params) -> Finding | None:
    pr = _pairs(s, s.bps)
    if len(pr) < 36:                                       # need 3 h of baseline
        return None
    recent = pr[-4:]                                       # 20 min
    base = [v for _, v in pr[:-4]][-288:]
    cur = sum(v for _, v in recent) / len(recent)
    p75, p90, med = pct(base, 0.75), pct(base, 0.90), median(base)
    speed = s.speed or 0
    meaningful = p75 >= max(1e5, 0.005 * speed)            # baseline carried real traffic
    # reference = 75th percentile: robust to diurnal troughs and to a collapse that already lasted for a while
    if meaningful and p75 > 0 and cur < 0.05 * p75 and all(v < 0.10 * p75 for _, v in recent):
        return Finding("traffic", "high", 0.8, "Traffic dropped to near zero while link is up",
                       f"Throughput fell to {_fmt_bps(cur)} from a normal level of about {_fmt_bps(p75)} (peak {_fmt_bps(p90)}) although the link is up. "
                       "This pattern indicates a black-hole, upstream/downstream failure, or a blocked service rather than a physical fault.",
                       None, None, None, {"current_bps": round(cur), "baseline_p75": round(p75), "baseline_p90": round(p90)})
    sigma = max(mad_sigma(base), 0.1 * med, 1.0)
    if meaningful and cur > 2.0 * p90 and (cur - med) / sigma > 6 and all(v > 1.5 * p90 for _, v in recent) and cur > 0.05 * speed:
        return Finding("traffic", "low", 0.65, "Unusual traffic surge",
                       f"Throughput is {_fmt_bps(cur)}, more than twice the 90th percentile of its recent history ({_fmt_bps(p90)}). Could be a backup, an attack, or a loop.",
                       None, None, None, {"current_bps": round(cur), "baseline_p90": round(p90), "z": round((cur - med) / sigma, 1)})
    return None


def d_discards(s: Series, now: float, P: Params) -> Finding | None:
    pr = _pairs(s, s.disc)
    if len(pr) < P.min_points:
        return None
    last = pr[-12:]
    nz = sum(1 for _, v in last if v > 0)
    mean_last = sum(v for _, v in last) / len(last)
    if nz < 6 or mean_last < 1.0:
        return None
    win = pr[-36:]
    tr = trend([(t - now) / 3600 for t, _ in win], [v for _, v in win])
    rising = tr is not None and tr.p < 0.01 and tr.slope > 0
    return Finding("discards", "high" if mean_last >= 100 else "medium", _conf(tr, 24) if tr else 0.6,
                   "Rising packet discards" if rising else "Persistent packet discards",
                   f"The interface is dropping packets ({mean_last:.0f}/min averaged over the last hour, in {nz} of 12 samples). "
                   "Usually congestion (queue overflow), a duplex/speed mismatch, or a policer.",
                   None, None, None, {"mean_per_min": round(mean_last, 1), "slope_per_min_per_h": round(tr.slope, 2) if tr else None})


def _fmt_bps(v: float) -> str:
    for unit, k in (("Gbps", 1e9), ("Mbps", 1e6), ("kbps", 1e3)):
        if v >= k:
            return f"{v / k:.1f} {unit}"
    return f"{v:.0f} bps"


def _fmt_ago(sec: float) -> str:
    sec = max(0, sec)
    if sec < 5400:
        return f"{int(round(sec / 60))} min"
    return f"{sec / 3600:.1f} h"


DETECTORS = (d_errors, d_optic, d_util, d_flaps, d_traffic, d_discards)


def sanitize(s: Series) -> Series:
    """Drop non-finite numbers and enforce equal lengths (defence against corrupt storage / poisoned counters)."""
    n = len(s.t)
    for name in ("util", "bps", "err", "disc", "flaps", "rx", "up"):
        arr = getattr(s, name)
        arr = list(arr[:n]) + [None] * (n - len(arr))
        setattr(s, name, [v if isinstance(v, (int, float)) and math.isfinite(v) else None for v in arr])
    return s


def analyze(s: Series, now: float, P: Params | None = None) -> list[Finding]:
    P = P or Params()
    s = sanitize(s)
    if len(s.t) < P.min_points:
        return []
    out = []
    for det in DETECTORS:
        f = det(s, now, P)
        if f and f.confidence >= P.min_confidence:
            out.append(f)
    return out
