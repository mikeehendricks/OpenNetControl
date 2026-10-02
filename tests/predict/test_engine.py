"""Unit tests for the statistical engine (ai/predict.py) on synthetic series."""
import math
import random

import pytest

from opennetcontrol.ai import predict as P
from tests.predict.synth import make, cut, T0
from opennetcontrol.ai.predict import BUCKET


def _first_detect(kind, seed, hours=48, fault_at=20.0, want=None):
    s, tr, n = make(seed, hours, kind, fault_at_h=fault_at)
    for k in range(int(10 * 3600 / BUCKET), n):
        fs = [f for f in P.analyze(cut(s, k), T0 + k * BUCKET) if f.kind == (want or kind)]
        if fs and T0 + k * BUCKET >= tr.onset:
            return fs[0], T0 + k * BUCKET, tr
    return None, None, tr


def test_trend_detects_slope_and_significance():
    th = [i / 12 for i in range(60)]
    tr = P.trend(th, [2 * t + random.Random(1).gauss(0, 0.1) for t in th])
    assert abs(tr.slope - 2) < 0.2 and tr.p < 1e-6 and tr.r2 > 0.9


def test_trend_flat_noise_not_significant():
    r = random.Random(5)
    th = [i / 12 for i in range(60)]
    tr = P.trend(th, [r.gauss(0, 1) for _ in th])
    assert tr.p > 0.01 or abs(tr.slope) < 0.5


def test_trend_handles_constant_and_tiny_inputs():
    assert P.trend([0, 1, 2], [1, 2, 3]) is None
    t = P.trend([float(i) for i in range(10)], [5.0] * 10)
    assert t.slope == 0 and t.z == 0


def test_cusum_finds_onset():
    ts = [i * 300.0 for i in range(60)]
    xs = [0.0] * 30 + [3.0] * 30
    o = P.cusum_onset(ts, xs)
    assert o is not None and 28 * 300 <= o <= 33 * 300


def test_median_mad_pct_edge_cases():
    assert P.median([]) == 0 and P.mad_sigma([]) == 0 and P.pct([], .5) == 0
    assert P.median([1, 2, 3, 4]) == 2.5


@pytest.mark.parametrize("seed", range(1, 7))
def test_errors_ramp_detected_with_eta_before_threshold(seed):
    f, t, tr = _first_detect("errors", seed)
    assert f is not None, "error ramp not detected"
    assert t < tr.failure, "detected only after the failure threshold was crossed"
    assert f.severity in ("high", "medium", "low")


@pytest.mark.parametrize("seed", range(1, 6))
def test_optic_decay_detected_early_and_eta_reasonable(seed):
    f, t, tr = _first_detect("optic", seed)
    assert f is not None and t < tr.failure
    if f.eta_ts:
        # ETA must be within a factor of two of the true failure time, measured from detection
        true = tr.failure - t
        est = f.eta_ts - t
        assert 0.4 * true < est < 2.5 * true, (est, true)


@pytest.mark.parametrize("seed", range(1, 5))
def test_util_growth_detected_before_saturation(seed):
    f, t, tr = _first_detect("util", seed, hours=60, fault_at=24.0, want="utilization")
    assert f is not None and t < tr.failure


@pytest.mark.parametrize("kind,want", [("flap", "flaps"), ("silent", "traffic")])
def test_immediate_faults_detected_within_two_hours(kind, want):
    for seed in (1, 2, 3):
        f, t, tr = _first_detect(kind, seed, want=want)
        assert f is not None and t - tr.onset < 2 * 3600


@pytest.mark.parametrize("seed", range(100, 112))
def test_healthy_interfaces_do_not_alarm_after_learning(seed):
    s, _, n = make(seed, 72, None)
    bad = []
    for hr in range(27, 71, 2):
        k = hr * 12
        a = {f.kind for f in P.analyze(cut(s, k), T0 + k * BUCKET)}
        b = {f.kind for f in P.analyze(cut(s, k + 2), T0 + (k + 2) * BUCKET)}
        if a & b:
            bad.append((hr, a & b))
    assert not bad


def test_below_alarm_optic_is_critical_without_trend():
    s, _, n = make(1, 12, "optic", fault_at_h=1.0)
    s.rx = [-15.0 if v is not None else None for v in s.rx]
    f = [x for x in P.analyze(s, T0 + n * BUCKET) if x.kind == "optic"]
    assert f and f[0].severity == "critical"


def test_module_reported_thresholds_are_respected():
    s, _, n = make(3, 24, None)
    s.rx = [-9.0] * n
    s.low_warn, s.low_alarm = -8.0, -10.0        # this optic is tighter than the default
    f = [x for x in P.analyze(s, T0 + n * BUCKET) if x.kind == "optic"]
    assert f and "warning" in f[0].title.lower()


def test_garbage_values_never_raise():
    s, _, n = make(7, 24, "errors")
    s.err[10] = float("nan"); s.util[5] = float("inf"); s.rx[3] = float("-inf"); s.bps[2] = None
    s.flaps = s.flaps[:-5]                                   # ragged lengths
    P.analyze(s, T0 + n * BUCKET)


def test_too_little_data_yields_nothing():
    s, _, n = make(7, 0.5, "errors", fault_at_h=0.1)
    assert P.analyze(s, T0 + n * BUCKET) == []


def test_down_buckets_are_ignored():
    s, _, n = make(7, 24, "errors", fault_at_h=8)
    s.up = [0.0] * n
    assert P.analyze(s, T0 + n * BUCKET) == []


def test_confidence_bounds():
    for seed in range(1, 8):
        s, _, n = make(seed, 40, ["errors", "optic", "util", "flap", "silent"][seed % 5], fault_at_h=20)
        for f in P.analyze(s, T0 + n * BUCKET):
            assert 0 <= f.confidence <= 1 and f.severity in P.SEV_ORDER


def test_diurnal_ramp_is_not_called_saturation():
    """A smooth day/night swing on a busy link must not look like unbounded growth once the daily pattern is learned
    (the first 26 h are a documented learning phase in which a fast ramp that reaches the threshold within 8 h is flagged)."""
    n = 12 * 40
    t = [T0 + i * BUCKET for i in range(n)]
    util = [0.45 + 0.30 * math.sin(2 * math.pi * ((x - T0) / 86400 - 0.1)) for x in t]
    s = P.Series(t, util, [u * 1e9 for u in util], [0.0] * n, [0.0] * n, [0.0] * n, [None] * n, [1.0] * n, speed=10 ** 9)
    for k in range(12 * 27, n, 6):
        assert not [f for f in P.analyze(cut(s, k), T0 + k * BUCKET) if f.kind == "utilization"], k
