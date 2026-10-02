"""Predictive service: ingestion maths, lifecycle, caps, correlation, demo end-to-end, read-only guarantee."""
import random
import time

import pytest

from opennetcontrol import db as dbmod
from opennetcontrol.core import Core
from opennetcontrol.models import Counters
from opennetcontrol.predictive import _delta
from opennetcontrol.sim.clock import CLOCK
from tests.conftest import mk_settings

T0 = 1_700_000_000.0


class Clock:
    def __init__(self, t): self.t = t
    def __call__(self): return self.t


@pytest.fixture()
def env():
    clk = Clock(T0)
    dbmod.set_clock(clk)
    c = Core(mk_settings(predict_confirm_s=600))
    for n in ("a", "b"):
        c.db.x("INSERT INTO devices(name,address,vendor,platform,role,transport,created) VALUES(?,?,?,?,?,?,?)", (n, "10.0.0." + str(ord(n)), "cisco", "cisco_iosxe", "switch", "sim", 0))
    return c, clk


class Feeder:
    """Feeds synthetic cumulative counters at 5-minute polls."""
    def __init__(self, core, clk, dev=1, ifname="Te1/0/1", speed=10 ** 9):
        self.c, self.clk, self.dev, self.ifn, self.speed = core, clk, dev, ifname, speed
        self.ctr = dict(i=10 ** 12, o=10 ** 12, e=0, d=0, r=0)
        self.rx = None

    def step(self, util=0.3, err_pm=0.0, disc_pm=0.0, flaps=0, rx=None, up=True, poll=300, **kw):
        self.clk.t += poll
        self.ctr["o"] += int(util * self.speed / 8 * poll); self.ctr["i"] += int(util * self.speed / 8 * poll * 0.7)
        self.ctr["e"] += int(round(err_pm * poll / 60)); self.ctr["d"] += int(round(disc_pm * poll / 60)); self.ctr["r"] += flaps
        self.c.pred.ingest(self.dev, self.clk.t, [Counters(self.ifn, self.ctr["i"], self.ctr["o"], self.ctr["e"], 0, self.ctr["d"], 0, self.ctr["r"],
                                                          self.speed, rx, -12.0 if rx is not None else None, -14.0 if rx is not None else None)],
                           {self.ifn: up})
        return self.c.pred.analyze(self.clk.t)

    def run(self, hours, **fn):
        for k in range(int(hours * 12)):
            self.step(**{a: (v(k) if callable(v) else v) for a, v in fn.items()})


# ------------------------------------------------------------------ counters
def test_delta_handles_wrap_and_reset():
    assert _delta(10, 25) == 15
    assert _delta(2 ** 32 - 100, 50) == 150                      # 32-bit wrap
    assert _delta(2 ** 64 - 100, 50) == 150                      # 64-bit wrap
    assert _delta(10 ** 12, 500) is None                         # reset / reload
    assert _delta(5, 3) is None


def test_first_poll_is_baseline_and_duplicates_ignored(env):
    c, clk = env
    f = Feeder(c, clk)
    f.step(); assert c.db.q("SELECT * FROM iface_metrics") == []
    f.step(poll=1)                                               # <5 s later: duplicate poll
    assert c.db.q("SELECT * FROM iface_metrics") == []
    f.step(poll=300); assert len(c.db.q("SELECT * FROM iface_metrics")) == 1


def test_counter_reset_does_not_create_fake_traffic_or_errors(env):
    c, clk = env
    f = Feeder(c, clk)
    f.run(1, util=0.2)
    n0 = len(c.db.q("SELECT * FROM iface_metrics"))
    f.ctr = dict(i=1000, o=1000, e=0, d=0, r=0)                  # device reloaded
    f.step(util=0.2)
    assert len(c.db.q("SELECT * FROM iface_metrics")) == n0       # sample skipped
    f.step(util=0.2)
    assert max(r["util"] for r in c.db.q("SELECT util FROM iface_metrics")) < 0.3


def test_impossible_rate_from_poisoned_counter_is_dropped(env):
    c, clk = env
    f = Feeder(c, clk)
    f.run(0.5, util=0.1)
    f.ctr["o"] += 10 ** 16
    f.step(util=0.1)
    assert max(r["util"] for r in c.db.q("SELECT util FROM iface_metrics")) < 1.3
    assert all(r["out_bps"] < 2e9 for r in c.db.q("SELECT out_bps FROM iface_metrics"))


def test_data_gap_over_an_hour_is_not_interpolated(env):
    c, clk = env
    f = Feeder(c, clk)
    f.run(0.5, util=0.1)
    n0 = len(c.db.q("SELECT * FROM iface_metrics"))
    f.step(util=0.1, poll=7200)
    assert len(c.db.q("SELECT * FROM iface_metrics")) == n0


def test_invalid_interface_names_not_stored(env):
    c, clk = env
    for nm in ("<script>", "../x", "a" * 80, "", "x y"):
        c.pred.ingest(1, clk.t, [Counters(nm)], {})
    assert c.db.q("SELECT * FROM iface_state") == []


def test_disabled_flag_collects_nothing():
    c = Core(mk_settings(predict=False))
    c.pred.ingest(1, 1.0, [Counters("Te1")], {})
    assert c.db.q("SELECT * FROM iface_state") == [] and c.pred.analyze() == {"enabled": False}


# ------------------------------------------------------------------ lifecycle
def test_prediction_needs_confirmation_then_opens_then_clears(env):
    c, clk = env
    f = Feeder(c, clk)
    f.run(3, util=0.2)                                           # healthy history
    assert c.pred.list("all") == []
    f.run(2, util=0.2, err_pm=lambda k: 2 + 6 * k / 12 * 1.0)    # errors ramp
    p = c.pred.list("active")
    assert p and p[0]["kind"] == "errors" and p[0]["first_seen"] >= T0
    # first_seen precedes opening by >= the confirmation window
    assert p[0]["last_seen"] - p[0]["first_seen"] >= 600
    f.run(1.5, util=0.2)                                         # errors stop -> cleared after 3 clean analyses
    assert c.pred.list("active") == [] and c.pred.list("cleared")


def test_audit_trail_for_opened_predictions(env):
    c, clk = env
    f = Feeder(c, clk)
    f.run(3, util=0.2); f.run(2, util=0.2, err_pm=lambda k: 3 + k)
    assert c.db.one("SELECT 1 FROM audit WHERE action='prediction.opened'")
    assert c.audit.verify()["ok"]


def test_mute_and_unmute_and_expiry(env):
    c, clk = env
    f = Feeder(c, clk)
    f.run(3, util=0.2); f.run(2, util=0.2, err_pm=lambda k: 3 + k)
    pid = c.pred.list("active")[0]["id"]
    assert c.pred.mute(pid, 1, "known cable swap", "op")
    assert c.pred.get(pid)["status"] == "muted" and c.pred.counts()["active"] == 1
    assert c.pred.unmute(pid) and c.pred.get(pid)["status"] == "active"
    c.pred.mute(pid, 0.01, "x", "op")                            # clamped to 15 min
    row = c.db.one("SELECT muted_until FROM predictions WHERE id=?", (pid,))
    assert row["muted_until"] - clk.t >= 900 - 1
    clk.t += 1000
    assert c.pred.get(pid)["status"] == "active"                 # mute expired
    assert not c.pred.mute(99999, 1, "", "op")


def test_interface_going_down_marks_prediction_materialized(env):
    c, clk = env
    f = Feeder(c, clk)
    f.run(3, util=0.2, rx=-4.5)
    f.run(5, util=0.2, rx=lambda k: -4.5 - 0.15 * k)
    assert any(p["kind"] == "optic" for p in c.pred.list("active"))
    f.run(0.5, util=0.0, up=False)
    m = c.pred.list("materialized")
    assert m and m[0]["materialized_ts"] > m[0]["first_seen"]
    assert c.pred.stats()["materialized"] >= 1 and c.pred.stats()["median_lead_time_s"] > 0
    # a down interface produces no new predictions
    assert not [p for p in c.pred.list("active") if p["ifname"] == "Te1/0/1" and p["kind"] == "optic"]


def test_flood_caps_hold_under_poisoned_telemetry(env):
    c, clk = env
    rnd = random.Random(3)
    for k in range(40):
        clk.t += 300
        cs = [Counters(f"p{i}", 10 ** 9 * k, 10 ** 9 * k, int(30 * k * k), 0, 0, 0, 3 * k, 10 ** 9) for i in range(200)]
        c.pred.ingest(1, clk.t, cs, {})
        c.pred.analyze(clk.t)
    n = c.db.one("SELECT COUNT(*) c FROM predictions WHERE device_id=1")["c"]
    assert 0 < n <= 50 * 3                                       # <= per-device cap per status bucket (active/cleared...)
    assert c.db.one("SELECT COUNT(*) c FROM predictions WHERE status='active' AND device_id=1")["c"] <= 50


def test_both_link_ends_yield_cable_cause_and_one_end_local_cause(env):
    c, clk = env
    c.db.x("INSERT INTO links VALUES(1,'Te1/0/1','b','Te1/0/9',?)", (clk.t,))
    a, b = Feeder(c, clk, 1, "Te1/0/1"), Feeder(c, clk, 2, "Te1/0/9")
    for fd in (a, b):
        pass
    for k in range(36):
        a.step(util=0.2); b.step(util=0.2)
    for k in range(24):
        a.step(util=0.2, err_pm=3 + 2 * k); b.step(util=0.2, err_pm=3 + 2 * k)
    rows = c.pred.list("active")
    assert len(rows) == 2 and all("Both ends" in (r["cause"] or "") for r in rows)
    for k in range(40):
        a.step(util=0.2, err_pm=60 + 3 * k); b.step(util=0.2, err_pm=0)
    rows = {r["device"]: r for r in c.pred.list("active")}
    assert "Only this end" in rows["a"]["cause"]


def test_prune_removes_old_metrics_and_orphans(env):
    c, clk = env
    f = Feeder(c, clk)
    f.run(2, util=0.2)
    clk.t += 5 * 86400
    c.db.x("DELETE FROM devices WHERE id=1")
    c.pred.analyze(clk.t)
    assert c.db.q("SELECT * FROM iface_metrics") == [] and c.db.q("SELECT * FROM iface_state WHERE device_id=1") == []


def test_metrics_query_bounds_and_validation(env):
    c, clk = env
    f = Feeder(c, clk)
    f.run(2, util=0.2)
    assert len(c.pred.metrics(1, "Te1/0/1", 6)["points"]) > 5
    assert c.pred.metrics(1, "Te1/0/1", 10 ** 6)["step_s"] >= 300         # hours clamped to 72
    assert len(c.pred.metrics(1, "Te1/0/1", 72)["points"]) <= 400
    for bad in ("", "a;b", "../x", "x" * 70, "a' OR 1=1--"):
        with pytest.raises(ValueError):
            c.pred.metrics(1, bad, 1)
    with pytest.raises(ValueError):
        c.pred.list("bogus")


# ------------------------------------------------------------------ demo end-to-end
@pytest.fixture(scope="module")
def demo():
    dbmod.set_clock(None); CLOCK.reset()
    c = Core(mk_settings(demo_history_h=6))
    c.seed_demo()
    yield c
    dbmod.set_clock(None); CLOCK.reset()


def test_demo_finds_every_injected_degradation_and_nothing_else(demo):
    got = {(p["device"], p["ifname"], p["kind"]) for p in demo.pred.list("active")}
    expect = {("hq-core1", "TenGigabitEthernet1/1/2", "errors"), ("hq-fw2", "port1", "errors"), ("hq-dist2", "1/1/48", "optic"),
              ("cebu-sw1", "1/1/48", "utilization"), ("davao-sw1", "1/1/2", "flaps"), ("hq-fw1", "ethernet1/3", "traffic")}
    assert expect <= got
    assert len(got - expect) == 0, f"unexpected extra predictions: {got - expect}"


def test_demo_shared_cable_cause_and_eta(demo):
    p = next(x for x in demo.pred.list("active") if x["device"] == "hq-core1")
    assert "Both ends" in p["cause"] and p["eta_hours"] and 0 < p["eta_hours"] < 8
    o = next(x for x in demo.pred.list("active") if x["kind"] == "optic")
    assert o["evidence"]["slope_db_per_h"] < -0.5


def test_demo_prediction_precedes_real_failure():
    """Fast-forward: the optic prediction exists BEFORE the interface goes down, then materialises."""
    dbmod.set_clock(None); CLOCK.reset()
    c = Core(mk_settings(demo_history_h=6)); c.seed_demo()
    try:
        assert any(p["kind"] == "optic" and p["device"] == "hq-dist2" for p in c.pred.list("active"))
        assert not [a for a in c.alerts() if a["kind"] == "interface_down" and a["device"] == "hq-dist2"]
        c.fast_forward(12 * 3600)
        assert [a for a in c.alerts() if a["kind"] == "interface_down" and a["device"] == "hq-dist2"]
        assert any(p["device"] == "hq-dist2" for p in c.pred.list("materialized"))
        assert c.pred.stats()["median_lead_time_s"] > 3600
    finally:
        dbmod.set_clock(None); CLOCK.reset()


def test_heal_clears_the_prediction():
    from opennetcontrol import lab
    dbmod.set_clock(None); CLOCK.reset()
    c = Core(mk_settings(demo_history_h=6)); c.seed_demo()
    try:
        lab.heal("hq-core1", "TenGigabitEthernet1/1/2")
        c.fast_forward(2 * 3600)
        assert not [p for p in c.pred.list("active") if p["device"] == "hq-core1"]
    finally:
        dbmod.set_clock(None); CLOCK.reset()


def test_predictive_collection_is_strictly_read_only(demo):
    from opennetcontrol import lab
    ok = ("show ", "diagnose ", "get ", "/interface print", "/system ", "/ip ", "/export", "set cli ", "set output")
    for sim in lab.LAB.values():
        bad = [h for h in sim.history if not h.startswith(ok) and " print" not in h and h not in ("terminal length 0", "terminal pager 0", "no page", "set output standard",
                                                                          "set cli pager off", "screen-length 0 temporary", "skip-page-display", "no paging", "")]
        assert not bad, (sim.name, bad[:5])
        assert not sim.reloaded


def test_overview_and_topology_expose_risk(demo):
    ov = demo.overview()
    assert ov["predictions"]["active"] >= 6 and ov["predictions"]["interfaces_at_risk"] >= 5
    assert any(e["state"] == "at_risk" for e in demo.topology()["edges"])


def test_analysis_scales(demo):
    t = time.time()
    demo.pred.analyze()
    assert time.time() - t < 2.0
