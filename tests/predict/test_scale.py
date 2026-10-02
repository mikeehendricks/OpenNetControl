"""Performance, concurrency and soak checks for the predictive service (budgets are deliberately generous: they catch regressions
such as accidental O(n^2) behaviour, not micro-timing)."""
import random
import threading
import time

from opennetcontrol import db as dbmod
from opennetcontrol.core import Core
from opennetcontrol.models import Counters
from tests.conftest import mk_settings

T0 = 1_700_000_000.0


def _fleet(nd, ni, ns, confirm=600):
    clk = [T0]
    dbmod.set_clock(lambda: clk[0])
    c = Core(mk_settings(predict_confirm_s=confirm))
    for d in range(nd):
        c.db.x("INSERT INTO devices(name,address,vendor,platform,role,transport,created) VALUES(?,?,?,?,?,?,?)",
               (f"d{d}", f"10.9.{d // 250}.{d % 250}", "cisco", "cisco_iosxe", "switch", "sim", 0))
    r = random.Random(7)
    ctr = {}
    for _ in range(ns):
        clk[0] += 300
        for d in range(1, nd + 1):
            cs = []
            for i in range(ni):
                v = ctr.get((d, i), 10 ** 12) + int(r.uniform(1e6, 2e8)); ctr[(d, i)] = v
                cs.append(Counters(f"Gi1/0/{i + 1}", v, v, 0, 0, 0, 0, 0, 10 ** 9))
            c.pred.ingest(d, clk[0], cs, {})
    return c, clk


def test_ingest_and_analysis_scale_to_1000_interfaces():
    c, clk = _fleet(40, 25, 72)                      # 1000 interfaces, 6 h of history
    t = time.time(); res = c.pred.analyze(clk[0]); dt = time.time() - t
    assert res["interfaces"] == 1000
    assert dt < 20, f"analysis of 1000 interfaces took {dt:.1f}s"
    assert res["findings"] == 0                       # healthy random traffic must not be flagged at scale (FP check)
    assert c.db.one("SELECT COUNT(*) n FROM predictions")["n"] == 0


def test_api_reads_stay_available_and_consistent_during_analysis_and_ingest():
    c, clk = _fleet(20, 20, 72)
    errors, stop = [], threading.Event()

    def reader():
        while not stop.is_set():
            try:
                c.pred.list("active"); c.pred.health(); c.pred.stats()
                c.overview()
                c.db.q("SELECT COUNT(*) FROM iface_metrics")
            except Exception as e:                    # noqa
                errors.append(repr(e)); return

    ts = [threading.Thread(target=reader) for _ in range(6)]
    for t in ts: t.start()
    try:
        for _ in range(6):
            clk[0] += 300
            for d in range(1, 21):
                c.pred.ingest(d, clk[0], [Counters(f"Gi1/0/{i + 1}", 10 ** 13 + int(clk[0]) * 1000, 10 ** 13 + int(clk[0]) * 1000, 0, 0, 0, 0, 0, 10 ** 9) for i in range(20)], {})
            c.pred.analyze(clk[0])
    finally:
        stop.set()
        for t in ts: t.join(10)
    assert not errors, errors[:3]


def test_two_concurrent_analyses_do_not_duplicate_predictions():
    c, clk = _fleet(2, 4, 40)
    # an error ramp on one interface
    for k in range(60):
        clk[0] += 300
        e = k * 400
        c.pred.ingest(1, clk[0], [Counters("Gi1/0/1", 10 ** 13 + k * 10 ** 6, 10 ** 13 + k * 10 ** 6, e, 0, 0, 0, 0, 10 ** 9)], {})
    ths = [threading.Thread(target=lambda: c.pred.analyze(clk[0] + 1)) for _ in range(8)]
    for t in ths: t.start()
    for t in ths: t.join(30)
    c.pred.analyze(clk[0] + 900)
    n = c.db.one("SELECT COUNT(*) n FROM predictions WHERE device_id=1 AND ifname='Gi1/0/1' AND kind='errors' AND status IN ('active','muted')")["n"]
    assert n <= 1


def test_soak_72h_retention_keeps_database_bounded():
    c, clk = _fleet(5, 6, 12 * 24 * 5)               # 5 days of 5-minute polls
    c.pred.analyze(clk[0])
    n = c.db.one("SELECT COUNT(*) n FROM iface_metrics")["n"]
    assert n <= 5 * 6 * 12 * 73                       # retention is 72 h (+ one prune interval)
    oldest = c.db.one("SELECT MIN(ts) m FROM iface_metrics")["m"]
    assert clk[0] - oldest <= 73 * 3600
