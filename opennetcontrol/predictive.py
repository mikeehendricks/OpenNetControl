"""Predictive interface monitoring service: counter ingestion, metric storage, analysis scheduling and the prediction
lifecycle (confirm -> active -> cleared / materialized, mute).  The statistics live in ai/predict.py.

Read-only by construction: nothing in here talks to a device or proposes a change."""
from __future__ import annotations

import logging
import math
import re
import threading

from .ai import predict as P
from .db import now, jdump
from .models import Counters
from .policy import canon_if

log = logging.getLogger("opennetcontrol.predictive")

BUCKET = P.BUCKET
WINDOW_H = 36
MAX_ACTIVE_PER_DEVICE = 50          # flood caps against poisoned/garbage telemetry
MAX_ACTIVE_TOTAL = 2000
MAX_IFACES_PER_DEVICE = 512
IFNAME_RE = re.compile(r"^[A-Za-z0-9][\w./:\-]{0,63}$")
KINDS = set(P.KINDS)
SEVERITIES = ("critical", "high", "medium", "low")
CLEAR_AFTER = 3                      # consecutive analyses without the finding before a prediction is closed


def _delta(prev: int, cur: int) -> int | None:
    """Counter delta with wrap handling; None = counter reset (device reload / clear counters)."""
    if cur >= prev:
        return cur - prev
    for bits in (32, 64):
        mod = 1 << bits
        if prev < mod and prev >= mod * 0.75 and cur < mod * 0.25:
            implied = cur + mod - prev
            if implied < (1 << 31):
                return implied
    return None


class Predictive:
    def __init__(self, core):
        self.core = core
        s = core.s
        self.enabled = bool(s.predict)
        self.confirm_s = max(0, min(int(s.predict_confirm_s), 3600))
        self.retention_s = max(3, min(int(s.predict_retention_h), 720)) * 3600
        self.params = P.Params(util_warn=min(0.99, max(0.5, float(s.predict_util_warn))),
                               err_crit_pm=min(1e7, max(1.0, float(s.predict_err_crit_pm))))
        self.pending: dict[tuple, float] = {}
        self.lock = threading.Lock()
        self._last_prune = 0.0
        self.last_analysis = 0.0

    @property
    def db(self):
        return self.core.db

    # ================================================================ ingestion
    def ingest(self, device_id: int, ts: float, counters: list[Counters], oper: dict[str, bool] | None = None) -> int:
        if not self.enabled or not counters:
            return 0
        oper = oper or {}
        n = 0
        with self.db.tx():
            prev = {r["ifname"]: r for r in self.db.q("SELECT * FROM iface_state WHERE device_id=?", (device_id,))}
            for c in counters[:MAX_IFACES_PER_DEVICE]:
                if not IFNAME_RE.match(c.name or ""):
                    continue
                canon_up = oper.get(c.name)
                up = 1 if (canon_up is None or canon_up) else 0
                p = prev.get(c.name)
                self.db.x("INSERT OR REPLACE INTO iface_state VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (device_id, c.name, ts, c.in_octets, c.out_octets, c.in_errors, c.out_errors, c.in_discards, c.out_discards,
                           c.resets, c.speed_bps, c.rx_low_warn, c.rx_low_alarm, up))
                if not p or ts - p["ts"] < 5 or ts - p["ts"] > 3600:      # first sight, duplicate poll, or data gap: baseline only
                    continue
                dt = ts - p["ts"]
                ds = [_delta(p[k], v) for k, v in (("in_o", c.in_octets), ("out_o", c.out_octets), ("in_e", c.in_errors),
                                                   ("out_e", c.out_errors), ("in_d", c.in_discards), ("out_d", c.out_discards))]
                if any(d is None for d in ds):                          # counters reset: do not fabricate a sample
                    continue
                dr = _delta(p["resets"], c.resets)
                if dr is None:
                    dr = 0
                in_bps, out_bps = ds[0] * 8 / dt, ds[1] * 8 / dt
                speed = c.speed_bps or p["speed"] or 0
                ceiling = speed * 1.25 if speed else 4e11
                if max(in_bps, out_bps) > ceiling:                      # physically impossible: corrupt or poisoned counter
                    continue
                flaps = float(min(dr, 1000))
                if not dr and p["up"] != up:
                    flaps = 1.0
                util = max(in_bps, out_bps) / speed if speed else None
                rx = c.rx_dbm if (c.rx_dbm is not None and math.isfinite(c.rx_dbm) and -45 < c.rx_dbm < 20) else None
                self.db.x("INSERT OR REPLACE INTO iface_metrics VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                          (device_id, c.name, ts, in_bps, out_bps, util, min(1e9, (ds[2] + ds[3]) / dt * 60),
                           min(1e9, (ds[4] + ds[5]) / dt * 60), flaps, rx, up))
                n += 1
        return n

    # ================================================================ analysis
    def _load(self, since: float):
        rows = self.db.q(
            "SELECT device_id, ifname, CAST(ts/? AS INTEGER) b, AVG(util) util, AVG(MAX(in_bps,out_bps)) bps, AVG(err_pm) err, AVG(disc_pm) disc,"
            " SUM(flaps) flaps, AVG(rx_dbm) rx, AVG(up) up FROM iface_metrics WHERE ts>=? GROUP BY device_id, ifname, b ORDER BY device_id, ifname, b",
            (BUCKET, since))
        state = {(r["device_id"], r["ifname"]): r for r in self.db.q("SELECT * FROM iface_state")}
        series: dict[tuple, P.Series] = {}
        for r in rows:
            k = (r["device_id"], r["ifname"])
            s = series.get(k)
            if s is None:
                st = state.get(k) or {}
                s = series[k] = P.Series([], [], [], [], [], [], [], [], speed=int(st.get("speed") or 0),
                                         low_warn=st.get("low_warn"), low_alarm=st.get("low_alarm"))
            s.t.append(r["b"] * BUCKET)
            s.util.append(r["util"]); s.bps.append(r["bps"]); s.err.append(r["err"]); s.disc.append(r["disc"])
            s.flaps.append(r["flaps"]); s.rx.append(r["rx"]); s.up.append(r["up"])
        return series, state

    def analyze(self, at: float | None = None) -> dict:
        if not self.enabled:
            return {"enabled": False}
        with self.lock:
            t = at if at is not None else now()
            series, state = self._load(t - WINDOW_H * 3600)
            found: dict[tuple, P.Finding] = {}
            down: set[tuple] = set()
            for k, s in series.items():
                st = state.get(k)
                if st is not None and st["up"] == 0 or (s.up and s.up[-1] is not None and s.up[-1] < 0.5):
                    down.add(k)
                    continue
                if t - s.t[-1] > 1800:           # stale series (device not polled): no fresh evidence
                    continue
                try:
                    for f in P.analyze(s, t, self.params):
                        found[(k[0], k[1], f.kind)] = f
                except Exception:                # a malformed series must never break the cycle
                    log.exception("analysis failed for %s", k)
            self._reconcile(t, found, down)
            self._correlate()
            self._prune(t)
            self.last_analysis = t
            return {"enabled": True, "interfaces": len(series), "findings": len(found), "pending": len(self.pending)}

    def _reconcile(self, t: float, found: dict, down: set) -> None:
        live = {(r["device_id"], r["ifname"], r["kind"]): r for r in
                self.db.q("SELECT * FROM predictions WHERE status IN ('active','muted')")}
        per_dev: dict[int, int] = {}
        for (d, _, _), r in live.items():
            per_dev[d] = per_dev.get(d, 0) + 1
        for key, f in found.items():
            row = live.get(key)
            ev = jdump(f.evidence)
            if row:
                st = row["status"]
                if st == "muted" and (row["muted_until"] or 0) <= t:
                    st = "active"
                self.db.x("UPDATE predictions SET severity=?, confidence=?, title=?, detail=?, evidence=?, eta_ts=?, eta_low=?, eta_high=?,"
                          " last_seen=?, clear_count=0, status=? WHERE id=?",
                          (f.severity, f.confidence, f.title, f.detail, ev, f.eta_ts, f.eta_low, f.eta_high, t, st, row["id"]))
                continue
            first = self.pending.setdefault(key, t)
            if t - first < self.confirm_s:
                continue
            if per_dev.get(key[0], 0) >= MAX_ACTIVE_PER_DEVICE or len(live) >= MAX_ACTIVE_TOTAL:
                continue                            # flood cap
            pid = self.db.x("INSERT INTO predictions(device_id,ifname,kind,severity,confidence,title,detail,evidence,eta_ts,eta_low,eta_high,"
                            "first_seen,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'active')",
                            (key[0], key[1], key[2], f.severity, f.confidence, f.title, f.detail, ev, f.eta_ts, f.eta_low, f.eta_high, first, t))
            per_dev[key[0]] = per_dev.get(key[0], 0) + 1
            dev = self.core.db.one("SELECT name FROM devices WHERE id=?", (key[0],))
            self.core.audit.log("system", "prediction.opened", {"id": pid, "device": dev["name"] if dev else key[0], "interface": key[1],
                                                                 "kind": key[2], "severity": f.severity, "confidence": f.confidence})
        for key in list(self.pending):
            if key not in found:
                del self.pending[key]
        for key, row in live.items():
            if key in found:
                continue
            if (key[0], key[1]) in down and row["status"] == "active":
                self.db.x("UPDATE predictions SET status='materialized', materialized_ts=?, closed=? WHERE id=?", (t, t, row["id"]))
                continue
            n = (row["clear_count"] or 0) + 1
            if n >= CLEAR_AFTER:
                self.db.x("UPDATE predictions SET status='cleared', closed=?, clear_count=? WHERE id=?", (t, n, row["id"]))
            else:
                self.db.x("UPDATE predictions SET clear_count=? WHERE id=?", (n, row["id"]))

    def _correlate(self) -> None:
        """Use the discovered topology: both link ends degrading -> shared medium; one end -> local port/optic."""
        rows = self.db.q("SELECT id, device_id, ifname, kind FROM predictions WHERE status IN ('active','muted') AND kind IN ('errors','optic','flaps')")
        if not rows:
            return
        idx: dict[tuple, list[dict]] = {}
        for r in rows:
            idx.setdefault((r["device_id"], canon_if(r["ifname"])), []).append(r)
        ids = {d["name"]: d["id"] for d in self.db.q("SELECT id,name FROM devices")}
        names = {v: k for k, v in ids.items()}
        causes: dict[int, str] = {}
        for l in self.db.q("SELECT a_dev,a_if,b_name,b_if FROM links"):
            b = ids.get(l["b_name"])
            if b is None:
                continue
            a_rows, b_rows = idx.get((l["a_dev"], canon_if(l["a_if"]))), idx.get((b, canon_if(l["b_if"])))
            for here, other, my_dev, my_if, far_dev, far_if in ((a_rows, b_rows, l["a_dev"], l["a_if"], l["b_name"], l["b_if"]),
                                                                (b_rows, a_rows, b, l["b_if"], names.get(l["a_dev"], "?"), l["a_if"])):
                if not here:
                    continue
                if other:
                    msg = f"Both ends of the link are degrading ({far_dev} {far_if} too), so the shared path (cable, patch panel or fibre) is the likely cause."
                else:
                    msg = f"Only this end is affected; {far_dev} {far_if} looks healthy, so suspect the local port or transceiver."
                for r in here:
                    causes[r["id"]] = msg
        for rid, msg in causes.items():
            self.db.x("UPDATE predictions SET cause=? WHERE id=?", (msg, rid))

    def _prune(self, t: float) -> None:
        if t - self._last_prune < 3600:
            return
        self._last_prune = t
        self.db.x("DELETE FROM iface_metrics WHERE ts < ?", (t - self.retention_s,))
        self.db.x("DELETE FROM predictions WHERE status IN ('cleared','materialized') AND closed < ?", (t - 14 * 86400,))
        live = {r["id"] for r in self.db.q("SELECT id FROM devices")}
        for r in self.db.q("SELECT DISTINCT device_id FROM iface_state"):
            if r["device_id"] not in live:
                self.db.x("DELETE FROM iface_state WHERE device_id=?", (r["device_id"],))
                self.db.x("DELETE FROM iface_metrics WHERE device_id=?", (r["device_id"],))
                self.db.x("DELETE FROM predictions WHERE device_id=?", (r["device_id"],))

    # ================================================================ queries
    def _row(self, r: dict, names: dict) -> dict:
        import json
        r = dict(r)
        try:
            r["evidence"] = json.loads(r["evidence"] or "{}")
        except ValueError:
            r["evidence"] = {}
        r["device"] = names.get(r["device_id"], "?")
        r["eta_hours"] = round((r["eta_ts"] - now()) / 3600, 2) if r.get("eta_ts") else None
        r["age_s"] = int(max(0, now() - (r["first_seen"] or now())))
        if r["status"] == "muted" and (r["muted_until"] or 0) <= now():
            r["status"] = "active"
        return r

    def list(self, status: str = "active", device_id: int | None = None, limit: int = 500) -> list[dict]:
        if status not in ("active", "muted", "cleared", "materialized", "all"):
            raise ValueError("bad status")
        limit = max(1, min(int(limit), 1000))
        sql, args = "SELECT * FROM predictions", []
        where = []
        if status == "active":
            where.append("status IN ('active','muted')")
        elif status != "all":
            where.append("status=?"); args.append(status)
        if device_id is not None:
            where.append("device_id=?"); args.append(device_id)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, COALESCE(eta_ts, 9e18), id DESC LIMIT ?"
        args.append(limit)
        names = {d["id"]: d["name"] for d in self.db.q("SELECT id,name FROM devices")}
        return [self._row(r, names) for r in self.db.q(sql, tuple(args))]

    def get(self, pid: int) -> dict | None:
        r = self.db.one("SELECT * FROM predictions WHERE id=?", (pid,))
        if not r:
            return None
        names = {d["id"]: d["name"] for d in self.db.q("SELECT id,name FROM devices")}
        return self._row(r, names)

    def mute(self, pid: int, hours: float, reason: str, actor: str) -> bool:
        hours = max(0.25, min(float(hours), 24 * 30))
        n = self.db.x("UPDATE predictions SET status='muted', muted_until=?, mute_reason=?, muted_by=? WHERE id=? AND status IN ('active','muted')",
                      (now() + hours * 3600, (reason or "")[:200], actor, pid))
        return n > 0

    def unmute(self, pid: int) -> bool:
        return self.db.x("UPDATE predictions SET status='active', muted_until=NULL WHERE id=? AND status='muted'", (pid,)) > 0

    def counts(self) -> dict:
        sev = {s: 0 for s in SEVERITIES}
        at_risk = set()
        for r in self.db.q("SELECT device_id, ifname, severity FROM predictions WHERE status='active' OR (status='muted' AND muted_until>?)", (now(),)):
            sev[r["severity"]] = sev.get(r["severity"], 0) + 1
            at_risk.add((r["device_id"], r["ifname"]))
        return {"enabled": self.enabled, "active": sum(sev.values()), "by_severity": sev, "interfaces_at_risk": len(at_risk),
                "tracked_interfaces": (self.db.one("SELECT COUNT(*) c FROM iface_state") or {"c": 0})["c"]}

    def stats(self) -> dict:
        """How have past predictions fared?  (materialized = interface went down while a prediction was open)"""
        rows = self.db.q("SELECT status, first_seen, materialized_ts, muted_by FROM predictions")
        mat = [r for r in rows if r["status"] == "materialized"]
        lead = sorted(r["materialized_ts"] - r["first_seen"] for r in mat if r["materialized_ts"])
        return {"total": len(rows), "active": sum(1 for r in rows if r["status"] in ("active", "muted")),
                "cleared": sum(1 for r in rows if r["status"] == "cleared"), "materialized": len(mat),
                "median_lead_time_s": lead[len(lead) // 2] if lead else None}

    def health(self, device_id: int | None = None) -> list[dict]:
        names = {d["id"]: d["name"] for d in self.db.q("SELECT id,name FROM devices")}
        risk: dict[tuple, str] = {}
        for r in self.db.q("SELECT device_id, ifname, severity FROM predictions WHERE status IN ('active','muted')"):
            k = (r["device_id"], r["ifname"])
            if k not in risk or SEVERITIES.index(r["severity"]) < SEVERITIES.index(risk[k]):
                risk[k] = r["severity"]
        t = now()
        last = {(r["device_id"], r["ifname"]): r for r in self.db.q(
            "SELECT m.* FROM iface_metrics m JOIN (SELECT device_id d, ifname i, MAX(ts) mt FROM iface_metrics WHERE ts>=? GROUP BY d, i) x "
            "ON x.d=m.device_id AND x.i=m.ifname AND x.mt=m.ts", (t - 6 * 3600,))}
        out = []
        if device_id is not None:
            states = self.db.q("SELECT * FROM iface_state WHERE device_id=? ORDER BY device_id, ifname LIMIT 5000", (device_id,))
        else:
            states = self.db.q("SELECT * FROM iface_state ORDER BY device_id, ifname LIMIT 5000")
        for st in states:
            k = (st["device_id"], st["ifname"])
            m = last.get(k)
            out.append({"device_id": st["device_id"], "device": names.get(st["device_id"], "?"), "ifname": st["ifname"], "up": bool(st["up"]),
                        "speed_bps": st["speed"], "util": m["util"] if m else None, "err_pm": m["err_pm"] if m else None,
                        "rx_dbm": m["rx_dbm"] if m else None, "risk": risk.get(k, "ok")})
        return out

    def metrics(self, device_id: int, ifname: str, hours: float = 6.0) -> dict:
        if not IFNAME_RE.match(ifname or ""):
            raise ValueError("bad interface name")
        hours = max(0.25, min(float(hours), 72.0))
        t = now()
        step = max(BUCKET, int(hours * 3600 / 360 // BUCKET * BUCKET))        # <= ~360 points
        rows = self.db.q(
            "SELECT CAST(ts/? AS INTEGER)*? t, AVG(in_bps) i, AVG(out_bps) o, AVG(util) u, AVG(err_pm) e, AVG(disc_pm) d, SUM(flaps) f, AVG(rx_dbm) r, AVG(up) up "
            "FROM iface_metrics WHERE device_id=? AND ifname=? AND ts>=? GROUP BY CAST(ts/? AS INTEGER) ORDER BY t",
            (step, step, device_id, ifname, t - hours * 3600, step))
        st = self.db.one("SELECT * FROM iface_state WHERE device_id=? AND ifname=?", (device_id, ifname))
        preds = [self._row(r, {}) for r in self.db.q("SELECT * FROM predictions WHERE device_id=? AND ifname=? AND status IN ('active','muted')", (device_id, ifname))]
        rnd = lambda v, n=4: None if v is None else round(v, n)
        return {"ifname": ifname, "step_s": step, "now": t, "speed_bps": st["speed"] if st else None,
                "low_warn": st["low_warn"] if st else None, "low_alarm": st["low_alarm"] if st else None,
                "points": [{"t": r["t"], "in_bps": rnd(r["i"], 0), "out_bps": rnd(r["o"], 0), "util": rnd(r["u"]), "err_pm": rnd(r["e"]),
                            "disc_pm": rnd(r["d"]), "flaps": r["f"], "rx_dbm": rnd(r["r"], 2), "up": rnd(r["up"], 2)} for r in rows],
                "predictions": [{k: p[k] for k in ("id", "kind", "severity", "confidence", "title", "eta_ts", "evidence")} for p in preds],
                "thresholds": {"util_warn": self.params.util_warn, "err_crit_pm": self.params.err_crit_pm}}
