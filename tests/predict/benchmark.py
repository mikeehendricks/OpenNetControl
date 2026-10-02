"""Benchmark the predictive engine on synthetic data.  Run:  python -m tests.predict.benchmark [--json out.json]

Tuning seeds (1-999) and held-out evaluation seeds (10000+) are disjoint; only held-out numbers are reported."""
from __future__ import annotations

import json
import sys
import time

from opennetcontrol.ai.predict import analyze, Params
from .synth import make, cut, T0
from opennetcontrol.ai.predict import BUCKET

KIND_OF = {"errors": "errors", "optic": "optic", "util": "utilization", "flap": "flaps", "silent": "traffic"}


CONFIRM = 2          # buckets (10 min) a finding must persist before it is surfaced (mirrors the service's confirm window)


def _confirmed(s, k, kind=None):
    """kinds flagged at both k and k+CONFIRM buckets."""
    a = {f.kind for f in analyze(cut(s, k), T0 + k * BUCKET, Params())}
    if not a:
        return set()
    b = {f.kind for f in analyze(cut(s, k + CONFIRM), T0 + (k + CONFIRM) * BUCKET, Params())}
    return a & b


def healthy_fp(seeds, hours=72, start_h=4):
    """Evaluate every hour on healthy interfaces.  Splits learning phase (<26 h of history) from steady state."""
    out = {"learning": [0, 0], "steady": [0, 0]}          # [flagged evaluations, evaluations]
    by: dict[str, int] = {}
    ifaces_flagged_steady = set()
    for sd in seeds:
        s, _, n = make(sd, hours, None)
        for hr in range(start_h, hours - 1):
            k = int(hr * 3600 / BUCKET)
            ph = "learning" if hr < 26 else "steady"
            kinds = _confirmed(s, k)
            out[ph][1] += 1
            if kinds:
                out[ph][0] += 1
                for x in kinds:
                    by[x] = by.get(x, 0) + 1
                if ph == "steady":
                    ifaces_flagged_steady.add(sd)
    return out, by, len(ifaces_flagged_steady)


def fault_runs(kind, seeds, hours=60):
    res = []
    want = KIND_OF[kind]
    for sd in seeds:
        s, tr, n = make(sd, hours, kind)
        det = None
        for k in range(int(10 * 3600 / BUCKET), n - CONFIRM, 3):     # every 15 min from hour 10
            now = T0 + k * BUCKET
            if want not in _confirmed(s, k):
                continue
            if now < tr.onset:
                det = ("early", now)                                # flagged before the fault existed = false positive
            else:
                f = [x for x in analyze(cut(s, k + CONFIRM), T0 + (k + CONFIRM) * BUCKET, Params()) if x.kind == want]
                det = ("ok", T0 + (k + CONFIRM) * BUCKET, f[0] if f else None)
            break
        res.append((tr, det))
    return res


def main():
    t0 = time.time()
    out = {"seeds": "held-out 10000+ (tuning used 1-999 and early dev seeds)", "notes": "synthetic data; not a substitute for field validation",
           "confirmation": f"a finding must persist {CONFIRM} buckets ({CONFIRM * 5} min) before it is surfaced"}
    ev, by, nif = healthy_fp(range(10000, 10060))
    out["healthy"] = {"interfaces": 60, "hours_each": 72,
                      "learning_phase_(<26h_history)": {"flagged": ev["learning"][0], "evaluations": ev["learning"][1],
                                                        "rate": round(ev["learning"][0] / max(1, ev["learning"][1]), 4)},
                      "steady_state_(>=26h)": {"flagged": ev["steady"][0], "evaluations": ev["steady"][1],
                                               "rate": round(ev["steady"][0] / max(1, ev["steady"][1]), 4)},
                      "interfaces_ever_flagged_in_steady_state": nif, "by_kind": by}
    out["faults"] = {}
    tp = fn = early = 0
    for kind in KIND_OF:
        runs = fault_runs(kind, range(10000, 10030))
        det_ok = [(tr, d) for tr, d in runs if d and d[0] == "ok"]
        miss = sum(1 for tr, d in runs if d is None)
        e = sum(1 for tr, d in runs if d and d[0] == "early")
        delay = [(d[1] - tr.onset) / 60 for tr, d in det_ok]
        lead = [(tr.failure - d[1]) / 60 for tr, d in det_ok if tr.failure and tr.failure - tr.onset > 1800]
        before = sum(1 for x in lead if x > 0)
        tp += len(det_ok); fn += miss; early += e
        sv = {}
        for tr, d in det_ok:
            if d[2]:
                sv[d[2].severity] = sv.get(d[2].severity, 0) + 1
        out["faults"][kind] = {"runs": len(runs), "detected": len(det_ok), "missed": miss, "flagged_before_onset": e,
                               "median_detection_delay_min": round(sorted(delay)[len(delay) // 2], 1) if delay else None,
                               "median_lead_time_before_impact_min": round(sorted(lead)[len(lead) // 2], 1) if lead else None,
                               "detected_before_impact": f"{before}/{len(lead)}" if lead else "n/a (impact is immediate)", "severity_at_detection": sv}
    out["overall"] = {"fault_runs": tp + fn + early, "detected_after_onset": tp, "missed": fn, "flagged_before_onset": early,
                      "recall": round(tp / max(1, tp + fn + early), 3)}
    out["elapsed_s"] = round(time.time() - t0, 1)
    print(json.dumps(out, indent=1))
    if "--json" in sys.argv:
        open(sys.argv[sys.argv.index("--json") + 1], "w").write(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
