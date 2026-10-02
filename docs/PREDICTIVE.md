# Predictive interface monitoring

OpenNetControl learns what "normal" looks like for every interface and raises an **early warning** when an interface is
drifting towards trouble - *before* the link drops or users notice. The page is **read-only**: the AI never changes a device.

## What it watches (per interface, every poll)

| Signal | Source | Problem it catches | Example finding |
|---|---|---|---|
| In/out error rate (CRC, FCS, input errors) | counters | failing cable, connector, optic, duplex mismatch | "errors rising 0.4 -> 38/min, ~3.7 h until service-affecting" |
| Optical receive power (DOM) | transceiver diagnostics | ageing/dirty fibre, failing SFP | "-1.4 dB/h, ~1.4 h until the low-alarm level" |
| Utilisation trend | counters / speed | capacity exhaustion | "growing 4 %/h, ~44 min until saturated" |
| Link flaps | oper-state changes | unstable link, bad optic, STP/PoE issues | "5 flaps in 1 h" |
| Traffic collapse on an *up* link | counters | silent failure (upstream dead, ACL, misroute) | "traffic fell to ~0 while link is up" |
| Discards | counters | congestion/queue drops | |

When *both ends* of a link degrade together the finding says "shared path (cable, patch panel or fibre)"; when only one end
does it says "port or optic" - so the right person is sent to the right place.

## How it works (honest description)

Statistical online learning, **not** deep learning and **not** an LLM, so every number is explainable and it runs on a small VM:

1. Counters are converted to 5-minute buckets of rates. Counter wraps, resets, duplicates, gaps and impossible rates are handled (or dropped).
2. A robust baseline (median/MAD; hour-of-day profile once 26 h of history exist) is learned per interface.
3. Trends are tested with Mann-Kendall, slopes fitted with Theil-Sen **after** the CUSUM-detected onset of the change, and extrapolated to the impact threshold -> ETA with a low/high range.
4. Confidence = 0.55 x strength + 0.25 x data sufficiency + 0.2 x persistence. Nothing under 0.5 is shown, and a finding must persist **10 minutes** (`ONC_PREDICT_CONFIRM_S`) before it opens.
5. Severity follows the ETA: already breached = critical, <= 6 h high, <= 24 h medium, otherwise low. Findings escalate as the ETA shrinks and clear by themselves when the interface recovers.
6. If a flagged interface later goes down, the prediction is marked **materialized** (this is how the "predictions that came true" and lead-time statistics are produced).

Safeguards: at most 50 open predictions per device and 2,000 in total (poisoned telemetry cannot flood the UI), at most 512 interfaces per device,
72 h retention (`ONC_PREDICT_RETENTION_H`), telemetry collection uses **read-only commands only** (`show`/`get`/`diagnose`/`print`).

## Where to find it

* **Predictive page** - summary, early-warning table, interface health map. Click a row: charts (utilisation, errors, optical power) with the forecast, evidence, likely cause, mute for N hours.
* **Overview** - "Predicted problems" tile and early-warning list; **Topology** - at-risk links are drawn dashed amber.
* **AI Assistant** - "what is about to fail?", "any interfaces at risk?", "show interface errors on hq-core1" (read-only, answers from live data).
* **API** (viewer role and above; mute/unmute need operator): `GET /api/predictions[?status=&device_id=]`, `/api/predictions/stats`, `/api/predictions/{id}`,
  `POST /api/predictions/{id}/mute|unmute`, `GET /api/interfaces/health`, `GET /api/devices/{id}/metrics?ifname=&hours=`.

## Settings

`ONC_PREDICT` (default 1), `ONC_PREDICT_CONFIRM_S` (600), `ONC_PREDICT_RETENTION_H` (72), `ONC_PREDICT_UTIL_WARN` (0.90), `ONC_PREDICT_ERR_CRIT_PM` (100 errors/min),
`ONC_DEMO_HISTORY_H` (demo only: hours of simulated history to backfill, 0 = none).
Vendors: counters and optics are parsed for Cisco IOS-XE/NX-OS, Fortinet, Palo Alto, MikroTik, Ruckus ICX/Unleashed and Aruba AOS-CX/Instant.

## Measured accuracy - read the caveats

`python -m tests.predict.benchmark` (results in `predictive_benchmark.json`). Held-out synthetic seeds, 150 injected faults, 60 healthy interfaces x 72 h:

| Fault type | Detected | Median time from fault onset to detection | Median warning before service impact |
|---|---|---|---|
| Rising errors | 30/30 | 46 min | ~2.0 h |
| Optical degradation | 30/30 | 77 min | ~11.5 h |
| Utilisation growth | 30/30 | 121 min | ~7.8 h |
| Flapping | 30/30 | 38 min | n/a (impact is immediate) |
| Silent traffic loss | 30/30 | 38 min | n/a (impact is immediate) |

False positives on healthy interfaces: 0.04 % of hourly evaluations once 26 h of history exist (1 interface of 60 flagged, utilisation); 0.61 % during the first 26 h ("learning phase").

**Caveats:** the faults were designed by the same people who built the detector, on simulated data - this proves the mechanics, not field accuracy.
Real networks will differ; expect to tune thresholds. Severity is ETA-based, so early findings start low/medium and escalate.
Telemetry in the shipped demo is simulated. Parsers for real devices follow vendor documentation but have only been validated against simulators.
