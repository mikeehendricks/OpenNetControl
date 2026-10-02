# OpenNetControl v0.2.0 - Executive Report

**Scope:** (1) new capability - AI predictive monitoring of network interfaces; (2) usability, feature, functional and destructive/vulnerability testing of the whole product, with emphasis on the new code.
**Date:** 2 Oct 2026 | **Build:** v0.2.0 (working tree on top of `ce107aa`) | **Method:** automated tests, scanners, live-socket abuse and load tests, browser tests, installer tests, one reviewer. No human penetration test.

---

## 1. Bottom line

| Question | Answer |
|---|---|
| Does the new AI warn before a problem becomes an outage? | **Yes, on the simulated fleet and on synthetic benchmarks.** In the demo it flagged all 6 injected developing faults and nothing else; one flagged optic then really failed and was recorded as a *prediction that came true*. **Not yet proven on real hardware or real traffic.** |
| Is it safe to run? | **Yes, within the stated limits.** 0 open vulnerabilities from 7 scanners; 0 critical/high findings. The new feature is read-only: it cannot change a device. |
| Did testing find problems? | **11 defects in this phase (1 high, 4 medium, 6 low/info). All fixed, each with a regression test or a documented manual check.** |
| Ready for production? | **Ready for a lab or pilot with real devices; not yet for unattended production** - see section 7. |

## 2. What was built

An interface-health engine that learns a baseline for every interface from 5-minute counter data and flags developing trouble with a **forecast of when it will hurt**:

* rising errors (cable, connector, duplex), fading optical power (ageing fibre or optic), utilisation heading to saturation, link flapping, and *silent* traffic collapse on a link that is still "up";
* tells apart "both ends degrading -> shared cable/fibre" from "one end -> port or optic";
* every warning carries confidence, ETA range, the numbers behind it, a plain-language likely cause, and can be muted;
* surfaced on a new **Predictive page** (with health map and charts), the Overview, the Topology (at-risk links), the **AI assistant** ("what is about to fail?") and the API;
* telemetry collectors for all 9 supported platforms (Cisco IOS-XE/NX-OS, Fortinet, Palo Alto, MikroTik, Ruckus ICX/Unleashed, Aruba AOS-CX/Instant), read-only commands only.

It is statistical learning (robust baselines, trend tests, change-point detection), deliberately **not** a black-box model: every alert is explainable. Details: [`PREDICTIVE.md`](PREDICTIVE.md).

![Predictive](screenshots/09-predictive.png)

## 3. How well does the prediction work?

Held-out synthetic benchmark (150 injected faults, 60 healthy interfaces x 72 h; `predictive_benchmark.json`):

| Fault | Detected | Median detection delay after onset | Median warning before impact |
|---|---|---|---|
| Rising errors | 30/30 | 46 min | ~2.0 h |
| Fading optics | 30/30 | 77 min | ~11.5 h |
| Utilisation growth | 30/30 | 121 min | ~7.8 h |
| Flapping / silent loss | 60/60 | 38 min | none (already impacting) |

* False alarms: **0.04 %** of hourly checks after 26 h of history (0.61 % in the first 26 h, while it learns daily patterns).
* **Read this honestly:** the faults were designed by the authors on simulated data, so 150/150 shows the mechanism works, *not* that it will catch 100 % in your network. Real traffic is messier. Plan a tuning period.
* Severity is driven by time-to-impact, so a slow problem first shows as low/medium and escalates - a feature, but it means "high" is rare early on.

## 4. Test results

| Category | What was tested | Result |
|---|---|---|
| **Functional / feature** | Engine maths and every detector (41 tests); 9 platform parsers round-tripped through the simulators (30); service lifecycle - counter wrap/reset, duplicates, gaps, confirm -> open -> clear, mute/expiry, materialize, audit trail, correlation, retention (22); demo end-to-end with the exact expected prediction set | **93 / 93 pass** |
| **Usability** | 22 real-browser (Playwright) journeys: login, every page, keyboard use and Esc on drawers, mobile viewport, mute/unmute, health map, AI chat, fast-forward turning a warning into a real outage; 0 console errors | **22 / 22 pass** |
| **Security / abuse (API)** | 70 tests: no-token 401, role checks (viewer cannot mute), interface-name / id / hours / body fuzzing (NaN, inf, -1, 1e308, 1 MB, wrong types), audit entries, lab controls admin-only, assistant is read-only | **70 / 70 pass** |
| **Destructive** | See 5 | all survived |
| **Regression** | Whole suite on Python 3.13 **and** 3.10 | **348 / 348 + 22 browser** (was 178 + 14 before this release) |
| **Scanners** | Bandit 0 · Semgrep (292 rules) 0 · njsscan 0 · pip-audit 0 CVEs · detect-secrets 0 real · Checkov 0 failed (53 pass) · ShellCheck clean · sqlmap on 3 new endpoints: not injectable | **0 open** |
| **Install / upgrade** | Fresh install behind nginx+TLS; **in-place upgrade from v0.1.1 keeps data**; deliberately broken upgrade; uninstall `--purge`; systemd exposure score 1.2 (OK) | pass (after fix F-10) |

## 5. Destructive testing - what we tried to break

| Attack / failure | Outcome |
|---|---|
| A compromised device streams 16-48 MB of output | **Was exploitable** (CPU and memory burn until timeout; 235 MB, whole timeout consumed) - **fixed** with an 8 MiB cap (F-05). Legitimate 1.6 MB output still accepted. |
| Hostile 2 MB text fed to all 9 parsers (100k fake interfaces, giant lines, 2 M newlines, ReDoS-style) | Worst case was 3.6 s - **fixed** to 0.25 s with bounded work (F-06). |
| Poisoned counters: wrap, reset, impossible rates, duplicate polls, hour-long gaps, junk interface names | Ignored or clamped; no fake traffic, no crash, nothing stored for invalid names. |
| Flood of predictions from garbage telemetry | Capped at 50/device, 2,000 total. |
| 64 concurrent clients for 25 s on one worker | 5,725 requests, **0 errors**, ~230 req/s, p95 468 ms, p99 612 ms; service healthy afterwards. |
| 8 threads racing mute/unmute on one prediction (320 calls) | No 5xx, no corruption (see note N-1). |
| Oversized / malformed request bodies | 413 / 422, never 500. |
| Read APIs while analysis and ingest run concurrently | Consistent; no exceptions. |
| 1,000 interfaces; 2,400 interfaces; 5 days of polling | Analysis 1.4 s for 1,000 interfaces (6 h history) and 5.8 s for 2,400 (12 h history) per cycle - cost grows with history up to the 36 h analysis window; database stays within the 72 h retention bound; 40 devices x 25 ports raised **zero** false alarms. |
| Upgrade existing v0.1.1 database | Migrates in place; devices, users and audit log intact. |
| Upgrade with a broken release | Previously left the service **stopped** - **fixed** (F-10): previous version restored and restarted. |

## 6. Defects found in this phase (all fixed)

| ID | Severity | Finding | Fix |
|---|---|---|---|
| F-01 | High (accuracy) | Early-warning time estimate ~9x too long when a fault had just started (trend fitted over a mostly-flat window) | Fit the trend after the detected onset; regression tests |
| F-02 | Medium | Steep daily traffic ramps were mistaken for capacity exhaustion | Seasonal baseline; documented 26 h learning phase |
| F-03 | Medium | "Traffic collapsed" baseline dragged toward zero by quiet periods | Use the 75th percentile |
| F-04 | Medium | Parsers rejected interface names starting with a digit (`1/1/1`) - **no telemetry for Aruba AOS-CX and Ruckus ICX switches** | Name rule fixed; round-trip test on all 9 platforms |
| F-05 | Medium (security/availability) | Unbounded device output: CPU/memory exhaustion by a malicious or faulty device; quadratic prompt scan | 8 MiB cap, constant-time prompt check; tests |
| F-06 | Low | Parsers did superlinear work on multi-MB hostile input (3.6 s) | Bounded work; timing test |
| F-07 | Low | Lab SSH server truncated big outputs (test tooling only) | `sendall` |
| F-08 | Low (usability) | 7th overview tile wrapped alone onto a second row | Responsive tile width |
| F-09 | Low | Installer and package reported v0.1.1 for the v0.2.0 build | Single version constant |
| F-10 | Low | A failed upgrade left the service stopped | Automatic rollback to the previous version; tested |
| F-11 | Info | Bandit: one SQL-string false positive, two `random` uses in the simulator | Refactored / annotated |

**Observations, deliberately not changed:** N-1 - unmuting a prediction that is not muted returns 404 (correct, but surfaces during races). N-2 - demo start-up takes ~4 s extra to back-fill 6 h of history (`ONC_DEMO_HISTORY_H=0` disables). N-3 - throughput numbers are one Python worker on a shared sandbox; use them as a floor.

## 7. What is NOT proven (limits)

1. **No real-device validation.** Counter/optics parsers follow vendor documentation and were tested against simulators and a local SSH lab only. Some simulated output fields are approximations. This is the biggest risk before production.
2. **Prediction accuracy is measured on synthetic data** designed by the authors. Field accuracy and false-alarm rates are unknown.
3. No human penetration test, no long soak beyond a simulated 5 days, no screen-reader/accessibility audit, no firmware matrix, Docker image not built, installer tested on Debian 13 only (Python 3.10 and 3.13 tested).
4. Standing product limits: SSH-CLI only, no SSO/MFA, single-node SQLite, self-signed certificate by default, vault key on the same host.

## 8. Recommended next steps

1. **Pilot read-only** against 3-5 real switches/firewalls per vendor; compare parsed counters with the devices' own CLI; fix parser gaps (expect some).
2. Run the predictor in shadow mode for 2-4 weeks; review every warning with the network team; tune `ONC_PREDICT_*` thresholds; record true/false positives (the page already counts "came true" and "cleared on their own").
3. Put the project's CI in place (`docs/ci.yml.example`), enable GitHub security features and branch protection, and replace the self-signed certificate.
4. Commission an independent penetration test before exposing it beyond a management network.
5. Revoke the GitHub token that was shared in chat.

## 9. Reproduce

```bash
pip install -r requirements-dev.txt
pytest tests --ignore=tests/e2e          # 348 tests (~90 s)
playwright install chromium && pytest tests/e2e     # 22 browser tests (~60 s)
python -m tests.predict.benchmark --json out.json   # accuracy benchmark (~45 s)
```
