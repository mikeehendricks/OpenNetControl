# OpenNetControl - Test Report (usability, bugs, destructive/security testing)

Date: 2026-10-01 (updated 2026-10-02) - Version 0.1.1 - Result: **191 automated tests, all passing** after fixes. A separate third-party-tool security audit is in [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md).

## Executive summary

* **Verdict:** the platform is solid as an alpha for lab and read-only production use. Every attack and destructive
  scenario we tried was blocked, and no attempt could make a device reload, erase, or accept unvalidated commands.
* Testing found **9 product defects** (2 high, 5 medium, 2 low) plus **3 installer defects**. All are fixed and have regression tests.
* **No unresolved critical or high findings.** Residual risks are listed below; the main one is that vendor drivers have
  been validated against simulators and a local SSH lab - **not against real Cisco/Fortinet/Palo Alto/MikroTik/Ruckus/Aruba hardware**.
  That must be done before write access is enabled in production.

| Suite | Tests | What it covers |
|---|---|---|
| Drivers | 30 | Parse/render/apply/verify/undo for all 9 platforms against simulators |
| Core / workflow | 40 | Inventory, correlation, compliance, backups, change workflow, rollback on failure, audit chain |
| SSH integration | 14 | Real SSH to lab servers: collect on every platform, bad password, closed port, host-key pinning & MITM detection, full change over SSH |
| Security / destructive | 87 | See below |
| Fuzz + stress | 3 | ~600 random/hostile AI prompts, 4,000 random operation parameter sets, concurrent API + change load |
| Browser usability (Playwright) | 14 | Login, search/filter, drawer, keyboard, session expiry, mobile layout, accessibility basics, back/forward navigation |

## Defects found and fixed

| # | Sev. | Area | Finding | Fix |
|---|---|---|---|---|
| 1 | High | Change control | DB helper returned a stale `lastrowid` for UPDATEs, so the atomic status transitions (four-eyes approval, execute-once) did not behave atomically. Could have allowed double execution / broken approval. | Return `lastrowid` only for INSERT, `rowcount` otherwise. Concurrency test: 6 simultaneous executes -> exactly 1 wins, 1 backup. |
| 2 | Medium | API | A huge integer in a path/body ID (e.g. `/api/backups/99999999999999999999`) caused an unhandled SQLite `OverflowError` -> HTTP 500 (cheap error/DoS vector). | Bounded ID types on all routes; catch-all handler returns a generic 500 with no internals. |
| 3 | Medium | AI guardrail | Destructive-intent filter did not normalise Unicode: full-width or zero-width-padded "reload" bypassed the regex (not exploitable only because the parser also failed to understand it). | NFKC normalisation + control/format-character stripping before any check; tests assert refusal. |
| 4 | Medium | Auth / availability | Lockout was keyed on username alone: an outsider could lock the real admin out by guessing wrong passwords. | Layered throttling: (user, IP) pair, per-IP, and a high per-user ceiling. Test proves admin can still sign in from a clean IP while the attacker is blocked. |
| 5 | Medium | Usability / availability | Login rate limit was a fixed 10/min per IP; all users behind an office NAT or reverse proxy share one IP, so normal sign-ins failed. Found by the browser suite. | `ONC_LOGIN_RATE_PER_MIN` (default 30); `ONC_TRUST_PROXY` for real client IPs; test proves a spoofed `X-Forwarded-For` is ignored unless trusted. |
| 6 | Medium | Functional | PAN-OS block rule was added at the bottom of the rulebase, where an earlier allow rule could shadow it. | Rule is now moved to the top. (FortiOS equivalent - see residual risks.) |
| 7 | Low | Usability / a11y | Escape did not close the detail drawer; focus not moved into it. | Global Escape handler; focus moves to the drawer's close button. |
| 8 | Low | Accessibility | Capability-matrix table headers lacked `scope`. | Added `scope="col"`. |
| 9 | High | Packaging | `httpx` is imported at runtime by the AI module but was missing from `requirements.txt`: a clean `pip install` (and the Docker image) produced an app that **would not start**. Hidden because the dev environment had it. Found by the installer test. | Added to `requirements.txt`; installer now imports the real application as its dependency check. |

Also corrected during testing (test or cosmetic issues, not product defects): bcrypt cost made tests slow (now configurable, `ONC_BCRYPT_ROUNDS`; production default stays 12), one test relied on a simulator quirk, topology tier layout overlap.

## Destructive / security tests (all passing)

* **Authentication:** every `/api/*` route rejects missing/invalid auth; JWT forgery (alg=none, wrong key, expired, tampered payload, role-claim escalation, unknown subject, junk headers); logout and password-change revoke tokens; disabled users blocked.
* **Authorization:** 15-case role matrix; operator cannot acknowledge blast radius; self-approval denied; viewers cannot read backups or the audit log.
* **Injection:** 7 SQL-injection payloads against login; injection in query/path params; newline/CLI-injection in change parameters; shell metacharacters never survive validation; 11 path-traversal variants.
* **Destructive operations:** `reload` as an op, as injected text, via the AI (including look-alike and zero-width forms), block `0.0.0.0/0`, block the management subnet, empty/oversize/negative target lists, over-cap blast radius, mass assignment (`extra` fields), `__proto__`. Result in every case: **no reload, no change row, no device touched.** A control experiment confirms the simulator *would* obey a reload if one were ever sent, so the pass is meaningful.
* **Change integrity:** post-change verification failure triggers automatic rollback of all devices; 6-way concurrent execute runs once; 9 concurrent mixed changes under read/poll load applied exactly once each with an intact audit chain.
* **Brute force / abuse:** lockout, no user enumeration (identical responses), rate limits, 64 KB body cap, ReDoS timing on the NLU parser.
* **SSRF:** 12 bad device addresses (loopback variants, link-local, newline...) rejected; simulator transport unavailable in production mode.
* **Transport:** SSH host-key pinning; MITM with a different key is refused and raises a critical alert.
* **Secrets/data:** encrypted at rest, never in API responses, DB file or backups (backups redacted); key files mode 0600; audit tampering (edit **and** delete) detected.
* **Web hardening:** strict CSP with no inline script/style (zero console errors in the browser), CORS closed to foreign origins, security headers, `no-store` on API, OpenAPI docs disabled, no internals in 500s.

## Usability findings (browser tests, Chromium, desktop and 390px mobile)

Verified: login errors are clear and don't leak which part was wrong; inventory search/filter and device drawer; keyboard
(Escape, focus, Enter to send in chat); session expiry returns to login; back/forward via URL hash; incident -> AI
investigation flow; a viewer-role UI hides actions they cannot perform; mobile layout does not overflow; labelled inputs, table scopes.

## Residual risks and limits (honest list)

1. **No real-hardware validation.** Parsers and command syntax follow vendor documentation but were exercised only against simulators/lab SSH servers. FortiOS LLDP summary, PAN-OS LLDP, Ruckus Unleashed, Aruba Instant and AOS-CX output formats are best-effort and the most likely to need adjustment.
2. **FortiOS block policy ordering:** the deny policy is appended; if an earlier allow policy matches first it will not take effect. Needs a `move ... before` against the real policy list. PAN-OS is handled.
3. **SSH CLI only.** No REST transports yet.
4. **No built-in TLS, MFA or SSO.** Deploy behind a TLS proxy; add SSO at the proxy for now. The session token lives in `sessionStorage` (mitigated by strict CSP, but not immune to a future XSS).
5. **Single node:** SQLite, in-process rate limiter, vault key stored on the same host by default (use `ONC_VAULT_KEY` from a secrets manager).
6. **Deny-list false positives by design:** descriptions containing words such as "password" or "username" are refused.
7. **AI scope:** rule-based intents; unfamiliar phrasing yields a "didn't understand" answer rather than a guess. Optional LLM is classification-only.
8. **Not performed:** third-party penetration test, load testing beyond the concurrent smoke test, long-duration soak, screen-reader testing, firmware-matrix testing.


## Installer testing (`install.sh`)

Run for real on a systemd host (Debian 13, root via sudo): not mocked. ShellCheck clean.

| Scenario | Result |
|---|---|
| Bad `--port`, unknown option, bad `--bind`, bad `--server-name`, relative paths, missing source dir, non-Debian OS | Refused with a clear message, nothing installed |
| Fresh install with `--nginx` (non-root user -> sudo re-exec) | Installs, health check passes |
| Service runs unprivileged; secrets/db 0600; env file 0640 root:service; TLS key 0600; app bound to loopback behind nginx | Verified; `systemd-analyze security` exposure 4.0 (OK) |
| HTTP -> HTTPS redirect, security headers through the proxy, login over TLS with the generated password | Verified |
| Production mode: simulator fault endpoint | 404 |
| Forged `X-Forwarded-For` through nginx / direct exposure | **Correction (v0.1.1):** originally reported as "ignored". An external review showed that from a loopback/trusted peer uvicorn's own proxy-header handling DID accept a forged header and bypass lockout/rate limits. Fixed and regression-tested over a real socket - see `docs/SECURITY_AUDIT.md` V-01 |
| Service restart, re-run (upgrade), port change on re-run | Data, password and settings preserved; nginx follows new port |
| `curl \| bash` style (stdin pipe, clone from git) in demo mode | Works |
| Mode switching demo <-> production <-> nginx on the same data | Security flags reset correctly each run (see below); warning when leaving demo mode |
| `--uninstall` (keeps data) and `--uninstall --purge` | No leftovers (files, user, certs, nginx site); nginx default site restored |
| Test suite on Python 3.10, 3.12, 3.13 (Ubuntu 22.04 / 24.04 interpreters) | 174/174 non-browser tests pass on each |

Installer defects found and fixed during this testing: (a) arguments were lost on the automatic sudo re-exec, silently
running a *default* install; (b) re-running in a different mode left a stale `ONC_TRUST_PROXY=1` (spoofable client IPs)
or demo/simulator flags - these are now set explicitly on every run; (c) uninstall left nginx without its default site.

**Not tested:** an actual Ubuntu 22.04/24.04 machine (Debian 13 and the Ubuntu Python versions were used as proxies),
non-x86 architectures (the installer falls back to compiling wheels, untested), air-gapped installs, Let's Encrypt (self-signed certificate only).
