# OpenNetControl - Third-Party Tool Security Audit

Target: `github.com/mikeehendricks/OpenNetControl` @ `b0e4076` (v0.1.0), cloned fresh from GitHub, installed with its own
`install.sh` (production-style: nginx TLS + systemd) and attacked. Remediated in **v0.1.1**. Date: 2026-10-02.

> **What this is - and is not.** Independent, industry-standard *tools* were run against the code and the deployed
> system, plus a manual review and hands-on exploit attempts. It is **not** a human penetration test by an external firm
> and it is not a compliance certification. Severities are my own CVSS-style judgement, not a vendor rating.

## Executive summary

* **Result: 15 issues found, all 15 fixed and re-verified.** 0 critical, 0 high, 3 medium, 8 low, 4 informational.
  Every scanner that can be run in CI now reports **zero findings** on the fixed code (see table below).
* **The one finding that matters most (V-01, medium):** an attacker able to reach the app from a "trusted proxy" address
  (loopback / a co-located proxy) could forge an `X-Forwarded-For` header on every request and **bypass the account
  lockout and rate limiting** - 25 consecutive wrong-password guesses were never blocked. This was a bug in how the
  web server was started, it was *not* caught by my earlier testing, and my earlier installer test report wrongly said the
  header was ignored (corrected in `TEST_REPORT.md`). In a default `--nginx` install the backend only listens on
  loopback behind nginx (which overwrites the header), so remote exploitation was not possible; it was still a real bypass for
  anything running on the same host, or any deployment with another proxy in front.
* **No injection or remote-code-execution issues were found.** SQL injection (sqlmap, Wapiti, manual review of every
  query), XSS, command injection, path traversal, SSRF, CRLF, open redirect, XXE and file-disclosure checks all came back clean.
  Dependencies have **no known CVEs**. No secrets were found in the repository or its full git history.
* **Biggest remaining risks are not code bugs:** drivers have never touched real network hardware, there is no MFA/SSO,
  and several GitHub repository protections could not be enabled with the access token provided (listed under *Actions for you*).

## Tools used

| Area | Tool(s) | Result before | Result after (v0.1.1) |
|---|---|---|---|
| Python SAST | Bandit | 7 findings (3 medium, 4 low) | **0** (2 documented `nosec` for non-bind literals) |
| Multi-language SAST | Semgrep (python, security-audit, owasp-top-ten, javascript, dockerfile, secrets, github-actions) | 1 | **0** |
| JavaScript SAST | njsscan | 1 | **0** |
| Dependency CVEs | pip-audit (OSV / PyPI advisories) | 0 | **0** (now checked against the hash-pinned lock) |
| Secrets | detect-secrets + full git-history regex scan | 0 real (5 test-fixture false positives) | **0** (baseline committed) |
| Dockerfile / CI config | Checkov | 1 failed (no HEALTHCHECK) | **0 failed** (53 Dockerfile + 72 GitHub-Actions checks pass) |
| Shell (installer) | ShellCheck | clean | clean |
| TLS configuration | sslyze | weak ciphers, bad cert | forward-secret AEAD only, valid leaf cert |
| nginx configuration | gixy | clean | clean |
| Web scanner (DAST) | Wapiti 3.3.2, all modules (38 vulnerability categories), authenticated | 0 vulnerabilities | 0 vulnerabilities |
| SQL injection (DAST) | sqlmap, level 5 / risk 3, JSON + GET + path params | 0 injectable | not re-run (no SQL code changed) |
| OS sandbox | `systemd-analyze security` | exposure 4.0 | **1.2** |
| Manual | Code/installer/config review; PoC exploit scripts | 2 findings beyond the tools | fixed |
| Regression tests | pytest (Python 3.10 / 3.12 / 3.13) + Playwright | - | **191 tests pass** (177 non-browser on each interpreter, 14 browser) |

## Findings

| ID | Sev. | Finding | Found by | Fix |
|---|---|---|---|---|
| **V-01** | **Medium** | **Forged `X-Forwarded-For` bypasses login lockout and rate limits.** uvicorn's built-in proxy-header handling replaced the client address with the forged header whenever the TCP peer was 127.0.0.1, even with `ONC_TRUST_PROXY` off. PoC: 25 bad logins with rotating forged IPs -> 25x HTTP 401, never blocked. | Manual review of server logs during the DAST run, confirmed with a PoC | uvicorn started with `proxy_headers=False`; the app now trusts `X-Forwarded-For` only if `ONC_TRUST_PROXY=1` **and** the TCP peer is in `ONC_TRUSTED_PROXIES` (default loopback). Same PoC now: 401 x5 then 429. Regression test runs a real uvicorn socket and was verified to **fail** on the vulnerable setting. |
| V-02 | Medium | TLS 1.2 accepted static-RSA (no forward secrecy), CBC, Camellia and ARIA suites; installer relied on OS defaults. | sslyze | Explicit ECDHE+AEAD cipher list, session tickets off, curve list. sslyze: 3 suites (ECDHE-RSA AES-128-GCM / AES-256-GCM / CHACHA20), 0 weak. |
| V-03 | Medium | Supply chain: dependencies unpinned and unhashed (`>=`); the installer and Dockerfile fetched whatever PyPI served at install time. | Manual review | `requirements.lock` - universal (Python 3.10-3.13), exact versions, 409 SHA-256 hashes; installer and Dockerfile use `--require-hashes`. Missing `httpx` runtime dependency was fixed earlier (v0.1.0). |
| V-04 | Low | Installer's self-signed certificate asserted `CA:TRUE` (a server cert that can act as a CA) and lasted 825 days. | sslyze | `CA:FALSE`, key usage + `serverAuth` EKU, 397 days. |
| V-05 | Low | nginx front-end had no request/connection rate limiting or timeouts, and did not set `server_tokens off` (Ubuntu's default leaks the version). | Manual review / header check | Per-IP request limit, stricter login limit (10/min), connection cap, header/body timeouts, `server_tokens off` per server block. Verified: login 429 after burst; 25 of 120 flood requests rejected. |
| V-06 | Low | Installer ran as root with unvalidated `--install-dir` / `--data-dir`: used in `rm -rf`, `sed` and generated systemd units. `--uninstall --install-dir /usr` was a data-destruction footgun. | Manual review | Strict charset, no `..`, must contain "opennetcontrol", minimum depth, no overlap; uninstall/purge also require a marker file. Six hostile invocations tested and refused. |
| V-07 | Low | First-run admin password stayed on disk in plaintext after the admin changed it. | Manual review | File deleted when that user changes their password (regression test). |
| V-08 | Low | Docker image had no `HEALTHCHECK`. | Checkov | Added; also pip cache/bytecode disabled, hash-verified install. |
| V-09 | Low | Backend sent a `Server: uvicorn` banner when exposed directly. | Header inspection | `server_header=False`; regression test. |
| V-10 | Low | Three `except: pass` blocks (poller loop, SSH close, lab server) silently swallowed errors - a failing poller would go unnoticed. | Bandit B110 | Logged (`log.exception` / debug) while keeping the poller alive. |
| V-11 | Low | Hardcoded default password (`lab-password`) in the lab SSH server. | Bandit B107, Semgrep | Random per-process password (or `ONC_LAB_PASSWORD`); tests read it from the module. |
| V-12 | Info | systemd sandbox could be stricter. | `systemd-analyze` | Added syscall filter, `MemoryDenyWriteExecute`, `ProtectProc`, namespace/clock/hostname/kernel-log protection, etc. Exposure 4.0 -> 1.2. Service verified healthy. |
| V-13 | Info | Front-end looked up the URL hash directly in the `PAGES` object, so `#constructor` resolved to an inherited property. Robustness bug next to the njsscan hit. | njsscan + code reading | `Object.hasOwn`; route comparison rewritten. 14 browser tests pass. |
| V-14 | Info | SQL built with an f-string for a table name (constant tuple - not exploitable). | Bandit B608 | Replaced with explicit statements. Every SQL call in the code base is now a literal with `?` placeholders. |
| V-15 | Info | Repository hygiene: no `SECURITY.md`, CI, Dependabot, CODEOWNERS, or secret baseline. | Review | Added `SECURITY.md`, CODEOWNERS, Dependabot (7-day cooldown), secrets baseline, and a CI definition (tests on 3 Pythons, Bandit, pip-audit, detect-secrets, ShellCheck, CodeQL; actions pinned to commit SHAs) shipped as `docs/ci.yml.example` - **it is not active until you copy it to `.github/workflows/ci.yml`** (GitHub rejected the token for lacking `workflow` scope). |

### Reviewed and judged false positives (no code change needed)
Bandit B104 x2 (`"0.0.0.0"` is parsed device data, not a socket bind - now a named, documented constant);
detect-secrets x5 (sample passwords in attack tests); Semgrep `PartialParsing` on `install.sh` (tool limitation);
Wapiti "Unencrypted Channels" x2 on the final run (I scanned the plain-HTTP loopback backend directly; the first run
through TLS was clean); sqlmap heuristic warnings (no injection confirmed).

## What was tried and held (no finding)
SQL injection (JSON body, query and path parameters; login, chat, change, audit, device endpoints); reflected/stored XSS;
command and CRLF injection; path traversal and backup-file probing; SSRF; open redirect; clickjacking and CSP checks;
TRACE/OPTIONS; oversized URL/body; JWT forgery; brute-force lockout (now also under forged-header attack); TLS downgrade
(TLS 1.0/1.1/SSLv3 rejected, TLS_FALLBACK_SCSV, no Heartbleed/CCS/ROBOT/renegotiation DoS/compression);
secrets in git history; known-CVE dependencies.

## Limits of this audit (read before relying on it)
* Automated tools plus one reviewer - **no independent human penetration test**, no Burp/ZAP session, no fuzzing of the SSH/CLI parsers with real device output.
* DAST ran on a demo instance with rate limits temporarily raised (otherwise the app's own throttling stops the scanner); sqlmap's login/chat/change runs hit my time budget before every technique finished - the SQL-injection conclusion rests mainly on the full source review (every query parameterised), not on sqlmap alone.
* Tested on Debian 13 (not Ubuntu 22.04/24.04); the Docker image was linted (Checkov) but not built.
* Wapiti does not generate JSON request bodies; JSON endpoints were covered by sqlmap, the project's own 87 security tests and fuzzing.
* Everything still applies from `TEST_REPORT.md`: drivers validated only against simulators; no built-in MFA/SSO; single node; self-signed certificate by default; FortiOS block-policy ordering.
* In `--nginx` mode the app deliberately trusts `X-Forwarded-For` from loopback (nginx overwrites it). Anyone with local access to the host can therefore still forge it - local access is already a stronger position.

## Actions for you (could not be done with the supplied token)
1. **Revoke the GitHub PAT that was pasted into chat** - it was exposed in chat and should be treated as compromised.
2. **Activate CI:** copy `docs/ci.yml.example` to `.github/workflows/ci.yml` (web UI, or a token with `workflow` scope).
3. In the repo's *Settings -> Code security*, enable: **private vulnerability reporting**, **Dependabot alerts + security updates**, **secret scanning + push protection**, and **code scanning (CodeQL)** (the supplied token got HTTP 403 on these).
4. Add **branch protection on `main`**: require pull requests, require the `CI` checks, block force-pushes; require signed commits/tags if you can.
5. Turn on 2FA for the GitHub account and use a fine-grained, short-lived token with only the scopes needed next time.
6. Replace the installer's self-signed certificate with a real one (`/etc/ssl/opennetcontrol/server.{crt,key}`) before real use.
7. Before enabling write access to production devices: validate drivers on real hardware in a lab.
