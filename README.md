# OpenNetControl

**An open-source, AI-assisted operations platform for multi-vendor networks.**
One login, one inventory, one live topology, and an AI assistant that finds the *cause* of an outage instead of
just listing symptoms - with human approval, automatic rollback and a tamper-evident audit trail on every change.

Natively supports **Cisco** (IOS-XE, NX-OS), **Fortinet** (FortiOS), **Palo Alto** (PAN-OS), **MikroTik** (RouterOS),
**Ruckus** (ICX switches, Unleashed Wi-Fi) and **Aruba** (AOS-CX, Instant).

![Overview](docs/screenshots/01-overview.png)

## What it does

| | |
|---|---|
| **Unified inventory** | Every device from every vendor normalised into one model (platform, version, CPU/memory, interfaces, neighbours, Wi-Fi clients), searchable and filterable. |
| **Live topology** | Built from LLDP/CDP neighbour data collected from the devices themselves, drawn by tier, with failed links in red and alert badges. |
| **Cross-domain correlation** | Alerts that share a failure domain are folded into one incident with a probable root cause and downstream symptoms. |
| **AI assistant** | Ask in plain English ("which devices still have telnet enabled?", "block 203.0.113.9 on all firewalls"). Answers come from live data; requests become *proposed* changes. |
| **Safe change control** | Per-vendor plan preview, four-eyes approval, blast-radius cap, pre-change backup, post-change verification, all-or-nothing automatic rollback. |
| **Compliance** | Telnet, default SNMP community, missing NTP, firmware baselines, missing backups - across all vendors at once. |
| **Audit** | Hash-chained audit log; the UI can verify the chain and flags edited or deleted entries. |

### Root cause, not symptoms
![Incident](docs/screenshots/02-incident-root-cause.png)

### Live multi-vendor topology
![Topology](docs/screenshots/03-topology.png)

### Natural-language operations, human-approved
The assistant renders the native commands for each vendor, runs them through guardrails, and then **stops**.
It has no tool that can approve or execute a change - that is enforced in code, not in a prompt.

![AI assistant and change approval](docs/screenshots/06-change-approval.png)

<details><summary>More screenshots</summary>

![Inventory](docs/screenshots/04-inventory-device.png)
![Compliance](docs/screenshots/07-compliance.png)
![Platforms](docs/screenshots/08-platforms.png)
</details>

## Quick start (demo)

The demo runs 15 simulated devices across 9 platforms - no hardware needed.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
ONC_DEMO=1 ONC_ALLOW_SIM=1 python -m opennetcontrol      # http://localhost:8080
```

Passwords are generated on first start and written (mode 0600) to `data/initial_<user>_password.txt`.
Set `ONC_ADMIN_PASSWORD` to choose your own. In demo mode the Overview page has buttons to power off a device,
spike CPU or drop a link so you can watch correlation and the AI investigation work.

## Production use

```bash
pip install -r requirements.txt
python -m opennetcontrol            # no ONC_DEMO / ONC_ALLOW_SIM: simulators and fault injection are disabled
```

* Run it behind a TLS-terminating reverse proxy. Set `ONC_TRUST_PROXY=1` **only** if that proxy sets `X-Forwarded-For`.
* Add devices (admin) via `POST /api/devices` with a stored credential; secrets are encrypted at rest (`ONC_VAULT_KEY` to supply your own key).
* Device access is SSH. Host keys are pinned on first connect and a changed key raises a critical alert.
* Docker: `docker build -t opennetcontrol . && docker run -p 8080:8080 -v onc-data:/data opennetcontrol`

### Configuration (environment)

`ONC_HOST`, `ONC_PORT`, `ONC_DATA_DIR`, `ONC_ADMIN_PASSWORD`, `ONC_JWT_SECRET`, `ONC_VAULT_KEY`, `ONC_TOKEN_TTL_MIN`,
`ONC_POLL_INTERVAL`, `ONC_FOUR_EYES`, `ONC_MAX_TARGETS`, `ONC_MIN_VERSIONS`, `ONC_LOGIN_MAX_FAILS`, `ONC_LOGIN_LOCK_S`,
`ONC_LOGIN_RATE_PER_MIN`, `ONC_RATE_PER_MIN`, `ONC_TRUST_PROXY`, `ONC_CORS_ORIGINS`, `ONC_LLM_URL` / `ONC_LLM_KEY` / `ONC_LLM_MODEL`.

The AI works fully offline with a built-in rule-based parser. Optionally point `ONC_LLM_URL` at an OpenAI-compatible
endpoint to improve intent classification; the model only ever sees the user's question, never device output, and its
output is re-validated by the same guardrails.

## Security model

* Roles `viewer < operator < admin`; role is re-read from the database on every request.
* Bearer-token auth (no cookies, so no CSRF), pinned HS256, revocation on logout/password change, per-user/IP lockout, rate limits.
* Strict input allow-lists for every operation parameter; **no free-form CLI is ever sent to a device**.
* Policy deny-list (reload, erase, format, factory-reset, credential changes, ...) applied to every rendered line *and* its undo.
* Four-eyes approval (requester cannot approve own change), atomic execution (double-submit executes once), blast-radius cap.
* SSRF controls on device addresses, strict CSP, security headers, body-size cap, generic error responses, no API docs exposed.

See [`docs/TEST_REPORT.md`](docs/TEST_REPORT.md) for what was tested, what was found, and what is **not** covered.

## Architecture

```
opennetcontrol/
  drivers/   one driver per platform: collect -> normalise, render(op) -> native CLI + undo, apply, verify
  sim/       faithful-enough simulators used for the demo and tests
  ai/        NLU, optional LLM classifier, agent with guardrails
  core.py    inventory, polling, correlation, compliance, change workflow
  security.py  vault, auth, rate limit, hash-chained audit
  app.py     FastAPI API + static SPA
lab/         real SSH servers wrapping the simulators (used by the SSH integration tests)
tests/       unit, integration, security, fuzz, and browser (Playwright) tests
```

Adding a vendor = one driver class implementing `collect`, `render`, `apply`, `verify` plus capability flags.

## Honest status

Alpha. The drivers have been validated **against simulators and a local SSH lab, not against real hardware**.
Command syntax follows vendor documentation, but parsers must be validated against your firmware versions before
trusting them in production. Start read-only (inventory, topology, compliance) and enable changes once verified in a lab.
REST/API transports (FortiOS, PAN-OS, ...) are on the roadmap; today every vendor is driven over SSH CLI.

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests --ignore=tests/e2e        # unit, integration, SSH, security, fuzz
playwright install chromium && pytest tests/e2e
python tests/e2e/shots.py http://localhost:8080   # regenerate screenshots from a running demo
```

## License

MIT
