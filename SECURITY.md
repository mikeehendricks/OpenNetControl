# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting:
**Security tab -> "Report a vulnerability"** on this repository. Include affected version, steps to reproduce and impact.
You will get an acknowledgement within 5 working days. Fixes are released as a patch version with a published advisory.

## Supported versions

Only the latest release receives security fixes (the project is pre-1.0).

## Scope and known limits

In scope: the application, `install.sh`, the Dockerfile and the default configuration they produce.
Documented residual risks (no real-hardware validation, no built-in TLS/MFA/SSO, single node) are listed in
[`docs/TEST_REPORT.md`](docs/TEST_REPORT.md) and [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md).

## Hardening checklist for operators

* Install with `--nginx` (TLS) or put your own TLS proxy in front; set `ONC_TRUST_PROXY=1` only behind a proxy that overwrites `X-Forwarded-For`.
* Never run `--demo` / `ONC_ALLOW_SIM=1` on a production host.
* Change the generated admin password immediately (the first-run password file is then deleted automatically).
* Back up the data directory (database + JWT key + vault key) and restrict access to it.
* Install from a tagged release (`--ref vX.Y.Z`), not from `main`.
