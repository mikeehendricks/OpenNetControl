"""Runtime configuration (environment driven, secure defaults)."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _b(name, default):
    return os.environ.get(name, str(default)).lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    data_dir: str = os.environ.get("ONC_DATA_DIR", "./data")
    host: str = os.environ.get("ONC_HOST", "127.0.0.1")
    port: int = int(os.environ.get("ONC_PORT", "8080"))
    demo: bool = _b("ONC_DEMO", False)               # seeds a simulated multi-vendor fleet
    allow_sim: bool = _b("ONC_ALLOW_SIM", False)     # permit 'sim' transport devices
    allow_loopback_targets: bool = _b("ONC_ALLOW_LOOPBACK", False)
    four_eyes: bool = _b("ONC_FOUR_EYES", True)      # approver must differ from requester
    poll_interval: int = int(os.environ.get("ONC_POLL_INTERVAL", "60"))
    max_targets: int = int(os.environ.get("ONC_MAX_TARGETS", "10"))
    token_ttl_min: int = int(os.environ.get("ONC_TOKEN_TTL_MIN", "480"))
    admin_password: str | None = os.environ.get("ONC_ADMIN_PASSWORD")
    llm_url: str | None = os.environ.get("ONC_LLM_URL")      # OpenAI-compatible /v1/chat/completions
    llm_key: str | None = os.environ.get("ONC_LLM_KEY")
    llm_model: str = os.environ.get("ONC_LLM_MODEL", "gpt-4o-mini")
    cors_origins: str = os.environ.get("ONC_CORS_ORIGINS", "")
    login_max_fails: int = int(os.environ.get("ONC_LOGIN_MAX_FAILS", "5"))
    login_lock_s: int = int(os.environ.get("ONC_LOGIN_LOCK_S", "900"))
    login_rate_per_min: int = int(os.environ.get("ONC_LOGIN_RATE_PER_MIN", "30"))
    trust_proxy: bool = _b("ONC_TRUST_PROXY", False)   # honour X-Forwarded-For (only behind your own reverse proxy)
    trusted_proxies: str = os.environ.get("ONC_TRUSTED_PROXIES", "127.0.0.1,::1")   # peers allowed to set X-Forwarded-For (needs ONC_TRUST_PROXY=1)
    rate_per_min: int = int(os.environ.get("ONC_RATE_PER_MIN", "240"))
    min_versions: str = os.environ.get("ONC_MIN_VERSIONS", "")   # e.g. "fortinet_fortios=7.4.0,cisco_iosxe=17.9"
