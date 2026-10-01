"""Authentication, RBAC, secrets vault, rate limiting and tamper-evident audit log."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken

from .db import DB, now, jdump

ROLES = {"viewer": 1, "operator": 2, "admin": 3}
PW_MIN = 12
BCRYPT_ROUNDS = max(4, int(os.environ.get('ONC_BCRYPT_ROUNDS', '12')))


def _key_file(path: str, gen) -> bytes:
    if os.path.exists(path):
        return open(path, "rb").read().strip()
    data = gen()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return data


class Vault:
    """Encrypts device credentials at rest (Fernet / AES-128-CBC + HMAC)."""

    def __init__(self, data_dir: str):
        key = os.environ.get("ONC_VAULT_KEY", "").encode() or _key_file(os.path.join(data_dir, "vault.key"), Fernet.generate_key)
        self.f = Fernet(key)

    def enc(self, s: str) -> bytes:
        return self.f.encrypt(s.encode())

    def dec(self, b: bytes) -> str:
        try:
            return self.f.decrypt(bytes(b)).decode()
        except InvalidToken:
            raise ValueError("credential cannot be decrypted (wrong vault key?)")


def check_password_policy(pw: str) -> None:
    if not isinstance(pw, str) or len(pw) < PW_MIN or len(pw) > 128:
        raise ValueError(f"password must be {PW_MIN}-128 characters")
    classes = sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]"))
    if classes < 3:
        raise ValueError("password needs at least 3 of: lower, upper, digit, symbol")


class Auth:
    def __init__(self, db: DB, data_dir: str, settings):
        self.db, self.s = db, settings
        self.secret = os.environ.get("ONC_JWT_SECRET", "").encode() or _key_file(
            os.path.join(data_dir, "jwt.key"), lambda: secrets.token_hex(32).encode())
        self._dummy = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(BCRYPT_ROUNDS))

    # ---- users
    def create_user(self, username: str, password: str, role: str):
        if role not in ROLES:
            raise ValueError("invalid role")
        if not re.match(r"^[A-Za-z0-9_.-]{3,32}$", username or ""):
            raise ValueError("invalid username")
        check_password_policy(password)
        h = bcrypt.hashpw(password.encode(), bcrypt.gensalt(BCRYPT_ROUNDS))
        self.db.x("INSERT INTO users(username,pw_hash,role,created) VALUES(?,?,?,?)", (username, h, role, now()))

    def _count(self, k: str) -> int:
        self.db.x("DELETE FROM login_fails WHERE ts<?", (now() - self.s.login_lock_s,))
        return self.db.q("SELECT COUNT(*) c FROM login_fails WHERE k=?", (k,))[0]["c"]

    def login(self, username: str, password: str, ip: str) -> str | None:
        """Throttling is layered so an outsider cannot lock a real user out of their own account:
        - (user, ip) pair: max_fails          -> stops guessing from one source
        - ip alone:        4 x max_fails      -> stops spraying many usernames from one source
        - user alone:      10 x max_fails     -> ceiling for distributed guessing (still lets the owner in from a clean IP until then)
        """
        username = (username or "")[:64]
        u_ = username.lower()
        keys = {f"p:{u_}|{ip}": self.s.login_max_fails, f"ip:{ip}": self.s.login_max_fails * 4, f"u:{u_}": self.s.login_max_fails * 10}
        if any(self._count(k) >= lim for k, lim in keys.items()):
            raise PermissionError("locked")
        u = self.db.one("SELECT * FROM users WHERE username=? AND disabled=0", (username,))
        ok = bcrypt.checkpw((password or "").encode()[:72], u["pw_hash"] if u else self._dummy)  # constant-ish time
        if not (u and ok):
            for k in keys:
                self.db.x("INSERT INTO login_fails VALUES(?,?)", (k, now()))
            return None
        self.db.x("DELETE FROM login_fails WHERE k=?", (f"p:{u_}|{ip}",))
        exp = now() + self.s.token_ttl_min * 60
        return jwt.encode({"sub": u["username"], "role": u["role"], "exp": exp, "iat": now(), "jti": uuid.uuid4().hex},
                          self.secret, algorithm="HS256")

    def verify(self, token: str) -> dict | None:
        try:
            p = jwt.decode(token, self.secret, algorithms=["HS256"], options={"require": ["exp", "sub", "jti"]})
        except jwt.PyJWTError:
            return None
        if self.db.one("SELECT 1 FROM revoked WHERE jti=?", (p["jti"],)):
            return None
        u = self.db.one("SELECT username, role, disabled FROM users WHERE username=?", (p["sub"],))
        if not u or u["disabled"]:
            return None
        return {"username": u["username"], "role": u["role"], "jti": p["jti"], "exp": p["exp"]}   # role from DB, not token

    def revoke(self, jti: str, exp: float):
        self.db.x("INSERT OR IGNORE INTO revoked VALUES(?,?)", (jti, exp))
        self.db.x("DELETE FROM revoked WHERE exp<?", (now(),))


class RateLimiter:
    def __init__(self, per_min: int):
        self.per_min, self.hits, self.lock = per_min, defaultdict(deque), threading.Lock()

    def allow(self, key: str, limit: int | None = None) -> bool:
        limit = limit or self.per_min
        t = time.time()
        with self.lock:
            q = self.hits[key]
            while q and q[0] < t - 60:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(t)
            if len(self.hits) > 5000:
                for k in [k for k, v in self.hits.items() if not v][:1000]:
                    self.hits.pop(k, None)
            return True


class Audit:
    """Append-only, hash-chained log: each row commits to the previous one."""

    def __init__(self, db: DB):
        self.db = db

    def log(self, actor: str, action: str, detail: dict | None = None):
        with self.db.tx() as db:
            prev = (db.one("SELECT hash FROM audit ORDER BY id DESC LIMIT 1") or {"hash": "GENESIS"})["hash"]
            ts, d = now(), jdump(detail or {})
            h = hashlib.sha256(f"{prev}|{ts!r}|{actor}|{action}|{d}".encode()).hexdigest()
            db.x("INSERT INTO audit(ts,actor,action,detail,prev,hash) VALUES(?,?,?,?,?,?)", (ts, actor, action, d, prev, h))

    def verify(self) -> dict:
        prev = "GENESIS"
        for r in self.db.q("SELECT * FROM audit ORDER BY id"):
            h = hashlib.sha256(f"{prev}|{r['ts']!r}|{r['actor']}|{r['action']}|{r['detail']}".encode()).hexdigest()
            if r["prev"] != prev or r["hash"] != h:
                return {"ok": False, "broken_at": r["id"]}
            prev = r["hash"]
        return {"ok": True, "broken_at": None}


SECRET_LINE = re.compile(r"(?i)(password|secret|community|phash|key|encrypted|\benc\b|mgmt-user|admin-password|hash)")


def redact_config(cfg: str) -> str:
    out = []
    for ln in cfg.splitlines():
        m = SECRET_LINE.search(ln)
        if m:
            out.append(ln[:m.end()] + " <redacted>")
        else:
            out.append(ln)
    return "\n".join(out)
