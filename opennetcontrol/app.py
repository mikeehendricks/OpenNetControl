"""HTTP API + web UI."""
from __future__ import annotations

import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from typing import Literal, Optional

from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, Path, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from . import validation as V
from . import lab as labmod
from .ai.agent import Agent
from .config import Settings
from .core import Core, ChangeError
from .drivers import DRIVERS, VENDORS
from .ops import OPS
from .security import ROLES, redact_config

log = logging.getLogger("opennetcontrol")
STATIC = os.path.join(os.path.dirname(__file__), "static")


ID = Annotated[int, Path(ge=1, le=2**31 - 1)]
DevId = Annotated[int, Field(ge=1, le=2**31 - 1)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginIn(Strict):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class PasswordIn(Strict):
    current: str = Field(max_length=256)
    new: str = Field(max_length=256)


class UserIn(Strict):
    username: str = Field(max_length=32)
    password: str = Field(max_length=256)
    role: Literal["viewer", "operator", "admin"]


class CredIn(Strict):
    name: str = Field(max_length=64)
    username: str = Field(max_length=64)
    secret: str = Field(max_length=256)


class DeviceIn(Strict):
    name: str = Field(max_length=63)
    address: str = Field(max_length=253)
    platform: str = Field(max_length=40)
    site: str = Field("", max_length=64)
    role: Optional[str] = Field(None, max_length=16)
    port: int = 22
    credential_id: Optional[int] = None
    transport: Literal["ssh", "sim"] = "ssh"
    tags: str = Field("", max_length=64)
    protected_ifaces: list[str] = Field(default_factory=list, max_length=32)
    mgmt_ip: str = Field("", max_length=15)


class ChangeIn(Strict):
    op: str = Field(max_length=40)
    params: dict = Field(default_factory=dict)
    device_ids: list[DevId] = Field(max_length=500)
    summary: str = Field("", max_length=200)
    acknowledge_blast_radius: bool = False


class ChatIn(Strict):
    message: str = Field(max_length=1000)


class FaultIn(Strict):
    action: Literal["power_off", "power_on", "link_down", "link_up", "cpu"]
    device: str = Field(max_length=63)
    interface: str = Field("", max_length=40)
    value: float = 0


def create_app(settings: Settings | None = None) -> FastAPI:
    s = settings or Settings()
    core = Core(s)
    agent = Agent(core)

    @asynccontextmanager
    async def lifespan(app):
        _bootstrap(core, s)
        if s.demo:
            core.seed_demo()
        else:
            core.poll_all()
        core.start_poller()
        yield
        core.stop()

    app = FastAPI(title="OpenNetControl", version="0.1.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.core = core

    def client_ip(request: Request) -> str:
        if s.trust_proxy:
            xff = request.headers.get("x-forwarded-for", "")
            if xff:
                return xff.split(",")[-1].strip()[:45]      # last hop = the one our proxy appended
        return request.client.host if request.client else "?"

    # ------------------------------------------------------------------ middleware
    @app.middleware("http")
    async def guard(request: Request, call_next):
        ip = client_ip(request)
        path = request.url.path
        if path.startswith("/api/"):
            cl = request.headers.get("content-length")
            if cl and (not cl.isdigit() or int(cl) > 65536):
                return JSONResponse({"detail": "request body too large"}, status_code=413)
            lim = {"/api/auth/login": s.login_rate_per_min, "/api/ai/chat": 40}.get(path)
            if not core.rl.allow(f"{ip}:{path if lim else 'api'}", lim):
                return JSONResponse({"detail": "rate limit exceeded"}, status_code=429, headers={"Retry-After": "30"})
        try:
            resp = await call_next(request)
        except Exception:
            log.exception("unhandled error")
            resp = JSONResponse({"detail": "internal error"}, status_code=500)
        h = resp.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        h["Content-Security-Policy"] = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                        "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        if path.startswith("/api/"):
            h["Cache-Control"] = "no-store"
        return resp

    @app.exception_handler(V.ValidationError)
    async def _ve(_, e): return JSONResponse({"detail": str(e)}, status_code=400)

    @app.exception_handler(ChangeError)
    async def _ce(_, e): return JSONResponse({"detail": str(e)}, status_code=409)

    @app.exception_handler(Exception)
    async def _any(_, e):
        log.exception("unhandled error")
        return JSONResponse({"detail": "internal error"}, status_code=500)

    @app.exception_handler(KeyError)
    async def _ke(_, e): return JSONResponse({"detail": "not found"}, status_code=404)

    # ------------------------------------------------------------------ auth deps
    def user(request: Request) -> dict:
        h = request.headers.get("authorization", "")
        if not h.lower().startswith("bearer "):
            raise HTTPException(401, "authentication required")
        u = core.auth.verify(h[7:].strip())
        if not u:
            raise HTTPException(401, "invalid or expired token")
        return u

    def need(role: str):
        def dep(u: dict = Depends(user)) -> dict:
            if ROLES[u["role"]] < ROLES[role]:
                core.audit.log(u["username"], "authz.denied", {"need": role})
                raise HTTPException(403, f"requires role '{role}'")
            return u
        return dep

    viewer, operator, admin = need("viewer"), need("operator"), need("admin")

    # ------------------------------------------------------------------ auth
    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.1.0"}

    @app.post("/api/auth/login")
    def login(b: LoginIn, request: Request):
        ip = client_ip(request)
        try:
            tok = core.auth.login(b.username, b.password, ip)
        except PermissionError:
            core.audit.log(b.username[:32], "auth.locked", {"ip": ip})
            raise HTTPException(429, "too many failed attempts; try again later")
        if not tok:
            core.audit.log(b.username[:32], "auth.failed", {"ip": ip})
            raise HTTPException(401, "invalid credentials")
        u = core.auth.verify(tok)
        core.audit.log(u["username"], "auth.login", {"ip": ip})
        return {"token": tok, "username": u["username"], "role": u["role"]}

    @app.post("/api/auth/logout")
    def logout(u: dict = Depends(user)):
        core.auth.revoke(u["jti"], u["exp"])
        core.audit.log(u["username"], "auth.logout")
        return {"ok": True}

    @app.get("/api/auth/me")
    def me(u: dict = Depends(user)):
        return {"username": u["username"], "role": u["role"]}

    @app.post("/api/auth/password")
    def change_pw(b: PasswordIn, request: Request, u: dict = Depends(user)):
        from .security import check_password_policy
        import bcrypt
        row = core.db.one("SELECT pw_hash FROM users WHERE username=?", (u["username"],))
        if not bcrypt.checkpw(b.current.encode()[:72], row["pw_hash"]):
            raise HTTPException(403, "current password incorrect")
        try:
            check_password_policy(b.new)
        except ValueError as e:
            raise HTTPException(400, str(e))
        core.db.x("UPDATE users SET pw_hash=? WHERE username=?", (bcrypt.hashpw(b.new.encode(), bcrypt.gensalt(__import__('opennetcontrol.security', fromlist=['x']).BCRYPT_ROUNDS)), u["username"]))
        core.auth.revoke(u["jti"], u["exp"])
        core.audit.log(u["username"], "auth.password_changed")
        return {"ok": True}

    @app.get("/api/users")
    def users(_: dict = Depends(admin)):
        return core.db.q("SELECT id,username,role,created,disabled FROM users ORDER BY id")

    @app.post("/api/users")
    def add_user(b: UserIn, u: dict = Depends(admin)):
        try:
            core.auth.create_user(b.username, b.password, b.role)
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            if "UNIQUE" in str(e):
                raise HTTPException(409, "user exists")
            raise
        core.audit.log(u["username"], "user.create", {"username": b.username, "role": b.role})
        return {"ok": True}

    # ------------------------------------------------------------------ read APIs
    @app.get("/api/overview")
    def overview(_: dict = Depends(viewer)):
        return {**core.overview(), "demo": s.demo}

    @app.get("/api/vendors")
    def vendors(_: dict = Depends(viewer)):
        return [{"platform": d.platform, "vendor": d.vendor, "vendor_name": VENDORS[d.vendor], "label": d.label, "roles": list(d.roles),
                 "capabilities": sorted(d.capabilities)} for d in DRIVERS.values()]

    @app.get("/api/ops")
    def ops(_: dict = Depends(viewer)):
        return [{"op": k, "risk": v["risk"], "desc": v["desc"], "params": list(v["params"])} for k, v in OPS.items()]

    @app.get("/api/devices")
    def devices(_: dict = Depends(viewer)):
        out = core.devices()
        for d in out:
            d.pop("credential_id", None); d.pop("host_key", None)
        return out

    @app.get("/api/devices/{did}")
    def device(did: ID, _: dict = Depends(viewer)):
        d = core.device_view(did)
        d.pop("credential_id", None)
        return d

    @app.get("/api/topology")
    def topology(_: dict = Depends(viewer)):
        return core.topology()

    @app.get("/api/alerts")
    def alerts(status: Literal["open", "resolved"] = "open", _: dict = Depends(viewer)):
        return core.alerts(status)

    @app.get("/api/incidents")
    def incidents(status: Literal["open", "resolved"] = "open", _: dict = Depends(viewer)):
        return core.incidents(status)

    @app.get("/api/compliance")
    def compliance(_: dict = Depends(viewer)):
        return core.compliance()

    # ------------------------------------------------------------------ device admin
    @app.post("/api/credentials")
    def add_cred(b: CredIn, u: dict = Depends(admin)):
        try:
            return {"id": core.add_credential(b.name, b.username, b.secret, u["username"])}
        except Exception as e:
            if "UNIQUE" in str(e):
                raise HTTPException(409, "credential name exists")
            raise

    @app.post("/api/devices")
    def add_device(b: DeviceIn, u: dict = Depends(admin)):
        did = core.add_device(u["username"], **b.model_dump())
        core.poll_device(did)
        core.recompute_incidents()
        return {"id": did}

    @app.delete("/api/devices/{did}")
    def del_device(did: ID, u: dict = Depends(admin)):
        core.delete_device(u["username"], did)
        return {"ok": True}

    @app.post("/api/devices/{did}/refresh")
    def refresh(did: ID, u: dict = Depends(operator)):
        r = core.poll_device(did)
        core.recompute_incidents()
        return r

    @app.post("/api/poll")
    def poll(u: dict = Depends(operator)):
        core.poll_all()
        return {"ok": True}

    @app.post("/api/devices/{did}/backup")
    def backup(did: ID, u: dict = Depends(operator)):
        try:
            return core.backup(u["username"], did)
        except Exception as e:
            if isinstance(e, KeyError):
                raise
            raise HTTPException(502, f"backup failed: {str(e)[:120]}")

    @app.get("/api/devices/{did}/backups")
    def backups(did: ID, _: dict = Depends(operator)):
        core.get_device(did)
        return core.backups(did)

    @app.get("/api/backups/{bid}")
    def backup_get(bid: ID, u: dict = Depends(operator)):
        core.audit.log(u["username"], "backup.view", {"id": bid})
        return core.backup_get(bid)

    # ------------------------------------------------------------------ incidents
    @app.post("/api/incidents/{iid}/ack")
    def ack(iid: ID, u: dict = Depends(operator)):
        if core.db.x("UPDATE incidents SET ack_by=? WHERE id=?", (u["username"], iid)) != 1:
            raise KeyError("incident")
        core.audit.log(u["username"], "incident.ack", {"id": iid})
        return {"ok": True}

    # ------------------------------------------------------------------ AI
    @app.post("/api/ai/chat")
    def chat(b: ChatIn, u: dict = Depends(viewer)):
        return agent.chat(u, b.message)

    # ------------------------------------------------------------------ changes
    @app.get("/api/changes")
    def changes(_: dict = Depends(viewer)):
        return core.changes()

    @app.get("/api/changes/{cid}")
    def change(cid: ID, _: dict = Depends(viewer)):
        return core.change(cid)

    @app.post("/api/changes")
    def propose(b: ChangeIn, u: dict = Depends(operator)):
        if b.acknowledge_blast_radius and ROLES[u["role"]] < ROLES["admin"]:
            raise HTTPException(403, "only admins may acknowledge blast radius")
        cid = core.propose_change(u["username"], b.op, b.params, b.device_ids, "api", b.summary, b.acknowledge_blast_radius)
        return {"id": cid}

    @app.post("/api/changes/{cid}/approve")
    def approve(cid: ID, u: dict = Depends(admin)):
        core.decide(cid, u["username"], True)
        return core.change(cid)

    @app.post("/api/changes/{cid}/reject")
    def reject(cid: ID, u: dict = Depends(admin)):
        core.decide(cid, u["username"], False)
        return core.change(cid)

    @app.post("/api/changes/{cid}/execute")
    def execute(cid: ID, u: dict = Depends(admin)):
        return core.execute(cid, u["username"])

    @app.post("/api/changes/{cid}/rollback")
    def rollback(cid: ID, u: dict = Depends(admin)):
        return core.rollback_change(cid, u["username"])

    # ------------------------------------------------------------------ audit
    @app.get("/api/audit")
    def audit(limit: int = 200, _: dict = Depends(admin)):
        limit = max(1, min(limit, 1000))
        return core.db.q("SELECT id,ts,actor,action,detail FROM audit ORDER BY id DESC LIMIT ?", (limit,))

    @app.get("/api/audit/verify")
    def audit_verify(_: dict = Depends(admin)):
        return core.audit.verify()

    # ------------------------------------------------------------------ demo lab faults
    @app.post("/api/lab/fault")
    def fault(b: FaultIn, u: dict = Depends(admin)):
        if not s.demo:
            raise HTTPException(404, "not found")
        if b.device not in labmod.LAB:
            raise KeyError("device")
        if b.action == "power_off": labmod.set_power(b.device, False)
        elif b.action == "power_on": labmod.set_power(b.device, True)
        elif b.action == "cpu": labmod.set_cpu(b.device, max(0, min(100, b.value)))
        else:
            labmod.link_fault(b.device, V.iface(b.interface), b.action == "link_down")
        core.audit.log(u["username"], "lab.fault", b.model_dump())
        core.poll_all()
        return {"ok": True}

    # ------------------------------------------------------------------ UI
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(os.path.join(STATIC, "index.html"), headers={"Cache-Control": "no-cache"})

    app.mount("/assets", StaticFiles(directory=STATIC), name="assets")
    return app


def _bootstrap(core: Core, s: Settings):
    if core.db.one("SELECT 1 FROM users LIMIT 1"):
        return
    pw = s.admin_password or secrets.token_urlsafe(18) + "Aa1!"
    core.auth.create_user("admin", pw, "admin")
    if not s.admin_password:
        path = os.path.join(s.data_dir, "initial_admin_password.txt")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pw + "\n")
        print(f"[OpenNetControl] First start: admin password written to {path} (delete it after first login)")
    if s.demo:
        for name, role in (("operator", "operator"), ("viewer", "viewer")):
            p = os.environ.get(f"ONC_DEMO_{name.upper()}_PASSWORD") or secrets.token_urlsafe(14) + "Aa1!"
            core.auth.create_user(name, p, role)
            if not os.environ.get(f"ONC_DEMO_{name.upper()}_PASSWORD"):
                path = os.path.join(s.data_dir, f"initial_{name}_password.txt")
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(p + "\n")
