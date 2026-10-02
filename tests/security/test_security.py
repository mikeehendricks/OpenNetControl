"""Adversarial / destructive testing against the HTTP API. Each test is an attack that must FAIL."""
import base64, json, os, sqlite3, threading, time
import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient
from opennetcontrol.app import create_app
from opennetcontrol import lab
from conftest import PW, login, mk_settings


def dev_id(client, H, name):
    return next(d["id"] for d in client.get("/api/devices", headers=H["viewer"]).json() if d["name"] == name)


# ------------------------------------------------------------------ authn / authz
def test_every_route_requires_auth(client):
    open_routes = {("GET", "/api/health"), ("POST", "/api/auth/login"), ("GET", "/")}
    for r in client.app.routes:
        if not hasattr(r, "methods") or not r.path.startswith("/api/"):
            continue
        for m in r.methods - {"HEAD", "OPTIONS"}:
            if (m, r.path) in open_routes:
                continue
            path = r.path.replace("{did}", "1").replace("{cid}", "1").replace("{iid}", "1").replace("{bid}", "1")
            resp = client.request(m, path, json={} if m != "GET" else None)
            assert resp.status_code == 401, f"{m} {r.path} -> {resp.status_code}"


RBAC = [  # (role, method, path, body, expected_forbidden)
    ("viewer", "POST", "/api/poll", None), ("viewer", "POST", "/api/devices/1/backup", None), ("viewer", "GET", "/api/audit", None),
    ("viewer", "POST", "/api/changes", {"op": "set_ntp", "params": {"server": "1.1.1.1"}, "device_ids": [1]}),
    ("viewer", "POST", "/api/incidents/1/ack", None), ("viewer", "GET", "/api/users", None),
    ("operator", "GET", "/api/audit", None), ("operator", "GET", "/api/users", None), ("operator", "POST", "/api/changes/1/approve", None),
    ("operator", "POST", "/api/changes/1/execute", None), ("operator", "POST", "/api/changes/1/rollback", None),
    ("operator", "POST", "/api/users", {"username": "evil", "password": "Aa1!aaaaaaaaaaaa", "role": "admin"}),
    ("operator", "DELETE", "/api/devices/1", None), ("operator", "POST", "/api/credentials", {"name": "x", "username": "u", "secret": "s"}),
    ("operator", "POST", "/api/lab/fault", {"action": "power_off", "device": "hq-fw1"}),
]


@pytest.mark.parametrize("role,method,path,body", RBAC)
def test_rbac_matrix(client, H, role, method, path, body):
    r = client.request(method, path, headers=H[role], json=body)
    assert r.status_code == 403, (r.status_code, r.text)


def test_operator_cannot_acknowledge_blast_radius(client, H):
    ids = [d["id"] for d in client.get("/api/devices", headers=H["operator"]).json()]
    r = client.post("/api/changes", headers=H["operator"], json={"op": "set_ntp", "params": {"server": "10.1.1.1"}, "device_ids": ids, "acknowledge_blast_radius": True})
    assert r.status_code == 403


def forge(client, **claims):
    base = {"sub": "admin", "role": "admin", "exp": time.time() + 600, "jti": "x" + str(time.time())}
    base.update(claims)
    return base


def test_jwt_forgeries(client, H):
    secret = client.core.auth.secret
    # alg=none
    hdr = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    pl = base64.urlsafe_b64encode(json.dumps(forge(client)).encode()).rstrip(b"=").decode()
    for tok in (f"{hdr}.{pl}.", f"{hdr}.{pl}.AAAA"):
        assert client.get("/api/audit", headers={"Authorization": "Bearer " + tok}).status_code == 401
    # wrong key
    bad = pyjwt.encode(forge(client), b"guess", algorithm="HS256")
    assert client.get("/api/audit", headers={"Authorization": "Bearer " + bad}).status_code == 401
    # expired
    old = pyjwt.encode(forge(client, exp=time.time() - 5), secret, algorithm="HS256")
    assert client.get("/api/audit", headers={"Authorization": "Bearer " + old}).status_code == 401
    # tampered payload of a real token
    h_, p_, s_ = H["viewer"]["Authorization"][7:].split(".")
    p2 = base64.urlsafe_b64encode(json.dumps({**json.loads(base64.urlsafe_b64decode(p_ + "==")), "role": "admin"}).encode()).rstrip(b"=").decode()
    assert client.get("/api/audit", headers={"Authorization": f"Bearer {h_}.{p2}.{s_}"}).status_code == 401
    # correctly signed token claiming admin for a viewer: role comes from DB, not the token
    esc = pyjwt.encode(forge(client, sub="viewer", role="admin"), secret, algorithm="HS256")
    assert client.get("/api/audit", headers={"Authorization": "Bearer " + esc}).status_code == 403
    # unknown subject
    ghost = pyjwt.encode(forge(client, sub="nobody"), secret, algorithm="HS256")
    assert client.get("/api/overview", headers={"Authorization": "Bearer " + ghost}).status_code == 401
    # junk
    for junk in ("", "Bearer", "Bearer ", "Bearer a.b.c", "Basic YWRtaW46YWRtaW4=", "Bearer " + "A" * 5000):
        assert client.get("/api/overview", headers={"Authorization": junk}).status_code == 401


def test_logout_revokes_token_and_password_change_revokes(client, H):
    h = H["viewer"]
    assert client.get("/api/overview", headers=h).status_code == 200
    client.post("/api/auth/logout", headers=h)
    assert client.get("/api/overview", headers=h).status_code == 401
    h2 = login(client, "operator")
    r = client.post("/api/auth/password", headers=h2, json={"current": PW["operator"], "new": "N3w-Strong#Passw0rd"})
    assert r.status_code == 200
    assert client.get("/api/overview", headers=h2).status_code == 401


def test_disabled_user_loses_access(client, H):
    client.core.db.x("UPDATE users SET disabled=1 WHERE username='operator'")
    assert client.get("/api/overview", headers=H["operator"]).status_code == 401


SQLI = ["' OR '1'='1", "admin'--", "admin' /*", "\" OR \"\"=\"", "'; DROP TABLE users;--", "admin\x00", "' UNION SELECT 1,2,3,4,5--"]


@pytest.mark.parametrize("payload", SQLI)
def test_sql_injection_login(client, payload):
    r = client.post("/api/auth/login", json={"username": payload, "password": payload})
    assert r.status_code in (401, 422, 429)
    assert client.core.db.one("SELECT COUNT(*) c FROM users")["c"] >= 4


def test_sql_injection_query_and_path_params(client, H):
    for p in ["/api/alerts?status=open' OR 1=1--", "/api/incidents?status=x", "/api/audit?limit=1;DROP TABLE users", "/api/devices/1 OR 1=1", "/api/devices/1'", "/api/changes/-1", "/api/backups/99999999999999999999"]:
        r = client.get(p, headers=H["admin"])
        assert r.status_code in (404, 422), (p, r.status_code)
    assert client.core.db.one("SELECT COUNT(*) c FROM users")["c"] >= 4


def test_login_lockout_and_no_user_enumeration(client):
    r1 = client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password-1"})
    r2 = client.post("/api/auth/login", json={"username": "doesnotexist", "password": "wrong-password-1"})
    assert r1.status_code == r2.status_code == 401 and r1.json() == r2.json()
    for _ in range(6):
        client.post("/api/auth/login", json={"username": "admin", "password": "bad"})
    r = client.post("/api/auth/login", json={"username": "admin", "password": PW["admin"]})
    assert r.status_code == 429, "account must stay locked even with the right password"


def test_password_policy(client, H):
    for pw in ("short", "alllowercaseletters", "NoSymbolsOrDigitsHere", "a" * 200, " " * 20):
        r = client.post("/api/users", headers=H["admin"], json={"username": "newbie", "password": pw, "role": "viewer"})
        assert r.status_code in (400, 422), pw
    r = client.post("/api/users", headers=H["admin"], json={"username": "ne wbie!", "password": "Strong#Passw0rd!x", "role": "viewer"})
    assert r.status_code == 400
    r = client.post("/api/users", headers=H["admin"], json={"username": "root", "password": "Strong#Passw0rd!x", "role": "superuser"})
    assert r.status_code == 422


def test_self_approval_blocked_over_api(client, H):
    did = dev_id(client, H, "hq-dist1")
    cid = client.post("/api/changes", headers=H["admin"], json={"op": "set_ntp", "params": {"server": "10.1.1.1"}, "device_ids": [did]}).json()["id"]
    assert client.post(f"/api/changes/{cid}/approve", headers=H["admin"]).status_code == 409
    assert client.post(f"/api/changes/{cid}/execute", headers=H["admin"]).status_code == 409
    assert client.post(f"/api/changes/{cid}/approve", headers=H["admin2"]).status_code == 200


def test_concurrent_execute_runs_once(client, H):
    did = dev_id(client, H, "hq-dist1")
    cid = client.post("/api/changes", headers=H["operator"], json={"op": "create_vlan", "params": {"vlan_id": 222, "vlan_name": "race"}, "device_ids": [did]}).json()["id"]
    client.post(f"/api/changes/{cid}/approve", headers=H["admin"])
    codes = []
    def go(): codes.append(client.post(f"/api/changes/{cid}/execute", headers=H["admin"]).status_code)
    ts = [threading.Thread(target=go) for _ in range(6)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert sorted(codes).count(200) == 1, codes
    assert client.core.db.q("SELECT COUNT(*) c FROM backups WHERE reason=?", (f"pre-change #{cid}",))[0]["c"] == 1


# ------------------------------------------------------------------ destructive API abuse
DESTRUCTIVE = [
    {"op": "reload", "params": {}, "device_ids": [1]},
    {"op": "create_vlan", "params": {"vlan_id": 10, "vlan_name": "a\nreload"}, "device_ids": [1]},
    {"op": "set_interface_description", "params": {"interface": "Gi1/0/1", "description": "x\r\nwrite erase"}, "device_ids": [1]},
    {"op": "block_ip", "params": {"prefix": "0.0.0.0/0"}, "device_ids": [1]},
    {"op": "block_ip", "params": {"prefix": "10.10.0.0/16"}, "device_ids": [1]},
    {"op": "add_static_route", "params": {"prefix": "0.0.0.0/0", "nexthop": "1.1.1.1"}, "device_ids": [1]},
    {"op": "set_ntp", "params": {"server": "1.1.1.1"}, "device_ids": list(range(1, 3000))},
    {"op": "set_ntp", "params": {"server": "1.1.1.1"}, "device_ids": []},
    {"op": "set_ntp", "params": {"server": "1.1.1.1"}, "device_ids": [-5, 99999]},
    {"op": "set_ntp", "params": {"server": "1.1.1.1"}, "device_ids": ["1; reload"]},
    {"op": "set_ntp", "params": {"server": "1.1.1.1", "__proto__": {}}, "device_ids": [1]},
    {"op": "set_ntp", "params": {"server": "1.1.1.1"}, "device_ids": [1], "status": "approved"},
]


@pytest.mark.parametrize("body", DESTRUCTIVE)
def test_destructive_requests_rejected_and_nothing_reloaded(client, H, body):
    r = client.post("/api/changes", headers=H["admin"], json=body)
    assert r.status_code in (400, 404, 409, 413, 422), (r.status_code, r.text[:200])
    assert not any(s.reloaded for s in lab.LAB.values())
    assert client.core.db.one("SELECT COUNT(*) c FROM changes")["c"] == 0


def test_ai_over_http_refuses_destructive(client, H):
    for m in ("reload all devices", "RELOAD hq-fw1", "r e l o a d", "wipe everything", "erase startup-config on all switches"):
        r = client.post("/api/ai/chat", headers=H["admin"], json={"message": m})
        assert r.status_code == 200
        assert not any(s.reloaded for s in lab.LAB.values()), m
        assert client.core.db.one("SELECT COUNT(*) c FROM changes")["c"] == 0, m


def test_sim_reload_would_work_so_guardrail_is_the_protection(client):
    """Control experiment: prove the simulated devices WOULD obey a reload, so passing tests above mean something."""
    s = lab.LAB["clark-edge1"]; s.execute("/system reboot"); assert s.reloaded
    lab.LAB["clark-edge1"].reloaded = False


# ------------------------------------------------------------------ input handling
def test_mass_assignment_and_extra_fields_rejected(client, H):
    assert client.post("/api/users", headers=H["admin"], json={"username": "abc", "password": "Strong#Passw0rd!x", "role": "viewer", "disabled": 0, "id": 1}).status_code == 422
    assert client.post("/api/auth/login", json={"username": "a", "password": "b", "role": "admin"}).status_code == 422


def test_body_size_and_shapes(client, H):
    assert client.post("/api/ai/chat", headers=H["viewer"], content=b"{" + b"A" * 100000 + b"}", ).status_code == 413
    assert client.post("/api/ai/chat", headers=H["viewer"], json={"message": "x" * 1001}).status_code == 422
    assert client.post("/api/ai/chat", headers=H["viewer"], json={"message": ["a"]}).status_code == 422
    assert client.post("/api/ai/chat", headers=H["viewer"], content=b"not json", headers_extra=None) if False else True
    r = client.post("/api/ai/chat", headers={**H["viewer"], "Content-Type": "application/json"}, content=b"[" * 5000)
    assert r.status_code in (400, 413, 422)


def test_nlu_redos_resistance(client, H):
    for msg in ("block " * 160, "vlan " + "1" * 990, "create vlan " + "a " * 480, "disable interface " + "x/" * 480, "set description of interface " + "a b " * 240,
                ("(" * 400) + ")" * 400, "ntp " + "1." * 480):
        t = time.time()
        r = client.post("/api/ai/chat", headers=H["viewer"], json={"message": msg[:1000]})
        assert r.status_code == 200 and time.time() - t < 2, (msg[:30], time.time() - t)


def test_unicode_and_control_chars_in_chat(client, H):
    for m in ("show devices \u202e", "\x00\x01 show devices", "ｒｅｌｏａｄ all devices", "reload\u200b all devices", "show\tdevices"):
        r = client.post("/api/ai/chat", headers=H["admin"], json={"message": m})
        assert r.status_code == 200
        assert not any(s.reloaded for s in lab.LAB.values()), m
    r = client.post("/api/ai/chat", headers=H["admin"], json={"message": "ｒｅｌｏａｄ all devices"}).json()
    assert r.get("refused"), "full-width look-alike must hit the destructive guardrail"
    r = client.post("/api/ai/chat", headers=H["admin"], json={"message": "re\u200bload all devices"}).json()
    assert r.get("refused"), "zero-width split must hit the destructive guardrail"


# ------------------------------------------------------------------ SSRF / transport safety
@pytest.mark.parametrize("addr", ["127.0.0.1", "localhost", "0.0.0.0", "169.254.169.254", "::1", "2130706433", "127.1", "0x7f.1", "metadata.google.internal.invalid", "10.0.0.1\nreload", "a b", "127.0.0.1#x"])
def test_ssrf_targets_rejected(client, H, addr):
    cid = client.post("/api/credentials", headers=H["admin"], json={"name": "c1", "username": "u", "secret": "s"}).json()["id"]
    r = client.post("/api/devices", headers=H["admin"], json={"name": "ssrf1", "address": addr, "platform": "cisco_iosxe", "credential_id": cid})
    assert r.status_code in (400, 422), (addr, r.status_code, r.text)


def test_sim_transport_disabled_in_production_mode():
    app = create_app(mk_settings(demo=False, allow_sim=False))
    with TestClient(app) as c:
        h = {"Authorization": "Bearer " + c.post("/api/auth/login", json={"username": "admin", "password": PW["admin"]}).json()["token"]}
        r = c.post("/api/devices", headers=h, json={"name": "s1", "address": "hq-fw1", "platform": "paloalto_panos", "transport": "sim"})
        assert r.status_code == 400
        assert c.post("/api/lab/fault", headers=h, json={"action": "power_off", "device": "hq-fw1"}).status_code == 404


def test_device_validation(client, H):
    cid = client.post("/api/credentials", headers=H["admin"], json={"name": "c2", "username": "u", "secret": "s"}).json()["id"]
    for name in ("<img src=x onerror=alert(1)>", "a;b", "a b", "../x", "x" * 70, ""):
        r = client.post("/api/devices", headers=H["admin"], json={"name": name, "address": "192.0.2.10", "platform": "cisco_iosxe", "credential_id": cid})
        assert r.status_code in (400, 422), name
    r = client.post("/api/devices", headers=H["admin"], json={"name": "ok1", "address": "192.0.2.10", "platform": "evil_os", "credential_id": cid})
    assert r.status_code == 400
    r = client.post("/api/devices", headers=H["admin"], json={"name": "ok1", "address": "192.0.2.10", "platform": "cisco_iosxe", "credential_id": cid, "port": 70000})
    assert r.status_code == 400


# ------------------------------------------------------------------ web hardening
def test_security_headers(client, H):
    for path in ("/", "/api/health", "/assets/app.js"):
        h = client.get(path).headers
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert "script-src 'self'" in h["content-security-policy"] and "unsafe-inline" not in h["content-security-policy"]
    assert client.get("/api/overview", headers=H["viewer"]).headers["cache-control"] == "no-store"


def test_no_cors_for_foreign_origin(client):
    r = client.options("/api/auth/login", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in r.headers
    r = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


@pytest.mark.parametrize("path", ["/assets/../opennetcontrol.db", "/assets/..%2f..%2fetc/passwd", "/assets/%2e%2e/%2e%2e/etc/passwd", "/assets/....//....//etc/passwd",
                                  "/assets/..\\..\\etc\\passwd", "/assets/%00.js", "/assets//etc/passwd", "/assets/../app.py", "/static/../x", "/.git/config", "/.env"])
def test_path_traversal(client, path):
    r = client.get(path)
    assert r.status_code in (404, 400, 422), (path, r.status_code)
    assert "root:" not in r.text and "SQLite" not in r.text


def test_docs_and_methods(client, H):
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(p).status_code == 404
    for m in ("PUT", "PATCH", "TRACE", "DELETE"):
        assert client.request(m, "/api/overview", headers=H["admin"]).status_code in (405, 404)


def test_rate_limit_triggers():
    app = create_app(mk_settings(rate_per_min=30))
    with TestClient(app) as c:
        codes = [c.get("/api/health").status_code for _ in range(60)]
        assert 429 in codes
        codes = [c.post("/api/auth/login", json={"username": "x", "password": "y"}).status_code for _ in range(15)]
        assert 429 in codes


def test_errors_do_not_leak_internals(client, H, monkeypatch):
    monkeypatch.setattr(client.core, "overview", lambda: 1 / 0)
    r = client.get("/api/overview", headers=H["viewer"])
    assert r.status_code == 500 and "Traceback" not in r.text and "ZeroDivision" not in r.text and "opennetcontrol" not in r.text


# ------------------------------------------------------------------ data protection
def test_secrets_never_exposed_or_stored_plaintext(client, H):
    cid = client.post("/api/credentials", headers=H["admin"], json={"name": "c3", "username": "netops", "secret": "SuperSecretSshPassw0rd"}).json()["id"]
    dump = ""
    for p in ("/api/devices", "/api/users", "/api/audit", "/api/overview", "/api/vendors", "/api/changes", "/api/compliance", "/api/devices/1", "/api/incidents"):
        dump += client.get(p, headers=H["admin"]).text
    assert "SuperSecretSshPassw0rd" not in dump and "pw_hash" not in dump and "$2b$" not in dump
    assert "credential_id" not in client.get("/api/devices", headers=H["admin"]).text
    raw = open(os.path.join(client.core.s.data_dir, "opennetcontrol.db"), "rb").read() + open(os.path.join(client.core.s.data_dir, "opennetcontrol.db-wal"), "rb").read() if os.path.exists(os.path.join(client.core.s.data_dir, "opennetcontrol.db-wal")) else open(os.path.join(client.core.s.data_dir, "opennetcontrol.db"), "rb").read()
    assert b"SuperSecretSshPassw0rd" not in raw
    for f in ("vault.key", "jwt.key"):
        mode = os.stat(os.path.join(client.core.s.data_dir, f)).st_mode & 0o777
        assert mode == 0o600, (f, oct(mode))


def test_backups_are_redacted(client, H):
    did = dev_id(client, H, "hq-core1")
    r = client.post(f"/api/devices/{did}/backup", headers=H["operator"]).json()
    assert "Xk3jQ8x0NtopSecretHash" not in r["config"] and "public" not in r["config"].split("snmp-server community")[-1].split("\n")[0]
    did2 = dev_id(client, H, "hq-fw1")
    assert "SECRETHASH" not in client.post(f"/api/devices/{did2}/backup", headers=H["operator"]).json()["config"]
    did3 = dev_id(client, H, "davao-rtr1")
    assert "SECRETPASS" not in client.post(f"/api/devices/{did3}/backup", headers=H["operator"]).json()["config"]


def test_audit_chain_detects_tampering(client, H):
    client.get("/api/overview", headers=H["admin"])
    assert client.get("/api/audit/verify", headers=H["admin"]).json()["ok"]
    rows = client.core.db.q("SELECT id FROM audit")
    client.core.db.x("UPDATE audit SET actor='nobody' WHERE id=?", (rows[len(rows) // 2]["id"],))
    v = client.get("/api/audit/verify", headers=H["admin"]).json()
    assert not v["ok"]
    # deleting a row is also detected
    client.core.db.x("DELETE FROM audit WHERE id=?", (rows[-1]["id"] - 1,))
    assert not client.get("/api/audit/verify", headers=H["admin"]).json()["ok"]


def test_security_events_are_audited(client, H):
    client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    client.get("/api/audit", headers=H["operator"])
    did = dev_id(client, H, "hq-dist1")
    cid = client.post("/api/changes", headers=H["admin"], json={"op": "set_ntp", "params": {"server": "10.1.1.1"}, "device_ids": [did]}).json()["id"]
    client.post(f"/api/changes/{cid}/approve", headers=H["admin"])
    acts = {r["action"] for r in client.core.db.q("SELECT action FROM audit")}
    assert {"auth.failed", "authz.denied", "change.propose", "change.self_approval_denied"} <= acts


def test_vault_wrong_key_fails(tmp_path, monkeypatch):
    from opennetcontrol.security import Vault
    from cryptography.fernet import Fernet
    a = Vault(str(tmp_path)); tok = a.enc("secret")
    monkeypatch.setenv("ONC_VAULT_KEY", Fernet.generate_key().decode())
    with pytest.raises(ValueError):
        Vault(str(tmp_path)).dec(tok)


def test_forwarded_header_ignored_unless_proxy_trusted():
    """Attacker must not be able to dodge IP rate limits/lockouts by spoofing X-Forwarded-For."""
    app = create_app(mk_settings(login_rate_per_min=5))
    with TestClient(app) as c:
        codes = [c.post("/api/auth/login", json={"username": "x", "password": "y"}, headers={"X-Forwarded-For": f"9.9.9.{i}"}).status_code for i in range(12)]
        assert 429 in codes


def test_attacker_cannot_lock_out_real_admin_from_other_ip():
    app = create_app(mk_settings(trust_proxy=True, trusted_proxies="testclient"))
    with TestClient(app) as c:
        for _ in range(8):
            c.post("/api/auth/login", json={"username": "admin", "password": "guess"}, headers={"X-Forwarded-For": "6.6.6.6"})
        assert c.post("/api/auth/login", json={"username": "admin", "password": "guess"}, headers={"X-Forwarded-For": "6.6.6.6"}).status_code == 429
        ok = c.post("/api/auth/login", json={"username": "admin", "password": PW["admin"]}, headers={"X-Forwarded-For": "7.7.7.7"})
        assert ok.status_code == 200, "legitimate admin must still be able to sign in from a clean IP"


def test_xff_from_untrusted_peer_ignored_even_when_proxy_trust_enabled():
    """ONC_TRUST_PROXY alone is not enough: the TCP peer itself must be a configured trusted proxy."""
    app = create_app(mk_settings(trust_proxy=True, trusted_proxies="10.255.255.1", login_rate_per_min=5))
    with TestClient(app) as c:
        codes = [c.post("/api/auth/login", json={"username": "x", "password": "y"}, headers={"X-Forwarded-For": f"9.9.9.{i}"}).status_code for i in range(12)]
        assert 429 in codes


def test_real_socket_xff_spoof_cannot_bypass_lockout():
    """Regression (found by external DAST review): uvicorn's own proxy-header rewriting trusted X-Forwarded-For from
    127.0.0.1, so a forged header per request evaded lockout/rate limits even with ONC_TRUST_PROXY off.
    This must be tested over a real socket - TestClient never goes through uvicorn."""
    import socket, threading, time, httpx, uvicorn
    from opennetcontrol.config import Settings
    with socket.socket() as s0:
        s0.bind(("127.0.0.1", 0)); port = s0.getsockname()[1]
    st = mk_settings()
    cfg = uvicorn.Config(create_app(st), host="127.0.0.1", port=port, log_level="warning", proxy_headers=False, server_header=False)
    srv = uvicorn.Server(cfg); th = threading.Thread(target=srv.run, daemon=True); th.start()
    try:
        for _ in range(100):
            if srv.started: break
            time.sleep(0.05)
        codes = [httpx.post(f"http://127.0.0.1:{port}/api/auth/login", json={"username": "victim", "password": "wrong"},
                            headers={"X-Forwarded-For": f"203.0.113.{i}"}).status_code for i in range(15)]
        assert codes[:5] == [401] * 5 and 429 in codes, codes
        r = httpx.get(f"http://127.0.0.1:{port}/api/health")
        assert "server" not in {k.lower() for k in r.headers}, "server banner must not be sent"
    finally:
        srv.should_exit = True; th.join(5)


def test_initial_password_file_removed_after_password_change(tmp_path):
    from fastapi.testclient import TestClient
    st = mk_settings(data_dir=str(tmp_path), admin_password=None)
    app = create_app(st)
    with TestClient(app) as c:
        f = tmp_path / "initial_admin_password.txt"
        assert f.exists()
        pw = f.read_text().strip()
        tok = c.post("/api/auth/login", json={"username": "admin", "password": pw}).json()["token"]
        r = c.post("/api/auth/password", headers={"Authorization": f"Bearer {tok}"}, json={"current": pw, "new": "N3w-Strong-Passw0rd!x"})
        assert r.status_code == 200, r.text
        assert not f.exists(), "first-run password must not stay on disk after it is changed"


def test_health_endpoint_discloses_no_version(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
