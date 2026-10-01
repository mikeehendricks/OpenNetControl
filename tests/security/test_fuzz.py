"""Seeded fuzzing + concurrency stress. Invariants: no 500s, no unvalidated text reaches a device, no reload ever happens."""
import random, string, threading, time
import pytest
from opennetcontrol import lab, validation as V
from opennetcontrol.ops import OPS, validate_op
from opennetcontrol.policy import check_lines, PolicyViolation
from opennetcontrol.drivers import DRIVERS

R = random.Random(1337)
ALPHABET = string.printable + "ｒｅｌｏａｄ\u202e\u200b'\"`;|&$<>\\{}[]()%\x00\x1b☃日本語"
WORDS = ["create", "vlan", "block", "ip", "on", "all", "firewalls", "disable", "interface", "shutdown", "telnet", "ssid", "named", "route", "via", "ntp",
         "server", "aruba", "fortinet", "mikrotik", "palo", "cisco", "ruckus", "10.10.0.1/16", "203.0.113.9", "0.0.0.0/0", "reload", "erase", "hq-fw1", "Guest", "Gi1/0/1", "4094", "-1", "99999999999"]


def rand_msg():
    k = R.random()
    if k < .4:
        return " ".join(R.choice(WORDS) for _ in range(R.randint(1, 14)))
    if k < .7:
        return "".join(R.choice(ALPHABET) for _ in range(R.randint(1, 300)))
    return " ".join(R.choice(WORDS) + R.choice(["", "\n", ";", "\x00", "`", "$("]) for _ in range(R.randint(1, 20)))


def test_fuzz_ai_chat_no_500_no_reload(client, H):
    from opennetcontrol.ai.agent import Agent
    agent = Agent(client.core)
    for i in range(600):
        m = rand_msg()[:1000]
        if i < 30:
            r = client.post("/api/ai/chat", headers=H["admin"], json={"message": m})
            assert r.status_code in (200, 400, 422), (r.status_code, repr(m))
        else:
            try:
                agent.chat({"username": "operator", "role": "operator"}, m)
            except V.ValidationError:
                pass
        assert not any(s.reloaded for s in lab.LAB.values()), repr(m)
    # whatever the AI proposed, every rendered line must have passed the deny-list
    for c in client.core.db.q("SELECT plan FROM changes"):
        import json
        for p in json.loads(c["plan"]):
            check_lines(p["lines"]); check_lines(p["undo"])


def test_fuzz_op_validators_never_emit_dangerous_cli():
    for _ in range(4000):
        op = R.choice(list(OPS))
        params = {k: R.choice(["".join(R.choice(ALPHABET) for _ in range(R.randint(0, 40))), R.randint(-10, 5000), None, True, [], {}, "10.0.0.0/24", "1.2.3.4", "Gi1/0/1", "x"]) for k in OPS[op]["params"]}
        try:
            clean = validate_op(op, params)
        except (V.ValidationError, Exception) as e:
            assert isinstance(e, V.ValidationError), (op, params, e)    # only clean validation errors, never crashes
            continue
        for drv in DRIVERS.values():
            if op not in drv.capabilities:
                continue
            apply, undo = drv.render(op, clean, None)
            for ln in apply + undo:
                assert "\n" not in ln and "\r" not in ln and "\x00" not in ln and "\x1b" not in ln
            try:
                check_lines(apply)
            except PolicyViolation:
                pass  # blocked is fine; what matters is it can never pass with shell metacharacters
            else:
                assert not any(ch in "".join(apply) for ch in ";|&`$<>\\"), (op, clean, apply)


def test_concurrent_api_stress_and_mixed_changes(client, H):
    errs, codes = [], []
    did = next(d["id"] for d in client.get("/api/devices", headers=H["viewer"]).json() if d["name"] == "hq-dist2")
    def reader():
        for _ in range(25):
            for p in ("/api/overview", "/api/devices", "/api/topology", "/api/incidents", "/api/compliance"):
                codes.append(client.get(p, headers=H["viewer"]).status_code)
    def poller():
        for _ in range(4): codes.append(client.post("/api/poll", headers=H["operator"]).status_code)
    def changer(n):
        for i in range(3):
            r = client.post("/api/changes", headers=H["operator"], json={"op": "create_vlan", "params": {"vlan_id": 300 + n * 10 + i, "vlan_name": f"s{n}{i}"}, "device_ids": [did]})
            codes.append(r.status_code)
            if r.status_code == 200:
                cid = r.json()["id"]
                codes.append(client.post(f"/api/changes/{cid}/approve", headers=H["admin"]).status_code)
                codes.append(client.post(f"/api/changes/{cid}/execute", headers=H["admin"]).status_code)
    ts = [threading.Thread(target=reader) for _ in range(4)] + [threading.Thread(target=poller)] + [threading.Thread(target=changer, args=(n,)) for n in range(3)]
    t0 = time.time(); [t.start() for t in ts]; [t.join() for t in ts]
    assert 500 not in codes, sorted(set(codes))
    assert time.time() - t0 < 60
    assert client.core.audit.verify()["ok"]
    sim = lab.LAB["hq-dist2"]
    created = [v for v in sim.vlans if v >= 300]
    assert len(created) == 9, created                      # every approved change applied exactly once
