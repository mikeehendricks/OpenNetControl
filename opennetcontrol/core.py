"""Platform core: inventory, polling, alerting + correlation, topology, compliance, change control."""
from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import validation as V
from .config import Settings
from .db import DB, now, jdump
from .drivers import get_driver, VENDORS, DRIVERS
from .models import Facts, Iface, Neighbor, DriverError, ApplyError, UnsupportedOperation
from .ops import OPS, validate_op
from .policy import check_lines, check_op, canon_if, PolicyViolation
from .security import Auth, Audit, Vault, RateLimiter, redact_config
from .transport import SSHSession, SimSession, HostKeyMismatch
from . import lab as labmod


class ChangeError(Exception):
    pass


def facts_from_dict(d: dict) -> Facts:
    f = Facts()
    for k, v in d.items():
        if k == "interfaces":
            f.interfaces = [Iface(**i) for i in v]
        elif k == "neighbors":
            f.neighbors = [Neighbor(**n) for n in v]
        elif k == "vlans":
            f.vlans = {int(a): b for a, b in v.items()}
        elif hasattr(f, k):
            setattr(f, k, v)
    return f


def _vtuple(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


class Core:
    def __init__(self, settings: Settings):
        import os
        self.s = settings
        os.makedirs(settings.data_dir, exist_ok=True)
        self.db = DB(os.path.join(settings.data_dir, "opennetcontrol.db"))
        self.vault = Vault(settings.data_dir)
        self.auth = Auth(self.db, settings.data_dir, settings)
        self.audit = Audit(self.db)
        self.rl = RateLimiter(settings.rate_per_min)
        self.pool = ThreadPoolExecutor(max_workers=8)
        self.poll_lock = threading.Lock()
        self.exec_lock = threading.Lock()
        self._stop = threading.Event()
        self.last_poll = 0.0

    # ================================================================ inventory
    def add_credential(self, name, username, secret, actor="system") -> int:
        name = V.name(name, "credential name"); username = V.name(username, "username")
        if not isinstance(secret, str) or not 1 <= len(secret) <= 256:
            raise V.ValidationError("secret must be 1-256 chars")
        cid = self.db.x("INSERT INTO credentials(name,username,secret_enc) VALUES(?,?,?)", (name, username, self.vault.enc(secret)))
        self.audit.log(actor, "credential.create", {"name": name})
        return cid

    def add_device(self, actor, name, address, platform, site="", role=None, port=22, credential_id=None,
                   transport="ssh", tags="", protected_ifaces=None, mgmt_ip="") -> int:
        name = V.hostname(name)
        if platform not in DRIVERS:
            raise V.ValidationError(f"unsupported platform; choose one of {sorted(DRIVERS)}")
        drv = DRIVERS[platform]
        site = V.name(site, "site") if site else ""
        role = role or drv.roles[0]
        if role not in ("switch", "router", "firewall", "wireless"):
            raise V.ValidationError("invalid role")
        if transport not in ("ssh", "sim"):
            raise V.ValidationError("invalid transport")
        if transport == "sim":
            if not self.s.allow_sim:
                raise V.ValidationError("simulated devices are disabled (set ONC_ALLOW_SIM=1)")
            if address not in labmod.LAB:
                raise V.ValidationError("unknown simulated device")
        else:
            V.check_target_address(address, self.s.allow_loopback_targets)
            if credential_id is None or not self.db.one("SELECT 1 FROM credentials WHERE id=?", (credential_id,)):
                raise V.ValidationError("a valid credential_id is required for ssh devices")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise V.ValidationError("port must be 1-65535")
        tags = V.name(tags, "tags") if tags else ""
        pif = [V.iface(x) for x in (protected_ifaces or [])][:32]
        if mgmt_ip:
            mgmt_ip = V.ipv4(mgmt_ip, "mgmt_ip")
        try:
            did = self.db.x("INSERT INTO devices(name,address,port,vendor,platform,site,role,tags,transport,credential_id,protected_ifaces,mgmt_ip,created)"
                            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (name, address, port, drv.vendor, platform, site, role, tags, transport, credential_id, jdump(pif), mgmt_ip, now()))
        except Exception as e:
            if "UNIQUE" in str(e):
                raise V.ValidationError("a device with this name already exists")
            raise
        self.audit.log(actor, "device.create", {"id": did, "name": name, "platform": platform})
        return did

    def delete_device(self, actor, did):
        d = self.get_device(did)
        for t in ("snapshots", "backups"):
            self.db.x(f"DELETE FROM {t} WHERE device_id=?", (did,))
        self.db.x("DELETE FROM links WHERE a_dev=?", (did,))
        self.db.x("DELETE FROM alerts WHERE device_id=?", (did,))
        self.db.x("DELETE FROM devices WHERE id=?", (did,))
        self.audit.log(actor, "device.delete", {"id": did, "name": d["name"]})
        self.recompute_incidents()

    def get_device(self, did) -> dict:
        d = self.db.one("SELECT * FROM devices WHERE id=?", (did,))
        if not d:
            raise KeyError("device not found")
        d["protected_ifaces"] = json.loads(d["protected_ifaces"] or "[]")
        return d

    def devices(self) -> list[dict]:
        rows = self.db.q("SELECT d.*, s.ts snap_ts, s.reachable, s.facts, s.error FROM devices d LEFT JOIN snapshots s ON s.device_id=d.id ORDER BY d.site, d.name")
        out = []
        for r in rows:
            f = json.loads(r.pop("facts") or "null")
            r["protected_ifaces"] = json.loads(r["protected_ifaces"] or "[]")
            r["facts"] = f
            r["reachable"] = None if r["reachable"] is None else bool(r["reachable"])
            out.append(r)
        return out

    def device_view(self, did) -> dict:
        for d in self.devices():
            if d["id"] == did:
                d["alerts"] = self.db.q("SELECT * FROM alerts WHERE device_id=? AND status='open' ORDER BY opened DESC", (did,))
                d["capabilities"] = sorted(get_driver(d["platform"]).capabilities)
                return d
        raise KeyError("device not found")

    def protected_ips(self) -> set[str]:
        ips = set()
        for d in self.db.q("SELECT address, mgmt_ip FROM devices"):
            for x in (d["address"], d["mgmt_ip"]):
                try:
                    ipaddress.IPv4Address(x); ips.add(x)
                except ValueError:
                    pass
        ips.add(self.s.host)
        return ips

    # ================================================================ sessions
    def open_session(self, dev: dict):
        drv = get_driver(dev["platform"])
        if dev["transport"] == "sim":
            if not self.s.allow_sim:
                raise DriverError("simulation disabled")
            sim = labmod.LAB.get(dev["address"])
            if sim is None:
                raise DriverError("simulated device missing")
            ses = SimSession(sim)
        else:
            cred = self.db.one("SELECT * FROM credentials WHERE id=?", (dev["credential_id"],))
            if not cred:
                raise DriverError("credential missing")
            ses = SSHSession(dev["address"], dev["port"], cred["username"], self.vault.dec(cred["secret_enc"]), drv.prompt_re,
                             pinned_key=dev["host_key"], allow_loopback=self.s.allow_loopback_targets)
            if not dev["host_key"] and ses.host_key:
                self.db.x("UPDATE devices SET host_key=? WHERE id=? AND host_key IS NULL", (ses.host_key, dev["id"]))
                self.audit.log("system", "device.hostkey_pinned", {"device": dev["name"], "fp": ses.host_key})
        try:
            for c in drv.paging:
                ses.run(c)
        except Exception:
            ses.close(); raise
        return ses

    # ================================================================ polling / alerts
    def poll_device(self, did) -> dict:
        dev = self.get_device(did)
        drv = get_driver(dev["platform"])
        facts, err = None, ""
        try:
            with self.open_session(dev) as ses:
                facts = drv.collect(ses)
        except HostKeyMismatch as e:
            err = f"HOSTKEY: {e}"
        except DriverError as e:
            err = str(e)
        except Exception as e:  # parser bug etc. must not kill the poller
            err = f"collector error: {type(e).__name__}: {str(e)[:120]}"
        self.db.x("INSERT OR REPLACE INTO snapshots(device_id,ts,reachable,facts,error) VALUES(?,?,?,?,?)",
                  (did, now(), 1 if facts else 0, jdump(facts.to_dict()) if facts else None, err))
        if facts:
            for n in facts.neighbors:
                self.db.x("INSERT OR REPLACE INTO links VALUES(?,?,?,?,?)", (did, n.local_if, n.remote_host, n.remote_if, now()))
        self._evaluate(dev, facts, err)
        return {"id": did, "reachable": bool(facts), "error": err}

    def poll_all(self) -> list[dict]:
        if not self.poll_lock.acquire(blocking=False):
            return []
        try:
            ids = [d["id"] for d in self.db.q("SELECT id FROM devices")]
            res = list(self.pool.map(self.poll_device, ids))
            self.recompute_incidents()
            self.last_poll = time.time()
            return res
        finally:
            self.poll_lock.release()

    def _wanted_alerts(self, dev, facts: Facts | None, err: str):
        want = {}
        if facts is None:
            kind = "hostkey_changed" if err.startswith("HOSTKEY") else "device_unreachable"
            want[(kind, "")] = ("critical", f"{dev['name']} {'SSH host key changed (possible MITM)' if kind == 'hostkey_changed' else 'is unreachable'}: {err[:100]}")
            return want
        hist = {canon_if(r["a_if"]) for r in self.db.q("SELECT a_if FROM links WHERE a_dev=?", (dev["id"],))}
        for i in facts.interfaces:
            if i.admin_up and not i.oper_up and (i.description or canon_if(i.name) in hist) and not re.match(r"(?i)^(vlan|loopback|bridge|tunnel)", i.name):
                want[("interface_down", i.name)] = ("high", f"Interface {i.name} is down on {dev['name']}" + (f" ({i.description})" if i.description else ""))
        if facts.cpu_pct >= 85:
            want[("high_cpu", "")] = ("critical" if facts.cpu_pct >= 95 else "high", f"CPU at {facts.cpu_pct:.0f}% on {dev['name']}")
        if facts.mem_pct >= 90:
            want[("high_memory", "")] = ("high", f"Memory at {facts.mem_pct:.0f}% on {dev['name']}")
        return want

    def _evaluate(self, dev, facts, err):
        want = self._wanted_alerts(dev, facts, err)
        open_ = {(a["kind"], a["key"]): a for a in self.db.q("SELECT * FROM alerts WHERE device_id=? AND status='open'", (dev["id"],))}
        for k, (sev, msg) in want.items():
            if k in open_:
                self.db.x("UPDATE alerts SET message=?, severity=? WHERE id=?", (msg, sev, open_[k]["id"]))
            else:
                self.db.x("INSERT INTO alerts(device_id,kind,key,severity,message,opened,status) VALUES(?,?,?,?,?,?, 'open')",
                          (dev["id"], k[0], k[1], sev, msg, now()))
        for k, a in open_.items():
            if k not in want:
                self.db.x("UPDATE alerts SET status='resolved', closed=? WHERE id=?", (now(), a["id"]))

    def recompute_incidents(self):
        alerts = self.db.q("SELECT a.*, d.name dname FROM alerts a JOIN devices d ON d.id=a.device_id WHERE a.status='open'")
        names = {d["id"]: d["name"] for d in self.db.q("SELECT id,name FROM devices")}
        idof = {v: k for k, v in names.items()}
        unreach = {a["device_id"] for a in alerts if a["kind"] in ("device_unreachable", "hostkey_changed")}
        links = self.db.q("SELECT * FROM links")
        deg: dict[int, int] = {}
        adj: dict[int, set] = {}
        for l in links:
            b = idof.get(l["b_name"])
            if b is None:
                continue
            deg[l["a_dev"]] = deg.get(l["a_dev"], 0) + 1
            deg[b] = deg.get(b, 0) + 1
            adj.setdefault(l["a_dev"], set()).add(b); adj.setdefault(b, set()).add(l["a_dev"])
        root_of: dict[int, int] = {}      # unreachable device -> root
        seen = set()
        for d in unreach:
            if d in seen:
                continue
            comp, stack = set(), [d]
            while stack:
                x = stack.pop()
                if x in comp:
                    continue
                comp.add(x); stack += [y for y in adj.get(x, ()) if y in unreach]
            seen |= comp
            root = sorted(comp, key=lambda x: (-deg.get(x, 0), names.get(x, "")))[0]
            for x in comp:
                root_of[x] = root
        groups: dict[int, list] = {}
        for a in alerts:
            r = a["device_id"]
            if r in root_of:
                r = root_of[r]
            elif a["kind"] == "interface_down":
                for l in links:
                    if l["a_dev"] == a["device_id"] and canon_if(l["a_if"]) == canon_if(a["key"]):
                        b = idof.get(l["b_name"])
                        if b in root_of:
                            r = root_of[b]
                        break
            a["root"] = r
            groups.setdefault(r, []).append(a)
        sevrank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        live = set()
        for root, items in groups.items():
            ikey = f"root:{root}"
            live.add(ikey)
            sev = max((i["severity"] for i in items), key=lambda s: sevrank.get(s, 0))
            rootdown = any(i["device_id"] == root and i["kind"] in ("device_unreachable", "hostkey_changed") for i in items)
            others = [i for i in items if not (i["device_id"] == root and i["kind"] in ("device_unreachable", "hostkey_changed"))]
            if rootdown:
                title = f"{names[root]} unreachable" + (f" - {len(others)} correlated symptom(s)" if others else "")
            else:
                title = items[0]["message"] + (f" (+{len(items)-1} more)" if len(items) > 1 else "")
            row = self.db.one("SELECT id FROM incidents WHERE ikey=?", (ikey,))
            summ = self.rca_text(root, items, rootdown)
            if row:
                self.db.x("UPDATE incidents SET title=?, severity=?, status='open', closed=NULL, summary=? WHERE id=?", (title, sev, summ, row["id"]))
                iid = row["id"]
            else:
                iid = self.db.x("INSERT INTO incidents(ikey,root_device_id,title,severity,status,opened,summary) VALUES(?,?,?,?, 'open',?,?)",
                                (ikey, root, title, sev, now(), summ))
            for i in items:
                self.db.x("UPDATE alerts SET incident_id=? WHERE id=?", (iid, i["id"]))
        for r in self.db.q("SELECT id, ikey FROM incidents WHERE status='open'"):
            if r["ikey"] not in live:
                self.db.x("UPDATE incidents SET status='resolved', closed=? WHERE id=?", (now(), r["id"]))

    def rca_text(self, root, items, rootdown) -> str:
        name = self.db.one("SELECT name FROM devices WHERE id=?", (root,))["name"]
        lines = []
        if rootdown:
            lines.append(f"Probable root cause: **{name}** has stopped responding (management plane unreachable).")
            sym = [i for i in items if i["kind"] == "interface_down"]
            if sym:
                lines.append("Correlated downstream symptoms (same failure domain):")
                lines += [f"- {i['message']}" for i in sym]
            lines.append("Suggested next steps: check power/uplink on the root device, confirm from the console, review the last change record for this device. No automated remediation is proposed for loss of reachability.")
        else:
            lines.append("No upstream failure was found; the issue is local to this device:")
            lines += [f"- {i['message']}" for i in items]
            if any(i["kind"] == "high_cpu" for i in items):
                lines.append("Suggested next steps: identify top processes, check for recent config changes, loops or flooding.")
            if any(i["kind"] == "interface_down" for i in items):
                lines.append("Suggested next steps: check the cable/optic and the remote end; the neighbor remains reachable so the fault is on the link.")
        return "\n".join(lines)

    # ================================================================ views
    def alerts(self, status="open"):
        return self.db.q("SELECT a.*, d.name device FROM alerts a JOIN devices d ON d.id=a.device_id WHERE a.status=? ORDER BY a.opened DESC LIMIT 500", (status,))

    def incidents(self, status="open"):
        rows = self.db.q("SELECT i.*, d.name root_device FROM incidents i LEFT JOIN devices d ON d.id=i.root_device_id WHERE i.status=? ORDER BY i.opened DESC LIMIT 200", (status,))
        for r in rows:
            r["alerts"] = self.db.q("SELECT a.id,a.kind,a.severity,a.message,a.opened,d.name device FROM alerts a JOIN devices d ON d.id=a.device_id WHERE a.incident_id=? AND a.status='open'", (r["id"],))
        return rows

    def topology(self):
        devs = self.devices()
        by_name = {d["name"]: d for d in devs}
        down_if = {(a["device_id"], canon_if(a["key"])) for a in self.db.q("SELECT device_id,key FROM alerts WHERE status='open' AND kind='interface_down'")}
        nodes = [{"id": d["id"], "name": d["name"], "vendor": d["vendor"], "platform": d["platform"], "role": d["role"], "site": d["site"],
                  "status": "down" if d["reachable"] is False else ("unknown" if d["reachable"] is None else "up"),
                  "alerts": len(self.db.q("SELECT 1 FROM alerts WHERE device_id=? AND status='open'", (d["id"],)))} for d in devs]
        edges, seen = [], set()
        ids = {d["name"]: d["id"] for d in devs}
        for l in self.db.q("SELECT l.*, d.name a_name FROM links l JOIN devices d ON d.id=l.a_dev"):
            if l["b_name"] not in ids:
                continue
            key = tuple(sorted((l["a_name"], l["b_name"])))
            if key in seen:
                continue
            seen.add(key)
            a, b = by_name[l["a_name"]], by_name[l["b_name"]]
            down = a["reachable"] is False or b["reachable"] is False or (l["a_dev"], canon_if(l["a_if"])) in down_if
            edges.append({"a": a["id"], "b": b["id"], "a_if": l["a_if"], "b_if": l["b_if"], "state": "down" if down else "up"})
        return {"nodes": nodes, "edges": edges}

    def overview(self):
        devs = self.devices()
        vend: dict[str, int] = {}
        for d in devs:
            vend[d["vendor"]] = vend.get(d["vendor"], 0) + 1
        comp = self.compliance()
        sev: dict[str, int] = {}
        for a in self.alerts():
            sev[a["severity"]] = sev.get(a["severity"], 0) + 1
        return {"devices": len(devs), "reachable": sum(1 for d in devs if d["reachable"]), "unreachable": sum(1 for d in devs if d["reachable"] is False),
                "vendors": vend, "open_incidents": len(self.incidents()), "alert_severity": sev,
                "compliance_findings": len(comp), "critical_findings": sum(1 for c in comp if c["severity"] == "critical"),
                "pending_changes": self.db.q("SELECT COUNT(*) c FROM changes WHERE status='pending'")[0]["c"],
                "sites": sorted({d["site"] for d in devs if d["site"]}), "last_poll": self.last_poll,
                "clients": sum((d["facts"] or {}).get("clients", 0) for d in devs if d["role"] == "wireless")}

    def compliance(self):
        mins = {}
        for kv in filter(None, self.s.min_versions.split(",")):
            if "=" in kv:
                k, v = kv.split("=", 1); mins[k.strip()] = v.strip()
        out = []
        for d in self.devices():
            f = d["facts"]
            if not f:
                continue
            def add(rule, sev, detail):
                out.append({"device_id": d["id"], "device": d["name"], "vendor": d["vendor"], "rule": rule, "severity": sev, "detail": detail})
            if f.get("telnet_enabled"):
                add("telnet_enabled", "critical", "Telnet management access is enabled (cleartext credentials). Remediation: disable_telnet.")
            if f.get("snmp_public"):
                add("snmp_default_community", "high", "SNMP community 'public' is configured.")
            if d["role"] != "wireless" and not f.get("ntp_servers") and "set_ntp" in get_driver(d["platform"]).capabilities:
                add("no_ntp", "low", "No NTP server configured; logs/certs may drift. Remediation: set_ntp.")
            mv = mins.get(d["platform"])
            if mv and _vtuple(f.get("version", "")) and _vtuple(f["version"]) < _vtuple(mv):
                add("firmware_below_baseline", "medium", f"Version {f['version']} is below the configured baseline {mv}.")
            if f.get("uptime_s", 0) and d["snap_ts"] is not None:
                last = self.db.one("SELECT MAX(ts) t FROM backups WHERE device_id=?", (d["id"],))
                if not last or not last["t"]:
                    add("no_config_backup", "low", "No configuration backup has been taken yet.")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(out, key=lambda x: (order[x["severity"]], x["device"]))

    # ================================================================ backups
    def backup(self, actor, did, reason="manual") -> dict:
        import hashlib
        dev = self.get_device(did); drv = get_driver(dev["platform"])
        with self.open_session(dev) as ses:
            cfg = drv.get_config(ses)
        sha = hashlib.sha256(cfg.encode()).hexdigest()
        bid = self.db.x("INSERT INTO backups(device_id,ts,sha,config,reason) VALUES(?,?,?,?,?)", (did, now(), sha, cfg, reason))
        self.audit.log(actor, "device.backup", {"device": dev["name"], "sha": sha[:12], "reason": reason})
        return {"id": bid, "sha": sha, "config": redact_config(cfg)}

    def backups(self, did):
        return self.db.q("SELECT id,ts,sha,reason,LENGTH(config) size FROM backups WHERE device_id=? ORDER BY ts DESC LIMIT 50", (did,))

    def backup_get(self, bid):
        b = self.db.one("SELECT * FROM backups WHERE id=?", (bid,))
        if not b:
            raise KeyError("backup not found")
        b["config"] = redact_config(b["config"])
        return b

    # ================================================================ change control
    def select_devices(self, ids: list[int]) -> list[dict]:
        out = []
        for i in ids:
            out.append(self.get_device(i))
        return out

    def propose_change(self, requester: str, op: str, params: dict, device_ids: list, source="api", summary="", force_blast=False) -> int:
        if not isinstance(device_ids, list) or not device_ids or len(device_ids) > 500:
            raise ChangeError("device_ids must be a non-empty list")
        try:
            device_ids = [int(x) for x in device_ids]
        except (TypeError, ValueError):
            raise ChangeError("device_ids must be integers")
        device_ids = list(dict.fromkeys(device_ids))
        params = validate_op(op, params)
        devs = self.select_devices(device_ids)
        prot = self.protected_ips()
        plan = []
        for d in devs:
            drv = get_driver(d["platform"])
            snap = self.db.one("SELECT facts FROM snapshots WHERE device_id=?", (d["id"],))
            facts = facts_from_dict(json.loads(snap["facts"])) if snap and snap["facts"] else None
            item = {"device_id": d["id"], "name": d["name"], "platform": d["platform"], "vendor": d["vendor"]}
            try:
                check_op(op, params, d, prot)
                lines, undo = drv.render(op, params, facts)
                if not lines:
                    raise UnsupportedOperation("nothing to do (no matching configuration on device)")
                check_lines(lines); check_lines(undo)
                item.update(lines=lines, undo=undo, status="planned")
            except UnsupportedOperation as e:
                item.update(lines=[], undo=[], status="skipped", reason=str(e))
            except PolicyViolation as e:
                item.update(lines=[], undo=[], status="blocked", reason=str(e))
            plan.append(item)
        runnable = [p for p in plan if p["status"] == "planned"]
        if not runnable:
            reasons = "; ".join(sorted({f"{p['name']}: {p.get('reason','')}" for p in plan}))[:400]
            raise ChangeError(f"no device can accept this change ({reasons})")
        if len(runnable) > self.s.max_targets and not force_blast:
            raise ChangeError(f"blast radius: {len(runnable)} devices exceeds the limit of {self.s.max_targets}; "
                              f"split the change or set acknowledge_blast_radius")
        summary = summary or f"{OPS[op]['desc']} {json.dumps(params)} on {len(runnable)} device(s)"
        cid = self.db.x("INSERT INTO changes(requester,status,source,summary,op,params,targets,plan,created,force_blast) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (requester, "pending", source, summary[:300], op, jdump(params), jdump(device_ids), jdump(plan), now(), int(force_blast)))
        self.audit.log(requester, "change.propose", {"id": cid, "op": op, "params": params, "source": source, "targets": len(runnable),
                                                     "blocked": [p["name"] for p in plan if p["status"] == "blocked"]})
        return cid

    def change(self, cid) -> dict:
        c = self.db.one("SELECT * FROM changes WHERE id=?", (cid,))
        if not c:
            raise KeyError("change not found")
        for k in ("params", "targets", "plan", "results"):
            c[k] = json.loads(c[k]) if c[k] else None
        return c

    def changes(self):
        rows = self.db.q("SELECT id,requester,approver,status,source,summary,op,created,decided,executed FROM changes ORDER BY id DESC LIMIT 200")
        return rows

    def decide(self, cid, actor, approve: bool):
        c = self.change(cid)
        if approve and self.s.four_eyes and actor == c["requester"]:
            self.audit.log(actor, "change.self_approval_denied", {"id": cid})
            raise ChangeError("four-eyes rule: requester cannot approve their own change")
        new = "approved" if approve else "rejected"
        n = self.db.x("UPDATE changes SET status=?, approver=?, decided=? WHERE id=? AND status='pending'", (new, actor, now(), cid))
        if n != 1:
            raise ChangeError(f"change is not pending (status: {c['status']})")
        self.audit.log(actor, f"change.{new}", {"id": cid})

    def execute(self, cid, actor) -> dict:
        n = self.db.x("UPDATE changes SET status='running', executed=? WHERE id=? AND status='approved'", (now(), cid))
        if n != 1:
            c = self.change(cid)
            raise ChangeError(f"change cannot be executed (status: {c['status']})")
        c = self.change(cid)
        self.audit.log(actor, "change.execute", {"id": cid})
        results, applied, failed = [], [], None
        prot = self.protected_ips()
        with self.exec_lock:
            for item in c["plan"]:
                r = {"device": item["name"], "device_id": item["device_id"], "status": item["status"]}
                if item["status"] != "planned":
                    results.append(r); continue
                if failed:
                    r["status"] = "skipped"; r["detail"] = "halted after earlier failure"; results.append(r); continue
                dev = self.get_device(item["device_id"]); drv = get_driver(dev["platform"])
                try:
                    check_lines(item["lines"]); check_lines(item["undo"]); check_op(c["op"], c["params"], dev, prot)
                    with self.open_session(dev) as ses:
                        pre = drv.collect(ses)           # must be reachable & healthy before touching it
                        cfg = drv.get_config(ses)
                        self.db.x("INSERT INTO backups(device_id,ts,sha,config,reason) VALUES(?,?,?,?,?)",
                                  (dev["id"], now(), __import__("hashlib").sha256(cfg.encode()).hexdigest(), cfg, f"pre-change #{cid}"))
                        drv.apply(ses, item["lines"])
                        post = drv.collect(ses)
                        postcfg = drv.get_config(ses)
                        if not drv.verify(c["op"], c["params"], post, postcfg):
                            raise DriverError("post-change verification failed")
                    r["status"] = "applied"; applied.append(item)
                except Exception as e:
                    failed = f"{item['name']}: {str(e)[:200]}"
                    r["status"] = "failed"; r["detail"] = str(e)[:300]
                    r["rollback"] = self._rollback_item(dev, drv, item, c)
                results.append(r)
            if failed:       # all-or-nothing: revert devices that already succeeded
                for item in applied:
                    dev = self.get_device(item["device_id"]); drv = get_driver(dev["platform"])
                    rb = self._rollback_item(dev, drv, item, c)
                    for r in results:
                        if r["device_id"] == item["device_id"]:
                            r["status"] = "rolled_back"; r["rollback"] = rb
        status = "rolled_back" if failed else "completed"
        self.db.x("UPDATE changes SET status=?, results=? WHERE id=?", (status, jdump(results), cid))
        self.audit.log(actor, f"change.{status}", {"id": cid, "failed": failed})
        self.poll_all()
        return self.change(cid)

    def _rollback_item(self, dev, drv, item, c) -> str:
        try:
            with self.open_session(dev) as ses:
                drv.apply(ses, item["undo"], ignore_errors=True)
                post = drv.collect(ses)
                ok = drv.verify(c["op"], c["params"], post, drv.get_config(ses), undo=True)
            return "reverted" if ok else "revert-unverified"
        except Exception as e:
            return f"rollback-failed: {str(e)[:100]}"

    def rollback_change(self, cid, actor) -> dict:
        n = self.db.x("UPDATE changes SET status='rolling_back' WHERE id=? AND status='completed'", (cid,))
        if n != 1:
            raise ChangeError("only completed changes can be rolled back")
        c = self.change(cid); res = []
        for item in c["plan"]:
            if item["status"] != "planned":
                continue
            dev = self.get_device(item["device_id"]); drv = get_driver(dev["platform"])
            res.append({"device": item["name"], "rollback": self._rollback_item(dev, drv, item, c)})
        self.db.x("UPDATE changes SET status='rolled_back', results=? WHERE id=?", (jdump(res), cid))
        self.audit.log(actor, "change.manual_rollback", {"id": cid, "results": res})
        self.poll_all()
        return self.change(cid)

    # ================================================================ lifecycle
    def start_poller(self):
        def loop():
            while not self._stop.wait(self.s.poll_interval):
                try:
                    self.poll_all()
                except Exception:
                    pass
        threading.Thread(target=loop, daemon=True, name="poller").start()

    def stop(self):
        self._stop.set()

    def seed_demo(self):
        specs = labmod.build_lab()
        for sp in specs:
            if self.db.one("SELECT 1 FROM devices WHERE name=?", (sp["name"],)):
                continue
            prot = ["ethernet1/2"] if sp["name"] == "hq-fw1" else []
            self.add_device("system", sp["name"], sp["address"], sp["platform"], site=sp["site"], role=sp["role"],
                            transport="sim", mgmt_ip=sp["mgmt_ip"], protected_ifaces=prot)
        # a few realistic baseline items
        for n in ("hq-core1", "hq-dist1", "hq-fw1", "cebu-sw1"):
            labmod.LAB[n].ntp.append("10.10.0.123")
        labmod.LAB["hq-fw1"].ntp = ["10.10.0.123"]
        self.poll_all()
