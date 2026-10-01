"""The AI operations assistant. Reads fleet context through typed tools, explains incidents, and
*proposes* changes into the approval workflow. It cannot execute anything by itself."""
from __future__ import annotations

import json
import re
import unicodedata

from .. import policy, validation as V
from ..core import Core, ChangeError
from ..drivers import get_driver, VENDORS
from ..ops import OPS, validate_op
from . import nlu, llm

HELP = (
    "I can answer questions about your estate and propose changes (which always go through approval).\n"
    "- **Inventory & health**: \"show all fortinet firewalls\", \"which devices are unreachable?\", \"which switches have high CPU?\"\n"
    "- **Investigate**: \"why is hq-dist1 down?\", \"what is wrong right now?\"\n"
    "- **Compliance**: \"which devices still have telnet enabled?\"\n"
    "- **Changes** (proposal only): \"create vlan 120 named guests on all aruba switches\", \"block ip 203.0.113.9 on all firewalls\", "
    "\"disable telnet on all mikrotik devices\", \"shutdown interface ether4 on davao-rtr1\", \"add ntp server 10.10.0.123 on all ruckus devices\".\n"
    "Destructive actions (reload, erase, factory reset...) are refused by design."
)


class Agent:
    def __init__(self, core: Core):
        self.core = core

    # ------------------------------------------------------------------ helpers
    def _match(self, f: dict) -> list[dict]:
        devs = self.core.devices()
        out = []
        for d in devs:
            if f.get("names") and d["name"] not in f["names"]:
                continue
            if f.get("vendor") and d["vendor"] != f["vendor"]:
                continue
            if f.get("platform") and d["platform"] != f["platform"]:
                continue
            if f.get("role") and d["role"] != f["role"]:
                continue
            if f.get("site") and d["site"] != f["site"]:
                continue
            out.append(d)
        return out

    @staticmethod
    def _desc(f: dict) -> str:
        bits = [f.get("site"), VENDORS.get(f.get("vendor", ""), f.get("vendor")), f.get("role")]
        return " ".join(b for b in bits if b) or "all"

    def _step(self, steps, tool, args, summary):
        steps.append({"tool": tool, "args": args, "summary": summary})

    # ------------------------------------------------------------------ entry
    def chat(self, user: dict, message: str) -> dict:
        if not isinstance(message, str) or not message.strip():
            raise V.ValidationError("message is required")
        if len(message) > 1000:
            raise V.ValidationError("message too long (max 1000 characters)")
        # normalise look-alike / zero-width characters BEFORE any guardrail regex sees the text
        message = unicodedata.normalize("NFKC", message)
        message = "".join(c for c in message if (c == "\n" or ord(c) >= 32) and unicodedata.category(c) not in ("Cf", "Cc") or c == "\n")
        steps: list = []
        audit = self.core.audit
        if policy.INJECTION_HINTS.search(message):
            audit.log(user["username"], "ai.injection_suspected", {"message": message[:200]})
            self._step(steps, "guardrail", {}, "Possible prompt-injection phrasing detected; guardrails do not depend on the prompt and remain enforced.")
        if policy.DESTRUCTIVE_INTENT.search(message):
            audit.log(user["username"], "ai.refused_destructive", {"message": message[:200]})
            self._step(steps, "guardrail", {}, "Destructive intent matched the deny policy")
            return {"reply": "I can't do that. Destructive operations (reload, erase, factory-reset, format, mass shutdown) are blocked by policy and "
                             "are not available to the AI agent or via the change API. If you really need to reboot a device, do it from the device console "
                             "under your maintenance procedure.", "intent": {"type": "refused"}, "steps": steps, "refused": True}
        sites = [r["site"] for r in self.core.db.q("SELECT DISTINCT site FROM devices WHERE site<>''")]
        names = [r["name"] for r in self.core.db.q("SELECT name FROM devices")]
        intent = None
        if self.core.s.llm_url:
            intent = llm.classify(self.core.s, message)
            if intent:
                self._step(steps, "llm.classify", {}, f"LLM classified request as '{intent['type']}'")
                # LLM output is never trusted over the deterministic parser for what a change *is*
                rule = nlu.parse(message, sites, names)
                if intent["type"] == "change" and (rule["type"] != "change" or rule.get("op") != intent.get("op")):
                    intent = rule
                    self._step(steps, "guardrail", {}, "LLM change intent did not match deterministic parser; using parser result")
                elif intent["type"] == "change":
                    intent["params"] = rule["params"]
                    intent["filters"] = rule["filters"]
                else:
                    ex = nlu.extract_filters(message, sites, names)
                    intent["filters"] = {**ex, **intent["filters"]}
        if not intent:
            intent = nlu.parse(message, sites, names)
            self._step(steps, "nlu.parse", {}, f"Intent: {intent['type']}")
        handler = getattr(self, f"_i_{intent['type']}", self._i_unknown)
        intent["q"] = message.lower()
        res = handler(user, intent, steps)
        res.setdefault("intent", {"type": intent["type"], "filters": intent.get("filters")})
        res["steps"] = steps
        audit.log(user["username"], "ai.query", {"message": message[:200], "intent": intent["type"]})
        return res

    # ------------------------------------------------------------------ handlers
    def _i_help(self, u, i, st):
        return {"reply": HELP}

    def _i_unknown(self, u, i, st):
        return {"reply": "I didn't understand that. Try *\"show all firewalls\"*, *\"what is wrong right now?\"* or type **help**."}

    def _table(self, devs, extra=None):
        cols = ["Device", "Vendor", "Platform", "Site", "Role", "Status", "Version"]
        rows = [[d["name"], VENDORS.get(d["vendor"], d["vendor"]), d["platform"], d["site"], d["role"],
                 "unknown" if d["reachable"] is None else ("up" if d["reachable"] else "DOWN"),
                 (d["facts"] or {}).get("version", "")] for d in devs]
        return {"columns": cols, "rows": rows}

    def _i_inventory(self, u, i, st):
        devs = self._match(i["filters"])
        self._step(st, "inventory.list", i["filters"], f"{len(devs)} device(s) matched")
        if not devs:
            return {"reply": "No devices match that filter."}
        return {"reply": f"Found **{len(devs)}** device(s) ({self._desc(i['filters'])}).", "table": self._table(devs)}

    def _i_summary(self, u, i, st):
        devs = self._match(i["filters"])
        by = {}
        for d in devs:
            by[VENDORS.get(d["vendor"], d["vendor"])] = by.get(VENDORS.get(d["vendor"], d["vendor"]), 0) + 1
        up = sum(1 for d in devs if d["reachable"])
        self._step(st, "inventory.summary", i["filters"], f"{len(devs)} devices")
        inc = len(self.core.incidents())
        return {"reply": f"**{len(devs)}** devices ({self._desc(i['filters'])}): {up} reachable, {len(devs)-up} not. "
                         f"Open incidents: **{inc}**.\n" + "\n".join(f"- {k}: {v}" for k, v in sorted(by.items()))}

    def _i_unreachable(self, u, i, st):
        devs = [d for d in self._match(i["filters"]) if d["reachable"] is False]
        self._step(st, "inventory.unreachable", i["filters"], f"{len(devs)} unreachable")
        if not devs:
            return {"reply": "Every matching device is reachable."}
        return {"reply": f"**{len(devs)}** device(s) are unreachable. Ask me *\"why is {devs[0]['name']} down?\"* for correlated impact.",
                "table": self._table(devs)}

    def _i_interfaces_down(self, u, i, st):
        ids = {d["id"] for d in self._match(i["filters"])}
        al = [a for a in self.core.alerts() if a["kind"] == "interface_down" and a["device_id"] in ids]
        self._step(st, "alerts.interface_down", i["filters"], f"{len(al)} alert(s)")
        if not al:
            return {"reply": "No monitored interfaces are down."}
        return {"reply": f"**{len(al)}** interface(s) down.", "table": {"columns": ["Device", "Interface", "Severity", "Message"],
                                                                      "rows": [[a["device"], a["key"], a["severity"], a["message"]] for a in al]}}

    def _i_resources(self, u, i, st):
        devs = [d for d in self._match(i["filters"]) if d["facts"]]
        devs.sort(key=lambda d: -(d["facts"]["cpu_pct"]))
        self._step(st, "telemetry.top_cpu", i["filters"], f"{len(devs)} devices ranked")
        rows = [[d["name"], d["platform"], f"{d['facts']['cpu_pct']:.0f}%", f"{d['facts']['mem_pct']:.0f}%"] for d in devs[:10]]
        return {"reply": "Top devices by CPU:", "table": {"columns": ["Device", "Platform", "CPU", "Memory"], "rows": rows}}

    def _i_versions(self, u, i, st):
        devs = [d for d in self._match(i["filters"]) if d["facts"]]
        self._step(st, "inventory.versions", i["filters"], f"{len(devs)} devices")
        return {"reply": "Software versions:", "table": {"columns": ["Device", "Platform", "Model", "Version", "Serial"],
                                                         "rows": [[d["name"], d["platform"], d["facts"]["model"], d["facts"]["version"], d["facts"]["serial"]] for d in devs]}}

    def _i_compliance(self, u, i, st):
        ids = {d["id"] for d in self._match(i["filters"])}
        low = " ".join(str(v) for v in i["filters"].values())
        fnd = [c for c in self.core.compliance() if c["device_id"] in ids]
        q = i.get("q", "")
        if "telnet" in q:
            fnd = [c for c in fnd if c["rule"] == "telnet_enabled"]
        elif "snmp" in q:
            fnd = [c for c in fnd if c["rule"] == "snmp_default_community"]
        self._step(st, "compliance.report", i["filters"], f"{len(fnd)} finding(s)")
        if not fnd:
            return {"reply": "No compliance findings for that scope."}
        crit = [c for c in fnd if c["severity"] == "critical"]
        tel = [c for c in fnd if c["rule"] == "telnet_enabled"]
        reply = f"**{len(fnd)}** finding(s), **{len(crit)}** critical."
        if tel:
            reply += f" Telnet is enabled on **{len(tel)}** device(s); I can propose *\"disable telnet on all devices\"* for approval."
        return {"reply": reply, "table": {"columns": ["Device", "Vendor", "Rule", "Severity", "Detail"],
                                          "rows": [[c["device"], c["vendor"], c["rule"], c["severity"], c["detail"]] for c in fnd[:40]]}}

    def _i_incidents(self, u, i, st):
        ids = {d["id"] for d in self._match(i["filters"])}
        inc = [x for x in self.core.incidents() if x["root_device_id"] in ids or any(True for a in x["alerts"])]
        self._step(st, "incidents.open", {}, f"{len(inc)} open incident(s)")
        if not inc:
            return {"reply": "All clear: there are no open incidents."}
        top = inc[0]
        return {"reply": f"**{len(inc)}** open incident(s). Highest priority: **{top['title']}**.\n\n{top['summary']}",
                "table": {"columns": ["#", "Severity", "Title", "Alerts"], "rows": [[x["id"], x["severity"], x["title"], len(x["alerts"])] for x in inc]}}

    def _i_explain(self, u, i, st):
        names = i["filters"].get("names")
        if not names:
            return self._i_incidents(u, i, st)
        n = names[0]
        d = next((x for x in self.core.devices() if x["name"] == n), None)
        view = self.core.device_view(d["id"])
        self._step(st, "device.view", {"name": n}, "loaded snapshot, alerts and neighbors")
        parts = []
        f = view["facts"]
        if view["reachable"] is False:
            parts.append(f"**{n}** is unreachable: {view['error']}")
        elif f:
            parts.append(f"**{n}** ({view['platform']}, {f['model']} v{f['version']}) is reachable; CPU {f['cpu_pct']:.0f}%, memory {f['mem_pct']:.0f}%, "
                         f"{sum(1 for x in f['interfaces'] if x['oper_up'])}/{len(f['interfaces'])} interfaces up.")
        inc = [x for x in self.core.incidents() if any(a["device"] == n for a in x["alerts"]) or x["root_device"] == n]
        self._step(st, "incidents.correlate", {"device": n}, f"{len(inc)} related incident(s)")
        for x in inc:
            parts.append(f"Incident #{x['id']}: {x['title']}\n{x['summary']}")
        if not inc and view["reachable"]:
            parts.append("No open alerts or incidents involve this device.")
        return {"reply": "\n\n".join(parts)}

    def _i_topology(self, u, i, st):
        t = self.core.topology()
        names = i["filters"].get("names")
        nodes = {n["id"]: n for n in t["nodes"]}
        self._step(st, "topology.get", {}, f"{len(t['nodes'])} nodes / {len(t['edges'])} links")
        rows = []
        for e in t["edges"]:
            a, b = nodes[e["a"]], nodes[e["b"]]
            if names and not ({a["name"], b["name"]} & set(names)):
                continue
            rows.append([a["name"], e["a_if"], b["name"], e["b_if"], e["state"]])
        return {"reply": f"**{len(rows)}** link(s).", "table": {"columns": ["Device A", "Port", "Device B", "Port", "State"], "rows": rows}}

    def _i_config(self, u, i, st):
        n = i["filters"]["names"][0]
        d = next(x for x in self.core.devices() if x["name"] == n)
        b = self.core.db.one("SELECT id FROM backups WHERE device_id=? ORDER BY ts DESC LIMIT 1", (d["id"],))
        self._step(st, "backups.latest", {"device": n}, "found" if b else "none")
        if not b:
            return {"reply": f"No backup exists for **{n}** yet. Use the Backup button on the device page (operators)."}
        cfg = self.core.backup_get(b["id"])["config"]
        return {"reply": f"Latest backup of **{n}** (secrets redacted), first 25 lines:\n```\n" + "\n".join(cfg.splitlines()[:25]) + "\n```"}

    def _i_change(self, user, i, st):
        if nlu_role(user) < 2:
            return {"reply": "Your role (viewer) is read-only. Ask an operator or admin to request this change.", "refused": True}
        op, params, f = i["op"], i["params"], i["filters"]
        try:
            params = validate_op(op, params)
        except V.ValidationError as e:
            return {"reply": f"I can't build that change: {e}.", "refused": True}
        if not (f.keys() & {"vendor", "role", "site", "names", "all", "platform"}):
            return {"reply": "Which devices should this apply to? Name a device, vendor, role or site (or say \"all\")."}
        devs = self._match(f)
        self._step(st, "inventory.resolve_targets", f, f"{len(devs)} device(s)")
        if not devs:
            return {"reply": "No devices match that scope."}
        try:
            cid = self.core.propose_change(user["username"], op, params, [d["id"] for d in devs], source="ai",
                                           summary=f"[AI] {OPS[op]['desc']} {json.dumps(params)} on {self._desc(f)}")
        except ChangeError as e:
            self._step(st, "guardrail", {}, str(e)[:160])
            return {"reply": f"I can't propose that: {e}", "refused": True}
        c = self.core.change(cid)
        self._step(st, "change.propose", {"id": cid}, "rendered per-vendor plan, pre-checked guardrails; awaiting approval")
        rows = []
        for p in c["plan"]:
            rows.append([p["name"], p["platform"], p["status"], " / ".join(p["lines"])[:200] if p["lines"] else p.get("reason", "")])
        ok = sum(1 for p in c["plan"] if p["status"] == "planned")
        return {"reply": f"Proposed change **#{cid}**: {OPS[op]['desc']} on **{ok}** device(s). Nothing has been applied. "
                         f"An administrator (other than you) must approve it on the **Changes** page; I will snapshot, verify and auto-rollback on failure.",
                "table": {"columns": ["Device", "Platform", "Plan", "Native commands"], "rows": rows}, "change_id": cid}


def nlu_role(user) -> int:
    from ..security import ROLES
    return ROLES.get(user["role"], 0)
