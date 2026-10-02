(() => {
"use strict";
const S = { token: sessionStorage.getItem("onc_token"), user: null, page: "overview", demo: false, chat: [], timer: null };
const VN = { cisco: "Cisco", fortinet: "Fortinet", paloalto: "Palo Alto", mikrotik: "MikroTik", ruckus: "Ruckus", aruba: "HPE Aruba" };
const NAV = [["overview", "Overview", "\u25A6"], ["inventory", "Inventory", "\u2630"], ["topology", "Topology", "\u2B21"], ["incidents", "Incidents", "\u26A0"], ["predictive", "Predictive", "\u25F7"],
  ["ai", "AI Assistant", "\u2726"], ["compliance", "Compliance", "\u2611"], ["changes", "Changes", "\u21C5"], ["platforms", "Platforms", "\u25A4"], ["audit", "Audit log", "\u2338"]];

// ---------------------------------------------------------------- helpers (no innerHTML anywhere)
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "text") e.textContent = v;
    else if (k === "style") e.style.cssText = v;   // CSSOM (CSP-safe), never the style attribute
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
}
function svg(tag, props, ...kids) {
  const e = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(props || {})) { if (k === "style") { if (v) e.style.cssText = v; } else e.setAttribute(k, v); }
  for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
}
const chip = (t, cls) => h("span", { class: "chip " + cls }, t);
const sev = s => chip(s, "sev-" + s);
const st = s => chip(String(s).replace("_", " "), "st-" + s);
const vend = v => h("span", { class: "vend v-" + v }, VN[v] || v);
const ago = ts => { if (!ts) return "-"; const s = Math.max(0, Date.now() / 1000 - ts); return s < 90 ? Math.round(s) + "s ago" : s < 5400 ? Math.round(s / 60) + "m ago" : s < 172800 ? Math.round(s / 3600) + "h ago" : Math.round(s / 86400) + "d ago"; };
const up = s => { const d = Math.floor(s / 86400); return d ? d + "d " + Math.floor(s % 86400 / 3600) + "h" : Math.floor(s / 3600) + "h " + Math.floor(s % 3600 / 60) + "m"; };

function inline(text) {
  const out = []; const re = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*\n]+\*)/g; let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const t = m[0];
    out.push(t.startsWith("**") ? h("strong", {}, t.slice(2, -2)) : t.startsWith("`") ? h("code", { class: "mono" }, t.slice(1, -1)) : h("em", {}, t.slice(1, -1)));
    last = m.index + t.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}
function md(text) {
  const root = h("div"); const lines = String(text).split("\n"); let i = 0, ul = null;
  while (i < lines.length) {
    const l = lines[i];
    if (l.startsWith("```")) { const buf = []; i++; while (i < lines.length && !lines[i].startsWith("```")) buf.push(lines[i++]); i++; root.append(h("pre", {}, buf.join("\n"))); ul = null; continue; }
    if (/^\s*-\s+/.test(l)) { if (!ul) { ul = h("ul"); root.append(ul); } ul.append(h("li", {}, inline(l.replace(/^\s*-\s+/, "")))); }
    else if (l.trim()) { ul = null; root.append(h("p", {}, inline(l))); } else ul = null;
    i++;
  }
  return root;
}
function table(cols, rows, opts = {}) {
  const t = h("table", {}, h("thead", {}, h("tr", {}, cols.map(c => h("th", { scope: "col" }, c)))),
    h("tbody", {}, rows.map(r => { const tr = h("tr", opts.click ? { class: "click", tabindex: "0", onclick: () => opts.click(r), onkeydown: e => { if (e.key === "Enter") opts.click(r); } } : {}, r.cells.map(c => h("td", {}, c))); return tr; })));
  return h("div", { class: "tablewrap" }, t);
}
function toast(msg, bad) { const t = h("div", { class: "toast" + (bad ? " bad" : ""), role: "status" }, msg); document.body.append(t); setTimeout(() => t.remove(), 4500); }

async function api(path, opts = {}) {
  const o = { method: opts.method || "GET", headers: {} };
  if (S.token) o.headers.Authorization = "Bearer " + S.token;
  if (opts.body !== undefined) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(opts.body); }
  const r = await fetch(path, o);
  let data = null; try { data = await r.json(); } catch (e) { /* empty */ }
  if (r.status === 401 && S.token && path !== "/api/auth/login") { logoutLocal(); throw new Error("Session expired"); }
  if (!r.ok) throw new Error((data && (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail))) || r.statusText);
  return data;
}
const act = async (fn, ok) => { try { const r = await fn(); if (ok) toast(ok); return r; } catch (e) { toast(e.message, true); } };
const role = () => S.user ? S.user.role : "viewer";
const can = r => ({ viewer: 1, operator: 2, admin: 3 })[role()] >= ({ viewer: 1, operator: 2, admin: 3 })[r];

// ---------------------------------------------------------------- shell
const root = document.getElementById("app");
function logoutLocal() { S.token = null; S.user = null; sessionStorage.removeItem("onc_token"); clearInterval(S.timer); renderLogin(); }

function renderLogin(msg) {
  root.replaceChildren();
  const err = h("div", { class: "err", role: "alert" }, msg || "");
  const u = h("input", { id: "u", autocomplete: "username", required: true, "aria-label": "Username" });
  const p = h("input", { id: "p", type: "password", autocomplete: "current-password", required: true, "aria-label": "Password" });
  const form = h("form", { onsubmit: async e => {
    e.preventDefault(); err.textContent = "";
    try { const r = await api("/api/auth/login", { method: "POST", body: { username: u.value, password: p.value } }); S.token = r.token; sessionStorage.setItem("onc_token", r.token); await boot(); }
    catch (x) { err.textContent = x.message; }
  } }, h("label", { for: "u" }, "Username"), u, h("label", { for: "p" }, "Password"), p, h("div", { style: "" }), h("button", { class: "primary", type: "submit", style: "width:100%;margin-top:16px" }, "Sign in"), err);
  root.append(h("div", { class: "login" }, h("div", { class: "card" }, h("div", { class: "brand" }, logo(), h("span", {}, "OpenNetControl")),
    h("p", { class: "muted" }, "Multi-vendor, AI-assisted network operations."), form)));
  u.focus();
}
function logo() { return svg("svg", { viewBox: "0 0 32 32", class: "logo", "aria-hidden": "true" }, svg("rect", { width: 32, height: 32, rx: 7, fill: "#14b8a6" }), svg("circle", { cx: 9, cy: 16, r: 3, fill: "#fff" }), svg("circle", { cx: 23, cy: 9, r: 3, fill: "#fff" }), svg("circle", { cx: 23, cy: 23, r: 3, fill: "#fff" }), svg("path", { d: "M9 16L23 9M9 16L23 23", stroke: "#fff", "stroke-width": 2 })); }

async function boot() {
  try { S.user = await api("/api/auth/me"); } catch (e) { return renderLogin(); }
  try { const ops = await api("/api/overview"); S.ov = ops; } catch (e) { /* ignore */ }
  const hash = location.hash.replace("#", ""); if (NAV.map(n => n[0]).includes(hash)) S.page = hash;
  drawShell(); go(S.page);
  clearInterval(S.timer); S.timer = setInterval(() => { if (!document.hidden && ["overview", "inventory", "incidents", "topology", "predictive"].includes(S.page) && !document.querySelector(".drawer")) go(S.page, true); }, 20000);
}
function drawShell() {
  root.replaceChildren();
  const nav = h("nav", { class: "nav", "aria-label": "Main" }, NAV.map(([id, label, ic]) => h("button", { "data-page": id, onclick: () => go(id) }, h("span", { "aria-hidden": "true" }, ic), h("span", { class: "t" }, label), id === "incidents" ? h("span", { class: "badge chip sev-high", id: "b-inc", hidden: true }) : null, id === "predictive" ? h("span", { class: "badge chip sev-medium", id: "b-pred", hidden: true }) : null, id === "changes" ? h("span", { class: "badge chip st-pending", id: "b-chg", hidden: true }) : null)));
  const ask = h("input", { class: "ask", placeholder: "Ask the AI: \"which devices are unreachable?\"", "aria-label": "Ask the AI assistant", onkeydown: e => { if (e.key === "Enter" && ask.value.trim()) { const q = ask.value; ask.value = ""; go("ai"); sendChat(q); } } });
  root.append(h("div", { class: "shell" },
    h("aside", { class: "side" }, h("div", { class: "brand" }, logo(), h("span", {}, "OpenNetControl")), nav,
      h("div", { class: "foot" }, h("div", {}, S.user.username, " \u00B7 ", S.user.role), h("button", { class: "ghost", style: "margin-top:8px", onclick: async () => { try { await api("/api/auth/logout", { method: "POST" }); } catch (e) { /* */ } logoutLocal(); } }, "Sign out"))),
    h("div", { class: "main" }, h("header", { class: "top" }, h("h1", { id: "title" }, ""), ask), h("main", { class: "content", id: "content", tabindex: "-1" }))));
}
async function go(page, quiet) {
  S.page = page; location.hash = page;
  document.querySelectorAll(".nav button").forEach(b => b.classList.toggle("active", b.dataset.page === page));
  document.getElementById("title").textContent = (NAV.find(n => n[0] === page) || [])[1] || "";
  const c = document.getElementById("content");
  try {
    const node = await PAGES[page]();
    if (S.page === page) { c.replaceChildren(node); }
    refreshBadges();
  } catch (e) { c.replaceChildren(h("div", { class: "card" }, h("p", { class: "err", role: "alert" }, "Error: " + e.message))); }
}
async function refreshBadges() {
  try {
    const o = await api("/api/overview"); S.ov = o;
    const bi = document.getElementById("b-inc"), bc = document.getElementById("b-chg");
    if (bi) { bi.textContent = o.open_incidents; bi.hidden = !o.open_incidents; }
    if (bc) { bc.textContent = o.pending_changes; bc.hidden = !o.pending_changes; }
    const bp = document.getElementById("b-pred"), pc = o.predictions ? o.predictions.active : 0;
    if (bp) { bp.textContent = pc; bp.hidden = !pc; bp.setAttribute("aria-label", pc + " developing problems"); }
  } catch (e) { /* */ }
}

// ---------------------------------------------------------------- pages
const PAGES = {};
const kpi = (label, v, sub, cls) => h("div", { class: "card kpi" }, h("h3", {}, label), h("div", { class: "v " + (cls || "") }, v), h("div", { class: "s" }, sub || "\u00A0"));

PAGES.overview = async () => {
  const [o, inc, comp, pr] = await Promise.all([api("/api/overview"), api("/api/incidents"), api("/api/compliance"), api("/api/predictions")]);
  S.ov = o;
  const max = Math.max(1, ...Object.values(o.vendors));
  const wrap = h("div", { class: "grid" },
    h("div", { class: "grid kpis" }, kpi("Devices", o.devices, o.sites.length + " sites"), kpi("Reachable", o.reachable + "/" + o.devices, o.unreachable ? o.unreachable + " unreachable" : "all healthy"),
      kpi("Open incidents", o.open_incidents, Object.entries(o.alert_severity).map(([k, v]) => v + " " + k).join(", ") || "no active alerts"),
      kpi("Predicted problems", o.predictions ? o.predictions.active : 0, (o.predictions ? o.predictions.interfaces_at_risk : 0) + " interfaces at risk", o.predictions && o.predictions.active ? "warn" : ""), kpi("Critical findings", o.critical_findings, o.compliance_findings + " total findings"), kpi("Pending changes", o.pending_changes, "awaiting approval"), kpi("Wi-Fi clients", o.clients, "across all controllers")),
    h("div", { class: "grid two" },
      h("div", { class: "card" }, h("h3", {}, "Active incidents"), inc.length ? table(["Severity", "Incident", "Opened"], inc.map(i => ({ cells: [sev(i.severity), i.title, ago(i.opened)], id: i.id })), { click: () => go("incidents") }) : h("p", { class: "muted" }, "\u2713 No open incidents. Everything looks healthy.")),
      h("div", { class: "card" }, h("h3", {}, "Estate by vendor"), Object.entries(o.vendors).sort((a, b) => b[1] - a[1]).map(([v, n]) => h("div", { style: "margin:10px 0" }, h("div", { class: "row" }, vend(v), h("span", { class: "spacer" }), h("strong", {}, n)), h("div", { class: "bar", role: "img", "aria-label": VN[v] + ": " + n + " devices" }, (() => { const i = h("i"); i.style.width = (100 * n / max) + "%"; return i; })()))))),
    h("div", { class: "card" }, h("div", { class: "row" }, h("h3", { style: "margin:0" }, "Early warnings (predicted before they cause an outage)"), h("span", { class: "spacer" }), h("button", { onclick: () => go("predictive") }, "Open Predictive")),
      pr.items.length ? table(["Severity", "Device", "Interface", "Issue", "Expected impact"], pr.items.slice(0, 5).map(p => ({ p, cells: [sev(p.severity), p.device, p.ifname, p.title, fmtEta(p)] })), { click: r => predictionDrawer(r.p.id) }) : h("p", { class: "muted" }, "\u2713 Nothing is trending toward a failure.")),
    h("div", { class: "grid two" },
      h("div", { class: "card" }, h("h3", {}, "Top compliance findings"), table(["Severity", "Device", "Rule"], comp.slice(0, 6).map(c => ({ cells: [sev(c.severity), c.device, c.rule] })), { click: () => go("compliance") })),
      h("div", { class: "card" }, h("h3", {}, "Ask the AI Assistant"), h("div", { class: "chips" }, ["What is wrong right now?", "Which devices still have telnet enabled?", "Show all Palo Alto and Fortinet firewalls", "Which devices have the highest CPU?"].map(q => h("button", { onclick: () => { go("ai"); sendChat(q); } }, q))),
        h("p", { class: "muted" }, "Changes proposed by the assistant are never applied directly: they go through approval, snapshot, verification and auto-rollback."))),
    role() === "admin" && o.demo ? labPanel() : null);
  return wrap;
};
function labPanel() {
  const run = (action, device, extra) => act(async () => { await api("/api/lab/fault", { method: "POST", body: { action, device, ...extra } }); go("overview"); }, "Lab event applied");
  return h("div", { class: "card" }, h("h3", {}, "Demo lab controls (only available when ONC_DEMO=1)"), h("div", { class: "row" },
    h("button", { onclick: () => run("power_off", "hq-dist1") }, "Power off hq-dist1"), h("button", { onclick: () => run("power_on", "hq-dist1") }, "Power on hq-dist1"),
    h("button", { onclick: () => run("cpu", "cebu-fw1", { value: 97 }) }, "Spike CPU on cebu-fw1"), h("button", { onclick: () => run("cpu", "cebu-fw1", { value: 30 }) }, "Normalise CPU"),
    h("button", { onclick: () => run("link_down", "hq-core1", { interface: "TenGigabitEthernet1/1/4" }) }, "Drop hq-core1 Te1/1/4"),
    h("button", { onclick: () => run("degrade", "hq-dc1", { interface: "Ethernet1/1", kind: "errors" }) }, "Start CRC errors on hq-dc1 Eth1/1"),
    h("button", { onclick: () => run("heal", "hq-dist2", { interface: "1/1/48" }) }, "Replace optic on hq-dist2 1/1/48"),
    h("button", { onclick: () => run("fast_forward", "hq-core1", { value: 10800 }) }, "\u23E9 Fast-forward 3 h"), h("button", { onclick: () => run("fast_forward", "hq-core1", { value: 21600 }) }, "\u23E9 Fast-forward 6 h")));
}

PAGES.inventory = async () => {
  const devs = await api("/api/devices");
  const q = h("input", { placeholder: "Search name, model, site, serial\u2026", "aria-label": "Search inventory" });
  const mk = (id, label, opts) => h("select", { id, "aria-label": label }, h("option", { value: "" }, label), opts.map(o => h("option", { value: o }, VN[o] || o)));
  const fv = mk("fv", "All vendors", [...new Set(devs.map(d => d.vendor))].sort()), fr = mk("fr", "All roles", [...new Set(devs.map(d => d.role))].sort()), fs = mk("fs", "All sites", [...new Set(devs.map(d => d.site))].sort());
  const holder = h("div");
  const draw = () => {
    const t = q.value.toLowerCase();
    const rows = devs.filter(d => (!fv.value || d.vendor === fv.value) && (!fr.value || d.role === fr.value) && (!fs.value || d.site === fs.value) &&
      (!t || [d.name, d.site, d.platform, (d.facts || {}).model, (d.facts || {}).serial, (d.facts || {}).version].join(" ").toLowerCase().includes(t)));
    holder.replaceChildren(table(["", "Device", "Vendor", "Platform", "Model", "Version", "Site", "Role", "CPU", "Uptime", "Last seen"],
      rows.map(d => ({ d, cells: [h("span", { class: "dot " + (d.reachable === false ? "down" : d.reachable ? "up" : ""), title: d.reachable ? "reachable" : "unreachable", role: "img", "aria-label": d.reachable ? "reachable" : "unreachable" }), h("strong", {}, d.name), vend(d.vendor), d.platform, (d.facts || {}).model || "-", (d.facts || {}).version || "-", d.site, d.role,
        d.facts ? Math.round(d.facts.cpu_pct) + "%" : "-", d.facts ? up(d.facts.uptime_s) : "-", ago(d.snap_ts)] })), { click: r => deviceDrawer(r.d.id) }));
    count.textContent = rows.length + " of " + devs.length + " devices";
  };
  const count = h("span", { class: "muted" });
  [q, fv, fr, fs].forEach(e => e.addEventListener("input", draw));
  draw();
  return h("div", { class: "card" }, h("div", { class: "row" }, h("div", { style: "flex:2;min-width:200px" }, q), h("div", { style: "flex:1;min-width:120px" }, fv), h("div", { style: "flex:1;min-width:120px" }, fr), h("div", { style: "flex:1;min-width:120px" }, fs),
    can("operator") ? h("button", { onclick: () => act(async () => { await api("/api/poll", { method: "POST" }); go("inventory"); }, "Inventory refreshed") }, "Refresh all") : null, count), holder);
};
async function deviceDrawer(id) {
  const d = await act(() => api("/api/devices/" + id)); if (!d) return;
  document.querySelector(".drawer")?.remove();
  const f = d.facts;
  const cfgBox = h("div");
  const close = () => dr.remove();
  const dr = h("aside", { class: "drawer", role: "dialog", "aria-label": "Device " + d.name },
    h("div", { class: "row" }, h("h2", { style: "margin:0" }, d.name), vend(d.vendor), st(d.reachable ? "up" : "down"), h("span", { class: "spacer" }), h("button", { onclick: close, "aria-label": "Close" }, "\u2715")),
    h("p", { class: "muted" }, d.platform + " \u00B7 " + d.site + " \u00B7 " + d.role + " \u00B7 " + d.transport),
    d.error ? h("p", { class: "err" }, d.error) : null,
    f ? h("div", {}, h("table", {}, h("tbody", {}, [["Model", f.model], ["Version", f.version], ["Serial", f.serial], ["Uptime", up(f.uptime_s)], ["CPU / Memory", Math.round(f.cpu_pct) + "% / " + Math.round(f.mem_pct) + "%"], ["Telnet", f.telnet_enabled ? "ENABLED" : "off"], ["NTP", f.ntp_servers.join(", ") || "none"], f.role === "wireless" || d.role === "wireless" ? ["Clients / APs", f.clients + " / " + f.aps] : null].filter(Boolean).map(([k, v]) => h("tr", {}, h("td", { class: "muted" }, k), h("td", {}, v || "-"))))),
      h("h3", { class: "muted" }, "Interfaces"), table(["Name", "Admin", "Oper", "IP", "Description"], f.interfaces.map(i => ({ cells: [i.name, i.admin_up ? "up" : "down", st(i.oper_up ? "up" : "down"), i.ip || "-", i.description || ""] }))),
      Object.keys(f.ssids || {}).length ? [h("h3", { class: "muted" }, "SSIDs"), table(["SSID", "State"], Object.entries(f.ssids).map(([k, v]) => ({ cells: [k, st(v ? "up" : "down")] })))] : null,
      f.neighbors.length ? [h("h3", { class: "muted" }, "Neighbors (LLDP)"), table(["Local", "Neighbor", "Remote port"], f.neighbors.map(n => ({ cells: [n.local_if, n.remote_host, n.remote_if] })))] : null) : null,
    d.alerts.length ? [h("h3", { class: "muted" }, "Open alerts"), table(["Severity", "Message"], d.alerts.map(a => ({ cells: [sev(a.severity), a.message] })))] : null,
    h("p", { class: "muted" }, "Supported operations: " + d.capabilities.join(", ")),
    h("div", { class: "row" }, can("operator") ? h("button", { onclick: () => act(async () => { await api("/api/devices/" + id + "/refresh", { method: "POST" }); close(); deviceDrawer(id); }, "Refreshed") }, "Refresh now") : null,
      can("operator") ? h("button", { onclick: () => act(async () => { const r = await api("/api/devices/" + id + "/backup", { method: "POST" }); cfgBox.replaceChildren(h("pre", {}, r.config.slice(0, 6000))); }, "Backup stored") }, "Backup config") : null,
      can("admin") ? h("button", { class: "danger", onclick: () => { if (confirm("Remove " + d.name + " from inventory?")) act(async () => { await api("/api/devices/" + id, { method: "DELETE" }); close(); go("inventory"); }, "Device removed"); } }, "Remove") : null),
    cfgBox);
  document.body.append(dr); dr.querySelector("button")?.focus();
}

PAGES.topology = async () => {
  const t = await api("/api/topology");
  const byId = Object.fromEntries(t.nodes.map(n => [n.id, n]));
  const adj = {}; t.edges.forEach(e => { (adj[e.a] = adj[e.a] || []).push(e.b); (adj[e.b] = adj[e.b] || []).push(e.a); });
  const tier = {}; let q = t.nodes.filter(n => n.role === "firewall" || n.role === "router").map(n => n.id);
  q.forEach(i => tier[i] = 0);
  for (let k = 0; k < q.length; k++) for (const nb of adj[q[k]] || []) if (tier[nb] === undefined) { tier[nb] = tier[q[k]] + 1; q.push(nb); }
  t.nodes.forEach(n => { if (tier[n.id] === undefined) tier[n.id] = n.role === "wireless" ? 3 : 1; });
  const levels = {}; t.nodes.forEach(n => (levels[tier[n.id]] = levels[tier[n.id]] || []).push(n));
  const W = 1180, TH = 110, maxT = Math.max(...Object.keys(levels).map(Number)); const H = (maxT + 1) * TH + 50;
  const pos = {};
  Object.entries(levels).forEach(([lv, ns]) => { ns.sort((a, b) => a.site.localeCompare(b.site) || a.name.localeCompare(b.name)); ns.forEach((n, i) => pos[n.id] = { x: 130 + (i + 0.5) * (W - 150) / ns.length, y: 50 + lv * TH }); });
  const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "topo", role: "img", "aria-label": "Network topology map", width: "100%" });
  Object.keys(levels).forEach(lv => s.append(svg("text", { class: "tier", x: 8, y: 20 + lv * TH + 30 }, ["EDGE", "CORE", "DIST.", "ACCESS", "WI-FI"][lv] || "TIER " + lv)));
  t.edges.forEach(e => { const a = pos[e.a], b = pos[e.b]; s.append(svg("line", { class: "edge" + (e.state === "down" ? " down" : e.state === "at_risk" ? " risk" : ""), x1: a.x, y1: a.y, x2: b.x, y2: b.y })); });
  t.nodes.forEach(n => { const p = pos[n.id];
    const g = svg("g", { class: `node st-${n.status} vendor-${n.vendor}`, transform: `translate(${p.x - 62},${p.y - 20})`, tabindex: 0, role: "button", "aria-label": n.name + " " + n.status });
    g.append(svg("rect", { width: 124, height: 40, rx: 9 }), svg("text", { x: 62, y: 17, "text-anchor": "middle", "font-weight": "700" }, n.name), svg("text", { x: 62, y: 31, "text-anchor": "middle", style: "" }, VN[n.vendor] + " \u00B7 " + n.role));
    if (n.status === "down") g.append(svg("circle", { cx: 120, cy: 2, r: 7, fill: "#ef4444" }));
    else if (n.alerts) g.append(svg("circle", { cx: 120, cy: 2, r: 7, fill: "#f97316" }));
    g.addEventListener("click", () => deviceDrawer(n.id)); g.addEventListener("keydown", ev => { if (ev.key === "Enter") deviceDrawer(n.id); });
    s.append(g); });
  return h("div", { class: "card" }, h("div", { class: "legend" }, h("span", {}, "\u25CF Red dashed = failed link / device down"), h("span", {}, "\u25CF Amber dashed = predicted problem developing on this link"), h("span", {}, "\u25CF Orange badge = active alert"), h("span", {}, "Built live from LLDP/neighbor data collected from every vendor"), h("span", {}, t.nodes.length + " devices \u00B7 " + t.edges.length + " links")), s);
};

PAGES.incidents = async () => {
  const [inc, res] = await Promise.all([api("/api/incidents"), api("/api/incidents?status=resolved")]);
  const card = i => h("div", { class: "card" }, h("div", { class: "row" }, sev(i.severity), h("strong", {}, "#" + i.id + " " + i.title), h("span", { class: "spacer" }), h("span", { class: "muted" }, "opened " + ago(i.opened)), i.ack_by ? chip("ack: " + i.ack_by, "st-approved") : null),
    md(i.summary), h("h3", { class: "muted", style: "margin-top:12px" }, "Correlated alerts (" + i.alerts.length + ")"), table(["Device", "Severity", "Alert"], i.alerts.map(a => ({ cells: [a.device, sev(a.severity), a.message] }))),
    h("div", { class: "row", style: "margin-top:10px" }, can("operator") && !i.ack_by ? h("button", { onclick: () => act(async () => { await api("/api/incidents/" + i.id + "/ack", { method: "POST" }); go("incidents"); }, "Acknowledged") }, "Acknowledge") : null,
      h("button", { class: "primary", onclick: () => { go("ai"); sendChat(i.root_device ? "why is " + i.root_device + " having problems?" : "what is wrong right now?"); } }, "\u2726 Investigate with AI")));
  return h("div", { class: "grid" }, inc.length ? inc.map(card) : h("div", { class: "card" }, h("p", { class: "muted" }, "\u2713 No open incidents.")),
    h("div", { class: "card" }, h("h3", {}, "Recently resolved"), res.length ? table(["Incident", "Closed"], res.slice(0, 10).map(r => ({ cells: [r.title, ago(r.closed)] }))) : h("p", { class: "muted" }, "None yet.")));
};

// ---------------------------------------------------------------- predictive interface monitoring
const KIND_LABEL = { errors: "Errors", optic: "Optics", utilization: "Capacity", flaps: "Flapping", traffic: "Traffic", discards: "Drops" };
const fmtBps = v => v == null ? "-" : v >= 1e9 ? (v / 1e9).toFixed(1) + " Gbps" : v >= 1e6 ? (v / 1e6).toFixed(1) + " Mbps" : v >= 1e3 ? (v / 1e3).toFixed(0) + " kbps" : Math.round(v) + " bps";
const fmtEta = p => { const hrs = p.eta_hours; if (hrs == null) return p.kind === "flaps" || p.kind === "traffic" || p.kind === "discards" ? "occurring now" : "no forecast"; return hrs < 1 ? "~" + Math.max(1, Math.round(hrs * 60)) + " min" : hrs < 48 ? "~" + hrs.toFixed(1) + " h" : "~" + (hrs / 24).toFixed(1) + " d"; };
const etaNote = p => p.kind === "errors" ? "until errors become service-affecting" : p.kind === "optic" ? "until optical alarm level" : p.kind === "utilization" ? "until link is saturated" : "";
function meter(conf) {
  const o = h("span", { class: "meter", role: "img", "aria-label": "confidence " + Math.round(conf * 100) + " percent", title: "Confidence " + Math.round(conf * 100) + "%" });
  const i = h("i"); i.style.width = Math.round(conf * 100) + "%"; o.append(i); return o;
}
function lineChart(o) {
  const W = o.w || 520, H = o.h || 130, L = 44, R = 10, T = 8, B = 20;
  const pts = (o.pts || []).filter(p => p[1] != null);
  const box = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", width: "100%" });
  const first = pts[0], last = pts[pts.length - 1];
  box.setAttribute("aria-label", o.title + (pts.length ? ": from " + o.fmt(first[1]) + " to " + o.fmt(last[1]) + " over the period" : ": no data"));
  box.append(svg("title", {}, o.title));
  if (!pts.length) { box.append(svg("text", { x: W / 2, y: H / 2, "text-anchor": "middle", class: "axis" }, "no data yet")); return box; }
  const fc = (o.fc || []).filter(p => p[1] != null);
  const tmin = pts[0][0], tmax = Math.max(pts[pts.length - 1][0], ...fc.map(p => p[0]), tmin + 1);
  const vals = pts.map(p => p[1]).concat(fc.map(p => p[1]), (o.lines || []).map(l => l.y));
  let lo = o.min != null ? o.min : Math.min(...vals), hi = o.max != null ? o.max : Math.max(...vals);
  if (hi - lo < 1e-9) { hi = lo + 1; }
  const pad = (hi - lo) * 0.08; if (o.min == null) lo -= pad; if (o.max == null) hi += pad;
  const X = t => L + (t - tmin) / (tmax - tmin) * (W - L - R), Y = v => T + (1 - (v - lo) / (hi - lo)) * (H - T - B);
  for (let k = 0; k <= 2; k++) { const v = lo + (hi - lo) * k / 2; box.append(svg("line", { x1: L, x2: W - R, y1: Y(v), y2: Y(v), class: "grid" }), svg("text", { x: L - 4, y: Y(v) + 3, "text-anchor": "end", class: "axis" }, o.fmt(v))); }
  (o.lines || []).forEach(l => { if (l.y >= lo && l.y <= hi) box.append(svg("line", { x1: L, x2: W - R, y1: Y(l.y), y2: Y(l.y), class: "thr " + (l.cls || "") }), svg("text", { x: W - R - 2, y: Y(l.y) - 3, "text-anchor": "end", class: "axis thr-t" }, l.label)); });
  let d = ""; pts.forEach((p, i) => { d += (i ? "L" : "M") + X(p[0]).toFixed(1) + " " + Y(p[1]).toFixed(1); });
  box.append(svg("path", { d, class: "series" }));
  if (fc.length) { let f = "M" + X(last[0]).toFixed(1) + " " + Y(last[1]).toFixed(1); fc.forEach(p => { f += "L" + X(p[0]).toFixed(1) + " " + Y(p[1]).toFixed(1); }); box.append(svg("path", { d: f, class: "forecast" })); }
  const nowT = o.now || last[0];
  box.append(svg("text", { x: L, y: H - 4, class: "axis" }, "-" + Math.round((nowT - tmin) / 3600 * 10) / 10 + " h"), svg("text", { x: X(Math.min(nowT, tmax)), y: H - 4, "text-anchor": "middle", class: "axis" }, "now"));
  if (tmax > nowT + 60) box.append(svg("text", { x: W - R, y: H - 4, "text-anchor": "end", class: "axis fc-t" }, "+" + Math.round((tmax - nowT) / 3600 * 10) / 10 + " h forecast"));
  return box;
}
function forecastFor(p, m) {
  const ev = p.evidence || {}, now = m.now;
  if (p.kind === "utilization" && ev.forecast) return ev.forecast;
  if (p.kind === "errors" && p.eta_ts && ev.current_per_min != null) return [[now, ev.current_per_min], [p.eta_ts, ev.threshold_per_min]];
  if (p.kind === "optic" && p.eta_ts && ev.rx_dbm != null) return [[now, ev.rx_dbm], [p.eta_ts, ev.low_alarm]];
  return [];
}
function charts(m, preds) {
  const P = m.points, now = m.now, byKind = {};
  (preds || []).forEach(p => { byKind[p.kind] = p; });
  const fcOf = k => byKind[k] ? forecastFor(byKind[k], m) : [];
  const col = k => P.map(p => [p.t, p[k]]);
  const box = h("div", { class: "charts" });
  const add = (title, node, sub) => box.append(h("div", { class: "chartbox" }, h("div", { class: "muted small" }, title), node, sub ? h("div", { class: "small muted" }, sub) : null));
  add("Utilisation", lineChart({ title: "Utilisation", pts: col("util"), fc: fcOf("utilization"), now, fmt: v => Math.round(v * 100) + "%", min: 0, max: Math.max(1, ...P.map(p => p.util || 0)), lines: [{ y: m.thresholds.util_warn, label: "saturation", cls: "warn" }] }),
    "Peak " + fmtBps(Math.max(0, ...P.map(p => Math.max(p.in_bps || 0, p.out_bps || 0)))) + (m.speed_bps ? " of " + fmtBps(m.speed_bps) : ""));
  add("Input errors per minute", lineChart({ title: "Input errors per minute", pts: col("err_pm"), fc: fcOf("errors"), now, fmt: v => v >= 10 ? Math.round(v) : v.toFixed(1), min: 0, lines: [{ y: m.thresholds.err_crit_pm, label: "service-affecting", cls: "crit" }] }));
  if (P.some(p => p.rx_dbm != null)) add("Optical receive power (dBm)", lineChart({ title: "Optical receive power", pts: col("rx_dbm"), fc: fcOf("optic"), now, fmt: v => v.toFixed(1), lines: [m.low_warn != null ? { y: m.low_warn, label: "low warn", cls: "warn" } : null, m.low_alarm != null ? { y: m.low_alarm, label: "low alarm", cls: "crit" } : null].filter(Boolean) }));
  if (P.some(p => (p.flaps || 0) > 0)) add("Link flaps per interval", lineChart({ title: "Link flaps", pts: col("flaps"), now, fmt: v => Math.round(v), min: 0 }));
  return box;
}
async function metricsFor(devId, ifname, hours) { return api("/api/devices/" + devId + "/metrics?ifname=" + encodeURIComponent(ifname) + "&hours=" + hours); }
async function predictionDrawer(id) {
  const p = await act(() => api("/api/predictions/" + id)); if (!p) return;
  const m = await act(() => metricsFor(p.device_id, p.ifname, 12)); if (!m) return;
  document.querySelector(".drawer")?.remove();
  const close = () => dr.remove(), ev = p.evidence || {};
  const evRows = Object.entries(ev).filter(([k, v]) => v != null && typeof v !== "object" && !k.endsWith("_ts")).map(([k, v]) => h("tr", {}, h("td", { class: "muted" }, k.replace(/_/g, " ")), h("td", {}, String(v))));
  const hours = h("select", { "aria-label": "Mute duration" }, [["1", "1 hour"], ["8", "8 hours"], ["24", "24 hours"], ["168", "7 days"]].map(([v, l]) => h("option", { value: v }, l)));
  const dr = h("aside", { class: "drawer wide", role: "dialog", "aria-label": "Prediction " + p.id },
    h("div", { class: "row" }, h("h2", { style: "margin:0" }, p.title), h("span", { class: "spacer" }), h("button", { onclick: close, "aria-label": "Close" }, "\u2715")),
    h("div", { class: "row", style: "margin:8px 0" }, sev(p.severity), chip(KIND_LABEL[p.kind] || p.kind, "st-unknown"), h("strong", {}, p.device + " " + p.ifname), meter(p.confidence), h("span", { class: "muted" }, "confidence " + Math.round(p.confidence * 100) + "%"),
      p.status === "muted" ? chip("muted by " + (p.muted_by || "?"), "st-pending") : null, p.status === "materialized" ? chip("failure occurred", "st-down") : null),
    p.eta_ts ? h("p", { class: "eta" }, h("strong", {}, fmtEta(p)), " " + etaNote(p)) : h("p", { class: "muted" }, fmtEta(p)),
    h("p", {}, p.detail),
    p.cause ? h("p", { class: "cause" }, "\u21AA Likely cause: " + p.cause) : null,
    charts(m, [p]),
    h("h3", { class: "muted" }, "Evidence (what the model measured)"), h("div", { class: "tablewrap short" }, h("table", {}, h("tbody", {}, evRows))),
    h("p", { class: "muted small" }, "First flagged " + up(p.age_s) + " ago. Statistical analysis (robust baseline, Mann-Kendall trend test, Theil-Sen slope, CUSUM onset) - not a black box; every figure above is reproducible from the stored counters."),
    h("div", { class: "row" },
      h("button", { class: "primary", onclick: () => { close(); go("ai"); sendChat("Why is " + p.device + " " + p.ifname + " degrading and what should I do?"); } }, "\u2726 Ask AI"),
      can("operator") && p.status !== "muted" ? [hours, h("button", { onclick: () => act(async () => { await api("/api/predictions/" + id + "/mute", { method: "POST", body: { hours: Number(hours.value), reason: "acknowledged from UI" } }); close(); go("predictive"); }, "Muted") }, "Mute (known issue)")] : null,
      can("operator") && p.status === "muted" ? h("button", { onclick: () => act(async () => { await api("/api/predictions/" + id + "/unmute", { method: "POST" }); close(); go("predictive"); }, "Unmuted") }, "Unmute") : null));
  document.body.append(dr); dr.querySelector("button")?.focus();
}
async function ifaceDrawer(devId, dev, ifname, preds) {
  const m = await act(() => metricsFor(devId, ifname, 12)); if (!m) return;
  document.querySelector(".drawer")?.remove();
  const close = () => dr.remove();
  const dr = h("aside", { class: "drawer wide", role: "dialog", "aria-label": "Interface " + ifname },
    h("div", { class: "row" }, h("h2", { style: "margin:0" }, dev + " " + ifname), h("span", { class: "spacer" }), h("button", { onclick: close, "aria-label": "Close" }, "\u2715")),
    h("p", { class: "muted" }, "Last 12 hours, 5-minute samples" + (m.speed_bps ? " \u00B7 link speed " + fmtBps(m.speed_bps) : "")),
    m.predictions.length ? m.predictions.map(p => h("p", {}, sev(p.severity), " ", h("a", { href: "#predictive", onclick: e => { e.preventDefault(); predictionDrawer(p.id); } }, p.title))) : h("p", { class: "muted" }, "\u2713 No developing problems detected on this interface."),
    charts(m, m.predictions.map(p => ({ ...p, evidence: p.evidence }))));
  document.body.append(dr); dr.querySelector("button")?.focus();
}
PAGES.predictive = async () => {
  const [pr, hl, stt] = await Promise.all([api("/api/predictions"), api("/api/interfaces/health"), api("/api/predictions/stats")]);
  const items = pr.items, c = pr.counts;
  const hi = (c.by_severity.critical || 0) + (c.by_severity.high || 0);
  const tbl = items.length ? table(["Severity", "Device", "Interface", "Issue", "Confidence", "Expected impact", "Likely cause"],
    items.map(p => ({ p, cells: [sev(p.severity), h("strong", {}, p.device), p.ifname, h("span", {}, chip(KIND_LABEL[p.kind] || p.kind, "st-unknown"), " ", p.title, p.status === "muted" ? chip(" muted", "st-pending") : null), h("span", { class: "row" }, meter(p.confidence), Math.round(p.confidence * 100) + "%"), fmtEta(p) + (etaNote(p) ? " " + etaNote(p) : ""), p.cause ? p.cause.split(",")[0] : "-"] })), { click: r => predictionDrawer(r.p.id) })
    : h("p", { class: "muted" }, "\u2713 No developing problems detected. " + c.tracked_interfaces + " interfaces are being learned and watched.");
  const byDev = {}; hl.forEach(x => (byDev[x.device] = byDev[x.device] || []).push(x));
  const grid = h("div", { class: "ifgrid-wrap" }, Object.entries(byDev).map(([dev, ifs]) => h("div", { class: "ifdev" }, h("div", { class: "muted small" }, dev),
    h("div", { class: "ifgrid" }, ifs.map(x => h("button", { class: "ifcell risk-" + (x.up ? x.risk : "down"), title: x.device + " " + x.ifname + " \u00B7 " + (x.up ? "risk: " + x.risk : "link down") + (x.util != null ? " \u00B7 " + Math.round(x.util * 100) + "% util" : ""),
      "aria-label": x.device + " " + x.ifname + ", " + (x.up ? "risk " + x.risk : "link down"), onclick: () => ifaceDrawer(x.device_id, x.device, x.ifname) }, x.ifname.replace(/^(TenGigabitEthernet|Ethernet|ethernet|ether|port|eth)/, "").slice(0, 7) || x.ifname.slice(0, 6)))))));
  const legend = h("div", { class: "legend" }, [["ok", "healthy"], ["low", "low risk"], ["medium", "medium"], ["high", "high"], ["critical", "critical"], ["down", "link down"]].map(([k, l]) => h("span", {}, h("i", { class: "swatch risk-" + k }), l)));
  return h("div", { class: "grid" },
    h("div", { class: "grid kpis" }, kpi("Developing problems", c.active, hi ? hi + " high / critical" : "none urgent", hi ? "warn" : ""), kpi("Interfaces at risk", c.interfaces_at_risk, "of " + c.tracked_interfaces + " tracked"),
      kpi("Predictions that came true", stt.materialized, stt.median_lead_time_s != null ? "median warning " + (stt.median_lead_time_s >= 3600 ? (stt.median_lead_time_s / 3600).toFixed(1) + " h" : Math.round(stt.median_lead_time_s / 60) + " min") + " ahead" : "interface went down while flagged"),
      kpi("Cleared on their own", stt.cleared, "recovered / transient")),
    h("div", { class: "card" }, h("div", { class: "row" }, h("h3", { style: "margin:0" }, "Early warnings"), h("span", { class: "spacer" }), h("span", { class: "muted small" }, "Read-only: this page never changes a device")), tbl),
    h("div", { class: "card" }, h("h3", {}, "Interface health map"), legend, grid, h("p", { class: "muted small" }, "Click an interface for its last 12 hours of utilisation, errors, optical power and flaps.")),
    h("div", { class: "card" }, h("h3", {}, "How it predicts"), h("p", { class: "muted" }, "Every poll, OpenNetControl reads each interface's counters (bytes, errors, discards, link resets) and - where the port has a transceiver - its optical receive power. It learns a robust baseline per interface (including the daily rhythm once 26 h of history exist), tests for statistically significant trends, locates when a change started, and extrapolates to the moment a threshold would be crossed. A finding must persist for several minutes before it is shown. When both ends of a link degrade it points at the cable; when one end does, at the port or optic. It is statistical learning, not a language model, and it only advises."),
      role() === "admin" && S.ov && S.ov.demo ? h("p", { class: "muted small" }, "Demo: use the lab controls on Overview to fast-forward time and watch a prediction turn into a real outage.") : null));
};

PAGES.compliance = async () => {
  const c = await api("/api/compliance");
  const by = c.reduce((a, x) => (a[x.severity] = (a[x.severity] || 0) + 1, a), {});
  return h("div", { class: "grid" }, h("div", { class: "grid kpis" }, ["critical", "high", "medium", "low"].map(k => kpi(k, by[k] || 0, "findings"))),
    h("div", { class: "card" }, h("div", { class: "row" }, h("h3", { style: "margin:0" }, "Findings"), h("span", { class: "spacer" }), can("operator") ? h("button", { class: "primary", onclick: () => { go("ai"); sendChat("disable telnet on all devices"); } }, "\u2726 Propose telnet remediation") : null),
      table(["Severity", "Device", "Vendor", "Rule", "Detail"], c.map(x => ({ cells: [sev(x.severity), h("strong", {}, x.device), vend(x.vendor), x.rule, x.detail] })))));
};

PAGES.changes = async () => {
  const list = await api("/api/changes");
  const wrap = h("div", { class: "grid" });
  if (can("operator")) wrap.append(await newChangeCard());
  wrap.append(h("div", { class: "card" }, h("h3", {}, "Change requests"), list.length ? table(["#", "Status", "Summary", "Requester", "Approver", "Source", "Created"], list.map(c => ({ c, cells: [c.id, st(c.status), c.summary, c.requester, c.approver || "-", c.source, ago(c.created)] })), { click: r => changeDrawer(r.c.id) }) : h("p", { class: "muted" }, "No changes yet. Ask the AI assistant to propose one, or use the form above.")));
  return wrap;
};
async function newChangeCard() {
  const [ops, devs] = await Promise.all([api("/api/ops"), api("/api/devices")]);
  const sel = h("select", { "aria-label": "Operation" }, ops.map(o => h("option", { value: o.op }, o.desc + " [" + o.risk + "]")));
  const inputs = h("div", { class: "row" });
  const fields = {};
  const PH = { vlan_id: "VLAN id", vlan_name: "name", interface: "interface (e.g. Gi1/0/5)", description: "description", enabled: "true / false", prefix: "10.1.2.0/24", nexthop: "10.0.0.1", server: "10.0.0.123", ssid: "SSID" };
  const draw = () => { inputs.replaceChildren(); const op = ops.find(o => o.op === sel.value); Object.keys(fields).forEach(k => delete fields[k]); op.params.forEach(p => { const i = h("input", { placeholder: PH[p] || p, "aria-label": p, style: "flex:1;min-width:140px" }); fields[p] = i; inputs.append(i); }); };
  sel.addEventListener("change", draw); draw();
  const vsel = h("select", { multiple: true, size: 6, "aria-label": "Target devices" }, devs.map(d => h("option", { value: d.id }, d.name + " (" + (VN[d.vendor] || d.vendor) + ")")));
  return h("div", { class: "card" }, h("h3", {}, "New change request"), h("div", { class: "row" }, h("div", { style: "flex:1;min-width:240px" }, sel), h("div", { style: "flex:3;min-width:300px" }, inputs)),
    h("label", {}, "Targets (ctrl/cmd-click for multiple)"), vsel, h("div", { class: "row", style: "margin-top:10px" }, h("button", { class: "primary", onclick: () => act(async () => {
      const params = {}; Object.entries(fields).forEach(([k, i]) => { const v = i.value.trim(); params[k] = k === "enabled" ? v === "true" : (k === "vlan_id" ? (v === "" ? "" : Number(v)) : v); });
      const r = await api("/api/changes", { method: "POST", body: { op: sel.value, params, device_ids: [...vsel.selectedOptions].map(o => Number(o.value)) } }); go("changes"); changeDrawer(r.id);
    }, "Change proposed") }, "Preview & propose"), h("span", { class: "muted" }, "Nothing is applied until an administrator approves.")));
}
async function changeDrawer(id) {
  const c = await act(() => api("/api/changes/" + id)); if (!c) return;
  document.querySelector(".drawer")?.remove();
  const close = () => dr.remove(), reload = () => { close(); go("changes"); changeDrawer(id); };
  const res = Object.fromEntries((c.results || []).filter(r => r.device).map(r => [r.device, r]));
  const dr = h("aside", { class: "drawer", role: "dialog", "aria-label": "Change " + id },
    h("div", { class: "row" }, h("h2", { style: "margin:0" }, "Change #" + c.id), st(c.status), h("span", { class: "spacer" }), h("button", { onclick: close, "aria-label": "Close" }, "\u2715")),
    h("p", {}, c.summary), h("p", { class: "muted" }, "Requested by " + c.requester + " (" + c.source + ")" + (c.approver ? " \u00B7 decided by " + c.approver : "")),
    h("h3", { class: "muted" }, "Per-vendor execution plan"),
    c.plan.map(p => h("div", { class: "card", style: "margin:8px 0;padding:12px" }, h("div", { class: "row" }, h("strong", {}, p.name), vend(p.vendor), st(res[p.name] ? res[p.name].status : p.status), res[p.name] && res[p.name].rollback ? chip("rollback: " + res[p.name].rollback, "st-pending") : null),
      p.lines.length ? h("pre", {}, p.lines.join("\n")) : h("p", { class: "muted" }, p.reason || ""), res[p.name] && res[p.name].detail ? h("p", { class: "err" }, res[p.name].detail) : null)),
    h("div", { class: "row" },
      can("admin") && c.status === "pending" ? [h("button", { class: "primary", onclick: () => act(async () => { await api("/api/changes/" + id + "/approve", { method: "POST" }); reload(); }, "Approved") }, "Approve"), h("button", { class: "danger", onclick: () => act(async () => { await api("/api/changes/" + id + "/reject", { method: "POST" }); reload(); }, "Rejected") }, "Reject")] : null,
      can("admin") && c.status === "approved" ? h("button", { class: "primary", onclick: () => act(async () => { await api("/api/changes/" + id + "/execute", { method: "POST" }); reload(); }, "Execution finished") }, "Execute now") : null,
      can("admin") && c.status === "completed" ? h("button", { class: "danger", onclick: () => act(async () => { await api("/api/changes/" + id + "/rollback", { method: "POST" }); reload(); }, "Rolled back") }, "Roll back") : null),
    h("p", { class: "muted" }, "Safety: four-eyes approval \u2192 pre-change config snapshot \u2192 apply \u2192 verify \u2192 automatic rollback on any failure (all-or-nothing across devices)."));
  document.body.append(dr); dr.querySelector("button")?.focus();
}

// ---------------------------------------------------------------- AI assistant
const SUGG = ["What is wrong right now?", "Which devices are unreachable?", "Which devices still have telnet enabled?", "Show all Fortinet and Palo Alto firewalls",
  "Create VLAN 120 named guests on all Aruba switches", "Block IP 203.0.113.9 on all firewalls", "Disable telnet on all MikroTik devices", "Reload all devices"];
function chatNode(m) {
  if (m.role === "u") return h("div", { class: "msg u" }, m.text);
  const n = h("div", { class: "msg a" }, md(m.reply || m.text || ""));
  if (m.table && m.table.rows.length) n.append(table(m.table.columns, m.table.rows.map(r => ({ cells: r.map(x => ["up", "DOWN", "down", "planned", "blocked", "skipped"].includes(x) ? st(x === "DOWN" ? "down" : x) : ["critical", "high", "medium", "low"].includes(x) ? sev(x) : String(x)) }))));
  if (m.change_id) n.append(h("div", { class: "row", style: "margin-top:8px" }, h("button", { class: "primary", onclick: () => changeDrawer(m.change_id) }, "Review change #" + m.change_id)));
  if (m.steps && m.steps.length) n.append(h("div", { class: "steps" }, h("div", { class: "muted" }, "Agent steps"), m.steps.map(s => h("div", {}, s.tool + ": " + s.summary))));
  return n;
}
let msgsBox = null;
async function sendChat(text) {
  S.chat.push({ role: "u", text }); const thinking = { role: "a", text: "Thinking\u2026" }; S.chat.push(thinking); paintChat();
  try { const r = await api("/api/ai/chat", { method: "POST", body: { message: text } }); S.chat[S.chat.indexOf(thinking)] = { role: "a", ...r }; }
  catch (e) { S.chat[S.chat.indexOf(thinking)] = { role: "a", text: "Error: " + e.message }; }
  paintChat();
}
function paintChat() { if (!msgsBox || !document.body.contains(msgsBox)) return; msgsBox.replaceChildren(...S.chat.map(chatNode)); msgsBox.scrollTop = msgsBox.scrollHeight; }
PAGES.ai = async () => {
  msgsBox = h("div", { class: "msgs", "aria-live": "polite" });
  if (!S.chat.length) S.chat.push({ role: "a", reply: "Hi, I'm your network operations assistant. I can see the whole estate (Cisco, Fortinet, Palo Alto, MikroTik, Ruckus, Aruba), investigate incidents and **propose** changes. Type **help** to see what I can do." });
  const inp = h("input", { placeholder: "Ask about devices, incidents, compliance\u2026 or request a change", "aria-label": "Message", maxlength: 1000 });
  const send = () => { if (inp.value.trim()) { const q = inp.value; inp.value = ""; sendChat(q); } };
  inp.addEventListener("keydown", e => { if (e.key === "Enter") send(); });
  const w = h("div", { class: "chat" }, h("div", { class: "chips" }, SUGG.map(q => h("button", { onclick: () => sendChat(q) }, q))), msgsBox, h("div", { class: "composer" }, inp, h("button", { class: "primary", onclick: send }, "Send")));
  setTimeout(() => { paintChat(); inp.focus(); }, 0);
  return w;
};

PAGES.platforms = async () => {
  const [v, ops] = await Promise.all([api("/api/vendors"), api("/api/ops")]);
  return h("div", { class: "card" }, h("h3", {}, "Native platform support & capability matrix"), h("p", { class: "muted" }, "Every operation is rendered by a vendor driver into native CLI. Unsupported combinations are skipped, never guessed."),
    h("div", { class: "tablewrap" }, h("table", { class: "matrix" }, h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Platform"), ops.map(o => h("th", { scope: "col", title: o.desc }, o.op.replace(/_/g, " "))))),
      h("tbody", {}, v.map(p => h("tr", {}, h("td", {}, vend(p.vendor), " ", p.label), ops.map(o => h("td", { class: p.capabilities.includes(o.op) ? "yes" : "no", "aria-label": p.capabilities.includes(o.op) ? "supported" : "not supported" }, p.capabilities.includes(o.op) ? "\u2713" : "\u2013"))))))));
};

PAGES.audit = async () => {
  if (!can("admin")) return h("div", { class: "card" }, h("p", { class: "muted" }, "The audit log is visible to administrators only."));
  const [a, v] = await Promise.all([api("/api/audit?limit=300"), api("/api/audit/verify")]);
  return h("div", { class: "card" }, h("div", { class: "row" }, h("h3", { style: "margin:0" }, "Tamper-evident audit log"), h("span", { class: "spacer" }), chip(v.ok ? "hash chain verified \u2713" : "CHAIN BROKEN at #" + v.broken_at, v.ok ? "st-approved" : "st-failed")),
    table(["#", "Time", "Actor", "Action", "Detail"], a.map(r => ({ cells: [r.id, new Date(r.ts * 1000).toLocaleString(), r.actor, r.action, h("span", { class: "mono" }, r.detail.slice(0, 160))] }))));
};

document.addEventListener("keydown", e => { if (e.key === "Escape") { const d = document.querySelector(".drawer"); if (d) { d.remove(); document.getElementById("content")?.focus(); } } });
window.addEventListener("hashchange", () => { const p = location.hash.replace("#", ""); if (S.user && p !== S.page && Object.hasOwn(PAGES, p)) go(p); });
if (S.token) boot(); else renderLogin();
})();
