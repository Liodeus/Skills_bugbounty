"use strict";
const SEVS = ["critical", "high", "medium", "low", "info"];
const SEVHEX = { critical: "#ff4d4f", high: "#ff7a45", medium: "#ffc53d", low: "#40a9ff", info: "#8c8c8c" };
const $ = (s, r = document) => r.querySelector(s);
const view = $("#view");
window.__tbl = {};

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cost = (n) => "$" + Number(n || 0).toFixed(2);
const shortTime = (s) => (s ? String(s).replace("T", " ").replace("Z", "").slice(0, 16) : "—");
async function api(p) { const r = await fetch(p); if (!r.ok) throw new Error(p + " " + r.status); return r.json(); }
const sevChip = (s) => `<span class="chip sev-${esc(s)}">${esc(s)}</span>`;

function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast"; t.textContent = msg;
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

/* ---- modal (report viewer) ---- */
function openModal(title, html) {
  let m = $("#modal");
  if (!m) { m = document.createElement("div"); m.id = "modal"; document.body.appendChild(m); }
  m.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;z-index:60";
  m.innerHTML = `<div style="margin:auto;max-width:900px;width:92%;max-height:88vh;overflow:auto;background:#161b22;border:1px solid #2a3140;border-radius:12px;padding:22px">
    <div style="display:flex;align-items:center;margin-bottom:10px"><b>${esc(title)}</b><span style="flex:1"></span><button id="mclose" style="background:#1c2230;color:#e6edf3;border:1px solid #2a3140;border-radius:6px;cursor:pointer;padding:3px 10px">✕</button></div>
    <div class="md">${html}</div></div>`;
  m.onclick = (e) => { if (e.target === m || e.target.id === "mclose") m.remove(); };
}
async function showReport(slug, filename) {
  try { const d = await api(`/api/report/${encodeURIComponent(slug)}/${encodeURIComponent(filename)}`); openModal(filename, d.html); }
  catch { toast("report not found"); }
}
window.showReport = showReport;

/* ---- generic sortable table ---- */
function sortableTable(mount, cols, rows, key) {
  const st = (window.__tbl[key] ||= { sort: null, dir: 1 });
  function draw() {
    let data = rows.slice();
    if (st.sort) {
      const c = cols.find((x) => x.key === st.sort);
      data.sort((a, b) => { const av = c.val ? c.val(a) : a[c.key], bv = c.val ? c.val(b) : b[c.key]; return (av > bv ? 1 : av < bv ? -1 : 0) * st.dir; });
    }
    const thead = cols.map((c) => `<th class="${c.num ? "num" : ""}" data-k="${c.key}">${esc(c.label)}${st.sort === c.key ? (st.dir > 0 ? " ▲" : " ▼") : ""}</th>`).join("");
    const body = data.map((r) => "<tr>" + cols.map((c) => `<td class="${c.num ? "num" : ""}">${c.html ? c.html(r) : esc(r[c.key] ?? "")}</td>`).join("") + "</tr>").join("");
    mount.innerHTML = `<table><thead><tr>${thead}</tr></thead><tbody>${body}</tbody></table>` + (data.length ? "" : '<div class="empty">no rows</div>');
    mount.querySelectorAll("th").forEach((th) => th.onclick = () => { const k = th.dataset.k; if (st.sort === k) st.dir *= -1; else { st.sort = k; st.dir = 1; } draw(); });
  }
  draw();
}

/* ---- views ---- */
async function vOverview() {
  const o = await api("/api/overview");
  const mat = await api("/api/severity-matrix");
  const sev = o.findings_by_severity || {};
  const cards = [
    ["Programs", `${o.programs_hunted}/${o.programs_total}`, "hunted/total"],
    ["Findings", o.findings_total, "verified"],
    ["Open leads", o.open_leads, "for review"],
    ["Spent", cost(o.total_cost_usd), "total"],
    ["Monitor alerts", o.monitor_alerts, ""],
    ["Last run", shortTime(o.last_run), ""],
  ];
  let html = `<div class="cards">${cards.map((c) => `<div class="card"><div class="k">${esc(c[0])}</div><div class="v">${esc(c[1])}</div><div class="muted">${esc(c[2])}</div></div>`).join("")}</div>`;
  if (o.stop) html += `<div class="panel" style="border-color:var(--crit)">🛑 STOP sentinel present — the loop is halted.</div>`;
  html += `<div class="panel"><h3>Findings by severity</h3>` +
    SEVS.map((s) => `${sevChip(s)} <b>${sev[s] || 0}</b>`).join(" &nbsp; ") + `</div>`;
  // heatmap
  html += `<div class="panel"><h3>Severity heatmap (program × severity)</h3>`;
  if (!mat.length) html += `<div class="empty">no findings yet</div>`;
  else {
    html += `<table class="heat"><thead><tr><th class="lab">Program</th>${SEVS.map((s) => `<th>${s}</th>`).join("")}</tr></thead><tbody>` +
      mat.map((r) => `<tr><td class="lab"><a href="#/program/${encodeURIComponent(r.slug)}">${esc(r.slug)}</a></td>` +
        SEVS.map((s) => { const n = r[s] || 0; const bg = n ? SEVHEX[s] + "44" : "transparent"; return `<td style="background:${bg}">${n || ""}</td>`; }).join("") + `</tr>`).join("") +
      `</tbody></table>`;
  }
  html += `</div><div class="panel"><h3>Live activity</h3><div id="feed" class="logbox" style="height:160px"></div></div>`;
  view.innerHTML = html;
  renderFeed();
}

async function vPrograms() {
  const rows = await api("/api/programs");
  view.innerHTML = `<div class="filters"><input id="q" placeholder="filter programs…"/></div><div id="tbl"></div>`;
  const cols = [
    { key: "title", label: "Program", html: (r) => `<a href="#/program/${encodeURIComponent(r.slug)}">${esc(r.title)}</a>` },
    { key: "type", label: "Type", html: (r) => `<span class="chip">${r.bounty ? "BBP" : "VDP"}</span>` },
    { key: "bounty_max", label: "Max $", num: true },
    { key: "hosts", label: "Hosts", num: true },
    { key: "status", label: "Status", html: (r) => `<span class="st-${esc(r.status)}">${esc(r.status)}</span>` },
    { key: "findings", label: "Findings", num: true },
    { key: "open_leads", label: "Leads", num: true },
    { key: "cost", label: "Cost", num: true, html: (r) => cost(r.cost), val: (r) => r.cost },
    { key: "last_run", label: "Last run", html: (r) => shortTime(r.last_run) },
  ];
  const draw = (q) => sortableTable($("#tbl"), cols, q ? rows.filter((r) => (r.title + r.slug).toLowerCase().includes(q.toLowerCase())) : rows, "programs");
  $("#q").oninput = (e) => draw(e.target.value);
  draw("");
}

async function vProgram(slug) {
  let d; try { d = await api(`/api/programs/${encodeURIComponent(slug)}`); } catch { view.innerHTML = `<div class="empty">program not found</div>`; return; }
  const tabs = ["Overview", "Scope", "Recon", "Leads", "Findings", "Runs", "Monitor"];
  view.innerHTML = `<h2 style="margin:0 0 4px">${esc(d.slug)}</h2>
    <div class="tabs">${tabs.map((t, i) => `<button data-t="${t}" class="${i === 0 ? "active" : ""}">${t}</button>`).join("")}</div>
    <div id="tabc"></div>`;
  const c = $("#tabc");
  const draw = (t) => {
    if (t === "Overview") c.innerHTML = `<div class="panel md">${d.program_html || "<div class='empty'>no description</div>"}</div>`;
    else if (t === "Scope") c.innerHTML = scopeTbl("In scope", d.scopes, true) + scopeTbl("Out of scope", d.out_of_scope, false);
    else if (t === "Recon") c.innerHTML = reconView(d.recon);
    else if (t === "Leads") c.innerHTML = listView(d.leads, leadCols(false), "no leads");
    else if (t === "Findings") c.innerHTML = findingsView(d.findings, d.slug);
    else if (t === "Runs") c.innerHTML = runsView(d.runs);
    else if (t === "Monitor") c.innerHTML = monitorView(d.monitor_baseline);
    c.querySelectorAll("[data-report]").forEach((b) => b.onclick = () => showReport(d.slug, b.dataset.report));
  };
  view.querySelectorAll(".tabs button").forEach((b) => b.onclick = () => {
    view.querySelectorAll(".tabs button").forEach((x) => x.classList.remove("active")); b.classList.add("active"); draw(b.dataset.t);
  });
  draw("Overview");
}

function scopeTbl(title, items, isIn) {
  const rows = (items || []).map((s) => typeof s === "string" ? { scope: s } : s);
  if (!rows.length) return `<div class="panel"><h3>${esc(title)}</h3><div class="empty">none</div></div>`;
  const body = rows.map((s) => `<tr><td class="mono">${esc(s.scope || "")}</td><td>${esc(s.scope_type_name || s.scope_type || "")}</td>${isIn ? `<td>${esc(s.asset_value || "")}</td>` : ""}</tr>`).join("");
  return `<div class="panel"><h3>${esc(title)} (${rows.length})</h3><table><thead><tr><th>Asset</th><th>Type</th>${isIn ? "<th>Criticality</th>" : ""}</tr></thead><tbody>${body}</tbody></table></div>`;
}
function reconView(r) {
  r = r || {};
  const blk = (label, arr) => `<div class="panel"><h3>${esc(label)} (${(arr || []).length})</h3>${(arr || []).length ? `<div class="mono" style="max-height:280px;overflow:auto">${(arr || []).map(esc).join("<br>")}</div>` : '<div class="empty">none</div>'}</div>`;
  return blk("Live hosts", r.live_hosts) + blk("Endpoints", r.endpoints) + blk("JS files", r.js_files) + blk("Params", r.params) + blk("Tech", r.tech);
}
function runsView(runs) {
  if (!runs || !runs.length) return `<div class="empty">no runs yet</div>`;
  const body = runs.slice().reverse().map((r) => `<tr><td>${shortTime(r.finished_at || r.started_at)}</td><td>${esc(r.mode || "")}</td><td class="st-${esc(r.status)}">${esc(r.status || "")}</td><td>${esc(r.subtype || "")}</td><td class="num">${r.findings_count ?? "—"}</td><td class="num">${r.leads_count ?? "—"}</td><td class="num">${cost(r.total_cost_usd)}</td></tr>`).join("");
  return `<div class="panel"><table><thead><tr><th>When</th><th>Mode</th><th>Status</th><th>Subtype</th><th class="num">Findings</th><th class="num">Leads</th><th class="num">Cost</th></tr></thead><tbody>${body}</tbody></table></div>`;
}
function monitorView(base) {
  const urls = Object.keys(base || {});
  if (!urls.length) return `<div class="empty">no monitor baseline yet (run --monitor)</div>`;
  const body = urls.map((u) => `<tr><td class="mono">${esc(u)}</td><td class="num">${esc(base[u].status)}</td><td class="mono">${esc(base[u].hash)}</td><td>${shortTime(base[u].checked_at)}</td></tr>`).join("");
  return `<div class="panel"><h3>Monitor baseline (${urls.length})</h3><table><thead><tr><th>URL</th><th class="num">Status</th><th>Body hash</th><th>Checked</th></tr></thead><tbody>${body}</tbody></table></div>`;
}
function findingsView(items, slug) {
  if (!items || !items.length) return `<div class="empty">no verified findings</div>`;
  const body = items.map((f) => `<tr><td>${sevChip((f.severity || "info").toLowerCase())}</td><td>${esc(f.title || "")}</td><td>${esc((f.dedupe_key || "").split(":")[0])}</td><td>${f.report_path ? `<button data-report="${esc(f.report_path)}" style="cursor:pointer;background:#1c2230;color:#e6edf3;border:1px solid #2a3140;border-radius:5px;padding:2px 8px">report</button>` : "—"}</td></tr>`).join("");
  return `<div class="panel"><table><thead><tr><th>Severity</th><th>Title</th><th>Class</th><th>Report</th></tr></thead><tbody>${body}</tbody></table></div>`;
}
function listView(items, cols, emptyMsg) {
  if (!items || !items.length) return `<div class="empty">${esc(emptyMsg)}</div>`;
  const body = items.map((r) => "<tr>" + cols.map((c) => `<td>${c.html ? c.html(r) : esc(r[c.key] ?? "")}</td>`).join("") + "</tr>").join("");
  return `<div class="panel"><table><thead><tr>${cols.map((c) => `<th>${esc(c.label)}</th>`).join("")}</tr></thead><tbody>${body}</tbody></table></div>`;
}
function leadCols(withProgram) {
  const cols = [
    { key: "priority", label: "Prio", html: (r) => `<span class="chip">${esc(r.priority || "")}</span>` },
    { key: "status", label: "Status", html: (r) => `<span class="chip">${esc(r.status || "")}</span>` },
    { key: "vuln_class", label: "Class" },
    { key: "title", label: "Title" },
    { key: "asset", label: "Asset", html: (r) => `<span class="mono">${esc(r.asset || "")}</span>` },
    { key: "endpoint", label: "Endpoint", html: (r) => `<span class="mono">${esc(r.endpoint || "")}</span>` },
  ];
  if (withProgram) cols.push({ key: "slug", label: "Program", html: (r) => `<a href="#/program/${encodeURIComponent(r.slug)}">${esc(r.slug)}</a>` });
  return cols;
}

async function vFindings() {
  const all = await api("/api/findings");
  view.innerHTML = `<div class="filters">
    <select id="sev"><option value="">all severities</option>${SEVS.map((s) => `<option>${s}</option>`).join("")}</select>
    <input id="q" placeholder="filter…"/></div><div id="tbl"></div>`;
  const cols = [
    { key: "severity", label: "Severity", html: (r) => sevChip(r.severity), val: (r) => SEVS.indexOf(r.severity) },
    { key: "title", label: "Title" },
    { key: "vuln_class", label: "Class" },
    { key: "slug", label: "Program", html: (r) => `<a href="#/program/${encodeURIComponent(r.slug)}">${esc(r.slug)}</a>` },
    { key: "first_seen", label: "First seen", html: (r) => shortTime(r.first_seen) },
    { key: "report_path", label: "Report", html: (r) => r.report_path ? `<a href="#" onclick="showReport('${esc(r.slug)}','${esc(r.report_path)}');return false">report</a>` : "—" },
  ];
  const draw = () => {
    const sv = $("#sev").value, q = $("#q").value.toLowerCase();
    let rows = all.filter((r) => (!sv || r.severity === sv) && (!q || (r.title + r.slug + r.vuln_class).toLowerCase().includes(q)));
    sortableTable($("#tbl"), cols, rows, "findings");
  };
  $("#sev").onchange = draw; $("#q").oninput = draw; draw();
}

async function vLeads() {
  const all = await api("/api/leads");
  view.innerHTML = `<div class="filters">
    <select id="stt"><option value="">all statuses</option>${["open", "hunted", "reported", "dismissed"].map((s) => `<option>${s}</option>`).join("")}</select>
    <input id="q" placeholder="filter…"/></div><div id="tbl"></div>`;
  const cols = leadCols(true);
  const draw = () => {
    const stt = $("#stt").value, q = $("#q").value.toLowerCase();
    let rows = all.filter((r) => (!stt || r.status === stt) && (!q || JSON.stringify(r).toLowerCase().includes(q)));
    sortableTable($("#tbl"), cols, rows, "leads");
  };
  $("#stt").onchange = draw; $("#q").oninput = draw; draw();
}

function barRows(items, label, valfn, fmt) {
  const max = Math.max(1, ...items.map(valfn));
  return `<div class="panel"><h3>${esc(label)}</h3><div class="bars">` + items.map((it) => {
    const v = valfn(it); return `<div class="bar-row"><div>${esc(it.name || it.slug || it.day)}</div><div class="bar-track"><div class="bar-fill" style="width:${(v / max * 100).toFixed(1)}%"></div></div><div class="num">${fmt(v, it)}</div></div>`;
  }).join("") + `</div></div>`;
}
async function vCost() {
  const c = await api("/api/cost");
  let html = `<div class="cards"><div class="card"><div class="k">Total spent</div><div class="v">${cost(c.total)}</div></div></div>`;
  html += c.by_phase.length ? barRows(c.by_phase, "By phase ($)", (x) => x.cost, (v, it) => `${cost(v)} · ${it.n} calls`) : "";
  html += (c.by_model && c.by_model.length) ? barRows(c.by_model, "By model ($)", (x) => x.cost, (v) => cost(v)) : "";
  html += c.by_program.length ? barRows(c.by_program, "By program ($)", (x) => x.cost, (v) => cost(v)) : "";
  html += c.by_day.length ? barRows(c.by_day, "Over time ($/day)", (x) => x.cost, (v) => cost(v)) : "";
  view.innerHTML = html || `<div class="empty">no cost data yet</div>`;
}

async function vChanges() {
  const c = await api("/api/changes");
  let html = `<div class="panel"><h3>Monitor alerts (${c.monitor_alerts.length})</h3>`;
  html += c.monitor_alerts.length ? `<table><thead><tr><th>When</th><th>Program</th><th>URL</th><th>Guess</th><th>Reason</th></tr></thead><tbody>` +
    c.monitor_alerts.map((a) => `<tr><td>${shortTime(a.ts)}</td><td>${esc(a.slug)}</td><td class="mono">${esc(a.url)}</td><td>${esc(a.severity_guess || "")}</td><td>${esc(a.reason || "")}</td></tr>`).join("") + `</tbody></table>` : `<div class="empty">none</div>`;
  html += `</div><div class="panel"><h3>Scope changes (catalog)</h3><div class="md">${c.scope_changes_html || "<div class='empty'>none</div>"}</div></div>`;
  view.innerHTML = html;
}

function vLog() {
  view.innerHTML = `<div class="panel"><h3>run.log (live)</h3><div id="logbox" class="logbox"></div></div>`;
  renderLog();
}

/* ---- live streams ---- */
const logBuf = [];
function renderLog() { const b = $("#logbox"); if (b) { b.textContent = logBuf.join("\n"); b.scrollTop = b.scrollHeight; } }
function renderFeed() { const f = $("#feed"); if (f) { f.textContent = logBuf.slice(-40).join("\n"); f.scrollTop = f.scrollHeight; } }

let lastToast = 0;
function initStreams() {
  const ev = new EventSource("/api/stream/events");
  ev.onopen = () => { $("#dot").className = "dot on"; $("#connlabel").textContent = "live"; };
  ev.onerror = () => { $("#dot").className = "dot off"; $("#connlabel").textContent = "reconnecting…"; };
  ev.addEventListener("update", (e) => {
    $("#updated").textContent = "updated " + new Date().toLocaleTimeString();
    if (Date.now() - lastToast > 3000) { toast("data updated — refreshing"); lastToast = Date.now(); }
    render();
  });
  const lg = new EventSource("/api/stream/log");
  lg.onmessage = (e) => {
    let line; try { line = JSON.parse(e.data); } catch { line = e.data; }
    logBuf.push(line); if (logBuf.length > 1000) logBuf.shift();
    renderLog(); renderFeed();
  };
}

/* ---- router ---- */
const ROUTES = { overview: vOverview, programs: vPrograms, program: vProgram, findings: vFindings, leads: vLeads, cost: vCost, changes: vChanges, log: vLog };
async function render() {
  const h = (location.hash || "#/overview").slice(2).split("/");
  const name = h[0] || "overview";
  const fn = ROUTES[name] || vOverview;
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === name));
  $("#crumb").textContent = name[0].toUpperCase() + name.slice(1) + (h[1] ? " · " + decodeURIComponent(h[1]) : "");
  try { await fn(h[1] ? decodeURIComponent(h[1]) : undefined); }
  catch (e) { view.innerHTML = `<div class="empty">error: ${esc(e.message)}</div>`; }
}
window.addEventListener("hashchange", render);
$("#refresh").onclick = render;
if (!location.hash) location.hash = "#/overview";
render();
initStreams();
