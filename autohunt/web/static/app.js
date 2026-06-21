"use strict";
const SEVS = ["critical", "high", "medium", "low", "info"];
const SEVHEX = { critical: "#ff4d4f", high: "#ff7a45", medium: "#ffc53d", low: "#40a9ff", info: "#8c8c8c" };
const $ = (s, r = document) => r.querySelector(s);
const view = $("#view");
const main = $(".main");

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cost = (n) => "$" + Number(n || 0).toFixed(2);
const shortTime = (s) => (s ? String(s).replace("T", " ").replace("Z", "").slice(0, 16) : "—");
const sevChip = (s) => `<span class="chip sev-${esc(s)}">${esc(s)}</span>`;
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
async function api(p) { const r = await fetch(p); if (!r.ok) throw new Error(p + " → " + r.status); return r.json(); }

/* ---- transient UI state that survives live refresh ---- */
const ST = { filters: {}, sort: {}, tab: {} };
const fbucket = () => (ST.filters[location.hash] ||= {});
const getF = (id, def = "") => { const b = fbucket(); return id in b ? b[id] : def; };
const setF = (id, v) => { fbucket()[id] = v; };

/* ---- toasts (errors / notices only) ---- */
function toast(msg, isErr) {
  const t = document.createElement("div");
  t.className = "toast" + (isErr ? " err" : "");
  t.textContent = msg;
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

/* ---- accessible modal (report viewer) ---- */
let lastFocus = null;
function escClose(e) { if (e.key === "Escape") closeModal(); }
function closeModal() {
  const m = $("#modal");
  if (m) { m.remove(); document.removeEventListener("keydown", escClose); if (lastFocus && lastFocus.focus) lastFocus.focus(); }
}
function openModal(title, html) {
  closeModal();
  lastFocus = document.activeElement;
  const bd = document.createElement("div");
  bd.className = "modal-bd"; bd.id = "modal";
  bd.innerHTML = `<div class="modal-box" role="dialog" aria-modal="true" aria-label="${esc(title)}">
    <div class="modal-head"><b>${esc(title)}</b><span class="spacer"></span>
    <button class="tbtn" id="mclose" aria-label="Close">✕</button></div>
    <div class="md">${html}</div></div>`;
  document.body.appendChild(bd);
  bd.addEventListener("click", (e) => { if (e.target === bd || e.target.id === "mclose") closeModal(); });
  document.addEventListener("keydown", escClose);
  const c = $("#mclose", bd); if (c) c.focus();
}
async function showReport(slug, filename) {
  try { const d = await api(`/api/report/${encodeURIComponent(slug)}/${encodeURIComponent(filename)}`); openModal(filename, d.html); }
  catch { toast("report not found", true); }
}
window.showReport = showReport;

/* ---- sortable table (keyboard + a11y), returns rendered row count ---- */
function sortableTable(mount, cols, rows, key) {
  const st = (ST.sort[key] ||= { sort: null, dir: 1 });
  function draw() {
    let data = rows.slice();
    if (st.sort) {
      const c = cols.find((x) => x.key === st.sort);
      if (c) data.sort((a, b) => { const av = c.val ? c.val(a) : a[c.key], bv = c.val ? c.val(b) : b[c.key]; return (av > bv ? 1 : av < bv ? -1 : 0) * st.dir; });
    }
    const thead = cols.map((c) => {
      const s = st.sort === c.key ? (st.dir > 0 ? "ascending" : "descending") : "none";
      return `<th ${c.num ? 'class="num" ' : ""}data-k="${c.key}" tabindex="0" role="button" aria-sort="${s}">${esc(c.label)}${st.sort === c.key ? (st.dir > 0 ? " ▲" : " ▼") : ""}</th>`;
    }).join("");
    const body = data.map((r) => "<tr>" + cols.map((c) => `<td${c.num ? ' class="num"' : ""}>${c.html ? c.html(r) : esc(r[c.key] ?? "")}</td>`).join("") + "</tr>").join("");
    mount.innerHTML = `<div class="tablewrap"><table><thead><tr>${thead}</tr></thead><tbody>${body}</tbody></table></div>` + (data.length ? "" : '<div class="empty">no rows match</div>');
    mount.querySelectorAll("th[data-k]").forEach((th) => {
      const sort = () => { const k = th.dataset.k; if (st.sort === k) st.dir *= -1; else { st.sort = k; st.dir = 1; } draw(); };
      th.onclick = sort;
      th.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sort(); } };
    });
  }
  draw();
  return rows.length;
}

/* helper: a filter bar with persistent state + live count */
function filterBar(inner) { return `<div class="filters">${inner}<span class="count" id="cnt"></span></div>`; }
function setCount(n, total) { const c = $("#cnt"); if (c) c.textContent = total === undefined ? `${n} rows` : `${n} / ${total}`; }

/* ---- views ---- */
async function vOverview() {
  const [o, mat] = await Promise.all([api("/api/overview"), api("/api/severity-matrix")]);
  const sev = o.findings_by_severity || {};
  const cards = [
    ["Programs", `${o.programs_hunted}/${o.programs_total}`, "hunted / total"],
    ["Findings", o.findings_total, "verified"],
    ["Open leads", o.open_leads, "for review"],
    ["Spent", cost(o.total_cost_usd), "estimate"],
    ["Monitor alerts", o.monitor_alerts, ""],
    ["Last run", shortTime(o.last_run), ""],
  ];
  let html = `<div class="cards">${cards.map((c) => `<div class="card"><div class="k">${esc(c[0])}</div><div class="v">${esc(c[1])}</div><div class="muted">${esc(c[2])}</div></div>`).join("")}</div>`;
  if (o.stop) html += `<div class="panel" style="border-color:var(--crit)">🛑 <b>STOP sentinel present</b> — the loop is halted (<code>data/hunts/STOP</code>).</div>`;
  html += `<div class="panel"><h3>Findings by severity</h3><div style="display:flex;gap:14px;flex-wrap:wrap;align-items:center">` +
    SEVS.map((s) => `<span>${sevChip(s)} <b>${sev[s] || 0}</b></span>`).join("") + `</div></div>`;
  html += `<div class="panel scroll"><h3>Severity heatmap (program × severity)</h3>`;
  if (!mat.length) html += `<div class="empty">no findings yet</div>`;
  else html += `<table class="heat"><thead><tr><th class="lab">Program</th>${SEVS.map((s) => `<th>${s}</th>`).join("")}</tr></thead><tbody>` +
    mat.map((r) => `<tr><td class="lab"><a href="#/program/${encodeURIComponent(r.slug)}">${esc(r.slug)}</a></td>` +
      SEVS.map((s) => { const n = r[s] || 0; return n ? `<td style="background:${SEVHEX[s]}33">${n}</td>` : `<td class="z">·</td>`; }).join("") + `</tr>`).join("") + `</tbody></table>`;
  html += `</div><div class="panel"><h3>Live activity (run.log)</h3><div id="feed" class="logbox" style="height:170px"></div></div>`;
  view.innerHTML = html;
  renderFeed();
}

async function vPrograms() {
  const rows = await api("/api/programs");
  view.innerHTML = filterBar(`<input id="q" placeholder="filter programs…" />`) + `<div id="tbl"></div>`;
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
  const q = $("#q"); q.value = getF("q");
  const draw = () => {
    const term = q.value.toLowerCase(); setF("q", q.value);
    const f = term ? rows.filter((r) => (r.title + r.slug).toLowerCase().includes(term)) : rows;
    sortableTable($("#tbl"), cols, f, "programs"); setCount(f.length, rows.length);
  };
  q.oninput = debounce(draw, 120); draw();
}

async function vProgram(slug) {
  let d; try { d = await api(`/api/programs/${encodeURIComponent(slug)}`); }
  catch { view.innerHTML = `<div class="empty">program not found</div>`; return; }
  const tabs = ["Overview", "Scope", "Recon", "Leads", "Findings", "Runs", "Monitor"];
  const cur = ST.tab[slug] && tabs.includes(ST.tab[slug]) ? ST.tab[slug] : "Overview";
  view.innerHTML = `<div class="tabs" role="tablist">${tabs.map((t) => `<button data-t="${t}" class="${t === cur ? "active" : ""}" role="tab" aria-selected="${t === cur}">${t}</button>`).join("")}</div><div id="tabc"></div>`;
  const c = $("#tabc");
  const draw = (t) => {
    ST.tab[slug] = t;
    if (t === "Overview") c.innerHTML = `<div class="panel md">${d.program_html || "<div class='empty'>no description</div>"}</div>`;
    else if (t === "Scope") c.innerHTML = scopeTbl("In scope", d.scopes, true) + scopeTbl("Out of scope", d.out_of_scope, false);
    else if (t === "Recon") c.innerHTML = reconView(d.recon);
    else if (t === "Leads") c.innerHTML = listView(d.leads, leadCols(false), "no leads recorded yet");
    else if (t === "Findings") c.innerHTML = findingsView(d.findings);
    else if (t === "Runs") c.innerHTML = runsView(d.runs);
    else if (t === "Monitor") c.innerHTML = monitorView(d.monitor_baseline);
    c.querySelectorAll("[data-report]").forEach((b) => b.onclick = () => showReport(slug, b.dataset.report));
  };
  view.querySelectorAll(".tabs button").forEach((b) => b.onclick = () => {
    view.querySelectorAll(".tabs button").forEach((x) => { x.classList.remove("active"); x.setAttribute("aria-selected", "false"); });
    b.classList.add("active"); b.setAttribute("aria-selected", "true"); draw(b.dataset.t);
  });
  draw(cur);
}

function scopeTbl(title, items, isIn) {
  const rows = (items || []).map((s) => typeof s === "string" ? { scope: s } : s);
  if (!rows.length) return `<div class="panel"><h3>${esc(title)}</h3><div class="empty">none</div></div>`;
  const body = rows.map((s) => `<tr><td class="mono">${esc(s.scope || "")}</td><td>${esc(s.scope_type_name || s.scope_type || "")}</td>${isIn ? `<td>${esc(s.asset_value || "")}</td>` : ""}</tr>`).join("");
  return `<div class="panel scroll"><h3>${esc(title)} (${rows.length})</h3><div class="tablewrap"><table><thead><tr><th>Asset</th><th>Type</th>${isIn ? "<th>Criticality</th>" : ""}</tr></thead><tbody>${body}</tbody></table></div></div>`;
}
function reconView(r) {
  r = r || {};
  const blk = (label, arr) => `<div class="panel"><h3>${esc(label)} (${(arr || []).length})</h3>${(arr || []).length ? `<div class="mono" style="max-height:300px;overflow:auto">${(arr || []).map(esc).join("<br>")}</div>` : '<div class="empty">none</div>'}</div>`;
  return blk("Suggested focus", r.suggested_focus) + blk("Live hosts", r.live_hosts) + blk("Endpoints", r.endpoints) + blk("JS files", r.js_files) + blk("Params", r.params) + blk("Tech", r.tech);
}
function runsView(runs) {
  if (!runs || !runs.length) return `<div class="empty">no runs yet</div>`;
  const body = runs.slice().reverse().map((r) => `<tr><td>${shortTime(r.finished_at || r.started_at)}</td><td><span class="chip">${esc(r.mode || "")}</span></td><td class="st-${esc(r.status)}">${esc(r.status || "")}</td><td>${esc(r.subtype || "")}</td><td class="num">${r.findings_count ?? "—"}</td><td class="num">${r.leads_count ?? "—"}</td><td class="num">${cost(r.total_cost_usd)}</td></tr>`).join("");
  return `<div class="panel scroll"><div class="tablewrap"><table><thead><tr><th>When</th><th>Mode</th><th>Status</th><th>Subtype</th><th class="num">Findings</th><th class="num">Leads</th><th class="num">Cost</th></tr></thead><tbody>${body}</tbody></table></div></div>`;
}
function monitorView(base) {
  const urls = Object.keys(base || {});
  if (!urls.length) return `<div class="empty">no monitor baseline yet — run <code>autohunt.py --monitor</code></div>`;
  const body = urls.map((u) => `<tr><td class="mono">${esc(u)}</td><td class="num">${esc(base[u].status)}</td><td class="mono">${esc(base[u].hash)}</td><td>${shortTime(base[u].checked_at)}</td></tr>`).join("");
  return `<div class="panel scroll"><h3>Monitor baseline (${urls.length})</h3><div class="tablewrap"><table><thead><tr><th>URL</th><th class="num">Status</th><th>Body hash</th><th>Checked</th></tr></thead><tbody>${body}</tbody></table></div></div>`;
}
function findingsView(items) {
  if (!items || !items.length) return `<div class="empty">no verified findings</div>`;
  const body = items.map((f) => `<tr><td>${sevChip((f.severity || "info").toLowerCase())}</td><td>${esc(f.title || "")}</td><td>${esc((f.dedupe_key || "").split(":")[0])}</td><td>${f.report_path ? `<button class="tbtn" data-report="${esc(f.report_path)}">report</button>` : "—"}</td></tr>`).join("");
  return `<div class="panel scroll"><div class="tablewrap"><table><thead><tr><th>Severity</th><th>Title</th><th>Class</th><th>Report</th></tr></thead><tbody>${body}</tbody></table></div></div>`;
}
function listView(items, cols, emptyMsg) {
  if (!items || !items.length) return `<div class="empty">${esc(emptyMsg)}</div>`;
  const body = items.map((r) => "<tr>" + cols.map((c) => `<td>${c.html ? c.html(r) : esc(r[c.key] ?? "")}</td>`).join("") + "</tr>").join("");
  return `<div class="panel scroll"><div class="tablewrap"><table><thead><tr>${cols.map((c) => `<th>${esc(c.label)}</th>`).join("")}</tr></thead><tbody>${body}</tbody></table></div></div>`;
}
function leadCols(withProgram) {
  const cols = [
    { key: "priority", label: "Prio", html: (r) => `<span class="chip prio-${esc((r.priority || "medium").toLowerCase())}">${esc(r.priority || "—")}</span>` },
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
  view.innerHTML = filterBar(`<select id="sev"><option value="">all severities</option>${SEVS.map((s) => `<option>${s}</option>`).join("")}</select><input id="q" placeholder="filter…" />`) + `<div id="tbl"></div>`;
  const cols = [
    { key: "severity", label: "Severity", html: (r) => sevChip(r.severity), val: (r) => SEVS.indexOf(r.severity) },
    { key: "title", label: "Title" },
    { key: "vuln_class", label: "Class" },
    { key: "slug", label: "Program", html: (r) => `<a href="#/program/${encodeURIComponent(r.slug)}">${esc(r.slug)}</a>` },
    { key: "first_seen", label: "First seen", html: (r) => shortTime(r.first_seen) },
    { key: "report_path", label: "Report", html: (r) => r.report_path ? `<a href="#" onclick="showReport('${esc(r.slug)}','${esc(r.report_path)}');return false">report</a>` : "—" },
  ];
  const sev = $("#sev"), q = $("#q"); sev.value = getF("sev"); q.value = getF("q");
  const draw = () => {
    setF("sev", sev.value); setF("q", q.value);
    const sv = sev.value, term = q.value.toLowerCase();
    const f = all.filter((r) => (!sv || r.severity === sv) && (!term || (r.title + r.slug + r.vuln_class).toLowerCase().includes(term)));
    sortableTable($("#tbl"), cols, f, "findings"); setCount(f.length, all.length);
  };
  sev.onchange = draw; q.oninput = debounce(draw, 120); draw();
}

async function vLeads() {
  const all = await api("/api/leads");
  view.innerHTML = filterBar(`<select id="stt"><option value="">all statuses</option>${["open", "hunted", "reported", "dismissed"].map((s) => `<option>${s}</option>`).join("")}</select><input id="q" placeholder="filter…" />`) + `<div id="tbl"></div>`;
  const cols = leadCols(true);
  const stt = $("#stt"), q = $("#q"); stt.value = getF("stt"); q.value = getF("q");
  const draw = () => {
    setF("stt", stt.value); setF("q", q.value);
    const s = stt.value, term = q.value.toLowerCase();
    const f = all.filter((r) => (!s || r.status === s) && (!term || JSON.stringify(r).toLowerCase().includes(term)));
    sortableTable($("#tbl"), cols, f, "leads"); setCount(f.length, all.length);
  };
  stt.onchange = draw; q.oninput = debounce(draw, 120); draw();
}

function barRows(items, label, valfn, fmt) {
  const max = Math.max(1, ...items.map(valfn));
  return `<div class="panel"><h3>${esc(label)}</h3><div class="bars">` + items.map((it) => {
    const v = valfn(it);
    return `<div class="bar-row"><div title="${esc(it.name || it.slug || it.day)}">${esc(it.name || it.slug || it.day)}</div><div class="bar-track"><div class="bar-fill" style="width:${(v / max * 100).toFixed(1)}%"></div></div><div class="num">${fmt(v, it)}</div></div>`;
  }).join("") + `</div></div>`;
}
async function vCost() {
  const c = await api("/api/cost");
  let html = `<div class="cards"><div class="card"><div class="k">Total (estimate)</div><div class="v">${cost(c.total)}</div></div></div>`;
  if (c.by_phase.length) html += barRows(c.by_phase, "By phase", (x) => x.cost, (v, it) => `${cost(v)} · ${it.n}×`);
  if (c.by_model && c.by_model.length) html += barRows(c.by_model, "By model", (x) => x.cost, (v) => cost(v));
  if (c.by_program.length) html += barRows(c.by_program, "By program", (x) => x.cost, (v) => cost(v));
  if (c.by_day.length) html += barRows(c.by_day, "Over time ($/day)", (x) => x.cost, (v) => cost(v));
  view.innerHTML = (c.by_phase.length || c.by_program.length) ? html : `<div class="empty">no cost data yet — run a hunt</div>`;
}

async function vChanges() {
  const c = await api("/api/changes");
  let html = `<div class="panel scroll"><h3>Monitor alerts (${c.monitor_alerts.length})</h3>`;
  html += c.monitor_alerts.length ? `<div class="tablewrap"><table><thead><tr><th>When</th><th>Program</th><th>URL</th><th>Guess</th><th>Reason</th></tr></thead><tbody>` +
    c.monitor_alerts.map((a) => `<tr><td>${shortTime(a.ts)}</td><td>${esc(a.slug)}</td><td class="mono">${esc(a.url)}</td><td>${esc(a.severity_guess || "")}</td><td>${esc(a.reason || "")}</td></tr>`).join("") + `</tbody></table></div>` : `<div class="empty">none</div>`;
  html += `</div><div class="panel"><h3>Scope changes (catalog)</h3><div class="md">${c.scope_changes_html || "<div class='empty'>none</div>"}</div></div>`;
  view.innerHTML = html;
}

function vLog() {
  view.innerHTML = `<div class="panel"><h3>run.log (live)</h3><div id="logbox" class="logbox"></div></div>`;
  renderLog();
}

/* ---- live streams ---- */
const logBuf = [];
function renderLog() { const b = $("#logbox"); if (b) { b.textContent = logBuf.join("\n") || "(waiting for log output…)"; b.scrollTop = b.scrollHeight; } }
function renderFeed() { const f = $("#feed"); if (f) { f.textContent = logBuf.slice(-40).join("\n") || "(no recent activity)"; f.scrollTop = f.scrollHeight; } }

let paused = false, pending = false;
function flashUpdated() {
  const u = $("#updated"); if (!u) return;
  u.textContent = "updated " + new Date().toLocaleTimeString(); u.classList.add("flash");
  setTimeout(() => u.classList.remove("flash"), 600);
}
const liveRefresh = debounce(() => { if (paused) { pending = true; return; } render({ silent: true }); }, 800);

function initStreams() {
  const ev = new EventSource("/api/stream/events");
  ev.onopen = () => { $("#dot").className = "dot on"; $("#connlabel").textContent = "live"; };
  ev.onerror = () => { $("#dot").className = "dot off"; $("#connlabel").textContent = "reconnecting…"; };
  ev.addEventListener("update", () => { flashUpdated(); liveRefresh(); });
  const lg = new EventSource("/api/stream/log");
  lg.onmessage = (e) => { let line; try { line = JSON.parse(e.data); } catch { line = e.data; } logBuf.push(line); if (logBuf.length > 1000) logBuf.shift(); renderLog(); renderFeed(); };
}

/* ---- router ---- */
const ROUTES = { overview: vOverview, programs: vPrograms, program: vProgram, findings: vFindings, leads: vLeads, cost: vCost, changes: vChanges, log: vLog };
async function render({ silent = false } = {}) {
  const scroll = main.scrollTop;
  const h = (location.hash || "#/overview").slice(2).split("/");
  const name = h[0] || "overview";
  const fn = ROUTES[name] || vOverview;
  document.querySelectorAll("#nav a").forEach((a) => {
    const on = a.dataset.view === name; a.classList.toggle("active", on);
    if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  $("#crumb").textContent = name[0].toUpperCase() + name.slice(1) + (h[1] ? " · " + decodeURIComponent(h[1]) : "");
  if (!silent) view.innerHTML = '<div class="skeleton"></div>';
  try { await fn(h[1] ? decodeURIComponent(h[1]) : undefined); }
  catch (e) { view.innerHTML = `<div class="empty">⚠ ${esc(e.message)}</div>`; }
  main.scrollTop = silent ? scroll : 0;
}

window.addEventListener("hashchange", () => render());
$("#refresh").onclick = () => render();
$("#pause").onclick = () => {
  paused = !paused;
  const b = $("#pause");
  b.setAttribute("aria-pressed", String(paused));
  b.textContent = paused ? "▶ Paused" : "⏸ Live";
  if (!paused && pending) { pending = false; render({ silent: true }); }
};
if (!location.hash) location.hash = "#/overview";
render();
initStreams();
