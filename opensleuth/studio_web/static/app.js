/* CoreProbe — Forensic Artifact Recovery & Exploit Workstation */
"use strict";

/* ---------------- icons (monochrome SVGs) ---------------- */
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
  artifacts: I('<path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/>'),
  research: I('<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>'),
  bfu: I('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'),
  evidence: I('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>'),
  exploits: I('<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26"/>'),
};

/* ---------------- navigation specification ---------------- */
const NAV = [
  ["dashboard", "Dashboard"], ["devices", "Devices"], ["applications", "Applications"],
  ["browser", "Browser"], ["chats", "Chats"], ["cloud", "Cloud"], ["contacts", "Contacts"],
  ["calendars", "Calendars"], ["calls", "Calls"], ["location", "Location"], ["media", "Media"],
  ["messages", "Messages"], ["files", "Files"], ["forensics", "Forensics"], ["reports", "Reports"],
  ["exploits", "Exploits"], ["research", "Research"], ["bfu", "BFU Lab"], ["evidence", "Evidence"], ["artifacts", "Artifacts"], ["tools", "Tools"], ["settings", "Settings"],
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
  forensics: ["Forensics", "Timeline, SQLite & multi-hash analysis"],
  reports: ["Reports", "CASE/UCO & evidentiary certification"],
  exploits: ["Exploits", "Public iOS exploit catalog (91 routes)"],
  tools: ["Tools", "Open-source forensic toolchain + install status"],
  research: ["Research", "Zero-day research: campaigns, traces, leads"],
  bfu: ["BFU Lab", "Modern-phone BFU: FS intelligence, keybags, decrypt"],
  evidence: ["Evidence", "Chain of custody: certify, verify, seals"],
  artifacts: ["Artifacts", "Crash logs, wireless, super-timeline"],
  settings: ["Settings", "Configuration and examiner preferences"],
};

/* ---------------- global state & cache ---------------- */
let DEVICE = null, APPS = [], ARTIFACTS = {}, CASES = [], ACTIVE_CASE = null;
let currentHash = "dashboard", chatSelected = null;
let notesTimer = null;
let NOTIFICATIONS_LIST = [];
let UNREAD_NOTIFS = 0;
let LAST_DEVICE_UDID = null;
let LAST_DEVICE_STATE = null;

// Catalog & Analysis Cache (avoids UI freeze & DOM thrashing)
const CACHE = {
  exploits: null,
  tools: null,
  doctor: null,
  stance: null,
  surface: null,
  bfu: null,
  settings: null,
};

/* ---------------- api & utility helpers ---------------- */
async function api(path, opts) {
  try {
    const r = await fetch(path, opts);
    return await r.json();
  } catch (err) {
    return { error: String(err) };
  }
}

const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&apos;"}[c]));
const fmtDate = iso => { if (!iso) return "—"; const d = new Date(iso); return isNaN(d) ? String(iso) : d.toLocaleString(); };
const fmtBytes = n => n > 1048576 ? (n/1048576).toFixed(1)+" MB" : n > 1024 ? (n/1024).toFixed(1)+" KB" : n+" B";

/* ---------------- text notifications & activity log ---------------- */
function notify(title, message, level = "info", category = "SYSTEM") {
  const now = new Date();
  const timeStr = now.toTimeString().split(" ")[0];
  const notif = {
    id: Date.now() + Math.random(),
    title: String(title),
    message: String(message),
    level: level.toLowerCase(),
    category: String(category).toUpperCase(),
    timestamp: timeStr,
  };
  NOTIFICATIONS_LIST.unshift(notif);
  if (NOTIFICATIONS_LIST.length > 100) NOTIFICATIONS_LIST.pop();

  UNREAD_NOTIFS++;
  updateNotifBadge();
  renderNotifDrawer();
  showToast(notif);
}

function showToast(n) {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const t = document.createElement("div");
  t.className = `toast-card ${n.level}`;
  const badgeMap = { success: "SUCCESS", error: "FAILED", warning: "WARNING", info: "INFO" };
  const badgeText = badgeMap[n.level] || "SYSTEM";

  t.innerHTML = `
    <div class="toast-body">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:2px">
        <span class="text-tag ${n.level}">${badgeText}</span>
        <span class="toast-title">${esc(n.title)}</span>
      </div>
      <div class="toast-msg">${esc(n.message)}</div>
    </div>
    <div class="toast-close" onclick="this.parentElement.remove()">×</div>
  `;
  container.appendChild(t);
  setTimeout(() => { if (t.parentElement) t.remove(); }, 5000);
}

function toast(msg, kind = "blue") {
  const levelMap = { green: "success", red: "error", amber: "warning", blue: "info" };
  const lvl = levelMap[kind] || kind || "info";
  notify("System Update", msg, lvl, "OPERATOR");
}

function updateNotifBadge() {
  const badge = document.getElementById("notif-badge");
  if (!badge) return;
  if (UNREAD_NOTIFS > 0) {
    badge.textContent = UNREAD_NOTIFS > 99 ? "99+" : String(UNREAD_NOTIFS);
    badge.style.display = "inline-block";
  } else {
    badge.style.display = "none";
  }
}

function toggleNotifs() {
  const drawer = document.getElementById("notif-drawer");
  if (!drawer) return;
  const isOpen = drawer.style.display === "flex";
  drawer.style.display = isOpen ? "none" : "flex";
  if (!isOpen) {
    UNREAD_NOTIFS = 0;
    updateNotifBadge();
    renderNotifDrawer();
  }
}

function renderNotifDrawer() {
  const body = document.getElementById("notif-drawer-body");
  const countEl = document.getElementById("drawer-notif-count");
  if (!body) return;
  if (countEl) countEl.textContent = String(NOTIFICATIONS_LIST.length);

  if (!NOTIFICATIONS_LIST.length) {
    body.innerHTML = '<div class="empty-state">No recorded activity yet.</div>';
    return;
  }
  body.innerHTML = NOTIFICATIONS_LIST.map(n => `
    <div class="notif-card">
      <div class="notif-card-head">
        <div style="display:flex;align-items:center;gap:6px">
          <span class="text-tag ${n.level}">${esc(n.category)}</span>
          <span class="notif-card-title">${esc(n.title)}</span>
        </div>
        <span class="notif-card-time">${esc(n.timestamp)}</span>
      </div>
      <div class="notif-card-msg">${esc(n.message)}</div>
    </div>
  `).join("");
}

async function clearAllNotifications() {
  NOTIFICATIONS_LIST = [];
  UNREAD_NOTIFS = 0;
  updateNotifBadge();
  renderNotifDrawer();
  await api("/api/notifications/clear", { method: "POST" });
  toast("Notifications cleared", "blue");
}

/* ---------------- shell & navigation ---------------- */
function buildNav() {
  document.getElementById("nav").innerHTML = NAV.map(([id, label]) =>
    `<div class="nav-item ${id === currentHash ? "active" : ""}" data-nav="${id}">
      ${ICONS[id]}
      <span>${label}</span>
      <span class="nav-badge" id="badge-${id}"></span>
    </div>`
  ).join("");
  document.querySelectorAll(".nav-item").forEach(n => n.onclick = () => location.hash = n.dataset.nav);
}

function navCounts() {
  const chatTotal = (ARTIFACTS.messages?.length || 0) + (ARTIFACTS.whatsapp?.length || 0) +
                    (ARTIFACTS.telegram?.length || 0) + (ARTIFACTS.signal?.length || 0);
  const map = {
    applications: APPS.length || "",
    browser: (ARTIFACTS.history?.length || 0) + (ARTIFACTS.bookmarks?.length || 0) || "",
    chats: chatTotal || "",
    contacts: ARTIFACTS.contacts?.length || "",
    calls: ARTIFACTS.calls?.length || "",
    location: ARTIFACTS.locations?.length || "",
    media: ARTIFACTS.media_index?.length || "",
    messages: ARTIFACTS.messages?.length || "",
    files: (ARTIFACTS.app_databases?.length || 0) || "",
  };
  NAV.forEach(([id]) => { const b = document.getElementById("badge-" + id); if (b) b.textContent = map[id] || ""; });
}

function renderCasePanel() {
  const c = ACTIVE_CASE;
  document.getElementById("case-info").innerHTML = c ? `
    <div class="ci-row"><span class="ci-key">Case ID</span><span class="ci-val mono">${esc(c.case_id)}</span></div>
    <div class="ci-row"><span class="ci-key">Target/Desc</span><span class="ci-val">${esc(c.description || c.owner || "—")}</span></div>
    <div class="ci-row"><span class="ci-key">Created</span><span class="ci-val">${fmtDate(c.created)}</span></div>
    <div class="ci-row"><span class="ci-key">Examiner</span><span class="ci-val">${esc(c.examiner || "Forensic Examiner")}</span></div>
    <div class="ci-row"><span class="ci-key">Evidence</span><span class="ci-val">${esc(c.evidence_items || "1 target")}</span></div>
    <div class="ci-row"><span class="ci-key">Status</span><span class="ci-val"><span class="status-pill amber">ACTIVE</span></span></div>` :
    `<div class="empty-state">No case loaded.<br><button class="btn primary" style="margin-top:8px" onclick="openCaseModal()">Open or Create Case</button></div>`;

  document.getElementById("case-id").textContent = c ? c.case_id : "—";
  const srcs = [...(c?.evidence_sources || [])];
  if (DEVICE) srcs.push({ name: DEVICE.model, os: "iOS " + DEVICE.ios, live: true });
  document.getElementById("evidence-sources").innerHTML = srcs.length ? srcs.map(s =>
    `<div class="evidence-src">
      ${ICONS.phone}
      <span class="src-name">${esc(s.name)}${s.live ? ' <span class="tag-badge green" style="margin-left:4px">LIVE</span>' : ""}</span>
      <span class="src-os">${esc(s.os || "")}</span>
    </div>`
  ).join("") : `<div class="empty-state" style="padding:10px">No evidence sources configured.</div>`;

  const notes = document.getElementById("case-notes");
  if (document.activeElement !== notes) notes.value = c?.notes || "";
}

/* ---------------- global search ---------------- */
function onGlobalSearch(q) {
  q = q.trim().toLowerCase();
  const dropdown = document.getElementById("search-dropdown");
  if (!dropdown) return;
  if (!q) {
    dropdown.style.display = "none";
    dropdown.innerHTML = "";
    return;
  }
  const results = [];
  NAV.forEach(([id, label]) => {
    if (label.toLowerCase().includes(q) || id.includes(q)) {
      results.push({ label: `View: ${label}`, hint: "Page navigation", action: () => { location.hash = id; dropdown.style.display = "none"; } });
    }
  });
  if (DEVICE && (DEVICE.model.toLowerCase().includes(q) || DEVICE.chip.toLowerCase().includes(q) || DEVICE.udid.toLowerCase().includes(q))) {
    results.push({ label: `Attached: ${DEVICE.model} (${DEVICE.chip})`, hint: `Device Mode: ${DEVICE.state}`, action: () => { location.hash = "devices"; dropdown.style.display = "none"; } });
  }
  (CACHE.exploits?.routes || []).filter(r => r.name.toLowerCase().includes(q) || (r.chips || []).some(c => c.toLowerCase().includes(q))).slice(0, 4).forEach(r => {
    results.push({ label: `Exploit: ${r.name}`, hint: `Layer: ${r.layer} · Chips: ${r.chips?.join(",")}`, action: () => { location.hash = "exploits"; dropdown.style.display = "none"; } });
  });
  (ARTIFACTS.messages || []).filter(m => String(m.text || "").toLowerCase().includes(q)).slice(0, 3).forEach(m => {
    results.push({ label: `Message: ${m.text.slice(0, 40)}`, hint: `${m.sender || "Unknown"} · ${fmtDate(m.date)}`, action: () => { location.hash = "chats"; dropdown.style.display = "none"; } });
  });

  if (!results.length) {
    dropdown.innerHTML = `<div class="empty-state" style="padding:12px">No items match "${esc(q)}"</div>`;
  } else {
    dropdown.innerHTML = results.slice(0, 8).map((r, i) => `
      <div class="search-result-item" data-idx="${i}">
        <div style="flex:1">
          <div style="font-weight:600;color:#fff">${esc(r.label)}</div>
          <div style="font-size:10.5px;color:var(--muted)">${esc(r.hint)}</div>
        </div>
        <span class="mono" style="color:var(--faint);font-size:10px">↵</span>
      </div>
    `).join("");
    dropdown.querySelectorAll(".search-result-item").forEach((el, i) => {
      el.onclick = () => results[i].action();
    });
  }
  dropdown.style.display = "block";
}

document.addEventListener("click", e => {
  const dropdown = document.getElementById("search-dropdown");
  const searchInput = document.getElementById("global-search");
  if (dropdown && !dropdown.contains(e.target) && e.target !== searchInput) {
    dropdown.style.display = "none";
  }
});

/* ---------------- case switcher modal ---------------- */
function openCaseModal() {
  const modal = document.getElementById("case-modal");
  const select = document.getElementById("case-select-dropdown");
  if (!modal || !select) return;
  select.innerHTML = `<option value="">Choose a case (${CASES.length} found)...</option>` +
    CASES.map(c => `<option value="${esc(c.case_id)}" ${c.case_id === ACTIVE_CASE?.case_id ? "selected" : ""}>${esc(c.case_id)} — ${esc(c.description || c.owner || "Target")} (${fmtDate(c.created)})</option>`).join("");
  modal.style.display = "flex";
}

function closeCaseModal() {
  const modal = document.getElementById("case-modal");
  if (modal) modal.style.display = "none";
}

function onCaseSelectChanged(val) {
  if (!val) return;
  const match = CASES.find(c => c.case_id === val);
  if (match) {
    document.getElementById("new-case-id").value = match.case_id;
    document.getElementById("new-case-examiner").value = match.examiner || "";
    document.getElementById("new-case-desc").value = match.description || match.owner || "";
  }
}

async function submitCaseModal() {
  const id = document.getElementById("new-case-id").value.trim();
  const ex = document.getElementById("new-case-examiner").value.trim();
  const desc = document.getElementById("new-case-desc").value.trim();
  if (!id) {
    toast("Case ID / folder name is required", "red");
    return;
  }
  const payload = {
    case_id: id,
    examiner: ex || "Forensic Examiner",
    description: desc || id,
    created: new Date().toISOString(),
  };
  const r = await api("/api/case", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (r.saved) {
    ACTIVE_CASE = r.case || payload;
    closeCaseModal();
    notify("Case Activated", `Active case switched to ${id}`, "success", "EVIDENCE");
    renderCasePanel();
    await refreshCurrentPage();
  } else {
    toast((r && r.error) || "Failed to switch case", "red");
  }
}

/* ---------------- backup parser modal ---------------- */
function openParseModal() {
  const modal = document.getElementById("parse-modal");
  if (!modal) return;
  const pathInput = document.getElementById("parse-backup-path");
  if (pathInput) pathInput.value = ACTIVE_CASE?.destination ? `${ACTIVE_CASE.destination}/backup` : "~/cases/C1/backup";
  modal.style.display = "flex";
}

function closeParseModal() {
  const modal = document.getElementById("parse-modal");
  if (modal) modal.style.display = "none";
}

async function submitParseModal() {
  const p = document.getElementById("parse-backup-path").value.trim();
  const statusEl = document.getElementById("parse-modal-status");
  const btn = document.getElementById("parse-modal-submit-btn");
  if (!p) {
    toast("Path to backup directory is required", "red");
    return;
  }
  btn.disabled = true;
  statusEl.innerHTML = `<span class="mono" style="color:var(--accent)">Parsing backup at ${esc(p)} (extracting databases & generating report)...</span>`;
  notify("Parser Started", `Parsing disk backup image at ${p}`, "info", "FORENSICS");

  const r = await api("/api/parse-image", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path: p }),
  });
  btn.disabled = false;
  if (r.ok) {
    notify("Parsing Complete", `Artifacts parsed successfully. Report available at ${r.report}`, "success", "FORENSICS");
    closeParseModal();
    await refreshCurrentPage();
  } else {
    statusEl.innerHTML = `<span class="mono" style="color:var(--red)">Failed: ${esc(r.error || "Manifest.db missing or corrupt")}</span>`;
    notify("Parser Error", r.error || "Failed to parse backup image", "error", "FORENSICS");
  }
}

/* ---------------- dashboard ---------------- */
function pageDashboard() {
  const totalDevices = DEVICE ? 1 : 0;
  const artifactCount = Object.entries(ARTIFACTS).filter(([k]) => !["media_index","sqlite_files","timeline_preview","files","device","prefs"].includes(k))
    .reduce((a, [, v]) => a + (Array.isArray(v) ? v.length : 0), 0);
  const caseRows = (CASES.length ? CASES : [
    {case_id:"2026-CASE-01", owner:"Subject A", evidence_items:"iPhone 14 (A15)", created:new Date().toISOString(), status:"In Progress"},
  ]).slice(0, 6).map(c => `<tr>
    <td class="mono"><b>${esc(c.case_id)}</b></td>
    <td>${esc(c.evidence_items || c.owner || "Target")}</td>
    <td class="mono">${fmtDate(c.created)}</td>
    <td><span class="status-pill ${c.status === "Completed" ? "green" : "amber"}">${esc(c.status || "ACTIVE")}</span></td>
  </tr>`).join("");

  const logLines = (NOTIFICATIONS_LIST.length ? NOTIFICATIONS_LIST.slice(0, 5) : [
    { title: DEVICE ? `Device Connected: ${DEVICE.model}` : "Device: No device attached", timestamp: "now", level: DEVICE ? "success" : "info", category: "DEVICE" }
  ]).map(n => `
    <div class="log-event">
      <span class="text-tag ${n.level}">${esc(n.category || "LOG")}</span>
      <div class="log-body">
        <div class="log-text">${esc(n.title || n.message)}</div>
        <div class="log-time">${esc(n.timestamp)}</div>
      </div>
    </div>
  `).join("");

  const sections = NAV.slice(1).map(([id]) => {
    const [t, d] = SECTION_META[id] || [id, ""];
    return `<div class="section-card" data-nav="${id}">
      ${ICONS[id]}
      <div>
        <div class="section-card-title">${t}</div>
        <div class="section-card-desc">${d}</div>
      </div>
      <span class="section-card-chevron">›</span>
    </div>`;
  }).join("");

  return `
    <div class="page-title">Dashboard</div>
    <div class="page-sub">Overview of your forensic analysis progress, hardware state, and evidence sources.</div>
    <div class="metric-row">
      ${[["Total Devices", totalDevices, "devices", "devices"],["Artifacts Found", artifactCount.toLocaleString(), "forensics", "forensics"],["Exploit Routes", "91 Cataloged", "exploits", "exploits"],["Cases", CASES.length || 1, "reports", "reports"]]
        .map(([l, v, ic, nav]) => `<div class="metric-card">${ICONS[ic]}<div class="metric-body"><div class="metric-label">${l}</div><div class="metric-value">${v}</div><div class="metric-link" data-nav="${nav}">View ${l.replace("Total ","").replace(" Found","")} →</div></div></div>`).join("")}
    </div>
    <div class="two-col">
      <div class="panel-card">
        <div class="panel-card-head">Recent Forensic Cases</div>
        <table class="data"><thead><tr><th>Case Name</th><th>Target</th><th>Date</th><th>Status</th></tr></thead><tbody>${caseRows}</tbody></table>
      </div>
      <div class="panel-card">
        <div class="panel-card-head">Recent System Activity & Notifications</div>${logLines}
      </div>
    </div>
    <div class="panel-card">
      <div class="panel-card-head">Quick Actions</div>
      <div class="quick-actions" style="padding:11px 13px">
        <button class="btn primary" style="font-weight:700" onclick="quickAction('autoexploit')">⚡ Auto-Exploit Device</button>
        <button class="btn primary" onclick="quickAction('add')">Device Manager</button>
        <button class="btn" onclick="quickAction('parse')">Parse Image</button>
        <button class="btn" onclick="quickAction('report')">Generate Report</button>
        <button class="btn" onclick="quickAction('open')">Open Case</button>
        <button class="btn" onclick="quickAction('export')">Export Evidence</button>
      </div>
    </div>
    <div class="panel-card">
      <div class="panel-card-head">All Workstation Sections</div>
      <div style="padding:13px"><div class="section-grid">${sections}</div></div>
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
  const bfuActions = document.getElementById("bfu-actions");
  const afuActions = document.getElementById("afu-actions");
  if (bfuActions) bfuActions.style.display = m === "BFU" ? "flex" : "none";
  if (afuActions) afuActions.style.display = m === "AFU" ? "flex" : "none";
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
  const pfx = activeMode === "BFU" && rank > 11 ? `
    <div class="log-event" style="margin-top:8px">
      <span class="text-tag warning">ATTENTION</span>
      <div class="log-body"><div class="log-text">BFU on ${d.chip}: no public bootrom exploit exists. One lawful passcode unlock (AFU) restores all logical extraction routes.</div></div>
    </div>` : "";
  return `<div style="padding:6px 13px 12px">${rows.map(([t, s, k]) => `
    <div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border)">
      <span class="status-pill ${k}">${s}</span>
      <span class="mono" style="color:var(--text);font-size:11.5px">${t}</span>
    </div>`).join("")}${pfx}</div>`;
}

async function dumpEverything() {
  if (!ACTIVE_CASE) { toast("Open or create a case first", "red"); return; }
  if (activeMode === "AFU") {
    notify("Full Acquisition Started", "Backup, media, crash logs, and diagnostics started. Unlock device once for the backup step.", "info", "FORENSICS");
    await api("/api/acquire", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ destination: ACTIVE_CASE.destination, case_id: ACTIVE_CASE.case_id }),
    });
  } else {
    const out = document.getElementById("bfu-out");
    if (out) out.textContent = "Running BFU identity probe (serial/UDID/recovery state)...";
    notify("BFU Probe Started", "Identity-level probe running without device passcode.", "info", "FORENSICS");
    const r = await api("/api/bfu", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ destination: ACTIVE_CASE.destination || "", chip: DEVICE?.chip }),
    });
    if (out) out.textContent = r.ok ? (r.output || "BFU extraction complete.") : (r.error || "BFU probe failed");
    notify(r.ok ? "BFU Probe Complete" : "BFU Probe Failed", r.ok ? "Identity data pulled." : (r.error || "Failed"), r.ok ? "success" : "error", "FORENSICS");
  }
}

function pageDevices() {
  const d = DEVICE;
  const rows = d ? [[d.model, "Apple iOS", d.ios + " (" + d.build + ")", "Logical" + (d.state === "BFU" ? " (gated)" : ""), d.state, "now"]]
    : [["No device connected", "—", "—", "—", "DISCONNECTED", "—"]];
  return `
    <div class="page-title">Devices</div>
    <div class="page-sub">Hardware detection, acquisition mode (AFU/BFU), and exploit routes.</div>
    <div class="quick-actions">
      <span class="mode-chip ${activeMode === "AFU" ? "active" : ""}" data-mode="AFU" onclick="setMode('AFU')">AFU — After First Unlock</span>
      <span class="mode-chip ${activeMode === "BFU" ? "active" : ""}" data-mode="BFU" onclick="setMode('BFU')">BFU — Before First Unlock</span>
      <span style="align-self:center;margin-left:auto" class="mono">
        ${d ? `<span class="status-pill ${d.state === "AFU" ? "green" : "amber"}">${d.state}</span> ${esc(d.model)} (${esc(d.chip)})` : '<span class="status-pill gray">NO DEVICE</span>'}
      </span>
    </div>
    <div class="quick-actions">
      <div style="display:flex;gap:9px" id="afu-actions">
        <button class="btn primary" onclick="dumpEverything()" ${!d || d.state !== "AFU" ? "disabled" : ""}>Dump Everything (Logical Suite)</button>
        <button class="btn" onclick="refreshCurrentPage()">Refresh Detection</button>
      </div>
      <div style="display:flex;gap:9px" id="bfu-actions" style="display:none">
        <button class="btn primary" onclick="dumpEverything()" ${!d ? "disabled" : ""}>Run BFU Identity Probe</button>
        <button class="btn" onclick="location.hash='bfu'">Open Modern BFU Lab →</button>
      </div>
    </div>
    <div class="two-col">
      <div class="panel-card">
        <div class="panel-card-head">Routes & Exploits — Public Capability</div>
        <div id="routes-panel">${routesHtml()}</div>
      </div>
      <div>
        <div class="panel-card">
          <div class="panel-card-head">Acquisition Mode Guidance</div>
          <div style="text-align:left;padding:13px;font-size:12px;line-height:1.5;color:var(--muted)">
            <b style="color:#fff">AFU (After First Unlock)</b> — device was unlocked with passcode since boot: full logical acquisition (backups, decrypted media, crash logs, diagnostics, app containers).<br><br>
            <b style="color:#fff">BFU (Before First Unlock)</b> — never unlocked since boot: class keys locked by SEP; identity-level data only on modern chips (A12+); checkm8 bootrom route applies to A7–A11 hardware.
          </div>
        </div>
        <div class="panel-card">
          <div class="panel-card-head">BFU Probe Output</div>
          <div class="mono" id="bfu-out" style="padding:10px 13px;white-space:pre-wrap;font-size:11px;max-height:170px;overflow:auto">Run the BFU probe to collect serial, UDID, and recovery state without a passcode.</div>
        </div>
      </div>
    </div>
    <div class="panel-card">
      <table class="data"><thead><tr><th>Device</th><th>Platform</th><th>OS</th><th>Acquisition</th><th>Status</th><th>Last Activity</th></tr></thead>
      <tbody>${rows.map(r => `<tr>${r.map((c, i) => `<td>${i === 4 && c !== "—" ? `<span class="status-pill ${c === "AFU" ? "green" : c === "BFU" ? "amber" : "gray"}">${c}</span>` : esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>
    </div>
    ${d ? `<div class="panel-card"><div class="panel-card-head">Hardware & Identity Detail — ${esc(d.model)}</div>
      <div class="form-grid">
        <div class="form-field"><span class="form-label">Product Type</span><span class="mono">${esc(d.product_type)}</span></div>
        <div class="form-field"><span class="form-label">UDID</span><span class="mono">${esc(d.udid)}</span></div>
        <div class="form-field"><span class="form-label">Silicon / Chip</span><span class="mono">${esc(d.chip)}</span></div>
        <div class="form-field"><span class="form-label">Execution State</span><span class="mono">${esc(d.state)}</span></div>
      </div></div>` : ""}`;
}

/* ---------------- applications ---------------- */
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
  if (out) out.textContent = "dumping " + coreSelectedApps.size + " app container(s)...";
  notify("Container Extraction", `Dumping containers for ${coreSelectedApps.size} applications...`, "info", "FORENSICS");
  const r = await api("/api/dump-apps", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ destination: ACTIVE_CASE.destination, apps: [...coreSelectedApps] }),
  });
  if (out) out.textContent = r.ok ? "done — containers in appdata/" : (r.error || "failed");
  notify(r.ok ? "App Dump Complete" : "App Dump Failed", r.ok ? "Containers extracted." : (r.error || "Extraction failed"), r.ok ? "success" : "error", "FORENSICS");
}

function pageApplications() {
  const rows = APPS.length ? APPS.map(a => `
    <tr>
      <td style="width:30px;text-align:center"><input type="checkbox" class="app-sel" data-b="${esc(a.bundle)}" onchange="syncAppSelection()"></td>
      <td><b>${esc(a.name)}</b></td>
      <td class="mono">${esc(a.bundle)}</td>
      <td class="mono">${esc(a.version || "—")}</td>
      <td>User Application</td>
      <td class="mono">—</td>
    </tr>
  `).join("") : `<tr><td colspan="6" class="empty-state">Connect a device to enumerate installed user applications.</td></tr>`;

  return `
    <div class="page-title">Applications</div>
    <div class="page-sub">Installed iOS applications and container artifacts. Select apps to dump app sandbox databases.</div>
    <div class="quick-actions">
      <button class="btn primary" onclick="selAllApps(true)">Select All</button>
      <button class="btn" onclick="selAllApps(false)">Select None</button>
      <button class="btn" id="dump-selected" disabled onclick="dumpSelectedApps()">Dump Selected Containers</button>
      <span class="mono" id="sel-count" style="align-self:center">0 selected</span>
      <span class="mono" style="align-self:center;color:var(--faint)" id="app-dump-status"></span>
      <span style="margin-left:auto" class="mono">${APPS.length} applications indexed</span>
    </div>
    <div class="panel-card">
      <div class="filter-bar">
        <input class="form-input" placeholder="Search application name or package..." style="width:280px" oninput="filterTable('app-table', this.value)">
        <span class="status-pill gray">auto-detected · ${APPS.length} apps</span>
      </div>
      <table class="data" id="app-table">
        <thead><tr><th style="width:30px"></th><th>Application</th><th>Bundle ID</th><th>Version</th><th>Type</th><th>Data Containers</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/* ---------------- detection banner ---------------- */
function detectionBanner() {
  const b = ARTIFACTS;
  const parts = [];
  if (DEVICE) parts.push(`device: <b>${esc(DEVICE.model)}</b> (${esc(DEVICE.state)})`);
  parts.push(`apps: ${APPS.length}`);
  parts.push(`media: ${b.media_index?.length || 0}`);
  if (b.crash_count) parts.push(`crash logs: ${b.crash_count}`);
  parts.push(b.backup_present
    ? `<span class="status-pill green">BACKUP EXTRACTED</span>`
    : `<span class="status-pill amber">BACKUP PENDING</span>`);
  return `<div class="panel-card" style="padding:9px 14px;margin-bottom:14px;display:flex;gap:10px;flex-wrap:wrap;align-items:center">
    <span class="text-tag info">AUTO-DETECT</span>${parts.join('<span style="color:var(--border2)">|</span>')}
  </div>`;
}

/* ---------------- browser ---------------- */
function pageBrowser() {
  const tabs = [
    ["History", (ARTIFACTS.history || []).map(h => [h.title || h.url, h.url, fmtDate(h.date)])],
    ["Bookmarks", (ARTIFACTS.bookmarks || []).map(b => [b.title, b.url, fmtDate(b.modified)])],
  ];
  return `
    <div class="page-title">Browser</div><div class="page-sub">Web history, bookmarks, and search queries extracted from Safari.</div>
    <div class="panel-card">
      <div class="subnav">${tabs.map(([t], i) => `<span class="subnav-item ${i === 0 ? "active" : ""}" onclick="switchTab(this, 'btab', ${i})">${t}</span>`).join("")}</div>
      ${tabs.map(([t, rows], i) => `<div class="btab" id="btab-${i}" style="display:${i === 0 ? "block" : "none"}">
        <table class="data"><thead><tr><th>Title</th><th>URL</th><th>Timestamp</th></tr></thead>
        <tbody>${rows.map(r => `<tr><td>${esc(r[0])}</td><td class="mono">${esc(r[1])}</td><td class="mono">${esc(r[2])}</td></tr>`).join("") || `<tr><td colspan="3" class="empty-state">No ${t.toLowerCase()} artifacts in current extraction.</td></tr>`}</tbody></table></div>`).join("")}
    </div>`;
}

function switchTab(el, prefix, i) {
  el.parentElement.querySelectorAll(".subnav-item").forEach(s => s.classList.remove("active"));
  el.classList.add("active");
  for (let k = 0; k < 12; k++) {
    const p = document.getElementById(`${prefix}-${k}`);
    if (p) p.style.display = k === i ? "block" : "none";
  }
}

/* ---------------- chats & messages ---------------- */
let chatServiceFilter = "all";
function _allChats() {
  const all = [];
  (ARTIFACTS.messages || []).forEach(m => all.push({ ...m, service: m.service || "SMS/iMessage", source_db: "sms.db" }));
  (ARTIFACTS.whatsapp || []).forEach(m => all.push({ ...m, service: "WhatsApp", source_db: "ChatStorage.sqlite" }));
  (ARTIFACTS.telegram || []).forEach(m => all.push({ ...m, service: "Telegram", source_db: "tgdata.db" }));
  (ARTIFACTS.signal || []).forEach(m => all.push({ ...m, service: "Signal", source_db: "Signal.sqlite" }));
  return all;
}

function selectChatFilter(svc) {
  chatServiceFilter = svc;
  chatSelected = null;
  render();
}

function pageChats() {
  const all = _allChats();
  if (!all.length) {
    return emptyPage("Chats", "Chat applications and conversations.",
      "No chat artifacts in current extraction. Run an acquisition or parse a backup directory containing sms.db, ChatStorage.sqlite, or tgdata.db.");
  }
  const filtered = chatServiceFilter === "all" ? all : all.filter(m => (m.service || "").toLowerCase().includes(chatServiceFilter));
  const chats = {};
  filtered.forEach(m => {
    const k = m.chat || m.sender || "Unknown";
    (chats[k] = chats[k] || []).push(m);
  });
  const keys = Object.keys(chats);
  const sel = chatSelected && chats[chatSelected] ? chatSelected : (keys[0] || "");
  const thread = (chats[sel] || []).map(m => `
    <div class="bubble ${m.from_me ? "me" : "them"}">
      ${esc(m.text || "(attachment)")}
      ${m.attachments?.length ? `<div class="mono" style="margin-top:2px">attachment: ${esc(m.attachments.join(", "))}</div>` : ""}
      <div class="bubble-time">${esc(m.sender || "")} · ${fmtDate(m.date)} · <span class="mono">${esc(m.service || "")}</span></div>
    </div>`).join("");

  const services = ["all", "whatsapp", "telegram", "signal", "sms"];
  const counts = {
    all: all.length,
    whatsapp: (ARTIFACTS.whatsapp || []).length,
    telegram: (ARTIFACTS.telegram || []).length,
    signal: (ARTIFACTS.signal || []).length,
    sms: (ARTIFACTS.messages || []).length,
  };

  return `
    <div class="page-title">Chats & Messaging Intelligence</div>
    <div class="page-sub">Conversation forensics across WhatsApp, Telegram, Signal, and SMS/iMessage.</div>
    <div class="filter-bar" style="margin-bottom:12px;gap:6px">
      ${services.map(s => `
        <button class="btn ${chatServiceFilter === s ? "primary" : ""}" onclick="selectChatFilter('${s}')">
          ${s.toUpperCase()} (${counts[s] || 0})
        </button>`).join("")}
    </div>
    <div class="chat-wrap">
      <div class="chat-list">
        ${keys.map(k => `
          <div class="chat-item ${k === sel ? "active" : ""}" onclick="selectChat('${esc(k).replace(/'/g, "\\'")}')">
            <div class="chat-name">${esc(k)} <span class="status-pill gray" style="font-size:9px">${esc(chats[k][0]?.service || "Chat")}</span></div>
            <div class="chat-preview">${esc((chats[k].slice(-1)[0]?.text || "").slice(0, 40))}</div>
          </div>`).join("") || '<div class="empty-state">No conversations match filter.</div>'}
      </div>
      <div class="chat-thread">${thread || '<div class="empty-state">No messages</div>'}</div>
      <div class="chat-meta">
        <div class="meta-row"><div class="meta-key">Conversation</div><b>${esc(sel || "—")}</b></div>
        <div class="meta-row"><div class="meta-key">Messages</div>${chats[sel]?.length || 0}</div>
        <div class="meta-row"><div class="meta-key">Service</div>${esc(chats[sel]?.[0]?.service || "—")}</div>
        <div class="meta-row"><div class="meta-key">Database</div><span class="mono">${esc(chats[sel]?.[0]?.source_db || "sms.db")}</span></div>
      </div>
    </div>`;
}
function selectChat(k) { chatSelected = k; render(); }

function pageMessages() {
  const all = _allChats();
  const rows = all.map(m => `
    <tr>
      <td class="mono">${fmtDate(m.date)}</td>
      <td><b>${esc(m.chat || m.sender || "")}</b></td>
      <td>${m.from_me ? "Outgoing" : "Incoming"}</td>
      <td><span class="status-pill ${String(m.service).toLowerCase().includes("whatsapp") ? "green" : String(m.service).toLowerCase().includes("telegram") ? "blue" : "gray"}">${esc(m.service || "SMS")}</span></td>
      <td>${esc(m.text || "(attachment)")}</td>
      <td class="mono">${esc(m.source_db || "sms.db")}</td>
    </tr>`).join("") || `<tr><td colspan="6" class="empty-state">No message artifacts extracted.</td></tr>`;

  return `
    <div class="page-title">Messages</div><div class="page-sub">Searchable message log from SMS, MMS, WhatsApp, Telegram, and Signal.</div>
    <div class="panel-card">
      <div class="filter-bar">
        <input class="form-input" placeholder="Search message text, sender, or chat..." style="width:280px" oninput="filterTable('msg-table', this.value)">
        <span class="mono" style="margin-left:auto">${all.length} messages indexed</span>
      </div>
      <table class="data" id="msg-table">
        <thead><tr><th>Timestamp</th><th>Participant</th><th>Direction</th><th>Service</th><th>Message Body</th><th>Source Database</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/* ---------------- contacts & calls & calendars ---------------- */
function pageContacts() {
  const rows = (ARTIFACTS.contacts || []).map(c => `<tr>
    <td><b>${esc(c.name)}</b></td>
    <td class="mono">${esc((c.phones || []).join(", ") || "—")}</td>
    <td>${esc((c.emails || []).join(", ") || "—")}</td>
    <td>AddressBook.sqlitedb</td>
    <td class="mono">${fmtDate(c.modified)}</td>
  </tr>`).join("") || `<tr><td colspan="5" class="empty-state">No contacts extracted.</td></tr>`;
  return tablePage("Contacts", "Extracted address book contacts and identities.", ["Name","Phone","Email","Source","Last Modified"], rows);
}

function pageCalls() {
  const rows = (ARTIFACTS.calls || []).map(c => `<tr>
    <td class="mono"><b>${esc(c.phone || "")}</b></td>
    <td>${esc(c.type || c.direction || "Call")}</td>
    <td class="num">${c.duration_seconds || 0}s</td>
    <td class="mono">${fmtDate(c.date)}</td>
    <td class="mono">CallHistory.storedata</td>
  </tr>`).join("") || `<tr><td colspan="5" class="empty-state">No call logs extracted.</td></tr>`;
  return tablePage("Calls", "Call records and duration history.", ["Number/Contact","Direction","Duration","Timestamp","Source Database"], rows);
}

function pageCalendars() {
  return `
    <div class="page-title">Calendars</div><div class="page-sub">Calendar events and appointments.</div>
    <div class="panel-card">
      <div class="empty-state">
        No calendar events indexed in active extraction.<br>
        When parsed from <span class="mono">Calendar.sqlitedb</span>, scheduled appointments and invitations appear here.
      </div>
    </div>`;
}

function pageCloud() {
  return `
    <div class="page-title">Cloud Evidence</div><div class="page-sub">Device-extracted cloud tokens, iCloud pairing, and synchronization history.</div>
    <div class="panel-card">
      <div class="panel-card-head">Local iCloud & Account Identifiers</div>
      <div style="padding:14px;line-height:1.6;color:var(--muted)">
        ${DEVICE ? `
          <div class="ci-row"><span class="ci-key">Target UDID</span><span class="ci-val mono">${esc(DEVICE.udid)}</span></div>
          <div class="ci-row"><span class="ci-key">Account Status</span><span class="ci-val"><span class="status-pill green">PAIRED</span> Local account pairing extracted</span></div>
          <div class="ci-row"><span class="ci-key">Cloud Sync</span><span class="ci-val">Local backup files available in case folder</span></div>
        ` : `
          <div class="empty-state">Attach an iOS target to inspect pairing tokens and local iCloud accounts.</div>
        `}
      </div>
    </div>`;
}

/* ---------------- location ---------------- */
let locationTypeFilter = "all";
function filterLocationType(t) {
  locationTypeFilter = t;
  render();
}
function pageLocation() {
  const locs = ARTIFACTS.locations || [];
  if (!locs.length) {
    return `
      <div class="page-title">Location & Telemetry Intelligence</div>
      <div class="page-sub">GPS fixes, Cell Tower handshakes, and Wi-Fi geolocation tracking.</div>
      <div class="panel-card">
        <div class="empty-state">
          No location records parsed in current extraction.<br>
          Location data is extracted from <span class="mono">consolidated.db</span>, <span class="mono">cache_encryptedA.db</span>, or cell tower caches.
        </div>
      </div>`;
  }
  const filtered = locationTypeFilter === "all" ? locs : locs.filter(l => (l.type || "GPSFix") === locationTypeFilter);
  const rows = filtered.slice(0, 300).map(r => `
    <tr>
      <td class="mono">${fmtDate(r.date)}</td>
      <td><span class="status-pill ${r.type === 'GPSFix' ? 'green' : 'blue'}">${esc(r.type || "GPSFix")}</span></td>
      <td class="mono">${esc(Number(r.latitude || 0).toFixed(6))}, ${esc(Number(r.longitude || 0).toFixed(6))}</td>
      <td>${esc(r.details || "—")}</td>
      <td><a class="btn" style="padding:2px 8px;font-size:10.5px;text-decoration:none" href="https://www.openstreetmap.org/?mlat=${r.latitude}&mlon=${r.longitude}#map=16/${r.latitude}/${r.longitude}" target="_blank">Open Map ↗</a></td>
    </tr>
  `).join("");

  return `
    <div class="page-title">Location & Telemetry Intelligence</div>
    <div class="page-sub">GPS fixes, Cell Tower handshakes, and Wi-Fi geolocation tracking.</div>
    <div class="panel-card">
      <div class="filter-bar">
        <button class="btn ${locationTypeFilter === 'all' ? 'primary' : ''}" onclick="filterLocationType('all')">ALL (${locs.length})</button>
        <button class="btn ${locationTypeFilter === 'GPSFix' ? 'primary' : ''}" onclick="filterLocationType('GPSFix')">GPS FIXES</button>
        <button class="btn ${locationTypeFilter === 'CellTower' ? 'primary' : ''}" onclick="filterLocationType('CellTower')">CELL TOWERS</button>
        <input class="form-input" placeholder="Search coordinates..." style="width:200px;margin-left:auto" oninput="filterTable('loc-table', this.value)">
      </div>
      <table class="data" id="loc-table">
        <thead><tr><th>Timestamp</th><th>Fix Type</th><th>Coordinates (Lat, Lon)</th><th>Details</th><th>Mapping</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/* ---------------- media ---------------- */
let ml = [], mi = 0;
function openLightbox(i) { mi = i; renderLightbox(); document.getElementById("lightbox").style.display = "flex"; }
function closeLightbox() { document.getElementById("lightbox").style.display = "none"; }
function navLight(delta) { mi = (mi + delta + ml.length) % ml.length; renderLightbox(); }
function renderLightbox() {
  const m = ml[mi];
  const img = document.getElementById("lb-img");
  if (m && m.thumb) { img.src = m.thumb; img.style.display = "block"; } else if (img) img.style.display = "none";
  document.getElementById("lb-name").textContent = (mi + 1) + " / " + ml.length;
  document.getElementById("lb-meta").innerHTML =
    `<div style="font-weight:700;color:#fff;font-size:12px">${esc(m?.name)}</div>` +
    `${fmtBytes(m?.size || 0)} · ${fmtDate(m?.mtime)} · source: ${esc(m?.source || "")}<br>` +
    `<span style="word-break:break-all">${m?.hash ? "sha256: " + esc(m.hash) : "sha256: on demand"}</span>`;
}
function pageMedia() {
  const items = ARTIFACTS.media_index || [];
  ml = items;
  const cards = items.map((m, i) => `
    <div class="media-card" style="cursor:pointer" onclick="openLightbox(${i})">
      ${m.thumb ? `<img class="media-thumb" src="${m.thumb}" loading="lazy">` : `<div class="media-thumb-placeholder">${ICONS.files}</div>`}
      <div class="media-body"><div class="media-name">${esc(m.name)}</div>
      <div class="media-meta">${fmtDate(m.mtime)} · ${fmtBytes(m.size)}</div>
      <div class="media-hash">${m.hash ? "sha256:" + esc(m.hash.slice(0, 16)) + "…" : "sha256: —"}</div></div>
    </div>`).join("");
  return `
    <div class="page-title">Media</div><div class="page-sub">Photos, videos and audio evidence extracted from the filesystem.</div>
    ${items.length ? `<div class="filter-bar"><input class="form-input" placeholder="Filter media..." style="width:240px" oninput="filterGrid(this.value)"><span class="mono" style="margin-left:auto">${items.length} media files indexed</span></div>
    <div class="media-grid" id="media-grid">${cards}</div>` :
    `<div class="panel-card"><div class="empty-state">No media indexed. Run an acquisition with the media option enabled.</div></div>`}`;
}
function filterGrid(q) {
  q = q.toLowerCase();
  document.querySelectorAll("#media-grid .media-card").forEach(c =>
    c.style.display = c.textContent.toLowerCase().includes(q) ? "" : "none");
}

function pageFiles() {
  const rows = (ARTIFACTS.app_databases || []).slice(0, 300).map(d => `<tr>
    <td class="mono"><b>${esc(d.path)}</b></td>
    <td>${esc(d.domain)}</td>
    <td class="num">${fmtBytes(d.size)}</td>
    <td class="mono">Extracted</td>
  </tr>`).join("");
  return tablePage("Files", "Application sandbox databases and container storage.", ["Path","Domain","Size","Status"], rows || `<tr><td colspan="4" class="empty-state">No files indexed.</td></tr>`);
}

/* ---------------- forensics ---------------- */
function pageForensics() {
  const tabs = ["Timeline","Artifact Search","Hash Analysis","SQLite Browser","File System"];
  const tl = ARTIFACTS.timeline_preview || [];
  const sqliteFiles = ARTIFACTS.sqlite_files || [];
  return `
    <div class="page-title">Forensics</div><div class="page-sub">Advanced forensic examination: timeline, multi-table search, multi-hashing, and SQLite inspection.</div>
    <div class="panel-card">
      <div class="subnav">${tabs.map((t, i) => `<span class="subnav-item ${i === 0 ? "active" : ""}" onclick="switchTab(this,'ftab',${i})">${t}</span>`).join("")}</div>

      <div class="ftab" id="ftab-0">
        ${tl.length ? `<table class="data"><thead><tr><th>Timestamp</th><th>Artifact Category</th><th>Event Summary</th></tr></thead>
          <tbody>${tl.map(r => `<tr><td class="mono">${esc(r[0])}</td><td><span class="status-pill blue">${esc(r[1])}</span></td><td>${esc(r[2])}</td></tr>`).join("")}</tbody></table>`
        : `<div class="empty-state">Timeline populates after a backup is parsed. Generate report or run acquisition to view events.</div>`}
      </div>

      <div class="ftab" id="ftab-1" style="display:none">
        <div class="filter-bar"><input class="form-input" id="fa-search" placeholder="Search across all extracted records..." style="width:360px" oninput="artifactSearch(this.value)"></div>
        <div id="fa-results"><div class="empty-state">Type to search messages, contacts, calls, history, and notes.</div></div>
      </div>

      <div class="ftab" id="ftab-2" style="display:none">
        <div style="padding:14px">
          <div class="form-field">
            <span class="form-label">File Path (under ~/cases)</span>
            <input class="form-input" id="hash-path" placeholder="/home/.../cases/.../file" style="width:100%;max-width:560px" value="${esc(ACTIVE_CASE?.destination ? ACTIVE_CASE.destination + "/case.json" : "")}">
          </div>
          <div style="margin-top:10px;display:flex;gap:8px">
            <button class="btn primary" onclick="doMultiHash()">Compute Multi-Hash (MD5 + SHA-256 + SHA-512)</button>
            <button class="btn" onclick="doHash()">Compute SHA-256</button>
          </div>
          <div id="hash-result" style="margin-top:12px"></div>
        </div>
      </div>

      <div class="ftab" id="ftab-3" style="display:none">
        <div class="filter-bar">
          <select class="form-select" id="sql-file" onchange="loadSqlTables()" style="max-width:440px">
            <option value="">Select a SQLite file (${sqliteFiles.length} available)...</option>
            ${sqliteFiles.map(f => `<option value="${esc(f)}">${esc(f.split("/").slice(-3).join("/"))}</option>`).join("")}
          </select>
          <select class="form-select" id="sql-table" onchange="loadSqlRows()" style="max-width:220px"><option value="">Table...</option></select>
        </div>
        <div id="sql-out"><div class="empty-state">Choose a database and table to browse records (read-only mode).</div></div>
      </div>

      <div class="ftab" id="ftab-4" style="display:none">
        <table class="data"><thead><tr><th>Database Path</th><th>Domain</th><th>Size</th></tr></thead>
        <tbody>${(ARTIFACTS.app_databases || []).slice(0, 150).map(d => `<tr><td class="mono">${esc(d.path)}</td><td>${esc(d.domain)}</td><td class="num">${fmtBytes(d.size)}</td></tr>`).join("") || `<tr><td colspan="3" class="empty-state">No database files extracted.</td></tr>`}</tbody></table>
      </div>
    </div>`;
}

function artifactSearch(q) {
  q = q.toLowerCase().trim();
  const box = document.getElementById("fa-results");
  if (!q) { box.innerHTML = `<div class="empty-state">Type to search across artifact records.</div>`; return; }
  const groups = [];
  const scan = (name, rows, fields) => {
    const hits = (rows || []).filter(r => fields.some(f => String(r[f] || "").toLowerCase().includes(q))).slice(0, 8);
    if (hits.length) groups.push(`<div class="panel-heading" style="padding:10px 14px 4px">${name} — ${hits.length} hit(s)</div>
      <table class="data"><tbody>${hits.map(r => `<tr><td class="mono">${fmtDate(r.date || r.created || r.modified)}</td><td>${esc(fields.map(f => r[f]).filter(Boolean).join(" · ").slice(0, 160))}</td></tr>`).join("")}</tbody></table>`);
  };
  scan("Messages (SMS/iMessage)", ARTIFACTS.messages, ["text", "sender", "chat"]);
  scan("WhatsApp", ARTIFACTS.whatsapp, ["text", "sender", "chat"]);
  scan("Telegram", ARTIFACTS.telegram, ["text", "sender", "chat"]);
  scan("Signal", ARTIFACTS.signal, ["text", "sender", "chat"]);
  scan("Location & Telemetry", ARTIFACTS.locations, ["type", "details"]);
  scan("Contacts", ARTIFACTS.contacts, ["name", "organization"]);
  scan("Calls", ARTIFACTS.calls, ["phone", "type"]);
  scan("History", ARTIFACTS.history, ["url", "title"]);
  scan("Keychain", ARTIFACTS.keychain, ["service", "account"]);
  scan("Notes", ARTIFACTS.notes, ["title"]);
  box.innerHTML = groups.join("") || `<div class="empty-state">No matches found for "${esc(q)}".</div>`;
}

async function doHash() {
  const p = document.getElementById("hash-path").value.trim();
  const out = document.getElementById("hash-result");
  if (!p) { out.innerHTML = '<span class="mono">enter a path</span>'; return; }
  out.innerHTML = '<span class="mono">Computing SHA-256...</span>';
  const r = await api("/api/hash", {method: "POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({path: p})});
  out.innerHTML = r.sha256 ? `<div class="mono" style="word-break:break-all;color:#34d399">SHA-256: ${esc(r.sha256)}</div>` : `<span class="mono" style="color:var(--red)">${esc(r.error || "failed")}</span>`;
}

async function doMultiHash() {
  const p = document.getElementById("hash-path").value.trim();
  const out = document.getElementById("hash-result");
  if (!p) { out.innerHTML = '<span class="mono">enter a path</span>'; return; }
  out.innerHTML = '<span class="mono">Computing C++ hardware-accelerated triple multi-hash...</span>';
  const r = await api("/api/multihash?path=" + encodeURIComponent(p));
  if (r && !r.error && r.sha256) {
    out.innerHTML = `
      <table class="data" style="max-width:720px">
        <thead><tr><th>Algorithm</th><th>Hash Digest</th></tr></thead>
        <tbody>
          <tr><td><b>MD5</b></td><td class="mono">${esc(r.md5)}</td></tr>
          <tr><td><b>SHA-256</b></td><td class="mono">${esc(r.sha256)}</td></tr>
          <tr><td><b>SHA-512</b></td><td class="mono" style="word-break:break-all">${esc(r.sha512)}</td></tr>
          <tr><td><b>Engine</b></td><td><span class="status-pill green">Single-Pass Native C++ (Hardware Accelerated)</span></td></tr>
        </tbody>
      </table>`;
  } else {
    out.innerHTML = `<span class="mono" style="color:var(--red)">${esc((r && r.error) || "computation failed (path must be under ~/cases)")}</span>`;
  }
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
    document.getElementById("sql-out").innerHTML = `<div class="empty-state">${r.tables.length} tables found — select one to preview rows.</div>`;
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
  const statusEl = document.getElementById("rep-status");
  if (statusEl) statusEl.textContent = "generating report.html & case_uco.jsonld...";
  notify("Report Generation", `Generating forensic report for ${ACTIVE_CASE.case_id}...`, "info", "EVIDENCE");
  const r = await api("/api/report", {method: "POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({case: ACTIVE_CASE})});
  if (statusEl) statusEl.textContent = r.ok ? "Report ready" : (r.error || "failed");
  if (r.ok) {
    notify("Report Ready", `Examiner report generated: ${r.report}`, "success", "EVIDENCE");
    render();
  } else {
    notify("Report Failed", r.error || "Failed to generate report", "error", "EVIDENCE");
  }
}

function pageReports() {
  const dest = ACTIVE_CASE?.destination || "";
  return `
    <div class="page-title">Reports & Evidentiary Certification</div>
    <div class="page-sub">Generate case reports, CASE/UCO cyber-investigation ontologies, and triple-hash certificates.</div>
    <div class="panel-card"><div class="panel-card-head">New Report Generation</div>
      <div class="form-grid">
        <div class="form-field"><span class="form-label">Report Title</span><input class="form-input" id="rep-title" value="${ACTIVE_CASE ? esc(ACTIVE_CASE.case_id) + " — Forensic Investigation Report" : "Case Report"}"></div>
        <div class="form-field"><span class="form-label">Examiner</span><input class="form-input" id="rep-examiner" value="${esc(ACTIVE_CASE?.examiner || "Forensic Examiner")}"></div>
        <div class="form-field"><span class="form-label">Evidence Scope</span><select class="form-select"><option>Full Evidence Summary (All Artifacts)</option><option>Messages & Chats Only</option><option>Location & Telemetry Only</option></select></div>
        <div class="form-field"><span class="form-label">Output Standard</span><select class="form-select"><option>HTML + CASE/UCO JSON-LD 1.3.0</option><option>HTML Only</option></select></div>
        <div class="form-field full"><span class="form-label">Examiner Findings Notes</span><textarea class="form-textarea" placeholder="Summary of forensic findings...">${esc(ACTIVE_CASE?.notes || "")}</textarea></div>
      </div>
      <div style="padding:0 14px 14px"><button class="btn primary" onclick="genReport()">Generate Report</button> <span id="rep-status" class="mono" style="margin-left:8px"></span></div>
    </div>
    <div class="panel-card"><div class="panel-card-head">Generated Reports, Ontologies & Integrity Seals</div>
      <table class="data"><thead><tr><th>Document</th><th>Format</th><th>Description</th><th>Action</th></tr></thead>
      <tbody>${ACTIVE_CASE ? `
        <tr><td><b>${esc(ACTIVE_CASE.case_id)} — report.html</b></td><td><span class="status-pill green">HTML</span></td><td>Standard examiner forensic report with charts and artifacts</td><td><button class="btn" onclick="window.open('/api/file?path=${encodeURIComponent(dest + "/report/report.html")}')">Open HTML</button></td></tr>
        <tr><td><b>${esc(ACTIVE_CASE.case_id)} — case_uco.jsonld</b></td><td><span class="status-pill purple">CASE / UCO JSON-LD</span></td><td>Cyber-investigation Analysis Standard Expression (CASE / UCO 1.3.0)</td><td><button class="btn" onclick="window.open('/api/uco?case=${encodeURIComponent(ACTIVE_CASE.case_id)}')">View UCO</button></td></tr>
        <tr><td><b>${esc(ACTIVE_CASE.case_id)} — certification.json</b></td><td><span class="status-pill blue">Triple-Hash Seal</span></td><td>MD5, SHA-256, SHA-512 manifest and examiner attestation</td><td><button class="btn" onclick="window.open('/api/file?path=${encodeURIComponent(dest + "/certification.json")}')">View Certificate</button></td></tr>
        <tr><td><b>${esc(ACTIVE_CASE.case_id)} — evidence export</b></td><td><span class="status-pill amber">tar.gz</span></td><td>Cryptographically hashed evidence archive</td><td><button class="btn" onclick="exportCase()">Download</button></td></tr>`
        : `<tr><td colspan="4" class="empty-state">No active case selected. Reports generate as <span class="mono">report.html</span>, <span class="mono">case_uco.jsonld</span>, and <span class="mono">certification.json</span>.</td></tr>`}</tbody></table>
    </div>`;
}

async function exportCase() {
  if (!ACTIVE_CASE) { toast("No active case to export", "red"); return; }
  notify("Export Archive", `Packaging evidence archive for ${ACTIVE_CASE.case_id}...`, "info", "EVIDENCE");
  const r = await api("/api/export", {method: "POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({case_id: ACTIVE_CASE.case_id})});
  if (r.url) {
    notify("Export Complete", `Archive ready (${fmtBytes(r.size)}). Download started.`, "success", "EVIDENCE");
    window.open(r.url);
  } else {
    notify("Export Failed", r.error || "Archive creation failed", "error", "EVIDENCE");
  }
}

/* ---------------- settings (real persistence) ---------------- */
async function pageSettings() {
  if (!CACHE.settings) {
    CACHE.settings = await api("/api/settings");
  }
  const s = CACHE.settings || {};
  return `
    <div class="page-title">Settings</div><div class="page-sub">Workstation preferences and forensic execution defaults.</div>
    <div class="panel-card">
      <div class="panel-card-head">Workstation Configuration</div>
      <div class="form-grid">
        <div class="form-field">
          <span class="form-label">Default Examiner Name</span>
          <input class="form-input" id="set-examiner" value="${esc(s.examiner || "Forensic Examiner")}">
        </div>
        <div class="form-field">
          <span class="form-label">Cases Storage Root</span>
          <input class="form-input" id="set-cases-root" value="${esc(s.cases_root || "~/cases")}">
        </div>
        <div class="form-field">
          <span class="form-label">Default Integrity Hash</span>
          <select class="form-select" id="set-hash-algo">
            <option value="Triple-Hash (MD5+SHA256+SHA512)" ${s.hash_algo?.includes("Triple") ? "selected" : ""}>Triple-Hash (MD5 + SHA-256 + SHA-512 Native)</option>
            <option value="SHA-256" ${s.hash_algo === "SHA-256" ? "selected" : ""}>SHA-256 Only</option>
          </select>
        </div>
        <div class="form-field">
          <span class="form-label">Background Polling Frequency</span>
          <select class="form-select" id="set-poll-rate">
            <option value="4000" ${s.poll_interval === 4000 ? "selected" : ""}>4 seconds (Balanced Responsive)</option>
            <option value="2000" ${s.poll_interval === 2000 ? "selected" : ""}>2 seconds (High Speed)</option>
            <option value="8000" ${s.poll_interval === 8000 ? "selected" : ""}>8 seconds (Low Power)</option>
          </select>
        </div>
      </div>
      <div style="padding:0 14px 14px;display:flex;gap:8px">
        <button class="btn primary" onclick="saveSettings()">Save Configuration</button>
        <button class="btn" onclick="clearWorkstationCache()">Clear UI Cache</button>
      </div>
    </div>`;
}

async function saveSettings() {
  const ex = document.getElementById("set-examiner").value.trim();
  const cr = document.getElementById("set-cases-root").value.trim();
  const ha = document.getElementById("set-hash-algo").value;
  const pr = parseInt(document.getElementById("set-poll-rate").value) || 4000;

  const payload = { examiner: ex, cases_root: cr, hash_algo: ha, poll_interval: pr };
  const r = await api("/api/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  CACHE.settings = r;
  document.getElementById("topbar-examiner").textContent = ex || "Examiner";
  notify("Settings Saved", "Workstation configuration written to disk.", "success", "SYSTEM");
}

function clearWorkstationCache() {
  Object.keys(CACHE).forEach(k => CACHE[k] = null);
  toast("Workstation cache invalidated", "blue");
  refreshCurrentPage();
}

/* ---------------- helper tables & views ---------------- */
function tablePage(title, sub, cols, rows) {
  return `
    <div class="page-title">${title}</div><div class="page-sub">${sub}</div>
    <div class="panel-card">
      <div class="filter-bar"><input class="form-input" placeholder="Filter ${title.toLowerCase()}..." style="width:240px" oninput="filterTable('tp-${title}', this.value)"><button class="btn" onclick="refreshCurrentPage()">Refresh</button></div>
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
  if (a === "autoexploit") {
    location.hash = "exploits";
    startAutoExploit();
    return;
  }
  if (a === "add") location.hash = "devices";
  else if (a === "open") openCaseModal();
  else if (a === "report") location.hash = "reports";
  else if (a === "export") exportCase();
  else if (a === "parse") openParseModal();
}

/* ---------------- exploit state & evaluation ---------------- */
let EXPLOIT_FILTER_CHIP = "";
let EXPLOIT_FILTER_IOS = "";
let EXPLOIT_FILTER_LAYER = "";
let EXPLOIT_FILTER_NOHW = false;
let ROUTE_DETAILS_EXPANDED = {};

function toggleRouteDetails(idx) {
  ROUTE_DETAILS_EXPANDED[idx] = !ROUTE_DETAILS_EXPANDED[idx];
  const row = document.getElementById(`route-detail-${idx}`);
  if (row) {
    row.style.display = ROUTE_DETAILS_EXPANDED[idx] ? "table-row" : "none";
  }
}

// Three-tier honest deployability (mirrors backend /api/exploit/execute):
//   HOST     - executor runs a real PC-side binary (checkm8/gaster, usbliter8ctl,
//              palera1n, irecovery, PongoOS/Blackbird). -> runs host tool
//   SIDELOAD - on-device app agent (Dopamine/kfd/TrollStore/NathanLR). Requires
//              installing the app on an unlocked device (afu_agent flow).
//   none     - DOCUMENTED-only chains (no public PoC / CISA / research-only),
//              no public weaponization -> not deployable, honesty-flagged.
const DEPLOY_HINT_RE = /no public poc|no public tooling|research-only|cisa known exploited|documented only|no public weaponization/i;
const HOST_BIN_RE = /gaster|ipwndfu|palera1n|checkra1n|irecovery|usbliter8ctl|picotool|idevice|pymobiledevice3|ifuse|ssh|pongoos|restored|idevicebackup2|ipwnder32/i;
function routeDeployMode(r) {
  const tl = (r.tooling || []).join(" ").toLowerCase();
  if (DEPLOY_HINT_RE.test(tl)) return "none";
  const layer = String(r.layer || "");
  if (HOST_BIN_RE.test(tl) || ["bootrom","bootrom-chain","sep","iboot"].includes(layer)) return "host";
  if (["kernel","userspace","trollstore","ppl"].includes(layer)) return "sideload";
  return "none";
}
function deployTierBadge(r) {
  const m = routeDeployMode(r);
  if (m === "host")    return `<span class="status-pill green" style="font-size:9px">HOST</span>`;
  if (m === "sideload") return `<span class="status-pill cyan" style="font-size:9px">SIDELOAD</span>`;
  return `<span class="status-pill gray" style="font-size:9px">RESEARCH-ONLY</span>`;
}
async function executeSingleRoute(name, idx) {
  const outBox = document.getElementById(`route-out-${idx}`);
  const statusTag = document.getElementById(`route-tag-${idx}`);
  if (outBox) {
    outBox.style.display = "block";
    outBox.textContent = `Testing route preconditions for ${name}...`;
  }
  notify("Exploit Execution", `Testing route ${name}...`, "info", "EXPLOIT");
  const r = await api("/api/exploit/execute", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ route: name, allow_destructive: false }),
  });
  if (outBox) {
    outBox.textContent = r.message + (r.output ? `\n\nOutput:\n${r.output}` : "") + (r.detail ? `\nDetail: ${r.detail}` : "");
  }
  if (statusTag) {
    statusTag.className = `status-pill ${r.ok ? "green" : "amber"}`;
    statusTag.textContent = r.ok ? "VERIFIED / READY" : (r.status?.toUpperCase() || "FAILED");
  }
}

async function evalExploitsTarget() {
  const c = document.getElementById("target-chip")?.value || "";
  const v = document.getElementById("target-ios")?.value.trim() || "";
  const l = document.getElementById("target-layer")?.value || "";
  const n = document.getElementById("target-nohw")?.checked || false;
  EXPLOIT_FILTER_CHIP = c;
  EXPLOIT_FILTER_IOS = v;
  EXPLOIT_FILTER_LAYER = l;
  EXPLOIT_FILTER_NOHW = n;
  CACHE.exploits = null; // force fetch with filter
  await render();
}

async function resetExploitsTarget() {
  EXPLOIT_FILTER_CHIP = DEVICE?.chip || "";
  EXPLOIT_FILTER_IOS = DEVICE?.ios || "";
  EXPLOIT_FILTER_LAYER = "";
  EXPLOIT_FILTER_NOHW = false;
  CACHE.exploits = null;
  await render();
}

/* ---------------- auto-exploiter ---------------- */
let AEXPLOIT = null;
let AE_DESTRUCTIVE = false;

function toggleAeDestructive(v) {
  AE_DESTRUCTIVE = !!v;
}

async function refreshAutoExploit() {
  try { AEXPLOIT = await api("/api/autoexploit"); }
  catch { AEXPLOIT = null; }
  return AEXPLOIT;
}

async function startAutoExploit() {
  const allowD = document.getElementById("ae-destructive")?.checked ?? AE_DESTRUCTIVE;
  AE_DESTRUCTIVE = allowD;
  notify("Auto-Exploiter", "Probing attached device and running prioritized exploit routes...", "info", "EXPLOIT");
  const r = await api("/api/autoexploit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ allow_destructive: allowD }),
  });
  if (r.busy) { notify("Auto-Exploiter Busy", "An exploit run is already active.", "warning", "EXPLOIT"); }
  else if (r.started) { notify("Auto-Exploiter Running", "Probing target silicon and testing public routes until hit.", "info", "EXPLOIT"); pollAutoExploit(); }
  else { notify("Auto-Exploiter Failed", "Could not start exploit engine.", "error", "EXPLOIT"); }
}

async function pollAutoExploit() {
  const st = await refreshAutoExploit();
  if (st && st.running) {
    const pane = document.getElementById("ae-pane");
    if (pane) pane.innerHTML = await renderAutoExploitPane(st);
    setTimeout(pollAutoExploit, 1500);
  } else if (st && !st.finished_at) {
    setTimeout(pollAutoExploit, 700);
  } else if (st && st.report) {
    const pane = document.getElementById("ae-pane");
    if (pane) pane.innerHTML = await renderAutoExploitPane(st);
  }
}

async function renderAutoExploitPane(st) {
  if (!st) { await refreshAutoExploit(); st = AEXPLOIT; }
  if (!st) return `<div class="empty-state">Auto-exploiter state unavailable.</div>`;
  const rep = st.report;
  const dev = rep && rep.target ? rep.target : null;
  const lines = st.log && st.log.length ? st.log.map(l => `<div class="log-line">${esc(l)}</div>`).join("") : "";
  const results = rep && rep.results && rep.results.length
    ? `<table class="data"><thead><tr><th>Route</th><th>Status</th><th>Detail</th></tr></thead><tbody>
       ${rep.results.map(r => {
         const mark = r.status === "succeeded" ? "✓" : r.status === "failed" ? "✗" : r.status === "skipped" ? "–" : "…";
         const color = r.status === "succeeded" ? "green" : r.status === "failed" ? "red" : r.status === "skipped" ? "gray" : "amber";
         return `<tr><td class="mono"><b>${esc(r.name)}</b></td><td><span class="status-pill ${color}">${mark} ${esc(r.status)}</span></td><td style="font-size:11px">${esc(r.detail)}</td></tr>`;
       }).join("")}</tbody></table>`
    : `<div class="empty-state">No routes attempted yet. Start the auto-exploiter to run applicable routes.</div>`;

  const banner = st.running
    ? `<div class="log-event"><span class="text-tag warning">RUNNING</span><div class="log-body"><div class="log-text"><b>Probing and testing routes:</b> trying bootrom → SEP → AFU in priority sequence.</div></div></div>`
    : rep && rep.winner
      ? `<div class="log-event"><span class="text-tag success">SUCCESS</span><div class="log-body"><div class="log-text"><b>Route succeeded:</b> ${esc(rep.winner)}</div></div></div>`
      : st.error
        ? `<div class="log-event"><span class="text-tag error">ERROR</span><div class="log-body"><div class="log-text">${esc(st.error)}</div></div></div>`
        : `<div class="log-event"><span class="text-tag info">IDLE</span><div class="log-body"><div class="log-text">Ready. Start the auto-exploiter to probe device and run applicable routes until one succeeds.</div></div></div>`;

  return `
    <div style="padding:12px 14px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
      ${st.running ? `<span class="status-pill amber">● RUNNING</span>` : (rep && rep.winner) ? `<span class="status-pill green">SUCCESS</span>` : `<span class="status-pill gray">IDLE</span>`}
      <label style="display:flex;align-items:center;gap:6px;font-size:11.5px;color:var(--muted);cursor:pointer">
        <input type="checkbox" id="ae-destructive" ${AE_DESTRUCTIVE ? "checked" : ""} oninput="toggleAeDestructive(this.checked)"> Allow destructive (A10/A11 checkm8 on iOS 16+)
      </label>
      <button class="btn primary" style="margin-left:auto" onclick="startAutoExploit()" ${st.running ? "disabled" : ""}>${st.running ? "Running…" : "▶ Auto-Exploit Device"}</button>
      ${st.running ? `<button class="btn" onclick="setTimeout(pollAutoExploit,1000)">Refresh</button>` : ""}
    </div>
    ${banner}
    ${dev ? `<div style="padding:8px 14px;border-top:1px solid var(--border2);display:flex;flex-wrap:wrap;gap:16px;font-size:11.5px">
        <span class="mono" style="color:var(--muted)">device: <b style="color:#fff">${esc(dev.model || "?")}</b></span>
        <span class="mono" style="color:var(--muted)">chip: <b style="color:#fff">${esc(dev.chip || "?")}</b></span>
        <span class="mono" style="color:var(--muted)">iOS: <b style="color:#fff">${esc(dev.ios || "?")}</b></span>
        <span class="mono" style="color:var(--muted)">state: <b style="color:#fff">${esc(dev.state || "?")}</b>${dev.pwnd ? ` (PWND: ${esc(dev.pwnd)})` : ""}</span>
      </div>` : ""}
    <div style="padding:10px 14px;border-top:1px solid var(--border2)">${results}</div>
    ${lines ? `<div style="padding:10px 14px;border-top:1px solid var(--border2);max-height:160px;overflow:auto;font-family:var(--font-mono);font-size:11px;color:var(--muted);background:#090b0e">${lines}</div>` : ""}`;
}

async function pageExploits() {
  if (!EXPLOIT_FILTER_CHIP && DEVICE?.chip) EXPLOIT_FILTER_CHIP = DEVICE.chip;
  if (!EXPLOIT_FILTER_IOS && DEVICE?.ios) EXPLOIT_FILTER_IOS = DEVICE.ios;

  const params = [];
  if (EXPLOIT_FILTER_CHIP) params.push("chip=" + encodeURIComponent(EXPLOIT_FILTER_CHIP));
  if (EXPLOIT_FILTER_IOS) params.push("ios=" + encodeURIComponent(EXPLOIT_FILTER_IOS));
  if (EXPLOIT_FILTER_LAYER) params.push("layer=" + encodeURIComponent(EXPLOIT_FILTER_LAYER));
  if (EXPLOIT_FILTER_NOHW) params.push("no_hardware=1");
  const qp = params.length ? "?" + params.join("&") : "";

  if (!CACHE.exploits) {
    CACHE.exploits = await api("/api/exploits" + qp);
  }
  const d = CACHE.exploits;
  const routes = d?.routes || [];
  const discs = d?.disclosures || [];
  const expo = d?.exposure || [];
  const rec = d?.recommendation || [];
  const targetLabel = (EXPLOIT_FILTER_CHIP || EXPLOIT_FILTER_IOS)
    ? ` · Target: ${EXPLOIT_FILTER_CHIP || "Any"} / ${EXPLOIT_FILTER_IOS || "Any"}`
    : (DEVICE ? ` · Attached: ${DEVICE.chip || "?"} / ${DEVICE.ios || "?"}` : "");

  await refreshAutoExploit();
  const aePane = await renderAutoExploitPane(AEXPLOIT);

  const chipsList = ["", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12", "A13", "A14", "A15", "A16", "A17", "M1", "M2", "M3", "M4"];
  const layersList = ["", "bootrom", "sep", "kernel", "userspace", "trollstore", "pac/ppl"];

  const routeRows = routes.map((r, idx) => {
    const isExp = ROUTE_DETAILS_EXPANDED[idx];
    const chipsStr = (r.chips || []).join(", ") || "ANY";
    const toolsStr = (r.tooling || []).map(t => `<span class="status-pill gray" style="font-size:9.5px;padding:1px 5px">${esc(t)}</span>`).join(" ");
    const statePill = r.state ? `<span class="status-pill ${r.state.includes('DFU') ? 'purple' : 'cyan'}" style="font-size:9.5px">${esc(r.state)}</span>` : "—";
    return `
      <tr>
        <td class="mono"><b>${esc(r.name)}</b></td>
        <td><span class="status-pill ${r.hardware === "none" ? "green" : r.hardware === "rig" ? "red" : "amber"}">${esc(r.hardware)}</span></td>
        <td>${esc(r.layer)}</td>
        <td class="mono">${esc(r.year)}</td>
        <td class="mono" style="font-size:11px">${esc(chipsStr)}</td>
        <td>${esc(String(r.ios || "").slice(0, 36))}</td>
        <td>${statePill} ${deployTierBadge(r)}</td>
        <td>${toolsStr || "—"}</td>
        <td>${esc(String(r.bfu || "").slice(0, 36))}</td>
        <td><button class="btn" style="padding:2px 8px;font-size:11px" onclick="toggleRouteDetails(${idx})">${isExp ? "Hide" : "Details"}</button></td>
      </tr>
      <tr id="route-detail-${idx}" style="display:${isExp ? "table-row" : "none"};background:#131720">
        <td colspan="10" style="padding:14px;border-bottom:1px solid var(--border2)">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;font-size:11.5px">
            <div>
              <div style="color:var(--muted);font-weight:700;margin-bottom:6px">EXPLOIT OVERVIEW & TECHNICAL NOTES</div>
              <div style="line-height:1.5">${esc(r.notes || "Defensive exploit documentation and implementation.")}</div>
              <div style="margin-top:8px;color:var(--faint)">Layer: <b>${esc(r.layer)}</b> · Year: <b>${esc(r.year)}</b> · BFU Impact: <b>${esc(r.bfu || "None")}</b></div>
            </div>
            <div>
              <div style="color:var(--muted);font-weight:700;margin-bottom:6px">PRECONDITION VERIFICATION & EXECUTION</div>
              <div>Supported Silicon: <span class="mono">${esc(chipsStr)}</span></div>
              <div>Required State: <span class="mono">${esc(r.state || "AFU / Normal")}</span></div>
              <div>Hardware Tooling: <span class="mono">${esc(r.hardware === "none" ? "Plain PC + USB Cable" : r.hardware === "rig" ? "Hardware Rig Required (usbliter8/RP2350)" : "App / Local Execution")}</span></div>
              <div style="margin-top:10px;display:flex;align-items:center;gap:8px">
                <button class="btn success" onclick="executeSingleRoute('${esc(r.name).replace(/'/g, "\\'")}', ${idx})">⚡ Test / Run Route</button>
                <span id="route-tag-${idx}" class="status-pill gray">UNTESTED</span>
              </div>
            </div>
          </div>
          <div class="route-exec-box" id="route-out-${idx}" style="display:none"></div>
        </td>
      </tr>`;
  }).join("");

  const discRows = discs.map(x => {
    const k = String(x.kind || "");
    const high = /keychain|root|kernel.?exec|kernel.?write|kernel privilege|arbitrary code|bypass/i.test(k + " " + String(x.impact || ""));
    const badge = high ? `<span class="status-pill red">HIGH-VALUE</span>` : `<span class="status-pill amber">${esc(k.slice(0, 24))}</span>`;
    return `<tr>
      <td class="mono"><b>${esc(x.cve)}</b></td>
      <td>${esc(x.component)}</td>
      <td>${badge}</td>
      <td class="mono">${esc(String(x.patch || "").slice(0, 30))}</td>
      <td>${esc(String(x.impact || "").slice(0, 66))}</td>
    </tr>`;
  }).join("");

  const expoRows = expo.map(x => `
    <tr><td class="mono"><b>${esc(x.name || x.cve || "")}</b></td><td>${esc(x.match || x.kind || "")}</td>
        <td>${esc(x.hardware || x.component || "")}</td></tr>`).join("");

  const verRows = [
    ["26.0", '<span class="status-pill green">Dopamine 3 (A12/A13 + arm64)</span>'],
    ["26.0.1", '<span class="status-pill green">Dopamine 3 (A12/A13 + arm64)</span>'],
    ["26.1", '<span class="status-pill gray">none public</span>'],
    ["26.6", '<span class="status-pill gray">none public</span>'],
    ["26.6.1", '<span class="status-pill gray">none public</span>'],
    ["27.0", '<span class="status-pill gray">none public</span>'],
  ].map(([v, pill]) => `<tr><td class="mono">${v}</td><td>${pill}</td></tr>`).join("");

  return `
    <div class="page-title">Public Exploit Catalog & Silicon Exposure Matrix${esc(targetLabel)}</div>
    <div class="page-sub">Verified public iOS exploit routes, jailbreak vectors, and recent acquisition disclosures. 100% lawful, defensive research catalog.</div>

    <!-- Auto-Exploiter (Cellebrite/AXIOM style) -->
    <div class="panel-card">
      <div class="panel-card-head">
        Auto-Exploiter
        <span class="status-pill" style="margin-left:6px;font-weight:400">probe → run routes → stop on hit</span>
      </div>
      <div id="ae-pane">${aePane}</div>
    </div>

    <!-- Target Evaluation Card -->
    <div class="panel-card">
      <div class="panel-card-head">Target Device & Silicon Evaluator</div>
      <div class="filter-bar" style="flex-wrap:wrap;gap:8px;padding:10px 14px">
        <span class="mono" style="color:var(--muted)">Target Chip:</span>
        <select class="form-select" id="target-chip" style="width:130px">
          ${chipsList.map(c => `<option value="${c}" ${EXPLOIT_FILTER_CHIP === c ? "selected" : ""}>${c ? c : "All Chips"}</option>`).join("")}
        </select>
        <span class="mono" style="color:var(--muted);margin-left:8px">Target iOS:</span>
        <input class="form-input" id="target-ios" placeholder="e.g. 16.5" style="width:110px" value="${esc(EXPLOIT_FILTER_IOS)}">
        <span class="mono" style="color:var(--muted);margin-left:8px">Layer:</span>
        <select class="form-select" id="target-layer" style="width:130px">
          ${layersList.map(l => `<option value="${l}" ${EXPLOIT_FILTER_LAYER === l ? "selected" : ""}>${l ? l : "All Layers"}</option>`).join("")}
        </select>
        <label style="display:flex;align-items:center;gap:6px;font-size:11.5px;color:var(--muted);cursor:pointer;margin-left:8px">
          <input type="checkbox" id="target-nohw" ${EXPLOIT_FILTER_NOHW ? "checked" : ""}> Plain PC+USB Only
        </label>
        <button class="btn primary" onclick="evalExploitsTarget()">Evaluate Target</button>
        <button class="btn" onclick="resetExploitsTarget()">Reset</button>
      </div>
    </div>

    ${rec.length ? `<div class="panel-card"><div class="panel-card-head">Recommended Acquisition Vectors for ${esc(EXPLOIT_FILTER_CHIP || DEVICE?.chip || "Target")}</div>
      ${rec.map(s => `<div class="log-event"><span class="text-tag success">RECOMMENDED</span><div class="log-body"><div class="log-text">${esc(s.slice(0, 140))}</div></div></div>`).join("")}</div>` : ""}

    ${expo.length ? `<div class="panel-card"><div class="panel-card-head">Exposure Assessment (${esc(EXPLOIT_FILTER_CHIP || "Target")} / ${esc(EXPLOIT_FILTER_IOS || "Any")})</div>
      <table class="data"><thead><tr><th>Route / CVE</th><th>Exposure Window</th><th>Hardware / Component</th></tr></thead><tbody>${expoRows}</tbody></table></div>` : ""}

    <div class="panel-card">
      <div class="panel-card-head">Firmware Status (26.x-27.x)</div>
      <table class="data"><thead><tr><th>iOS</th><th>Public Route Status</th></tr></thead><tbody>${verRows}</tbody></table>
    </div>

    <div class="panel-card">
      <div class="panel-card-head">Routes (${routes.length} cataloged)</div>
      <div class="filter-bar">
        <input class="form-input" id="exploit-filter" placeholder="Filter routes by name, tool, or layer..." style="width:300px" oninput="filterTable('tp-Exploits', this.value)">
        <button class="btn" onclick="CACHE.exploits=null;render()">Refresh</button>
      </div>
      <table class="data" id="tp-Exploits">
        <thead><tr><th>Route Name</th><th>Hardware</th><th>Layer</th><th>Year</th><th>Silicon</th><th>iOS Window</th><th>State</th><th>Tooling</th><th>BFU Impact</th><th>Action</th></tr></thead>
        <tbody>${routeRows}</tbody>
      </table>
    </div>

    <div class="panel-card">
      <div class="panel-card-head">Recent Vulnerability Disclosures (${discs.length} tracked)</div>
      <table class="data"><thead><tr><th>CVE</th><th>Component</th><th>Impact Severity</th><th>Patch Window</th><th>Technical Detail</th></tr></thead>
      <tbody>${discRows}</tbody></table>
    </div>`;
}

/* ---------------- tools & diagnostics ---------------- */
async function runDoctorCheck() {
  CACHE.doctor = null;
  notify("Doctor Diagnostics", "Running host toolchain & workstation health checks...", "info", "SYSTEM");
  await render();
}

async function pageTools() {
  if (!CACHE.tools) CACHE.tools = await api("/api/tools");
  if (!CACHE.doctor) CACHE.doctor = await api("/api/doctor");
  if (!CACHE.stance) CACHE.stance = await api("/api/stance");
  if (!CACHE.bfu) CACHE.bfu = await api("/api/bfu?chip=" + encodeURIComponent(DEVICE?.chip || "A13"));

  const tdata = CACHE.tools;
  const doc = CACHE.doctor;
  const stance = CACHE.stance;
  const bfu = CACHE.bfu;

  const tools = (tdata && tdata.tools) || [];
  const sum = (tdata && tdata.summary) || {};
  const installed = tools.filter(t => t.installed).length;
  const cats = ["acquisition", "jailbreak", "restore", "parsing", "analysis"];

  const compRows = stance ? stance.rows.map(r => {
    const [cap, ...cells] = r;
    const sm = stance.status_map || {};
    const pill = v => {
      const s = sm[v] || v;
      const cls = v === "FULL" ? "green" : (v === "NONE" || v === "N/A") ? "gray" : "amber";
      return `<span class="status-pill ${cls}">${esc(s)}</span>`;
    };
    return `<tr><td><b>${esc(cap)}</b></td>${cells.map(c => `<td>${pill(c)}</td>`).join("")}</tr>`;
  }).join("") : "";

  const docPill = doc
    ? `<span class="status-pill ${doc.ready ? "green" : "amber"}">${doc.ready ? "ALL CHECKS PASSED" : `${doc.passed}/${doc.total} PASSED`}</span>`
    : "";

  return `
    <div class="page-head"><div class="page-title">Forensic Toolchain & Workstation Diagnostics</div>
    <div class="page-sub">Open-source iOS forensic tooling and workstation health detected live on this host.</div></div>

    <!-- Doctor Diagnostics Panel -->
    <div class="panel-card">
      <div class="panel-card-head">
        Workstation Diagnostics (Doctor) ${docPill}
        <button class="btn" style="margin-left:auto" onclick="runDoctorCheck()">Re-run Diagnostics</button>
      </div>
      ${doc ? `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:12px 14px">
          ${(doc.checks || []).map(c => `
            <div class="log-event" style="padding:6px 10px;border:1px solid var(--border);border-radius:4px;background:var(--panel2)">
              <span class="text-tag ${c.ok ? "success" : "warning"}">${c.ok ? "PASS" : "WARN"}</span>
              <div class="log-body">
                <div class="log-text"><b>${esc(c.check)}</b> <span class="mono" style="color:var(--muted);font-size:11px">(${esc(c.detail || (c.ok ? "ok" : "missing"))})</span></div>
              </div>
            </div>`).join("")}
        </div>` : '<div class="empty-state">Diagnostics not loaded. Click Re-run Diagnostics.</div>'}
    </div>

    <!-- Toolchain Metrics -->
    <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px">
      ${cats.map(c => { const cc = (sum.by_category && sum.by_category[c]) || {installed:0,total:0};
        return `<div class="metric-card"><div class="metric-body"><div class="metric-label">${c.toUpperCase()}</div>
        <div class="metric-value">${cc.installed}/${cc.total}</div></div></div>`; }).join("")}
    </div>

    <div class="panel-card"><div class="panel-card-head">Toolchain (${installed}/${tools.length} installed)</div>
    <div class="filter-bar"><input class="form-input" id="tool-filter" placeholder="Filter tools by name or purpose..." style="width:280px" oninput="filterTable('tp-Tools', this.value)">
      <button class="btn" onclick="CACHE.tools=null;render()">Refresh</button></div>
    <table class="data" id="tp-Tools"><thead><tr><th>Tool</th><th>Category</th><th>Status</th><th>Purpose</th></tr></thead><tbody>
    ${tools.map(t => `<tr><td><b>${esc(t.name)}</b></td><td><span class="status-pill gray">${t.cat}</span></td>
      <td>${t.installed ? '<span class="status-pill green">INSTALLED</span>' : '<span class="status-pill amber">MISSING</span>'}</td>
      <td>${esc(t.purpose)}</td></tr>`).join("") || '<tr><td colspan="4">No tools data available.</td></tr>'}
    </tbody></table>
    </div>

    ${bfu ? `<!-- BFU panel -->
    <div class="panel-card"><div class="panel-card-head">BFU for modern devices (${esc(bfu.playbook.chip)})</div>
    ${bfu.playbook.eligible
      ? `<div class="log-event"><span class="text-tag success">ELIGIBLE</span><div class="log-body"><div class="log-text">usbliter8 route is public for this chip. Execution Playbook:</div></div></div>
         <table class="data"><thead><tr><th>#</th><th>Phase</th><th>Action</th><th>Expectation</th></tr></thead><tbody>
         ${bfu.playbook.steps.map(st => `<tr><td>${st.n}</td><td><span class="status-pill blue">${st.phase}</span></td><td class="mono">${esc(st.cmd)}</td><td>${esc(st.expect)}</td></tr>`).join("")}
         </tbody></table>`
      : `<div class="log-event"><span class="text-tag warning">SEP WALL</span><div class="log-body"><div class="log-text">No public bootrom route for ${esc(bfu.playbook.chip)}. Escrow pairing is the passcode-free recovery path.</div></div></div>`}
    <div class="log-event"><span class="text-tag info">SEP STATUS</span><div class="log-body"><div class="log-text">SEP wall: ${esc(bfu.playbook.sep_wall)}</div></div></div>
    <div class="filter-bar" style="margin-top:10px">
      <span class="mono" style="color:var(--muted)">escrow find:</span>
      <input class="form-input" id="escrow-path" placeholder="/home/jewboy420/cases" style="width:260px" value="${esc(ACTIVE_CASE?.destination || "")}">
      <button class="btn" onclick="runEscrowFind()">Find Escrow Records</button>
      <span class="mono" style="color:var(--muted);margin-left:10px">keybag:</span>
      <input class="form-input" id="keybag-path" placeholder="path to systembag.kb" style="width:220px" value="">
      <button class="btn" onclick="runKeybagStatus()">Keybag Status</button>
    </div>
    <div id="bfu-results" class="log-event" style="display:none;margin-top:8px"><div class="log-body" id="bfu-results-body"></div></div>
    <div class="filter-bar" style="margin-top:10px">
      <span class="mono" style="color:var(--muted)">app DBs:</span>
      <input class="form-input" id="appcat-path" placeholder="extracted container dir" style="width:260px" value="">
      <button class="btn" onclick="runAppCatalog()">Discover App Databases</button>
      <span class="mono" style="color:var(--muted);margin-left:10px">escrow unlock:</span>
      <input class="form-input" id="escrow-record" placeholder="record.plist" style="width:140px" value="">
      <input class="form-input" id="escrow-backup" placeholder="backup dir" style="width:130px" value="">
      <input class="form-input" id="escrow-out" placeholder="out dir" style="width:110px" value="">
      <button class="btn" onclick="runEscrowUnlock()">Unlock Backup</button>
    </div>
    <div id="bfu-results2" class="log-event" style="display:none;margin-top:8px"><div class="log-body" id="bfu-results-body2"></div></div>
    </div>` : ""}

    ${stance ? `<!-- Stance vs Commercial -->
    <div class="panel-card"><div class="panel-card-head">Honest stance vs commercial platforms</div>
    <table class="data"><thead><tr><th>Capability</th><th>CoreProbe</th>${stance.competitors.map(c => `<th>${esc(c)}</th>`).join("")}</tr></thead>
    <tbody>${compRows}</tbody></table>
    <div class="log-event"><span class="text-tag info">STANDARDS</span><div class="log-body"><div class="log-text">Full parity on logical / encrypted-with-passcode / checkm8 acquisition and exploit cataloging. No open-source tool matches Cellebrite BFU/DPA private hardware.</div></div></div>
    </div>` : ""}`;
}

async function runEscrowFind() {
  const p = document.getElementById("escrow-path") || document.getElementById("escrow-dir");
  const body = document.getElementById("bfu-results-body") || document.getElementById("kb-out");
  const wrap = document.getElementById("bfu-results") || body;
  if (!p || !p.value.trim()) { toast("Directory required", "red"); return; }
  const r = await api("/api/escrow?dir=" + encodeURIComponent(p.value.trim()));
  const f = r?.found || [];
  body.innerHTML = `<b>${f.length}</b> escrow record(s) found under ${esc(p.value)}.` +
    f.map(x => `<div class="mono" style="margin-top:4px">· ${esc(x.file)} [${(x.keybags||[]).map(k=>k.type).join(", ")}]</div>`).join("");
  if (wrap.style) wrap.style.display = "block";
}

async function runKeybagStatus() {
  const f = document.getElementById("keybag-path");
  const body = document.getElementById("bfu-results-body");
  const wrap = document.getElementById("bfu-results");
  if (!f || !f.value.trim()) { toast("Path to keybag required", "red"); return; }
  const r = await api("/api/keybag?file=" + encodeURIComponent(f.value.trim()));
  body.innerHTML = r?.ok ? `<pre class="mono" style="font-size:11px">${esc(r.text)}</pre>` : `<span class="mono" style="color:var(--red)">${esc(r?.error || "failed")}</span>`;
  wrap.style.display = "block";
}

async function runAppCatalog() {
  const p = document.getElementById("appcat-path");
  const body = document.getElementById("bfu-results-body2");
  const wrap = document.getElementById("bfu-results2");
  if (!p || !p.value.trim()) { toast("Directory required", "red"); return; }
  const r = await api("/api/appcatalog?dir=" + encodeURIComponent(p.value.trim()));
  const dbs = r?.databases || [];
  body.innerHTML = `<b>${dbs.length}</b> database(s) found.` +
    dbs.map(d => `<div class="mono" style="margin-top:4px">· ${esc(d.rel)} [${esc(d.app || "App")}]</div>`).join("");
  wrap.style.display = "block";
}

async function runEscrowUnlock() {
  const rec = document.getElementById("escrow-record");
  const bk = document.getElementById("escrow-backup");
  const out = document.getElementById("escrow-out");
  const body = document.getElementById("bfu-results-body2");
  const wrap = document.getElementById("bfu-results2");
  if (!rec || !rec.value || !bk || !bk.value || !out || !out.value) {
    toast("Record, backup, and output paths are all required", "red");
    return;
  }
  const q = "record=" + encodeURIComponent(rec.value.trim()) + "&backup=" + encodeURIComponent(bk.value.trim()) + "&out=" + encodeURIComponent(out.value.trim());
  const r = await api("/api/escrow/unlock?" + q);
  body.innerHTML = r?.ok ? `<span class="status-pill green">DECRYPTED</span> <span class="mono">${esc(r.decrypted)}</span>` : `<span class="status-pill red">FAILED</span> <span class="mono">${esc(r?.error || "failed")}</span>`;
  wrap.style.display = "block";
}

/* ---------------- research ---------------- */
let CAMPAIGN = null;
async function pageResearch() {
  if (!CAMPAIGN) CAMPAIGN = await api("/api/campaign");
  if (!CACHE.surface) CACHE.surface = await api("/api/surface");

  const SURF = CACHE.surface;
  const surfRows = (SURF && SURF.targets) || [];
  const surfHtml = surfRows.length ? `
    <div class="panel-card"><div class="panel-card-head">Attack-Surface Targets (from ${(SURF.analysis && SURF.analysis.total) || 0} Tracked CVEs)</div>
    ${surfRows.map(t => `<div class="log-event"><span class="text-tag warning">SURFACE</span><div class="log-body"><div class="log-text">
      <b>${esc(t.component)}</b> (${t.cves} CVEs) ${t.prime_examples.length ? "&middot; PRIME: " + esc(t.prime_examples.join(", ")) : ""}
      ${t.high_examples.length ? "&middot; HIGH: " + esc(t.high_examples.join(", ")) : ""}</div></div></div>`).join("")}
    </div>` : "";

  const camps = (CAMPAIGN && CAMPAIGN.campaigns) || {};
  const leads = (CAMPAIGN && CAMPAIGN.leads) || [];
  const campRows = Object.entries(camps).map(([id, c]) =>
    `<tr><td class="mono"><b>${esc(c.name)}</b></td><td>${esc(c.target)}</td><td>${esc(c.chip || "—")}</td>
     <td class="mono">${esc(c.ios || "—")}</td><td class="mono">${c.sessions}</td><td class="mono">${c.leads || 0}</td></tr>`).join("")
    || '<tr><td colspan="6" class="empty-state">No research campaigns created yet.</td></tr>';

  const leadRows = leads.slice().reverse().map(l => {
    const cls = l.verdict === "finding" ? "red" : l.verdict === "escalated" || l.verdict === "promising" ? "amber" : "gray";
    return `<tr><td class="mono">${esc(l.id)}</td><td>${esc(l.kind)}</td>
      <td><span class="status-pill ${cls}">${esc(l.verdict)}</span></td>
      <td>${esc(l.detail.slice(0, 90))}</td>
      <td>
        <button class="btn" style="padding:2px 7px;font-size:10px" onclick="triageLead('${esc(l.id)}','promising')">Promising</button>
        <button class="btn" style="padding:2px 7px;font-size:10px" onclick="triageLead('${esc(l.id)}','dead-end')">Dead-End</button>
        <button class="btn" style="padding:2px 7px;font-size:10px" onclick="triageLead('${esc(l.id)}','escalated')">Escalate</button>
      </td></tr>`;
  }).join("") || '<tr><td colspan="5" class="empty-state">No research leads recorded.</td></tr>';

  return `
    <div class="page-head"><div class="page-title">Zero-Day Research</div>
    <div class="page-sub">Campaign orchestrator: DFU captures -> traces -> fuzz sessions -> leads -> verdicts. Honest instrumentation.</div></div>
    ${surfHtml}
    <div class="panel-card"><div class="panel-card-head">Campaigns</div>
    <div class="filter-bar">
      <input class="form-input" id="cp-name" placeholder="campaign name" style="width:180px">
      <input class="form-input" id="cp-chip" placeholder="chip (A13)" style="width:100px">
      <input class="form-input" id="cp-ios" placeholder="iOS" style="width:90px">
      <button class="btn primary" onclick="newCampaign()">New Campaign</button>
    </div>
    <div style="padding:10px 14px">
      <textarea id="cp-capture" class="notes-input" style="width:100%;height:100px" placeholder="Paste usbmon capture text here, select campaign below, and run dry session..."></textarea>
    </div>
    <div class="filter-bar">
      <select class="form-select" id="cp-select">${Object.keys(camps).map(id => `<option value="${esc(id)}">${esc(camps[id].name)}</option>`).join("") || '<option value="">(create a campaign first)</option>'}</select>
      <button class="btn" onclick="dryRun()">Run Dry Session</button>
    </div>
    <table class="data"><thead><tr><th>Name</th><th>Target</th><th>Chip</th><th>iOS</th><th>Sessions</th><th>Leads</th></tr></thead>
    <tbody>${campRows}</tbody></table></div>

    <div class="panel-card"><div class="panel-card-head">Leads (${leads.length})</div>
    <table class="data"><thead><tr><th>ID</th><th>Kind</th><th>Verdict</th><th>Detail</th><th>Triage Action</th></tr></thead>
    <tbody>${leadRows}</tbody></table>
    <div class="log-event"><span class="text-tag info">LADDER</span><div class="log-body"><div class="log-text">Triage ladder: observed → promising (repro) → escalated (root cause) → finding (public writeup).</div></div></div>
    </div>`;
}

async function newCampaign() {
  const name = document.getElementById("cp-name").value.trim();
  if (!name) { toast("Campaign name required", "red"); return; }
  const r = await api("/api/campaign", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "new", name, chip: document.getElementById("cp-chip").value, ios: document.getElementById("cp-ios").value, target: "DFU" }),
  });
  if (r.ok) {
    CAMPAIGN = null;
    notify("Campaign Created", `New campaign '${name}' initialized.`, "success", "EXPLOIT");
    render();
  } else toast(r.error || "failed", "red");
}

async function dryRun() {
  const id = document.getElementById("cp-select").value;
  const capture = document.getElementById("cp-capture").value;
  if (!id || !capture.trim()) { toast("Campaign selection and capture text required", "red"); return; }
  const r = await api("/api/campaign", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "dry-run", campaign_id: id, capture }),
  });
  if (r.ok) {
    CAMPAIGN = null;
    notify("Dry Session Analyzed", `Session analyzed: ${r.anomalies?.length || 0} anomalies found.`, "success", "EXPLOIT");
    render();
  } else toast(r.error || "failed", "red");
}

async function triageLead(id, verdict) {
  const r = await api("/api/campaign", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "triage", lead_id: id, verdict }),
  });
  if (r.ok) {
    CAMPAIGN = null;
    notify("Lead Triaged", `${id} marked as ${verdict}`, "info", "EXPLOIT");
    render();
  } else toast(r.error || "failed", "red");
}

/* ---------------- bfu lab ---------------- */
async function pageBfuLab() {
  return `<div class="page-head"><div class="page-title">BFU Lab (Modern Phones)</div>
    <div class="page-sub">Works on ANY iOS model: Filesystem class intelligence, keybag status, and native decrypt engine.</div></div>
    <div class="panel-card"><div class="panel-card-head">Filesystem intelligence (bfufs)</div>
    <div class="filter-bar">
      <input class="form-input" id="bfu-fs-path" placeholder="BFU mounted or pulled root path" style="width:340px" value="${esc(ACTIVE_CASE?.destination ? ACTIVE_CASE.destination + "/bfu" : "")}">
      <button class="btn primary" onclick="runBfuFs()">Scan Classes</button>
    </div>
    <div id="bfu-fs-out" style="padding:10px 14px;display:none"></div></div>

    <div class="panel-card"><div class="panel-card-head">Keybag tools</div>
    <div class="filter-bar">
      <input class="form-input" id="kb-file" placeholder="Path to systembag.kb / Manifest.plist" style="width:300px">
      <button class="btn" onclick="runKeybagUI()">Keybag Status</button>
      <input class="form-input" id="escrow-dir" placeholder="Case directory for escrow search" style="width:240px" value="${esc(ACTIVE_CASE?.destination || "")}">
      <button class="btn" onclick="runEscrowFind()">Escrow Find</button>
    </div>
    <div id="kb-out" style="padding:10px 14px;display:none"></div></div>`;
}

async function runBfuFs() {
  const p = document.getElementById("bfu-fs-path").value.trim();
  const out = document.getElementById("bfu-fs-out");
  if (!p) { toast("Path required", "red"); return; }
  out.style.display = "block";
  out.innerHTML = '<span class="mono">Scanning filesystem DataProtection classes...</span>';
  const r = await api("/api/bfufs?dir=" + encodeURIComponent(p));
  const s = r?.summary || {};
  out.innerHTML = `
    <div class="log-event"><span class="text-tag ${s.content_readable ? "success" : "warning"}">SCAN RESULT</span>
    <div class="log-text"><b>${s.total_files || 0}</b> files scanned · <b>${s.content_readable || 0}</b> plaintext-readable at BFU · <b>${s.metadata_visible || 0}</b> metadata-only.</div></div>
    ${(r.readable || []).slice(0, 20).map(f => `<div class="mono" style="padding-left:14px;color:#34d399">+ ${esc(f.rel)}</div>`).join("")}
    ${(r.targets || []).slice(0, 20).map(f => `<div class="mono" style="padding-left:14px;color:var(--muted)">· ${esc(f.rel)} [${esc(f.interest || "class")}]</div>`).join("")}
  `;
}

async function runKeybagUI() {
  const f = document.getElementById("kb-file").value.trim();
  const out = document.getElementById("kb-out");
  if (!f) { toast("Keybag file required", "red"); return; }
  out.style.display = "block";
  out.innerHTML = '<span class="mono">Parsing keybag...</span>';
  const r = await api("/api/keybag?file=" + encodeURIComponent(f));
  out.innerHTML = r?.ok ? `<pre class="mono" style="white-space:pre-wrap;font-size:11px">${esc(r.text)}</pre>` : `<span class="mono" style="color:var(--red)">${esc(r?.error || "failed")}</span>`;
}

/* ---------------- evidence ---------------- */
async function pageEvidence() {
  return `
    <div class="page-head"><div class="page-title">Evidence & Chain of Custody</div>
    <div class="page-sub">Certify a case directory (native multi-hashing + HMAC seal) and verify evidentiary integrity.</div></div>
    <div class="panel-card"><div class="panel-card-head">Certify a Case Directory</div>
    <div class="filter-bar">
      <input class="form-input" id="cert-dir" placeholder="Case directory to seal" style="width:280px" value="${esc(ACTIVE_CASE?.destination || "")}">
      <input class="form-input" id="cert-out" placeholder="Output folder" style="width:200px" value="${esc(ACTIVE_CASE?.destination ? ACTIVE_CASE.destination + "/report" : "")}">
      <input class="form-input" id="cert-examiner" placeholder="examiner name" style="width:160px" value="${esc(ACTIVE_CASE?.examiner || "Forensic Examiner")}">
      <button class="btn primary" onclick="runCertify()">Certify + Seal</button>
    </div></div>

    <div class="panel-card"><div class="panel-card-head">Verify a Sealed Report</div>
    <div class="filter-bar">
      <input class="form-input" id="cert-report" placeholder="Path to sealed-report.json" style="width:360px">
      <button class="btn" onclick="runCertVerify()">Verify Integrity</button>
    </div>
    <div id="cert-out" style="padding:10px 14px;display:none"></div></div>`;
}

async function runCertify() {
  const dir = document.getElementById("cert-dir").value.trim();
  const out = document.getElementById("cert-out").value.trim();
  const examiner = document.getElementById("cert-examiner").value.trim();
  if (!dir || !out || !examiner) { toast("Case directory, output directory, and examiner name are required", "red"); return; }
  notify("Certification Started", `Computing multi-hashes for ${dir}...`, "info", "EVIDENCE");
  const r = await api("/api/certify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ case_dir: dir, out, examiner }),
  });
  if (r && !r.error) {
    notify("Certified Successfully", `Certified ${r.file_count} evidence files with cryptographic seal.`, "success", "EVIDENCE");
  } else {
    notify("Certification Error", r?.error || "Failed", "error", "EVIDENCE");
  }
}

async function runCertVerify() {
  const f = document.getElementById("cert-report").value.trim();
  const out = document.getElementById("cert-out");
  if (!f) { toast("Report path required", "red"); return; }
  out.style.display = "block";
  out.innerHTML = '<span class="mono">Verifying seal integrity...</span>';
  const r = await api("/api/certify?verify=" + encodeURIComponent(f));
  if (!r || r.error) { out.innerHTML = `<span class="mono" style="color:var(--red)">${esc(r?.error || "failed")}</span>`; return; }
  out.innerHTML = `
    <div class="log-event"><span class="text-tag ${r.integrity_ok ? "success" : "error"}">${r.integrity_ok ? "VERIFIED" : "TAMPERED"}</span>
    <div class="log-text">Seal ${r.seal_valid ? "VALID" : "INVALID"} · ${r.file_count} files verified · ${r.tampered || 0} tampered files.
    ${r.tampered ? (r.failures || []).map(x => `<div class="mono" style="color:var(--red)">${esc(x.status)}: ${esc(x.relpath)}</div>`).join("") : ""}
    </div></div>`;
}

/* ---------------- artifacts ---------------- */
async function pageArtifacts() {
  return `
    <div class="page-head"><div class="page-title">Artifact Analysis</div>
    <div class="page-sub">Crash logs (.ips), wireless registries (WiFi/Bluetooth), and merged super-timeline.</div></div>
    <div class="panel-card"><div class="panel-card-head">Scan Extraction Directory</div>
    <div class="filter-bar">
      <input class="form-input" id="art-dir" placeholder="Extraction root path" style="width:360px" value="${esc(ACTIVE_CASE?.destination || "")}">
      <button class="btn" onclick="runCrashLogs()">Crash Logs</button>
      <button class="btn" onclick="runWireless()">Wireless</button>
      <button class="btn" onclick="runSysdiagnose()">Sysdiagnose</button>
      <button class="btn" onclick="runKnowledgeC()">knowledgeC</button>
      <button class="btn primary" onclick="runSuperTimeline()">Super-timeline</button>
    </div>
    <div id="art-out" style="padding:10px 14px;display:none"></div></div>`;
}

async function runCrashLogs() {
  const d = document.getElementById("art-dir").value.trim();
  const out = document.getElementById("art-out");
  if (!d) { toast("Path required", "red"); return; }
  out.style.display = "block";
  out.innerHTML = '<span class="mono">Scanning crash logs...</span>';
  const r = await api("/api/crashlogs?dir=" + encodeURIComponent(d));
  const s = r?.summary || {};
  const rows = r?.crashes || [];
  out.innerHTML = `
    <div class="log-event"><span class="text-tag ${rows.length ? "success" : "warning"}">CRASH LOGS</span>
    <div class="log-text"><b>${s.total || 0}</b> crash logs analyzed.</div></div>
    ${rows.slice(0, 15).map(c => `<div class="mono" style="padding-left:14px">· ${esc(c.timestamp || "?")} ${esc(c.process || c.name)} [${esc(c.exception_type || "crash")}]</div>`).join("")}`;
}

async function runWireless() {
  const d = document.getElementById("art-dir").value.trim();
  const out = document.getElementById("art-out");
  if (!d) { toast("Path required", "red"); return; }
  out.style.display = "block";
  out.innerHTML = '<span class="mono">Scanning wireless artifacts...</span>';
  const r = await api("/api/wireless?dir=" + encodeURIComponent(d));
  const wifi = r?.wifi || [], bt = r?.bluetooth || [];
  out.innerHTML = `
    <div class="log-event"><span class="text-tag ${wifi.length || bt.length ? "success" : "warning"}">WIRELESS</span>
    <div class="log-text"><b>${wifi.length}</b> WiFi networks · <b>${bt.length}</b> Bluetooth devices.</div></div>
    ${wifi.slice(0, 10).map(w => `<div class="mono" style="padding-left:14px">WiFi: ${esc(w.ssid || w.network_id)} · ${esc(w.security || "?")}</div>`).join("")}
    ${bt.slice(0, 10).map(b => `<div class="mono" style="padding-left:14px">BT: ${esc(b.name || b.address || "?")} ${b.paired ? "(paired)" : ""}</div>`).join("")}`;
}

async function runSysdiagnose() {
  const d = document.getElementById("art-dir").value.trim();
  const out = document.getElementById("art-out");
  if (!d) { toast("Path required", "red"); return; }
  out.style.display = "block";
  out.innerHTML = '<span class="mono">Scanning sysdiagnose...</span>';
  const r = await api("/api/sysdiagnose?dir=" + encodeURIComponent(d));
  out.innerHTML = `
    <div class="log-event"><span class="text-tag info">SYSDIAGNOSE</span>
    <div class="log-text"><b>${r.total || 0}</b> diagnostics files inventoried.</div></div>`;
}

async function runKnowledgeC() {
  const d = document.getElementById("art-dir").value.trim();
  const out = document.getElementById("art-out");
  if (!d) { toast("Path required", "red"); return; }
  out.style.display = "block";
  out.innerHTML = '<span class="mono">Parsing knowledgeC database...</span>';
  const r = await api("/api/knowledgec?dir=" + encodeURIComponent(d));
  const ev = r?.events || [];
  out.innerHTML = `
    <div class="log-event"><span class="text-tag ${ev.length ? "success" : "warning"}">KNOWLEDGEC</span>
    <div class="log-text"><b>${ev.length}</b> events extracted.</div></div>
    ${ev.slice(0, 20).map(e => `<div class="mono" style="padding-left:14px">· ${esc(e.ts || "?")} [${esc(e.kind || "")}] ${esc(e.value || "")}</div>`).join("")}`;
}

async function runSuperTimeline() {
  const d = document.getElementById("art-dir").value.trim();
  const out = document.getElementById("art-out");
  if (!d) { toast("Path required", "red"); return; }
  out.style.display = "block";
  out.innerHTML = '<span class="mono">Generating super-timeline...</span>';
  notify("Super-Timeline", `Generating chronological timeline for ${ACTIVE_CASE?.case_id || "extraction"}...`, "info", "FORENSICS");
  const r = await api("/api/timeline", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ case_id: ACTIVE_CASE?.case_id || "" }),
  });
  if (r.ok) {
    out.innerHTML = `<div class="log-event"><span class="text-tag success">TIMELINE READY</span><div class="log-text">Super-timeline generated: <span class="mono">${esc(r.path)}</span></div></div>`;
    notify("Super-Timeline Generated", "Chronological evidence timeline generated successfully.", "success", "FORENSICS");
  } else {
    // fallback to dir appcatalog check
    const r2 = await api("/api/appcatalog?dir=" + encodeURIComponent(d));
    const dbs = r2?.databases || [];
    out.innerHTML = `<div class="log-event"><span class="text-tag info">INDEXED</span><div class="log-text"><b>${dbs.length}</b> timestamped databases cataloged. Run timeline command to export CSV.</div></div>`;
  }
}

/* ---------------- pages dispatch table ---------------- */
const PAGES = {
  dashboard: pageDashboard,
  devices: pageDevices,
  applications: pageApplications,
  browser: pageBrowser,
  chats: pageChats,
  cloud: pageCloud,
  contacts: pageContacts,
  calendars: pageCalendars,
  calls: pageCalls,
  location: pageLocation,
  media: pageMedia,
  messages: pageMessages,
  files: pageFiles,
  forensics: pageForensics,
  reports: pageReports,
  exploits: pageExploits,
  tools: pageTools,
  settings: pageSettings,
  research: pageResearch,
  bfu: pageBfuLab,
  evidence: pageEvidence,
  artifacts: pageArtifacts,
};

async function render() {
  const h = (location.hash || "#dashboard").slice(1);
  currentHash = PAGES[h] ? h : "dashboard";
  buildNav();
  navCounts();

  const bannerPages = ["browser", "chats", "cloud", "contacts", "calendars", "calls",
                       "location", "media", "messages", "files", "forensics"];
  const html = await PAGES[currentHash]();
  const pageContainer = document.getElementById("page");
  if (pageContainer) {
    pageContainer.innerHTML = (bannerPages.includes(currentHash) ? detectionBanner() : "") + (html || "");
  }
  document.querySelectorAll("[data-nav]").forEach(el => el.onclick = () => location.hash = el.dataset.nav);
  renderCasePanel();
}
window.addEventListener("hashchange", render);

/* ---------------- non-disruptive background polling ---------------- */
async function backgroundPoll() {
  try {
    const dev = await api("/api/device");
    const isAttached = dev && !dev.error && dev.udid;
    const currentUdid = isAttached ? dev.udid : null;
    const currentState = isAttached ? dev.state : null;

    // Detect device state transitions
    if (currentUdid !== LAST_DEVICE_UDID || currentState !== LAST_DEVICE_STATE) {
      if (currentUdid && !LAST_DEVICE_UDID) {
        notify("Device Attached", `${dev.model} (${dev.chip || "Apple silicon"}) connected in ${dev.state} mode.`, "success", "DEVICE");
      } else if (!currentUdid && LAST_DEVICE_UDID) {
        notify("Device Detached", "iOS target device disconnected.", "warning", "DEVICE");
      } else if (currentUdid && currentState !== LAST_DEVICE_STATE) {
        notify(`Device Mode Changed (${currentState})`, `${dev.model} transitioned to ${currentState}.`, "info", "DEVICE");
      }
      LAST_DEVICE_UDID = currentUdid;
      LAST_DEVICE_STATE = currentState;
      DEVICE = isAttached ? dev : null;

      // Update UI headers & status without destroying entire page
      const tag = document.getElementById("rail-status-tag");
      const text = document.getElementById("rail-status-text");
      if (tag && text) {
        if (DEVICE) {
          tag.className = `text-tag ${DEVICE.state === "AFU" ? "success" : "warning"}`;
          tag.textContent = DEVICE.state;
          text.textContent = `${DEVICE.model} (${DEVICE.chip})`;
        } else {
          tag.className = "text-tag success";
          tag.textContent = "ONLINE";
          text.textContent = "System Ready";
        }
      }
      renderCasePanel();

      // Only refresh page if currently viewing devices or dashboard
      if (currentHash === "devices" || currentHash === "dashboard") {
        render();
      }
    }

    // Check notifications feed from server
    const notifRes = await api("/api/notifications");
    if (notifRes && Array.isArray(notifRes.notifications)) {
      if (notifRes.notifications.length > NOTIFICATIONS_LIST.length) {
        const newEntries = notifRes.notifications.slice(NOTIFICATIONS_LIST.length);
        newEntries.forEach(n => {
          NOTIFICATIONS_LIST.unshift(n);
          UNREAD_NOTIFS++;
          showToast(n);
        });
        updateNotifBadge();
        renderNotifDrawer();
      }
    }
  } catch {
    // network poll error - quiet
  }
}

async function refreshCurrentPage() {
  const [dev, apps, cases, logr] = await Promise.all([
    api("/api/device"), api("/api/apps"), api("/api/cases"), api("/api/log")
  ]);
  DEVICE = dev && !dev.error && dev.udid ? dev : null;
  APPS = apps || [];
  CASES = cases || [];
  if (!ACTIVE_CASE && CASES.length) ACTIVE_CASE = CASES[0];
  if (ACTIVE_CASE) ARTIFACTS = await api("/api/artifacts?case=" + encodeURIComponent(ACTIVE_CASE.case_id));
  ARTIFACTS._log = logr.lines || [];

  document.getElementById("evidence-count").textContent =
    ((ARTIFACTS.messages?.length || 0) + (ARTIFACTS.contacts?.length || 0) + (ARTIFACTS.calls?.length || 0)) + " items";

  await render();
}

/* ---------------- bootstrap initialization ---------------- */
document.addEventListener("DOMContentLoaded", async () => {
  // Setup notes autosave
  const notesEl = document.getElementById("case-notes");
  if (notesEl) {
    notesEl.addEventListener("input", e => {
      if (!ACTIVE_CASE) return;
      clearTimeout(notesTimer);
      notesTimer = setTimeout(() => {
        api("/api/case", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ case_id: ACTIVE_CASE.case_id, destination: ACTIVE_CASE.destination, notes: e.target.value }),
        });
      }, 800);
    });
  }

  // Initial load
  await refreshCurrentPage();

  // Load examiner name in header
  if (CACHE.settings?.examiner) {
    const exBadge = document.getElementById("topbar-examiner");
    if (exBadge) exBadge.textContent = CACHE.settings.examiner;
  }

  // Smooth, non-disruptive background polling every 4 seconds
  setInterval(backgroundPoll, 4000);
});
