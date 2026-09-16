# UI Guide — web studio & desktop app

## Desktop app (`opensleuth-desktop`)

Native QtWebEngine shell over the same backend (auto-starts on
127.0.0.1:9121, reuses a running one). Menus + toolbar + live device
status bar (model / AFU-BFU / chip / iOS polled from /api/device).

| Shortcut | Page |
|---|---|
| Ctrl+1 | Dashboard |
| Ctrl+2 | Exploits (77 routes, filters, disclosure table w/ HIGH-VALUE badges) |
| Ctrl+6 | Research (campaigns, leads, attack-surface targets) |
| Ctrl+7 | BFU Lab (FS intelligence, keybag, escrow) |
| Ctrl+8 | Evidence (certify create/verify) |
| Ctrl+9 | Artifacts (crash logs, wireless, sysdiagnose, knowledgeC, timeline) |
| Ctrl+3/4/5 | Reports / Devices / Settings |
| Ctrl+R / Ctrl+= / Ctrl+- | Reload / zoom |

## Web studio (`opensleuth-web`)

Same pages in any browser. **Binds 127.0.0.1 only** — use a tunnel for
remote; there is no built-in auth (see SECURITY.md).

### Key pages

- **Research**: create campaigns, paste usbmon captures for dry runs,
  triage leads (promising/dead-end/escalated), attack-surface targets
  from the tracked-CVE analysis
- **BFU Lab**: bfufs scan (per-class map + readable-now inventory),
  keybag status, escrow find, decrypt inputs
- **Evidence**: certify a case dir + verify sealed reports
- **Artifacts**: one path field → crash logs / wireless / sysdiagnose /
  knowledgeC / super-timeline renderers
- **Exploits**: device-aware exposure, filterable routes, per-firmware
  status, disclosures with HIGH-VALUE tagging
- **Tools**: 42-tool toolchain install status + honest stance matrix

## APIs

All UI features are plain JSON endpoints (/api/device, /api/exploits,
/api/campaign, /api/bfufs, /api/keybag, /api/escrow[/unlock],
/api/appcatalog, /api/crashlogs, /api/wireless, /api/sysdiagnose,
/api/knowledgec, /api/certify, /api/firmware, /api/surface, /api/tools,
/api/stance, /api/doctor, /api/bfu) — scriptable for automation.
