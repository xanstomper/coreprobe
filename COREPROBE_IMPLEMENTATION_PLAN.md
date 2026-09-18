# COREPROBE IMPLEMENTATION PLAN

Generated: 2026-09-18 · Auditor: JCode (principal engineer) · Status: LIVING DOCUMENT

Priorities follow: **correctness > evidence integrity > security > interoperability >
reliability > performance > aesthetics**.

---

## 1. Current Architecture (as audited)

```
coreprobe/
├── opensleuth/            # Python package (~12.8k LOC)
│   ├── cli.py             # 2326-line argparse entry point; all commands
│   ├── exploits.py        # static public exploit catalog (77 routes + 36 CVEs)
│   ├── matrix.py          # chip/OS model maps + recommend() steps
│   ├── exploitrunner.py   # auto-exploiter: probe→plan→run-until-hit
│   ├── usb.py             # sysfs USB discovery, mode classify, chip heuristics
│   ├── bfu.py/bfufs.py/keybag.py/escrow.py/dataprotection.py  # BFU stack
│   ├── backup.py + artifacts/*.py  # backup index + 13 artifact parsers
│   ├── certify.py         # evidence manifest + HMAC-SHA256 seal + verify
│   ├── report.py/timeline.py/ileapp.py/appcatalog.py  # reporting/analysis
│   ├── research.py/campaign.py/dfufuzz.py/dfu_live.py/sepos.py  # research lab
│   ├── studio_web/        # HTTP server + static web UI
│   └── studio_desktop.py  # QtWebEngine shell around studio_web
├── core/                  # C++ core (SHA-256/manifest/MBDB, ~150 MiB/s)
└── tests/                 # 380 passing (pytest), incl. Qt browser-render tests
```

Working well (preserve): sysfs-first device detection, exploit catalog data
quality, BFU keybag/decrypt engine, certify seal, artifact parser breadth,
test culture. `cli.py` is large but cohesive — not rewriting without cause.

## 2. Architecture Problems (ranked)

| # | Problem | Impact | Fix |
|---|---------|--------|-----|
| P1 | **No truth gating**: catalog routes are treated as runnable; nothing separates DOCUMENTED from LAB-VALIDATED from INTEGRATED | Investigator cannot tell research from capability; violates core standard | M2: capability registry + status machine + planner gating |
| P2 | **No event journal**: acquisitions live only in stdout + ad-hoc JSON files | Nothing auditable; no case replay; failures vanish | M3: append-only session journal + evidence IDs |
| P3 | **Path-prefix traversal** in `_safe_case_file`, `_sha256`, icon handler (`startswith` not `is_relative_to`); `/api/parse-image` + `/api/acquire` accept arbitrary paths | Web-exposed arbitrary read/write | M6: fix + adversarial tests |
| P4 | **No parser provenance** (parser name/version, source row refs) | Derived artifacts untraceable to raw source | M3.4: provenance envelope on parse outputs |
| P5 | No device fingerprint record (property→source→confidence) | Device claims unverifiable | M4: fingerprint module |
| P6 | `afu_jailbreak` executor only *checks* AFC2; catalog implies CoreProbe can run Dopamine etc. | Misleading capability | M2: status DOCUMENTED, planner marks RESEARCH ONLY |

## 3. Existing Functionality (baseline verified)

- Device probe: USB sysfs classify (normal/DFU/recovery/pwned) + lockdown enrich
- Acquisition: backup (idevicebackup2/pymobiledevice3), media (ifuse/AFC),
  info/apps/crash/sysdiagnose/syslog; checkm8 gaster-pwn flow; usbliter8
  verify; jailbroken AFC2 pull; escrow unlock
- BFU: keybag parse/unwrap, cprotect, AES-CBC decrypt, class expectations
- Parsing: sms/calls/contacts/notes/safari/whatsapp/telegram/signal/voicemail/
  locations/plists + appcatalog sqlite inventory + iLEAPP bridge
- Integrity: certify manifest+seal+verify; native C++ hashing
- Research: CVE fetch pipeline, DFU fuzz campaign, SEPOS analyzer
- UI: web studio + desktop shell (dashboard/exploits/tools/… pages)
- Tests: 380 green (headless Qt excluded from bulk runs; passes solo)

## 4. Missing Functionality → Milestones

### M2 — Capability TRUTH system (`opensleuth/truth.py`)
Status machine: UNKNOWN → DOCUMENTED → PUBLIC_POC → LAB_REPRODUCED →
LAB_VALIDATED → INTEGRATED → REGRESSION_TESTED (+ BROKEN, RETIRED).
Operational pool = REGRESSION_TESTED only. Machine-readable capability
manifests (`capabilities.json`) with adapter, validation evidence, supported
builds, prerequisites. Consistency auditor refuses inconsistent registry.
Planner/UI derive status from manifests — never hardcoded labels.

Honest seed (verified against the codebase today):
- `logical-backup`, `media-afc`, `device-info`: adapters exist in cli.py +
  E2E tests → REGRESSION_TESTED (fixtures) → OPERATIONAL
- `checkm8-pwn`: real adapter (gaster subprocess + PWND verification) but
  hardware validation unrecorded → INTEGRATED, validation-required
- `usbliter8`: host verify-only (exploit runs on RP2350) → DOCUMENTED
- jailbreak routes (Dopamine/Serotonin/...): no CoreProbe adapter runs them
  (executor only detects AFC2) → DOCUMENTED, research-only

### M3 — Event-sourced case pipeline (`opensleuth/journal.py`)
Append-only JSONL per session: event_id, case_id, session_id, ts (UTC),
monotonic ts, component+version, event_type, severity, device/evidence refs,
parent_event_id, payload. Evidence IDs EVD-000001+, custody events,
failure records (ERROR/WARNING/TIMEOUT/DISCONNECT/PARSER_FAILURE/…),
case replay renderer. Corrections = new events referencing originals.
Wire: probe/plan/run/acquire/certify emit events. No console scraping.

### M4 — Device fingerprint (`opensleuth/fingerprint.py`)
Every property carries value+source+confidence (Observed/Inferred/
Heuristic/Unknown): model, SoC, iOS/build, UDID, USB mode, lock state,
pairing, PWND state. Feeds planner + journal.

### M5 — Honest acquisition planner (`opensleuth/planner.py`)
Input fingerprint → query truth registry → output per-method:
AVAILABLE (operational) / VALIDATION REQUIRED (integrated) /
RESEARCH ONLY (documented) / UNSUPPORTED. Pre-flight checks; post-run
verification (expected state observed or NOT VALIDATED). CLI
`opensleuth capabilities` + `opensleuth acquire auto`; UI planner panel
replaces implied-run semantics on the Exploits page.

### M6 — Security & integrity hardening
Fix prefix checks (`Path.is_relative_to`), constrain parse-image/acquire
destinations to ~/cases, size/count caps, hostile-input parser tests
(corrupt sqlite/plist), traversal regression tests.

### M7 — Docs & release
README truth-section, UI-GUIDE updates, CHANGELOG.

## 5. Testing Strategy
- Every milestone ships tests in the same commit
- New: truth-gating tests (planner refuses non-operational), journal
  immutability/replay tests, traversal adversarial tests, malformed-DB
  parser tests, fingerprint source-confidence tests
- E2E stays green throughout; commit only on green

## 6. Security Concerns (from audit)
- server.py:236 `_sha256`, :273 `_safe_case_file`, :240 icon check — prefix
  bypass (`~/cases-evil`) → fix in M6 (earlier if touching server anyway)
- `/api/parse-image` runs dump on any path; `/api/acquire` writes backup to
  any destination → restrict under ~/cases
- 62 subprocess call sites: argv-form (no shell) = safe from injection;
  keep it that way, add regression note

## 7. Forensic-Integrity Concerns
- certify() is solid (HMAC, per-file SHA-256) but point-in-time only;
  journal (M3) makes custody continuous and replayable
- Derived artifacts (parsed rows) lack provenance → M3.4 envelope:
  {parser, parser_version, source_path, row_ref, extracted_at, warnings}

## 8. Research Areas → COREPROBE_RESEARCH.md
SEP A12+ path (passattack/faultinjection models exist), restore-traversal
CVE-2026-84598 observation harness, DFU fuzz corpus growth, parser coverage
gaps (deleted rows, WAL files), timeline precision semantics.

## 9. Sequence & Dependencies
M2 → M3 → M4 → M5 (planner needs truth+fingerprint+journal) → M6 → M7.
M6 security fixes land independently ASAP within M5's server touches.
