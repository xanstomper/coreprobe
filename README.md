# CoreProbe / opensleuth

**An open-source iOS forensic triage + exploit-research workstation — the honest Cellebrite-class alternative.**

- **91 verified public exploit routes** (A4 → A20 Pro, iOS 6 → 27.0) + **36 acquisition-relevant Apple-advisory CVEs** (iOS 26.x/27.x)
- **Capability TRUTH system**: research status ≠ operational capability — a strict status machine (UNKNOWN → DOCUMENTED → PUBLIC_POC → LAB_REPRODUCED → LAB_VALIDATED → INTEGRATED → REGRESSION_TESTED) with a consistency auditor; only REGRESSION_TESTED capabilities are planner-selectable
- **Event-sourced case journal**: append-only sessions, permanent EVD-000001+ evidence IDs, custody events, first-class failure records, full case replay
- **Own BFU stack**: keybag parser, UID-key unwrap, cprotect parsing, AES-CBC sector decryption
- **Zero-day research program**: DFU USB capture → trace analysis → mutation fuzzing → campaign triage
- **PAC-diversifier scanner** (`opensleuth pacscan`): automates the CVE-2026-65330 discovery technique — find fixed-diversifier pointer-signing in any kernelcache = own-exploit research leads
- **Court-ready chain of custody**: native-hash manifest + HMAC-SHA256 integrity seal + tamper detection
- **Desktop app + web studio + CLI** — every capability wired into all three
- 323 tests green · MIT license

> **Integrity rule (absolute):** every catalog entry is real, publicly documented research. Nothing is fabricated. "No public route" is a valid, honest answer. A new zero-day enters only through: observed crash → reproduced → root-caused → public writeup.

## Documentation

| Doc | Contents |
|---|---|
| [docs/EXPLOIT-CATALOG.md](docs/EXPLOIT-CATALOG.md) | **Every exploit route + CVE** with chips/iOS/hardware/BFU/tooling |
| [docs/COMPARISON.md](docs/COMPARISON.md) | **vs Cellebrite/AXIOM/GrayKey/Elcomsoft/XRY/Oxygen/Belkasoft** — where we win, where we honestly don't |
| [docs/COMPETITORS-FULL.md](docs/COMPETITORS-FULL.md) | **Every competitor expanded**: Cellebrite, AXIOM, GrayKey, Elcomsoft, XRY, Oxygen, Belkasoft, OSS peers + summary matrix |
| [docs/BFU-GUIDE.md](docs/BFU-GUIDE.md) | BFU on every chip class: expectations, yield card, escrow, decrypt engine |
| [docs/RESEARCH-GUIDE.md](docs/RESEARCH-GUIDE.md) | The zero-day research program: capture, fuzz, campaign, notebook |
| [docs/FORENSICS-GUIDE.md](docs/FORENSICS-GUIDE.md) | Artifact parsing: crash logs, wireless, sysdiagnose, knowledgeC, timeline, appcatalog |
| [docs/COURT-GUIDE.md](docs/COURT-GUIDE.md) | Chain of custody: certify, verify, evidence handling |
| [docs/UI-GUIDE.md](docs/UI-GUIDE.md) | Web studio + desktop app: every page and control |
| [docs/roadmap-gaps.md](docs/roadmap-gaps.md) | The two hard walls (A12+ SEP, DPA) and what would move them |
| [docs/A12-PLUS-BFU-PATHS.md](docs/A12-PLUS-BFU-PATHS.md) | **The three buildable paths**: SEPOS research, counter bypass model, fault injection |
| [docs/PICOLESS-BFU.md](docs/PICOLESS-BFU.md) | **What works with zero hardware** vs what needs the Pico — honest split |
| [docs/silicon-research.md](docs/silicon-research.md) | Silicon envelope + exploit-dev toolbox |

## Quick start

```bash
git clone https://github.com/xanstomper/coreprobe && cd coreprobe
sudo ./install.sh --with-web-service      # + --with-cxx --with-checkm8-tools --with-desktop
opensleuth doctor                          # workstation readiness check
opensleuth capabilities --audit            # capability registry consistency audit
opensleuth fingerprint                     # device fingerprint w/ source+confidence
opensleuth plan2                           # truth-gated acquisition plan
opensleuth exposure --chip A13 --ios 26.6.1
opensleuth autoexploit                     # AXIOM-style: probe then run every applicable
                                           # public route until one succeeds (see below)
```

**Desktop app:** `opensleuth-desktop` (Ctrl+1-9 pages, live device status)
**Web studio:** `opensleuth-web` → http://127.0.0.1:9121 (Research · BFU Lab · Evidence · Artifacts · Exploits · Tools)

## Auto-Exploiter

One command that behaves like Cellebrite/AXIOM's "auto" flow: it probes the
attached device (chip / iOS / BFU·AFU·DFU·recovery state), builds an ordered
plan of the **public** routes that actually apply, and runs each one through
the real tooling until **one succeeds** — then stops.

```bash
opensleuth autoexploit              # detect + try checkm8 → SEP → AFU → logical
opensleuth autoexploit --allow-destructive   # allow A10/A11 checkm8 on iOS 16+ (passcode-off caveat)
```

It is available on the **Exploits** page in both the desktop app and web studio
(the "Auto-Exploiter" panel with a start button and live per-route status), and
as a one-click **⚡ Auto-Exploit Device** button on the dashboard.

Device detection is daemon-independent: it reads sysfs USB first (works even
when usbmuxd is down or a device is locked in DFU/BFU), then enriches with
lockdown/pymobiledevice3 when a service layer is reachable. Chip is determined
from ProductType, a serial-prefix table, or iBoot boardconfig in recovery mode.
If a device is in DFU with an ambiguous chip, the auto-exploiter still offers a
**safe checkm8 probe** (gaster pwn only produces a hit on genuine A7-A11, and is
harmless on newer silicon), so pressing the button always tries rather than
silently doing nothing.

Ordering (bootrom first, strongest primitive): checkm8 (A7-A11) / usbliter8
(A12-A13) → PongoOS/ramdisk chain → Blackbird SEP (A10/T2) → AFU kernel
jailbreaks (Dopamine, Serotonin, …) → logical + backup. Routes are never
falsely reported as working: a route only counts as a hit when an objective
state change is observed (PWND marker in USB serial, irecovery env reachable,
AFC2/SSH mount, or a reachable logical service). Missing tooling is reported
per-route so it can be installed and the run repeated.

## Capability TRUTH system

CoreProbe never presents a documented exploit as a usable capability. Every
capability lives in a machine-readable registry (`opensleuth/capabilities.json`)
with a strict status machine:

```
UNKNOWN → DOCUMENTED → PUBLIC_POC → LAB_REPRODUCED → LAB_VALIDATED
        → INTEGRATED → REGRESSION_TESTED          (+ BROKEN / RETIRED)
```

Only `REGRESSION_TESTED` — adapter exists + validation evidence recorded +
test fixture — enters the **operational pool** the acquisition planner may
select. The pool is defensive: even direct status mutation cannot smuggle an
unevidenced capability in (`opensleuth capabilities --audit` verifies).

Current honest statuses (from the codebase audit): `device-info`,
`logical-backup`, `backup-parse` operational (fixture-tested); `checkm8-pwn`
INTEGRATED — real adapter, no recorded hardware validation yet;
`usbliter8-verify` and the jailbreak-detect family DOCUMENTED (research only:
the former needs the RP2350 rig, the latter only detects examiner-installed
agents).

`opensleuth plan2` renders the truth-gated plan (AVAILABLE / VALIDATION
REQUIRED / RESEARCH ONLY / UNSUPPORTED per capability), and the web studio
exposes the same via `/api/plan2`.

## Event-sourced case journal

Every acquisition session writes an append-only journal
(`<case>/journal/S-*.jsonl`): device detections, fingerprints, capability
assessments, acquisition start/progress/completion/interruption, evidence
creation (`EVD-000001`… permanent IDs), hashing, custody events, parser
warnings/failures, reports. Corrections are new events referencing originals;
history is never rewritten. `/api/journal?case=X` returns per-session
summaries with structural verification and a full replay.

## What it can do right now

| Capability | Status |
|---|---|
| Logical / encrypted backup acquisition (+keychain via --unback) | ✅ full |
| checkm8 flow (A7-A11): pwn → AES keys → ramdisk → keybags | ✅ full |
| BFU decryption engine (keybag unwrap → cprotect → AES-CBC) | ✅ full (ours) |
| BFU FS intelligence (per-class map, readable-now inventory) | ✅ any modern phone |
| Escrow/backup-keybag unlock (passcode-free path, all models) | ✅ full |
| iCloud account acquisition (warrant-gated) | ✅ harness |
| Artifact parsing: SMS/calls/notes/Safari/crash/wireless/knowledgeC/sysdiagnose | ✅ full |
| Super-timeline (pattern of life) | ✅ full |
| iLEAPP bridge (100+ parsers) | ✅ integration |
| Auto-Exploiter (detect → run routes → stop on hit) | ✅ full, UI + CLI |
| Court chain of custody (certify/verify) | ✅ full |
| Exploit-dev toolbox (IMG4/IPSW/trustcache/patch catalog) | ✅ full |
| DFU research: capture → trace → corpus → fuzz → campaign | ✅ full |
| Native C++ core (hash/manifest/mbdb, ~150 MiB/s) | ✅ full |
| **BFU passcode bypass (A12+)** | ○ none — SEP is closed silicon; see docs/roadmap-gaps.md |
| **DPA-style vendor services** | ○ not reachable without Apple legal agreements |

## The honest position

CoreProbe matches or beats commercial tools on logical/checkm8/escrow
acquisition, artifact depth, reporting integrity, and research
instrumentation — at $0, fully auditable. It cannot (and does not
pretend to) provide a BFU passcode bypass on A12+ or vendor-central
services; those are the two walls documented in
[docs/roadmap-gaps.md](docs/roadmap-gaps.md). The research campaign is
the open path forward, and every part of it ships in this repo.

## Legal

For lawful use by examiners, researchers, and device owners. iCloud
acquisition requires `--warrant`. See SECURITY.md.
