# CoreProbe / opensleuth

**An open-source iOS forensic triage + exploit-research workstation — the honest Cellebrite-class alternative.**

- **77 verified public exploit routes** (A4 → A20 Pro, iOS 6 → 27.0) + **36 acquisition-relevant Apple-advisory CVEs** (iOS 26.x/27.x)
- **Own BFU stack**: keybag parser, UID-key unwrap, cprotect parsing, AES-CBC sector decryption
- **Zero-day research program**: DFU USB capture → trace analysis → mutation fuzzing → campaign triage
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
| [docs/silicon-research.md](docs/silicon-research.md) | Silicon envelope + exploit-dev toolbox |

## Quick start

```bash
git clone https://github.com/xanstomper/coreprobe && cd coreprobe
sudo ./install.sh --with-web-service      # + --with-cxx --with-checkm8-tools --with-desktop
opensleuth doctor                          # workstation readiness check
opensleuth exposure --chip A13 --ios 26.6.1
```

**Desktop app:** `opensleuth-desktop` (Ctrl+1-9 pages, live device status)
**Web studio:** `opensleuth-web` → http://127.0.0.1:9121 (Research · BFU Lab · Evidence · Artifacts · Exploits · Tools)

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
