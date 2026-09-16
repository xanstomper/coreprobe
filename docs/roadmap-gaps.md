# Competitive gaps: BFU passcode bypass & DPA services

**Status: not open-source reachable today. This document is the honest map.**

CoreProbe's stance matrix (`opensleuth stance`) lists these as the two gaps
no open-source effort has closed. This page says exactly why and what would
have to happen to close them.

---

## Gap 4: BFU passcode bypass (A12+)

### Why it is a wall
- From A12 onward the Secure Enclave Processor (SEP) is a separate
  processor with its own firmware (SEPOS) and its own isolated memory.
- User-class keybag keys are created at first unlock and live only inside
  the SEP; neither the kernel, iBoot, nor any host-side tool can read them.
- The A12+ bootrom had no public exploit until 2025. usbliter8
  (Paradigm Shift, 2026-06-18) gives DFU command injection on A12/A13 -
  iBoot control and ramdisk boot - but does NOT bypass SEP passcode
  enforcement. That's why "PWND" ≠ "unlocked".
- Vendor BFU tools (GrayKey, Cellebrite services) either exploit SEP
  vulnerabilities they do not publish, or use vendor/partner interfaces
  Apple does not license publicly.

### What CoreProbe already does (the reachable 90%)
- **Escrow/paired-computer unlock** - the one passcode-free path that
  works on every model: `opensleuth escrow find/describe/unlock/sweep`.
- **usbliter8 playbook + yield card** for A12/A13: pwn, ramdisk, keybags,
  metadata, honest per-class expectations.
- **Keybag analysis**: per-class key presence so examiners know exactly
  what is usable at BFU.
- **checkm8 full flow** on A7-A11: AES keyset, keybags, ramdisk pull.

### What would actually close the wall
1. A public A14+ bootrom/SEP vulnerability with a working bypass
   (research program; not schedulable).
2. Apple licensing a lawful-access interface (legislation-dependent).
3. Vendor partnership (commercial route, out of OSS scope).

---

## Gap 5: DPA / Cellebrite central services

### What DPA is
Cellebrite's Device Protection Access services that run in their central
environment and interface with Apple's production infrastructure under
legal agreements (e.g., court orders served through Cellebrite). The
capability is gated by Cellebrite's contracts, not by mailing a binary.

### Why it is not open-source reachable
- Requires the vendor's legal relationship with Apple.
- Requires central infrastructure under the vendor's control.
- No public protocol or interface exists to replicate.

### What CoreProbe does instead (honest alternatives)
- **Escrow** (prior-trust backups) - often the same outcome for
  paired devices, fully open.
- **AFU extraction routes** after first unlock via the cataloged
  jailbreak/exploit paths.
- **iCloud with lawful authorization** (`acquire icloud --warrant`).
- **Certify** for court-ready chain of custody of whatever is acquired.

---

## Priorities moving forward (winnable work)
1. Artifact breadth - iLEAPP integration (done: `opensleuth ileapp`)
2. Court-ready reporting (done: `opensleuth certify`)
3. Cloud harness (done: hardened, warrant-gated)
4. BFU: usbliter8-class research and escrow expansion (in progress;
   hardware-bound Pico 2 flow ready in docs/runbook-usbliter8-pico2.md)
5. Ecosystem: CI, contributing docs, community (done)

**Bottom line:** items 4-5 are walls that only research breakthroughs or
vendor/legal relationships can move. Everything reachable has been built;
the standing of each item is tracked in `opensleuth stance`.