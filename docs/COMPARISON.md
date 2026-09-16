# CoreProbe vs. Commercial Forensic Platforms — Honest Comparison

Updated 2026-09-16. This comparison is maintained in code (`opensleuth stance`) so it cannot drift from reality.

## Capability matrix

| Capability | CoreProbe | Cellebrite UFED/Premium | Magnet AXIOM | GrayKey | Elcomsoft iFT |
|---|---|---|---|---|---|
| Logical backup (local) | ● full | ● full | ◐ partial | — | ● full |
| Encrypted backup + keychain (passcode) | ◐ partial | ● full | ◐ partial | — | ● full |
| Full filesystem (jailbreak route) | ● full | ● full | ◐ partial | — | ● full |
| checkm8 hardware route (A7-A11) | ● full | ● full | — | — | ◐ partial |
| usbliter8 DFU route (A12/A13) | ⚗ research | ◐ partial | — | — | ◐ partial |
| BFU keybag + AES keyset analysis (A7-A11) | ● full | ● full | — | — | ◐ partial |
| Escrow/paired-computer unlock (ALL models incl. A13/A18) | ◐ partial | ● full | ◐ partial | — | ◐ partial |
| usbliter8 BFU playbook (A12/A13) | ● full | ● full | — | — | ◐ partial |
| BFU passcode bypass | ○ none | ● full | — | ● full | ◐ partial |
| Cloud (iCloud) acquisition | ○ none | ● full | ● full | — | ◐ partial |
| App artifact breadth (100+ apps) | ◐ partial | ● full | ● full | — | ◐ partial |
| Court-ready reporting | ◐ partial | ● full | ● full | — | ◐ partial |
| Openness / auditability | ● full | ○ none | ○ none | ○ none | ○ none |
| Automation / API | ● full | ◐ partial | ◐ partial | ○ none | ◐ partial |
| Cost | $0 | $$$ | $$$ | $$$$ | $$$ |

Legend: ● full ◐ partial ⚗ research ○ none — n/a

## Where CoreProbe is better

- **Openness/auditability**: every claim in this repo is testable; 323 tests green. Cellebrite/AXIOM are closed boxes a court must trust.
- **Exploit catalog**: 77 public routes + 36 CVEs, ranked by acquisition value — the vendors keep theirs hidden or price it per-case.
- **Cost**: $0 vs $$$$ licenses / per-device fees.
- **Research instrumentation**: DFU capture + trace analysis + mutation fuzzing + campaign triage — a real zero-day research program in a box. No commercial vendor ships this.
- **Silicon envelope**: published per-chip truth (checkm8, Blackbird, usbliter8 incl. provenance) with honest 'nothing public for A14+'.
- **Own BFU stack**: keybag parser + UID-key unwrap + cprotect + AES-CBC sector decryption — ours, round-trip tested.
- **Court chain**: certify (native-hash manifest + HMAC-SHA256 seal + tamper detection) included, free.

## Where CoreProbe is NOT better (honest)

- **BFU passcode bypass (A12+)**: ○ none. SEP is closed silicon; GrayKey/Cellebrite rent unpublished SEP bugs. Our answer is the research campaign, not a pretend bypass.
- **DPA / Cellebrite central services**: not reachable without Apple legal agreements.
- **Cloud (iCloud) breadth**: harness exists (warrant-gated) but Apple web APIs cover far less than vendor pipelines.
- **Vendor validation/certification**: no court-tested tooling certification; community trust only.
- **Support ecosystem**: no 40-person support org.

## Status of each gap (2026-09-16)
```
where CoreProbe stands vs those gaps (2026-09-16 build):
  1. ARTIFACT BREADTH - BUILT: opensleuth ileapp run/breath bridges
     iLEAPP's 100+ parsers (invoked externally, GPLv3 respected);
     CoreProbe appcatalog adds DB discovery on top.
  2. COURT-READY REPORTING - BUILT: opensleuth certify (native hash
     manifest + HMAC-SHA256 seal + verify + HTML report).
  3. CLOUD ACQUISITION - BUILT (warrant-gated, retried): account-level
     contacts/calendar/notes/reminders/photos/devices via pyicloud.
  4. BFU PASSCODE BYPASS (A12+) - WALL (SEE docs/silicon-research.md):
     SEP is closed; reachable subset built (escrow, usbliter8
     playbook, yield card, keybags, silicon workbench (DFU trace +
     fuzzer + notebook) AND our own decrypt engine (keybag unwrap +
  5. DPA / Cellebrite central services - WALL: requires vendor-Apple
     legal agreements; no public protocol. Escrow/certify are the
     open alternatives (docs/roadmap-gaps.md).
  6. ECOSYSTEM - BUILT baseline: CI workflow, CONTRIBUTING, SECURITY,
     MIT LICENSE. Community growth is the long pole.
Bottom line: every winnable gap is now shipped; the two walls are
hardware/legal, documented honestly in docs/roadmap-gaps.md.
```

See docs/roadmap-gaps.md for the detailed treatment of the two hard walls.