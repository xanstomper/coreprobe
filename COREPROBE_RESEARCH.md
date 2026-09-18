# COREPROBE RESEARCH BACKLOG

Format per directive: Topic / Why It Matters / Current Knowledge / Sources /
Technical Findings / Implementation Opportunity / Risk / Dependencies / Status.

Statuses: UNRESEARCHED · RESEARCHING · READY · IMPLEMENTING · TESTING ·
COMPLETE · REJECTED.

---

## R1. checkm8 adapter hardware validation matrix
- Why: checkm8 is our strongest public route; truth system currently marks it
  INTEGRATED (adapter exists) but no recorded lab validation per SoC.
- Current knowledge: gaster pwn flow implemented (cli.py acquire checkm8);
  PWND marker verification exists; per-chip validation runs not recorded.
- Sources: axi0mX checkm8 writeup; gaster repo; our exploitrunner.
- Findings: A7-A11 covered by exploit; A10/A11 iOS16+ needs passcode-off.
- Opportunity: validation-run recorder feeding truth registry
  (LAB_VALIDATED per chip+iOS), fixtures documented in capabilities.json.
- Risk: none (records only). Dependencies: M2 truth registry.
- Status: READY

## R2. Journal-backed acquisition interruption/recovery
- Why: device disconnects mid-acquisition must be recorded and partial
  evidence preserved without invalidating hashes.
- Current knowledge: certify seals point-in-time; no continuous record.
- Sources: directive §22-23; own audit.
- Findings: need ACQUISITION_INTERRUPTED event + per-object hashing on
  completion, never in-place appends.
- Opportunity: journal (M3) + resume decision helper in adapters.
- Risk: LOW. Dependencies: M3.
- Status: READY

## R3. Parser hostile-input hardening
- Why: evidence is hostile input; corrupt sqlite/plist must not crash a case.
- Current knowledge: parsers use try/except around plist decode; sqlite opened
  read-only URI. No fuzzed fixtures in tests.
- Sources: directive §26; audit.
- Opportunity: malformed-fixture regression suite (truncated DBs, bogus
  plists, huge rows), per-parser error events into journal.
- Risk: LOW. Dependencies: M3 (failure events).
- Status: READY

## R4. Exploit catalog → truth registry reconciliation
- Why: 77 catalog routes currently render as plain "routes"; UI must show
  research-vs-operational honestly.
- Current knowledge: exploits.py data verified against public sources.
- Opportunity: map ROUTES entries → capability IDs with honest statuses;
  exposure view gains per-route status pill.
- Risk: mislabeling → mitigated by auditor + tests asserting only seeded
  operational capabilities are plannable.
- Dependencies: M2, M5. Status: IMPLEMENTING

## R5. A12+ SEP / passcode-bypass honest roadmap
- Why: the two commercial-only walls; keep public models current.
- Current knowledge: passattack.py keyspace/budget model; faultinjection.py
  equipment tiers; roadmap-gaps.md.
- Sources: Apple Platform Security guide; Paradigm Shift usbliter8.
- Opportunity: keep as research docs; no fake capability rows.
- Risk: none. Dependencies: none. Status: COMPLETE (docs exist)

## R6. Restore-traversal CVE-2026-84598 observation harness
- Why: first-hand research route already built (cve2026_84598_restore.py).
- Current knowledge: crafted-manifest probe + observe-only flow, mock-pinned
  verdicts, lab cases CVE84598-LAB*.
- Opportunity: emit validation events into journal; record verdict matrix.
- Risk: LOW. Dependencies: M3. Status: READY

## R7. Timeline precision semantics
- Why: do not invent precision; date-only sources must not render as seconds.
- Current knowledge: timeline.py merges sources with naive dt handling.
- Opportunity: precision field (date/datetime/second) end-to-end.
- Risk: LOW. Dependencies: M3 artifact envelope. Status: UNRESEARCHED

## R8. Search/index over cases
- Why: directive §15; current report filter is client-side only.
- Current knowledge: none server-side.
- Opportunity: sqlite FTS5 index per case built during processing.
- Risk: scope; defer until M5 done. Status: UNRESEARCHED
