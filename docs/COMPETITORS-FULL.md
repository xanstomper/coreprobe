# All Competitors — detailed comparison (2026-09-16)

CoreProbe is compared below against every meaningful player in iOS/mobile
forensics. Ratings: ● full ◐ partial ⚗ research ○ none — n/a.
Maintained in code (`opensleuth stance`); this page expands each row.

## Cellebrite UFED / Premium / Physical Analyzer
The market leader. Full logical/physical/cloud, licensed BFU "services"
on modern devices, huge device coverage, court validation.
- **Where we match/win**: logical + encrypted-backup acquisition; checkm8
  flows; artifact parsing depth (with iLEAPP); reporting transparency
  (our certify is auditable, theirs is trust-us); price ($0 vs $$$);
  exploit knowledge (77-route public catalog vs hidden internals).
- **Where they win**: BFU passcode bypass (their SEP bugs, rented);
  DPA central services (Apple legal agreements); device breadth
  (1000s of phones, not just iOS); validation/certification; support.

## Magnet AXIOM
Analysis-first platform; strong artifact processing + case management.
- **Match/win**: parsing breadth (iLEAPP bridge ≈ artifact count),
  timeline (ours merges knowledgeC — richer pattern-of-life than most),
  cost, openness.
- **They win**: court-tested reporting workflows, multi-source
  correlation (cloud+mobile+computer in one case), examiner ecosystem.

## Grayshift GrayKey
Hardware BFU passcode-cracking appliance.
- **Match/win**: nothing on their core trick (SEP brute-force via
  unpublished bugs). We match their *public* surface: usbliter8 gives
  A12/A13 bootrom control (GrayKey's alleged lineage — see the Magnet
  Forensics litigation note in EXPLOIT-CATALOG.md).
- **They win**: the actual A12+ BFU unlock. ○ for us, honestly.

## Elcomsoft iOS Forensic Toolkit
Checkm8-powered agent-based extraction; keychain via passcode.
- **Match/win**: checkm8 route parity (we ship gaster/palera1n flows),
  keychain from encrypted backups (--unback), price.
- **They win**: polished agent extraction on more iOS versions,
  GPU-accelerated password cracking ecosystem.

## MSAB XRY / Oxygen Detective / Belkasoft EC X
Generalist mobile suites.
- **Match/win**: iOS-specific depth (we go silicon-deep; they don't),
  research instrumentation, cost.
- **They win**: multi-platform (Android/feature phones), validation,
  LE procurement channels.

## Open-source neighbors (honest peers)
- **iLEAPP/APOLLO/MEAT/ArtEx**: parsing only → we integrate, then add
  acquisition + research + custody they don't have.
- **MVT**: spyware detection → narrower scope than CoreProbe.
- **libimobiledevice/pymobiledevice3**: libraries → we build the
  examiner workstation on top (and contribute flows back).

## Summary table

| Capability | CoreProbe | Cellebrite | AXIOM | GrayKey | Elcomsoft | XRY | Oxygen | Belkasoft |
|---|---|---|---|---|---|---|---|---|
| Logical acquisition | ● | ● | ◐ | — | ● | ● | ● | ● |
| Encrypted backup + keychain | ◐ | ● | ◐ | — | ● | ◐ | ◐ | ◐ |
| Full FS via jailbreak/checkm8 | ● | ● | ◐ | — | ● | ◐ | ◐ | ◐ |
| BFU passcode bypass (A12+) | ○ | ● | — | ● | ◐ | ○ | ○ | ○ |
| Cloud (iCloud) | ◐ | ● | ● | — | ◐ | ◐ | ● | ◐ |
| Artifact breadth | ◐ | ● | ● | — | ◐ | ◐ | ◐ | ◐ |
| Court reporting/custody | ◐ | ● | ● | — | ◐ | ◐ | ◐ | ◐ |
| Research instrumentation | ● | ○ | ○ | ○ | ○ | ○ | ○ | ○ |
| Openness/auditability | ● | ○ | ○ | ○ | ○ | ○ | ○ | ○ |
| Cost | $0 | $$$ | $$$ | $$$$ | $$$ | $$$ | $$$ | $$$ |

## Being-implemented (honest roadmap)

- Live campaign fuzz runs from the UI (CLI-ready today)
- knowledgeC → super-timeline merge (both exist; wiring next)
- iCloud panel in the web UI (CLI-ready today)
- Real-device validation of the decrypt engine layouts
- iLEAPP output import into the Artifacts page

## What it can actually do RIGHT NOW

Everything marked ●/◐ above is shipped, tested (323 green), and
documented in this repo. The two ○ rows are the walls; the research
campaign in this repo is the only open path to moving them.
