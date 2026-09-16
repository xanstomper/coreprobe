# A12+ BFU Bypass — the three buildable research paths

Apple will not grant legal access (post-2016 FBI stance). Vendor DPA is
unreachable. These are the three paths an open project can actually
pursue, each now instrumented in CoreProbe.

## Path 1 — SEP vulnerability research (`opensleuth sepos`)

Find a bug in SEPOS itself, GrayKey-style.

```
opensleuth firmware extract <ipsw> --out fw/
opensleuth sepos info fw/**/sep-firmware.*.im4p     # TLV inventory + Mach-O facts
opensleuth sepos diff <old.im4p> <new.im4p>         # build-to-build surface changes
```

Attack surface (in priority order):
1. AP→SEP mailbox request validation (AppleSEPKeyStore parses
   attacker-influenced data; fuzz with kernel r/w in AFU state)
2. SEPOS counter-increment path (wrong-passcode handling)
3. Key-derivation loop bounds (passcode → key unwrap)

Model: Blackbird (A10/T2 SEPROM race) proved the class works; TXM
hardening on A12+ is what a new bug must defeat.

## Path 2 — Counter bypass / accelerated brute force (`opensleuth passattack`)

Stock policy makes guessing hopeless — the model quantifies it:

```
$ opensleuth passattack --space 6-digit --days 30
  keyspace      : 1,000,000
  policy budget : 501 attempts in 30 days
  coverage      : 0.05%
  verdict       : infeasible — requires counter bypass (SEP research)
```

So the research targets ARE the counter:
- counter persistence across reboot/DFU (any reset path = the bug)
- delay-enforcement scheduler path
- effaceable-storage (NOR) counter region write-gating

Path 1 and Path 2 converge: both need SEPOS code understanding.

## Path 3 — Hardware fault injection (`opensleuth faultinjection`)

Glitch the silicon during the critical moments.

```
opensleuth faultinjection targets     # sepos-counter, key-unwrap, delay-sched, seprom-sigcheck
opensleuth faultinjection equipment   # $4k ChipWhisperer → $30k EM station → $150k laser
opensleuth faultinjection plan sepos-counter
  # width 20-400ns step 10 | offset ±2000ns step 25 | 5 reps | grid 6,505 points
```

Log outcomes (normal/reset/glitch-effect/...) per point; any repeatable
non-normal outcome at consistent (offset,width) = candidate → campaign
lead → reproduce → root-cause.

## Recommended program order

1. SEPOS build library: download IPSWs for your target chips, extract
   + diff SEP firmware across versions (path 1 tooling, free, today)
2. AFU kernel r/w fuzzing of the AppleSEPKeyStore surface (uses the
   existing catalog's AFU routes)
3. ChipWhisperer-class bench for the counter moment (path 3 entry tier)
4. All findings through: opensleuth campaign → verdict ladder →
   public writeup → catalog entry

## Honesty

No public A12+ SEP bypass exists. These are instruments for finding
one — months-to-years of specialized work with no guarantee. What's
already guaranteed: escrow, AFU routes, encrypted-backup-with-passcode,
and full post-unlock tooling.
