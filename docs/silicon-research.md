# Silicon-level research: what exists, what CoreProbe ships, what remains

**The honest map.** CoreProbe cannot ship a working A12+ SEP passcode
bypass: no public exploit exists. DPA-style access is Cellebrite's legal
agreement with Apple, not code. What CoreProbe DOES ship is the public
silicon envelope plus the instrument class that produced it.

## Public silicon envelope (opensleuth silicon)

| Exploit | Chips | What it gives |
|---|---|---|
| limera1n (2010) | A4 | bootrom pwn (historical) |
| checkm8 (2019) | A7-A11 | full DFU control, any iOS; unpatchable |
| Blackbird (2020) | A10/A10X/T2, A11 limited | SEPROM race: SEP code exec + keybag ops = the BFU key chain |
| usbliter8 (2026) | A12/A13/S4/S5 | SecureROM code exec via DFU USB (DWC2) - SEP untouched |

A14+: **nothing public.** That is a fact, not a gap in our catalog.

## Research workbench (the "make ours" pipeline)
```
dfu-usbmon.sh  -> usbmon text capture
opensleuth silicon --trace <capture> --corpus corpus.csv
    (decode DFU requests, flag anomalies, build mutation corpus)
dfu-fuzz.py corpus.csv <iters>   -> mutate + drive a real device via pyusb;
    device death/hang/stall are the signals that precede bugs
opensleuth silicon --notebook <lab> --note "..."  -> timestamped research log
```
The companies got their capability from exactly this loop: capture the
protocol, fuzz the boundary conditions, log what breaks. The workbench
does not manufacture a bypass - it is the instrument that finds one.

## Lab kit (opensleuth silicon --lab <dir>)
- `dfu-usbmon.sh` - passive DFU USB capture (the checkm8/usbliter8 trace class)
- `dfu-identify.sh` - pwned-DFU introspection (serial/ecid/boardconfig/nonce)
- `session-log.sh` - timestamped research session log
- `chip-notes.md` - per-chip envelope summary

## What would produce a new A12+ SEP bypass
1. A public bootrom/SEP vulnerability (original research; hardware fuzzing
   against SEPROM is the realistic program - expensive, long, uncertain).
2. A vendor/legal interface (commercial, not OSS-reachable).
3. Legislative lawful-access mandates (out of our hands).

Until then: usbliter8 (A12/A13) + ramdisk flows, escrow, and AFU routes are
the honest maximum on modern silicon, and CoreProbe ships all of them.
