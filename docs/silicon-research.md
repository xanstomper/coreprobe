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

## Our own BFU decryption stack (the payoff end of the pipeline)
```
keybag unwrap <bag> --uid-key <key>      -> class keys (AES-ECB with UID key)
acquire bfu-decrypt <file> --inspect <cprotect>
acquire bfu-decrypt <file> --cprotect + --class-key
    -> per-file key unwrap (AES-ECB with class key) -> AES-CBC sector decrypt
```
Documented iOS data-protection pipeline, self-tested by round-trips.
Applies where class keys are obtainable: checkm8 A7-A11 (UID-key AES from
the pwned engine), escrow/backup keybags. On A12+ the keys stay in the
SEP, so this stack is the recovery end of the A7-A11 + escrow flows and a
target for the fuzz research. Validate against a real device fixture
before case work (Apple does not publish the format).

## Exploit-development toolbox (the ingredients for new-chip work)
```
firmware scan <dir> / identify <file>   -> image classification (IMG4/Mach-O)
firmware img4 <file>                    -> IM4P container parse (type/desc/key/cert)
firmware extract <ipsw> --out <dir>     -> IPSW extraction + classification
trustcache build --hashes ... --out t  -> CD-hash whitelist (research boot)
trustcache parse <file>                 -> inspect an existing trustcache
patches [--target kernel|sep|iboot|sptm] -> documented patch-point catalog
```
These are the real artifacts exploit development consumes: firmware
images to patch, trustcaches to whitelist payloads, and an honest
inventory of the documented patch classes (AMFI bypass, KTRR wipe,
iBoot sig NOP, SPTM bypass, Blackbird SEP ops). Combined with the DFU
workbench they form a complete open-source development loop.

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
