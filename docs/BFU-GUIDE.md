# BFU Guide — Before First Unlock on every chip class

**The honest model first:** iOS data protection wraps content in per-class
keys. At BFU (device rebooted, passcode not yet entered):
- Class **None** content is readable — pull it now
- Class **CompleteUntilFirstUserAuthentication** — metadata visible, content encrypted until first unlock
- Class **Complete/CompleteUnlessOpen** — encrypted
- On A12+ the class keys live only inside the SEP. **No open-source tool
  can read them at BFU.** Anyone claiming otherwise is selling you something.

## 1. Per-chip reality

| Chip class | BFU route | What you get |
|---|---|---|
| A7–A11 | checkm8 (unpatchable bootrom) | PWN DFU → AES keyset (GID/UID) → keybags → ramdisk pull → **our decrypt engine** |
| A10/A10X/T2 | + Blackbird SEPROM race | SEP code exec, keybag ops — the only public SEP-keybag path |
| A12/A13 | usbliter8 (2026-06-18, Paradigm Shift) | SecureROM code exec → iBoot control → ramdisk. **SEP untouched** |
| A14+ | **nothing public** | escrow/backup path only |

## 2. Workflow: any modern phone

```bash
opensleuth acquire bfu --chip A13 --ios 26.6.1 --yield-card --out case
# → what THIS device can yield right now (live USB state + tooling)

opensleuth bfufs <pulled-root>
# → per-file class map from real cprotect xattrs:
#   which files are PLAINTEXT at BFU (pull them!)
#   which are metadata-only targets for after unlock/escrow

opensleuth keybag backupbag <Manifest.plist>
# → extract the BackupKeyBag from an encrypted backup (base64 or raw)
```

## 3. Workflow: escrow / paired-computer unlock (passcode-free, all models)

The one passcode-free path that works on every model — if the device was
ever paired with a computer, that relationship may unlock backup
decryption:

```bash
opensleuth escrow find <case-materials>      # locate records/keybags
opensleuth escrow describe <record>          # classes + passcode material
opensleuth escrow unlock <record> <backup> --out case/decrypted
opensleuth escrow sweep <materials> --out case   # batch hunt everything
```

## 4. Workflow: checkm8 devices (A7–A11) — full stack

```bash
opensleuth acquire bfu --chip A10 --watch --keys --out case
#   --watch: waits for DFU entry, auto-chains gaster pwn → AES keys
#   --ramdisk ./payloads: loads iBSS/iBEC/ramdisk/devicetree/trustcache, pulls keybags

opensleuth keybag unwrap case/systembag.kb --uid-key <hex|file> --out case/class-keys.json
opensleuth acquire bfu-decrypt <file> --cprotect <blob> --class-key <hex>
#   → per-file key unwrap → AES-CBC sector decrypt (our own engine)
```

## 5. Workflow: A12/A13 (usbliter8)

```bash
opensleuth acquire bfu --chip A13 --route usbliter8 --out case
#   7-step playbook: RP2350 flash → DFU → PWND → iBoot control → ramdisk → pull → escrow
#   Hardware: Waveshare RP2350 USB-A / Pico 2 / TINY2350 (see docs/runbook-usbliter8-pico2.md)
```

## 6. Runbook generation

```bash
opensleuth acquire bfu --chip A13 --ios 26.6.1 --runbook case/bfu-runbook.md --out case
```

## UI

**BFU Lab** page (desktop Ctrl+7): FS intelligence scan, keybag status,
escrow find, decrypt inputs — all live.

## Honest limits

- A12+ SEP: user-class keys never leave the SEP at BFU. Vendors rent
  unpublished SEP bugs; we don't have one and won't fake one.
- The decrypt engine's layouts follow public references — validate
  against a real device fixture before case work.
