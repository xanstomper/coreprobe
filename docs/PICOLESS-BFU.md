# Picoless BFU — what works without the Pico 2 (honest)

The Pico 2 is mandatory for **one specific thing**: extracting the A12/A13
GID key. That key unlocks SEP firmware analysis (which leads to SEP bugs).
Everything else can run right now with zero hardware.

## What WORKS picoless (today, shipped, tested)

| Capability | How |
|---|---|
| Passcode-free backup unlock (ANY model) | `escrow find/describe/unlock/sweep` |
| BackupKeyBag extraction from encrypted backups | `keybag backupbag <Manifest.plist>` |
| BFU filesystem intelligence (class map, plaintext inventory) | `bfufs <pulled-root>` |
| Keybag analysis + our decrypt engine | `keybag status/unwrap`, `acquire bfu-decrypt` |
| SEP firmware acquisition + fingerprinting | `ipswfetch` + `sepos info/diff` (real Apple CDN data) |
| Attack-surface analysis | `surface` (36 CVEs, PRIME-tier) |
| Full research pipeline | `campaign`, DFU trace/fuzz/notebook, `faultinjection` |
| Court-ready chain of custody | `certify` |

## What does NOT work picoless, and why

| Capability | Why |
|---|---|
| A12/A13 GID key extraction | usbliter8's DWC2 USB race **cannot be hit by a PC USB stack** — the RP2350 board provides the precise timing. This is why even GrayKey/Cellebrite use custom hardware. |
| A12+ SEPOS decryption | Same key. No A12+ GID is public anywhere (see `sepos gidkeys`). |
| A14+ pwn | No public exploit exists at all. |

## The one picoless avenue that exists (already built)

**Escrow/backup-keybag** is the legitimate passcode-free path that needs
no hardware and works on every model — including A13/26.6.1. It fires
when the device was ever paired with a computer. It is not a SEP bypass;
it is the practical unlock that covers a large share of real casework.

## When the Pico 2 arrives

1. `acquire usbliter8` — pwn DFU (PWND:[usbliter8])
2. dump keys → `sepos gidkeys register A13 <keyfile>`
3. `sepos decrypt` the real SEPOS (pipeline proven on fixtures, waiting
   for real key material)
4. `sepos analyze` + `sepos diff-bin` across the iOS builds we already
   fetched — the binary-diff hunt on Apple's own counter/key code

The software is finished and tested. The only missing piece is the $12
board and a device in DFU.
