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

## The picoless A12+ research avenue (built, live)

Escrow is the practical unlock, but it is not an exploit hunt. The one
genuine picoless route to NEW A12/A13 capability is hunting a
**host-reachable DFU bug** - a length/state-confusion flaw in the DFU
protocol layer (the checkm8 bug class) that a normal PC USB stack CAN
deliver, unlike usbliter8's device-side DWC2 race.

Built and wired:

1. `campaign new <name> --chip A13` — start a research campaign
2. `campaign run <id> --capture <usbmon.txt> --check` — non-mutating:
   verifies a device in DFU mode (pid 0x1227) is present and speaks DFU.
   Safe to run any time; refuses non-DFU Apple devices outright.
3. `campaign run <id> --capture <usbmon.txt> --live --confirm-live-dfu`
   — drives DFU-class control-transfer mutations at the DFU-mode device
   over plain PC USB (picoless). Safety model:
   - refuses anything except DFU mode (pid 0x1227) - a live iPhone in
     normal mode is never touched (brick protection)
   - only DFU-class requests (0x21/0xA1) travel; data stages only on
     DNLOAD, zero-filled, capped at 4 KiB
   - device death/hang is the observed signal; worst case is a hang,
     re-enter DFU with the button sequence. Nothing is written to NAND
     from DFU without a signed image, so this cannot brick.

The capture corpus comes from `dfu-usbmon.sh` (in the lab kit). Start
with `campaign run <id> --capture <file> --dry` to build/analyze the
corpus offline first, then go live.

## The picoless avenue that existed before (escrow)

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
