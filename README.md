# opensleuth

Open-source iOS forensic triage: an AXIOM/Cellebrite-style *logical extraction*
pipeline for Linux, built entirely on the open ecosystem
(libimobiledevice, ifuse) and Python stdlib.

```
iPhone (USB) ──> acquire ──> backup dir / media dir ──> dump ──> artifacts
                                                                  ├── messages.csv
                                                                  ├── contacts.csv
                                                                  ├── calls.csv
                                                                  ├── safari.csv
                                                                  ├── artifacts.json
                                                                  └── report.html   (AXIOM-style UI)
```

## What it does

| Stage | Tool | Status |
|---|---|---|
| USB pairing / device info | libimobiledevice (`ideviceinfo`) | ✅ |
| Full device backup | `idevicebackup2` | ✅ |
| Media (DCIM/Downloads/Recordings) | `ifuse` + copy | ✅ |
| App inventory | `ideviceinstaller` | ✅ |
| Backup index (`Manifest.db`) | Python `sqlite3` | ✅ |
| Artifact parsers (SMS, contacts, calls, Safari, prefs) | Python stdlib | ✅ |
| Timeline + HTML/CSV/JSON report | Python `html`/`csv`/`json` | ✅ |
| Encrypted backup + keychain decryption (`acquire --encrypted --password --unback`) | pyiosbackup | ✅ |
| iCloud acquisition | roadmap | ⏳ |

## Install / requirements

- Python 3.9+
- `libimobiledevice-utils` (`idevicebackup2`, `ideviceinfo`, `ideviceinstaller`)
- `ifuse` + FUSE for media copy

```bash
sudo apt install libimobiledevice-utils ifuse
git clone <your-repo> && cd opensleuth
```

## Usage

```bash
# 0. MAXIMUM LOGICAL ACQUISITION (everything below in one shot)
python3 -m opensleuth acquire all --out ~/cases/case1 --password <backup-pass>
#    pulls: device info, ALL mobilegestalt keys, IORegistry, battery, wifi,
#    live process list, app inventory, crash reports, screen orientation,
#    wallpaper, media (DCIM/Downloads/Recordings), 30s syslog window,
#    full unencrypted backup, AND full encrypted backup auto-decrypted via
#    pyiosbackup (keychain included). Add --sysdiagnose for a full
#    sysdiagnose archive (requires tapping "Allow" on the phone).

# 1. Per-service acquisition (phone must be plugged in, unlocked, trusted)
python3 -m opensleuth acquire backup --out ~/cases/case1/backup
python3 -m opensleuth acquire media  --out ~/cases/case1/media
python3 -m opensleuth acquire info   --out ~/cases/case1/device.json
python3 -m opensleuth acquire apps   --out ~/cases/case1/apps.json

# 2. App + artifact extraction from a backup (pymobiledevice3 writes
#    <backup>/<UDID>/... so point extract/dump at that inner directory)
python3 -m opensleuth extract ~/cases/case1/backup/<UDID> -o ~/cases/case1/appdata
python3 -m opensleuth dump    ~/cases/case1/backup/<UDID> -o ~/cases/case1/report
# -> report.html, messages.csv, contacts.csv, calls.csv, safari.csv,
#    artifacts.json, file_index.ndjson (full per-file inventory), timeline.csv
```

## Supported artifacts (v1)

- **iMessage / SMS**: `sms.db` (chats, senders, text, attachments, handled
  NSAttributedString bodies)
- **Contacts**: `AddressBook.sqlitedb` (names, org, phones, emails, birthday)
- **Call history**: `CallHistory.storedata` (direction, duration, answered)
- **Safari**: `History.db` + `Bookmarks.db`
- **Keychain**: `keychain-2.db` from decrypted encrypted-backups / jailbroken
  pulls (metadata + plaintext attempts; wrapped data exposed as hex)
- **Voicemail**: `voicemail.db` (sender, duration, audio presence)
- **Notes**: `NoteStore.sqlite` (titles, timestamps, raw body blobs saved)
- **Preferences**: `Library/Preferences/*.plist` (app/OS settings, tokens)
- **App database inventory**: every `.sqlite/.db/.storedata` in AppDomain-*
  containers, size + path, in report and `app_databases.csv`
- **Media inventory**: DCIM/Downloads/Recordings file listing with sizes
- **App container inventory**: per-`AppDomain-*` file counts and bytes from
  `Manifest.db`, with `extract` for full tree pulls

## Honest limits (same as Cellebrite logical)

- Full filesystem extraction on A12/A13 now has a public bootrom route:
  **usbliter8** (Paradigm Shift, 2026-06-18) - see "BFU / usbliter8" below.
- Full filesystem extraction beyond logical: public jailbreaks now reach
  iOS 18.7.1 on A12/A13 (Dopamine 3 + momentarius, which also covers
  26.0-26.0.1) and iOS 17.3.1 on A14-A17 Pro (Dopamine 3 + Titan);
  A8-A11 have checkm8/palera1n (PC-only) to 18.7.10. Nothing public on
  17.3.2+ for A14+, or 26.0.2+.
- `checkm8` bootrom exploit only covers A7-A11 (BFU-partial possible there)
- Keychain items require an **encrypted** backup + device passcode (supported via `--unback`)
- Deleted files are not recoverable from logical backups

## Capability planning (public vuln matrix, as of 2026)

```bash
# What public routes exist for any chip/iOS combo:
python3 -m opensleuth matrix A12 16.6.1
python3 -m opensleuth matrix A13 26.6.1

# Connected device -> recommended route, automatically:
python3 -m opensleuth plan --out ~/cases/case1

# Full filesystem pull from an ALREADY-jailbroken device (AFC2 root mount):
python3 -m opensleuth acquire jailbroken --out ~/cases/case1/fs

# Complete public exploit inventory, annotated with hardware needs:
python3 -m opensleuth exploits                  # everything known
python3 -m opensleuth exploits --no-hardware    # plain PC + USB only
python3 -m opensleuth exploits A13              # per-chip
python3 -m opensleuth silicon                    # bootrom/SEP envelope only

# Zero-extra-hardware bootrom route (A7-A11): gaster/ipwndfu -> palera1n/PongoOS
python3 -m opensleuth acquire checkm8 --out ~/cases/case1 [--chip A10] [--force]
#   note: A10/T2 additionally get the Blackbird SEP keybag path after pwn
#         (PongoOS 'sep pwn' / 'sep decrypt') - the BFU keybag primitive
#   --watch waits for DFU entry (start it, then press the button combo);
#         fires gaster the moment the device lands in DFU

# DFU entry watcher (timing-critical helper for any bootrom flow)
python3 -m opensleuth acquire dfu --out ~/cases/case1 [--timeout 180]
#   live mode transitions (normal -> recovery -> DFU), exit on DFU entry;
#   pairs with checkm8 --watch and the usbliter8 RP2350 flow

# CVE-2026-84598 restore-staging probe (research route; requires Find My OFF)
python3 -m opensleuth acquire restore-traversal --out ~/cases/case1 [--watch]
#   crafts a Manifest.mbdb with dot-dot traversal windows (schema verified
#   against 26.6.1: properties 8.0 / system-domains 19.0 / mbdb u32le),
#   serves it through the restore handshake, and CLASSIFIES the result:
#   GATE (Find My 211 = schema accepted, trigger blocked) vs
#   TRAVERSAL RESOLVED (device requested staged dot-dot paths). Never
#   completes a file transfer - safe to fire on any <26.7 target.
#   Full research notes: docs/research-2026-09-16-afc-26.6.1.md

# Public research pipeline: fetch Apple security releases + flag new
# acquisition-relevant CVEs (incremental - only shows what's new):
python3 -m opensleuth research [--detailed]
#   state: ~/.coreprobe/research-state.json; high-value findings are folded
#   into `opensleuth exploits` as RECENT_DISCLOSURES (e.g. CVE-2026-84598
#   MobileBackup path traversal - affects iOS <26.7 incl. a stock 26.6.1)

# Exposure report: every public route + CVE disclosure for a chip/iOS
# (auto-detects the connected device, or pass --chip/--ios):
python3 -m opensleuth exposure [--chip A13] [--ios 26.6.1] [--detailed]
```

The matrix data lives in `opensleuth/matrix.py` (chip-iOS map, checkm8 window,
per-version jailbreak windows) and is designed to be updated as public
capability evolves. Since 2026-06-18 the A12/A13 row is no longer empty:
the public **usbliter8** bootrom exploit (Paradigm Shift, coordinated with
Apple) provides SecureROM code execution on A12/A13 in any iOS state.

## Project layout

```
opensleuth/
  acquire.py        # wraps idevicebackup2 / ifuse / ideviceinfo
  usb.py            # sysfs USB discovery, mode classify (DFU/recovery/pwned),
                    # DFU entry watcher shared by every bootrom flow
  backup.py         # Manifest.db index, file extraction
  util.py           # Apple-epoch timestamps, plists, sizes
  artifacts/
    __init__.py
    sms.py contacts.py calls.py safari.py plists.py
  report.py         # HTML/CSV/JSON/timeline generation
  cli.py            # argparse entry point
tests/
  fixture.py        # builds a synthetic iPhone backup for testing
```

## BFU (Before First Unlock) - what is actually possible

After a reboot, before the passcode is entered once, iOS keeps pairing records and
user-data class keys locked. On **A12/A13 devices (iPhone 11 = A13) the door is
now the public usbliter8 bootrom exploit** (2026-06-18): it pwns SecureROM over
USB (RP2350 board), giving DFU-level control to host tools - the same class of
capability checkm8 gave A7-A11. It does NOT touch the Secure Enclave, so
passcode-derived keys stay fused; but bootrom control enables demoting
production mode, booting raw iBoot, and the ramdisk/AFC flows used for
full-filesystem extraction. What leaks pre-unlock:

| Data | BFU accessible? |
|---|---|
| USB serial, product info, PID (sysfs/`lsusb`) | ✅ yes |
| UDID via usbmuxd | ✅ yes |
| Recovery/DFU detection (iBoot state) | ✅ yes |
| Lockdown services, pairing, backups, AFC | ❌ gated until first unlock |
| Messages, photos, keychain, app data | ❌ encrypted (class keys not loaded) |
| SecureROM code exec (A12/A13) | ✅ usbliter8 (RP2350 board, tethered) |

```bash
# Probe any device in ANY state (BFU/AFU/recovery/DFU):
python3 -m opensleuth acquire probe --out ~/cases/case1

# usbliter8 bootrom route (A12/A13) - verify PWN DFU + get the chain:
python3 -m opensleuth acquire usbliter8 --out ~/cases/case1/ul8
#   Physical flow:
#     1. Flash usbliter8 firmware (RP2350: Pico 2 / Waveshare RP2350 USB-A)
#        from github.com/rav000/usbliter8 releases.
#     2. iPhone -> DFU (volume up, volume down, hold power; then power+vol-down).
#     3. Unplug from PC, plug into RP2350 board, wait for green LED (~1s).
#     4. Replug to PC: serial shows `PWND:[usbliter8]`.
#     5. usbliter8ctl demote | boot <raw-iBoot>, then ramdisk/AFC extraction.
```

Practical notes:
- Never reboot a subject device before acquiring; a single unlock (AFU) restores
  pairing + service access, after which `acquire all` applies.
- After a reboot, re-pairing is normally required (tap "Trust This Computer").
- On A7-A11 devices, checkm8-based flows (ipwndfu lineage) extract
  filesystem/keychain data in BFU. On A12/A13 usbliter8 is now the equivalent
  bootrom route (SEP still gates passcode data).
- Recovery-mode iBoot (`pymobiledevice3 restore`) exposes only bootloader state;
  Apple-signed ramdisks cannot decrypt the user volume without the passcode.

## AFU / BFU acquisition map

```bash
# AFU (after first unlock) - the full logical suite, one command:
opensleuth acquire afu --out ~/cases/case1 --password <pw> [--sysdiagnose]
#   = device info, gestalt, IORegistry, battery, wifi, processes, apps, crash,
#     orientation, wallpaper, media, syslog, unencrypted backup,
#     encrypted backup + keychain unpack (pyiosbackup), optional sysdiagnose

# Jailbroken device (per matrix, iOS <= 16.6.1 on A12-A16 etc.):
opensleuth acquire jailbroken --out ~/cases/case1/fs            # AFC2 root
opensleuth acquire jailbroken --out ~/cases/case1/fs --ssh root@DEVICE_IP  # SSH

# BFU (before first unlock) - EVERYTHING obtainable in that state:
opensleuth acquire bfu --out ~/cases/case1 [--chip A10]
#   = USB identity (serial/PID), UDID, recovery/DFU detection,
#     checkm8 flow when chip is A7-A11 + tooling present (gaster/ipwndfu),
#     lockdown gating check.
#   A12+ BFU: usbliter8 bootrom route (RP2350; see BFU section above).
#   A14+ BFU: no public route - the command records gating for the record.
```

| State | Public routes (as of 2026) | opensleuth |
|---|---|---|
| AFU, any iOS | logical backup + services + keychain (via password) | `acquire afu` |
| AFU, jailbreakable iOS | full filesystem + keychain dump; see `exploits` for the window (Dopamine 3 reaches A12/A13 15.0-18.7.1 + 26.0-26.0.1, A14-A17 Pro 15.0-17.3.1, A8-A11 via checkm8 to 18.7.10) | `acquire jailbroken` |
| BFU, A7-A11 | checkm8: iBoot/AES/BFU-partial | `acquire bfu --chip` |
| BFU, A12/A13 | **usbliter8**: SecureROM PWN DFU (RP2350) | `acquire usbliter8` / `bfu` |
| BFU, A14+ | none public | `acquire bfu` (records gating) |

## opensleuth studio_web (browser UI) - Exploits section

The web dashboard (port 9121 by default, `OPENSLEUTH_PORT` to change) has a
dedicated **Exploits** nav section backed by `/api/exploits`:
- device-aware: shows the connected phone's chip/iOS, recommended routes,
  and its live exposure report (every route + CVE disclosure that applies)
- filterable route table (hardware pill, layer, year, iOS window, BFU
  capability) plus the full recent-disclosures table
- whole catalog is served via `/api/exploits?chip=&ios=&layer=&no_hardware=`

Catalog state as of 2026-09-16: **66 public routes + 20 verified CVE
disclosures** spanning iOS 6 through iOS 26.0.1, all chips A4-A20 Pro,
plus tvOS/watchOS/bridgeOS routes. Newest public capability: Dopamine
3.0.9 (26.0-26.0.1 on A12/A13; 17.3.1 on A14-A17 Pro) and palera1n 3.0
beta 2 (18.7.10 cap, tvOS 26.6, bridgeOS 10.6). Nothing public on
iOS 27 / A18+ as of the 2026-09-15 release - the catalog says so
explicitly rather than inventing entries.

## opensleuth studio (desktop GUI)

Professional PyQt6 desktop application — AXIOM-style case workflow:

```bash
python3 -m opensleuth.studio
```

- **Case Builder**: case ID auto-generation, examiner/agency/location/owner,
  consent confirmation, evidence destination picker, notes, SHA-256 manifest
  option; saves case.json
- **Target Device**: auto-polls usbmuxd (2.5 s), device card (model, iOS,
  build, UDID, chip), auto-detected AFU/BFU state with manual override,
  per-route capability panel (logical / checkm8 / jailbreak with
  AVAILABLE / LOCKED / NOT POSSIBLE pills)
- **Acquisition**: toggle cards for every evidence category (backup,
  encrypted backup + keychain, media, crash, diagnostics, syslog, app
  containers), live app enumeration with real app icons (SpringBoard
  service) + search + select-all, animated progress view with per-step
  status pills and streaming log
- **Results**: artifact count cards, per-artifact tables (messages,
  contacts, calls, keychain…), open HTML report / evidence folder
- Animated page transitions, animated toggles, dark professional theme

Offscreen smoke test: `python3 tests/studio_smoke.py` (writes
`/tmp/studio-*.png` screenshots).

## Roadmap

- [ ] Encrypted backup support (`idevicebackup2 backup --encrypt`) with keybag
  parsing and keychain extraction (requires passcode)
- [ ] Notes (protobuf `ZICCLOUDSYNCINGOBJECT` decode), WhatsApp/Telegram,
  health, voicemail parsers
- [ ] Deleted-message slack recovery from WAL files
- [ ] iCloud backup pull with user-supplied credentials
- [ ] Timeline geolocation + map view

MIT license.
## Field deployment

One-command examiner install (apt deps, pyiosbackup/pymobiledevice3, optional checkm8 tooling and web studio service):

```bash
git clone https://github.com/xanstomper/coreprobe && cd coreprobe
sudo ./install.sh --with-web-service
# optional: sudo ./install.sh --with-checkm8-tools   (gaster/palera1n/irecovery)
# optional: sudo ./install.sh --with-desktop         (native Qt desktop shell)

python3 -m opensleuth exposure --chip A13 --ios 26.6.1
```

**Desktop app** (native window over the same workspace UI):

```bash
python3 -m opensleuth.studio_desktop   # or: opensleuth-desktop
```

The shell embeds the web backend on 127.0.0.1, with native menus
(Navigate/View/Help), toolbar navigation, Ctrl+1-5 page shortcuts, zoom, and a
live device status bar (model, AFU/BFU state, chip, iOS) polling `/api/device`.

**Native C++ core** (zero-dependency C++17, built via CMake):

```bash
sudo ./install.sh --with-cxx          # or: cmake -B build && cmake --build build
opensleuth cxx selftest               # FIPS SHA-256/SHA-1 vectors + MBDB unit tests
opensleuth cxx hash --sha1 <files>    # evidence hashing (~150 MiB/s)
opensleuth cxx verify <file> <hex>    # chain-of-custody check
opensleuth cxx manifest <dir> --out m # SHA-256 every extracted file (sorted manifest)
opensleuth cxx mbdb <Manifest.mbdb>   # parse backup index, flag traversal entries
opensleuth cxx bench                  # native hashing throughput
```

The C++ parser implements the Manifest.mbdb format reverse-engineered against
iOS 26.6.1 and flags the CVE-2026-84598 traversal shapes (`../../`, deep
`../../../`, `SysContainerDomain-../../..` domain escapes) in both path and
domain fields. Cross-validated in tests against the Python writer whose bytes
were verified live on the device.

The web studio binds **127.0.0.1 only** by default. To expose it (tunnel / LAN), set
`OPENSLEUTH_HOST=0.0.0.0` explicitly. There is no built-in auth: never bind it to a
public interface.
