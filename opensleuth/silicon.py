"""Public silicon-level (bootrom / SEP) exploit catalog for iOS devices.

This is CoreProbe's niche layer: capability that lives BELOW iOS itself,
in code fused into the chip (SecureROM / SEPROM). Every entry below is
publicly documented research - nothing here is a private 0-day. Cellebrite
and Elcomsoft price exactly this envelope into their products; we publish
it openly and wire it into the acquisition planner.

Envelope as of 2026-09:

  limera1n    : A4 bootrom (geohot, 2010) - historical, iPhone 4 era.
  checkm8     : A7-A11 bootrom (axi0mX, 2019) - PWN DFU on any iOS, BFU
                partial extraction, iBoot/AES access. Unpatchable.
  Blackbird   : SEPROM race exploit (checkra1n/PongoOS) - full SEP code
                execution on A10/A10X/T2, limited on A11. Gives
                hardware keybag operations (sep_aes_kbag: UID-key AES)
                and BPR patch = the actual keychain/BFU key path.
  usbliter8   : A12/A13 SecureROM (Paradigm Shift, 2026-06-18) - DWC2 USB
                DMA pointer underflow (DART bypass in SecureROM), PWN DFU
                via RP2350 board, boot raw iBoot / demote production.
                SEP untouched. First public A12/A13 bootrom.
                PROVENANCE: Magnet Forensics (GrayKey) filed suit 2026-07-07
                alleging this is their proprietary A12/A13 SecureROM 0-day
                ("MSG"), published by a former exploit engineer. If accurate,
                CoreProbe ships the same silicon-level access vendors sold.

SEP = Secure Enclave Processor. SEP floor: on every chip, the SEP keybag
(which holds the encryption keys for user data) is decrypted only by SEP
hardware using the UID key. So:

  - checkm8 gives you the WHOLE SOC except SEP -> BFU-partial.
  - Blackbird gives you the SEP itself -> full keybag chain (A8-A10).
  - usbliter8 gives you SecureROM control but NOT SEP -> BFU-partial
    with full boot control (ramdisk flows).

Commercial landscape (public record, 2024-2026):
  - Cellebrite Inseyets (blog, 2026-05-29): claims AFU + BFU on latest
    iPhone/iOS ("the access gap is closed"). Private 0-days, NOT
    independently verifiable. Leaked iOS Support Matrix (Apr 2024) showed
    "In Research" for iOS 17.4+ and no iPhone 15 coverage.
  - Magnet GrayKey (leak, Nov 2024, 404 Media): FULL iPhone 11; PARTIAL
    iPhone 12-16; none on iOS 18 betas. iOS 26 "day-one support" claimed
    (Sept 2025) - specifics not public. GrayKey = usbliter8 provenance.
  - Apple countermeasures: iOS 18.1+ inactivity reboot -> BFU in ~4 days;
    Lockdown Mode; memory integrity enforcement (A12+). Net effect:
    vendors shift from silicon to private software 0-days, and the gap is
    shrinking - "Apple is winning the cat-and-mouse game for now".

The commercial tools' "BFU extraction" on A12+ runs on private exploits;
the open envelope honestly stops at BFU-partial + bootrom control (plus
AFU software jailbreaks: Dopamine 3 reaches A12/A13 to 18.7.1 + 26.0-26.0.1,
A14-A17 Pro to 17.3.1, arm64 A8-A11 to 18.7.1 - see `opensleuth exploits`).
"""

from __future__ import annotations

from pathlib import Path

from typing import Any, Optional

# --------------------------------------------------------------------------
# The catalog
# --------------------------------------------------------------------------

EXPLOITS: list[dict[str, Any]] = [
    {
        "name": "limera1n",
        "year": 2010,
        "discoverer": "geohot (Hotz)",
        "venue": "public",
        "linux": "A4",
        "chips": ["A4"],
        "devices": ["iPhone 4", "iPhone 3GS (later bootrom)", "iPod touch 3"],
        "state": ["DFU", "Recovery"],
        "hardware": "USB only (standard host)",
        "capabilities": ["PWN DFU", "custom LLB/iBoot boot"],
        "bfu": "historical bootrom control; pre-SEP era (A4 has no SEP user keybag) - full FS on unlocked-class data",
        "sep": False,
        "tooling": ["limera1n", "ipwndfu (early)"],
        "patched": "Hardware-only; not patchable by software",
        "notes": "Pre-iPhone5 hardware only.",
    },
    {
        "name": "checkm8",
        "year": 2019,
        "discoverer": "axi0mX",
        "venue": "public",
        "linux": "A7-A11 bootrom (USB DFU)",
        "chips": ["A7", "A8", "A9", "A10", "A11"],
        "devices": ["iPhone 5s ... iPhone X", "iPad Air/Air2/mini2..4", "iPod touch 6/7"],
        "state": ["DFU"],
        "hardware": "USB only (standard host). DFU entry needed.",
        "capabilities": [
            "PWN DFU",
            "arbitrary code exec in SecureROM",
            "boot unsigned iBoot / ramdisk",
            "AES engine access (GID/UID)",
            "BFU-partial filesystem + keybag analysis",
        ],
        "bfu": "BFU-partial: class keys for NSFileProtectionNone/CompleteUntilFirstUserAuthentication are recoverable; stronger classes need passcode (SEP)",
        "sep": False,
        "tooling": ["gaster", "ipwndfu", "ipwnder32", "checkra1n", "palera1n", "PongoOS", "Elcomsoft Phone Breaker (checkm8 mode)"],
        "patched": "Hardware-only; unpatchable",
        "notes": "The reference bootrom exploit of the era; foundation of all open A7-A11 flows.",
    },
    {
        "name": "Blackbird",
        "year": 2020,
        "discoverer": "checkra1n team (SEP research)",
        "venue": "public (PongoOS source)",
        "linux": "SEPROM race during firmware load",
        "chips": ["A10", "A10X", "T2", "A11 (limited)"],
        "devices": ["iPhone 7/7+", "iPad Pro 10.5/12.9 (2nd gen)", "Macs with T2", "iPhone 8/8+/X (limited)"],
        "state": ["Post-checkm8 boot (PongoOS)"],
        "hardware": "USB; runs inside PongoOS after checkm8",
        "capabilities": [
            "SEP code execution (SEPROM level)",
            "sep_aes_kbag: hardware AES with GID/UID keys",
            "keybag decryption (the BFU key path)",
            "SEP firmware patch (BPR check removal -> no lockdown)",
            "SEP memory r/w + jump",
        ],
        "bfu": "FULL BFU keybag chain on supported SEPs: the keys that gate user data live in the keybag; with SEP AES you can unwrap them - the same primitive commercial BFU tools use",
        "sep": True,
        "tooling": ["PongoOS (sep pwn / sep decrypt)", "checkra1n / palera1n (SEP-limited variants)"],
        "patched": "Hardware-only (SEPROM); unpatchable",
        "notes": "Prerequisite: checkm8 (A10/A11) or T2 chain. Niche: full SEP compromise is NOT public on A12+.",
    },
    {
        "name": "usbliter8",
        "year": 2026,
        "discoverer": "Paradigm Shift (@__gsch, @hdesk)",
        "venue": "public (2026-06-18, coordinated with Apple Product Security)",
        "linux": "A12/A13 SecureROM (Synopsys DWC2 USB DMA pointer underflow)",
        "chips": ["A12", "A13", "S4", "S5"],
        "devices": ["iPhone XS/XS Max/XR", "iPhone 11/11 Pro/11 Pro Max/SE2", "Apple Watch S4/S5", "HomePod mini"],
        "state": ["DFU (NOT via LLB break)"],
        "hardware": "RP2350 board required (Waveshare RP2350 USB-A, Pico 2, TINY2350). PC USB stacks cannot hit the race.",
        "capabilities": [
            "PWN DFU (PWND:[usbliter8])",
            "SecureROM code exec (EL1) on A12/A13",
            "demote production mode",
            "boot raw (unsigned/decrypted) iBoot",
            "foundation for ramdisk / SSH extraction (usbliter8ra1n chain: iBoot patch, SPTM bypass, TXM bypass, kernel patchfinder, SSH ramdisk)",
        ],
        "bfu": "BFU-partial + bootrom control: ramdisk/SSH flows can enumerate the FS; SEP-gated data classes still need passcode or an AFU window (SEP not touched)",
        "sep": False,
        "tooling": ["usbliter8 (firmware + usbliter8ctl)", "usbliter8ra1n (full boot chain)", "picotool"],
        "patched": "Hardware-only; unpatchable",
        "notes": "First public A12/A13 bootrom since checkm8. Tethered: re-run after every boot. "
                 "Provenance per Magnet Forensics v. Paradigm Shift (filed 2026-07-07): alleged "
                 "ex-Magnet/GrayKey SecureROM 0-day 'MSG', published by a former exploit engineer.",
    },
]

# Chip -> list of exploit names (fast lookup)
CHIP_EXPLOITS: dict[str, list[str]] = {}
for _exp in EXPLOITS:
    for _c in _exp["chips"]:
        CHIP_EXPLOITS.setdefault(_c, []).append(_exp["name"])

ALL_CHIPS = sorted({c for e in EXPLOITS for c in e["chips"]})
ALL_NAMES = [e["name"] for e in EXPLOITS]


# --------------------------------------------------------------------------
# Accessors
# --------------------------------------------------------------------------

def by_name(name: str) -> Optional[dict[str, Any]]:
    """Return exploit dict by (case-insensitive) name."""
    for e in EXPLOITS:
        if e["name"].lower() == name.lower():
            return e
    return None


def for_chip(chip: str) -> list[dict[str, Any]]:
    """Exploits applicable to a chip ('' -> all)."""
    chip = (chip or "").upper()
    if not chip or chip == "ALL":
        return list(EXPLOITS)
    return [e for e in EXPLOITS if chip in e["chips"]]


def covered_chips() -> list[str]:
    return ALL_CHIPS


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def render(chip: str = "", detailed: bool = False) -> str:
    """Human-readable catalog, optionally filtered by chip.

    Matches matrix-style output: numbered capabilities, honest BFU column.
    """
    rows = for_chip(chip)
    if not rows:
        return f"no public silicon exploits catalogued for chip '{chip}'"
    lines = []
    title = f"public silicon-level exploit envelope{('  (chip ' + chip.upper() + ')') if chip else ''}"
    lines.append("=" * len(title))
    lines.append(title)
    lines.append("=" * len(title))
    for e in rows:
        lines.append("")
        lines.append(f"## {e['name']}  ({e['year']}, {e['discoverer']})")
        lines.append(f"  vector   : {e['linux']}")
        lines.append(f"  chips    : {', '.join(e['chips'])}")
        lines.append(f"  devices  : {'; '.join(e['devices'])}")
        lines.append(f"  state    : {', '.join(e['state'])}")
        lines.append(f"  hardware : {e['hardware']}")
        if not detailed:
            lines.append(f"  caps     : {'; '.join(e['capabilities'])}")
        else:
            for cap in e["capabilities"]:
                lines.append(f"    - {cap}")
        lines.append(f"  BFU      : {e['bfu']}")
        lines.append(f"  SEP      : {'COMPROMISED (full keybag path)' if e['sep'] else 'untouched (BFU-partial)'}")
        lines.append(f"  tools    : {'; '.join(e['tooling'])}")
        lines.append(f"  patch    : {e['patched']}")
        if e.get("notes"):
            lines.append(f"  notes    : {e['notes']}")
    lines.append("")
    lines.append("Envelope summary: checkm8 (A7-A11) + Blackbird (SEP, A10/T2) + usbliter8 (A12/A13)")
    lines.append("cover every PUBLIC bootrom/SEP route on iPhones. A14+ has none public.")
    return "\n".join(lines)

# --------------------------------------------------------------------------
# Silicon research lab kit: capture + instrumentation (does NOT ship a
# bypass; it ships the instrument class that produced the entries above).
# --------------------------------------------------------------------------

LAB_FILES = {
    "dfu-usbmon.sh": "#!/usr/bin/env bash\n"
    "# Passive DFU USB capture (usbmon). Run BEFORE entering DFU.\n"
    "# Captures every USB packet against the Apple DFU interface - the same\n"
    "# kind of trace that produced checkm8 (overflow) and usbliter8 (DWC2\n"
    "# DMA underflow). Stops with Ctrl-C. Output: dfu-capture-<ts>.pcapng\n"
    "set -euo pipefail\n"
    "TS=$(date +%Y%m%d-%H%M%S)\n"
    "OUT=${1:-dfu-capture-$TS.pcapng}\n"
    "echo \"== DFU USB capture -> $OUT\"\n"
    "sudo modprobe usbmon 2>/dev/null || true\n"
    "BUS=1\n"
    "if [ ! -r /sys/kernel/debug/usb/usbmon/$BUS ]; then\n"
    "  echo 'usbmon not readable; try: sudo mount -t debugfs none /sys/kernel/debug'\n"
    "  exit 1\n"
    "fi\n"
    "sudo tcpdump -i usbmon$BUS -U -w \"$OUT\" &\n"
    "TPID=$!\n"
    "trap \"sudo kill $TPID 2>/dev/null || true\" EXIT\n"
    "echo 'capturing... (Ctrl-C to stop; enter DFU when ready)'\n"
    "wait $TPID\n",
    "dfu-identify.sh": "#!/usr/bin/env bash\n"
    "# Pwned/DFU device introspection: chip identity, board config, nonces.\n"
    "set -uo pipefail\n"
    "OUT=${1:-.}\n"
    "mkdir -p \"$OUT\"\n"
    "for env in serial ecid boardid boardconfig cpuid nonce; do\n"
    "  echo \"== getenv $env\"\n"
    "  irecovery -q -c \"getenv $env\" 2>&1 || true\n"
    "done > \"$OUT/dfu-identify-$(date +%Y%m%d-%H%M%S).log\"\n"
    "echo \"identity log written to $OUT\"\n",
    "session-log.sh": "#!/usr/bin/env bash\n"
    "# Research session logger: timestamps every step into a case-ready log.\n"
    "set -uo pipefail\n"
    "LOG=${1:-session.log}\n"
    "echo \"== CoreProbe silicon research session $(date -u +%Y-%m-%dT%H:%M:%SZ)\" > \"$LOG\"\n"
    "log() { echo \"[$(date -u +%H:%M:%SZ)] $*\" >> \"$LOG\"; }\n"
    "cmd() { log \"> $*\"; \"$@\" >> \"$LOG\" 2>&1; log \"< exit $?\"; }\n"
    "echo \"log -> $LOG  (add steps with: cmd <your-command>)\"\n",
    "dfu-fuzz.py": "#!/usr/bin/env python3\n"
    "# Mutation fuzzer for Apple DFU control transfers (research use).\n"
    "# Loads corpus.csv (opensleuth silicon trace --corpus), mutates\n"
    "# wLength/wValue/wIndex/bRequest, drives a REAL device via pyusb,\n"
    "# and logs device death/hang/stall - the signals before bugs.\n"
    "# SAFETY: lawful devices only. A crash may require re-entering DFU.\n"
    "import sys, time\n"
    "sys.path.insert(0, 'REPO')  # patched at generation\n"
    "import usb.core, usb.util  # noqa\n"
    "from opensleuth.dfutrace import read_corpus\n"
    "from opensleuth.dfufuzz import run_fuzz\n"
    "class LiveDevice:\n"
    "    def __init__(self, vid=0x05ac, pid=0x1227):\n"
    "        self.dev = usb.core.find(idVendor=vid, idProduct=pid)\n"
    "        if self.dev is None:\n"
    "            print('apple dfu device not found (vid 0x05ac pid 0x1227/1222)'); sys.exit(2)\n"
    "    def alive(self):\n"
    "        try:\n"
    "            return usb.core.find(idVendor=0x05ac) is not None\n"
    "        except Exception:\n"
    "            return False\n"
    "    def ctrl_transfer(self, bm, b, wv, wi, wl, timeout):\n"
    "        return self.dev.ctrl_transfer(bm, b, wv, wi, wl or None, timeout=timeout)\n"
    "def main():\n"
    "    corpus_path = sys.argv[1] if len(sys.argv) > 1 else 'corpus.csv'\n"
    "    iterations = int(sys.argv[2]) if len(sys.argv) > 2 else 300\n"
    "    dev = LiveDevice()\n"
    "    corpus = read_corpus(corpus_path)\n"
    "    print(f'fuzzing {len(corpus)} requests x {iterations} iterations')\n"
    "    res = run_fuzz(dev, corpus, iterations=iterations, log=print)\n"
    "    print('sent', res['sent'], '| crashes', res['crashes'], '| hangups', res['hangups'])\n"
    "    print('interesting responses:', len(res['interesting']))\n"
    "if __name__ == '__main__':\n"
    "    main()\n",
    "README.md": """# CoreProbe silicon research lab kit

For lawful research on devices under your authority.

Kit contents:
  - dfu-usbmon.sh    passive DFU USB capture (usbmon) - the trace class
                     that produced checkm8 and usbliter8
  - dfu-identify.sh  pwned-DFU introspection (serial/ecid/boardconfig/nonce)
  - session-log.sh   timestamped research session log

Process:
  1. session-log.sh
  2. dfu-usbmon.sh (BEFORE entering DFU)
  3. Enter DFU; pwn (gaster A7-A11 / RP2350 usbliter8 A12/A13)
  4. dfu-identify.sh in pwned DFU
  5. irecovery flashes + env commands, all session-logged
  6. opensleuth silicon trace <capture> --corpus corpus.csv
  7. python3 dfu-fuzz.py corpus.csv 300   (mutation fuzzing, lawful devices)

Honest envelope (opensleuth silicon):
  - A7-A11: checkm8 (full DFU control)
  - A10/A10X/T2: + Blackbird SEPROM race = FULL BFU keybag chain
  - A12/A13: usbliter8 (SecureROM code exec, SEP untouched)
  - A14+: NO PUBLIC silicon exploit. This kit cannot change that.
A working A12+ SEP bypass would be an unpublished vulnerability found by
original research - not a download.
""",
}


def lab_kit(out: str | Path, chip: str = "A13") -> dict[str, Any]:
    """Generate the silicon research lab kit into a directory."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, content in LAB_FILES.items():
        f = out / name
        f.write_text(content)
        if name.endswith(".sh"):
            f.chmod(0o755)
        written.append(name)
    hits = for_chip(chip)
    notes = [f"# {chip} silicon notes", ""]
    for h in hits:
        notes.append(f"## {h['name']} ({h['year']})")
        notes.append(f"  {h['linux']}")
        notes.append(f"  BFU: {h['bfu']}")
        notes.append("")
    (out / "chip-notes.md").write_text("\n".join(notes))
    written.append("chip-notes.md")
    return {"out": str(out), "files": written, "chip": chip}


def notebook(lab_dir: str | Path, note: str | None = None,
             notebook_name: str = "research.json") -> dict[str, Any]:
    """Append a timestamped note to the lab's research notebook."""
    lab_dir = Path(lab_dir)
    lab_dir.mkdir(parents=True, exist_ok=True)
    path = lab_dir / notebook_name
    entries = []
    if path.exists():
        import json
        entries = json.loads(path.read_text())
    if note:
        entries.append({"ts": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(timespec="seconds"),
            "note": note})
        path.write_text(__import__("json").dumps(entries, indent=2))
    return {"notebook": str(path), "entries": entries}


def render_notebook(nb: dict[str, Any]) -> str:
    lines = [f"research notebook: {nb['notebook']}  ({len(nb['entries'])} entries)", ""]
    for e in nb["entries"]:
        lines.append(f"  [{e['ts']}] {e['note']}")
    return "\n".join(lines)


def render_lab(r: dict[str, Any]) -> str:
    lines = [f"silicon lab kit generated: {r['out']} (chip {r['chip']})", ""]
    for f in r["files"]:
        lines.append(f"  - {f}")
    lines += ["", "process: session-log.sh -> dfu-usbmon.sh -> enter DFU -> pwn",
              "-> dfu-identify.sh -> irecovery flows"]
    return "\n".join(lines)
