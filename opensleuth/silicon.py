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