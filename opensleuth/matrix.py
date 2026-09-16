"""Public iOS extraction capability matrix (maintained, as-of-2026).

Every route below is PUBLIC, documented capability. Note: since June 18 2026
the usbliter8 BootROM exploit (Paradigm Shift) covers A12/A13 - a bootrom
route now exists for iPhone 11 (A13) in ANY state, tethered via an RP2350
board. Secure Enclave (passcode/keychain material) is NOT directly
compromised; BFU-partial + full-filesystem extraction is.

Routes:
  logical   : pairing + backups + AFC (every iOS, AFU required)
  checkm8   : bootrom exploit, A7-A11, any iOS incl. BFU-partial
  usbliter8 : bootrom exploit, A12/A13 (XS/XR/11/SE2), any iOS incl. BFU-
              partial; tethered, requires RP2350 USB rig (Pico 2 etc.)
  jailbreak : per-version kernel exploits, AFU required
  trollstore: signed-app install (no jailbreak), AFU required
"""

# ProductType -> chip (common devices; unknown entries fall back to generic)
CHIP_OF_MODEL = {
    "iPhone6,1": "A7", "iPhone6,2": "A7",         # 5s
    "iPhone7,2": "A8", "iPhone7,1": "A8",         # 6/6+
    "iPhone8,1": "A9", "iPhone8,2": "A9", "iPhone8,4": "A9",   # 6s/SE1
    "iPhone9,1": "A10", "iPhone9,2": "A10", "iPhone9,3": "A10", "iPhone9,4": "A10",  # 7
    "iPhone10,1": "A11", "iPhone10,2": "A11", "iPhone10,3": "A11",  # 8/8+/X
    "iPhone10,4": "A11", "iPhone10,5": "A11", "iPhone10,6": "A11", "iPhone11,2": "A12",
    "iPhone11,4": "A12", "iPhone11,6": "A12", "iPhone11,8": "A12",  # XS/XS Max/XR
    "iPhone12,1": "A13", "iPhone12,3": "A13", "iPhone12,5": "A13",  # 11 family
    "iPhone12,8": "A13",                                     # SE2
    "iPhone13,1": "A14", "iPhone13,2": "A14", "iPhone13,3": "A14", "iPhone13,4": "A14",  # 12
    "iPhone14,2": "A15", "iPhone14,3": "A15", "iPhone14,4": "A15", "iPhone14,5": "A15",  # 13
    "iPhone14,7": "A15", "iPhone14,8": "A15",   # 13 mini/SE3
    "iPhone15,2": "A16", "iPhone15,3": "A16",   # 14 Pro/Pro Max
    "iPhone14,6": "A15", "iPhone14,7": "A15",   # SE3 / 14
    "iPhone14,8": "A15",                         # 14 Plus
    "iPhone15,4": "A16", "iPhone15,5": "A16",   # 15 / 15 Plus
    "iPhone16,1": "A17 Pro", "iPhone16,2": "A17 Pro",  # 15 Pro / Pro Max
    "iPhone17,1": "A18 Pro", "iPhone17,2": "A18 Pro",  # 16 Pro / Pro Max
    "iPhone17,3": "A18", "iPhone17,4": "A18",   # 16 / 16 Plus
    "iPhone17,5": "A18",                         # 16e
    "iPhone18,1": "A19 Pro", "iPhone18,2": "A19 Pro",  # 17 Pro / Pro Max
    "iPhone18,3": "A19",                         # 17
    "iPhone18,4": "A19 Pro",                     # Air (2026)
    "iPhone18,5": "A19",                         # 17e
    "iPhone19,1": "A20 Pro", "iPhone19,2": "A20 Pro",  # 18 Pro / Pro Max
    # iPads (26.x-relevant): 8th gen = A12, 9th gen = A13 (Dopamine 3.0.9 on
    # iPadOS 26.0-26.0.1 per Jailbreak/26.x table), 7th gen = A10 (palera1n)
    "iPad7,11": "A10", "iPad7,12": "A10",      # iPad 7th gen (A10)
    "iPad11,6": "A12", "iPad11,7": "A12",      # iPad 8th gen (A12)
    "iPad12,1": "A13", "iPad12,2": "A13",      # iPad 9th gen (A13)
    "iPad11,1": "A12", "iPad11,2": "A12",      # iPad mini 5th gen (A12)
    "iPad11,3": "A12", "iPad11,4": "A12",      # iPad Air 3rd gen (A12)
}

CHECKM8_CHIPS = {"A7", "A8", "A9", "A10", "A11"}

# usbliter8 (Paradigm Shift, 2026-06-18): DWC2 USB DMA pointer underflow in
# SecureROM (DART bypass on these chips). A12/A13 + S4/S5. Tethered; needs a
# physical RP2350 board (Waveshare RP2350 USB-A, Pico 2, TINY2350...) because
# the race cannot be hit from a normal PC USB stack. SEP untouched.
USBLITER8_CHIPS = {"A12", "A13"}

def _ios_str(v):
    """Lossless iOS version display: 18.71 -> '18.7.1'; 16.61 -> '16.6.1';
    26.0 -> '26.0'; 26.01 -> '26.0.1'; 14.8 -> '14.8'; 17.7 -> '17.7'."""
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    if "." not in s:
        return f"{s}.0"
    major, minor = s.split(".", 1)
    if len(minor) == 2 and minor[1] != "0":
        # two nonzero digits: split into minor.patch (18.71 -> 18.7.1)
        return f"{major}.{minor[0]}.{minor[1]}"
    return f"{major}.{minor}"


# chip range inclusive; ios range inclusive; kind: jailbreak|trollstore
JAILBREAKS = [
    {"chips": (12, 14), "ios": (12.0, 13.5), "tool": "unc0ver / Chimera", "kind": "jailbreak"},
    {"chips": (12, 14), "ios": (14.0, 14.8), "tool": "unc0ver / Taurine (14.0-14.4)", "kind": "jailbreak"},
    {"chips": (8, 11), "ios": (12.0, 14.81), "tool": "checkra1n (checkm8 PC route; A11 needs BPR skip)", "kind": "jailbreak"},
    {"chips": (8, 14), "ios": (13.0, 13.7), "tool": "Odyssey (13.0-13.7)", "kind": "jailbreak"},
    {"chips": (12, 16), "ios": (15.0, 15.41), "tool": "XinaA15 (15.0-15.4.1)", "kind": "jailbreak"},
    {"chips": (8, 11), "ios": (15.0, 15.86), "tool": "meowbrek2 (arm64 15.0-15.8.6)", "kind": "jailbreak"},
    {"chips": (9, 11), "ios": (15.0, 15.82), "tool": "nekoJB rootful (A9-A11 15.0-15.8.2)", "kind": "jailbreak"},
    {"chips": (12, 16), "ios": (16.0, 16.61), "tool": "Dopamine / Serotonin (16.0-16.6.1; Serotonin = TrollStore semi-JB)", "kind": "jailbreak"},
    {"chips": (12, 16), "ios": (16.5, 16.61), "tool": "NathanLR (16.5.1-16.6.1 + 16.7RC + 17.0)", "kind": "jailbreak"},
    {"chips": (8, 11), "ios": (16.0, 16.61), "tool": "Def1nit3lyN0tAJa1lbr3akTool (arm64 16.0-16.6.1)", "kind": "jailbreak"},
    {"chips": (12, 16), "ios": (15.0, 16.61), "tool": "Dopamine / Dopamine 2 (kfd on 16.0-16.6.1)", "kind": "jailbreak"},
    {"chips": (12, 16), "ios": (14.0, 16.61), "tool": "TrollStore (install-only, no JB)", "kind": "trollstore"},
    {"chips": (9, 11), "ios": (15.0, 18.70), "tool": "palera1n (rootless, SEP-limited; checkm8 base)", "kind": "jailbreak"},
    {"chips": (8, 11), "ios": (15.0, 18.70), "tool": "palera1n-roothide (detection-evasion fork; 15-18, passcode-compatible)", "kind": "jailbreak"},
    {"chips": (12, 13), "ios": (15.0, 18.71), "tool": "Dopamine 3 (momentarius; 26.0-26.0.1 too)", "kind": "jailbreak"},
    {"chips": (12, 13), "ios": (26.0, 26.01), "tool": "Dopamine 3 (momentarius PPL bypass)", "kind": "jailbreak"},
    {"chips": (14, 16), "ios": (15.0, 16.61), "tool": "Dopamine 2 (kfd; A14+ to 16.5)", "kind": "jailbreak"},
    {"chips": (14, 17), "ios": (15.0, 17.31), "tool": "Dopamine 3 (Titan SPTM + ClearSword; A14-A17 Pro/M1/M2)", "kind": "jailbreak"},
    {"chips": (9, 11), "ios": (16.7, 18.71), "tool": "Dopamine 3 (DarkSword arm64 window)", "kind": "jailbreak"},
    {"chips": (8, 11), "ios": (16.0, 17.20), "tool": "bakera1n (checkm8/PongoOS, dev-oriented)", "kind": "jailbreak"},
]

CHIP_RANK = {f"A{i}": i for i in range(7, 21)}
CHIP_RANK["A17 Pro"] = 17
CHIP_RANK["A18 Pro"] = 18
CHIP_RANK["A19 Pro"] = 19
CHIP_RANK["A20 Pro"] = 20

KNOWN_DEVICES = {
    "iPhone11,8": ("iPhone XR", "A12"),
    "iPhone12,1": ("iPhone 11", "A13"),
    "iPhone9,1": ("iPhone 7", "A10"),
    "iPhone10,3": ("iPhone X", "A11"),
    "iPhone12,3": ("iPhone 11 Pro", "A13"),
    "iPhone12,5": ("iPhone 11 Pro Max", "A13"),
    "iPhone12,8": ("iPhone SE 2", "A13"),
    "iPhone13,1": ("iPhone 12 mini", "A14"),
    "iPhone13,2": ("iPhone 12", "A14"),
    "iPhone13,3": ("iPhone 12 Pro Max", "A14"),
    "iPhone13,4": ("iPhone 12 Pro", "A14"),
    "iPhone14,2": ("iPhone 13 Pro", "A15"),
    "iPhone14,3": ("iPhone 13 Pro Max", "A15"),
    "iPhone14,4": ("iPhone 13 mini", "A15"),
    "iPhone14,5": ("iPhone 13", "A15"),
    "iPhone14,6": ("iPhone SE 3", "A15"),
    "iPhone14,7": ("iPhone 14", "A15"),
    "iPhone14,8": ("iPhone 14 Plus", "A15"),
    "iPhone15,2": ("iPhone 14 Pro", "A16"),
    "iPhone15,3": ("iPhone 14 Pro Max", "A16"),
    "iPhone15,4": ("iPhone 15", "A16"),
    "iPhone15,5": ("iPhone 15 Plus", "A16"),
    "iPhone16,1": ("iPhone 15 Pro", "A17 Pro"),
    "iPhone16,2": ("iPhone 15 Pro Max", "A17 Pro"),
    "iPhone17,1": ("iPhone 16 Pro", "A18 Pro"),
    "iPhone17,2": ("iPhone 16 Pro Max", "A18 Pro"),
    "iPhone17,3": ("iPhone 16", "A18"),
    "iPhone17,4": ("iPhone 16 Plus", "A18"),
    "iPhone17,5": ("iPhone 16e", "A18"),
    "iPhone18,1": ("iPhone 17 Pro", "A19 Pro"),
    "iPhone18,2": ("iPhone 17 Pro Max", "A19 Pro"),
    "iPhone18,3": ("iPhone 17", "A19"),
    "iPhone18,4": ("iPhone Air", "A19 Pro"),
    "iPhone18,5": ("iPhone 17e", "A19"),
    "iPhone19,1": ("iPhone 18 Pro", "A20 Pro"),
    "iPhone19,2": ("iPhone 18 Pro Max", "A20 Pro"),
    "iPad7,11": ("iPad 7th gen", "A10"),
    "iPad7,12": ("iPad 7th gen", "A10"),
    "iPad11,6": ("iPad 8th gen", "A12"),
    "iPad11,7": ("iPad 8th gen", "A12"),
    "iPad12,1": ("iPad 9th gen", "A13"),
    "iPad12,2": ("iPad 9th gen", "A13"),
    "iPad11,1": ("iPad mini 5", "A12"),
    "iPad11,2": ("iPad mini 5", "A12"),
    "iPad11,3": ("iPad Air 3", "A12"),
    "iPad11,4": ("iPad Air 3", "A12"),
}

# Named targets: one-command profiles for specific devices/eras
PROFILES = {
    "iphone11": {
        "name": "iPhone 11 family (A13)",
        "models": ["iPhone12,1", "iPhone12,3", "iPhone12,5", "iPhone12,8"],
        "chip": "A13",
        "bfu": "usbliter8 (2026-06-18): bootrom PWN DFU via RP2350 - identity + "
               "iBoot/bootrom control in any state; SEP untouched (see README "
               "usbliter8 flow for ramdisk extraction). Identity-only fallback: "
               "acquire bfu (serial/UDID/state).",
        "afu": "logical suite + encrypted backup (keychain needs passcode), or "
               "usbliter8 bootrom flow for a full filesystem pull.",
    },
    "ios11era": {
        "name": "iOS 11-era devices (A9-A11: 6s / 7 / 8 / X)",
        "models": [
            "iPhone8,1", "iPhone8,2", "iPhone8,4",
            "iPhone9,1", "iPhone9,2", "iPhone9,3", "iPhone9,4",
            "iPhone10,1", "iPhone10,2", "iPhone10,3",
            "iPhone10,4", "iPhone10,5", "iPhone10,6",
        ],
        "chip": "A9-A11",
        "bfu": "checkm8 eligible: acquire bfu --chip A10 + DFU + gaster/ipwndfu "
               "for iBoot/AES/BFU-partial.",
        "afu": "jailbreak windows per iOS version (unc0ver up to 14.x, "
               "checkra1n/palera1n 15-17) -> full filesystem via acquire jailbroken.",
    },
}


def profile_info(name):
    """Return (key, profile) for a named target profile."""
    key = name.strip().lower().replace("-", "").replace(" ", "").replace("_", "")
    for k, v in PROFILES.items():
        if k == key or k.replace("era", "era ") == key:
            return k, v
    return None, None


def _ver_tuple(ver):
    """'16.6.1' -> (16, 6, 1); float-tolerant."""
    try:
        return tuple(int(p) for p in str(ver).split(".")[:3] + ["0", "0"][: 3 - len(str(ver).split("."))])
    except (ValueError, TypeError):
        return (0,)


def _in_range(ios, lo, hi):
    lo_t, hi_t = _ver_tuple(lo), _ver_tuple(hi)
    v = _ver_tuple(ios)
    return lo_t <= v <= hi_t


def chip_for(device_class, model_number=None):
    if device_class in CHIP_OF_MODEL:
        return CHIP_OF_MODEL[device_class]
    return None


def recommend(chip, ios):
    """Return list of extraction steps for a chip+iOS combo (best first)."""
    if not chip:
        return ["unknown chip: verify hardware manually, assume logical-only until confirmed"]
    rank = CHIP_RANK.get(chip.upper(), 0)
    steps = ["logical: pairing + backup + AFC (always available AFU)"]
    if rank and rank <= 11:
        steps.insert(
            0,
            "checkm8 (bootrom): BFU-partial + full FS possible, any iOS; "
            "tools: gaster / ipwndfu lineage / palera1n (A8-A11); "
            "SEP keybag path on A10/T2 via Blackbird (PongoOS sep pwn) - "
            "see `opensleuth silicon`",
        )
    if chip.upper() in USBLITER8_CHIPS:
        steps.insert(
            0,
            "usbliter8 (bootrom, 2026-06-18): PWN DFU on A12/A13, any iOS incl. "
            "BFU-partial; tethered - needs RP2350 board (Waveshare RP2350 USB-A / "
            "Pico 2), DCIM->DFU entry, then usbliter8ctl demote/boot raw iBoot "
            "(iBoot proxying / ramdisk flow as with checkm8). SEP untouched.",
        )
    for jb in JAILBREAKS:
        if jb["chips"][0] <= rank <= jb["chips"][1] and _in_range(ios, jb["ios"][0], jb["ios"][1]):
            prefix = "jailbreak" if jb["kind"] == "jailbreak" else "side-load"
            steps.append(f"{prefix}: {jb['tool']} (iOS {_ios_str(jb['ios'][0])}-{_ios_str(jb['ios'][1])})")
    if not any("checkm8" in s or "usbliter8" in s or "jailbreak" in s for s in steps):
        steps.append("no public kernel/bootrom route for this chip+iOS: logical-only")
    if chip not in CHECKM8_CHIPS and chip.upper() not in USBLITER8_CHIPS:
        steps.append("BFU (locked) on this chip: no public route, any iOS")
    elif chip.upper() in USBLITER8_CHIPS:
        steps.append("BFU (locked): usbliter8 covers DFU/bootrom; SEP-gated user data "
                     "still needs AFU or known passcode style recovery via ramdisk")
    return steps


def render(chip, ios, device_class=None, product_version=None):
    out = []
    if device_class:
        out.append(f"device: {device_class} (chip {chip})")
    if product_version:
        out.append(f"iOS: {product_version}")
    for i, s in enumerate(recommend(chip, ios), 1):
        out.append(f"  {i}. {s}")
    return "\n".join(out)