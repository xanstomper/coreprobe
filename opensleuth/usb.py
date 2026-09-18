"""USB device discovery + mode classification for Apple iOS devices.

One shared implementation for every bootrom-level flow (bfu / checkm8 /
usbliter8 / probe). Reads /sys/bus/usb/devices; classifies each Apple
device into normal / recovery / dfu / pwned based on USB product strings
and well-known Apple PIDs:

  0x1227 (DFU mode)      SecureROM DFU - the checkm8/usbliter8 target state
  0x1281 (Recovery)      iBoot recovery mode
  serial contains PWND    pwned DFU (gaster 'PWND:[checkm8]' or
                          usbliter8 'PWND:[usbliter8]')
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable, Optional

SYSFS_USB = Path("/sys/bus/usb/devices")
APPLE_VID = "05ac"

# Well-known Apple USB PIDs (hex, no 0x) by mode
DFU_PIDS = {"1227"}           # SecureROM DFU (all eras incl. A12/A13)
RECOVERY_PIDS = {"1281"}      # iBoot recovery
WTF_PIDS = {"1222"}           # WTF (older devices, DFU-adjacent)

PWN_MARKERS = ("PWND:[CHECKM8]", "PWND:[USBLITER8]", "PWND:")

# Apple serial-format first-3-char prefixes -> chip, for chip detection when a
# device is in DFU/Recovery (no lockdown ProductType available). These are the
# well-known, stable 12-char factory serial prefixes by silicon generation.
# Not exhaustive (Apple reuses prefixes across factories), so callers treat
# this as a best-effort narrowing, not ground truth.
SERIAL_CHIP_HINTS = {
    # Only reasonably-specific 3-4 char prefixes. Apple reuses the first few
    # chars across generations, so we match by LONGEST prefix and only list
    # prefixes that are not too generic to be misleading.
    "A4": ("G24", "G32"),
    "A5": ("C39L", "H37"),
    "A6": ("D6", "F4K"),
    "A7": ("F17", "F18"),
    "A8": ("F17W", "F78"),
    "A9": ("C39M", "F2LD", "F22G"),
    "A10": ("C39", "C7G", "DNP", "C3G", "C6KD"),
    "A11": ("C6K", "C6Q", "DNP"),
    "A12": ("C3D", "F17"),
    "A13": ("DNP", "F2L", "C7G"),
}


def chip_from_serial(serial: Optional[str]) -> str:
    """Best-effort chip guess from an Apple USB serial prefix.

    Matches the LONGEST known prefix (later chips share early chars with
    earlier ones, e.g. 'C3' could be a lot of generations). Returns '' when
    too ambiguous to guess, so callers can fall back to boardconfig/irecovery
    or ask the examiner rather than guess wrong and run the wrong route.
    """
    s = (serial or "").upper()
    if not s:
        return ""
    best_len = -1
    best_chip = ""
    for chip, prefixes in SERIAL_CHIP_HINTS.items():
        for p in prefixes:
            if s.startswith(p) and len(p) > best_len:
                best_len = len(p)
                best_chip = chip
    return best_chip


_BOARDCONFIG_CHIP = {
    # iPhone board configs -> chip (reliable, read via irecovery in recovery)
    "d10ap": "A9", "d10apb": "A9", "d10apv": "A9",     # iPhone 6s
    "d11ap": "A9", "d11apb": "A9", "d11apv": "A9",      # iPhone 6s Plus
    "n69ap": "A9", "n69uap": "A9",                        # iPhone SE
    "d20ap": "A10", "d20apb": "A10",                      # iPhone 7
    "d21ap": "A10", "d21apb": "A10",                      # iPhone 7 Plus
    "n71ap": "A10",                                        # iPad 6th gen
    "d22ap": "A11", "d22apb": "A11",                       # iPhone 8
    "d221ap": "A11", "d221apb": "A11",                     # iPhone 8 Plus
    "d321ap": "A11", "d321apb": "A11",                     # iPhone X
    "n115ap": "A11",                                       # iPad 7th gen
    "d331ap": "A12", "d331pap": "A12",                     # iPhone XS
    "d332ap": "A12",                                       # iPhone XS Max
    "n841ap": "A12",                                       # iPhone XR
    "d411ap": "A13", "d411p": "A13",                       # iPhone 11
    "d421ap": "A13",                                       # iPhone 11 Pro
    "d422ap": "A13",                                       # iPhone 11 Pro Max
    "d791ap": "A13",                                       # SE2
    "d3pap": "A12",
}


def chip_from_boardconfig(boardconfig: Optional[str]) -> str:
    """Chip from a recovery-mode iBoot boardconfig (e.g. 'd20ap' -> A10)."""
    return _BOARDCONFIG_CHIP.get((boardconfig or "").lower().strip(), "")


def chip_from_irecovery(sysfs: Path = SYSFS_USB) -> str:
    """If an Apple device is in Recovery, query iBoot boardconfig via irecovery
    and map it to a chip. Returns '' if not determinable."""
    devices = apple_devices(sysfs)
    if not any(d.get("mode") == "recovery" for d in devices):
        return ""
    import subprocess
    try:
        p = subprocess.run(["irecovery", "-q", "-c", "getenv boardconfig"],
                           capture_output=True, text=True, timeout=8)
        bc = (p.stdout or p.stderr).strip().lower().splitlines()
        for line in bc:
            if "=" in line or not line:
                continue
            chip = chip_from_boardconfig(line)
            if chip:
                return chip
        # some builds print the value alone on the last line
        for line in reversed(bc):
            if line and len(line) < 16:
                chip = chip_from_boardconfig(line)
                if chip:
                    return chip
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return ""


def read_attr(dev: Path, name: str) -> Optional[str]:
    try:
        return (dev / name).read_text().strip()
    except OSError:
        return None


def classify(entry: dict[str, Any]) -> str:
    """Classify a USB entry dict (product/serial/product_id keys) into
    normal | recovery | dfu | pwned-dfu | pwned."""
    serial = (entry.get("serial") or "").upper()
    pid = (entry.get("product_id") or "").lower()
    product = (entry.get("product") or "").lower()
    pwnd = any(m in serial for m in PWN_MARKERS)
    if pid in DFU_PIDS or pid in WTF_PIDS or "dfu" in product:
        return "pwned-dfu" if pwnd else "dfu"
    if pid in RECOVERY_PIDS or "recovery" in product:
        return "recovery"
    if pwnd:
        return "pwned"
    return "normal"


def apple_devices(sysfs: Path = SYSFS_USB) -> list[dict[str, Any]]:
    """All Apple devices currently on USB with mode classification.

    Returns entries: {product, manufacturer, serial, product_id, mode,
    sysfs}. Safe on systems without the path (returns []).
    """
    out: list[dict[str, Any]] = []
    try:
        dirs = sorted(p for p in sysfs.iterdir() if p.is_dir())
    except OSError:
        return out
    for d in dirs:
        if read_attr(d, "idVendor") != APPLE_VID:
            continue
        entry = {
            "product": read_attr(d, "product"),
            "manufacturer": read_attr(d, "manufacturer"),
            "serial": read_attr(d, "serial"),
            "product_id": read_attr(d, "idProduct"),
            "sysfs": str(d),
        }
        entry["mode"] = classify(entry)
        out.append(entry)
    return out


def usb_state(sysfs: Path = SYSFS_USB) -> dict[str, Any]:
    """Snapshot summary: devices by mode + flags used by acquisition flows."""
    devices = apple_devices(sysfs)
    modes = [d["mode"] for d in devices]
    return {
        "devices": devices,
        "any": bool(devices),
        "dfu": any(m in ("dfu", "pwned-dfu") for m in modes),
        "recovery": "recovery" in modes,
        "pwnd": any("pwned" in m for m in modes),
        "pwnd_usbliter8": any(
            "PWND:[USBLITER8]" in (d.get("serial") or "").upper() for d in devices
        ),
        "pwnd_checkm8": any(
            "PWND:[CHECKM8]" in (d.get("serial") or "").upper() for d in devices
        ),
    }


def watch_dfu(
    timeout: float = 180.0,
    poll: float = 0.25,
    sysfs: Path = SYSFS_USB,
    on_transition: Optional[Callable[[str, dict], None]] = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Block until an Apple device appears in DFU (PID 1227/1222) or
    timeout. Reports every mode transition through on_transition(ts, entry).

    Used by examiners during the timing-critical button sequence:
    start this BEFORE pressing the DFU combo; it prints the moment the
    device lands in DFU so gaster/usbliter8 can fire immediately.

    Returns the final usb_state() snapshot; 'dfu' key tells success.
    """
    start = clock()
    last_modes: dict[str, str] = {}
    state = usb_state(sysfs)
    while True:
        state = usb_state(sysfs)
        for d in state["devices"]:
            key = d.get("serial") or d.get("product_id") or "?"
            prev = last_modes.get(key)
            if prev != d["mode"]:
                last_modes[key] = d["mode"]
                if on_transition:
                    on_transition(f"{time.strftime('%H:%M:%S')}", d)
        if state["dfu"] or clock() - start >= timeout:
            return state
        sleep(poll)
