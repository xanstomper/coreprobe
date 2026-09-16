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
