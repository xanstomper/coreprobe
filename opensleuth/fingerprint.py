"""Device fingerprinting with provenance: value + source + confidence.

The standard: every device property CoreProbe states must record WHERE it
came from, so an investigator can distinguish observed facts from heuristics.

Confidence levels:
  Observed   - read directly from the device/handshake (lockdown keys, USB
               descriptors, PWND serial markers)
  Inferred   - derived from an observed value via a table (ProductType->chip)
  Heuristic  - best-effort guess (serial-prefix chip hints)
  Unknown    - not determinable in the current state

The fingerprint feeds the acquisition planner and the session journal
(FingerprintRecorded event).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional

from .matrix import KNOWN_DEVICES, chip_for
from .usb import chip_from_serial, chip_from_irecovery, usb_state

CONF_LEVELS = ("Observed", "Inferred", "Heuristic", "Unknown")


@dataclass
class Property:
    value: Any
    source: str
    confidence: str = "Unknown"

    def __post_init__(self) -> None:
        if self.confidence not in CONF_LEVELS:
            raise ValueError(f"invalid confidence {self.confidence!r}")

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "source": self.source,
                "confidence": self.confidence}


@dataclass
class Fingerprint:
    properties: dict[str, Property] = field(default_factory=dict)

    def set(self, name: str, value: Any, source: str,
            confidence: str = "Unknown") -> None:
        self.properties[name] = Property(value, source, confidence)

    def get(self, name: str) -> Optional[Property]:
        return self.properties.get(name)

    def value(self, name: str) -> Any:
        p = self.properties.get(name)
        return p.value if p else None

    def to_dict(self) -> dict[str, dict[str, Any]]:
        return {k: p.to_dict() for k, p in self.properties.items()}

    # convenience accessors used by the planner
    @property
    def chip(self) -> str:
        return str(self.value("chip") or "")

    @property
    def ios(self) -> str:
        return str(self.value("ios") or "")

    @property
    def state(self) -> str:
        return str(self.value("state") or "")


def _lockdown_info(timeout: int = 20) -> dict[str, str]:
    try:
        p = subprocess.run(["ideviceinfo"], capture_output=True, text=True,
                           timeout=timeout)
        if p.returncode != 0:
            return {}
        info = {}
        for line in p.stdout.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                info[k.strip()] = v.strip()
        return info
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}


def fingerprint_device() -> Fingerprint:
    """Build the fingerprint of whatever is attached right now."""
    fp = Fingerprint()
    snap = usb_state()
    devs = snap.get("devices", [])
    fp.set("present", bool(devs), "sysfs /sys/bus/usb/devices", "Observed")

    if not devs:
        fp.set("state", "absent", "no Apple device on USB", "Observed")
        return fp

    booted = next((d for d in devs if d.get("mode") == "normal"), devs[0])
    serial = booted.get("serial") or ""
    mode = booted.get("mode") or "normal"

    fp.set("usb_mode", mode, "sysfs USB PID/product string", "Observed")
    fp.set("usb_serial", serial, "sysfs serial attribute", "Observed")
    fp.set("usb_product_id", booted.get("product_id") or "",
           "sysfs idProduct", "Observed")

    # lock state / acquisition state
    if mode == "dfu":
        fp.set("state", "DFU", "USB PID 0x1227", "Observed")
    elif mode == "pwned-dfu":
        fp.set("state", "pwned-dfu", "PWND marker in serial", "Observed")
        pwnd_by = ("usbliter8" if snap.get("pwnd_usbliter8")
                   else "checkm8" if (snap.get("pwnd_checkm8") or snap.get("pwnd"))
                   else "unknown")
        fp.set("pwnd_by", pwnd_by, "PWND serial marker", "Observed")
    elif mode == "recovery":
        fp.set("state", "recovery", "USB PID 0x1281", "Observed")
    else:
        info = _lockdown_info()
        if info:
            fp.set("state", "AFU", "lockdown answers (paired+unlocked)",
                  "Observed")
        else:
            fp.set("state", "BFU", "booted but lockdown unreachable "
                  "(locked or unpaired)", "Inferred")

    # identity from lockdown when available
    info = _lockdown_info() if mode == "normal" else {}
    if info.get("ProductType"):
        fp.set("product_type", info["ProductType"], "lockdown ProductType",
              "Observed")
        model = KNOWN_DEVICES.get(info["ProductType"],
                                  (info["ProductType"],))[0]
        fp.set("model", model, "KNOWN_DEVICES table lookup", "Inferred")
    if info.get("ProductVersion"):
        fp.set("ios", info["ProductVersion"], "lockdown ProductVersion",
              "Observed")
    if info.get("BuildVersion"):
        fp.set("build", info["BuildVersion"], "lockdown BuildVersion",
              "Observed")
    if info.get("UniqueDeviceID"):
        fp.set("udid", info["UniqueDeviceID"], "lockdown UniqueDeviceID",
              "Observed")

    # chip: ProductType > boardconfig (recovery) > serial hint
    pt = fp.value("product_type")
    if pt:
        chip = chip_for(str(pt))
        if chip:
            fp.set("chip", chip, "ProductType -> CHIP_OF_MODEL table",
                  "Inferred")
    if not fp.get("chip"):
        bc_chip = chip_from_irecovery()
        if bc_chip:
            fp.set("chip", bc_chip, "irecovery getenv boardconfig -> table",
                  "Observed")
    if not fp.get("chip"):
        s_chip = chip_from_serial(serial)
        if s_chip:
            fp.set("chip", s_chip, "serial-prefix hint table", "Heuristic")
    if not fp.get("chip"):
        fp.set("chip", "", "not determinable in this state", "Unknown")

    return fp


def render(fp: Fingerprint) -> str:
    lines = ["", "DEVICE FINGERPRINT", "=" * 56]
    order = ["present", "model", "product_type", "chip", "ios", "build",
             "udid", "state", "pwnd_by", "usb_mode", "usb_serial",
             "usb_product_id"]
    for name in order:
        p = fp.get(name)
        if p is None:
            continue
        lines.append(f"  {name:16s}: {str(p.value)!s:34s}"
                     f" [{p.confidence}] via {p.source}")
    extra = [k for k in fp.properties if k not in order]
    for name in extra:
        p = fp.properties[name]
        lines.append(f"  {name:16s}: {str(p.value)!s:34s}"
                     f" [{p.confidence}] via {p.source}")
    lines.append("=" * 56)
    return "\n".join(lines)
