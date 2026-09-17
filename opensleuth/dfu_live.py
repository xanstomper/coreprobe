"""Live DFU transport over plain PC USB - the picoless A12+ research path.

usbliter8 needs an RP2350 because its bug lives in the DWC2 *device*
controller timing, which a PC host stack cannot reproduce. But the
checkm8-class bugs (length/state confusion in the DFU *protocol* layer)
are host-reachable: they are triggered by control-transfer requests the
host sends, not by device-side timing. Hunting those on an A12/A13
SecureROM is the one genuine picoless route to new capability, and this
module is the instrument: a pyusb transport that speaks DFU-class
requests to a device in DFU mode and detects death/hang, built to feed
`opensleuth campaign run --live`.

Safety model (absolute):
  - Target ONLY Apple DFU mode (PID 0x1227). Normal-mode and recovery
    devices are REFUSED - sending control requests to a live iPhone is
    how you brick research hardware.
  - Only the DFU request class (0x21 host->dev, 0xA1 dev->host) is
    forwarded; everything else is dropped with a warning.
  - Data stages are only attached to DNLOAD (the only DFU request that
    carries one), capped at 4 KiB, zero-filled. Every other OUT request
    is sent with no data stage.
  - Worst case on a DFU device is a hang: re-enter DFU with the button
    sequence. Nothing is written to NAND from DFU mode without a signed
    image, so this cannot brick.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

APPLE_VID = 0x05AC
DFU_PID = 0x1227          # SecureROM DFU (all eras incl. A12/A13)
RECOVERY_PID = 0x1281     # iBoot recovery - not a fuzz target

DFU_OUT = 0x21            # host -> device, class, interface
DFU_IN = 0xA1             # device -> host, class, interface

DNLOAD = 0x01
UPLOAD = 0x02
DETACH = 0x00
GETSTATUS = 0x03
CLRSTATUS = 0x04
GETSTATE = 0x05
ABORT = 0x06

REQ_NAMES = {0x00: "DETACH", 0x01: "DNLOAD", 0x02: "UPLOAD",
             0x03: "GETSTATUS", 0x04: "CLRSTATUS", 0x05: "GETSTATE",
             0x06: "ABORT"}

# Maximum zero-fill data stage for DNLOAD mutations (4 KiB).
MAX_DNLOAD_DATA = 0x1000


def find_dfu_device() -> Optional[Any]:
    """Find the Apple device currently in DFU mode (PID 0x1227)."""
    try:
        import usb.core
        return usb.core.find(idVendor=APPLE_VID, idProduct=DFU_PID)
    except Exception:  # noqa: BLE001 - no pyusb / no access -> not found
        return None


def find_apple_devices() -> list[Any]:
    """All Apple USB devices (for status display / refusing non-DFU)."""
    try:
        import usb.core
        return list(usb.core.find(find_all=True, idVendor=APPLE_VID) or [])
    except Exception:  # noqa: BLE001
        return []


def describe(dev: Any) -> str:
    """Human-readable one-liner for a pyusb device."""
    try:
        m = dev.manufacturer or ""
        p = dev.product or ""
        pid = f"{dev.idProduct:#06x}" if dev.idProduct is not None else "?"
        sn = dev.serial_number or ""
        return f"{m} {p} pid={pid} sn={sn}".strip()
    except Exception:  # noqa: BLE001
        return "<device>"


class DfuTransport:
    """pyusb transport matching the dfufuzz interface.

    Interface used by run_fuzz():
        ctrl_transfer(bmRequestType, bRequest, wValue, wIndex,
                      wLength, timeout_ms) -> bytes
        alive() -> bool
    """

    def __init__(self, dev: Optional[Any] = None,
                 log: Callable[[str], None] = print) -> None:
        self.log = log
        self.dev = dev if dev is not None else find_dfu_device()
        if self.dev is None:
            raise RuntimeError(
                "no Apple device in DFU mode (pid 0x1227) found on USB; "
                "enter DFU: vol-up, vol-down, hold power 10s, "
                "then power+vol-down 5s")
        pid = getattr(self.dev, "idProduct", None)
        if pid != DFU_PID:
            raise RuntimeError(
                f"refusing non-DFU Apple device (pid {pid:#06x}); "
                f"only pid {DFU_PID:#06x} (DFU mode) is fuzzable safely "
                f"- found: {describe(self.dev)}")
        self._claimed = False

    # -- dfufuzz interface ------------------------------------------------
    def alive(self) -> bool:
        """Device still present and still in DFU? Rebinds on re-entry so
        a fuzz hunt can resume across deaths (the device re-enumerates
        when the examiner re-enters DFU)."""
        if self.dev is None:
            return False
        try:
            cur = find_dfu_device()
            if cur is None:
                return False
            # prefer the same physical device; rebind if a fresh handle
            # appeared (re-entry) - same VID/PID means it is our device
            if (cur.bus, cur.address) != (self.dev.bus, self.dev.address):
                self.dev = cur
            return True
        except Exception:  # noqa: BLE001
            return False

    def ctrl_transfer(self, bmRequestType: int, bRequest: int,
                      wValue: int = 0, wIndex: int = 0,
                      wLength: int = 0, timeout_ms: int = 500) -> bytes:
        """One DFU-class control transfer (protocol-correct, safe)."""
        if self.dev is None:
            raise RuntimeError("device gone")
        # Only DFU class requests travel; refuse anything else outright.
        if bmRequestType not in (DFU_OUT, DFU_IN):
            self.log(f"[skip] non-DFU bmRequestType {bmRequestType:#04x}")
            return b""
        if bmRequestType == DFU_IN:
            # device -> host: read wLength bytes
            return bytes(self.dev.ctrl_transfer(
                bmRequestType, bRequest, wValue, wIndex, wLength,
                timeout=timeout_ms))
        # host -> device
        data: bytes = b""
        if bRequest == DNLOAD:
            # the only DFU request with a data stage; cap the fill so a
            # 0xFFFF boundary mutation cannot become a 64 KiB write
            n = min(wLength, MAX_DNLOAD_DATA)
            data = b"\x00" * n
            self.log(f"[dnload] wLength={wLength:#06x} -> {n:#06x} B zero fill")
        return bytes(self.dev.ctrl_transfer(
            bmRequestType, bRequest, wValue, wIndex, data,
            timeout=timeout_ms))

    # -- status / verify ---------------------------------------------------
    def get_status(self) -> dict[str, Any]:
        """GETSTATUS (6 bytes) + GETSTATE (1 byte) parse."""
        out: dict[str, Any] = {}
        try:
            st = bytes(self.dev.ctrl_transfer(DFU_IN, GETSTATUS, 0, 0, 6,
                                              timeout=1000))
            if len(st) >= 6:
                out["status"] = st[0]
                out["poll_timeout"] = int.from_bytes(st[1:4], "little")
                out["state"] = st[4]
                out["string_idx"] = st[5]
        except Exception as exc:  # noqa: BLE001
            out["status_error"] = str(exc)
        try:
            st = bytes(self.dev.ctrl_transfer(DFU_IN, GETSTATE, 0, 0, 1,
                                              timeout=1000))
            if st:
                out["dfu_state"] = st[0]
        except Exception as exc:  # noqa: BLE001
            out["state_error"] = str(exc)
        return out

    def verify(self) -> dict[str, Any]:
        """Non-mutating check: device present, DFU mode, speaks DFU."""
        return {"device": describe(self.dev),
                "bus": getattr(self.dev, "bus", None),
                "address": getattr(self.dev, "address", None),
                "dfu_mode": True, **self.get_status()}


def render_verify(v: dict[str, Any]) -> str:
    lines = ["live DFU device check", "=" * 60]
    lines.append(f"device:   {v.get('device')}")
    lines.append(f"bus/addr: {v.get('bus')}/{v.get('address')}")
    lines.append(f"mode:     {'DFU (pid 0x1227) - fuzzable' if v.get('dfu_mode')
                             else 'NOT DFU - refused'}")
    if "status" in v:
        lines.append(f"GETSTATUS: status={v['status']} state={v['state']} "
                     f"poll={v['poll_timeout']}ms")
    if "dfu_state" in v:
        lines.append(f"GETSTATE:  state={v['dfu_state']}")
    for k in ("status_error", "state_error"):
        if k in v:
            lines.append(f"  ({k}: {v[k]})")
    lines.append("-" * 60)
    lines.append("next: campaign run <id> --capture <usbmon.txt> --live "
                 "--confirm-live-dfu")
    return "\n".join(lines)


def wait_for_reentry(timeout_s: float, poll_s: float = 1.0,
                     log: Callable[[str], None] = print) -> bool:
    """Block until an Apple DFU device (pid 0x1227) reappears on USB.

    Used after a fuzz-induced death: the examiner re-enters DFU with the
    button sequence and the campaign resumes. Returns True if the device
    came back within timeout_s, False otherwise.
    """
    import time
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        dev = find_dfu_device()
        if dev is not None:
            return True
        time.sleep(poll_s)
    return False