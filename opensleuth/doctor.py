"""opensleuth doctor: workstation + device diagnostics.

Checks the full acquisition toolchain, native core, device state, and the
forensic environment - the examiner's pre-case sanity pass.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import forensics


def _tool(name: str, key: str) -> bool:
    return shutil.which(name) is not None


def run() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str = ""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    # python + package
    add("opensleuth package", True, f"python {sys.version.split()[0]} / opensleuth import ok")
    try:
        from . import __version__
        add("version", True, __version__)
    except Exception as exc:  # noqa: BLE001
        add("version", False, str(exc))

    # core acquisition stack
    add("ideviceinfo (libimobiledevice)", _tool("ideviceinfo", "ideviceinfo"))
    add("pymobiledevice3", _tool("pymobiledevice3", "pymobiledevice3"))
    add("ifuse + FUSE", _tool("ifuse", "ifuse") and _tool("fusermount", "fusermount"))
    add("usbmuxd binary", _tool("usbmuxd", "usbmuxd"))
    add("irecovery", _tool("irecovery", "irecovery"))

    # checkm8 / usbliter8 tooling
    add("gaster (checkm8 pwn)", _tool("gaster", "gaster"))
    add("palera1n", _tool("palera1n", "palera1n"))
    add("usbliter8ctl (A12/A13)", _tool("usbliter8ctl", "usbliter8ctl"))

    # native core
    try:
        from . import cxx
        import subprocess as sp
        binary = cxx.binary()
        p = sp.run([str(binary), "selftest"], capture_output=True, text=True, timeout=90)
        add("native core (osleuth_core)", p.returncode == 0, binary.name)
    except Exception as exc:  # noqa: BLE001
        add("native core (osleuth_core)", False, str(exc)[:120])

    # forensic detection from the catalog
    detect = {t["name"]: t["installed"] for t in forensics.detect()}
    core = ["sqlite3", "plutil", "exiftool"]
    add("analysis basics (sqlite3/plutil/exiftool)",
        all(detect.get(c) for c in core), ", ".join(c for c in core if detect.get(c)))
    parsers = ["iLEAPP", "MEAT", "APOLLO", "ArtEx", "MVT"]
    inst = [p for p in parsers if detect.get(p)]
    add("artifact parsers (iLEAPP/MEAT/APOLLO/ArtEx/MVT)", bool(inst),
        ", ".join(inst) or "none installed")

    # device
    try:
        from .usb import usb_state
        snap = usb_state()
        devs = snap.get("devices") or []
        add("device on USB", bool(devs), f"{len(devs)} device(s)" if devs else "none")
        if devs:
            d = devs[0]
            add("DFU/recovery flags", not (snap.get("dfu") or snap.get("recovery")),
                f"dfu={snap.get('dfu')} recovery={snap.get('recovery')} pwnd={snap.get('pwnd')}")
        add("usbmuxd responding", _usbmuxd_alive(), "")
    except Exception as exc:  # noqa: BLE001
        add("device on USB", False, str(exc)[:120])

    # environment
    try:
        st = shutil.disk_usage("/tmp")
        add("scratch space", st.free > 1 << 30, f"{st.free >> 30} GiB free")
    except OSError as exc:
        add("scratch space", False, str(exc))

    ok_count = sum(1 for c in checks if c["ok"])
    return {"checks": checks, "passed": ok_count, "total": len(checks),
            "ready": ok_count == len(checks)}


def _usbmuxd_alive() -> bool:
    try:
        p = subprocess.run(["pymobiledevice3", "usbmux", "list"],
                           capture_output=True, text=True, timeout=15)
        return p.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def render(d: dict[str, Any], json_out: bool = False) -> str:
    if json_out:
        return json.dumps(d, indent=2)
    lines = [f"opensleuth doctor: {d['passed']}/{d['total']} checks passed",
             ""]
    for c in d["checks"]:
        mark = "✓" if c["ok"] else "✗"
        detail = f"  ({c['detail']})" if c.get("detail") else ""
        lines.append(f"  {mark} {c['check']}{detail}")
    lines.append("")
    if d["ready"]:
        lines.append("Workstation is ready for acquisition.")
    else:
        lines.append("Missing items above. Install:  sudo ./install.sh --with-cxx --with-checkm8-tools")
        lines.append("then: pip install --break-system-packages -e . (this repo)")
    return "\n".join(lines)