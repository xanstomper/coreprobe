"""Open-source iOS forensic toolchain catalog.

Every tool listed is a real, public, open-source project relevant to iOS
forensic acquisition and triage. `opensleuth tools` reports which ones are
installed on the examiner workstation (live detection via PATH).

Categories:
  acquisition   - device access, backup, mounting, recovery
  jailbreak     - acquisition-enabling public exploit tooling
  restore       - firmware / restore engines (IPSW, img4, futurerestore)
  parsing       - artifact / media / backup parsers
  analysis      - reporting, metadata, pattern-of-life
"""

from __future__ import annotations

import shutil
from typing import Any

TOOLS: list[dict[str, Any]] = [
    # --------------------------------------------------------- acquisition
    {"name": "libimobiledevice", "cat": "acquisition", "oss": True, "detect": "ideviceinfo",
     "url": "https://github.com/libimobiledevice/libimobiledevice",
     "purpose": "USB services layer (ideviceinfo/backup2/pair/installer) - the base stack."},
    {"name": "pymobiledevice3", "cat": "acquisition", "oss": True, "detect": "pymobiledevice3",
     "url": "https://github.com/doronz88/pymobiledevice3",
     "purpose": "Python device stack: usbmux, lockdown, crash reports, app list, mounter."},
    {"name": "ifuse", "cat": "acquisition", "oss": True, "detect": "ifuse",
     "url": "https://github.com/libimobiledevice/ifuse",
     "purpose": "FUSE mount of AFC (DCIM/Downloads) for media extraction."},
    {"name": "usbmuxd", "cat": "acquisition", "oss": True, "detect": "usbmuxd",
     "url": "https://github.com/libimobiledevice/usbmuxd",
     "purpose": "USB multiplexing daemon every acquisition path depends on."},
    {"name": "irecovery", "cat": "acquisition", "oss": True, "detect": "irecovery",
     "url": "https://github.com/libimobiledevice/irecovery",
     "purpose": "Recovery/DFU mode shell: enter recovery, query, load images."},
    {"name": "pyiosbackup", "cat": "acquisition", "oss": True, "detect": "pyiosbackup",
     "url": "https://github.com/avivyar/pyiosbackup",
     "purpose": "Encrypted/local backup decryption - the keychain unpack used by `opensleuth acquire --unback`."},
    {"name": "ipwndfu", "cat": "acquisition", "oss": True, "detect": "ipwndfu",
     "url": "https://github.com/axi0mX/ipwndfu",
     "purpose": "Legacy A4-era bootrom pwn + early checkm8 research harness."},
    # ---------------------------------------------------------- jailbreak
    {"name": "checkra1n", "cat": "jailbreak", "oss": True, "detect": "checkra1n",
     "url": "https://checkra.in",
     "purpose": "checkm8 bootrom exploit GUI - A7-A11, iOS 12-14.8.1 (+ partial newer)."},
    {"name": "palera1n", "cat": "jailbreak", "oss": True, "detect": "palera1n",
     "url": "https://github.com/palera1n/palera1n",
     "purpose": "checkm8 CLI rootless JB - A8-A11 (and A12+ with passcode restrictions)."},
    {"name": "gaster", "cat": "jailbreak", "oss": True, "detect": "gaster",
     "url": "https://github.com/0x7ff/gaster",
     "purpose": "checkm8 pwn/DFU payloads + custom iBSS for A7-A11."},
    {"name": "usbliter8ctl", "cat": "jailbreak", "oss": True, "detect": "usbliter8ctl",
     "url": "https://github.com/usbliter8/usbliter8",
     "purpose": "A12/A13 DFU command injection + iBoot control (2025) - `opensleuth acquire usbliter8`."},
    {"name": "dopamine", "cat": "jailbreak", "oss": True, "detect": "dopamine",
     "url": "https://github.com/opa334/Dopamine",
     "purpose": "Rootless semi-untethered JB - iOS 15-16.x (A12+ arm64e) + arm64."},
    # ------------------------------------------------------------ restore
    {"name": "futurerestore", "cat": "restore", "oss": True, "detect": "futurerestore",
     "url": "https://github.com/futurerestore/futurerestore",
     "purpose": "Restore engine to unsigned firmware (restore-path research platform)."},
    {"name": "ipsw", "cat": "restore", "oss": True, "detect": "ipsw",
     "url": "https://github.com/blacktop/ipsw",
     "purpose": "IPSW parsing, kernelcache extraction, dyld shared cache tooling."},
    {"name": "img4tool", "cat": "restore", "oss": True, "detect": "img4tool",
     "url": "https://github.com/tihmstar/img4tool",
     "purpose": "IMG4/IM4P parsing for restore-image analysis."},
    # ------------------------------------------------------------ parsing
    {"name": "iLEAPP", "cat": "parsing", "oss": True, "detect": "iLEAPP",
     "url": "https://github.com/abrignoni/iLEAPP",
     "purpose": "iOS Logs Events And Plists Parser - SMS, calls, Safari, locations + 100+ artifacts."},
    {"name": "MEAT", "cat": "parsing", "oss": True, "detect": "MEAT",
     "url": "https://github.com/abrignoni/MEAT",
     "purpose": "Media Evidence Analysis Toolkit - photo/video metadata and timeline."},
    {"name": "APOLLO", "cat": "parsing", "oss": True, "detect": "APOLLO",
     "url": "https://github.com/mac4n6/APOLLO",
     "purpose": "Apple Pattern of Life Lazy Outarder - knowledge-base queries of location/usage."},
    {"name": "ArtEx", "cat": "parsing", "oss": True, "detect": "ArtEx",
     "url": "https://github.com/ehudthelefthand/ArtEx",
     "purpose": "iOS artifact extractor - Messages, contacts, call logs, Safari from backups."},
    {"name": "MVT", "cat": "parsing", "oss": True, "detect": "mvt",
     "url": "https://github.com/mvt-project/mvt",
     "purpose": "Mobile Verification Toolkit - spyware/Pegasus indicators in iOS backups."},
    # ------------------------------------------------------------ analysis
    {"name": "sqlite3", "cat": "analysis", "oss": True, "detect": "sqlite3",
     "url": "https://sqlite.org",
     "purpose": "SQLite CLI - primary artifact DB query surface."},
    {"name": "plutil", "cat": "analysis", "oss": True, "detect": "plutil",
     "url": "https://github.com/nowxploit/plutil",
     "purpose": "Property-list inspection (binary/xml) - prefs, manifests, metadata."},
    {"name": "exiftool", "cat": "analysis", "oss": True, "detect": "exiftool",
     "url": "https://exiftool.org",
     "purpose": "Media EXIF/XMP forensics - GPS, camera, edit history."},
]

CATEGORY_ORDER = ["acquisition", "jailbreak", "restore", "parsing", "analysis"]


def detect() -> list[dict[str, Any]]:
    """TOOLS with live 'installed' flag resolved from PATH."""
    out = []
    for t in TOOLS:
        row = dict(t)
        row["installed"] = shutil.which(t["detect"]) is not None
        out.append(row)
    return out


def summary() -> dict[str, Any]:
    rows = detect()
    inst = sum(1 for r in rows if r["installed"])
    return {
        "total": len(rows),
        "installed": inst,
        "missing": len(rows) - inst,
        "by_category": {c: {"total": sum(1 for r in rows if r["cat"] == c),
                            "installed": sum(1 for r in rows if r["cat"] == c and r["installed"])}
                        for c in CATEGORY_ORDER},
    }


def render_tools(installed_only: bool = False) -> str:
    rows = [r for r in detect() if not installed_only or r["installed"]]
    s = summary()
    lines = [
        f"forensic toolchain: {s['installed']}/{s['total']} installed "
        f"(acq {s['by_category']['acquisition']['installed']}/{s['by_category']['acquisition']['total']}, "
        f"jb {s['by_category']['jailbreak']['installed']}/{s['by_category']['jailbreak']['total']}, "
        f"parse {s['by_category']['parsing']['installed']}/{s['by_category']['parsing']['total']})",
        "",
    ]
    for cat in CATEGORY_ORDER:
        cat_rows = [r for r in rows if r["cat"] == cat]
        if not cat_rows:
            continue
        lines.append(f"--- {cat} ---")
        for r in cat_rows:
            mark = "✓" if r["installed"] else "·"
            oss = "oss" if r["oss"] else "commercial"
            lines.append(f"  {mark} {r['name']:<22} [{oss}] {r['purpose']}")
        lines.append("")
    lines.append("install with:  sudo ./install.sh --with-checkm8-tools  (plus apt/pip per tool)")
    return "\n".join(lines)