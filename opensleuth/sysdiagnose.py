"""Sysdiagnose analyzer: inventory + key evidence extraction.

A sysdiagnose (Settings > Privacy > Analytics > the spinner, or
hold Volume-Down+Power+Side) is a ~1-4GB gzipped tarball of hundreds of
diagnostic files - the single richest artifact an examiner can obtain
from a cooperating (unlocked) device WITHOUT any exploit. It contains
logs, power/log analytics plists, network reports, WiFi/GPS state,
app usage stats, and more.

This module inventories the extracted bundle and surfaces high-value
files: location hints, network usage, app usage, diagnostics logs.

Honesty: layout varies by iOS version; missing files yield empty rows.
"""

from __future__ import annotations

import plistlib
import re
import tarfile
from pathlib import Path
from typing import Any

HIGH_VALUE = [
    (re.compile(r"(Accessibility|assistivetouch)", re.I), "accessibility"),
    (re.compile(r"(AppUsage|app_usage|ScreenTime)", re.I), "app-usage"),
    (re.compile(r"(location|Location|GPS)", re.I), "location"),
    (re.compile(r"(WiFi|wifi|network_usage|NetworkUsage)", re.I), "network"),
    (re.compile(r"(power|battery|PowerLog)", re.I), "power/battery"),
    (re.compile(r"(cellular|Carrier|baseband)", re.I), "cellular"),
    (re.compile(r"(logs/|log_archive|Diagnostic|diagnostic)", re.I), "diagnostics"),
    (re.compile(r"(system_version|SysProfile|SPCommands)", re.I), "device-info"),
    (re.compile(r"(bluetooth|Bluetooth)", re.I), "bluetooth"),
    (re.compile(r"(notifications|Notification)", re.I), "notifications"),
    (re.compile(r"(specialized/|wireless)", re.I), "wireless"),
]


def extract(tarball: str | Path, out: str | Path, limit: int | None = None) -> dict[str, Any]:
    """Extract a sysdiagnose .tar.gz (already decrypted by the device)."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    t = str(tarball)
    with tarfile.open(t, "r:*") as tf:
        members = tf.getmembers()
        if limit:
            members = members[:limit]
        tf.extractall(out, members=members, filter="data")
    return {"tarball": t, "out": str(out), "files": len(members)}


def inventory(root: str | Path) -> dict[str, Any]:
    root = Path(root)
    files = []
    if root.exists():
        for f in sorted(root.rglob("*")):
            if f.is_file():
                rel = f.relative_to(root).as_posix()
                files.append({"rel": rel, "size": f.stat().st_size,
                              "category": _category(rel)})
    by_cat: dict[str, list[str]] = {}
    for f in files:
        by_cat.setdefault(f["category"], []).append(f["rel"])
    return {"root": str(root), "total": len(files), "by_category": by_cat,
            "files": files}


def _category(rel: str) -> str:
    for pat, label in HIGH_VALUE:
        if pat.search(rel):
            return label
    return "other"


def parse_app_usage_plist(data: bytes, source: str = "<appusage>") -> list[dict[str, Any]]:
    """Parse ScreenTime/app-usage style plists (device, days, bundles)."""
    try:
        root = plistlib.loads(data)
    except Exception:  # noqa: BLE001
        return []
    rows = []
    for dev in (root.get("devices") or [root]):
        if not isinstance(dev, dict):
            continue
        for day in dev.get("days") or []:
            if not isinstance(day, dict):
                continue
            for app in day.get("apps") or []:
                if not isinstance(app, dict):
                    continue
                rows.append({
                    "source": source,
                    "bundle": app.get("bundleName") or app.get("bundleID"),
                    "usage_seconds": app.get("totalTimeUsage") or app.get("usageSeconds"),
                    "day": day.get("date") or day.get("day"),
                    "launches": app.get("launchCount") or app.get("numberOfLaunches"),
                })
    return rows


def render_inventory(inv: dict[str, Any]) -> str:
    lines = [f"sysdiagnose inventory: {inv['total']} files ({inv['root']})", ""]
    for cat in sorted(inv["by_category"], key=lambda c: -len(inv["by_category"][c])):
        rels = inv["by_category"][cat]
        lines.append(f"  {cat:<14} {len(rels):>4} files")
        for r in rels[:4]:
            lines.append(f"      {r}")
        if len(rels) > 4:
            lines.append(f"      ... {len(rels) - 4} more")
    return "\n".join(lines)