"""Wireless artifacts: WiFi known networks + Bluetooth connections.

Parses the well-documented preference plists found in backups/pulls:
  com.apple.wifi.plist (managed via iCloud sync or backups)
    KnownNetworks dict: SSID, BSSID, joined dates, security
  com.apple.bluetooth.plist
    paired/recent devices
Location: Significant Locations plists are covered by artifacts.plists;
this module keeps network/bt artifacts together.

Honesty: key layouts drift across iOS versions; missing keys yield empty
rows, never invented ones.
"""

from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any


def parse_wifi_plist(data: bytes, source: str = "<wifi>") -> list[dict[str, Any]]:
    try:
        root = plistlib.loads(data)
    except Exception:  # noqa: BLE001
        return []
    nets = root.get("KnownNetworks") or {}
    rows = []
    for nid, info in nets.items():
        if not isinstance(info, dict):
            continue
        raw_ssid = info.get("SSID") or info.get("SSIDString")
        if isinstance(raw_ssid, bytes):
            try:
                raw_ssid = raw_ssid.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                raw_ssid = raw_ssid.hex()
        ssid = raw_ssid if isinstance(raw_ssid, str) and raw_ssid else None
        # joined timestamps appear under various keys
        joined = info.get("AddedAt") or info.get("__OSSpecific__", {}).get(
            "JOINED") if isinstance(info.get("__OSSpecific__"), dict) else None
        rows.append({
            "source": source,
            "network_id": str(nid)[:80],
            "ssid": ssid,
            "bssid": info.get("BSSID"),
            "security": info.get("SecurityMode") or info.get("SupportedSecurityTypes"),
            "joined": str(joined) if joined else None,
            "last_auto_join": info.get("LastAutoJoinedAt"),
            "hidden": info.get("HIDDEN_NETWORK"),
        })
    return rows


def parse_bluetooth_plist(data: bytes, source: str = "<bt>") -> list[dict[str, Any]]:
    try:
        root = plistlib.loads(data)
    except Exception:  # noqa: BLE001
        return []
    rows = []
    core = root.get("CoreAudio") or {}
    # Classic layout: DeviceCache / PairedDevices
    cache = root.get("DeviceCache") or {}
    paired = root.get("PairedDevices") or []
    for addr in paired:
        info = cache.get(addr, {}) if isinstance(cache, dict) else {}
        rows.append({
            "source": source,
            "address": str(addr),
            "name": info.get("Name") or info.get("DisplayName"),
            "paired": True,
            "last_seen": info.get("LastSeenTime"),
            "class_of_device": info.get("ClassOfDevice"),
        })
    # newer: RecentDevices name list
    for name in root.get("RecentDevices") or []:
        rows.append({"source": source, "address": None,
                     "name": name if isinstance(name, str) else None,
                     "paired": False, "last_seen": None,
                     "class_of_device": None})
    return rows


def scan(root: str | Path) -> dict[str, list[dict[str, Any]]]:
    root = Path(root)
    wifi: list[dict[str, Any]] = []
    bt: list[dict[str, Any]] = []
    if root.exists():
        for f in root.rglob("com.apple.wifi.plist"):
            wifi += parse_wifi_plist(f.read_bytes(), source=str(f))
        for f in root.rglob("com.apple.bluetooth.plist"):
            bt += parse_bluetooth_plist(f.read_bytes(), source=str(f))
    return {"wifi": wifi, "bluetooth": bt}


def render(rows: dict[str, list[dict[str, Any]]]) -> str:
    lines = [f"wireless artifacts: {len(rows['wifi'])} networks, "
             f"{len(rows['bluetooth'])} bluetooth entries", ""]
    lines.append("WiFi known networks:")
    for n in rows["wifi"][:40]:
        ssid = n["ssid"] or n["network_id"]
        lines.append(f"  {ssid}  bssid={n['bssid'] or '?'} sec={n['security'] or '?'}"
                     f"{' hidden' if n['hidden'] else ''}")
    if not rows["wifi"]:
        lines.append("  (none found)")
    lines.append("")
    lines.append("Bluetooth:")
    for b in rows["bluetooth"][:40]:
        lines.append(f"  {b['name'] or b['address'] or '?'}"
                     f"{' [paired]' if b['paired'] else ' [recent]'}")
    if not rows["bluetooth"]:
        lines.append("  (none found)")
    return "\n".join(lines)