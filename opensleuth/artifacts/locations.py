"""iOS Location & Cell/Wi-Fi Telemetry forensic parser.

Parses location databases:
- consolidated.db / cache_encryptedA.db (locationd cache)
- com.apple.routined caches (Cache.sqlite / Cloud-State.sqlite)
- CellularUsage.db
Reconstructs historical GPS fix points, Wi-Fi location triangulation points,
and cell tower connections into a normalized timeline.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ..util import apple_to_dt


def parse_locationd(db_path: str | Path) -> dict[str, Any]:
    """Parse consolidated.db or cache_encryptedA.db."""
    db_path = Path(db_path)
    if not db_path.is_file():
        return {"cell": [], "wifi": [], "gps": [], "total": 0}

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    cells = []
    wifis = []
    gps = []

    # CellLocation
    try:
        cur = conn.execute(
            "SELECT Latitude, Longitude, Timestamp, Confidence, MCC, MNC, LAC, CI "
            "FROM CellLocation WHERE Latitude IS NOT NULL AND Longitude IS NOT NULL "
            "ORDER BY Timestamp DESC LIMIT 1000"
        )
        for r in cur:
            cells.append({
                "latitude": r["Latitude"],
                "longitude": r["Longitude"],
                "date": apple_to_dt(r["Timestamp"]),
                "confidence": r["Confidence"],
                "type": "CellTower",
                "details": f"MCC={r['MCC']} MNC={r['MNC']} LAC={r['LAC']} CI={r['CI']}",
            })
    except sqlite3.OperationalError:
        pass

    # WifiLocation
    try:
        cur = conn.execute(
            "SELECT MAC, Latitude, Longitude, Timestamp, Confidence, Channel "
            "FROM WifiLocation WHERE Latitude IS NOT NULL AND Longitude IS NOT NULL "
            "ORDER BY Timestamp DESC LIMIT 1000"
        )
        for r in cur:
            wifis.append({
                "latitude": r["Latitude"],
                "longitude": r["Longitude"],
                "date": apple_to_dt(r["Timestamp"]),
                "confidence": r["Confidence"],
                "type": "WiFiAP",
                "details": f"BSSID={r['MAC']} Channel={r['Channel']}",
            })
    except sqlite3.OperationalError:
        pass

    # CdmaCellLocation / GpsLocation
    try:
        cur = conn.execute(
            "SELECT Latitude, Longitude, Timestamp, Confidence "
            "FROM CdmaCellLocation WHERE Latitude IS NOT NULL AND Longitude IS NOT NULL "
            "ORDER BY Timestamp DESC LIMIT 1000"
        )
        for r in cur:
            cells.append({
                "latitude": r["Latitude"],
                "longitude": r["Longitude"],
                "date": apple_to_dt(r["Timestamp"]),
                "confidence": r["Confidence"],
                "type": "CDMACell",
                "details": "CDMA Cell Tower",
            })
    except sqlite3.OperationalError:
        pass

    conn.close()
    return {
        "cell": cells,
        "wifi": wifis,
        "gps": gps,
        "total": len(cells) + len(wifis) + len(gps),
    }


def parse_routined(db_path: str | Path) -> list[dict[str, Any]]:
    """Parse com.apple.routined CoreData Cache.sqlite / Cloud-State.sqlite."""
    db_path = Path(db_path)
    if not db_path.is_file():
        return []

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    visits = []

    try:
        cur = conn.execute(
            "SELECT Z_PK, ZLATITUDE, ZLONGITUDE, ZUNCERTAINTY, ZENTRYDATE, ZEXITDATE "
            "FROM ZRTLEARNEDLOCATIONOFINTERESTVISITMO "
            "WHERE ZLATITUDE IS NOT NULL AND ZLONGITUDE IS NOT NULL "
            "ORDER BY ZENTRYDATE DESC LIMIT 500"
        )
        for r in cur:
            visits.append({
                "latitude": r["ZLATITUDE"],
                "longitude": r["ZLONGITUDE"],
                "entry_date": apple_to_dt(r["ZENTRYDATE"]) if r["ZENTRYDATE"] else None,
                "exit_date": apple_to_dt(r["ZEXITDATE"]) if r["ZEXITDATE"] else None,
                "uncertainty": r["ZUNCERTAINTY"],
                "type": "SignificantLocationVisit",
            })
    except sqlite3.OperationalError:
        pass

    conn.close()
    return visits


def parse(db_path: str | Path) -> dict[str, Any]:
    """Auto-detect and parse iOS location artifact file."""
    p = Path(db_path)
    name = p.name.lower()
    if "consolidated" in name or "cache_encrypted" in name:
        res = parse_locationd(p)
        return {"kind": "locationd", "data": res, "locations": res["cell"] + res["wifi"]}
    elif "routined" in str(p).lower() or "cache" in name or "cloud-state" in name:
        visits = parse_routined(p)
        return {"kind": "routined", "visits": visits, "locations": visits}
    else:
        # Generic attempt
        res = parse_locationd(p)
        if res["total"] > 0:
            return {"kind": "locationd", "data": res, "locations": res["cell"] + res["wifi"]}
        visits = parse_routined(p)
        return {"kind": "routined", "visits": visits, "locations": visits}
