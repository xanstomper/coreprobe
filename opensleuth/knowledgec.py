"""Knowledge Corpus (knowledgeC) parser - Apple's own behavior log.

knowledgeC.db (SQLite, in /private/var/db/CoreDuet/Knowledge on a full
filesystem extraction, or inside a sysdiagnose under system_logs/
archive or CoreDuet) records nearly every user-device interaction:
app launches, screen locks, notifications, device plug-ins, headphone
use - the "pattern of life" source par excellence.

Schema (documented widely in forensic literature):
  ZOBJECT: ZSTREAMNAME, ZENDDATETIME, ZVALUESTRING, ...
  streams: /app/inFocus, /device/lock, /user/notification, etc.

Honesty: this reads REAL rows from the database; empty DB -> empty
timeline. Never invents entries.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

try:
    from ._apple_time import apple_to_iso  # type: ignore
except ImportError:
    def apple_to_iso(ts: float) -> str | None:
        # Apple epoch = 2001-01-01T00:00:00Z (offset 978307200)
        try:
            from datetime import datetime, timezone, timedelta
            d = datetime(2001, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=float(ts))
            return d.isoformat()
        except (ValueError, OverflowError):
            return None

KNOWN_STREAMS = {
    "/app/inFocus": "app-focus",
    "/app/activation": "app-open",
    "/app/terminated": "app-close",
    "/device/lock": "lock",
    "/device/unlock": "unlock",
    "/device/pluggedIn": "plugged-in",
    "/device/unplugged": "unplugged",
    "/device/screenSharingStart": "screen-share",
    "/user/notification": "notification",
    "/siri/utterance": "siri",
    "/audio/headphone": "headphones",
    "/calendar/eventTriggered": "calendar",
    "/location/visit": "location-visit",
}


def parse_knowledgec(db_path: str | Path, limit: int = 100000) -> list[dict[str, Any]]:
    """Read ZOBJECT rows into a behavior timeline (read-only)."""
    db_path = Path(db_path)
    if not db_path.exists():
        return []
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        return []
    try:
        cur = con.cursor()
        cur.execute(
            "SELECT ZSTREAMNAME, ZENDDATETIME, ZVALUESTRING, ZSTRUCTUREDDATA "
            "FROM ZOBJECT ORDER BY ZENDDATETIME LIMIT ?", (limit,))
        rows = []
        for stream, end, value, sdata in cur.fetchall():
            rows.append({
                "ts": apple_to_iso(end) if end is not None else None,
                "stream": stream,
                "kind": KNOWN_STREAMS.get(stream, "other"),
                "value": value,
            })
        return rows
    except sqlite3.Error:
        return []
    finally:
        con.close()


def find_knowledgec(root: str | Path) -> list[Path]:
    root = Path(root)
    hits = []
    if root.exists():
        for name in ("knowledgeC.db", "knowledgeC-copy.sqlite"):
            hits += [p for p in root.rglob(name) if p.is_file()]
    return hits


def app_usage_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Count app-focus events per app value."""
    from collections import Counter
    c = Counter(r["value"] for r in rows if r["kind"] == "app-focus" and r["value"])
    return dict(c.most_common(50))


def render(rows: list[dict[str, Any]], limit: int = 30) -> str:
    if not rows:
        return "knowledgeC: no rows (database not found or empty)"
    from collections import Counter
    kinds = Counter(r["kind"] for r in rows)
    lines = [f"knowledgeC: {len(rows)} events",
             f"  by kind: {dict(kinds)}", ""]
    for r in rows[-limit:]:
        lines.append(f"  {r['ts'] or '?'}  [{r['kind']}] {r['value'] or ''}")
    apps = app_usage_summary(rows)
    if apps:
        lines.append("")
        lines.append("top apps by focus events:")
        for app, n in list(apps.items())[:10]:
            lines.append(f"  {n:>5}  {app}")
    return "\n".join(lines)