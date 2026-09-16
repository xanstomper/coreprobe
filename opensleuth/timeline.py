"""Super-timeline builder: merge artifact sources into one chronology.

Consumes the artifact parsers' outputs (SMS, calls, notes, Safari) plus
generic timestamped records (CSV/JSON) and produces a single merged,
sorted timeline (CSV + JSON) - the Cellebrite-class "pattern of life"
deliverable.

Sources are duck-typed: any list of dicts with a timestamp-ish field
(date/ts/time/datetime/created) works. Output rows carry: ts, source,
type, who, text.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TS_FIELDS = ("ts", "timestamp", "date", "datetime", "time", "created",
             "created_at", "when", "start", "mtime")


def _to_iso(v: Any) -> str | None:
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        # apple epoch (2001-01-01) if huge, unix if ~1e9, mac if ~7e8
        try:
            if v > 6e8:
                base = 978307200 if v > 5e8 else 0
                import time
                return datetime.fromtimestamp(v + base, tz=timezone.utc).isoformat()
            return datetime.fromtimestamp(v, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    s = str(v).strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M", "%Y-%m-%d", "%m/%d/%Y %H:%M", "%m/%d/%Y"):
        try:
            d = datetime.strptime(s, fmt)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d.isoformat()
        except ValueError:
            continue
    return None


def extract_ts(row: dict[str, Any]) -> str | None:
    for f in TS_FIELDS:
        if f in row:
            iso = _to_iso(row[f])
            if iso:
                return iso
    return None


def _text_of(row: dict[str, Any]) -> str:
    for f in ("text", "body", "message", "content", "title", "url",
              "summary", "detail", "note"):
        if row.get(f):
            return str(row[f])[:300]
    return ""


def _who_of(row: dict[str, Any]) -> str:
    for f in ("who", "from", "sender", "address", "person", "caller",
              "handle", "contact", "name"):
        if row.get(f):
            return str(row[f])[:80]
    return ""


def merge(sources: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """sources: {'sms': [...], 'calls': [...], ...} -> sorted timeline."""
    events = []
    for source, rows in sources.items():
        for row in rows:
            if not isinstance(row, dict):
                continue
            iso = extract_ts(row)
            if not iso:
                continue
            events.append({
                "ts": iso,
                "source": source,
                "type": str(row.get("type") or row.get("kind") or source),
                "who": _who_of(row),
                "text": _text_of(row),
            })
    events.sort(key=lambda e: e["ts"])
    return events


def from_backup_artifacts(artifacts: dict[str, Any]) -> list[dict[str, Any]]:
    """Feed the artifact parsers' dict (ARTIFACTS shape) into merge()."""
    mapping = {
        "messages": "sms", "sms": "sms",
        "calls": "calls", "call_history": "calls",
        "notes": "notes",
        "history": "safari", "safari": "safari",
        "bookmarks": "safari",
        "voicemail": "voicemail",
    }
    sources = {}
    for key, rows in (artifacts or {}).items():
        src = mapping.get(key)
        if src and isinstance(rows, list):
            sources.setdefault(src, []).extend(rows)
    return merge(sources)


def write_csv(events: list[dict[str, Any]], path: str | Path) -> int:
    path = Path(path)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["ts", "source", "type", "who", "text"])
        w.writeheader()
        w.writerows(events)
    return len(events)


def write_json(events: list[dict[str, Any]], path: str | Path) -> None:
    Path(path).write_text(json.dumps(events, indent=2, ensure_ascii=False))


def load_csv(path: str | Path) -> list[dict[str, Any]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def render(events: list[dict[str, Any]], limit: int = 40) -> str:
    if not events:
        return "timeline: no timestamped events found"
    from collections import Counter
    by_src = Counter(e["source"] for e in events)
    span = f"{events[0]['ts']} -> {events[-1]['ts']}"
    lines = [f"super-timeline: {len(events)} events ({span})",
             f"  by source: {dict(by_src)}", ""]
    for e in events[-limit:]:
        who = f" [{e['who']}]" if e["who"] else ""
        lines.append(f"  {e['ts']}  {e['source']:<8}{who} {e['text'][:70]}")
    if len(events) > limit:
        lines.append(f"  ... ({len(events) - limit} earlier)")
    return "\n".join(lines)