"""Notification metadata parser for DuetExpertCenter/notificationAndSuggestionDB.db.

Source artifact (HomeDomain/Library/DuetExpertCenter/
notificationAndSuggestionDB.db, present iOS 15-26): the system records
delivered-notification metadata here -- bundle ID, delivery timestamp,
thread/topic ID and sender identifier -- for 60+ days, across WhatsApp,
Signal, SMS/iMessage, Phone and third-party apps.

Forensic value is CORROBORATION AFTER DELETION: the rows survive uninstall
of the source app, so a notification from an app that no longer exists on
the device still proves the app was installed, active, and communicating
with a specific sender at a specific time. (Public research: Mattia
Epifani, 2025-26; parser added to iLEAPP July 2026. CoreProbe previously
had no parser for this DB.)

METADATA-FIRST: bundle/timestamp/thread/sender are the reliable fields.
Title/body text columns exist in some iOS builds and are included when
present, but they are NOT guaranteed: Apple has progressively redacted
notification content in this store (tightened again on iOS 26 after
research showed deleted-app message text recoverable from it), so an
empty title/body on iOS 26+ means "redacted by the OS", not "no content".

SCHEMA DEFENSIVENESS: the on-disk schema is undocumented and varies by
iOS version, so nothing below hardcodes a table or column name. Tables
are discovered from sqlite_master and columns are mapped at runtime via
PRAGMA table_info against synonym sets. A DB whose schema matches nothing
yields an empty result plus a warning -- never an exception (the dump
pipeline records warnings instead of dying on one hostile artifact).

Timestamps arrive as Apple-epoch values whose magnitude varies by build
(seconds, or sub-second units). They are magnitude-normalised, then
converted with the same apple_to_dt/unix_to_dt helpers sibling parsers
use; values under 1.2e9 are read as Apple-epoch seconds, larger values
as Unix seconds.
"""

import plistlib
import sqlite3

from ..util import apple_to_dt, unix_to_dt

SOURCE_DB = "notificationAndSuggestionDB.db"

# Canonical field -> column-name synonyms, in priority order. Compared
# case-insensitively with underscores stripped ("bundle_id" == "bundleId").
_FIELD_SYNONYMS = {
    "bundle_id": ("bundleid", "bundleidentifier", "appbundleid", "appid",
                  "appidentifier", "bundle"),
    "timestamp": ("timestamp", "time", "date", "creationdate", "createdat",
                  "delivereddate", "deliverydate", "eventdate", "ts"),
    "thread_id": ("threadid", "threadidentifier", "topicid", "topic",
                  "conversationid", "chatid", "groupid"),
    "sender": ("sender", "senderid", "senderidentifier", "contactid",
               "contactidentifier", "handle", "author", "from", "remoteid"),
    "title": ("title", "header", "subject", "summary"),
    "body": ("body", "message", "content", "text", "alerttext", "alert",
             "subtitle"),
    "notif_id": ("id", "uuid", "guid", "identifier", "notificationid"),
}


def _norm(name):
    return str(name).lower().replace("_", "").replace("-", "").replace(" ", "")


def _map_columns(cols):
    """Map canonical fields to actual column names for one table."""
    by_norm = {_norm(c): c for c in cols}
    out = {}
    for field, synonyms in _FIELD_SYNONYMS.items():
        for syn in synonyms:
            if syn in by_norm:
                out[field] = by_norm[syn]
                break
    return out


def _candidate_tables(conn):
    """Tables that plausibly hold notifications, best candidate first.

    Preference: name mentions notif/suggestion; otherwise any table whose
    columns can fill at least bundle_id + timestamp.
    """
    names = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    scored = []
    for name in names:
        try:
            cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{name}")')]
        except sqlite3.Error:
            continue
        if not cols:
            continue
        mapping = _map_columns(cols)
        score = 0
        low = name.lower()
        if "notif" in low:
            score += 4
        if "suggestion" in low or "duet" in low:
            score += 2
        if "bundle_id" in mapping:
            score += 2
        if "timestamp" in mapping:
            score += 2
        score += sum(1 for f in ("thread_id", "sender", "title", "body")
                     if f in mapping)
        # A table is only usable if we can attribute + date its rows.
        if "bundle_id" in mapping and "timestamp" in mapping:
            scored.append((score, name, mapping))
    scored.sort(key=lambda t: -t[0])
    return scored


def _to_dt(value):
    """Magnitude-normalise an epoch value, then convert to ISO-8601 UTC."""
    if value is None:
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    # Sub-second storage units: scale down until in the seconds range.
    # Apple-epoch seconds for 2001..2101 are ~0..3.2e9; ns are ~1e18.
    while v > 1e13:
        v /= 1000.0
    if v > 3.2e9:  # still too large for Apple seconds: last-resort ms
        v /= 1000.0
    if v >= 1.2e9:  # Unix-epoch range (2008+); Apple seconds stay below
        return unix_to_dt(v)
    return apple_to_dt(v)


def _text_value(v):
    """Coerce a cell to text; BLOB bodies may be utf-8 or a binary plist."""
    if v is None:
        return ""
    if isinstance(v, bytes):
        if v.startswith(b"bplist"):
            try:
                data = plistlib.loads(v)
                if isinstance(data, str):
                    return data
                if isinstance(data, dict):
                    for key in ("NSString", "body", "text", "title"):
                        if isinstance(data.get(key), str):
                            return data[key]
            except Exception:
                pass
        return v.decode("utf-8", errors="replace")
    return str(v)


def parse_with_warnings(db_path):
    """Return (rows, warnings). Never raises: any failure is ([], [why])."""
    warnings = []
    if not db_path:
        return [], [f"{SOURCE_DB}: no path supplied"]
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return [], [f"{SOURCE_DB}: cannot open: {exc}"]
    conn.row_factory = sqlite3.Row
    rows = []
    try:
        candidates = _candidate_tables(conn)
        if not candidates:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            warnings.append(
                f"{SOURCE_DB}: no notification table recognized "
                f"(tables seen: {', '.join(tables) or 'none'})")
            return [], warnings
        for _score, table, mapping in candidates:
            sel = ", ".join(f'"{actual}" AS "{field}"'
                            for field, actual in mapping.items())
            order = f' ORDER BY "{mapping["timestamp"]}"' \
                if "timestamp" in mapping else ""
            try:
                cur = conn.execute(f'SELECT {sel} FROM "{table}"{order}')
            except sqlite3.Error as exc:
                warnings.append(f"{SOURCE_DB}: table {table}: {exc}")
                continue
            for r in cur:
                bundle = _text_value(r["bundle_id"]).strip()
                title = _text_value(r["title"]) if "title" in mapping else ""
                body = _text_value(r["body"]) if "body" in mapping else ""
                sender = _text_value(r["sender"]) if "sender" in mapping else ""
                summary_parts = [p for p in (title, body) if p]
                rows.append({
                    "date": _to_dt(r["timestamp"]),
                    "bundle_id": bundle,
                    "sender": sender,
                    "thread_id": _text_value(r["thread_id"])
                                 if "thread_id" in mapping else "",
                    "title": title,
                    "body": body,
                    "summary": " - ".join(summary_parts)
                               or f"notification from {bundle or 'unknown app'}",
                    "type": "notification",
                    "source_db": SOURCE_DB,
                    "notification_id": _text_value(r["notif_id"])
                                       if "notif_id" in mapping else "",
                })
    except sqlite3.Error as exc:
        return [], [f"{SOURCE_DB}: unreadable database: {exc}"]
    finally:
        conn.close()
    return rows, warnings


def parse(db_path):
    """Return a list of notification records (calls/voicemail list shape).

    Missing DB / unknown schema -> [] (details via parse_with_warnings).
    """
    rows, _warnings = parse_with_warnings(db_path)
    return rows
