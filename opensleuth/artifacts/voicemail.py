"""Voicemail parser for HomeDomain/Library/Voicemail/voicemail.db."""

import sqlite3

from ..util import apple_to_dt


def parse(db_path):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(voicemail)")}
    sel = []
    for c in ("date", "sender", "callback_token", "duration", "expiration",
              "trashed_date", "flags", "token", "data"):
        sel.append(f'"{c}"' if c in cols else "NULL AS " + c)
    out = []
    for r in conn.execute(f'SELECT {", ".join(sel)} FROM voicemail ORDER BY date'):
        data = r["data"]
        out.append(
            {
                "date": apple_to_dt(r["date"]),
                "sender": r["sender"],
                "callback_token": r["callback_token"] or r["token"] or "",
                "duration_seconds": r["duration"],
                "expiration": apple_to_dt(r["expiration"]),
                "trashed": apple_to_dt(r["trashed_date"]),
                "flags": r["flags"],
                "audio_present": bool(data),
                "audio_size": len(data) if data else 0,
            }
        )
    conn.close()
    return out