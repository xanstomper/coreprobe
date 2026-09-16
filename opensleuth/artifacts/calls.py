"""Call history parser for HomeDomain/Library/CallHistoryDB/CallHistory.storedata.

This is a CoreData SQLite store (ZCALLRECORD table). Timestamps are Apple-epoch.
Call type mapping is heuristic: 1=incoming, 2=outgoing, 3=missed.
"""

import sqlite3

from ..util import apple_to_dt

CALL_TYPES = {1: "Incoming", 2: "Outgoing", 3: "Missed", 4: "Cancelled"}
KNOWN = {
    1: "Incoming",
    2: "Outgoing",
    3: "Missed",
    4: "Incoming (blocked)",
    5: "Outgoing (blocked)",
    6: "Missed (blocked)",
    7: "Incoming (unknown)",
    8: "Outgoing (unknown)",
}


def parse(db_path):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    out = []
    try:
        cur = conn.execute(
            "SELECT ZADDRESS AS phone, ZDATE AS date, ZDURATION AS duration, "
            "       ZORIGINATED AS originated, ZANSWERED AS answered, "
            "       ZCALLTYPE AS calltype, ZISOCountryCode AS country "
            "FROM ZCALLRECORD ORDER BY ZDATE"
        )
    except sqlite3.OperationalError as exc:
        conn.close()
        raise ValueError(f"CallHistory.storedata has no ZCALLRECORD: {exc}") from exc

    for r in cur:
        typ = CALL_TYPES.get(r["calltype"], f"Type {r['calltype']}")
        out.append(
            {
                "phone": r["phone"],
                "date": apple_to_dt(r["date"]),
                "duration_seconds": r["duration"],
                "direction": "Outgoing" if r["originated"] else "Incoming",
                "type": typ,
                "answered": bool(r["answered"]),
                "country": r["country"],
            }
        )
    conn.close()
    return out