"""Safari parser: HomeDomain/Library/Safari/History.db + Bookmarks.db."""

import sqlite3

from ..util import apple_to_dt


def _history(db_path):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    out = []
    sql = (
        "SELECT v.id, h.url, v.title, h.visit_count, v.visit_time, v.origin, "
        "       v.load_successful, h.domain_expansion "
        "FROM history_visits v JOIN history_items h ON v.history_item = h.id "
        "ORDER BY v.visit_time"
    )
    for r in conn.execute(sql):
        out.append(
            {
                "date": apple_to_dt(r["visit_time"]),
                "url": r["url"],
                "title": r["title"],
                "visit_count": r["visit_count"],
                "origin": r["origin"],
                "load_successful": r["load_successful"],
            }
        )
    conn.close()
    return out


def _bookmarks(db_path):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    out = []
    try:
        cur = conn.execute(
            "SELECT title, url, type, last_modified, folder FROM bookmarks "
            "WHERE url IS NOT NULL ORDER BY last_modified"
        )
    except sqlite3.OperationalError as exc:
        conn.close()
        raise ValueError(f"Bookmarks.db malformed: {exc}") from exc
    for r in cur:
        out.append(
            {
                "title": r["title"],
                "url": r["url"],
                "folder": bool(r["folder"]),
                "modified": apple_to_dt(r["last_modified"]),
            }
        )
    conn.close()
    return out


def parse(history_db, bookmarks_db=None):
    return {"history": _history(history_db), "bookmarks": _bookmarks(bookmarks_db) if bookmarks_db else []}