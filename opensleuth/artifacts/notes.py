"""Notes extractor (best-effort).

Modern iOS keeps note content in ZICCLOUDSYNCINGOBJECT.ZDATA as protobuf;
older builds used ZNOTE(ZTITLE, ZBODY). We extract titles, timestamps, and
save raw body blobs to disk for offline decoding.
"""

import sqlite3
from pathlib import Path

from ..util import apple_to_dt


def _locate(backup):
    for pattern in (
        "Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
        "Library/Notes/notes.sqlite",
    ):
        path = backup.get_path("HomeDomain", pattern)
        if path:
            return path
    for rec in backup.find(pattern="%NoteStore.sqlite"):
        path = backup.get_path(rec["domain"], rec["relativePath"])
        if path:
            return path
    return None


def parse(backup, blob_dir=None):
    path = _locate(backup)
    if path is None:
        return []
    blob_dir = Path(blob_dir) if blob_dir else None
    if blob_dir:
        blob_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    out = []
    try:  # modern schema
        rows = conn.execute(
            "SELECT Z_PK, ZCREATIONDATE, ZMODIFICATIONDATE, ZTITLE1 AS title, "
            "ZDATA AS body FROM ZICCLOUDSYNCINGOBJECT ORDER BY ZCREATIONDATE"
        )
    except sqlite3.OperationalError:
        try:  # legacy schema
            rows = conn.execute(
                "SELECT Z_PK, ZCREATIONDATE AS ZCREATIONDATE, ZMODIFICATIONDATE, "
                "ZTITLE AS title, ZBODY AS body FROM ZNOTE ORDER BY ZCREATIONDATE"
            )
        except sqlite3.OperationalError:
            conn.close()
            return out
    for r in rows:
        body = r["body"]
        saved = None
        if blob_dir and body:
            saved = str(blob_dir / f"note_{r['Z_PK']}.blob")
            Path(saved).write_bytes(body)
        out.append(
            {
                "title": (r["title"] or "").strip() or "(untitled)",
                "created": apple_to_dt(r["ZCREATIONDATE"]),
                "modified": apple_to_dt(r["ZMODIFICATIONDATE"]),
                "body_size": len(body) if body else 0,
                "body_saved": saved,
                "body_hex": body[:32].hex() if body else "",
            }
        )
    conn.close()
    return out