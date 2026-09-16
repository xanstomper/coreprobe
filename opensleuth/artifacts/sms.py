"""iMessage / SMS parser for HomeDomain/Library/SMS/sms.db."""

import plistlib
import sqlite3

from ..util import apple_to_dt


def _extract_text(row):
    """Plain text lives in `text`; newer messages store NSAttributedString in
    `attributedBody` (a binary plist with an NSString key)."""
    text = row["text"]
    if text:
        return text
    body = row["body"]
    if body:
        try:
            data = plistlib.loads(body)
            if isinstance(data, dict) and "NSString" in data:
                return data["NSString"]
        except Exception:
            pass
    return ""


def parse(db_path):
    """Return {"messages": [...], "count": n} from an sms.db copy."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    out = []

    # attachments keyed by ROWID
    attachments = {}
    try:
        for a in conn.execute(
            "SELECT ROWID, filename, mime_type, total_bytes FROM attachment"
        ):
            attachments[a["ROWID"]] = {
                "filename": a["filename"],
                "mime": a["mime_type"],
                "bytes": a["total_bytes"],
            }
    except sqlite3.OperationalError:
        pass

    attach_for = {}
    try:
        for j in conn.execute("SELECT message_id, attachment_id FROM message_attachment_join"):
            attach_for.setdefault(j["message_id"], []).append(
                attachments.get(j["attachment_id"], {})
            )
    except sqlite3.OperationalError:
        pass

    sql = (
        "SELECT m.ROWID AS id, m.guid, m.text, m.attributedBody AS body, "
        "       m.handle_id, m.date, m.is_from_me, m.service, h.id AS sender, "
        "       c.ROWID AS chat_id, c.chat_identifier, c.display_name "
        "FROM message m "
        "LEFT JOIN handle h ON m.handle_id = h.ROWID "
        "LEFT JOIN chat_message_join j ON j.message_id = m.ROWID "
        "LEFT JOIN chat c ON c.ROWID = j.chat_id "
        "ORDER BY m.date"
    )
    for r in conn.execute(sql):
        out.append(
            {
                "id": r["id"],
                "guid": r["guid"],
                "chat": r["display_name"] or r["chat_identifier"] or "",
                "sender": r["sender"],
                "date": apple_to_dt(r["date"]),
                "from_me": bool(r["is_from_me"]),
                "service": r["service"],
                "text": _extract_text(r),
                "attachments": [
                    a.get("filename") or f"(inlined {a.get('mime')})"
                    for a in attach_for.get(r["id"], [])
                ],
            }
        )
    conn.close()
    return {"messages": out, "count": len(out)}