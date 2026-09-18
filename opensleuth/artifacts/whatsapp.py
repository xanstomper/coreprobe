"""WhatsApp iOS forensic parser for ChatStorage.sqlite.

Extracts chats, messages, media references, and contact records from WhatsApp's
CoreData SQLite database (AppDomainGroup-group.net.whatsapp.WhatsApp.shared or
AppDomain-net.whatsapp.WhatsApp).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ..util import apple_to_dt


def parse(db_path: str | Path) -> dict[str, Any]:
    """Parse a WhatsApp ChatStorage.sqlite database.

    Returns {"messages": [...], "chats": [...], "count": n}.
    """
    db_path = Path(db_path)
    if not db_path.is_file():
        return {"messages": [], "chats": [], "count": 0}

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    # 1. Extract chat sessions
    chats = {}
    try:
        cur = conn.execute(
            "SELECT Z_PK, ZCONTACTJID, ZPARTNERNAME, ZMESSAGECOUNTER, ZUNREADCOUNT "
            "FROM ZWACHATSESSION"
        )
        for r in cur:
            chats[r["Z_PK"]] = {
                "id": r["Z_PK"],
                "jid": r["ZCONTACTJID"] or "",
                "name": r["ZPARTNERNAME"] or r["ZCONTACTJID"] or "",
                "message_count": r["ZMESSAGECOUNTER"] or 0,
                "unread": r["ZUNREADCOUNT"] or 0,
            }
    except sqlite3.OperationalError:
        pass

    # 2. Extract media items if available
    media = {}
    try:
        cur = conn.execute(
            "SELECT Z_PK, ZMEDIALOCALPATH, ZFILESIZE, ZTITLE, ZMEDIANAME FROM ZWAMEDIAITEM"
        )
        for r in cur:
            media[r["Z_PK"]] = {
                "path": r["ZMEDIALOCALPATH"] or "",
                "size": r["ZFILESIZE"] or 0,
                "title": r["ZTITLE"] or r["ZMEDIANAME"] or "",
            }
    except sqlite3.OperationalError:
        pass

    # 3. Extract messages
    messages = []
    try:
        # Check available columns in ZWAMESSAGE
        cur_cols = conn.execute("PRAGMA table_info(ZWAMESSAGE)").fetchall()
        col_names = {c["name"] for c in cur_cols}

        date_col = "ZMESSAGEDATE" if "ZMESSAGEDATE" in col_names else "ZDATE"
        text_col = "ZTEXT" if "ZTEXT" in col_names else "ZDATA"
        from_col = "ZFROMJID" if "ZFROMJID" in col_names else "ZTOJID"
        is_from_me = "ZISFROMME" if "ZISFROMME" in col_names else "1"
        media_col = "ZMEDIAITEM" if "ZMEDIAITEM" in col_names else "NULL"
        chat_col = "ZCHATSESSION" if "ZCHATSESSION" in col_names else "NULL"

        query = (
            f"SELECT Z_PK, {date_col} AS msg_date, {text_col} AS msg_text, "
            f"       {from_col} AS sender_jid, {is_from_me} AS from_me, "
            f"       {chat_col} AS chat_id, {media_col} AS media_id "
            f"FROM ZWAMESSAGE ORDER BY {date_col}"
        )

        for r in conn.execute(query):
            chat_info = chats.get(r["chat_id"], {})
            m_info = media.get(r["media_id"])
            media_desc = m_info["title"] or m_info["path"] if m_info else ""
            raw_date = r["msg_date"]

            messages.append({
                "id": r["Z_PK"],
                "chat": chat_info.get("name") or chat_info.get("jid") or "",
                "chat_jid": chat_info.get("jid") or "",
                "sender": r["sender_jid"] or ("Me" if r["from_me"] else ""),
                "date": apple_to_dt(raw_date) if raw_date else None,
                "from_me": bool(r["from_me"]),
                "service": "WhatsApp",
                "text": r["msg_text"] or "",
                "media": media_desc,
                "attachments": [media_desc] if media_desc else [],
            })
    except sqlite3.OperationalError:
        # Fallback: maybe older or generic schema
        try:
            for r in conn.execute("SELECT rowid, chat_id, text, timestamp FROM messages"):
                messages.append({
                    "id": r[0],
                    "chat": str(r[1]),
                    "sender": "",
                    "date": apple_to_dt(r[3]),
                    "from_me": False,
                    "service": "WhatsApp",
                    "text": r[2] or "",
                    "media": "",
                    "attachments": [],
                })
        except sqlite3.OperationalError:
            pass

    conn.close()
    return {
        "messages": messages,
        "chats": list(chats.values()),
        "count": len(messages),
    }
