"""Telegram iOS forensic parser for tgdata.db / telegram.sqlite.

Parses chats, messages, peers, and contact records from Telegram iOS
databases located under AppDomainGroup-group.ph.telegra.Telegraph or
AppDomain-ph.telegra.Telegraph.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _ts_to_iso(ts: int | float | None) -> str | None:
    if not ts:
        return None
    try:
        # Telegram stores Unix timestamp (seconds since 1970)
        # Check if timestamp looks like Unix (> 1e8) vs Cocoa epoch (< 1e9 but usually > 0)
        val = float(ts)
        if val > 1_000_000_000:
            return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
        else:
            # Apple epoch: seconds since 2001-01-01
            from ..util import apple_to_dt
            return apple_to_dt(val)
    except Exception:
        return str(ts)


def parse(db_path: str | Path) -> dict[str, Any]:
    """Parse a Telegram database.

    Returns {"messages": [...], "chats": [...], "users": [...], "count": n}.
    """
    db_path = Path(db_path)
    if not db_path.is_file():
        return {"messages": [], "chats": [], "users": [], "count": 0}

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    users = {}
    chats = {}
    messages = []

    # 1. Look for users table
    for utable in ("users", "users_v29", "peers"):
        try:
            cur = conn.execute(f"SELECT * FROM {utable}")
            for r in cur:
                uid = r["id"] if "id" in r.keys() else r["peer_id"] if "peer_id" in r.keys() else None
                if uid is not None:
                    fname = r["first_name"] if "first_name" in r.keys() else ""
                    lname = r["last_name"] if "last_name" in r.keys() else ""
                    phone = r["phone_number"] if "phone_number" in r.keys() else (r["phone"] if "phone" in r.keys() else "")
                    uname = r["username"] if "username" in r.keys() else ""
                    name = f"{fname or ''} {lname or ''}".strip() or uname or f"User {uid}"
                    users[uid] = {
                        "id": uid,
                        "name": name,
                        "username": uname,
                        "phone": phone,
                    }
            break
        except sqlite3.OperationalError:
            continue

    # 2. Look for dialogs / chats
    for ctable in ("chats", "chats_v29", "dialogs"):
        try:
            cur = conn.execute(f"SELECT * FROM {ctable}")
            for r in cur:
                cid = r["id"] if "id" in r.keys() else (r["peer_id"] if "peer_id" in r.keys() else None)
                if cid is not None:
                    title = r["title"] if "title" in r.keys() else f"Chat {cid}"
                    chats[cid] = {
                        "id": cid,
                        "title": title,
                    }
            break
        except sqlite3.OperationalError:
            continue

    # 3. Look for messages
    for mtable in ("messages_v29", "messages", "channel_messages"):
        try:
            cur_cols = conn.execute(f"PRAGMA table_info({mtable})").fetchall()
            col_names = {c["name"] for c in cur_cols}
            if not col_names:
                continue

            id_col = "mid" if "mid" in col_names else "id"
            peer_col = "peer_id" if "peer_id" in col_names else "chat_id"
            date_col = "date" if "date" in col_names else "timestamp"
            text_col = "message" if "message" in col_names else "text"
            out_col = "out" if "out" in col_names else "is_outgoing"

            query = (
                f"SELECT {id_col} AS msg_id, {peer_col} AS peer, {date_col} AS msg_date, "
                f"       {text_col} AS msg_text, "
                f"       {'1' if out_col not in col_names else out_col} AS is_out "
                f"FROM {mtable} ORDER BY {date_col}"
            )
            for r in conn.execute(query):
                peer_id = r["peer"]
                peer_name = ""
                if peer_id in chats:
                    peer_name = chats[peer_id]["title"]
                elif peer_id in users:
                    peer_name = users[peer_id]["name"]
                else:
                    peer_name = str(peer_id) if peer_id else ""

                messages.append({
                    "id": r["msg_id"],
                    "chat": peer_name,
                    "peer_id": peer_id,
                    "sender": "Me" if r["is_out"] else peer_name,
                    "date": _ts_to_iso(r["msg_date"]),
                    "from_me": bool(r["is_out"]),
                    "service": "Telegram",
                    "text": r["msg_text"] or "",
                    "attachments": [],
                })
            break
        except sqlite3.OperationalError:
            continue

    conn.close()
    return {
        "messages": messages,
        "chats": list(chats.values()),
        "users": list(users.values()),
        "count": len(messages),
    }
