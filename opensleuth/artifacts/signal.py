"""Signal iOS forensic parser and triage for Signal.sqlite / GrdbStorage.sqlite.

Inspects Signal app databases under AppDomainGroup-group.org.whispersystems.signal
or AppDomain-org.whispersystems.signal. Handles both SQLCipher encrypted status
detection (identifying the 16-byte salt and cipher header) and plaintext / decrypted
database extraction (threads, interactions, contacts).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ..util import apple_to_dt

SQLITE_HEADER = b"SQLite format 3\x00"


def inspect_db_encryption(path: Path) -> dict[str, Any]:
    """Check whether a database file is plaintext SQLite or SQLCipher encrypted."""
    if not path.is_file():
        return {"exists": False}

    size = path.stat().st_size
    if size < 16:
        return {"exists": True, "size": size, "type": "empty_or_truncated"}

    with open(path, "rb") as fh:
        header16 = fh.read(16)

    if header16 == SQLITE_HEADER:
        return {
            "exists": True,
            "size": size,
            "type": "plaintext_sqlite",
            "encrypted": False,
        }
    else:
        # SQLCipher begins with 16 bytes of random salt
        return {
            "exists": True,
            "size": size,
            "type": "sqlcipher_encrypted",
            "encrypted": True,
            "salt_hex": header16.hex(),
            "note": "Requires SQLCipher database key from iOS Keychain (item: 'database-key')",
        }


def parse(db_path: str | Path) -> dict[str, Any]:
    """Parse Signal database if plaintext or decrypted; report encryption metadata if locked."""
    db_path = Path(db_path)
    if not db_path.is_file():
        return {"status": "missing", "messages": [], "threads": [], "count": 0}

    info = inspect_db_encryption(db_path)
    if info.get("encrypted"):
        return {
            "status": "encrypted",
            "encryption_info": info,
            "messages": [],
            "threads": [],
            "count": 0,
            "note": "Signal database is SQLCipher-protected at rest.",
        }

    # If plaintext SQLite:
    messages = []
    threads = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row

        # Try legacy schema (model_TSInteraction)
        try:
            for r in conn.execute("SELECT rowid, * FROM model_TSThread"):
                threads.append({
                    "id": r["rowid"],
                    "name": r["uniqueId"] if "uniqueId" in r.keys() else str(r["rowid"]),
                })
        except sqlite3.OperationalError:
            pass

        try:
            cur = conn.execute("SELECT rowid, * FROM model_TSInteraction")
            for r in cur:
                text = r["body"] if "body" in r.keys() else (r["text"] if "text" in r.keys() else "")
                ts = r["timestamp"] if "timestamp" in r.keys() else 0
                is_out = bool(r["isOutgoing"]) if "isOutgoing" in r.keys() else False
                messages.append({
                    "id": r["rowid"],
                    "chat": "Signal Thread",
                    "sender": "Me" if is_out else "Contact",
                    "date": apple_to_dt(ts / 1000.0) if ts > 1e11 else apple_to_dt(ts),
                    "from_me": is_out,
                    "service": "Signal",
                    "text": text or "",
                    "attachments": [],
                })
        except sqlite3.OperationalError:
            pass

        conn.close()
    except Exception as exc:
        return {
            "status": "error",
            "error": str(exc),
            "encryption_info": info,
            "messages": [],
            "threads": [],
            "count": 0,
        }

    return {
        "status": "plaintext",
        "encryption_info": info,
        "messages": messages,
        "threads": threads,
        "count": len(messages),
    }
