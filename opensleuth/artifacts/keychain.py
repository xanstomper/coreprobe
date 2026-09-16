"""Keychain parser for keychain-2.db.

Sources: decrypted encrypted-backup (opensleuth acquire all --password →
pyiosbackup --unback) or jailbroken filesystem pulls. On older iOS the DATA
column is plaintext; modern iOS keeps it wrapped, so metadata is always
extracted and a plaintext attempt is made when possible.
"""

import sqlite3

from ..util import apple_to_dt

KINDS = (("genp", "generic_password"), ("inet", "internet_password"),
         ("cert", "certificate"), ("keys", "key"))


def _try_plaintext(data):
    if not data:
        return ""
    try:
        s = data.decode("utf-8")
        if s.isprintable() and 4 < len(s) < 512:
            return s
    except (UnicodeDecodeError, ValueError):
        pass
    return ""


def parse(db_path):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    out = []
    for table, kind in KINDS:
        try:
            cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        except sqlite3.OperationalError:
            continue
        if not cols:
            continue
        sel = []
        for c in ("agrp", "svce", "acct", "cdat", "mdat", "desc", "data"):
            sel.append(f'"{c}"' if c in cols else "NULL AS " + c)
        try:
            rows = conn.execute(f'SELECT {", ".join(sel)} FROM "{table}"').fetchall()
        except sqlite3.OperationalError:
            continue
        for r in rows:
            data = r["data"]
            out.append(
                {
                    "kind": kind,
                    "group": r["agrp"] or "",
                    "service": r["svce"] or r["desc"] or "",
                    "account": r["acct"] or "",
                    "created": apple_to_dt(r["cdat"]),
                    "modified": apple_to_dt(r["mdat"]),
                    "data_size": len(data) if data else 0,
                    "data_hex": data[:40].hex() if data else "",
                    "plaintext_attempt": _try_plaintext(data),
                }
            )
    conn.close()
    return out