"""Build a synthetic iPhone backup for end-to-end testing of the pipeline.

Simulates the layout produced by `idevicebackup2`:
  <root>/Manifest.plist, Manifest.db, <fileID[:2]>/<fileID> for every file.

Usage: python3 tests/fixture.py <outdir>
"""

import plistlib
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

APPLE_NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc).timestamp() - 978307200


def _new_db(path, tables):
    """tables: list of (name, [col defs], [rows]) where rows are dicts."""
    conn = sqlite3.connect(str(path))
    for name, cols, rows in tables:
        conn.execute(f"DROP TABLE IF EXISTS {name}")
        conn.execute(f"CREATE TABLE {name} ({', '.join(cols)})")
        if rows:
            keys = list(rows[0].keys())
            conn.executemany(
                f"INSERT INTO {name} ({', '.join(keys)}) VALUES ({', '.join('?' * len(keys))})",
                [tuple(r[k] for k in keys) for r in rows],
            )
    conn.commit()
    conn.close()


def build_sms(path):
    attributed = plistlib.dumps(
        {"NSAttributes": {}, "NSString": "voice memo: firmware test results attached"}
    )
    _new_db(
        path,
        [
            (
                "handle",
                ["ROWID INTEGER PRIMARY KEY", "id TEXT", "service TEXT"],
                [{"ROWID": 1, "id": "+15551234567", "service": "iMessage"}, {"ROWID": 2, "id": "sarah@icloud.com", "service": "iMessage"}],
            ),
            (
                "chat",
                ["ROWID INTEGER PRIMARY KEY", "chat_identifier TEXT", "service_name TEXT", "display_name TEXT"],
                [{"ROWID": 1, "chat_identifier": "+15551234567", "service_name": "iMessage", "display_name": "Sarah"}],
            ),
            (
                "message",
                ["ROWID INTEGER PRIMARY KEY", "guid TEXT", "text TEXT", "attributedBody BLOB", "handle_id INTEGER", "date REAL", "is_from_me INTEGER", "service TEXT"],
                [
                    {"ROWID": 1, "guid": "a1", "text": "hows the firmware coming", "attributedBody": None, "handle_id": 2, "date": APPLE_NOW - 3600, "is_from_me": 1, "service": "iMessage"},
                    {"ROWID": 2, "guid": "a2", "text": "almost done, flashing the target now", "attributedBody": None, "handle_id": 1, "date": APPLE_NOW - 1800, "is_from_me": 0, "service": "iMessage"},
                    {"ROWID": 3, "guid": "a3", "text": None, "attributedBody": attributed, "handle_id": 1, "date": APPLE_NOW - 900, "is_from_me": 0, "service": "iMessage"},
                ],
            ),
            (
                "attachment",
                ["ROWID INTEGER PRIMARY KEY", "guid TEXT", "filename TEXT", "mime_type TEXT", "total_bytes INTEGER"],
                [{"ROWID": 1, "guid": "att1", "filename": "~/Library/SMS/Attachments/00/01/IMG_0001.JPG", "mime_type": "image/jpeg", "total_bytes": 204800}],
            ),
            ("chat_message_join", ["chat_id INTEGER", "message_id INTEGER"], [{"chat_id": 1, "message_id": 1}, {"chat_id": 1, "message_id": 2}, {"chat_id": 1, "message_id": 3}]),
            ("message_attachment_join", ["message_id INTEGER", "attachment_id INTEGER"], [{"message_id": 3, "attachment_id": 1}]),
        ],
    )


def build_contacts(path):
    _new_db(
        path,
        [
            ("ABPerson", ["ROWID INTEGER PRIMARY KEY", "First TEXT", "Last TEXT", "Organization TEXT", "Department TEXT", "Birthday TEXT", "CreationDate REAL", "ModificationDate REAL"],
             [
                 {"ROWID": 1, "First": "Sarah", "Last": "Chen", "Organization": "", "Department": "", "Birthday": "1995-06-12", "CreationDate": 1750000000, "ModificationDate": 1750000000},
                 {"ROWID": 2, "First": "Mike", "Last": "Torres", "Organization": "Acme Security", "Department": "Red Team", "Birthday": None, "CreationDate": 1750000000, "ModificationDate": 1750000000},
             ]),
            ("ABMultiValueLabel", ["value INTEGER", "label TEXT"], [{"value": 3, "label": "_$!<Mobile>!$_"}, {"value": 4, "label": "_$!<Home>!$_"}, {"value": 5, "label": "_$!<Work>!$_"}, {"value": 7, "label": "_$!<Email>!$_"}]),
            ("ABMultiValue", ["record_id INTEGER", "value TEXT", "label INTEGER", "uid TEXT"],
             [
                 {"record_id": 1, "value": "+15551234567", "label": 3, "uid": "ab1"},
                 {"record_id": 1, "value": "sarah@icloud.com", "label": 7, "uid": "ab2"},
                 {"record_id": 2, "value": "+15559876543", "label": 3, "uid": "ab3"},
                 {"record_id": 2, "value": "mike@acme.test", "label": 7, "uid": "ab4"},
             ]),
            ("ABGroupMembers", ["group_id INTEGER", "member_id INTEGER"], []),
        ],
    )


def build_calls(path):
    _new_db(
        path,
        [
            ("ZCALLRECORD", ["Z_PK INTEGER PRIMARY KEY", "ZADDRESS TEXT", "ZDATE REAL", "ZDURATION REAL", "ZORIGINATED INTEGER", "ZANSWERED INTEGER", "ZCALLTYPE INTEGER", "ZISOCOUNTRYCODE TEXT"],
             [
                 {"Z_PK": 1, "ZADDRESS": "+15551234567", "ZDATE": APPLE_NOW - 7200, "ZDURATION": 315.0, "ZORIGINATED": 0, "ZANSWERED": 1, "ZCALLTYPE": 1, "ZISOCOUNTRYCODE": "us"},
                 {"Z_PK": 2, "ZADDRESS": "+15559876543", "ZDATE": APPLE_NOW - 5400, "ZDURATION": 0.0, "ZORIGINATED": 1, "ZANSWERED": 0, "ZCALLTYPE": 2, "ZISOCOUNTRYCODE": "us"},
                 {"Z_PK": 3, "ZADDRESS": "8005550199", "ZDATE": APPLE_NOW - 1800, "ZDURATION": 0.0, "ZORIGINATED": 0, "ZANSWERED": 0, "ZCALLTYPE": 3, "ZISOCOUNTRYCODE": "us"},
             ]),
        ],
    )


def build_safari_history(path):
    _new_db(
        path,
        [
            ("history_items", ["id INTEGER PRIMARY KEY", "url TEXT", "visit_count INTEGER", "domain_expansion TEXT"],
             [{"id": 1, "url": "https://github.com/1jehuang/jcode", "visit_count": 12, "domain_expansion": "github.com"},
              {"id": 2, "url": "https://opencode.ai/zen", "visit_count": 4, "domain_expansion": "opencode.ai"}]),
            ("history_visits", ["id INTEGER PRIMARY KEY", "history_item INTEGER", "visit_time REAL", "title TEXT", "origin INTEGER", "load_successful INTEGER"],
             [{"id": 1, "history_item": 1, "visit_time": APPLE_NOW - 3600, "title": "jcode - agent", "origin": 0, "load_successful": 1},
              {"id": 2, "history_item": 2, "visit_time": APPLE_NOW - 600, "title": "OpenCode", "origin": 0, "load_successful": 1}]),
        ],
    )


def build_safari_bookmarks(path):
    _new_db(
        path,
        [
            ("bookmarks", ["id INTEGER PRIMARY KEY", "title TEXT", "url TEXT", "type INTEGER", "folder INTEGER", "last_modified REAL"],
             [{"id": 1, "title": "Hercules", "url": "http://10.0.0.171:9120", "type": 0, "folder": 0, "last_modified": APPLE_NOW - 86400},
              {"id": 2, "title": "Jcode repo", "url": "https://github.com/1jehuang/jcode", "type": 0, "folder": 0, "last_modified": APPLE_NOW - 172800}]),
        ],
    )


def build_keychain(path):
    _new_db(
        path,
        [
            ("genp", ["ROWID INTEGER PRIMARY KEY", "agrp TEXT", "svce TEXT", "acct TEXT", "cdat REAL", "mdat REAL", "desc TEXT", "data BLOB"],
             [{"ROWID": 1, "agrp": "io.tailscale.ipn.ios", "svce": "tailscale-auth", "acct": "user@example.com", "cdat": APPLE_NOW - 86400, "mdat": APPLE_NOW - 3600, "desc": "Tailscale API key", "data": b"tskey-open-source-test-123456"}]),
            ("inet", ["ROWID INTEGER PRIMARY KEY", "agrp TEXT", "svce TEXT", "acct TEXT", "cdat REAL", "mdat REAL", "desc TEXT", "data BLOB"],
             [{"ROWID": 1, "agrp": "com.example.agent", "svce": "https://api.example.test", "acct": "ops", "cdat": APPLE_NOW - 7200, "mdat": APPLE_NOW - 600, "desc": "API password", "data": b"\x7f\x01\x02encrypted-blob"}]),
        ],
    )


def build_voicemail(path):
    _new_db(
        path,
        [
            ("voicemail", ["ROWID INTEGER PRIMARY KEY", "date REAL", "sender TEXT", "callback_token TEXT", "duration REAL", "expiration REAL", "trashed_date REAL", "flags INTEGER", "data BLOB"],
             [{"ROWID": 1, "date": APPLE_NOW - 4000, "sender": "+18005550199", "callback_token": "+18005550199", "duration": 34.0, "expiration": None, "trashed_date": None, "flags": 1, "data": b"\x00\x00\x00\x14ftypM4A " + b"x" * 100}]),
        ],
    )


def build_notes(path):
    _new_db(
        path,
        [
            ("ZICCLOUDSYNCINGOBJECT", ["Z_PK INTEGER PRIMARY KEY", "ZCREATIONDATE REAL", "ZMODIFICATIONDATE REAL", "ZTITLE1 TEXT", "ZDATA BLOB"],
             [{"Z_PK": 1, "ZCREATIONDATE": APPLE_NOW - 5000, "ZMODIFICATIONDATE": APPLE_NOW - 100, "ZTITLE1": "Extraction notes", "ZDATA": b"\x0a\x08\x12\x06hello" * 10}]),
        ],
    )


def main(outdir: str):
    root = Path(outdir)
    root.mkdir(parents=True, exist_ok=True)
    (root / "Manifest.plist").write_bytes(
        plistlib.dumps(
            {
                "BackupState": "new",
                "Version": 2.4,
                "IsEncrypted": False,
                "UDID": "00008030-TESTFIXTURE",
                "SerialNumber": "FIXTURE-SERIAL",
                "ProductVersion": "26.6.1",
                "DeviceInfo": {"ProductType": "iPhone12,1", "ProductName": "iPhone OS"},
            }
        )
    )

    files = {
        ("HomeDomain", "Library/SMS/sms.db"): build_sms,
        ("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb"): build_contacts,
        ("HomeDomain", "Library/CallHistoryDB/CallHistory.storedata"): build_calls,
        ("HomeDomain", "Library/Safari/History.db"): build_safari_history,
        ("HomeDomain", "Library/Safari/Bookmarks.db"): build_safari_bookmarks,
        ("HomeDomain", "Library/Voicemail/voicemail.db"): build_voicemail,
        ("SysContainerDomain-systemgroup.com.apple.keychain", "Library/Keychains/keychain-2.db"): build_keychain,
        ("HomeDomain", "Library/Group Containers/group.com.apple.notes/NoteStore.sqlite"): build_notes,
        ("AppDomain-com.example.agent", "Documents/config.json"): None,
        ("AppDomain-com.example.agent", "Documents/cache.sqlite"): None,
    }

    import hashlib

    man = sqlite3.connect(str(root / "Manifest.db"))
    man.execute("DROP TABLE IF EXISTS Files")
    man.execute("DROP TABLE IF EXISTS Properties")
    man.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file INTEGER)")
    man.execute("CREATE TABLE Properties (key TEXT, value BLOB)")
    entries = []

    for (domain, relpath), builder in files.items():
        if builder is None:
            content = b'{"endpoint": "https://api.example.test/v1", "token_enc": "AESGCM:deadbeef"}'
        else:
            content = b""
        h = hashlib.sha1(f"{domain}-{relpath}".encode()).hexdigest().upper()
        sub = root / h[:2]
        sub.mkdir(exist_ok=True)
        fpath = sub / h
        if builder is None:
            fpath.write_bytes(content)
        else:
            builder(fpath)
        entries.append((h, domain, relpath, 2, fpath.stat().st_size))

    man.executemany("INSERT INTO Files VALUES (?,?,?,?,?)", entries)
    man.commit()
    man.close()
    print(f"synthetic backup written to {root} ({len(entries)} files)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tests/fixture-out")