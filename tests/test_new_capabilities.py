"""Tests for newly expanded forensic capabilities:
- WhatsApp, Telegram, Signal, Locations artifact parsers
- CASE/UCO ontology standard reporting
- BFU database inspection & manifest export
- Triple-hash certification & examiner attestation
"""

import json
import sqlite3
import tempfile
from pathlib import Path

from opensleuth.artifacts import whatsapp, telegram, signal, locations
from opensleuth import report as R
from opensleuth import bfufs as B
from opensleuth import certify as C


def test_whatsapp_parser(tmp_path):
    db_path = tmp_path / "ChatStorage.sqlite"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE ZWACHATSESSION (Z_PK INTEGER PRIMARY KEY, ZCONTACTJID TEXT, ZPARTNERNAME TEXT, ZMESSAGECOUNTER INT, ZUNREADCOUNT INT)"
    )
    conn.execute(
        "INSERT INTO ZWACHATSESSION VALUES (1, '15551234567@s.whatsapp.net', 'Alice Smith', 5, 0)"
    )
    conn.execute(
        "CREATE TABLE ZWAMEDIAITEM (Z_PK INTEGER PRIMARY KEY, ZMEDIALOCALPATH TEXT, ZFILESIZE INT, ZTITLE TEXT, ZMEDIANAME TEXT)"
    )
    conn.execute(
        "INSERT INTO ZWAMEDIAITEM VALUES (10, '/media/photo.jpg', 45000, 'Meeting notes', 'photo.jpg')"
    )
    conn.execute(
        "CREATE TABLE ZWAMESSAGE (Z_PK INTEGER PRIMARY KEY, ZMESSAGEDATE REAL, ZTEXT TEXT, ZFROMJID TEXT, ZISFROMME INT, ZCHATSESSION INT, ZMEDIAITEM INT)"
    )
    conn.execute(
        "INSERT INTO ZWAMESSAGE VALUES (100, 700000000.0, 'Hello from WhatsApp!', '15551234567@s.whatsapp.net', 0, 1, NULL)"
    )
    conn.execute(
        "INSERT INTO ZWAMESSAGE VALUES (101, 700000060.0, 'Here is the doc', 'Me', 1, 1, 10)"
    )
    conn.commit()
    conn.close()

    res = whatsapp.parse(db_path)
    assert res["count"] == 2
    assert len(res["chats"]) == 1
    assert res["chats"][0]["name"] == "Alice Smith"
    msgs = res["messages"]
    assert msgs[0]["text"] == "Hello from WhatsApp!"
    assert msgs[0]["service"] == "WhatsApp"
    assert msgs[0]["from_me"] is False
    assert msgs[1]["from_me"] is True
    assert "Meeting notes" in msgs[1]["attachments"][0]


def test_telegram_parser(tmp_path):
    db_path = tmp_path / "tgdata.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, first_name TEXT, last_name TEXT, username TEXT, phone_number TEXT)"
    )
    conn.execute(
        "INSERT INTO users VALUES (42, 'Bob', 'Jones', 'bobjones', '+15559876543')"
    )
    conn.execute(
        "CREATE TABLE chats (id INTEGER PRIMARY KEY, title TEXT)"
    )
    conn.execute(
        "INSERT INTO chats VALUES (999, 'Operations Channel')"
    )
    conn.execute(
        "CREATE TABLE messages_v29 (mid INTEGER PRIMARY KEY, peer_id INT, date INT, message TEXT, out INT)"
    )
    conn.execute(
        "INSERT INTO messages_v29 VALUES (1, 42, 1726000000, 'Confidential update', 0)"
    )
    conn.execute(
        "INSERT INTO messages_v29 VALUES (2, 999, 1726000100, 'Broadcast message', 1)"
    )
    conn.commit()
    conn.close()

    res = telegram.parse(db_path)
    assert res["count"] == 2
    assert len(res["users"]) == 1
    assert res["users"][0]["name"] == "Bob Jones"
    msgs = res["messages"]
    assert msgs[0]["text"] == "Confidential update"
    assert msgs[0]["sender"] == "Bob Jones"
    assert msgs[0]["from_me"] is False
    assert msgs[1]["sender"] == "Me"
    assert msgs[1]["chat"] == "Operations Channel"
    assert msgs[1]["from_me"] is True


def test_signal_encryption_detection(tmp_path):
    # 1. Plaintext sqlite
    plain_db = tmp_path / "Signal_plain.sqlite"
    conn = sqlite3.connect(plain_db)
    conn.execute("CREATE TABLE test (id INT)")
    conn.commit()
    conn.close()

    info = signal.inspect_db_encryption(plain_db)
    assert info["encrypted"] is False
    assert info["type"] == "plaintext_sqlite"

    # 2. Simulated SQLCipher encrypted file (random salt)
    enc_db = tmp_path / "Signal_enc.sqlite"
    enc_db.write_bytes(b"\x12\x34\x56\x78" * 100)

    info_enc = signal.inspect_db_encryption(enc_db)
    assert info_enc["encrypted"] is True
    assert info_enc["type"] == "sqlcipher_encrypted"
    assert "salt_hex" in info_enc
    assert len(info_enc["salt_hex"]) == 32

    # Parse returns encrypted status gracefully
    res = signal.parse(enc_db)
    assert res["status"] == "encrypted"
    assert res["count"] == 0


def test_locations_parser(tmp_path):
    db_path = tmp_path / "consolidated.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE CellLocation (Latitude REAL, Longitude REAL, Timestamp REAL, Confidence REAL, MCC INT, MNC INT, LAC INT, CI INT)"
    )
    conn.execute(
        "INSERT INTO CellLocation VALUES (37.7749, -122.4194, 700000000.0, 95.0, 310, 410, 1234, 5678)"
    )
    conn.execute(
        "CREATE TABLE WifiLocation (MAC TEXT, Latitude REAL, Longitude REAL, Timestamp REAL, Confidence REAL, Channel INT)"
    )
    conn.execute(
        "INSERT INTO WifiLocation VALUES ('aa:bb:cc:dd:ee:ff', 37.7750, -122.4195, 700000010.0, 90.0, 6)"
    )
    conn.commit()
    conn.close()

    res = locations.parse(db_path)
    assert res["kind"] == "locationd"
    locs = res["locations"]
    assert len(locs) == 2
    assert locs[0]["latitude"] == 37.7749
    assert locs[0]["type"] == "CellTower"
    assert locs[1]["type"] == "WiFiAP"


def test_case_uco_ontology_export(tmp_path):
    artifacts = {
        "device": {"udid": "00008101-TEST12345678", "product": "iPhone 15 Pro", "serial": "DNQX123"},
        "messages": [{"text": "Investigation message", "date": "2026-09-18T10:00:00Z", "service": "SMS", "sender": "John"}],
        "whatsapp": [{"text": "WhatsApp message", "date": "2026-09-18T10:05:00Z", "sender": "Alice"}],
        "locations": [{"latitude": 40.7128, "longitude": -74.0060, "type": "CellTower"}],
    }
    uco_file = R.build_case_uco_report(artifacts, tmp_path)
    assert uco_file.exists()
    data = json.loads(uco_file.read_text())
    assert "@context" in data
    assert "uco-core" in data["@context"]
    assert "@graph" in data
    types = [obj.get("@type") for obj in data["@graph"]]
    assert "uco-observable:Device" in types
    assert "uco-observable:Message" in types
    assert "uco-observable:Location" in types


def test_bfu_sqlite_inspection(tmp_path):
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE foo (bar INT)")
    conn.commit()
    conn.close()

    info = B.inspect_bfu_sqlite(db_path)
    assert info["exists"] is True
    assert info["is_sqlite"] is True
    assert info["readable_header"] is True

    manifest_file = tmp_path / "bfu_manifest.json"
    B.export_bfu_manifest([{"rel": "test.db", "size": 4096}], manifest_file)
    assert manifest_file.exists()
    m_data = json.loads(manifest_file.read_text())
    assert m_data["total_files"] == 1


def test_triple_hash_certify(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "evidence.raw").write_bytes(b"forensic evidence bitstream triple hash test")
    out_dir = tmp_path / "certified_out"

    res = C.certify(case_dir, out_dir, examiner="Detective Miller")
    report = json.loads(Path(res["report"]).read_text())
    assert report["examiner"] == "Detective Miller"
    assert "attestation" in report
    assert "Detective Miller" in report["attestation"]

    file_entry = report["files"][0]
    assert "sha256" in file_entry
    assert "md5" in file_entry
    assert "sha1" in file_entry
    assert len(file_entry["sha256"]) == 64
    assert len(file_entry["md5"]) == 32
    assert len(file_entry["sha1"]) == 40
