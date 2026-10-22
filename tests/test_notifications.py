"""DuetExpertCenter notificationAndSuggestionDB.db parser tests.

The synthetic schema below mirrors tests/fixture.py::build_notifications:
plausible-but-synthetic (the real schema is undocumented and varies by
iOS build, which is exactly why the parser introspects tables/columns at
runtime instead of hardcoding either). Timestamps use the fixture's
APPLE_NOW convention (Apple-epoch seconds).
"""

import importlib.util
import sqlite3
from pathlib import Path

from opensleuth.artifacts import notifications as N
from opensleuth.timeline import from_backup_artifacts
from opensleuth.util import apple_to_dt

# Load tests/fixture.py by path (the tests package has no __init__.py and
# other test modules deliberately avoid importing it as a package).
_spec = importlib.util.spec_from_file_location(
    "cp_fixture", Path(__file__).with_name("fixture.py"))
_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)
APPLE_NOW = _fixture.APPLE_NOW
build_notifications = _fixture.build_notifications

# Apps "installed" on the synthetic device. com.example.deletedapp is
# deliberately absent: its notifications must still be returned.
INSTALLED_BUNDLES = {"net.whatsapp.WhatsApp", "org.whispersystems.signal",
                     "com.apple.MobileSMS", "com.apple.mobilephone"}


def _rows(tmp_path):
    db = tmp_path / "notificationAndSuggestionDB.db"
    build_notifications(db)
    return N.parse(db)


class TestExtraction:
    def test_all_rows_extracted(self, tmp_path):
        rows = _rows(tmp_path)
        assert len(rows) == 3
        by_bundle = {r["bundle_id"]: r for r in rows}
        wa = by_bundle["net.whatsapp.WhatsApp"]
        assert wa["sender"] == "+15551234567"
        assert wa["thread_id"] == "15551234567@s.whatsapp.net"
        assert wa["title"] == "Sarah Chen"
        assert wa["body"] == "running late, 10 mins"
        assert wa["type"] == "notification"
        assert wa["source_db"] == "notificationAndSuggestionDB.db"

    def test_deleted_app_rows_still_returned(self, tmp_path):
        rows = _rows(tmp_path)
        ghost = [r for r in rows if r["bundle_id"] == "com.example.deletedapp"]
        assert len(ghost) == 1
        assert ghost[0]["bundle_id"] not in INSTALLED_BUNDLES
        assert ghost[0]["sender"] == "+15550001111"
        assert ghost[0]["body"] == "this app was uninstalled"

    def test_timestamp_conversion_seconds(self, tmp_path):
        rows = _rows(tmp_path)
        wa = next(r for r in rows if r["bundle_id"] == "net.whatsapp.WhatsApp")
        assert wa["date"] == apple_to_dt(APPLE_NOW - 3600)

    def test_timestamp_conversion_nanoseconds(self, tmp_path):
        # fixture stores the deleted-app row's timestamp in ns
        rows = _rows(tmp_path)
        ghost = next(r for r in rows
                     if r["bundle_id"] == "com.example.deletedapp")
        assert ghost["date"] == apple_to_dt(APPLE_NOW - 900)

    def test_rows_sorted_by_timestamp(self, tmp_path):
        rows = _rows(tmp_path)
        dates = [r["date"] for r in rows]
        assert dates == sorted(dates)

    def test_timeline_compatible(self, tmp_path):
        rows = _rows(tmp_path)
        events = from_backup_artifacts({"notifications": rows})
        assert len(events) == 3
        assert all(e["source"] == "notifications" for e in events)
        ghost = next(e for e in events if "Ghost" in e["text"]
                     or "uninstalled" in e["text"])
        assert ghost["who"] == "+15550001111"


class TestDefensive:
    def test_missing_db_returns_empty_cleanly(self, tmp_path):
        rows, warnings = N.parse_with_warnings(tmp_path / "nope.db")
        assert rows == []
        assert warnings  # a warning, not silence
        assert N.parse(tmp_path / "nope.db") == []

    def test_unknown_schema_returns_empty_with_warning(self, tmp_path):
        db = tmp_path / "other.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE somethingelse (a TEXT, b INTEGER)")
        conn.execute("INSERT INTO somethingelse VALUES ('x', 1)")
        conn.commit()
        conn.close()
        rows, warnings = N.parse_with_warnings(db)
        assert rows == []
        assert any("no notification table recognized" in w for w in warnings)
        assert N.parse(db) == []

    def test_garbage_file_returns_empty(self, tmp_path):
        db = tmp_path / "garbage.db"
        db.write_bytes(b"\x00garbage-not-a-database")
        rows, warnings = N.parse_with_warnings(db)
        assert rows == []
        assert warnings

    def test_schema_without_body_columns(self, tmp_path):
        # Older/redacted build: metadata only, no title/body columns.
        db = tmp_path / "meta.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE notifications (bundle_id TEXT, "
                     "timestamp REAL, thread_id TEXT, sender TEXT)")
        conn.execute("INSERT INTO notifications VALUES "
                     "('com.apple.MobileSMS', ?, 't-1', '+15551234567')",
                     (APPLE_NOW - 60,))
        conn.commit()
        conn.close()
        rows = N.parse(db)
        assert len(rows) == 1
        assert rows[0]["bundle_id"] == "com.apple.MobileSMS"
        assert rows[0]["title"] == "" and rows[0]["body"] == ""
        assert rows[0]["summary"]  # falls back to a bundle-based summary
        assert rows[0]["date"] == apple_to_dt(APPLE_NOW - 60)

    def test_alternate_table_and_column_names(self, tmp_path):
        # A differently-shaped build: snake_case, different table name.
        db = tmp_path / "alt.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE notification_suggestions "
                     "(bundle_identifier TEXT, delivered_date REAL, "
                     "topic TEXT, contact_id TEXT, subject TEXT, alert TEXT)")
        conn.execute("INSERT INTO notification_suggestions VALUES "
                     "('com.apple.mobilephone', ?, 'call-thread', "
                     "'+15559876543', 'Missed call', 'Voicemail waiting')",
                     (APPLE_NOW - 120,))
        conn.commit()
        conn.close()
        rows = N.parse(db)
        assert len(rows) == 1
        r = rows[0]
        assert r["bundle_id"] == "com.apple.mobilephone"
        assert r["thread_id"] == "call-thread"
        assert r["sender"] == "+15559876543"
        assert r["title"] == "Missed call"
        assert r["body"] == "Voicemail waiting"
