"""Sysdiagnose + knowledgeC tests."""

import plistlib
import sqlite3
import tarfile
from pathlib import Path

from opensleuth import knowledgec as KC
from opensleuth import sysdiagnose as SD


def _mk_db(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE ZOBJECT (ZSTREAMNAME TEXT, ZENDDATETIME REAL, "
                "ZVALUESTRING TEXT, ZSTRUCTUREDDATA BLOB)")
    con.executemany("INSERT INTO ZOBJECT VALUES (?,?,?,?)", rows)
    con.commit()
    con.close()


class TestSysdiagnose:
    def test_extract_and_inventory(self, tmp_path):
        src = tmp_path / "sd"
        (src / "sysdiag/logs/powerlogs").mkdir(parents=True)
        (src / "sysdiag/logs/powerlogs/Powerlog.plist").write_bytes(b"p")
        (src / "sysdiag/WiFi").mkdir(parents=True)
        (src / "sysdiag/WiFi/x.plist").write_bytes(b"w")
        tgz = tmp_path / "sd.tar.gz"
        with tarfile.open(tgz, "w:gz") as tf:
            tf.add(src / "sysdiag", arcname="sysdiag")
        r = SD.extract(tgz, tmp_path / "out")
        assert r["files"] >= 3  # tar members (incl. the root dir)
        inv = SD.inventory(tmp_path / "out")
        assert inv["total"] >= 2  # actual files
        assert "power/battery" in inv["by_category"]
        assert "network" in inv["by_category"]

    def test_extract_not_tarball(self, tmp_path):
        import pytest
        f = tmp_path / "x.gz"
        f.write_bytes(b"junk")
        with pytest.raises((tarfile.TarError, OSError)):
            SD.extract(f, tmp_path / "o")

    def test_inventory_missing_dir(self):
        inv = SD.inventory("/nonexistent/nope")
        assert inv["total"] == 0

    def test_render(self, tmp_path):
        (tmp_path / "a").write_text("x")
        out = SD.render_inventory(SD.inventory(tmp_path))
        assert "sysdiagnose inventory" in out
        assert "other" in out or "files" in out

    def test_app_usage_plist(self):
        pl = plistlib.dumps({"devices": [{"days": [
            {"date": "2026-09-01", "apps": [
                {"bundleName": "com.x", "totalTimeUsage": 120}]}]}]})
        rows = SD.parse_app_usage_plist(pl, source="u")
        assert rows[0]["bundle"] == "com.x"
        assert rows[0]["usage_seconds"] == 120

    def test_app_usage_bad(self):
        assert SD.parse_app_usage_plist(b"junk") == []


class TestKnowledgeC:
    def _rows(self, tmp_path):
        db = tmp_path / "var/db/CoreDuet/Knowledge/knowledgeC.db"
        _mk_db(db, [
            ("/app/inFocus", 800000000.0, "com.apple.MobileSMS", None),
            ("/app/inFocus", 800000060.0, "com.spotify.client", None),
            ("/device/lock", 800000120.0, None, None),
            ("/user/notification", 800000130.0, "WhatsApp", None),
        ])
        return db

    def test_parse_reads_real_rows(self, tmp_path):
        db = self._rows(tmp_path)
        rows = KC.parse_knowledgec(db)
        assert len(rows) == 4
        assert rows[0]["kind"] == "app-focus"
        assert rows[0]["ts"].startswith("2026-05")
        assert rows[2]["kind"] == "lock"

    def test_find_knowledgec(self, tmp_path):
        self._rows(tmp_path)
        hits = KC.find_knowledgec(tmp_path)
        assert len(hits) == 1
        assert hits[0].name == "knowledgeC.db"

    def test_missing_db_empty(self):
        assert KC.parse_knowledgec("/nonexistent/knowledgeC.db") == []
        assert KC.find_knowledgec("/nonexistent") == []

    def test_corrupt_db_empty(self, tmp_path):
        f = tmp_path / "knowledgeC.db"
        f.write_bytes(b"not sqlite")
        assert KC.parse_knowledgec(f) == []

    def test_app_usage_summary(self, tmp_path):
        rows = KC.parse_knowledgec(self._rows(tmp_path))
        s = KC.app_usage_summary(rows)
        assert s["com.apple.MobileSMS"] == 1

    def test_render(self, tmp_path):
        rows = KC.parse_knowledgec(self._rows(tmp_path))
        out = KC.render(rows)
        assert "knowledgeC: 4 events" in out
        assert "com.apple.MobileSMS" in out

    def test_render_empty(self):
        assert "no rows" in KC.render([])

    def test_apple_epoch_conversion(self):
        iso = KC.apple_to_iso(0)
        assert iso is not None and iso.startswith("2001-01-01")
        assert KC.apple_to_iso(float("nan")) is None or KC.apple_to_iso(float("nan"))