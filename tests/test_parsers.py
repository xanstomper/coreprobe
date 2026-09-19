"""Parser framework tests: hostile input never crashes a case; provenance
envelope (parser/version/source/warnings) always present."""

import sqlite3

from opensleuth.parsers import safe_parse, PARSER_FRAMEWORK_VERSION


def _good_sms_parser(path):
    # mirrors opensleuth.artifacts.sms.parse against a minimal valid schema
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT text, date FROM message ORDER BY date").fetchall()
        return {"messages": [dict(r) for r in rows], "count": len(rows)}
    finally:
        conn.close()


def _make_db(path, table_sql, insert_sql):
    conn = sqlite3.connect(path)
    conn.execute(table_sql)
    conn.execute(insert_sql)
    conn.commit()
    conn.close()


class TestHostileInput:
    def test_missing_file(self, tmp_path):
        r = safe_parse("sms", "1", "sqlite", _good_sms_parser,
                       tmp_path / "nope.db")
        assert r.ok is False
        assert r.error_kind == "OSError"
        assert "not found" in r.error

    def test_garbage_bytes(self, tmp_path):
        f = tmp_path / "garbage.db"
        f.write_bytes(b"\x00garbage")
        r = safe_parse("sms", "1", "sqlite", _good_sms_parser, f)
        assert r.ok is False
        assert r.error_kind == "DatabaseError"
        assert "malformed database" in r.error

    def test_wrong_schema(self, tmp_path):
        f = tmp_path / "wrong.db"
        _make_db(f, "CREATE TABLE foo (bar TEXT)", "INSERT INTO foo VALUES ('x')")
        r = safe_parse("sms", "1", "sqlite", _good_sms_parser, f)
        assert r.ok is False
        assert r.error_kind == "OperationalError"
        assert "schema mismatch" in r.error

    def test_unexpected_exception_contained(self, tmp_path):
        def boom(path):
            raise RuntimeError("kaboom")
        r = safe_parse("x", "1", "sqlite", boom, tmp_path / "whatever")
        assert r.ok is False
        assert r.error_kind == "RuntimeError"
        assert "kaboom" in r.error

    def test_non_dict_return_rejected(self, tmp_path):
        f = tmp_path / "a.db"
        f.write_bytes(b"")
        r = safe_parse("x", "1", "sqlite", lambda p: [1, 2, 3], f)
        assert r.ok is False
        assert r.error_kind == "TypeError"

    def test_empty_valid_source_warns_but_ok(self, tmp_path):
        f = tmp_path / "empty.db"
        _make_db(f, "CREATE TABLE message (text TEXT, date INTEGER)",
                 "DELETE FROM message")
        r = safe_parse("sms", "1", "sqlite", _good_sms_parser, f)
        assert r.ok is True
        assert any("zero rows" in w for w in r.warnings)

    def test_huge_result_truncated(self, tmp_path):
        f = tmp_path / "big.db"
        conn = sqlite3.connect(f)
        conn.execute("CREATE TABLE message (text TEXT, date INTEGER)")
        conn.executemany("INSERT INTO message VALUES (?, ?)",
                         [("m", i) for i in range(500)])
        conn.commit()
        conn.close()
        r = safe_parse("sms", "1", "sqlite", _good_sms_parser, f,
                       max_rows=100)
        assert r.ok is True
        assert len(r.data["messages"]) == 100
        assert any("truncated" in w for w in r.warnings)


class TestProvenance:
    def test_envelope_fields_always_present(self, tmp_path):
        f = tmp_path / "m.db"
        _make_db(f, "CREATE TABLE message (text TEXT, date INTEGER)",
                 "INSERT INTO message VALUES ('hi', 1)")
        r = safe_parse("sms", "1.4", "sqlite", _good_sms_parser, f)
        d = r.to_dict()
        for k in ("parser", "parser_version", "framework_version",
                  "source_format", "source_path", "extracted_at", "ok",
                  "warnings", "error", "interpretations"):
            assert k in d, k
        assert d["parser"] == "sms"
        assert d["framework_version"] == PARSER_FRAMEWORK_VERSION
        assert d["data"]["count"] == 1

    def test_provenance_survives_failure(self, tmp_path):
        r = safe_parse("sms", "1", "sqlite", _good_sms_parser,
                       tmp_path / "gone.db")
        d = r.to_dict()
        assert d["ok"] is False
        assert d["parser"] == "sms" and d["source_path"].endswith("gone.db")
