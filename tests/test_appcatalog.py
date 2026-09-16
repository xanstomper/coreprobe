"""App artifact breadth tests: catalog, sqlite discovery, extraction."""

import csv
import sqlite3
from pathlib import Path

from opensleuth import appcatalog as A


def _mkdb(path: Path, tables: dict[str, list[tuple]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    for name, rows in tables.items():
        if not rows:
            continue
        cols = ", ".join(f'"{c}"' for c in rows[0])
        con.execute(f'CREATE TABLE "{name}" ({cols})')
        for r in rows[1:]:
            con.execute(f'INSERT INTO "{name}" VALUES ({",".join("?" * len(r))})', r)
    con.commit()
    con.close()


def test_catalog_breadth():
    assert len(A.APP_CATALOG) >= 40
    bundles = [e["bundle"] for e in A.APP_CATALOG]
    assert len(bundles) == len(set(bundles)), "duplicate bundles"
    confs = {e["confidence"] for e in A.APP_CATALOG}
    assert confs <= {"high", "med", "low"}
    # well-known apps present
    names = {e["app"] for e in A.APP_CATALOG}
    for expect in ("WhatsApp", "Telegram", "Signal", "Chrome", "TikTok",
                   "Instagram", "Snapchat", "Health", "Tinder", "Venmo"):
        assert any(n == expect or n.startswith(expect) for n in names), expect


def test_match_app_whatsapp():
    assert A.match_app("net.whatsapp.WhatsApp/Library/Application Support/chatstorage.sqlite") == "WhatsApp"


def test_match_app_generic_returns_none():
    assert A.match_app("ABC123/Documents/random.sqlite") is None


def test_find_dbs(tmp_path):
    _mkdb(tmp_path / "net.whatsapp.WhatsApp/Library/Application Support/chatstorage.sqlite",
          {"ZWAMESSAGE": [("ZTEXT",), ("hello",)]})
    _mkdb(tmp_path / "UUID/Documents/app.sqlite",
          {"things": [("id", "val"), (1, "x")]})
    (tmp_path / "UUID/Documents/history.sqlite-wal").write_bytes(b"wal")
    dbs = A.find_dbs(tmp_path)
    assert len(dbs) == 2
    wa = [d for d in dbs if d["app"] == "WhatsApp"]
    assert len(wa) == 1
    assert wa[0]["rel"].endswith("chatstorage.sqlite")
    assert all(not d["rel"].endswith("-wal") for d in dbs)


def test_inventory_reports_tables_and_rows(tmp_path):
    db = tmp_path / "app.sqlite"
    _mkdb(db, {"messages": [("id", "text"), (1, "hi")], "users": [("uid",)]})
    info = A.inventory(db)
    assert info is not None
    by = {t["table"]: t for t in info["tables"]}
    assert by["messages"]["rows"] == 1
    assert "text" in by["messages"]["columns"]
    assert by["users"]["rows"] == 0


def test_extract_table_to_csv(tmp_path):
    db = tmp_path / "app.sqlite"
    _mkdb(db, {"messages": [("id", "text", "ts"), (1, "hello", 100), (2, "bye", 200)]})
    out = tmp_path / "out.csv"
    r = A.extract_table(db, "messages", out)
    assert r["ok"] and r["rows"] == 2
    with open(out) as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == ["id", "text", "ts"]
    assert rows[1] == ["1", "hello", "100"]


def test_extract_where_and_limit(tmp_path):
    db = tmp_path / "app.sqlite"
    _mkdb(db, {"messages": [("id", "text"), (1, "a"), (2, "b"), (3, "c")]})
    out = tmp_path / "o.csv"
    r = A.extract_table(db, "messages", out, where='text = "b"')
    assert r["rows"] == 1
    r2 = A.extract_table(db, "messages", out, limit=2)
    assert r2["rows"] == 2


def test_extract_missing_table(tmp_path):
    db = tmp_path / "app.sqlite"
    _mkdb(db, {"messages": [("id",)]})
    r = A.extract_table(db, "nope", tmp_path / "o.csv")
    assert not r["ok"]


def test_inventory_unreadable(tmp_path):
    junk = tmp_path / "fake.db"
    junk.write_bytes(b"not a sqlite db at all")
    assert A.inventory(junk) is None


def test_render_list_has_apps_and_hint():
    out = A.render_list()
    assert "44 apps" in out or " apps" in out
    assert "WhatsApp" in out
    assert "inventory:" in out


def test_render_inventory_empty():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        out = A.render_inventory(Path(td))
    assert "no sqlite-family databases" in out