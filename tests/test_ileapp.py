"""iLEAPP integration tests."""

import tempfile
from pathlib import Path
from unittest import mock

from opensleuth import ileapp as I


def test_find_ileapp_on_path():
    with mock.patch("opensleuth.ileapp.shutil.which", return_value="/usr/local/bin/iLEAPP"):
        assert I.find_iLEAPP() == "/usr/local/bin/iLEAPP"


def test_find_ileapp_in_home(tmp_path, monkeypatch):
    (tmp_path / "iLEAPP" / "iLEAPP.py").parent.mkdir()
    (tmp_path / "iLEAPP" / "iLEAPP.py").write_text("")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    with mock.patch("opensleuth.ileapp.shutil.which", return_value=None):
        found = I.find_iLEAPP()
    assert found is not None and found.endswith("iLEAPP.py")


def test_find_ileapp_env_dir(tmp_path, monkeypatch):
    d = tmp_path / "tools" / "iLEAPP"
    d.mkdir(parents=True)
    (d / "iLEAPP.py").write_text("")
    monkeypatch.setenv("ILEAPP_DIR", str(d))
    with mock.patch("opensleuth.ileapp.shutil.which", return_value=None), \
         mock.patch("opensleuth.ileapp.Path.home", return_value=tmp_path):
        assert I.find_iLEAPP() == str(d / "iLEAPP.py")


def test_run_missing_ileapp_reports_install_hint(tmp_path):
    with mock.patch("opensleuth.ileapp.find_iLEAPP", return_value=None):
        r = I.run_iLEAPP(tmp_path, tmp_path / "out")
    assert not r["ok"]
    assert "Install it first" in r["error"]


def test_run_missing_input(tmp_path):
    with mock.patch("opensleuth.ileapp.find_iLEAPP", return_value="/tmp/iLEAPP.py"):
        r = I.run_iLEAPP(tmp_path / "nope", tmp_path / "out")
    assert not r["ok"]
    assert "does not exist" in r["error"]


def test_run_success(tmp_path):
    src = tmp_path / "extract"
    src.mkdir()
    (src / "f.txt").write_text("x")
    with mock.patch("opensleuth.ileapp.find_iLEAPP", return_value=str(tmp_path / "iLEAPP.py")):
        with mock.patch("opensleuth.ileapp.subprocess.run") as run:
            run.return_value = type("R", (), {"returncode": 0, "stdout": "done", "stderr": ""})()
            r = I.run_iLEAPP(src, tmp_path / "out")
    assert r["ok"]
    cmd = run.call_args.args[0]
    assert "-t" in cmd and "fs" in cmd and "-i" in cmd and str(src) in cmd


def test_run_timeout(tmp_path):
    from subprocess import TimeoutExpired
    src = tmp_path / "extract"
    src.mkdir()
    with mock.patch("opensleuth.ileapp.find_iLEAPP", return_value="iLEAPP"):
        with mock.patch("opensleuth.ileapp.subprocess.run",
                        side_effect=TimeoutExpired("iLEAPP", 30)):
            r = I.run_iLEAPP(src, tmp_path / "out", timeout=30)
    assert not r["ok"]
    assert "timed out" in r["error"]


def test_breath_report_merges(tmp_path):
    case = tmp_path / "case"
    (case / "net.whatsapp.WhatsApp/Library/Application Support").mkdir(parents=True)
    db = case / "net.whatsapp.WhatsApp/Library/Application Support/chatstorage.sqlite"
    import sqlite3
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE ZWAMESSAGE (ZTEXT TEXT)")
    con.commit()
    con.close()
    ile = tmp_path / "ileout"
    ile.mkdir()
    (ile / "report.html").write_text("")
    out = tmp_path / "out"
    r = I.breath_report(case, ile, out)
    assert r["engine"]["coreprobe"] == 1
    assert r["engine"]["ileapp"] == 1
    assert (out / "breath-report.json").exists()
    assert "WhatsApp" in r["coreprobe_databases"][0]["app"]


def test_breath_report_without_ileapp(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    (case / "x.txt").write_text("x")
    r = I.breath_report(case, None, tmp_path / "out2")
    assert r["engine"]["coreprobe"] == 0
    assert r["ileapp_outputs"] == []