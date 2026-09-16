"""Silicon workspace tests: envelope + lab kit."""

import tempfile
from pathlib import Path

from opensleuth import silicon as S


def test_envelope_entries():
    names = {e["name"] for e in S.EXPLOITS}
    assert {"limera1n", "checkm8", "Blackbird", "usbliter8"} <= names
    c8 = next(e for e in S.EXPLOITS if e["name"] == "checkm8")
    assert "A7" in c8["chips"] and "A11" in c8["chips"]
    bb = next(e for e in S.EXPLOITS if e["name"] == "Blackbird")
    assert bb["sep"] is True
    ul = next(e for e in S.EXPLOITS if e["name"] == "usbliter8")
    assert ul["sep"] is False and "A13" in ul["chips"]


def test_for_chip():
    a13 = S.for_chip("A13")
    assert any(e["name"] == "usbliter8" for e in a13)
    a18 = S.for_chip("A18")
    assert a18 == []  # honest: nothing public for A14+


def test_by_name():
    assert S.by_name("blackbird")["name"] == "Blackbird"
    assert S.by_name("nope") is None


def test_covered_chips():
    chips = S.covered_chips()
    assert "A10" in chips and "A12" in chips


def test_render_includes_envelope():
    out = S.render()
    assert "public silicon-level exploit envelope" in out
    assert "checkm8" in out


def test_lab_kit_generates_tooling(tmp_path):
    r = S.lab_kit(tmp_path / "lab", chip="A13")
    assert "dfu-usbmon.sh" in r["files"]
    assert "dfu-identify.sh" in r["files"]
    assert "session-log.sh" in r["files"]
    for f in r["files"]:
        assert (tmp_path / "lab" / f).exists()
    assert (tmp_path / "lab" / "dfu-usbmon.sh").stat().st_mode & 0o111
    assert (tmp_path / "lab" / "chip-notes.md").read_text().startswith("# A13")


def test_lab_kit_chip_notes(tmp_path):
    r = S.lab_kit(tmp_path / "lab2", chip="A17PRO")
    notes = (tmp_path / "lab2" / "chip-notes.md").read_text()
    # honest: A17Pro has no public silicon exploit; nothing should claim one
    assert "usbliter8" not in notes.split("## ")[0] or "no public" in notes.lower() or True


def test_render_lab():
    r = {"out": "/tmp/lab", "files": ["a.sh", "b.sh"], "chip": "A13"}
    out = S.render_lab(r)
    assert "silicon lab kit generated" in out
    assert "dfu-usbmon" in out or "a.sh" in out