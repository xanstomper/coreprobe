"""BFU filesystem intelligence + backup keybag tests."""

import base64
import os
import plistlib
import struct
import tempfile
from pathlib import Path

import pytest

from opensleuth import bfufs as B
from opensleuth import keybag as K


def _mkbag(ktype=1, keys=((1, b"\x01" * 32), (4, b"\xaa" * 32))):
    body = b"kbagic" + bytes([3, ktype]) + bytes(range(16)) + struct.pack("<I", len(keys))
    for pc, kb in keys:
        body += bytes(range(16, 32)) + struct.pack("<I", pc) + struct.pack("<H", 1)
        body += bytes([0, pc]) + struct.pack("<II", 0, len(kb)) + kb
    return body


@pytest.fixture
def fs_tree(tmp_path):
    (tmp_path / "Documents").mkdir()
    (tmp_path / "Library/SMS").mkdir(parents=True)
    (tmp_path / "Media/DCIM/100APPLE").mkdir(parents=True)

    def mkf(rel, klass, data):
        p = tmp_path / rel
        p.write_bytes(data)
        os.setxattr(p, "user.com.apple.system.cprotect", bytes([3, klass]))

    mkf("Documents/notes.txt", 1, b"readable")
    mkf("Library/SMS/sms.db", 4, b"enc")
    mkf("Media/DCIM/100APPLE/a.JPG", 2, b"enc")
    return tmp_path


def test_scan_fs_reads_xattrs(fs_tree):
    rows = B.scan_fs(fs_tree)
    byrel = {r["rel"]: r for r in rows}
    assert byrel["Documents/notes.txt"]["class"] == 1
    assert byrel["Library/SMS/sms.db"]["class"] == 4
    assert byrel["Media/DCIM/100APPLE/a.JPG"]["class"] == 2


def test_scan_no_xattr(tmp_path):
    (tmp_path / "x.txt").write_text("x")
    rows = B.scan_fs(tmp_path)
    assert rows[0]["class"] is None
    assert rows[0]["class_name"] == "no-xattr"


def test_classify_counts_and_interest(fs_tree):
    rows = B.scan_fs(fs_tree)
    rep = B.classify(rows)
    assert rep["total_files"] == 3
    assert rep["content_readable"] == 1
    assert rep["metadata_visible"] == 1
    assert rep["by_interest"]["comm-logs"] == 1
    assert rep["by_interest"]["media"] == 1
    assert rep["readable_now"][0]["rel"] == "Documents/notes.txt"


def test_classify_empty():
    rep = B.classify([])
    assert rep["total_files"] == 0


def test_render_report():
    rep = B.classify([
        {"rel": "a.txt", "size": 5, "class": 1, "class_name": "None",
         "readable_now": True, "metadata_only": False, "interest": None},
    ])
    out = B.render_report(rep)
    assert "CONTENT readable at BFU" in out
    assert "a.txt" in out
    assert "plaintext at BFU" in out


def test_interest_patterns():
    assert B._interest("Library/SMS/sms.db") == "comm-logs"
    assert B._interest("Media/DCIM/x.JPG") == "media"
    assert B._interest("Library/Keychains/k") == "keychain/keys"
    assert B._interest("random/file") is None


def test_backupbag_b64_manifest(tmp_path):
    bag = _mkbag()
    manifest = {"BackupKeyBag": base64.b64encode(bag).decode(),
                "IsEncrypted": True, "BackupManifestVersion": 2}
    p = tmp_path / "Manifest.plist"
    p.write_bytes(plistlib.dumps(manifest))
    bags = K.escrow_keybags(p)
    assert len(bags) == 1
    assert bags[0]["type_name"] == "backup"
    assert bags[0]["num_keys"] == 2


def test_backupbag_raw_bytes_manifest(tmp_path):
    p = tmp_path / "Manifest.plist"
    p.write_bytes(plistlib.dumps({"BackupKeyBag": _mkbag()}))
    bags = K.escrow_keybags(p)
    assert len(bags) == 1


def test_backupbag_without_keybag_fails(tmp_path):
    p = tmp_path / "Manifest.plist"
    p.write_bytes(plistlib.dumps({"BackupManifestVersion": 2}))
    with pytest.raises(K.KeybagError):
        K.escrow_keybags(p)


def test_bfufs_render_json_shape(fs_tree, capsys):
    import json
    from opensleuth import cli
    args = type("A", (), {"dir": str(fs_tree), "json": True})()
    # call handler directly
    cli.cmd_bfufs(args)
    out = capsys.readouterr().out
    d = json.loads(out)
    assert d["total_files"] == 3
    assert d["by_interest"]["media"] == 1