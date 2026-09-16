"""Escrow acquisition + usbliter8 BFU plan tests."""

import plistlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from opensleuth import escrow, keybag as K


def mk_keybag(ktype=2, keys=((4, b"\xaa" * 32), (1, b"\xbb" * 32))):
    body = b"kbagic" + bytes([3, ktype]) + bytes(range(16))
    body += struct.pack("<I", len(keys))
    for pc, kb in keys:
        body += bytes(range(16, 32))
        body += struct.pack("<I", pc)
        body += struct.pack("<H", 1)
        body += bytes([0, pc])
        body += struct.pack("<II", 0, len(kb))
        body += kb
    return body


def make_record(path: Path, with_password: bool = True):
    path.parent.mkdir(parents=True, exist_ok=True)
    rec = {"EscrowRecords": [{"Keybag": mk_keybag(),
                              "DeviceName": "iPhone 11",
                              "Locked": False}]}
    if with_password:
        rec["EscrowRecords"][0]["EscrowPassword"] = "escrowed-pass-1"
    path.write_bytes(plistlib.dumps(rec))


class FindTest(unittest.TestCase):
    def test_finds_escrow_records_in_tree(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            make_record(d / "records" / "iPhone11-escrow.plist")
            (d / "notes.txt").write_text("no keybag here")
            found = escrow.find_records(d)
            self.assertEqual(len(found), 1)
            self.assertTrue(found[0]["path"].endswith("iPhone11-escrow.plist"))
            self.assertEqual(len(found[0]["keybags"]), 1)

    def test_finds_backup_keybag_blob(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "backupbag.kb").write_bytes(mk_keybag(1))
            found = escrow.find_records(d)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["keybags"][0]["type"], "backup")

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(escrow.find_records(td), [])

    def test_missing_dir(self):
        self.assertEqual(escrow.find_records("/nonexistent/xyz"), [])


class DescribeTest(unittest.TestCase):
    def test_describe_with_password(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rec.plist"
            make_record(p, with_password=True)
            d = escrow.describe(p)
            self.assertTrue(d["passcode_material"])
            self.assertEqual(d["keybags"][0]["type"], "escrow")
            self.assertGreaterEqual(d["keybags"][0]["usable_count"], 2)
            self.assertIn("EscrowPassword", d["passcode_material"]["field"])

    def test_describe_without_password(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rec.plist"
            make_record(p, with_password=False)
            d = escrow.describe(p)
            self.assertIsNone(d["passcode_material"])

    def test_describe_nonplist_raises(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rec.plist"
            p.write_bytes(b"<xml>broken")
            with self.assertRaises(K.KeybagError):
                escrow.describe(p)


class _FakeBackupDecrypt:
    def __init__(self, path):
        self.path = path

    def decrypt(self, out, password):
        assert password == "escrowed-pass-1"
        Path(out).mkdir(parents=True, exist_ok=True)
        (Path(out) / "Manifest.plist").write_text("{}")


class _FakePyiosbackup:
    BackupDecrypt = _FakeBackupDecrypt


class _FailPyiosbackup:
    class BackupDecrypt:
        def __init__(self, path):
            pass

        def decrypt(self, out, password):
            raise RuntimeError("pw rejected")


class UnlockTest(unittest.TestCase):
    def test_no_material_reports_honest(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rec.plist"
            make_record(p, with_password=False)
            with tempfile.TemporaryDirectory() as bd:
                r = escrow.unlock_backup(p, bd, td + "/out")
        self.assertFalse(r["ok"])
        self.assertIn("no passcode material", r["error"].lower())

    def test_no_keybags(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rec.plist"
            p.write_bytes(plistlib.dumps({"deviceName": "x"}))
            with tempfile.TemporaryDirectory() as bd:
                r = escrow.unlock_backup(p, bd, td + "/out")
        self.assertFalse(r["ok"])
        self.assertTrue("no keybags" in r["error"] or "unreadable" in r["error"])

    def test_pyiosbackup_missing(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rec.plist"
            make_record(p, with_password=True)
            with tempfile.TemporaryDirectory() as bd:
                import types
                r = escrow.unlock_backup(p, bd, td + "/out",
                                         pyiosbackup_module=types.ModuleType("x"))
        self.assertFalse(r["ok"])
        self.assertIn("no BackupDecrypt", r["error"])

    def test_unlock_with_material_succeeds(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rec.plist"
            make_record(p, with_password=True)
            bd_dir = Path(td) / "backup"
            bd_dir.mkdir()
            r = escrow.unlock_backup(p, bd_dir, Path(td) / "out",
                                     pyiosbackup_module=_FakePyiosbackup)
            self.assertTrue(r["ok"])
            self.assertTrue((Path(r["decrypted"]) / "Manifest.plist").exists())
        # end of tempdir scope

    def test_unlock_sanitizes_password_from_report(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rec.plist"
            make_record(p, with_password=True)
            bd_dir = Path(td) / "backup"
            bd_dir.mkdir()
            r = escrow.unlock_backup(p, bd_dir, td + "/out",
                                     pyiosbackup_module=_FailPyiosbackup)
        self.assertFalse(r["ok"])
        blob = str(r)
        self.assertNotIn("escrowed-pass-1", blob)


class RenderTest(unittest.TestCase):
    def test_render_find_empty(self):
        self.assertIn("no escrow", escrow.render_find([]))

    def test_render_describe(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rec.plist"
            make_record(p, with_password=True)
            out = escrow.render_describe(escrow.describe(p))
            self.assertIn("passcode material: YES", out)
            self.assertIn("+", out)


class Usbliter8PlanTest(unittest.TestCase):
    def test_eligible_a13(self):
        from opensleuth.bfu import usbliter8_plan
        p = usbliter8_plan("A13")
        self.assertTrue(p["eligible"])
        self.assertEqual(p["route"], "usbliter8")
        self.assertGreaterEqual(len(p["steps"]), 7)
        self.assertIn("SEP", p["sep_wall"])

    def test_not_eligible_a18(self):
        from opensleuth.bfu import usbliter8_plan
        p = usbliter8_plan("A18")
        self.assertFalse(p["eligible"])
        self.assertIn("NOT ELIGIBLE", p["route"])

    def test_render_playbook(self):
        from opensleuth.bfu import render_usbliter8_plan
        out = render_usbliter8_plan("A13")
        self.assertIn("PWND:[usbliter8]", out)
        self.assertIn("ramdisk", out)
        self.assertIn("escrow", out.lower())
        self.assertIn("SEP wall", out)

    def test_render_no_route_points_to_escrow(self):
        from opensleuth.bfu import render_usbliter8_plan
        out = render_usbliter8_plan("A18")
        self.assertIn("opensleuth escrow", out)


if __name__ == "__main__":
    unittest.main()

class SweepTest(unittest.TestCase):
    def test_sweep_no_backup_reports(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            p = d / "records"
            p.mkdir()
            make_record(p / "rec.plist", with_password=False)
            with tempfile.TemporaryDirectory() as od:
                r = escrow.sweep(d, od)
        self.assertEqual(r["records"], 1)
        self.assertEqual(r["backups"], 0)
        self.assertEqual(r["attempts"][0]["status"], "no-backup")

    def test_sweep_attempts_unlock_against_sibling_backup(self):
        class FailPy:
            class BackupDecrypt:
                def __init__(self, path): pass
                def decrypt(self, out, password):
                    raise RuntimeError("pw rejected")
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            p = d / "records"
            p.mkdir()
            make_record(p / "rec.plist", with_password=True)
            b = d / "backups" / "UDID"
            b.mkdir(parents=True)
            (b / "Manifest.plist").write_text("{}")
            with tempfile.TemporaryDirectory() as od:
                r = escrow.sweep(d, od, pyiosbackup_module=FailPy)
                self.assertEqual(r["records"], 1)
                self.assertEqual(r["backups"], 1)
                self.assertEqual(len(r["attempts"]), 1)
                self.assertIn("pw rejected", r["attempts"][0]["status"])
                sweep_json = Path(r["out"])
                self.assertTrue(sweep_json.exists())

    def test_render_sweep(self):
        res = {"records": 1, "backups": 1,
               "attempts": [{"record": "/r.plist", "backup": "/b",
                             "status": "unlocked", "classes": ["NSFileProtectionNone"]}],
               "out": "/tmp/x.json"}
        out = escrow.render_sweep(res)
        self.assertIn("passcode-free unlocks: 1/1", out)
        self.assertIn("NSFileProtectionNone", out)


class BfuGapStanceTest(unittest.TestCase):
    def test_stance_has_gap_lines(self):
        from opensleuth import forensics as F
        out = F.render_stance()
        self.assertIn("where CoreProbe needs work to beat them", out)
        self.assertIn("ARTIFACT BREADTH", out)
        self.assertIn("COURT-READY REPORTING", out)
        self.assertIn("BFU PASSCODE BYPASS", out)
