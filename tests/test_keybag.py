"""Keybag parsing + BFU analysis tests (public kbagic layout)."""

import plistlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from opensleuth import keybag as K


def mk_keybag(ktype: int = 0, keys=()):
    """Craft a kbagic binary per the documented layout."""
    body = b"kbagic" + bytes([3, ktype]) + bytes(range(16))
    body += struct.pack("<I", len(keys))
    for pc, kb in keys:
        body += bytes(range(16, 32))            # key uuid 16B
        body += struct.pack("<I", pc)           # class (u32le)
        body += struct.pack("<H", 1)            # type (u16le)
        body += bytes([0])                      # wipe
        body += bytes([pc])                     # prot_class
        body += struct.pack("<II", 0, len(kb))  # keyflags + keylen
        body += kb
    return body


class ParseTest(unittest.TestCase):
    def test_parse_system_bag(self):
        bag = K.parse_keybag(mk_keybag(0, [(0, b"\x01" * 32), (4, b"\xaa" * 32)]))
        self.assertEqual(bag["type_name"], "system")
        self.assertEqual(bag["version"], 3)
        self.assertEqual(bag["num_keys"], 2)
        self.assertEqual(len(bag["keys"]), 2)

    def test_parse_escrow_type(self):
        bag = K.parse_keybag(mk_keybag(2, []))
        self.assertEqual(bag["type_name"], "escrow")

    def test_rejects_non_kbagic(self):
        with self.assertRaises(K.KeybagError):
            K.parse_keybag(b"not-a-keybag")

    def test_rejects_truncated_header(self):
        with self.assertRaises(K.KeybagError):
            K.parse_keybag(b"kbagic" + b"\x03")

    def test_lenient_truncated_key(self):
        # numKeys=1 but key bytes missing: must parse without OOB
        data = b"kbagic" + bytes([3, 0]) + bytes(16) + struct.pack("<I", 1)
        data += bytes(range(16, 32)) + struct.pack("<I", 4) + struct.pack("<H", 1)
        data += bytes([0, 4])
        bag = K.parse_keybag(data)
        self.assertEqual(bag["num_keys"], 1)
        self.assertIn("key_present", bag["keys"][0])

    def test_class_mapping(self):
        bag = K.parse_keybag(mk_keybag(0, [(4, b"\x01" * 32)]))
        self.assertEqual(bag["keys"][0]["class_name"],
                         "NSFileProtectionCompleteUntilFirstUserAuthentication")


class StatusTest(unittest.TestCase):
    def test_present_vs_missing(self):
        bag = K.parse_keybag(mk_keybag(0, [
            (1, b"\x01" * 32),    # key present
            (2, b"\x00" * 32),    # zeroed -> not present
            (4, b""),             # missing
        ]))
        st = K.keybag_status(bag)
        by = {r["class"]: r for r in st["classes"]}
        self.assertTrue(by["NSFileProtectionNone"]["usable_now"])
        self.assertEqual(by["NSFileProtectionNone"]["key_material_present"], 1)
        self.assertFalse(by["NSFileProtectionComplete"]["usable_now"])
        self.assertFalse(by["NSFileProtectionCompleteUntilFirstUserAuthentication"]["usable_now"])
        self.assertEqual(st["usable_count"], 1)

    def test_bfu_honest_classification(self):
        # The BFU reading: Complete* with no key material is locked
        bag = K.parse_keybag(mk_keybag(0, [(4, b""), (0, b"\xde\xad" * 16)]))
        st = K.keybag_status(bag)
        by = {r["class"]: r for r in st["classes"]}
        self.assertFalse(by["NSFileProtectionCompleteUntilFirstUserAuthentication"]["usable_now"])


class AnalyzeEscrowTest(unittest.TestCase):
    def test_analyze_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "systembag.kb"
            p.write_bytes(mk_keybag(0, [(0, b"\x01" * 32)]))
            a = K.analyze(p)
            self.assertEqual(a["status"]["usable_count"], 1)
            self.assertIn("classes", a["status"])

    def test_escrow_plist_extraction(self):
        esc = mk_keybag(2, [(4, b"\xaa" * 32), (1, b"\xbb" * 32)])
        rec = {"EscrowRecords": [{"Keybag": esc, "DeviceName": "iPhone 11"}]}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "escrow.plist"
            p.write_bytes(plistlib.dumps(rec))
            bags = K.escrow_keybags(p)
            self.assertEqual(len(bags), 1)
            st = K.keybag_status(bags[0])
            by = {r["class"]: r for r in st["classes"]}
            self.assertTrue(by["NSFileProtectionNone"]["usable_now"])
            self.assertTrue(by["NSFileProtectionCompleteUntilFirstUserAuthentication"]["usable_now"])

    def test_escrow_without_keybag_raises(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "plain.plist"
            p.write_bytes(plistlib.dumps({"deviceName": "x"}))
            with self.assertRaises(K.KeybagError):
                K.escrow_keybags(p)

    def test_escrow_nonplist_raises(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "junk.plist"
            p.write_bytes(b"<xml>broken")
            with self.assertRaises(K.KeybagError):
                K.escrow_keybags(p)


class RenderTest(unittest.TestCase):
    def test_render_status(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "systembag.kb"
            p.write_bytes(mk_keybag(0, [(0, b"\x01" * 32), (4, b"")]))
            out = K.render_status(p)
            self.assertIn("keybag: system", out)
            self.assertIn("usable now", out)
            self.assertIn("encrypted until", out)

    def test_render_escrow(self):
        esc = mk_keybag(2, [(4, b"\xaa" * 32)])
        rec = {"EscrowRecords": [{"Keybag": esc}]}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "escrow.plist"
            p.write_bytes(plistlib.dumps(rec))
            out = K.render_escrow(p)
            self.assertIn("escrow record", out)
            self.assertIn("+", out)


class BfuAesKeysTest(unittest.TestCase):
    def _capture(self, *a, **k):
        return __import__("opensleuth.bfu", fromlist=["capture_aes_keys"]).capture_aes_keys(*a, **k)

    def test_gaster_missing(self):
        with mock.patch("opensleuth.bfu.subprocess.run",
                        side_effect=FileNotFoundError("gaster")):
            r = self._capture("/tmp/x")
        self.assertFalse(r["ok"])
        self.assertIn("gaster not installed", r["error"])

    def test_gaster_no_keyset(self):
        with mock.patch("opensleuth.bfu.subprocess.run") as run, \
             mock.patch("opensleuth.bfu.Path.exists", return_value=False):
            run.return_value = type("R", (), {"returncode": 1, "stdout": "no device", "stderr": ""})()
            with tempfile.TemporaryDirectory() as td:
                r = self._capture(td)
        self.assertFalse(r["ok"])
        self.assertIn("no keyset", r["error"])

    def test_ipwndfu_timeout(self):
        from subprocess import TimeoutExpired
        with mock.patch("opensleuth.bfu.subprocess.run",
                        side_effect=TimeoutExpired("ipwndfu", 90)):
            with tempfile.TemporaryDirectory() as td:
                r = self._capture(td, tool="ipwndfu")
        self.assertFalse(r["ok"])
        self.assertIn("timed out", r["error"])

    def test_gaster_success_copies_keys(self):
        fake_bin = mock.Mock()
        fake_bin.name = "uid-key.bin"
        fake_bin.read_bytes.return_value = b"KEYDATA"
        with mock.patch("opensleuth.bfu.subprocess.run") as run, \
             mock.patch("opensleuth.bfu.Path.exists", return_value=True), \
             mock.patch("opensleuth.bfu.Path.glob", return_value=[fake_bin]):
            run.return_value = type("R", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()
            with tempfile.TemporaryDirectory() as td:
                r = self._capture(td)
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["keys"]), 1)


if __name__ == "__main__":
    unittest.main()