"""BFU acquisition tests: honest expectations + ramdisk flow."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from opensleuth import bfu


class ExpectationsTest(unittest.TestCase):
    def test_checkm8_chip(self):
        e = bfu.expectations("A10", "12.4")
        self.assertTrue(e["checkm8_eligible"])
        self.assertFalse(e["usbliter8_eligible"])
        self.assertEqual(e["bfu_bootrom_route"], "checkm8")

    def test_usbliter8_chip(self):
        e = bfu.expectations("A13", "26.6.1")
        self.assertFalse(e["checkm8_eligible"])
        self.assertTrue(e["usbliter8_eligible"])
        self.assertEqual(e["bfu_bootrom_route"], "usbliter8")

    def test_modern_chip_no_route(self):
        e = bfu.expectations("A18", "26.6.1")
        self.assertEqual(e["bfu_bootrom_route"], "none")

    def test_classes_cover_all_protection_levels(self):
        e = bfu.expectations("A13")
        names = {c["class"] for c in e["classes"]}
        self.assertIn("CompleteUntilFirstUserAuthentication", names)
        self.assertIn("Complete", names)
        self.assertIn("None", names)
        # nothing claims Complete content is decryptable at BFU
        for c in e["classes"]:
            if c["class"] == "Complete":
                self.assertEqual(c["checkm8_bfu"], "encrypted")

    def test_render_includes_route_and_bottom_line(self):
        out = bfu.render_expectations("A10", "12.4")
        self.assertIn("BFU expectations", out)
        self.assertIn("bootrom route: checkm8", out)
        self.assertIn("Bottom line", out)
        self.assertIn("CompleteUntilFirstUserAuthentication", out)

    def test_render_no_public_route_for_modern(self):
        out = bfu.render_expectations("A18", "26.6.1")
        self.assertIn("bootrom route: NONE PUBLIC", out)


class RamdiskFlowTest(unittest.TestCase):
    def test_payload_status_lists_all(self):
        with tempfile.TemporaryDirectory() as td:
            st = bfu.payload_status(td)
            self.assertEqual(len(st), len(bfu.RAMDISK_FILES))
            self.assertTrue(all(not s["present"] for s in st))

    def test_missing_payloads_aborts(self):
        with tempfile.TemporaryDirectory() as td:
            out = tempfile.mkdtemp()
            r = bfu.run_ramdisk_extract(td, out)
            self.assertFalse(r["ok"])
            self.assertIn("missing payloads", r["error"])

    @mock.patch("opensleuth.bfu.subprocess.run")
    def test_full_flow_pulls_keybags(self, run):
        sim = iter([
            mock.Mock(returncode=0, stdout="ok", stderr=""),
            mock.Mock(returncode=0, stdout="ok", stderr=""),
            mock.Mock(returncode=0, stdout="ok", stderr=""),
            mock.Mock(returncode=0, stdout="ok", stderr=""),
            mock.Mock(returncode=0, stdout="ok", stderr=""),
            # bootx
            mock.Mock(returncode=0, stdout="ok", stderr=""),
            # ssh tar payload
            mock.Mock(returncode=0, stdout=b"TARBALLBYTES".decode("latin-1"), stderr=""),
        ])
        run.side_effect = lambda *a, **k: next(sim)
        with tempfile.TemporaryDirectory() as td:
            for f in bfu.RAMDISK_FILES:
                (Path(td) / f).write_bytes(b"x")
            outd = tempfile.mkdtemp()
            r = bfu.run_ramdisk_extract(td, outd)
            self.assertTrue(r["ok"])
            self.assertTrue(r["keybags_tar"].endswith("bfu-keybags.tar"))
            self.assertIn(b"TARBALLBYTES", Path(r["keybags_tar"]).read_bytes())
            cmds = [c.args[0][0] for c in run.call_args_list]
            self.assertIn("irecovery", cmds)
            self.assertIn("sshpass", cmds)

    @mock.patch("opensleuth.bfu.subprocess.run")
    def test_timeout_reported(self, run):
        from subprocess import TimeoutExpired
        run.side_effect = TimeoutExpired("irecovery", 60)
        with tempfile.TemporaryDirectory() as td:
            for f in bfu.RAMDISK_FILES:
                (Path(td) / f).write_bytes(b"x")
            outd = tempfile.mkdtemp()
            r = bfu.run_ramdisk_extract(td, outd)
            self.assertFalse(r["ok"])
            self.assertIn("timed out", r["error"])

    def test_yield_card_checkm8_flow(self):
        card = bfu.yield_card("A10", "12.4",
                              device_flags={"attached": True, "dfu": True, "pwnd": True},
                              tooling={"gaster": True, "sshpass": True})
        by = {i["item"]: i for i in card["yield"]}
        self.assertEqual(by["AES keyset (GID/UID)"]["state"], "obtainable")
        self.assertEqual(by["system/user keybags (/var/Keychains)"]["state"], "obtainable")
        self.assertEqual(by["Complete* class content"]["state"], "locked at BFU (SEP)")
        self.assertTrue(card["checkm8_eligible"])

    def test_yield_card_a13_sep_gated(self):
        card = bfu.yield_card("A13", "26.6.1")
        by = {i["item"]: i for i in card["yield"]}
        self.assertIn("SEP-gated", by["AES keyset (GID/UID)"]["state"])
        self.assertTrue(card["usbliter8_eligible"])

    def test_render_yield_card(self):
        card = bfu.yield_card("A10", "12.4")
        out = bfu.render_yield_card(card)
        self.assertIn("BFU yield card", out)
        self.assertIn("checkm8 route available", out)

    def test_bfu_runbook_has_honest_limits(self):
        md = bfu.bfu_runbook("A13", "26.6.1", case_dir="case")
        self.assertIn("# BFU acquisition runbook", md)
        self.assertIn("Honest limits", md)
        self.assertIn("SEP", md)

    def test_bfu_runbook_checkm8_chain(self):
        md = bfu.bfu_runbook("A10", "12.4", case_dir="case")
        self.assertIn("--watch --keys --ramdisk", md)

    def test_subprocess_file_not_found(self):
        with mock.patch("opensleuth.bfu.subprocess.run",
                        side_effect=FileNotFoundError("gaster")):
            with tempfile.TemporaryDirectory() as td:
                for f in bfu.RAMDISK_FILES:
                    (Path(td) / f).write_bytes(b"x")
                outd = tempfile.mkdtemp()
                r = bfu.run_ramdisk_extract(td, outd)
                self.assertFalse(r["ok"])
                self.assertIn("missing tool", r["error"])


if __name__ == "__main__":
    unittest.main()