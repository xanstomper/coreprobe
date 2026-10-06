"""Tests for opensleuth.pacscan — kernelcache PAC-diversifier scanner."""

import struct
import unittest

from opensleuth import pacscan


def movz_w(rd: int, imm16: int) -> int:
    return 0x52800000 | (imm16 << 5) | rd


def pacia(rd: int, rm: int) -> int:
    # PACIA Xd, Xm : Rm at bits 5-9 (diversifier register), Rd at bits 0-4
    return 0xDAC10000 | (rm << 5) | rd


def blr(rn: int) -> int:
    return 0xD63F0000 | (rn << 5)


NOP = 0xD503201F


def pack(*insns) -> bytes:
    flat = []
    for i in insns:
        if isinstance(i, tuple):
            flat.extend(i)
        else:
            flat.append(i)
    return b"".join(struct.pack("<I", i) for i in flat)


def synth_fixture() -> bytes:
    """Synthetic arm64e: two fixed-diversifier PAC sites + string hint."""
    code = pack((movz_w(8, 0x307A), pacia(0, 8), blr(0)))
    code += pack(*([NOP] * 20))
    code += pack((movz_w(9, 0), pacia(1, 9), blr(1)))
    code += pack(*([NOP] * 20))
    code += b"com.apple.xattr.tmpfs\0"
    return code


class PacscanTest(unittest.TestCase):
    def test_importable_without_capstone(self):
        # module import must never fail even when capstone is absent
        self.assertIsNotNone(pacscan)

    def test_finds_fixed_diversifier_65330_pattern(self):
        r = pacscan.scan_pac_diversifiers(synth_fixture())
        divs = {f["diversifier"] for f in r["findings"]}
        self.assertIn(0x307A, divs)

    def test_finds_zero_diversifier_high(self):
        r = pacscan.scan_pac_diversifiers(synth_fixture())
        zero = next((f for f in r["findings"] if f["diversifier"] == 0), None)
        self.assertIsNotNone(zero)
        self.assertEqual(zero["severity"], "HIGH")

    def test_register_diversifier_not_flagged(self):
        # PACIA X0, X8 with no preceding MOVZ to X8 -> register-derived, not fixed
        code = pack((pacia(0, 8), blr(0)))
        r = pacscan.scan_pac_diversifiers(code)
        self.assertEqual(r["findings"], [])

    def test_nearby_string_hint(self):
        r = pacscan.scan_pac_diversifiers(synth_fixture())
        self.assertTrue(all(f["nearby_hint"] == "tmpfs" for f in r["findings"]))

    def test_render_contains_honesty_banner(self):
        out = pacscan.render_scan(pacscan.scan_pac_diversifiers(synth_fixture()))
        self.assertIn("static lead only", out)

    def test_render_empty_when_hardened(self):
        out = pacscan.render_scan(pacscan.scan_pac_diversifiers(pack(*([NOP] * 64))))
        self.assertIn("no fixed diversifiers found", out)

    def test_summary_counts(self):
        r = pacscan.scan_pac_diversifiers(synth_fixture())
        self.assertEqual(r["summary"]["pac_events"], 2)
        self.assertEqual(r["summary"]["fixed_diversifiers"], 2)


if __name__ == "__main__":
    unittest.main()
