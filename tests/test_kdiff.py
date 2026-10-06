"""Tests for opensleuth.kdiff — kernelcache patch-diff (n-day hunting)."""

import struct
import unittest

from opensleuth import kdiff


def mk(fix=False):
    """Two synthetic kernelcaches differing only in a surgical 40-instruction
    fix placed within 4KB of a symbol-bearing string."""
    base = bytearray()
    for i in range(4000):
        base += struct.pack('<I', 0xD503201F + (i & 0x7f))
    base += b'vnode_copyout_and_unlock' + b'\0' * 80
    code = b''.join(struct.pack('<I', 0xD2800000 | ((0x30 + i) << 5)) for i in range(512))
    base += code
    if fix:
        for j in range(40):
            base[16400 + j * 4:16400 + j * 4 + 4] = struct.pack('<I', 0xD2800000 | (j << 5))
    base += b'\x00' * 2000
    return bytes(base)


class KdiffTest(unittest.TestCase):
    def test_identical_kernels_no_findings(self):
        kc = mk(False)
        r = kdiff.diff_kernelcaches(kc, kc)
        self.assertEqual(r["findings"], [])

    def test_detects_surgical_fix_region(self):
        r = kdiff.diff_kernelcaches(mk(True), mk(False))
        self.assertTrue(r["findings"], "expected a changed region")

    def test_symbol_hint_raises_to_high(self):
        r = kdiff.diff_kernelcaches(mk(True), mk(False))
        top = r["findings"][0]
        self.assertEqual(top["severity"], "HIGH")
        self.assertIn("copyout", " ".join(top["nearby_symbols"]))

    def test_region_offset_is_correct(self):
        r = kdiff.diff_kernelcaches(mk(True), mk(False))
        self.assertEqual(int(r["findings"][0]["addr_start"], 16), 0x4000)

    def test_render_includes_honesty_banner(self):
        out = kdiff.render_diff(kdiff.diff_kernelcaches(mk(True), mk(False)))
        self.assertIn("n-day RESEARCH LEAD", out)

    def test_empty_input_error(self):
        r = kdiff.diff_kernelcaches(b"", b"valid" * 100)
        self.assertIn("error", r["summary"])


if __name__ == "__main__":
    unittest.main()