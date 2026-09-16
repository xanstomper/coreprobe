"""Firmware toolbox + trustcache + patch catalog tests."""

import hashlib
import struct
import zipfile

import pytest

from opensleuth import firmware as FW
from opensleuth import research_patches as RP
from opensleuth import trustcache as TC


def _im4p(ptype: bytes, image: bytes, desc: bytes = b"test",
          key: bytes = b"\x01" * 16, cert: bytes = b"\x02" * 8) -> bytes:
    def blob(b):
        return struct.pack(">I", len(b)) + b
    return b"IM4P" + ptype + blob(desc) + blob(image) + blob(key) + blob(cert)


def test_identify_macho():
    i = FW.identify.__wrapped__ if hasattr(FW.identify, "__wrapped__") else FW.identify
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "k.bin"
        f.write_bytes(b"\xfe\xed\xfa\xcf" + b"\x00" * 32)
        info = FW.identify(f)
    assert "Mach-O (64-bit)" in info["kind"]


def test_identify_missing():
    assert "error" in FW.identify("/nonexistent/x")


def test_scan_dir(tmp_path):
    (tmp_path / "a.im4p").write_bytes(_im4p(b"krnl", b"image"))
    (tmp_path / "b.bin").write_bytes(b"\xfe\xed\xfa\xce")
    (tmp_path / "c.txt").write_text("nothing")
    imgs = FW.scan_dir(tmp_path)
    assert len(imgs) == 2
    kinds = {i["kind"] for i in imgs}
    assert "Mach-O (32-bit)" in kinds


def test_parse_im4p():
    img = _im4p(b"krnl", b"\xfe\xed\xfa\xcf" + b"\x90" * 64,
                desc=b"kernelcache test")
    info = FW.parse_im4p(img, source="crafted")
    assert info["type"] == "krnl"
    assert info["description"] == "kernelcache test"
    assert info["image_len"] == 68
    assert info["container"] is None


def test_parse_img4_wrapper():
    inner = _im4p(b"ibot", b"payload")
    wrapper = b"IMG4" + b"ibot" + inner
    info = FW.parse_im4p(wrapper, source="img4")
    assert info["container"] == "ibot"
    assert info["type"] == "ibot"


def test_parse_im4p_truncated():
    with pytest.raises(ValueError):
        FW.parse_im4p(b"IM4P" + b"type", source="t")


def test_extract_ipsw(tmp_path):
    inner = _im4p(b"krnl", b"payload")
    ipsw = tmp_path / "fake.ipsw"
    with zipfile.ZipFile(ipsw, "w") as z:
        z.writestr("kernelcache", inner)
        z.writestr("iBSS", b"\xfe\xed\xfa\xcf")
    out = tmp_path / "out"
    r = FW.extract_ipsw(ipsw, out)
    assert r["files"] == 2
    assert len(r["images"]) == 2


def test_extract_nonzip(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"not a zip")
    with pytest.raises(ValueError):
        FW.extract_ipsw(f, tmp_path / "o")


def test_trustcache_roundtrip():
    hashes = [bytes(range(20)), hashlib.sha256(b"x").digest()[:20]]
    blob = TC.build(hashes, version=3)
    t = TC.parse(blob)
    assert t["version"] == 3
    assert t["count"] == 2
    assert t["entries"][0]["cdhash"] == bytes(range(20)).hex()


def test_trustcache_bad_hash_len():
    with pytest.raises(ValueError):
        TC.build([b"short"])


def test_trustcache_bad_magic():
    with pytest.raises(ValueError):
        TC.parse(b"\x00" * 40)


def test_trustcache_file_roundtrip(tmp_path):
    p = tmp_path / "t.tc"
    TC.build_file([bytes(range(20))], p)
    t = TC.parse_file(p)
    assert t["count"] == 1


def test_patch_catalog_shape():
    assert len(RP.PATCHES) >= 5
    for p in RP.PATCHES:
        assert p["name"] and p["target"] and p["lineage"]
        assert p["conf"] in ("high", "med")
    assert "sep" in RP.TARGETS and "kernel" in RP.TARGETS


def test_patch_render_filter():
    out = RP.render_list(target="sep")
    assert "SEP keybag ops" in out
    out2 = RP.render_list(target="iboot")
    assert "iBoot signature check" in out2


def test_patch_render_honest_note():
    out = RP.render_list()
    assert "not packaged exploits" in out