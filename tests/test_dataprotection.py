"""Data protection engine tests (our own BFU decryption stack)."""

import tempfile
from pathlib import Path

import pytest

from opensleuth import dataprotection as D

UID = bytes(range(32))
CLASS_KEY_NONE = bytes(range(32, 64))
CLASS_KEY_COMPLETE = bytes(range(64, 96))
PFK = bytes(range(96, 128))


@pytest.fixture(autouse=True)
def _require_aes():
    if not D.HAVE_AES:
        pytest.skip("pycryptodome required")


def test_parse_cprotect_basic():
    blob = bytes([3, 1]) + b"\xaa" * 32
    cp = D.parse_cprotect(blob, source="x")
    assert cp["version"] == 3
    assert cp["class"] == 1
    assert cp["class_name"] == "NSFileProtectionNone"
    assert cp["wrapped_len"] == 32


def test_parse_cprotect_empty():
    with pytest.raises(ValueError):
        D.parse_cprotect(b"", source="x")


def test_parse_cprotect_tolerates_variants():
    for n in (32, 40, 48):
        cp = D.parse_cprotect(bytes([3, 4]) + bytes(n), source="v")
        assert cp["wrapped_len"] == n


def test_unwrap_roundtrip():
    wrapped = D.compress_key_wrap(CLASS_KEY_NONE, UID)
    key = D.unwrap_class_key(wrapped, UID)
    assert key == CLASS_KEY_NONE


def test_unwrap_bad_uid_len():
    with pytest.raises(ValueError):
        D.unwrap_class_key(b"\x00" * 32, b"short")


def test_unwrap_tolerates_padding():
    wrapped = D.compress_key_wrap(CLASS_KEY_NONE, UID) + b"PADPAD"
    assert D.unwrap_class_key(wrapped, UID) == CLASS_KEY_NONE


def test_sector_roundtrip():
    payload = b"A" * 4096 + b"B" * 112  # 7 full blocks into sector 2
    enc = D.encrypt_sectors(payload, PFK)
    assert enc != payload
    dec = D.decrypt_sectors(enc, PFK)
    assert dec == payload


def test_sector_small_file():
    payload = b"tiny"
    enc = D.encrypt_sectors(payload, PFK)
    assert D.decrypt_sectors(enc, PFK) == payload


def test_pk_unwrap_roundtrip():
    wrapped = D.wrap_pk(PFK, CLASS_KEY_NONE)
    assert D._unwrap_pk(wrapped, CLASS_KEY_NONE) == PFK


def test_decrypt_case_with_cprotect(tmp_path):
    payload = b"secret" * 100
    payload += b"\x00" * (16 - len(payload) % 16)
    blob = bytes([3, 1]) + D.wrap_pk(PFK, CLASS_KEY_NONE)
    (tmp_path / "f").write_bytes(D.encrypt_sectors(payload, PFK))
    r = D.decrypt_case(tmp_path / "f", CLASS_KEY_NONE, cprotect_blob=blob,
                       out=tmp_path / "f.dec")
    assert (tmp_path / "f.dec").read_bytes() == payload
    assert r["class"] == "NSFileProtectionNone"


def test_decrypt_case_direct_key(tmp_path):
    payload = b"direct-key " * 50
    payload += b"\x00" * (16 - len(payload) % 16)
    (tmp_path / "f").write_bytes(D.encrypt_sectors(payload, PFK))
    r = D.decrypt_case(tmp_path / "f", PFK, out=str(tmp_path / "f.dec"))
    assert (tmp_path / "f.dec").read_bytes() == payload


def test_render_inspect():
    cp = D.parse_cprotect(bytes([3, 4]) + b"\xaa" * 32, source="s")
    out = D.render_inspect(cp)
    assert "NSFileProtectionCompleteUntilFirstUserAuthentication" in out
    assert "passcode-gated" in out


def test_pycrypto_missing_message(monkeypatch):
    monkeypatch.setattr(D, "HAVE_AES", False)
    with pytest.raises(RuntimeError, match="pycryptodome"):
        D.unwrap_class_key(b"\x00" * 32, UID)