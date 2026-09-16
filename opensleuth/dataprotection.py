"""iOS data protection decryption engine - CoreProbe's own BFU stack.

Implements the publicly documented iOS data-protection pipeline:

  1. cprotect xattr (com.apple.system.cprotect): per-file protection
     class + wrapped per-file key, stored in file metadata. During a
     BFU/ramdisk pull these xattrs travel with the files.
  2. keybag class-key unwrap: class keys in system/user keybags are
     wrapped with the device UID key; AES-ECB with the UID key unwraps
     them (checkm8 on A7-A11 exposes the UID-key AES engine; the
     `acquire bfu --keys` keyset carries the material).
  3. per-file content decryption: files are encrypted in fixed-size
     sectors with AES-CBC; the IV is the big-endian sector index, the
     key is the per-file key unwrapped from cprotect using the class key.

HONESTY: layouts below follow public references (iphone-dataprotection,
iOS forensics literature). They are self-tested by round-trip fixtures,
but MUST be validated against a real device fixture before case work -
Apple does not publish the format and versions drift.

The engine does not bypass SEP: on A12+ the class keys never leave the
SEP, so this pipeline applies where the keys are obtainable (checkm8
A7-A11, escrow/backup keybags).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from Crypto.Cipher import AES
    HAVE_AES = True
except ImportError:  # pragma: no cover
    HAVE_AES = False

INSTALL_HINT = "requires pycryptodome: pip install pycryptodome"

CLASS_NAMES = {
    0: "None/unknown", 1: "NSFileProtectionNone",
    2: "NSFileProtectionComplete",
    3: "NSFileProtectionCompleteUnlessOpen",
    4: "NSFileProtectionCompleteUntilFirstUserAuthentication",
    5: "NSFileProtectionCompleteUntilFirstUserAuthenticationUnlessOpen",
}


def _require_aes():
    if not HAVE_AES:
        raise RuntimeError(INSTALL_HINT)


def parse_cprotect(blob: bytes, source: str = "<blob>") -> dict[str, Any]:
    """Parse a com.apple.system.cprotect xattr blob (tolerant)."""
    if not blob:
        raise ValueError(f"{source}: empty cprotect blob")
    version = blob[0]
    klass = blob[1] if len(blob) > 1 else None
    wrapped = blob[2:]
    return {
        "source": source,
        "version": version,
        "class": klass,
        "class_name": CLASS_NAMES.get(klass, f"class-{klass}") if klass is not None else None,
        "wrapped_key": wrapped,
        "wrapped_len": len(wrapped),
    }


def unwrap_class_key(wrapped: bytes, uid_key: bytes) -> bytes:
    """AES-ECB unwrap of a keybag class key with the UID key."""
    _require_aes()
    if len(uid_key) not in (16, 24, 32):
        raise ValueError(f"uid key must be 16/24/32 bytes, got {len(uid_key)}")
    if len(wrapped) % 16 != 0:
        # documented bags carry padding; trim to the last full block
        wrapped = wrapped[: len(wrapped) - (len(wrapped) % 16)]
    cipher = AES.new(uid_key, AES.MODE_ECB)
    key = cipher.decrypt(wrapped)
    # class keys are 32 bytes per documentation; strip PKCS7-ish padding
    return key[:32]


def compress_key_wrap(class_key: bytes, uid_key: bytes) -> bytes:
    """Inverse of unwrap_class_key - for fixture round-trips only."""
    _require_aes()
    cipher = AES.new(uid_key, AES.MODE_ECB)
    return cipher.encrypt(class_key + b"\x00" * (32 - len(class_key)))


def decrypt_sectors(data: bytes, key: bytes, sector: int = 4096) -> bytes:
    """AES-CBC per-sector decryption: IV = big-endian sector index."""
    _require_aes()
    if len(key) not in (16, 24, 32):
        raise ValueError("key must be 16/24/32 bytes")
    out = bytearray()
    idx = 0
    for off in range(0, len(data), sector):
        chunk = data[off:off + sector]
        if len(chunk) < 16:
            out += chunk
            break
        iv = idx.to_bytes(16, "big")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        out += cipher.decrypt(chunk)
        idx += 1
    return bytes(out)


def encrypt_sectors(data: bytes, key: bytes, sector: int = 4096) -> bytes:
    """Inverse of decrypt_sectors - for fixture round-trips only."""
    _require_aes()
    out = bytearray()
    idx = 0
    for off in range(0, len(data), sector):
        chunk = data[off:off + sector]
        if len(chunk) < 16:
            out += chunk
            break
        iv = idx.to_bytes(16, "big")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        out += cipher.encrypt(chunk)
        idx += 1
    return bytes(out)


def decrypt_case(file_path: str | Path, class_key: bytes,
                 cprotect_blob: bytes | None = None, sector: int = 4096,
                 out: str | Path | None = None) -> dict[str, Any]:
    """Decrypt one pulled file: unwrap cprotect per-file key with the
    class key, then decrypt sectors. Returns dict with output path."""
    _require_aes()
    data = Path(file_path).read_bytes()
    per_file_key = class_key
    if cprotect_blob is not None:
        cp = parse_cprotect(cprotect_blob, source=str(file_path))
        wrapped = cp["wrapped_key"]
        per_file_key = _unwrap_pk(wrapped, class_key)
    plain = decrypt_sectors(data, per_file_key, sector=sector)
    if out is None:
        out = str(Path(file_path)) + ".dec"
    Path(out).write_bytes(plain)
    return {"file": str(file_path), "out": str(out), "size": len(plain),
            "class": cprotect_blob and parse_cprotect(cprotect_blob)["class_name"]}


def _unwrap_pk(wrapped: bytes, class_key: bytes) -> bytes:
    """Unwrap the per-file key: AES-ECB with the CLASS key (documented)."""
    if len(wrapped) < 32:
        raise ValueError(f"wrapped per-file key too short: {len(wrapped)}")
    cipher = AES.new(class_key, AES.MODE_ECB)
    pk = cipher.decrypt(wrapped[:32])
    return pk[:32]


def wrap_pk(per_file_key: bytes, class_key: bytes) -> bytes:
    """Inverse of _unwrap_pk - for fixture round-trips only."""
    cipher = AES.new(class_key, AES.MODE_ECB)
    return cipher.encrypt(per_file_key + b"\x00" * (32 - len(per_file_key)))


def render_inspect(cp: dict[str, Any]) -> str:
    return (
        f"cprotect: {cp['source']}\n"
        f"  version   : {cp['version']}\n"
        f"  class     : {cp['class']} ({cp['class_name']})\n"
        f"  wrapped   : {len(cp['wrapped_key'])} bytes "
        f"({cp['wrapped_key'][:16].hex()}...)\n"
        f"  BFU state : {'usable if class key obtainable' if cp['class'] in (0, 1, 3) else
                         'passcode-gated until first unlock' if cp['class'] in (2, 4, 5) else 'unknown'}"
    )