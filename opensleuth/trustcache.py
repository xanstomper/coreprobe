"""TrustCache builder/parser - the unsigned-code-execution ingredient.

TrustCaches whitelist CD hashes so signed images or binaries can run on
research devices. The format is documented publicly (libgrabkernel /
twitterati era research): header then 24-byte entries.

  header: magic u32le 0x3A84005E | version u32le | count u32le
          | uuid 16B | flags u32le
  entry : cdhash 20B | flags u32le

Honesty: layout per public references; round-trip tested here; validate
with the bootloader on your research device before relying on it.
"""

from __future__ import annotations

import struct
import uuid as _uuid
from pathlib import Path
from typing import Any

MAGIC = 0x3A84005E
HEADER = struct.Struct("<III16sI")
ENTRY = struct.Struct("<20sI")


def build(hashes: list[bytes], version: int = 0, flags: int = 0,
          uuid_bytes: bytes | None = None) -> bytes:
    if any(len(h) != 20 for h in hashes):
        raise ValueError("every trustcache entry hash must be 20 bytes")
    uid = uuid_bytes or _uuid.uuid4().bytes
    blobs = b"".join(ENTRY.pack(h, 0) for h in hashes)
    return HEADER.pack(MAGIC, version, len(hashes), uid, flags) + blobs


def parse(data: bytes, source: str = "<data>") -> dict[str, Any]:
    if len(data) < HEADER.size:
        raise ValueError(f"{source}: truncated trustcache header")
    magic, version, count, uid, flags = HEADER.unpack(data[:HEADER.size])
    if magic != MAGIC:
        raise ValueError(f"{source}: bad magic {magic:#x}")
    expected = HEADER.size + count * ENTRY.size
    if len(data) < expected:
        raise ValueError(f"{source}: truncated ({len(data)} < {expected})")
    entries = []
    off = HEADER.size
    for _ in range(count):
        cdhash, eflags = ENTRY.unpack(data[off:off + ENTRY.size])
        off += ENTRY.size
        entries.append({"cdhash": cdhash.hex(), "flags": eflags})
    return {"version": version, "count": count, "uuid": uid.hex(),
            "flags": flags, "entries": entries}


def build_file(hashes: list[bytes], path: str | Path) -> int:
    p = Path(path)
    p.write_bytes(build(hashes))
    return len(hashes)


def parse_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    return parse(p.read_bytes(), source=str(p))
