"""Firmware research toolbox: image identification, IMG4 parsing,
IPSW extraction - the input side of new-chip exploit development.

Real exploit work starts with firmware: pull an IPSW, identify the
images (kernelcache, ramdisk, iBoot, devicetree), parse the IMG4/IM4P
containers, and extract the payloads for patch analysis.

IMG4/IM4P layout follows the public img4tool documentation:
  IM4P: magic 'IM4P' | type 4B | desc_len 4B BE | desc | data_len 4B BE
        | data | key_len 4B BE | key | cert_len 4B BE | cert
  IMG4: magic 'IMG4' | 4B container tag | IM4P payload | (kexts/certs)

Honesty: parse against crafted fixtures + img4tool docs; validate with a
real IPSW before relying on it.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import Any

MAGICS = {
    b"IMG4": "IMG4 container",
    b"IM4P": "IM4P payload",
    b"IM4M": "IM4M manifest (sep image manifest)",
    b"IM4P\x00": "IM4P payload",
    b"\xfe\xed\xfa\xce": "Mach-O (32-bit)",
    b"\xce\xfa\xed\xfe": "Mach-O (32-bit, swapped)",
    b"\xfe\xed\xfa\xcf": "Mach-O (64-bit)",
    b"\xcf\xfa\xed\xfe": "Mach-O (64-bit, swapped)",
    b"\x1f\x8b": "gzip stream",
    b"PK\x03\x04": "ZIP archive (IPSW)",
    b"BDSC": "BDE/AV engine blob",
    b"hsdk": "developer payload (hsdk)",
}


def identify(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {"path": str(p), "error": "not found"}
    head = p.read_bytes()[:4]
    magic = MAGICS.get(head)
    if magic is None:
        # try longer prefixes
        head8 = p.read_bytes()[:8]
        if head8.startswith(b"IM4P"):
            magic = "IM4P payload"
    return {
        "path": str(p),
        "size": p.stat().st_size,
        "magic": head.hex(),
        "kind": magic or "unknown",
    }


def scan_dir(d: str | Path) -> list[dict[str, Any]]:
    d = Path(d)
    out = []
    if not d.exists():
        return out
    for f in sorted(d.rglob("*")):
        if f.is_file():
            info = identify(f)
            if info.get("kind") != "unknown":
                out.append({**info, "rel": f.relative_to(d).as_posix()})
    return out


def parse_im4p(data: bytes, source: str = "<data>") -> dict[str, Any]:
    """Parse an IM4P payload container (public layout)."""
    if data[:4] not in (b"IM4P", b"IMG4"):
        raise ValueError(f"{source}: not an IM4P/IMG4 container")
    payload = data
    container = None
    if data[:4] == b"IMG4":
        container = data[4:8].decode("latin-1", errors="replace")
        off = 8
        # IMG4 wraps an IM4P after the 4B tag; find it
        if data[off:off + 4] != b"IM4P":
            raise ValueError(f"{source}: IMG4 without IM4P payload")
        payload = data[off:]
    if len(payload) < 12:
        raise ValueError(f"{source}: IM4P header truncated")
    # 4B magic already checked; 4B type tag
    ptype = payload[4:8].decode("latin-1", errors="replace")
    off = 8

    def read_len() -> int:
        nonlocal off
        if off + 4 > len(payload):
            raise ValueError(f"{source}: truncated length field at {off}")
        n = struct.unpack(">I", payload[off:off + 4])[0]
        off += 4
        return n

    def read_blob() -> bytes:
        nonlocal off
        n = read_len()
        if off + n > len(payload):
            raise ValueError(f"{source}: blob truncated at {off} len={n}")
        b = payload[off:off + n]
        off += n
        return b

    desc = read_blob()
    image = read_blob()
    key = read_blob()
    cert = read_blob()
    return {
        "source": source,
        "container": container,
        "type": ptype,
        "description": desc.decode("latin-1", errors="replace"),
        "image_len": len(image),
        "image_sha256": __import__("hashlib").sha256(image).hexdigest(),
        "key": key,
        "cert_len": len(cert),
    }


def parse_img4_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    return parse_im4p(p.read_bytes(), source=str(p))


def extract_ipsw(ipsw: str | Path, out: str | Path) -> dict[str, Any]:
    """An IPSW is a ZIP: extract it and classify the contained images."""
    ipsw = Path(ipsw)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    if not zipfile.is_zipfile(ipsw):
        raise ValueError(f"{ipsw}: not a zip/IPSW")
    with zipfile.ZipFile(ipsw) as z:
        names = z.namelist()
        z.extractall(out)
    classified = scan_dir(out)
    return {"ipsw": str(ipsw), "out": str(out), "files": len(names),
            "images": classified}


def render_scan(images: list[dict[str, Any]]) -> str:
    if not images:
        return "no recognized firmware images found"
    lines = [f"firmware images: {len(images)}", ""]
    for i in images:
        lines.append(f"  {i.get('rel', i['path'])}  [{i['kind']}]  {i['size']:,} B")
    return "\n".join(lines)


def render_im4p(info: dict[str, Any]) -> str:
    return (
        f"IM4P: {info['source']}\n"
        f"  container : {info.get('container') or 'plain'}\n"
        f"  type      : {info['type']}\n"
        f"  desc      : {info['description']}\n"
        f"  image     : {info['image_len']:,} B  sha256 {info['image_sha256'][:16]}...\n"
        f"  key       : {len(info['key'])} B\n"
        f"  cert      : {info['cert_len']} B"
    )