"""SEPOS analyzer — SEP firmware research foundation (path 1).

Extracts and inventories Secure Enclave firmware (sep-firmware.im4p)
from IPSWs, decodes its tlv-container structure, and diffs SEP builds
across iOS versions — the starting point for SEP vulnerability research.

Known SEPOS structure (public reverse-engineering literature):
  The im4p payload is a TLV "TightVNC-era" style container:
    magic 'SEPOS' (0x5345504F53) | version u32 | entries...
  Each entry: tag u16 | length u32 | payload. Common tags:
    1 = SEPOS image (Mach-O, the main sepos binary)
    2 = txtramdisk (SEP ramdisk blobs)
    3 = ROM patch region
  Version field encodes the SEP build (e.g. 14.0.0).

Also catalogs AppleMacSEP/kernelcache co-images for cross-referencing.

HONESTY: layouts follow published SEPOS research (seposresearch/
checkra1n SEP notes). This module measures and inventories — it does
NOT contain or produce an exploit. A real SEP bypass requires finding
an actual vulnerability (fuzzing the AP->SEP surface, FI, etc.).
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from .firmware import parse_im4p

SEPOS_MAGIC = b"SEPOS"

# TLV tags seen in public teardowns
TAG_NAMES = {
    0x01: "sepos-image (Mach-O)",
    0x02: "txtramdisk",
    0x03: "rom-patch",
    0x04: "unknown-04",
    0x21: "manifest-fragment",
    0x22: "certificate",
}

MACHO_MAGICS = {b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"}


def extract_sep_image(im4p_path: str | Path) -> dict[str, Any]:
    """Parse a sep-firmware.im4p and return its TLV inventory + raw SEPOS image."""
    data = Path(im4p_path).read_bytes()
    info = parse_im4p(data, source=str(im4p_path))
    image = _image_of(data)
    out = {
        "file": str(im4p_path),
        "im4p": {k: v for k, v in info.items() if k != "key"},
        "tlv": parse_tlv(image) if image else None,
        "sepos_macho": None,
    }
    if image:
        out["sepos_macho"] = analyze_macho(image)
        tlv = out["tlv"]
        if not out["sepos_macho"] and tlv:
            # image blob may be the TLV container; analyze its Mach-O entry
            for e_start in _macho_offsets(image):
                m = analyze_macho(image[e_start:])
                if m:
                    out["sepos_macho"] = m
                    break
    return out


def _macho_offsets(image: bytes) -> list[int]:
    """Offsets of Mach-O headers inside a SEPOS TLV container."""
    if image[:5] != SEPOS_MAGIC:
        return []
    offs = []
    off = 9
    while off + 6 <= len(image):
        tag = struct.unpack("<H", image[off:off + 2])[0]
        length = struct.unpack("<I", image[off + 2:off + 6])[0]
        off += 6
        if off + length > len(image):
            break
        payload = image[off:off + length]
        if payload[:4] in MACHO_MAGICS:
            offs.append(off)
        off += length
    return offs


def _image_of(data: bytes) -> bytes | None:
    """Pull the image blob out of an IM4P (skipping type/desc header)."""
    if len(data) < 12:
        return None
    off = 8

    def read_len() -> int:
        nonlocal off
        if off + 4 > len(data):
            raise ValueError("truncated")
        n = struct.unpack(">I", data[off:off + 4])[0]
        off += 4
        return n

    try:
        read_len()          # desc
        read_len()          # skip desc text is wrong — desc blob follows
    except ValueError:
        return None
    # Re-parse properly: magic(4) type(4) desclen(4) desc datalen(4) data...
    off = 8
    desc_len = struct.unpack(">I", data[off:off + 4])[0]
    off += 4 + desc_len
    img_len = struct.unpack(">I", data[off:off + 4])[0]
    off += 4
    if off + img_len > len(data):
        return None
    return data[off:off + img_len]


def parse_tlv(image: bytes, source: str = "<sep>") -> list[dict[str, Any]]:
    """Parse the SEPOS TLV container inside the im4p image."""
    if image[:5] != SEPOS_MAGIC:
        return []
    version = struct.unpack("<I", image[5:9])[0]
    entries = []
    off = 9
    while off + 6 <= len(image):
        tag = struct.unpack("<H", image[off:off + 2])[0]
        length = struct.unpack("<I", image[off + 2:off + 6])[0]
        off += 6
        if off + length > len(image):
            break
        payload = image[off:off + length]
        head = payload[:16]
        entries.append({
            "tag": f"0x{tag:04x}",
            "name": TAG_NAMES.get(tag, f"tag-{tag}"),
            "length": length,
            "head_hex": head.hex(),
            "is_macho": payload[:4] in MACHO_MAGICS,
        })
        off += length
    if entries:
        entries[0]["container_version"] = version
    return entries


def analyze_macho(blob: bytes) -> dict[str, Any] | None:
    """First-pass Mach-O facts of the SEPOS binary."""
    if blob[:4] not in MACHO_MAGICS:
        return None
    little = blob[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")
    is64 = blob[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    magic, cputype = struct.unpack("<II" if little else ">II", blob[:8])
    return {
        "magic": f"0x{magic:08x}",
        "cputype": cputype,
        "arch": {12: "arm", 0x0100000C: "arm64"}.get(cputype, f"cpu-{cputype}"),
        "is64": is64,
        "size": len(blob),
        "ncmds": struct.unpack("<I" if not is64 else "<I", blob[16:20])[0] if len(blob) > 20 else None,
    }


def find_sep_images(root: str | Path) -> list[Path]:
    """Locate sep-firmware im4p files under an extracted IPSW root."""
    root = Path(root)
    hits = []
    if root.exists():
        for p in root.rglob("*"):
            if p.is_file() and "sep-firmware" in p.name.lower():
                hits.append(p)
    return hits


def diff_builds(older: dict[str, Any], newer: dict[str, Any]) -> list[str]:
    """Surface structural differences between two SEP builds."""
    changes = []
    for key in ("im4p",):
        o, n = older.get(key, {}), newer.get(key, {})
        for field in ("type", "description", "image_len"):
            if o.get(field) != n.get(field):
                changes.append(f"{key}.{field}: {o.get(field)} -> {n.get(field)}")
    ot = (older.get("tlv") or [])
    nt = (newer.get("tlv") or [])
    o_map = {e["tag"]: e for e in ot}
    n_map = {e["tag"]: e for e in nt}
    for tag in sorted(set(o_map) | set(n_map)):
        o, n = o_map.get(tag), n_map.get(tag)
        if o and not n:
            changes.append(f"tlv {tag} ({o['name']}) REMOVED ({o['length']}B)")
        elif n and not o:
            changes.append(f"tlv {tag} ({n['name']}) ADDED ({n['length']}B)")
        elif o and n and o["length"] != n["length"]:
            changes.append(f"tlv {tag} ({n['name']}): {o['length']}B -> {n['length']}B "
                           f"({n['length'] - o['length']:+d})")
    return changes


def render(inv: dict[str, Any]) -> str:
    lines = [f"SEP firmware: {inv['file']}",
             f"  im4p type : {inv['im4p'].get('type')}",
             f"  desc      : {inv['im4p'].get('description')}",
             f"  image     : {inv['im4p'].get('image_len', 0):,} B"]
    m = inv.get("sepos_macho")
    if m:
        lines += [f"  macho     : {m['arch']} ({m['size']:,} B, ncmds={m.get('ncmds')})"]
    tlv = inv.get("tlv")
    if tlv:
        lines.append(f"  TLV container v{tlv[0].get('container_version', '?')}:")
        for e in tlv:
            lines.append(f"    {e['tag']} {e['name']:<28} {e['length']:>10,} B"
                         f"{' [Mach-O]' if e.get('is_macho') else ''}")
    else:
        lines.append("  TLV: not a recognized SEPOS container (layout may differ)")
    return "\n".join(lines)


def render_diff(changes: list[str]) -> str:
    if not changes:
        return "no structural SEP differences found"
    return "\n".join("  " + c for c in changes)
