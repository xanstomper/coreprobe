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


def _read_asn1_tlv(data: bytes, off: int) -> tuple[int, bytes, int]:
    tag = data[off]
    loff = off + 1
    ln = data[loff]
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[loff + 1:loff + 1 + n], "big")
        hdr = 2 + n
    else:
        hdr = 2
    return tag, data[off + hdr:off + hdr + ln], off + hdr + ln


def parse_asn1_im4p(data: bytes, source: str = "<data>") -> dict[str, Any] | None:
    """Parse the DER/BER im4p layout used by real Apple images.

    SEQUENCE { IA5String "IM4P", IA5String type, IA5String desc,
                OCTET STRING payload, [OCTET STRING kbag ...] }
    Returns None if the data is not this layout.
    """
    try:
        tag, seq, _ = _read_asn1_tlv(data, 0)
        if tag != 0x30:
            return None
        # children: IA5String "IM4P", IA5String type, IA5String desc, OCTET payload...
        off = 0
        fields = []
        while off < len(seq) and len(fields) < 8:
            t, v, off = _read_asn1_tlv(seq, off)
            fields.append((t, v))
        if len(fields) < 4:
            return None
        (t0, magic), (t1, ptype), (t2, desc), (t3, payload) = fields[:4]
        if magic != b"IM4P":
            return None
        kbags = [v for t, v in fields[4:] if t == 0x04]
        # kbag structure: SEQ { INT version, OCTET STRING salt, OCTET STRING iv }
        kbag_info = []
        for kb in kbags:
            try:
                _, ks, o2 = _read_asn1_tlv(kb, 0)
                if ks[:2] != b"\x07\x02":
                    # embedded seq
                    _, ks2, o2 = _read_asn1_tlv(ks, 0) if ks[0] in (0x30,) else (0, ks, 0)
                    ks = ks2
                # walk: INT(1B) OCTET(16 salt) OCTET(16 iv) OCTET(32 key)?
                info = {"len": len(kb)}
                so = 0
                parts = []
                while so < len(ks):
                    tt, vv, so = _read_asn1_tlv(ks, so)
                    parts.append((tt, vv))
                info["parts"] = [(f"0x{tt:02x}", len(vv)) for tt, vv in parts]
                kbag_info.append(info)
            except Exception:  # noqa: BLE001
                kbag_info.append({"len": len(kb)})
        import hashlib as _h
        import re as _re
        # desc is hex-encoded ASCII text for sep images; decode for facts
        try:
            desc_bytes = bytes.fromhex(desc.decode("latin-1"))
        except (ValueError, UnicodeDecodeError):
            desc_bytes = desc
        facts = {"manifest_sha256": _h.sha256(desc_bytes).hexdigest()}
        # version integers travel as 02 02 XX XX / 02 04 XX XX XX XX ints
        # inside the desc; extract the small ones as build fingerprints
        ints = [int.from_bytes(m, "big") for m in
                _re.findall(rb"\x02\x04(\x00\x00?.{2})", desc_bytes, _re.S)]
        if not ints:
            ints = [int.from_bytes(m, "big") for m in
                    _re.findall(rb"\x02\x02(.{2})", desc_bytes, _re.S)]
        facts["manifest_ints"] = ints[:6]
        for marker in (b"impl", b"tbms", b"tz0s", b"tsss", b"arm"):
            facts[marker.decode()] = marker in desc_bytes
        return {
            "layout": "asn1",
            "type": ptype.decode("latin-1", "replace"),
            "description": desc.decode("latin-1", "replace")[:80],
            "manifest_facts": facts,
            "payload": payload,
            "payload_len": len(payload),
            "payload_sha256": _h.sha256(payload).hexdigest(),
            "encrypted": bool(kbags),
            "kbag_count": len(kbags),
            "kbags": kbag_info[:4],
        }
    except Exception:  # noqa: BLE001
        return None


def extract_sep_image(im4p_path: str | Path) -> dict[str, Any]:
    """Parse a sep-firmware.im4p and return its TLV inventory + raw SEPOS image."""
    data = Path(im4p_path).read_bytes()
    asn1 = parse_asn1_im4p(data, source=str(im4p_path))
    if asn1 is not None:
        image = asn1["payload"]
        out = {
            "file": str(im4p_path),
            "im4p": {k: v for k, v in asn1.items() if k != "payload"},
            "tlv": parse_tlv(image) if not asn1["encrypted"] else None,
            "sepos_macho": None,
            "payload_sha256": asn1.get("payload_sha256"),
        }
        if not asn1["encrypted"]:
            out["sepos_macho"] = analyze_macho(image)
            if not out["sepos_macho"] and out["tlv"]:
                for e_start in _macho_offsets(image):
                    m = analyze_macho(image[e_start:])
                    if m:
                        out["sepos_macho"] = m
                        break
        else:
            # entropy check: high entropy = confirmed encrypted/encoded
            import math
            from collections import Counter as _C
            counts = _C(image[::64])
            ent = -sum((c / len(image[::64])) * math.log2(c / len(image[::64]))
                       for c in counts.values())
            out["payload_entropy"] = round(ent, 2)
        return out
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
    im4p = inv.get("im4p", {})
    lines = [f"SEP firmware: {inv['file']}",
             f"  im4p type : {im4p.get('type')}",
             f"  desc      : {im4p.get('description')}",
             f"  layout    : {im4p.get('layout', 'binary')}",
             f"  image     : {im4p.get('payload_len') or im4p.get('image_len', 0):,} B"]
    facts = im4p.get("manifest_facts") or {}
    if facts.get("manifest_sha256"):
        lines.append(f"  payload sha256 : {inv.get('payload_sha256', facts['manifest_sha256'])[:32]}...")
        lines.append(f"  manifest ints  : {facts.get('manifest_ints')}")
        present = [k for k in ("impl", "tbms", "tz0s", "tsss", "arm") if facts.get(k)]
        lines.append(f"  manifest tags  : {', '.join(present)}")
    if im4p.get("encrypted"):
        lines.append(f"  ENCRYPTED : {im4p.get('kbag_count')} kbag(s) present "
                     f"(UID/GID-wrapped) - payload entropy {inv.get('payload_entropy', '?')} bits/byte")
        lines.append("              decrypt requires the GID key (gaster keys on pwned "
                     "DFU, or a publicly dumped image)")
        return "\n".join(lines)
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


# ---------------------------------------------------------------------------
# Decrypt + binary analysis: turns a pwned-device GID key into real SEPOS
# code analysis in one command. The pipeline is fully built; it starts
# producing attack-surface knowledge the moment key material exists.
# ---------------------------------------------------------------------------

def decrypt_payload(im4p_path: str | Path, gid_key: str | Path | bytes,
                    out: str | Path | None = None) -> dict[str, Any]:
    """Decrypt the SEPOS payload with the device GID key (from gaster keys).

    Encrypted sep payloads are AES-256-CBC with a zero IV, keyed by the
    GID key (per Apple's documented image encryption: 0x837-style keys
    applied via the crypto engine). gaster `keys` output on a pwned
    device supplies the GID-derived key material.
    """
    from Crypto.Cipher import AES
    data = Path(im4p_path).read_bytes()
    asn1 = parse_asn1_im4p(data, source=str(im4p_path))
    if asn1 is None:
        raise ValueError(f"{im4p_path}: not an asn1 im4p")
    if not asn1.get("encrypted"):
        raise ValueError("payload is not encrypted (nothing to decrypt)")
    if not isinstance(gid_key, bytes):
        kp = Path(gid_key)
        if kp.exists():
            key = kp.read_bytes()
        else:
            try:
                key = bytes.fromhex(str(gid_key).replace(" ", ""))
            except ValueError:
                raise ValueError("gid key must be a file path or hex")
    else:
        key = gid_key
    # try the two plausible key sizes/lengths
    payload = asn1["payload"]
    for keylen in (32, 16):
        if len(key) < keylen:
            continue
        k = key[:keylen]
        try:
            plain = AES.new(k, AES.MODE_CBC, b"\x00" * 16).decrypt(payload)
        except Exception:  # noqa: BLE001
            continue
        if _looks_like_sepos(plain):
            dest = Path(out) if out else Path(im4p_path).with_suffix(".sepos")
            dest.write_bytes(plain)
            return {"ok": True, "decrypted": str(dest), "size": len(plain),
                    "macho": analyze_macho(plain),
                    "tlv": parse_tlv(plain)}
    return {"ok": False,
            "error": "decryption produced no valid SEPOS structure (wrong key or key length)"}


def _looks_like_sepos(plain: bytes) -> bool:
    if plain[:5] == b"SEPOS":
        return True
    if plain[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                     b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        return True
    # TLV: content entropy drop below 6 bits/sample is a strong signal
    if len(plain) < 4096:
        return False
    from collections import Counter
    import math
    sample = plain[::512]
    c = Counter(sample)
    ent = -sum((n / len(sample)) * math.log2(n / len(sample)) for n in c.values())
    return ent < 6.0


def analyze_binary(sepos_bin: str | Path) -> dict[str, Any]:
    """Struct analysis of a DECRYPTED SEPOS image (Mach-O + segments)."""
    import struct
    data = Path(sepos_bin).read_bytes()
    out: dict[str, Any] = {"file": str(sepos_bin), "size": len(data)}
    m = analyze_macho(data)
    if not m:
        out["error"] = "not a Mach-O (may be TLV-wrapped; check tlv)"
        t = parse_tlv(data)
        if t:
            out["tlv"] = t
            for e in t:
                if e.get("is_macho"):
                    out["macho"] = analyze_macho("")
        return out
    out["macho"] = m
    # parse load commands: LC_SEGMENT_64 = 0x19, LC_UNIXTHREAD = 0x5
    ncmds = m.get("ncmds") or 0
    off = 32
    segments = []  # pragma: no cover (data-dependent)
    for _ in range(min(ncmds, 64)):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack("<II", data[off:off + 8])
        if cmdsize < 8:
            break
        if cmd == 0x19 and cmdsize >= 72:
            segname = data[off + 8:off + 24].split(b"\x00")[0].decode("latin-1")
            vmaddr, vmsize = struct.unpack("<QQ", data[off + 24:off + 40])
            segments.append({"name": segname, "vmaddr": hex(vmaddr),
                             "size": vmsize})
        off += cmdsize
    out["segments"] = segments
    # strings of interest (version/panic markers)
    import re
    interesting = sorted(set(re.findall(rb"[A-Za-z0-9_\/\.\-]{6,}", data[:1 << 20])) &
                         {s for s in re.findall(rb"[A-Za-z_]{4,}", data[:1 << 16])})
    out["symbol_markers"] = [s.decode("latin-1", "replace") for s in
                             interesting[:60] if any(k in s.lower() for k in
                             (b"sep", b"kbag", b"key", b"pass", b"counter", b"error", b"panic", b"auth"))]
    return out


def diff_binaries(old_bin: str | Path, new_bin: str | Path,
                  window: int = 4096) -> dict[str, Any]:
    """Byte-region diff between two decrypted SEPOS builds.

    Reports contiguous changed regions - these are WHERE Apple modified
    SEP behavior between builds (patch-diffing; each changed region is a
    candidate study target, esp. near kbag/counter handling).
    """
    a = Path(old_bin).read_bytes()
    b = Path(new_bin).read_bytes()
    n = min(len(a), len(b))
    regions = []
    start = None
    for i in range(0, n, 16):
        if a[i:i + 16] != b[i:i + 16]:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= 16:
                regions.append((start, i))
            start = None
    if start is not None:
        regions.append((start, n))
    merged = []
    for s, e in regions:
        if merged and s - merged[-1][1] <= window:
            merged[-1] = (merged[-1][0], e)
        else:
            merged.append((s, e))
    changed = sum(e - s for s, e in merged)
    return {"old": str(old_bin), "new": str(new_bin),
            "old_size": len(a), "new_size": len(b),
            "differing_bytes": changed,
            "changed_regions": [{"offset": s, "length": e - s,
                                 "pct": round(100 * (e - s) / max(len(a), 1), 3)}
                                for s, e in merged[:200]],
            "region_count": len(merged)}


def render_bin(a: dict[str, Any]) -> str:
    lines = [f"SEPOS binary: {a['file']} ({a['size']:,} B)"]
    m = a.get("macho") or {}
    if m:
        lines += [f"  macho: {m.get('arch')} ncmds={m.get('ncmds')}"]
    for s in a.get("segments", []):
        lines.append(f"  SEG {s['name']:<10} {s['vmaddr']}  {s['size']:,}")
    if a.get("symbol_markers"):
        lines.append("  markers: " + ", ".join(a["symbol_markers"][:20]))
    if "error" in a:
        lines.append(f"  error: {a['error']}")
    return "\n".join(lines)


def render_region_diff(d: dict[str, Any]) -> str:
    lines = [f"SEPOS binary diff: {d['old']} -> {d['new']}",
             f"  sizes: {d['old_size']:,} -> {d['new_size']:,} B",
             f"  differing bytes: {d['differing_bytes']:,} "
             f"({round(100 * d['differing_bytes'] / max(d['new_size'], 1), 2)}%)",
             f"  changed regions: {d['region_count']}", ""]
    for r in d["changed_regions"][:40]:
        lines.append(f"  0x{r['offset']:08x}  +{r['length']:,}B  ({r['pct']}%)")
    return "\n".join(lines)
