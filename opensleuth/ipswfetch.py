"""Partial IPSW fetch: range-download only sep-firmware from Apple's CDN.

IPSWs are plain ZIPs (~6GB) but HTTP supports range requests. We read
the end-of-central-directory + central directory (few KB), find the
sep-firmware entry, and fetch just that member (a few MB) — enabling
SEPOS build libraries without terabyte downloads.
"""

from __future__ import annotations

import struct
import urllib.request
from pathlib import Path
from typing import Any

UA = {"User-Agent": "CoreProbe-Research/0.1"}


def _tail(url: str, n: int = 65536, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={**UA, "Range": f"bytes=-{n}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _total_size(url: str, timeout: int = 60) -> int:
    req = urllib.request.Request(url, method="HEAD", headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return int(r.headers.get("Content-Length", 0))


def parse_central(tail: bytes, total: int) -> list[dict[str, Any]]:
    """Parse ZIP central-directory records from a file-tail buffer."""
    eocd_off = tail.rfind(b"PK\x05\x06")
    if eocd_off < 0:
        raise ValueError("EOCD not found in tail")
    eocd = tail[eocd_off:eocd_off + 22]
    _, _, _, _, n_entries, cd_size, cd_off, _ = struct.unpack("<IHHHHIIH", eocd)
    # ZIP64: offsets may be 0xFFFFFFFF; the CD always sits immediately
    # before the EOCD record, so derive it from the tail window instead.
    cd = tail[max(0, eocd_off - cd_size):eocd_off]
    entries = []
    off = 0
    while off + 46 <= len(cd) and len(entries) < n_entries:
        if cd[off:off + 4] != b"PK\x01\x02":
            break
        (sig, ver_made, ver_need, flags, method, mtime, mdate, crc,
         csize, usize, nlen, elen, clen, disk, iattr, eattr, lho) = \
            struct.unpack("<IHHHHHHIIIHHHHHII", cd[off:off + 46])
        name = cd[off + 46:off + 46 + nlen].decode("utf-8", "replace")
        entries.append({"name": name, "compressed": csize, "size": usize,
                        "method": method, "header_offset": lho})
        off += 46 + nlen + elen + clen
    return entries


def _zip64_cd_location(tail: bytes, total: int) -> tuple[int, int] | None:
    """Return (cd_offset, cd_size) from the ZIP64 EOCD record, or None."""
    import struct as _st
    eocd_off = tail.rfind(b"PK\x05\x06")
    if eocd_off < 0:
        return None
    z64 = tail.rfind(b"PK\x06\x07", 0, eocd_off)
    if z64 < 0:
        return None
    (eocd64_off,) = _st.unpack("<Q", tail[z64 + 8:z64 + 16])
    z64rec = eocd64_off - (total - len(tail))
    if z64rec < 0:
        return None
    rec = tail[z64rec:z64rec + 56]
    if rec[:4] != b"PK\x06\x06":
        return None
    cdsize, cdoff = _st.unpack("<QQ", rec[40:56])
    return cdoff, cdsize


def find_member(url: str, pattern: str = "sep-firmware", timeout: int = 60) -> dict[str, Any] | None:
    import struct as _st
    total = _total_size(url, timeout)
    if not total:
        raise ValueError("no content-length (range unsupported?)")
    tail = _tail(url, 1 << 20, timeout)  # 1 MiB covers big central dirs
    loc = _zip64_cd_location(tail, total)
    if loc:
        cdoff, cdsize = loc
        req = urllib.request.Request(url, headers={**UA, "Range": f"bytes={cdoff}-{cdoff + cdsize - 1}"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            cd = r.read()
    else:
        eocd_off = tail.rfind(b"PK\x05\x06")
        if eocd_off < 0:
            raise ValueError("no EOCD found")
        n_entries, cd_size, _ = _st.unpack("<HII", tail[eocd_off + 10:eocd_off + 20])
        cd = tail[max(0, eocd_off - cd_size):eocd_off]
    entries = []
    off = 0
    while off + 46 <= len(cd) and cd[off:off + 4] == b"PK\x01\x02":
        (_, _, _, _, method, _, _, _, csize, usize, nlen, elen, clen, _, _, _, lho) = \
            _st.unpack("<IHHHHHHIIIHHHHHII", cd[off:off + 46])
        name = cd[off + 46:off + 46 + nlen].decode("utf-8", "replace")
        # ZIP64 extra field (0x0001) carries 64-bit csize/usize/lho when
        # the base fields are 0xFFFFFFFF
        extra = cd[off + 46 + nlen:off + 46 + nlen + elen]
        eoff = 0
        while eoff + 4 <= len(extra):
            hid, hsize = _st.unpack("<HH", extra[eoff:eoff + 4])
            if hid == 0x0001:
                body = extra[eoff + 4:eoff + 4 + hsize]
                boff = 0
                if usize == 0xFFFFFFFF and boff + 8 <= len(body):
                    usize = _st.unpack("<Q", body[boff:boff + 8])[0]; boff += 8
                if csize == 0xFFFFFFFF and boff + 8 <= len(body):
                    csize = _st.unpack("<Q", body[boff:boff + 8])[0]; boff += 8
                if lho == 0xFFFFFFFF and boff + 8 <= len(body):
                    lho = _st.unpack("<Q", body[boff:boff + 8])[0]; boff += 8
                break
            eoff += 4 + hsize
        entries.append({"name": name, "compressed": csize, "size": usize,
                        "method": method, "header_offset": lho})
        off += 46 + nlen + elen + clen
    for e in entries:
        if pattern in e["name"] and not e["name"].endswith(".plist"):
            e["total_ipsw"] = total
            return e
    return None


def fetch_member(url: str, entry: dict[str, Any], timeout: int = 300) -> bytes:
    """Range-fetch the local-file header + compressed member data."""
    # local header ~30B + name; fetch a chunk and re-derive exact bounds
    start = entry["header_offset"]
    span = 30 + len(entry["name"]) + 512 + entry["compressed"]
    req = urllib.request.Request(url, headers={**UA, "Range": f"bytes={start}-{start + span}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        blob = r.read()
    lfh_sig, _, _, method, _, _, crc, csize, usize, nlen, elen = \
        struct.unpack("<IHHHHHIIIHH", blob[:30])
    if lfh_sig != 0x04034B50:
        raise ValueError(f"bad local header at {start}")
    data_off = 30 + nlen + elen
    return blob[data_off:data_off + csize]


def fetch_sep_firmware(url: str, out: str | Path, timeout: int = 300) -> Path:
    import zlib
    entry = find_member(url, "sep-firmware", timeout)
    if entry is None:
        raise ValueError("no sep-firmware in this IPSW")
    raw = fetch_member(url, entry, timeout)
    if entry["method"] == 0:
        data = raw
    elif entry["method"] == 8:
        data = zlib.decompress(raw, -15)
    else:
        raise ValueError(f"unsupported compression {entry['method']}")
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    print(f"{entry['name']}: {entry['size']:,} B (deflate {entry['compressed']:,} B)"
          f" from {entry['total_ipsw']:,} B ipsw -> {out}")
    return out