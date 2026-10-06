"""Kernelcache PAC-diversifier scanner — own-exploit research instrument #1.

Automates the exact technique behind CVE-2026-65330 (STAR Labs): scan the
kernelcache for FIXED PAC diversifiers in pointer-signing paths. A fixed,
publicly-known diversifier means any kernel-write primitive can forge a
validly-signed function pointer -> PC control.

What it finds (per diversifier class):
  - MOVZ imm + PACIA/PACDA/PACIB/PACDB pairs (fixed diversifier = constant imm)
  - Repeated use of the SAME constant across call sites = systemic weakness
  - Diversifier value 0 = signing with zero, the weakest case

Input: a kernelcache Mach-O (already decompressed: LZFSE/lzss handled by
`firmware extract` upstream, or feed it a raw arm64 kernelcache.bin).
Output: ranked findings (diversifier -> call sites -> affected VNOPs nearby).

Honesty: static analysis only. A finding is a RESEARCH LEAD (candidate),
not an exploit. Reachability (which VNOP/file-system path reaches the
signed call) must be proven on-device per the truth ladder.
"""

from __future__ import annotations

import struct
from typing import Any

try:
    import capstone as _capstone_mod
    _HAS_CAPSTONE = True
except ImportError:  # pragma: no cover - optional dep
    _capstone_mod = None
    _HAS_CAPSTONE = False

capstone = _capstone_mod

PAC_MNEMONICS = {"pacia", "pacda", "pacib", "pacdb",
                 "autia", "autda", "autib", "autdb"}
BRANCH_AFTER = 8  # instructions to look ahead for the AUTDA/BLR pair


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def scan_pac_diversifiers(data: bytes) -> dict[str, Any]:
    """Scan raw arm64e kernelcache bytes for fixed PAC diversifiers.

    Returns {'findings': [...], 'summary': {...}}. Findings sorted by
    severity (0-diversifier first, then by call-site count).
    """
    if not _HAS_CAPSTONE:
        return {"findings": [], "summary": {"error": "capstone not installed (pip install capstone)"}}
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = False

    # Pass 1: collect all PAC/AUT instructions with their immediate diversifiers
    events: list[dict[str, Any]] = []
    # Disassemble linearly; kernelcache is huge so step by 4-byte instructions
    # but rely on capstone to skip data pools (invalid encodings).
    for insn in md.disasm(data, 0):
        mnem = insn.mnemonic
        if mnem not in PAC_MNEMONICS:
            continue
        # diversifier is the second operand register, whose value must be
        # loaded by a preceding MOVZ/MOV (W register, immediate). Track via
        # backward scan of the last MOVZ to that register.
        diversifier = _resolve_diversifier(data, insn.address, insn.op_str)
        events.append({
            "addr": insn.address,
            "mnem": mnem,
            "op_str": insn.op_str,
            "diversifier": diversifier,  # int or None (register-derived)
        })

    # Pass 2: group by fixed diversifier value
    fixed: dict[int, list[dict[str, Any]]] = {}
    for ev in events:
        if ev["diversifier"] is not None:
            fixed.setdefault(ev["diversifier"], []).append(ev)

    findings = []
    for div, sites in sorted(fixed.items(), key=lambda kv: (kv[0] != 0, -len(kv[1]))):
        # Nearby VNOP hint: search surrounding 4KB for VNOP-setxattr-like strings
        hint = _nearby_hint(data, sites[0]["addr"])
        findings.append({
            "diversifier": div,
            "hex": hex(div),
            "call_sites": len(sites),
            "first_addr": hex(sites[0]["addr"]),
            "last_addr": hex(sites[-1]["addr"]),
            "mnemonics": sorted({s["mnem"] for s in sites}),
            "nearby_hint": hint,
            "severity": "HIGH" if div == 0 or len(sites) > 3 else "MEDIUM",
            "note": ("zero diversifier: PAC signs with constant 0 - any "
                     "attacker can forge with PACIA(x, 0)") if div == 0 else
                    ("fixed non-zero diversifier: forgeable once known "
                     "(CVE-2026-65330 pattern, div 0x307a)"),
        })
    return {"findings": findings,
            "summary": {"pac_events": len(events),
                        "fixed_diversifiers": len(fixed),
                        "total_bytes": len(data)}}


def _resolve_diversifier(data: bytes, addr: int, op_str: str) -> int | None:
    """Walk backwards up to 32 instructions looking for MOVZ Wn, #imm that
    feeds the diversifier register in the PAC op_str (second operand)."""
    try:
        # op_str like "x0, x1" -> diversifier register = second
        reg = op_str.split(",")[1].strip()
    except IndexError:
        return None
    # normalize width: diversifier is Wn when MOVR uses Wn, Xn in PAC -> strip leading
    reg = reg.lstrip("x").lstrip("w")
    back = 32 * 4
    start = max(0, addr - back)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    found = None
    for insn in md.disasm(data[start:addr + 4], start):
        dst = insn.op_str.split(",")[0].strip().lstrip("x").lstrip("w")
        if insn.mnemonic in ("movz", "mov", "orr") and dst == reg:
            # MOVZ Wn, #imm pattern
            parts = insn.op_str.split(",")
            if len(parts) == 2:
                imm = parts[1].strip()
                if imm.startswith("#"):
                    imm = imm[1:]
                try:
                    found = int(imm, 0)
                except ValueError:
                    found = None
    return found


def _nearby_hint(data: bytes, addr: int) -> str | None:
    """Look for nearby C-string hints (VNOP names, handlers) within 2KB."""
    lo = max(0, addr - 2048)
    window = data[lo:addr + 2048]
    for probe in (b"setxattr", b"removexattr", b"getxattr", b"setattrlist",
                  b"vnop", b"VNOP", b"tmpfs", b"apfs"):
        i = window.find(probe)
        if i >= 0:
            return probe.decode()
    return None


def render_scan(result: dict[str, Any]) -> str:
    if result["summary"].get("error"):
        return f"pacscan: {result['summary']['error']}"
    lines = ["=" * 60, "kernelcache PAC-diversifier scan", "=" * 60,
             f"  PAC events          : {result['summary']['pac_events']}",
             f"  fixed diversifiers  : {result['summary']['fixed_diversifiers']}",
             ""]
    if not result["findings"]:
        lines.append("  no fixed diversifiers found - kernelcache appears hardened.")
        lines.append("  (this is the EXPECTED state post-26.6.1; try an older build)")
    for f in result["findings"]:
        lines.append(f"## diversifier {f['hex']}  [{f['severity']}]  "
                     f"{f['call_sites']} call sites")
        lines.append(f"   mnemonics : {', '.join(f['mnemonics'])}")
        lines.append(f"   range     : {f['first_addr']} .. {f['last_addr']}")
        if f["nearby_hint"]:
            lines.append(f"   nearby    : {f['nearby_hint']}")
        lines.append(f"   note      : {f['note']}")
        lines.append("")
    lines.append("honesty: static lead only. A fixed diversifier is a CANDIDATE "
                 "- reachability must be proven on-device (truth ladder: "
                 "DOCUMENTED -> PUBLIC_POC -> LAB_REPRODUCED).")
    return "\n".join(lines)
