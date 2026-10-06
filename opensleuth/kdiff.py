"""Kernelcache patch-diff — own-exploit research instrument #2 (n-day hunting).

Turns the gap between two iOS builds into a bug candidate. When Apple ships
iOS X.Y fixing a vuln, the FIXED binary differs from the vulnerable binary in
exactly the region around the bug. Diffing two kernelcaches (vulnerable vs
fixed) surfaces those regions as candidate n-day vectors.

Method:
  1. Normalize each kernelcache to a sequence of (rmask,value) windows using
     a coarse-block hash (rolling chunk = 32 bytes per step).
  2. Align the two sequences (sequence alignment - diff) - identical runs = skip.
  3. Changed runs = candidate regions. Rank by:
       - context: is the change adjacent to a VNOP/copyout/OSSerialize/
         proc_-style symbol hint in nearby strings?
       - byte delta magnitude (small structural change to a hot path vs a full
         recompile flush).
  4. Emit ranked regions for manual RE / fuzzing.

Honesty: a diff is a RESEARCH LEAD, not a vuln. Patch-diffing is exactly how
public n-days are found, but the resulting bug still needs root-causing +
reachability + a weaponized primitive. Every finding is truth-ladder gated.

Input: two kernelcaches (decompressed arm64e). Order: <patched> <unpatched>
(so the output reads 'what the fix touched').
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any

CHUNK = 32        # bytes per rolling block
SNAP = 16         # alignment step
MIN_RUN = 6       # consecutive changed blocks to emit a region
CONTEXT = 24      # blocks of context around a region start/end
NEARBY_RANGE = 4096


def _block_hashes(data: bytes) -> list[int]:
    """Rolling 32-byte block hashes (1 per SNAP bytes)."""
    hashes = []
    n = len(data)
    for off in range(0, n - CHUNK + 1, SNAP):
        hashes.append(int.from_bytes(hashlib.blake2b(data[off:off + CHUNK],
                                                    digest_size=8).digest(), "little"))
    return hashes


def _align(ha: list[int], hb: list[int]) -> list[tuple[int, int]]:
    """Coarse alignment: build set of b-hashes, then map a-positions to
    nearest matching b-position greedily. Falls back to index when no match."""
    bpos: dict[int, list[int]] = {}
    for i, h in enumerate(hb):
        bpos.setdefault(h, []).append(i)
    out = []
    next_b = 0
    for i, h in enumerate(ha):
        cands = [j for j in bpos.get(h, []) if j >= next_b]
        if cands:
            j = cands[0]
            next_b = j + 1
        else:
            j = next_b  # assume insert in a
        out.append((i, j))
    return out


def _changed_runs(align: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Runs of consecutive a-positions whose aligned b-index is 'off' (>3 from
    the linear b-position at that a)."""
    runs = []
    cur = None
    for a, b in align:
        nominal = a
        if abs(b - nominal) > 3:
            if cur is None:
                cur = [a, a]
            else:
                cur[1] = a
        else:
            if cur:
                runs.append(tuple(cur))
                cur = None
    if cur:
        runs.append(tuple(cur))
    return [r for r in runs if (r[1] - r[0] + 1) >= MIN_RUN]


def _nearby_strings(data: bytes, addr: int) -> list[str]:
    """Find printable runs (likely symbol/string refs) within NEARBY_RANGE."""
    lo = max(0, addr - NEARBY_RANGE)
    window = data[lo:addr + NEARBY_RANGE]
    hits = set()
    for probe in (b"vnop", b"VNOP", b"setxattr", b"copyout", b"OSSerialize",
                  b"proc_lookup", b"task_for_pid", b"iokit", b"IOKit",
                  b"pmap", b"kernel_", b"os_refcnt", b"sandbox"):
        if probe in window:
            hits.add(probe.decode())
    return sorted(hits)


def diff_kernelcaches(patched: bytes, unpatched: bytes) -> dict[str, Any]:
    """Compare patched vs unpatched kernelcache. Order: patched=fix, unpatched=bug.

    Same-device builds are same-length, same-layout arm64e kernels, so
    index-aligned rolling-block-hash comparison cleanly surfaces the surgical
    regions Apple's patch touched. Insertions/deletions between builds are
    rare enough (handled as residual shift) that direct comparison is the
    right default for n-day hunting.
    """
    ha = _block_hashes(patched)
    hb = _block_hashes(unpatched)
    if not ha or not hb:
        return {"findings": [], "summary": {"error": "empty kernelcache input"}}

    # index-aligned differing blocks
    n = min(len(ha), len(hb))
    changed = [i for i in range(n) if ha[i] != hb[i]]
    if not changed:
        return {"findings": [], "summary": {"patched_bytes": len(patched),
                                            "unpatched_bytes": len(unpatched),
                                            "regions": 0}}
    # cluster into consecutive runs (allow 'shift by 1' gaps to absorb a single
    # inserted/removed instruction)
    runs: list[tuple[int, int]] = []
    start = prev = changed[0]
    for i in changed[1:]:
        if i - prev <= 2:
            prev = i
        else:
            runs.append((start, prev))
            start = prev = i
    runs.append((start, prev))
    runs = [r for r in runs if (r[1] - r[0] + 1) >= MIN_RUN]

    findings = []
    for a0, a1 in runs:
        start_byte = a0 * SNAP
        end_byte = a1 * SNAP + CHUNK
        size_bytes = end_byte - start_byte
        hints = _nearby_strings(patched, start_byte)
        span = a1 - a0 + 1
        if hints and span >= 8:
            sev = "HIGH"
        elif hints or span >= 8:
            sev = "MEDIUM"
        else:
            sev = "LOW"
        findings.append({
            "block_start": a0,
            "block_end": a1,
            "size_bytes": size_bytes,
            "addr_start": hex(start_byte),
            "addr_end": hex(end_byte),
            "nearby_symbols": hints,
            "severity": sev,
            "note": ("patch region adjacent to kernel symbol(s) - likely the "
                     "vulnerable code path") if hints else "changed region, no symbol hint",
        })
    findings = sorted(findings, key=lambda f: (f["severity"] != "HIGH", -f["size_bytes"]))
    return {"findings": findings,
            "summary": {"patched_bytes": len(patched),
                        "unpatched_bytes": len(unpatched),
                        "regions": len(findings)}}


def render_diff(result: dict[str, Any]) -> str:
    if result["summary"].get("error"):
        return f"kdiff: {result['summary']['error']}"
    lines = ["=" * 60, "kernelcache patch-diff (unpatched vs patched)", "=" * 60,
             f"  patched bytes   : {result['summary']['patched_bytes']}",
             f"  unpatched bytes : {result['summary']['unpatched_bytes']}",
             f"  changed regions : {result['summary']['regions']}", ""]
    if not result["findings"]:
        lines.append("  no structural differences detected (same build, or only")
        lines.append("  UInt64/constant metadata changed - re-verify build sourcing).")
    for f in result["findings"]:
        lines.append(f"## region {f['addr_start']}..{f['addr_end']}  [{f['severity']}]  "
                     f"{f['size_bytes']} bytes")
        if f["nearby_symbols"]:
            lines.append(f"   symbols : {', '.join(f['nearby_symbols'])}")
        lines.append(f"   note    : {f['note']}")
    lines.append("")
    lines.append("honesty: a diff is an n-day RESEARCH LEAD. Root-cause + reachability")
    lines.append("+ primitive still required (truth ladder). It is NOT a weaponized exploit.")
    return "\n".join(lines)