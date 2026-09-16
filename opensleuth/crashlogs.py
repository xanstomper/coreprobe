"""Crash-log parser for iOS CrashReporter .ips files.

Logical backups and BFU pulls carry CrashReporter bundles
(/Media/Library/Logs/CrashReporter/*). Each .ips is two JSON documents
separated by a newline: metadata then the crash body. Parsing them gives
the examiner: crashing process, exception, faulting frames, and app
versions - pattern-of-life + incident evidence.

Honesty: real .ips files vary by iOS version; the parser tolerates
missing fields and unknown formats (returns None rows, never invents).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse_ips(text: str, source: str = "<ips>") -> dict[str, Any] | None:
    lines = text.splitlines()
    if not lines:
        return None
    try:
        meta = json.loads(lines[0])
    except json.JSONDecodeError:
        return None
    body = None
    if len(lines) > 1:
        try:
            body = json.loads("\n".join(lines[1:]))
        except json.JSONDecodeError:
            body = None
    if not isinstance(meta, dict):
        return None
    faulting = (body or {}).get("faultingFrame") or {}
    exc = (body or {}).get("exception") or {}
    return {
        "source": source,
        "name": meta.get("name") or Path(source).stem,
        "app_name": meta.get("app_name"),
        "timestamp": meta.get("timestamp"),
        "os_version": meta.get("os_version"),
        "bundle_id": (body or {}).get("bundleInfo", {}).get("bundleID"),
        "exception_type": exc.get("type") or exc.get("signal"),
        "exception_codes": exc.get("codes"),
        "termination_reason": exc.get("terminationReason")
        or (body or {}).get("termination", {}).get("indicator"),
        "bug_type": meta.get("bug_type"),
        "incident_id": meta.get("incident_id"),
        "is_official": meta.get("isOfficial"),
        "faulting_frame": faulting.get("imageIndex"),
        "faulting_image": faulting.get("image"),
        "faulting_symbol": faulting.get("symbol"),
        "faulting_offset": faulting.get("imageOffset"),
        "process": (body or {}).get("procName") or meta.get("app_name"),
        "pid": (body or {}).get("pid"),
        "cpu_type": (body or {}).get("cpuType"),
    }


def scan_dir(root: str | Path) -> list[dict[str, Any]]:
    root = Path(root)
    out = []
    if not root.exists():
        return out
    for f in sorted(root.rglob("*.ips")):
        try:
            parsed = parse_ips(f.read_text(errors="replace"), source=str(f))
        except OSError:
            continue
        if parsed:
            rel = f.relative_to(root).as_posix()
            out.append({**parsed, "rel": rel})
    return out


def summarize(crashes: list[dict[str, Any]]) -> dict[str, Any]:
    from collections import Counter
    by_app = Counter(c.get("process") or c.get("app_name") or "?" for c in crashes)
    by_exc = Counter(c.get("exception_type") or "?" for c in crashes)
    return {"total": len(crashes), "by_process": dict(by_app),
            "by_exception": dict(by_exc)}


def render(crashes: list[dict[str, Any]], limit: int = 30) -> str:
    if not crashes:
        return "no crash logs (.ips) found"
    s = summarize(crashes)
    lines = [f"crash logs: {s['total']} parsed",
             f"  by process  : {s['by_process']}",
             f"  by exception: {s['by_exception']}", ""]
    for c in crashes[:limit]:
        sym = f"!{c['faulting_symbol']}" if c.get("faulting_symbol") else ""
        lines.append(
            f"  {c.get('timestamp') or '?'}  {c.get('process') or c.get('name')}"
            f"  [{c.get('exception_type') or '?'}] {sym}")
    if len(crashes) > limit:
        lines.append(f"  ... {len(crashes) - limit} more")
    return "\n".join(lines)