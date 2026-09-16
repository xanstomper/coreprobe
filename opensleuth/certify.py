"""Court-ready reporting: chain-of-custody manifest + integrity seal.

certify() walks a case directory, hashes every evidence file (native
osleuth_core when built, hashlib fallback), builds an examiner-signed
manifest, and seals it with HMAC-SHA256 so any tampering is detectable.

verify() recomputes hashes and the seal, reporting per-file integrity.

Usage:
  opensleuth certify <case-dir> --out <out-dir> --examiner "Jane Doe" \
      [--keyfile seal.key | --passphrase-env OPENSLEUTH_SEAL_PHRASE]
  opensleuth certify --verify <sealed-report.json>
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST_NAME = "evidence-manifest.csv"
REPORT_NAME = "sealed-report.json"
REPORT_HTML = "sealed-report.html"
KEY_NAME = "seal.key"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _native_hash(f: Path) -> str:
    """Prefer the C++ SHA-256 (fast); fall back to hashlib."""
    try:
        from . import cxx
        binary = cxx.binary()
        p = subprocess.run([str(binary), "hash", str(f)],
                           capture_output=True, text=True, timeout=120)
        if p.returncode == 0:
            line = [l for l in p.stdout.splitlines() if l.startswith("SHA256")][-1]
            return line.split()[1]
    except Exception:  # noqa: BLE001
        pass
    h = hashlib.sha256()
    with open(f, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _derive_key(passphrase: str | None, keyfile: Path | None, out: Path) -> bytes:
    if passphrase:
        return hashlib.sha256(passphrase.encode()).digest()
    if keyfile and keyfile.exists():
        return keyfile.read_bytes()[:32]
    key = os.urandom(32)
    dest = keyfile or (out / KEY_NAME)
    dest.write_bytes(key)
    try:
        os.chmod(dest, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return key


def _manifest_lines(entries: list[dict[str, Any]]) -> str:
    lines = ["sha256,size,relpath"]
    for e in sorted(entries, key=lambda x: x["relpath"]):
        lines.append(f"{e['sha256']},{e['size']},{e['relpath']}")
    return "\n".join(lines) + "\n"


def certify(case_dir: str | Path, out: str | Path, examiner: str,
            passphrase: str | None = None, keyfile: str | Path | None = None,
            tool: str = "opensleuth") -> dict[str, Any]:
    case_dir = Path(case_dir)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    if not case_dir.exists():
        raise FileNotFoundError(f"case dir not found: {case_dir}")

    entries: list[dict[str, Any]] = []
    for f in sorted(case_dir.rglob("*")):
        if not f.is_file():
            continue
        if out in f.parents:
            continue
        try:
            rel = f.relative_to(case_dir).as_posix()
            size = f.stat().st_size
        except OSError:
            continue
        entries.append({"relpath": rel, "size": size,
                        "sha256": _native_hash(f), "mtime": _now()})

    manifest_csv = _manifest_lines(entries)
    (out / MANIFEST_NAME).write_text(manifest_csv)

    key = _derive_key(passphrase, Path(keyfile) if keyfile else None, out)
    seal = hmac.new(key, manifest_csv.encode(), hashlib.sha256).hexdigest()

    report = {
        "tool": tool,
        "generated_at": _now(),
        "examiner": examiner,
        "case_dir": str(case_dir),
        "file_count": len(entries),
        "hash_engine": "osleuth_core(cpp)" if _cpp_available() else "hashlib(py)",
        "seal_algorithm": "HMAC-SHA256",
        "seal": seal,
        "manifest": MANIFEST_NAME,
        "files": entries,
    }
    (out / REPORT_NAME).write_text(json.dumps(report, indent=2))
    (out / REPORT_HTML).write_text(_html(report))
    return {"report": str(out / REPORT_NAME), "manifest": str(out / MANIFEST_NAME),
            "html": str(out / REPORT_HTML), "file_count": len(entries),
            "seal": seal, "seal_key": str(out / KEY_NAME) if not keyfile and not passphrase else None}


def _cpp_available() -> bool:
    try:
        from . import cxx
        return cxx.binary().exists()
    except Exception:  # noqa: BLE001
        return False


def verify(report_path: str | Path, passphrase: str | None = None,
           keyfile: str | Path | None = None) -> dict[str, Any]:
    report_path = Path(report_path)
    report = json.loads(report_path.read_text())
    entries = report["files"]
    failures = []
    for e in entries:
        f = Path(report["case_dir"]) / e["relpath"]
        if not f.exists():
            failures.append({"relpath": e["relpath"], "status": "missing"})
            continue
        cur = _native_hash(f)
        if cur != e["sha256"]:
            failures.append({"relpath": e["relpath"], "status": "TAMPERED",
                             "expected": e["sha256"], "actual": cur})
    manifest_csv = _manifest_lines(entries)
    if keyfile is None and not passphrase:
        candidate = report_path.parent / KEY_NAME
        if candidate.exists():
            keyfile = candidate
    key = _derive_key(passphrase, Path(keyfile) if keyfile else None, report_path.parent)
    seal_ok = hmac.compare_digest(
        report["seal"], hmac.new(key, manifest_csv.encode(), hashlib.sha256).hexdigest())
    return {
        "report": str(report_path),
        "examiner": report.get("examiner"),
        "generated_at": report.get("generated_at"),
        "file_count": len(entries),
        "seal_valid": seal_ok,
        "tampered": len(failures),
        "failures": failures,
        "integrity_ok": seal_ok and not failures,
    }


def render_verify(v: dict[str, Any]) -> str:
    lines = [
        f"integrity verification: {v['report']}",
        f"  examiner   : {v['examiner']}",
        f"  generated  : {v['generated_at']}",
        f"  files      : {v['file_count']}",
        f"  seal       : {'VALID' if v['seal_valid'] else 'INVALID - TAMPERED'}",
        f"  tampered   : {v['tampered']}",
    ]
    for f in v["failures"]:
        lines.append(f"    {f['status']} {f['relpath']}")
    lines.append("")
    lines.append("OVERALL: INTEGRITY OK" if v["integrity_ok"] else "OVERALL: INTEGRITY BROKEN")
    return "\n".join(lines)


def _html(report: dict[str, Any]) -> str:
    rows = "".join(
        f"<tr><td class='mono'>{e['relpath']}</td><td>{e['size']:,}</td>"
        f"<td class='mono'>{e['sha256']}</td></tr>"
        for e in report["files"])
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Sealed evidence report</title>
<style>body{{font-family:ui-monospace,monospace;background:#0a0b0d;color:#c9cfd8;padding:24px}}
h1{{color:#fff}} .seal{{border:1px solid #2a3040;border-radius:6px;padding:12px;margin:12px 0;background:#0e1013}}
table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #1e2129;padding:6px;text-align:left;font-size:12px}}
.mono{{font-family:ui-monospace,monospace}}</style></head><body>
<h1>Sealed Evidence Report</h1>
<div class="seal">
<b>Examiner:</b> {report['examiner']} &nbsp; <b>Generated:</b> {report['generated_at']}<br>
<b>Files:</b> {report['file_count']} &nbsp; <b>Hash engine:</b> {report['hash_engine']}<br>
<b>Seal (HMAC-SHA256):</b> <span class="mono">{report['seal']}</span>
</div>
<table><thead><tr><th>Relpath</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>"""