"""iLEAPP integration: artifact-breadth engine bridge.

iLEAPP (github.com/abrignoni/iLEAPP) is the open-source iOS parser with
100+ artifact definitions. When installed on the examiner workstation,
opensleuth delegates parsing to it and merges the results with its own
artifact inventory into a single breath report.

Honest notes:
  - iLEAPP must be installed separately (git clone + python3 deps).
  - iLEAPP is GPLv3: we invoke it as an external tool, we do not vendor
    its definitions into this repository.
  - Input: an extraction (filesystem/logical root) or a tar/gz/zip.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

INSTALL_HINT = ("iLEAPP not found. Install it first:\n"
                "  git clone https://github.com/abrignoni/iLEAPP\n"
                "  cd iLEAPP && python3 -m pip install -r requirements.txt\n"
                "  # then run iLEAPP.py directly, or set ILEAPP_DIR=/path/to/iLEAPP")


def find_iLEAPP() -> str | None:
    """Locate the iLEAPP launcher (PATH, ILEAPP_DIR, ~/iLEAPP)."""
    for cand in ("iLEAPP", "ileapp", "iLEAPP.py", "ileapp.py"):
        p = shutil.which(cand)
        if p:
            return p
    import os
    d = os.environ.get("ILEAPP_DIR")
    for base in (Path(d) if d else None, Path.home() / "iLEAPP", Path.home() / "tools" / "iLEAPP"):
        if base and (base / "iLEAPP.py").exists():
            return str(base / "iLEAPP.py")
    return None


def run_iLEAPP(inp: str | Path, out: str | Path, itype: str = "fs",
               extra: tuple[str, ...] = (), timeout: int = 1800,
               launcher: str | None = None) -> dict[str, Any]:
    """Run iLEAPP on an extraction. Returns honest status + log tail."""
    inp = Path(inp)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    launcher = launcher or find_iLEAPP()
    if launcher is None:
        return {"ok": False, "error": INSTALL_HINT}
    if not inp.exists():
        return {"ok": False, "error": f"input does not exist: {inp}"}
    cmd = [sys.executable if launcher.endswith(".py") else launcher]
    if launcher.endswith(".py"):
        cmd += [launcher]
    cmd += ["-t", itype, "-i", str(inp), "-o", str(out), *extra]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {"ok": False, "error": f"launcher not executable: {launcher}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"iLEAPP timed out after {timeout}s"}
    return {
        "ok": p.returncode == 0,
        "returncode": p.returncode,
        "log_tail": (p.stdout or p.stderr)[-1500:],
        "output_dir": str(out),
    }


def breath_report(case_dir: str | Path, ileapp_out: str | Path | None,
                  out: str | Path) -> dict[str, Any]:
    """Merge CoreProbe's DB inventory with iLEAPP output into one report."""
    from . import appcatalog as A
    case_dir = Path(case_dir)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    dbs = A.find_dbs(case_dir)
    inv = []
    for db in dbs:
        i = A.inventory(db["path"])
        if i:
            inv.append({**db, **i})
    ileapp_files = []
    if ileapp_out and Path(ileapp_out).exists():
        root = Path(ileapp_out)
        ileapp_files = [str(f.relative_to(root)) for f in sorted(root.rglob("*")) if f.is_file()]
    report = {
        "engine": {"coreprobe": len(inv), "ileapp": len(ileapp_files)},
        "coreprobe_databases": inv,
        "ileapp_outputs": ileapp_files,
    }
    path = out / "breath-report.json"
    path.write_text(json.dumps(report, indent=2, default=str))
    return {"report": str(path), **report}


def render_breath(r: dict[str, Any]) -> str:
    lines = [
        f"artifact breath report: {r['engine']}",
        "",
        f"CoreProbe databases ({len(r['coreprobe_databases'])}):",
    ]
    for db in r["coreprobe_databases"][:25]:
        app = f"  [{db.get('app')}]" if db.get("app") else ""
        lines.append(f"  {db['rel']}{app}  ({len(db.get('tables', []))} tables)")
    lines.append("")
    if r["ileapp_outputs"]:
        lines.append(f"iLEAPP outputs ({len(r['ileapp_outputs'])} files):")
        for f in r["ileapp_outputs"][:25]:
            lines.append(f"  {f}")
    else:
        lines.append("iLEAPP: no outputs (not run / no matches)")
    lines.append("")
    lines.append("full report: " + r["report"])
    return "\n".join(lines)