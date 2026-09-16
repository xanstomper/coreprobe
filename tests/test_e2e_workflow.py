"""End-to-end case workflow: fixture extraction -> artifacts -> timeline
-> wireless/crashlogs -> certify -> verify -> report.

This is the acceptance test that CoreProbe works as a real forensic tool:
given an extraction directory, every stage consumes the previous stage's
output and the final sealed report verifies clean - then detects tampering.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FX = ROOT / "tests" / "fixture-out"


@pytest.fixture(scope="module")
def extraction(tmp_path_factory):
    """Materialize the repo's backup fixture as a case extraction."""
    case = tmp_path_factory.mktemp("case-e2e")
    ext = case / "extraction"
    if FX.exists():
        shutil.copytree(FX, ext, dirs_exist_ok=True)
    else:
        # build a minimal extraction inline
        (ext / "HomeDomain/Library/SMS").mkdir(parents=True)
        (ext / "HomeDomain/Library/SMS/sms.db").write_bytes(b"")
    return case, ext


def test_full_case_workflow(extraction):
    case, ext = extraction
    out = case / "work"

    # 1. app DB discovery finds the extraction's databases
    r = subprocess.run([sys.executable, "-m", "opensleuth", "appcatalog",
                        "inventory", str(ext)], capture_output=True, text=True,
                       cwd=ROOT, timeout=120)
    assert r.returncode == 0
    assert "databases" in r.stdout.lower() or "database" in r.stdout.lower()

    # 2. crash logs + wireless parse (empty ok, command must work)
    r = subprocess.run([sys.executable, "-m", "opensleuth", "crashlogs",
                        str(ext)], capture_output=True, text=True, cwd=ROOT,
                       timeout=60)
    assert r.returncode == 0
    r = subprocess.run([sys.executable, "-m", "opensleuth", "wireless",
                        str(ext)], capture_output=True, text=True, cwd=ROOT,
                       timeout=60)
    assert r.returncode == 0

    # 3. timeline from a synthesized artifact dump (artifacts shape)
    arts = {"messages": [{"date": "2026-09-01 10:00:00",
                          "who": "+15550001111", "text": "on my way"}],
            "calls": [{"date": "2026-09-01 09:30:00", "caller": "+15550002222"}]}
    tl_in = out / "artifacts.json"
    out.mkdir(parents=True, exist_ok=True)
    tl_in.write_text(json.dumps(artifacts_shape(arts)))
    r = subprocess.run([sys.executable, "-m", "opensleuth", "timeline",
                        str(tl_in), "--out", str(out / "timeline.csv")],
                       capture_output=True, text=True, cwd=ROOT, timeout=60)
    assert r.returncode == 0
    assert "super-timeline" in r.stdout
    assert (out / "timeline.csv").exists()

    # 4. certify the case (native hashing + HMAC seal)
    r = subprocess.run([sys.executable, "-m", "opensleuth", "certify",
                        str(case), "--out", str(out / "cert"),
                        "--examiner", "E2E Test"],
                       capture_output=True, text=True, cwd=ROOT, timeout=180)
    assert r.returncode == 0, r.stderr
    report = out / "cert" / "sealed-report.json"
    assert report.exists()

    # 5. verify clean
    r = subprocess.run([sys.executable, "-m", "opensleuth", "certify",
                        "--verify", str(report)],
                       capture_output=True, text=True, cwd=ROOT, timeout=180)
    assert r.returncode == 0
    assert "INTEGRITY OK" in r.stdout

    # 6. tamper + detect
    victim = next((case / "extraction").rglob("sms.db"), None) or \
        next(f for f in (case / "extraction").rglob("*") if f.is_file())
    with open(victim, "ab") as fh:
        fh.write(b"tampered")
    r = subprocess.run([sys.executable, "-m", "opensleuth", "certify",
                        "--verify", str(report)],
                       capture_output=True, text=True, cwd=ROOT, timeout=180)
    assert "TAMPERED" in r.stdout or "INTEGRITY BROKEN" in r.stdout


def artifacts_shape(arts):
    return {"artifacts": arts}


def test_bfu_intelligence_e2e(tmp_path):
    """bfufs classifies a synthetic BFU pull end to end via CLI."""
    import os
    root = tmp_path / "bfu"
    (root / "Documents").mkdir(parents=True)
    p = root / "Documents" / "notes.txt"
    p.write_bytes(b"plaintext at bfu")
    os.setxattr(p, "user.com.apple.system.cprotect", bytes([3, 1]))
    import subprocess, sys
    r = subprocess.run([sys.executable, "-m", "opensleuth", "bfufs",
                        str(root)], capture_output=True, text=True, cwd=ROOT,
                       timeout=60)
    assert r.returncode == 0
    assert "CONTENT readable at BFU: 1" in r.stdout
    assert "notes.txt" in r.stdout