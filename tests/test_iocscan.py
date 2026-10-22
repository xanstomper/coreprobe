"""Tests for opensleuth.iocscan — Coruna / DarkSword IoC scanner.

Fixtures are synthetic trees built in a fresh mkdtemp directory per
test (repo style; avoids tmp_path). The false-positive guard (test 2)
is the most important test in this file: Coruna ships wallet-theft
modules for MetaMask/Exodus/Phantom, but a legitimate crypto app
folder is NOT an infection indicator and must produce zero findings.
"""

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from opensleuth import iocscan


@pytest.fixture()
def tree():
    d = Path(tempfile.mkdtemp(prefix="iocscan-test-"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


# 1 — Coruna: a PLASMAGRID string in a fake sysdiagnose -------------------

def test_plasmagrid_in_sysdiagnose_is_one_high_coruna_finding(tree):
    _write(tree, "system_logs.logarchive/Extra/powerd.log",
           "2026-03-01 00:00:01 powerd: loading PLASMAGRID stage\n"
           "2026-03-01 00:00:02 powerd: idle\n")
    report = iocscan.scan_path(tree)
    coruna = report.by_kit("coruna")
    assert len(coruna) == 1, f"expected exactly 1 Coruna finding: {coruna}"
    f = coruna[0]
    assert f.indicator_id == "CORUNA-PLASMAGRID"
    assert f.severity == "HIGH"
    assert f.line_no == 1
    assert "PLASMAGRID" in f.evidence_snippet
    assert f.path.endswith("powerd.log")


def test_plasmaloader_and_assistd_masquerade_flagged(tree):
    _write(tree, "logs/crash.log",
           "PlasmaLoader bootstrap ok\n"
           "spawned com.apple.assistd (container)\n")
    report = iocscan.scan_path(tree)
    ids = {f.indicator_id for f in report.findings}
    assert "CORUNA-PLASMALOADER" in ids
    assert "CORUNA-ASSISTD-MASQUERADE" in ids


def test_assistd_suppressed_in_legit_system_path(tree):
    _write(tree,
           "System/Library/LaunchDaemons/com.apple.assistd.plist",
           "Label com.apple.assistd\n")
    report = iocscan.scan_path(tree)
    assert report.by_kit("coruna") == []


def test_coruna_dga_domain_pattern(tree):
    # 15-character .xyz label (GTIG DGA pattern).
    _write(tree, "network.log", "dns query abcdefghijklmno.xyz A\n")
    report = iocscan.scan_path(tree)
    dga = [f for f in report.findings
           if f.indicator_id == "CORUNA-DGA-DOMAIN"]
    assert len(dga) == 1
    assert dga[0].severity == "MEDIUM"
    assert dga[0].evidence_snippet == "abcdefghijklmno.xyz"


# 2 — False-positive guard: legitimate wallet apps are NOT indicators ----

def test_legit_wallet_apps_produce_zero_findings(tree):
    _write(tree,
           "Applications/com.exodus.app/Info.plist",
           "Exodus wallet app data\nMetaMask mentioned in a help page\n")
    _write(tree,
           "Applications/io.metamask.app/data.txt",
           "MetaMask account backup\nPhantom import instructions\n")
    _write(tree, "sms.txt", "check my Exodus balance later\n")
    report = iocscan.scan_path(tree)
    assert report.findings == [], (
        f"legitimate wallet app data must not be flagged: {report.findings}")


def test_cve_numbers_are_not_infection_indicators(tree):
    _write(tree, "advisory.txt",
           "Patched: CVE-2025-31277 CVE-2025-43529 CVE-2026-20700 "
           "CVE-2025-14174 CVE-2025-43510 CVE-2025-43520\n")
    report = iocscan.scan_path(tree)
    assert report.findings == []


# 3 — DarkSword ------------------------------------------------------------

def test_darksword_string_in_log_is_finding(tree):
    _write(tree, "DiagnosticReports/webkit.log",
           "frame load failed\nDarkSword stage2 fetched\n")
    report = iocscan.scan_path(tree)
    ds = report.by_kit("darksword")
    assert len(ds) == 1
    assert ds[0].indicator_id == "DARKSWORD-NAME"
    assert ds[0].severity == "HIGH"
    assert ds[0].line_no == 2


def test_ghost_payload_names_flagged(tree):
    _write(tree, "u.log", "GHOSTKNIFE\nGHOSTSABER\nGHOSTBLADE\n")
    report = iocscan.scan_path(tree)
    ids = {f.indicator_id for f in report.by_kit("darksword")}
    assert ids == {"DARKSWORD-GHOSTKNIFE", "DARKSWORD-GHOSTSABER",
                   "DARKSWORD-GHOSTBLADE"}


# 4 — JSON output shape is stable -------------------------------------------

def test_json_shape_stable(tree):
    _write(tree, "a.log", "PLASMAGRID\n")
    report = iocscan.scan_path(tree, ios_version="26.2")
    data = iocscan.render(report, to_json=True)
    assert set(data) == {"root", "ios_version", "files_scanned",
                         "files_skipped", "summary", "findings"}
    assert data["ios_version"] == "26.2"
    assert data["summary"] == {"coruna": 1}
    (f,) = data["findings"]
    assert set(f) == {"indicator_id", "kit", "severity", "path",
                      "evidence_snippet", "line_no", "description"}
    json.dumps(data)  # must be JSON-serializable as-is
    text = iocscan.render(report)
    assert "CORUNA-PLASMAGRID" in text


def test_clean_tree_renders_no_findings(tree):
    _write(tree, "notes.txt", "ordinary examiner notes\n")
    report = iocscan.scan_path(tree)
    assert report.findings == []
    assert "none" in iocscan.render(report)


# Hygiene signals -----------------------------------------------------------

def test_shutdown_log_missing_flagged_only_on_26_2_plus(tree):
    _write(tree, "system_logs.logarchive/Extra/other.log", "x\n")
    flagged = iocscan.scan_path(tree, ios_version="26.2")
    ids = {f.indicator_id for f in flagged.findings}
    assert "HYGIENE-SHUTDOWN-LOG-MISSING" in ids
    # On 26.0/26.1 Apple itself overwrote shutdown.log — stay silent.
    silent = iocscan.scan_path(tree, ios_version="26.1")
    assert silent.findings == []
    # And without a version, stay silent too.
    assert iocscan.scan_path(tree).findings == []


def test_empty_diagnosticreports_is_low_hygiene(tree):
    (tree / "DiagnosticReports").mkdir()
    report = iocscan.scan_path(tree)
    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.indicator_id == "HYGIENE-DIAGNOSTICREPORTS-EMPTY"
    assert f.severity == "LOW" and f.kit == "hygiene"


def test_missing_root_is_empty_report(tree):
    report = iocscan.scan_path(tree / "does-not-exist")
    assert report.findings == [] and report.files_scanned == 0
