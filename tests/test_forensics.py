"""Forensic toolchain catalog tests."""

from opensleuth import forensics as F


def test_catalog_has_all_categories():
    cats = {t["cat"] for t in F.TOOLS}
    assert cats == set(F.CATEGORY_ORDER)
    assert cats == {"acquisition", "jailbreak", "restore", "parsing", "analysis"}


def test_catalog_includes_commercial_comparison_entries():
    rows = F.detect()
    names = {t["name"] for t in rows}
    for commercial in ("Cellebrite UFED / Premium", "Magnet AXIOM", "GrayKey",
                       "Elcomsoft iOS Forensic Toolkit", "MSAB XRY",
                       "Oxygen Forensic Detective", "Belkasoft Evidence Center X"):
        assert commercial in names
    assert any(not t["oss"] for t in rows)


def test_stance_matrix_shape():
    assert len(F.COMPETITORS) == 4
    assert len(F.STANCE_ROWS) >= 10
    # each row: capability + one status per competitor + CoreProbe
    for row in F.STANCE_ROWS:
        assert len(row) == 1 + 1 + len(F.COMPETITORS)
        cap, *cells = row
        assert cap and all(c in F._STATUS for c in cells), row


def test_stance_honest_about_modern_lock():
    # BFU bypass and iCloud must be honest NONE for CoreProbe
    by_cap = {r[0]: r[1:] for r in F.STANCE_ROWS}
    assert by_cap["BFU passcode bypass"][0] == "NONE"
    assert by_cap["Cloud (iCloud) acquisition"][0] == "NONE"
    # usbliter8 classified as research, not full
    assert by_cap["usbliter8 DFU route (A12/A13)"][0] == "RESEARCH"


def test_stance_renders_columns_and_legend():
    out = F.render_stance()
    for c in ["CoreProbe", "Cellebrite UFED/Premium", "Magnet AXIOM", "GrayKey"]:
        assert c in out
    assert "● full" in out and "○ none" in out and "legend:" in out
    assert "bottom line:" in out


def test_tools_all_have_required_fields():
    for t in F.TOOLS:
        assert t["name"] and t["purpose"]
        assert t["detect"] and t["url"].startswith("https://")
        assert t["cat"] in F.CATEGORY_ORDER
        assert isinstance(t["oss"], bool)


def test_no_duplicate_detect_binaries():
    detects = [t["detect"] for t in F.TOOLS]
    assert len(detects) == len(set(detects))


def test_detect_adds_installed_flag():
    rows = F.detect()
    assert len(rows) == len(F.TOOLS)
    assert all(isinstance(r["installed"], bool) for r in rows)


def test_summary_shape():
    s = F.summary()
    assert s["total"] == len(F.TOOLS)
    assert s["installed"] + s["missing"] == s["total"]
    for c in F.CATEGORY_ORDER:
        assert s["by_category"][c]["total"] >= 1
        assert 0 <= s["by_category"][c]["installed"] <= s["by_category"][c]["total"]


def test_render_includes_counts_and_categories():
    out = F.render_tools()
    assert "installed" in out
    for c in ("acquisition", "jailbreak", "restore", "parsing", "analysis"):
        assert c in out


def test_render_installed_only_filter():
    out = F.render_tools(installed_only=True)
    # every rendered line with a check mark is installed; '·' must not appear
    assert "\u00b7" not in out
    assert "\u2713" in out or "installed" in out


def test_cli_tools_json():
    import json
    import subprocess
    import sys
    from pathlib import Path

    r = subprocess.run([sys.executable, "-m", "opensleuth", "tools", "--json"],
                       capture_output=True, text=True,
                       cwd=Path(__file__).resolve().parent.parent)
    assert r.returncode == 0
    rows = json.loads(r.stdout)
    assert len(rows) == len(F.TOOLS)
    assert all("installed" in t for t in rows)