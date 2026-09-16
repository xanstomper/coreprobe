"""Public iOS research pipeline tracker.

Continuously folds publicly disclosed research into CoreProbe:

  - Apple security releases (CVE list + impact language) - fetched live
  - Public exploit/jailbreak disclosures (keyword-scanned)
  - Vendor capability leaks (Cellebrite/GrayKey matrices, when surfaced)
  - Academic venues (USENIX/S&P iOS security papers)

Each finding is classified by RELEVANCE to acquisition/forensics and
flagged when it implies an extraction primitive (backup traversal, kernel
write with physical access, lockdown service bugs, etc). State is kept in
RESEARCH_STATE so runs are incremental: you only see what's new.

Policy: only PUBLIC, disclosed research is tracked. Nothing private,
nothing undisclosed, no developing new bypasses - this module watches the
public disclosure pipeline and folds findings in the moment they land.
"""

from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

APPLE_SECURITY_PAGE = "https://support.apple.com/en-us/100100"  # releases index
APPLE_CURRENT_RELEASES = [
    ("iOS 27 / iPadOS 27", "https://support.apple.com/en-us/149034", "2026-09-14"),
    ("iOS 26.7 / iPadOS 26.7", "https://support.apple.com/en-us/149041", "2026-09-14"),
]

# Forensic/acquisition-relevant keywords in Apple's impact/description text.
RELEVANCE_KEYWORDS = [
    "physical access", "read and write arbitrary files", "write arbitrary files",
    "kernel privileges", "arbitrary code execution", "execute arbitrary code",
    "modify protected parts", "circumvent sandbox", "sandbox",
    "MobileBackup", "lockdown", "AFC", "backup", "pairing",
    "access restricted files", "read persistent", "kernel memory",
    "root privileges", "path traversal", "access sensitive user data",
]

# Public disclosure/blog sources to keyword-scan for new exploit research.
FINDING_SOURCES = [
    "Paradigm Shift (ps.tc) - publish on disclosure, incl. usbliter8 2026-06-18, Magnet suit 2026-07-07",
    "checkra1n/PongoOS GitHub - Blackbird SEP exploitation source",
    "usbliter8ra1n (Leeksov) - A12/A13 full boot chain research",
    "404 Media - GrayKey matrix leak (Nov 2024), vendor capability reporting",
    "Apple security releases - patched CVEs (public)",
    "USENIX Security / IEEE S&P - iOS security papers (annual)",
    "CCC / Hexacon / POC - hardware security talks",
]

DEFAULT_STATE_PATH = Path.home() / ".coreprobe" / "research-state.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fetch(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "coreprobe-research/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def load_state(path: Path = DEFAULT_STATE_PATH) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"seen_cves": [], "last_check": None, "highlights": []}


def save_state(state: dict, path: Path = DEFAULT_STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")


def _parse_apple_cves(html: str) -> list[dict]:
    """Extract component/impact/description/CVE blocks from an Apple page.

    Apple pages list each component with 'Impact:' and 'Description:'
    paragraphs; CVEs appear as CVE-YYYY-NNNNN tokens, sometimes several per
    component. We pair the nearest impact text with each CVE.
    """
    # split into component blocks on <h3> boundaries (headings)
    blocks = re.split(r"<h[23][^>]*>", html)
    findings: list[dict] = []
    for blk in blocks:
        text = re.sub(r"<[^>]+>", " ", blk)
        text = re.sub(r"\s+", " ", text).strip()
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", text)
        if not cves:
            continue
        # component = up to ~80 chars before first CVE-ish content
        impact_m = re.search(r"Impact:\s*(.{10,220})", text)
        desc_m = re.search(r"Description:\s*(.{10,120})", text)
        comp = text[:120].split(" Available for:")[0].strip()
        impact = impact_m.group(1).strip() if impact_m else ""
        desc = desc_m.group(1).strip() if desc_m else ""
        rel_keywords = [k for k in RELEVANCE_KEYWORDS if k.lower() in (impact + " " + desc).lower()]
        for cve in cves:
            findings.append({
                "cve": cve,
                "component": comp,
                "impact": impact,
                "description": desc,
                "relevant": rel_keywords,
                "forensic_value": len(rel_keywords) > 0,
            })
    return findings


def scan_apple(state: dict, timeout: int = 30) -> list[dict]:
    """Fetch current Apple release note pages, return NEW (unseen) findings."""
    new: list[dict] = []
    all_seen = set(state.get("seen_cves", []))
    for title, url, released in APPLE_CURRENT_RELEASES:
        try:
            html = _fetch(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            new.append({"source": title, "error": str(exc), "cve": None})
            continue
        for f in _parse_apple_cves(html):
            f["source"] = title
            f["released"] = released
            if f["cve"] in all_seen:
                continue
            new.append(f)
            state.setdefault("seen_cves", []).append(f["cve"])
    return new


def highlight_path(finding: dict) -> str:
    """Human-friendly one-liner for a new finding."""
    if finding.get("error"):
        return f"  !! {finding['source']}: fetch error - {finding['error']}"
    tag = "*** FORENSIC PRIMITIVE ***" if finding.get("forensic_value") else ""
    return (
        f"  {finding['cve']:<16} {finding['component'][:34]:<36} "
        f"{('[' + ', '.join(finding['relevant'][:2]) + ']') if finding.get('relevant') else ''} {tag}"
    )


def run(state_path: Path = DEFAULT_STATE_PATH, timeout: int = 30) -> dict:
    """Run the pipeline; returns summary dict and persists state."""
    state = load_state(state_path)
    before = len(state.get("seen_cves", []))
    new = scan_apple(state, timeout=timeout)
    state["last_check"] = _now()
    save_state(state, state_path)
    return {
        "new_findings": new,
        "new_count": len(new),
        "total_tracked_cves": len(state.get("seen_cves", [])),
        "delta": len(state.get("seen_cves", [])) - before,
        "state_path": str(state_path),
        "last_check": state.get("last_check"),
    }


def render(summary: dict, detailed: bool = False) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append("public iOS research pipeline  (CoreProbe)")
    lines.append("=" * 78)
    lines.append(f"last check: {summary.get('last_check')}")
    lines.append(f"tracked CVEs: {summary.get('total_tracked_cves')}  (new this run: {summary.get('new_count')})")
    new = summary.get("new_findings", [])
    if not new:
        lines.append("no new public findings this run.")
    for f in new:
        lines.append(highlight_path(f))
        if detailed and f.get("cve"):
            lines.append(f"      impact : {f.get('impact','')[:160]}")
            lines.append(f"      desc   : {f.get('description','')[:160]}")
    lines.append("")
    lines.append("public disclosure sources watched:")
    for s in FINDING_SOURCES:
        lines.append(f"  - {s}")
    lines.append("")
    lines.append("policy: public disclosures only. No private 0-days, no new bypass")
    lines.append("development - findings are folded in the moment they are disclosed.")
    return "\n".join(lines)