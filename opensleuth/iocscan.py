"""Spyware IoC scanner: Coruna + DarkSword indicators in an evidence tree.

Takes a directory — an extracted iOS backup, an extracted sysdiagnose,
or any plain text/log tree — and hunts the *published* indicators for
the two exploit kits that defined 2025-2026 iOS spyware forensics:

* **Coruna** (aka CryptoWaters) — Google Threat Intelligence Group
  (GTIG), 2026-03-03: five full chains / 23 exploits against
  iOS 13.0-17.2.1, proliferated from a surveillance vendor through
  watering-hole campaigns. Implant components named by GTIG include
  **PlasmaLoader** and **PLASMAGRID** (injected into `powerd`, running
  under the masquerade bundle id **`com.apple.assistd`**), a DGA whose
  domains are **15-character `.xyz` labels** (seed word `lazarus`,
  resolved via 8.8.8.8), and per-wallet theft modules (MetaMask,
  Exodus, Phantom, Trust, ...).
* **DarkSword** — GTIG / Lookout / iVerify, March 2026: an all-
  JavaScript full chain against iOS 18.4-18.7, deployed by multiple
  actors under the payload names **GHOSTKNIFE**, **GHOSTSABER** and
  **GHOSTBLADE**. Fileless and hit-and-run: it deletes its own
  DiagnosticReports / crash logs within minutes, which is why the
  hygiene signals below matter.

CONSERVATIVE BY DESIGN (this repo's integrity rule):
* A finding requires a *kit-specific* string. Generic app names are
  NOT indicators: a legitimate MetaMask / Exodus / Phantom app folder
  in a backup produces ZERO findings here, even though Coruna ships
  wallet-theft modules for those apps — the module names alone cannot
  distinguish an infected device from a crypto user.
* CVE numbers are *exposure*, not infection. DarkSword's six CVEs
  (CVE-2025-31277, CVE-2025-43529, CVE-2026-20700, CVE-2025-14174,
  CVE-2025-43510, CVE-2025-43520) are deliberately NOT scanned for:
  a log mentioning a CVE is a patched-system advisory, not an IoC.
* The Coruna resource-URL format (`sha256(cookie+id)[:40]`) is a
  server-side construction, not a string that appears in evidence;
  it is not scannable and is not faked here. The DGA *domain pattern*
  (15-char `.xyz` label) is scannable and is included at MEDIUM.
* `powerd` injection has no concrete on-disk string distinct from
  legitimate powerd logs; it is NOT flagged (too fuzzy — noted here
  as a deliberate omission).

Hygiene signals (LOW severity, always labeled as weak signals):
* `shutdown.log` is a spyware-detection artifact (historical IoCs for
  Pegasus-class implants). iVerify reporting (Sep 2025): iOS 26.0/26.1
  *overwrote* it on every reboot; Apple restored append behaviour in
  iOS 26.2. Therefore a missing/truncated shutdown.log is only
  meaningful on iOS >= 26.2 sysdiagnoses — on 26.0/26.1 a clean log is
  Apple's own doing and proves nothing either way, so this scanner
  stays silent unless the examiner supplies ios_version >= 26.2.
* An empty DiagnosticReports directory: DarkSword-class kits delete
  crash reports; an examiner-visible reports folder with zero files
  is worth a second look (and nothing more — LOW).

Every finding cites the file, the line, and a short evidence snippet.
Nothing here proves infection on its own; findings are leads for an
examiner, cross-checkable against MVT / iVerify tooling.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Indicator registry. Every entry is traceable to a public source named in
# the module docstring. If a string is not kit-specific, it is not here.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Indicator:
    indicator_id: str
    kit: str  # "coruna" | "darksword" | "hygiene"
    severity: str  # "HIGH" | "MEDIUM" | "LOW"
    needle: str  # literal string (case-sensitive unless regex set)
    description: str
    regex: bool = False


STRING_INDICATORS: tuple[Indicator, ...] = (
    # --- Coruna (GTIG, 2026-03-03) -------------------------------------
    Indicator(
        "CORUNA-PLASMAGRID", "coruna", "HIGH", "PLASMAGRID",
        "Coruna implant component name (PLASMAGRID) published by GTIG; "
        "no legitimate Apple or App Store component uses this name."),
    Indicator(
        "CORUNA-PLASMALOADER", "coruna", "HIGH", "PlasmaLoader",
        "Coruna loader component name published by GTIG."),
    Indicator(
        "CORUNA-ASSISTD-MASQUERADE", "coruna", "MEDIUM",
        "com.apple.assistd",
        "Coruna implant masquerade bundle id (GTIG). Flagged only when "
        "the containing file is outside legitimate Apple system paths; "
        "occurrences inside System/Library-style locations are the "
        "kind of reference an examiner must clear manually and are "
        "suppressed here to stay conservative."),
    # --- DarkSword (GTIG / Lookout / iVerify, March 2026) ---------------
    Indicator(
        "DARKSWORD-NAME", "darksword", "HIGH", "DarkSword",
        "DarkSword exploit-kit name (GTIG/Lookout disclosure)."),
    Indicator(
        "DARKSWORD-GHOSTKNIFE", "darksword", "HIGH", "GHOSTKNIFE",
        "DarkSword payload name used by UNC6748 (GTIG)."),
    Indicator(
        "DARKSWORD-GHOSTSABER", "darksword", "HIGH", "GHOSTSABER",
        "DarkSword payload name used by PARS Defense campaigns (GTIG)."),
    Indicator(
        "DARKSWORD-GHOSTBLADE", "darksword", "HIGH", "GHOSTBLADE",
        "DarkSword payload name used by UNC6353 (GTIG)."),
)

# Coruna DGA: domains are 15-character labels under .xyz (GTIG). Pattern
# match only — a random-looking 15-char .xyz domain is a lead, not proof.
DGA_INDICATOR = Indicator(
    "CORUNA-DGA-DOMAIN", "coruna", "MEDIUM", r"\b[a-z0-9]{15}\.xyz\b",
    "Possible Coruna DGA domain: exactly-15-character .xyz label "
    "(GTIG: DGA seeded 'lazarus', validated via 8.8.8.8). Pattern "
    "match — corroborate before treating as an indicator of "
    "compromise.", regex=True)

# Path fragments under which a `com.apple.assistd` reference is treated
# as a plausible legitimate system reference and suppressed (see the
# indicator description). Everything else (app containers, backup file
# trees, loose logs) is examiner-interesting.
_LEGIT_PATH_MARKERS = (
    "System/Library/",
    "System/Applications/",
    "usr/libexec/",
    "usr/share/",
    "private/var/db/SystemPolicyConfiguration/",
)

# Files never worth string-scanning (compressed / media payloads). Their
# *names* are still visible to the hygiene checks via the tree walk.
_SKIP_SUFFIXES = {
    ".gz", ".bz2", ".xz", ".zip", ".7z", ".tar",
    ".png", ".jpg", ".jpeg", ".gif", ".heic", ".heif",
    ".mov", ".mp4", ".m4a", ".mp3", ".aac",
    ".dylib", ".so", ".o", ".a", ".ipa", ".deb",
}

MAX_FILE_BYTES = 32 * 1024 * 1024  # skip giants; IoCs live in text/logs
_SNIPPET_CHARS = 160


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    indicator_id: str
    kit: str
    severity: str
    path: str  # relative to the scanned root, posix-style
    evidence_snippet: str
    line_no: int  # 1-based; 0 when not line-bound (hygiene findings)
    description: str = ""


@dataclass
class ScanReport:
    root: str
    ios_version: Optional[str] = None
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list[Finding] = field(default_factory=list)

    def by_kit(self, kit: str) -> list[Finding]:
        return [f for f in self.findings if f.kit == kit]

    def summary(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.kit] = out.get(f.kit, 0) + 1
        return out


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def _ver_tuple(v: Any) -> tuple[int, ...]:
    """Tolerant iOS version parse: '26.2' / '26.2.1' / (26, 2) -> tuple."""
    if v is None:
        return ()
    if isinstance(v, (tuple, list)):
        try:
            return tuple(int(p) for p in v)
        except (TypeError, ValueError):
            return ()
    try:
        return tuple(int(p) for p in str(v).split(".") if p.isdigit())
    except (TypeError, ValueError):
        return ()


def _iter_files(root: Path):
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            yield p


def _scan_file(path: Path, rel: str) -> list[Finding]:
    """String-indicator scan of one file. At most one finding per
    indicator per file (first occurrence) — an implant name repeated
    500 times in one log is one lead, not 500."""
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    findings: list[Finding] = []
    legit_path = any(m in rel for m in _LEGIT_PATH_MARKERS)
    for ind in STRING_INDICATORS:
        if ind.indicator_id == "CORUNA-ASSISTD-MASQUERADE" and legit_path:
            continue
        needle = ind.needle.encode()
        idx = raw.find(needle)
        if idx < 0:
            continue
        line_no = raw.count(b"\n", 0, idx) + 1
        line_start = raw.rfind(b"\n", 0, idx) + 1
        line_end = raw.find(b"\n", idx)
        if line_end < 0:
            line_end = len(raw)
        snippet = raw[line_start:line_end].decode("utf-8", "ignore")
        findings.append(Finding(
            indicator_id=ind.indicator_id, kit=ind.kit,
            severity=ind.severity, path=rel,
            evidence_snippet=snippet.strip()[:_SNIPPET_CHARS],
            line_no=line_no, description=ind.description))
    # DGA pattern (regex over the decoded text).
    text = raw.decode("utf-8", "ignore")
    m = re.search(DGA_INDICATOR.needle, text)
    if m:
        line_no = text.count("\n", 0, m.start()) + 1
        findings.append(Finding(
            indicator_id=DGA_INDICATOR.indicator_id, kit=DGA_INDICATOR.kit,
            severity=DGA_INDICATOR.severity, path=rel,
            evidence_snippet=m.group(0), line_no=line_no,
            description=DGA_INDICATOR.description))
    return findings


def _looks_like_sysdiagnose(root: Path, all_rels: list[str]) -> bool:
    markers = ("system_logs.logarchive", "sysdiagnose.log",
               "system_logs/", "DiagnosticReports")
    return any(any(mk in rel for mk in markers) for rel in all_rels)


def _hygiene_checks(root: Path, all_files: list[Path],
                    ios_version: Any) -> list[Finding]:
    findings: list[Finding] = []
    rels = [p.relative_to(root).as_posix() for p in all_files]

    # --- shutdown.log (only meaningful on iOS >= 26.2; see docstring) --
    ver = _ver_tuple(ios_version)
    shutdowns = [p for p in all_files if p.name == "shutdown.log"]
    if ver and ver >= (26, 2) and _looks_like_sysdiagnose(root, rels):
        if not shutdowns:
            findings.append(Finding(
                indicator_id="HYGIENE-SHUTDOWN-LOG-MISSING",
                kit="hygiene", severity="LOW", path="(tree)",
                evidence_snippet="no shutdown.log anywhere in a "
                                 "sysdiagnose-shaped tree",
                line_no=0,
                description="shutdown.log missing on an iOS >=26.2 "
                            "sysdiagnose. Since 26.2 restored append "
                            "behaviour, a missing log is a weak "
                            "tampering signal (iVerify shutdown.log "
                            "research). Weak signal only — devices and "
                            "partial sysdiagnoses can lack it innocently."))
        else:
            for p in shutdowns:
                try:
                    size = p.stat().st_size
                except OSError:
                    continue
                if size < 32:
                    findings.append(Finding(
                        indicator_id="HYGIENE-SHUTDOWN-LOG-TRUNCATED",
                        kit="hygiene", severity="LOW",
                        path=p.relative_to(root).as_posix(),
                        evidence_snippet=f"shutdown.log is {size} bytes",
                        line_no=0,
                        description="shutdown.log present but "
                                    "near-empty on iOS >=26.2 — "
                                    "possible truncation of historical "
                                    "spyware IoCs (iVerify). Weak "
                                    "signal only."))

    # --- empty DiagnosticReports ----------------------------------------
    diag_dirs = {p.parent for p in all_files
                 if p.parent.name == "DiagnosticReports"}
    # Also catch a DiagnosticReports dir that contains no files at all:
    for d in root.rglob("DiagnosticReports"):
        if d.is_dir() and not any(d.iterdir()):
            findings.append(Finding(
                indicator_id="HYGIENE-DIAGNOSTICREPORTS-EMPTY",
                kit="hygiene", severity="LOW",
                path=d.relative_to(root).as_posix(),
                evidence_snippet="DiagnosticReports directory is empty",
                line_no=0,
                description="Empty DiagnosticReports directory. "
                            "DarkSword-class kits delete their crash "
                            "reports (GTIG/Lookout); an empty reports "
                            "folder is a weak hygiene signal, not an "
                            "indicator of compromise."))
    _ = diag_dirs  # (presence alone, with files, is unremarkable)
    return findings


def scan_path(root: str | Path,
              ios_version: Optional[str] = None) -> ScanReport:
    """Scan a directory tree for Coruna / DarkSword indicators.

    `root` may be an extracted backup, an extracted sysdiagnose, or any
    text/log tree. `ios_version` (e.g. "26.2") only gates the
    shutdown.log hygiene check; string indicators are version-free.
    """
    root = Path(root)
    report = ScanReport(root=str(root), ios_version=ios_version)
    if not root.exists() or not root.is_dir():
        return report
    all_files: list[Path] = []
    for p in _iter_files(root):
        all_files.append(p)
        if p.suffix.lower() in _SKIP_SUFFIXES:
            report.files_skipped += 1
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                report.files_skipped += 1
                continue
        except OSError:
            report.files_skipped += 1
            continue
        rel = p.relative_to(root).as_posix()
        report.files_scanned += 1
        report.findings.extend(_scan_file(p, rel))
    report.findings.extend(_hygiene_checks(root, all_files, ios_version))
    # Stable order: kit, severity rank, path, line.
    rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    report.findings.sort(key=lambda f: (rank.get(f.severity, 3), f.kit,
                                        f.path, f.line_no))
    return report


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render(report: ScanReport, to_json: bool = False) -> str | dict:
    """Render a ScanReport. to_json=True returns a JSON-ready dict with
    a stable shape (root, ios_version, files_scanned, files_skipped,
    summary, findings)."""
    data = {
        "root": report.root,
        "ios_version": report.ios_version,
        "files_scanned": report.files_scanned,
        "files_skipped": report.files_skipped,
        "summary": report.summary(),
        "findings": [asdict(f) for f in report.findings],
    }
    if to_json:
        return data
    lines = [
        "IoC scan — Coruna / DarkSword (GTIG + Lookout, Mar 2026)",
        f"root: {report.root}  iOS: {report.ios_version or 'unknown'}",
        f"files scanned: {report.files_scanned} "
        f"(skipped: {report.files_skipped})",
    ]
    if not report.findings:
        lines.append("findings: none — no kit-specific indicators found")
        lines.append("(absence of findings is not proof of a clean "
                     "device; fileless kits leave few on-disk strings)")
        return "\n".join(lines)
    lines.append(f"findings: {len(report.findings)} "
                 f"{report.summary()}")
    for f in report.findings:
        loc = f"{f.path}:{f.line_no}" if f.line_no else f.path
        lines.append(f"[{f.severity}] {f.indicator_id} ({f.kit}) {loc}")
        lines.append(f"    {f.evidence_snippet}")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="opensleuth-iocscan",
        description="Scan a backup/sysdiagnose tree for Coruna + "
                    "DarkSword indicators (GTIG/Lookout, Mar 2026).")
    ap.add_argument("path", help="directory to scan")
    ap.add_argument("--ios", default=None,
                    help="device iOS version, e.g. 26.2 (gates the "
                         "shutdown.log hygiene check)")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON instead of text")
    args = ap.parse_args(argv)
    report = scan_path(args.path, ios_version=args.ios)
    out = render(report, to_json=args.json)
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(out)
    # Exit 1 when any HIGH finding exists — scriptable triage semantics.
    return 1 if any(f.severity == "HIGH" for f in report.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
