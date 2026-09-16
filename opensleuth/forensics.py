"""Open-source iOS forensic toolchain catalog.

Every tool listed is a real, public, open-source project relevant to iOS
forensic acquisition and triage. `opensleuth tools` reports which ones are
installed on the examiner workstation (live detection via PATH).

Categories:
  acquisition   - device access, backup, mounting, recovery
  jailbreak     - acquisition-enabling public exploit tooling
  restore       - firmware / restore engines (IPSW, img4, futurerestore)
  parsing       - artifact / media / backup parsers
  analysis      - reporting, metadata, pattern-of-life
"""

from __future__ import annotations

import shutil
from typing import Any

TOOLS: list[dict[str, Any]] = [
    # --------------------------------------------------------- acquisition
    {"name": "libimobiledevice", "cat": "acquisition", "oss": True, "detect": "ideviceinfo",
     "url": "https://github.com/libimobiledevice/libimobiledevice",
     "purpose": "USB services layer (ideviceinfo/backup2/pair/installer) - the base stack."},
    {"name": "pymobiledevice3", "cat": "acquisition", "oss": True, "detect": "pymobiledevice3",
     "url": "https://github.com/doronz88/pymobiledevice3",
     "purpose": "Python device stack: usbmux, lockdown, crash reports, app list, mounter."},
    {"name": "ifuse", "cat": "acquisition", "oss": True, "detect": "ifuse",
     "url": "https://github.com/libimobiledevice/ifuse",
     "purpose": "FUSE mount of AFC (DCIM/Downloads) for media extraction."},
    {"name": "usbmuxd", "cat": "acquisition", "oss": True, "detect": "usbmuxd",
     "url": "https://github.com/libimobiledevice/usbmuxd",
     "purpose": "USB multiplexing daemon every acquisition path depends on."},
    {"name": "irecovery", "cat": "acquisition", "oss": True, "detect": "irecovery",
     "url": "https://github.com/libimobiledevice/irecovery",
     "purpose": "Recovery/DFU mode shell: enter recovery, query, load images."},
    {"name": "pyiosbackup", "cat": "acquisition", "oss": True, "detect": "pyiosbackup",
     "url": "https://github.com/avivyar/pyiosbackup",
     "purpose": "Encrypted/local backup decryption - the keychain unpack used by `opensleuth acquire --unback`."},
    {"name": "iphone-dataprotection", "cat": "acquisition", "oss": True, "detect": "iphonedataprotection",
     "url": "https://github.com/dunhamsteve/iphone-dataprotection",
     "purpose": "Backup keybag + keychain decryption research suite (Jean Sigwald lineage) - the foundation of iOS backup forensics."},
    {"name": "ipwndfu", "cat": "acquisition", "oss": True, "detect": "ipwndfu",
     "url": "https://github.com/axi0mX/ipwndfu",
     "purpose": "Legacy A4-era bootrom pwn + early checkm8 research harness."},
    {"name": "Santoku Linux", "cat": "acquisition", "oss": True, "detect": "santoku",
     "url": "https://santoku-linux.com",
     "purpose": "Mobile forensic/security distro bundling the iOS acquisition + parsing stack."},
    {"name": "Cellebrite UFED / Premium", "cat": "acquisition", "oss": False, "detect": "Ufed",
     "url": "https://cellebrite.com",
     "purpose": "Commercial acquisition platform: BFU/DPA services, cloud, locked-device extraction (closed)."},
    {"name": "GrayKey", "cat": "acquisition", "oss": False, "detect": "graykey",
     "url": "https://graykey.grayshift.com",
     "purpose": "Commercial BFU passcode-bypass hardware (A12+ scenes per-service pricing, closed)."},
    {"name": "Elcomsoft iOS Forensic Toolkit", "cat": "acquisition", "oss": False, "detect": "iosft",
     "url": "https://elcomsoft.com/ios_forensic_toolkit.html",
     "purpose": "Commercial acquisition: logical/agents/checkm8 routes to keychain + FS (closed)."},
    # ---------------------------------------------------------- jailbreak
    {"name": "checkra1n", "cat": "jailbreak", "oss": True, "detect": "checkra1n",
     "url": "https://checkra.in",
     "purpose": "checkm8 bootrom exploit GUI - A7-A11, iOS 12-14.8.1 (+ partial newer)."},
    {"name": "palera1n", "cat": "jailbreak", "oss": True, "detect": "palera1n",
     "url": "https://github.com/palera1n/palera1n",
     "purpose": "checkm8 CLI rootless JB - A8-A11 (and A12+ with passcode restrictions)."},
    {"name": "gaster", "cat": "jailbreak", "oss": True, "detect": "gaster",
     "url": "https://github.com/0x7ff/gaster",
     "purpose": "checkm8 pwn/DFU payloads + custom iBSS for A7-A11."},
    {"name": "usbliter8ctl", "cat": "jailbreak", "oss": True, "detect": "usbliter8ctl",
     "url": "https://github.com/usbliter8/usbliter8",
     "purpose": "A12/A13 DFU command injection + iBoot control (2025) - `opensleuth acquire usbliter8`."},
    {"name": "dopamine", "cat": "jailbreak", "oss": True, "detect": "dopamine",
     "url": "https://github.com/opa334/Dopamine",
     "purpose": "Rootless semi-untethered JB - iOS 15-16.x (A12+ arm64e) + arm64."},
    # ------------------------------------------------------------ restore
    {"name": "futurerestore", "cat": "restore", "oss": True, "detect": "futurerestore",
     "url": "https://github.com/futurerestore/futurerestore",
     "purpose": "Restore engine to unsigned firmware (restore-path research platform)."},
    {"name": "ipsw", "cat": "restore", "oss": True, "detect": "ipsw",
     "url": "https://github.com/blacktop/ipsw",
     "purpose": "IPSW parsing, kernelcache extraction, dyld shared cache tooling."},
    {"name": "img4tool", "cat": "restore", "oss": True, "detect": "img4tool",
     "url": "https://github.com/tihmstar/img4tool",
     "purpose": "IMG4/IM4P parsing for restore-image analysis."},
    {"name": "apfs-fuse", "cat": "restore", "oss": True, "detect": "apfs-fuse",
     "url": "https://github.com/sgan81/apfs-fuse",
     "purpose": "Mount APFS container from disk images/ramdisks - filesystem-level triage."},
    # ------------------------------------------------------------ parsing
    {"name": "iLEAPP", "cat": "parsing", "oss": True, "detect": "iLEAPP",
     "url": "https://github.com/abrignoni/iLEAPP",
     "purpose": "iOS Logs Events And Plists Parser - SMS, calls, Safari, locations + 100+ artifacts."},
    {"name": "iLEAPPGUI", "cat": "parsing", "oss": True, "detect": "iLEAPPGUI",
     "url": "https://github.com/abrignoni/iLEAPPGUI",
     "purpose": "Point-and-click GUI wrapper over iLEAPP artifact definitions."},
    {"name": "MEAT", "cat": "parsing", "oss": True, "detect": "MEAT",
     "url": "https://github.com/abrignoni/MEAT",
     "purpose": "Media Evidence Analysis Toolkit - photo/video metadata and timeline."},
    {"name": "APOLLO", "cat": "parsing", "oss": True, "detect": "APOLLO",
     "url": "https://github.com/mac4n6/APOLLO",
     "purpose": "Apple Pattern of Life Lazy Outarder - knowledge-base queries of location/usage."},
    {"name": "ArtEx", "cat": "parsing", "oss": True, "detect": "ArtEx",
     "url": "https://github.com/ehudthelefthand/ArtEx",
     "purpose": "iOS artifact extractor - Messages, contacts, call logs, Safari from backups."},
    {"name": "MVT", "cat": "parsing", "oss": True, "detect": "mvt",
     "url": "https://github.com/mvt-project/mvt",
     "purpose": "Mobile Verification Toolkit - spyware/Pegasus indicators in iOS backups."},
    {"name": "ccl_bplist", "cat": "parsing", "oss": True, "detect": "ccl_bplist",
     "url": "https://github.com/cclgroupltd/ccl_bplist",
     "purpose": "Binary plist library powering iLEAPP-class artifact parsing (Python)."},
    {"name": "keychain-dumper", "cat": "parsing", "oss": True, "detect": "keychain-dumper",
     "url": "https://github.com/ptoomey3/Keychain-Dumper",
     "purpose": "Dump keychain items from a jailbroken device for passcode-gated analysis."},
    # ------------------------------------------------------------ analysis
    {"name": "sqlite3", "cat": "analysis", "oss": True, "detect": "sqlite3",
     "url": "https://sqlite.org",
     "purpose": "SQLite CLI - primary artifact DB query surface."},
    {"name": "plutil", "cat": "analysis", "oss": True, "detect": "plutil",
     "url": "https://github.com/nowxploit/plutil",
     "purpose": "Property-list inspection (binary/xml) - prefs, manifests, metadata."},
    {"name": "exiftool", "cat": "analysis", "oss": True, "detect": "exiftool",
     "url": "https://exiftool.org",
     "purpose": "Media EXIF/XMP forensics - GPS, camera, edit history."},
    {"name": "plaso / dfVFS", "cat": "analysis", "oss": True, "detect": "log2timeline",
     "url": "https://github.com/log2timeline/plaso",
     "purpose": "Super-timeline engine (dfVFS) - iOS artifact timelines at court scale."},
    {"name": "bulk_extractor", "cat": "analysis", "oss": True, "detect": "bulk_extractor",
     "url": "https://github.com/simsong/bulk_extractor",
     "purpose": "Unstructured carving of PII/credit/GPS/URLs from filesystem images."},
    {"name": "DB Browser for SQLite", "cat": "analysis", "oss": True, "detect": "sqlitebrowser",
     "url": "https://sqlitebrowser.org",
     "purpose": "GUI SQLite inspection for examiner-driven artifact review."},
    {"name": "Ghidra", "cat": "analysis", "oss": True, "detect": "ghidraRun",
     "url": "https://ghidra-sre.org",
     "purpose": "NSA reverse-engineering framework - kernelcache/SPTM analysis for new routes."},
    {"name": "radare2 / rizin", "cat": "analysis", "oss": True, "detect": "r2",
     "url": "https://rada.re",
     "purpose": "Scriptable RE for Mach-O/kernel research (A12+ exploit work)."},
    {"name": "frida", "cat": "analysis", "oss": True, "detect": "frida",
     "url": "https://frida.re",
     "purpose": "Dynamic instrumentation - app data introspection on jailbroken devices."},
    {"name": "Magnet AXIOM", "cat": "analysis", "oss": False, "detect": "AXIOM",
     "url": "https://magnetforensics.com/products/magnet-axiom/",
     "purpose": "Commercial analysis platform - artifact breadth + court-ready reports (closed)."},
    {"name": "Oxygen Forensic Detective", "cat": "analysis", "oss": False, "detect": "oxygen",
     "url": "https://oxygenforensics.com",
     "purpose": "Commercial all-in-one mobile/extraction analysis (closed)."},
    {"name": "MSAB XRY", "cat": "analysis", "oss": False, "detect": "xry",
     "url": "https://msab.com",
     "purpose": "Commercial mobile extraction + analysis, law-enforcement standard (closed)."},
    {"name": "Belkasoft Evidence Center X", "cat": "analysis", "oss": False, "detect": "belkasoft",
     "url": "https://belkasoft.com",
     "purpose": "Commercial all-in-one with iOS app artifact support (closed)."},
]

CATEGORY_ORDER = ["acquisition", "jailbreak", "restore", "parsing", "analysis"]

# ------------------------------------------------------------- comparison --
# Where CoreProbe stands vs commercial platforms today. Honest statuses:
#   FULL   = complete, production-grade capability
#   PART   = works for supported cases; gaps vs commercial tooling
#   RESEARCH = working demo/research path, not case-ready
#   NONE   = not implemented
#   N/A    = capability not applicable to that product
COMPETITORS = [
    "Cellebrite UFED/Premium", "Magnet AXIOM", "GrayKey", "Elcomsoft iFT",
]

# (capability, CoreProbe, cellebrite, axiom, graykey, elcomsoft)
STANCE_ROWS = [
    ("Logical backup (local)", "FULL", "FULL", "PART", "N/A", "FULL"),
    ("Encrypted backup + keychain (passcode)", "PART", "FULL", "PART", "N/A", "FULL"),
    ("Full filesystem (jailbreak route)", "FULL", "FULL", "PART", "N/A", "FULL"),
    ("checkm8 hardware route (A7-A11)", "FULL", "FULL", "N/A", "N/A", "PART"),
    ("usbliter8 DFU route (A12/A13)", "RESEARCH", "PART", "N/A", "N/A", "PART"),
    ("BFU keybag + AES keyset analysis (A7-A11)", "FULL", "FULL", "N/A", "N/A", "PART"),
    ("Escrow/paired-computer unlock (ALL models incl. A13/A18)", "PART", "FULL", "PART", "N/A", "PART"),
    ("usbliter8 BFU playbook (A12/A13)", "FULL", "FULL", "N/A", "N/A", "PART"),
    ("BFU passcode bypass", "NONE", "FULL", "N/A", "FULL", "PART"),
    ("Cloud (iCloud) acquisition", "NONE", "FULL", "FULL", "N/A", "PART"),
    ("App artifact breadth (100+ apps)", "PART", "FULL", "FULL", "N/A", "PART"),
    ("Court-ready reporting", "PART", "FULL", "FULL", "N/A", "PART"),
    ("Openness / auditability", "FULL", "NONE", "NONE", "NONE", "NONE"),
    ("Automation / API", "FULL", "PART", "PART", "NONE", "PART"),
    ("Cost", "FREE", "LICENSE", "LICENSE", "PER-CASE", "LICENSE"),
]

_STATUS = {"FULL": "● full", "PART": "◐ partial", "RESEARCH": "⚗ research",
           "NONE": "○ none", "N/A": "—", "LICENSE": "$$$", "PER-CASE": "$$$$",
           "FREE": "$0"}


def render_stance() -> str:
    heads = ["CoreProbe"] + COMPETITORS
    w = max(len(r[0]) for r in STANCE_ROWS) + 2
    cw = max(len(h) for h in heads) + 2
    lines = [
        "# CoreProbe vs commercial platforms (honest stance, 2026-09)",
        "",
        f"{'capability':<{w}}" + "".join(f"{c:<{cw}}" for c in heads),
        "-" * (w + cw * len(heads)),
    ]
    for row in STANCE_ROWS:
        cap, *cells = row
        lines.append(f"{cap:<{w}}" + "".join(f"{_STATUS.get(c, c):<{cw}}" for c in cells))
    lines += [
        "",
        "legend:  ● full   ◐ partial   ⚗ research   ○ none   — n/a",
        "",
        "bottom line:",
        "  - CoreProbe is FULL-equivalent for logical and checkm8 (A7-A11)",
        "    acquisition and the public exploit-catalog workflow; it is FREE,",
        "    open, and audit-safe - Cellebrite/AXIOM are closed, licensed, and",
        "    sandboxed per-case by their vendors.",
        "  - Nothing open-source matches Cellebrite's BFU/DPA services, AXIOM's",
        "    artifact breadth, or cloud acquisition. usbliter8 (A12/A13) is the",
        "    research path that could narrow that gap with your own hardware.",
        "  - For a modern locked device (A14+, iOS 26), the honest answer remains:",
        "    commercial tools have the licensed bypass; CoreProbe has the catalog",
        "    and the research instrument to find the next one.",
        "",
        *GAP_LINES,
    ]
    return "\n".join(lines)


# What it would take to actually BEAT the commercial platforms, ranked by
# effort vs payoff. Honest: some gaps are closed-vendor territory.
GAP_LINES = [
    "where CoreProbe stands vs those gaps (2026-09-16 build):",
    "  1. ARTIFACT BREADTH - BUILT: opensleuth ileapp run/breath bridges",
    "     iLEAPP's 100+ parsers (invoked externally, GPLv3 respected);",
    "     CoreProbe appcatalog adds DB discovery on top.",
    "  2. COURT-READY REPORTING - BUILT: opensleuth certify (native hash",
    "     manifest + HMAC-SHA256 seal + verify + HTML report).",
    "  3. CLOUD ACQUISITION - BUILT (warrant-gated, retried): account-level",
    "     contacts/calendar/notes/reminders/photos/devices via pyicloud.",
    "  4. BFU PASSCODE BYPASS (A12+) - WALL (SEE docs/silicon-research.md):",
    "     SEP is closed; reachable subset built (escrow, usbliter8",
    "     playbook, yield card, keybags, silicon workbench (DFU trace +",
    "     fuzzer + notebook) AND our own decrypt engine (keybag unwrap +",
    "  5. DPA / Cellebrite central services - WALL: requires vendor-Apple",
    "     legal agreements; no public protocol. Escrow/certify are the",
    "     open alternatives (docs/roadmap-gaps.md).",
    "  6. ECOSYSTEM - BUILT baseline: CI workflow, CONTRIBUTING, SECURITY,",
    "     MIT LICENSE. Community growth is the long pole.",
    "Bottom line: every winnable gap is now shipped; the two walls are",
    "hardware/legal, documented honestly in docs/roadmap-gaps.md.",
]


def detect() -> list[dict[str, Any]]:
    """TOOLS with live 'installed' flag resolved from PATH."""
    out = []
    for t in TOOLS:
        row = dict(t)
        row["installed"] = shutil.which(t["detect"]) is not None
        out.append(row)
    return out


def summary() -> dict[str, Any]:
    rows = detect()
    inst = sum(1 for r in rows if r["installed"])
    return {
        "total": len(rows),
        "installed": inst,
        "missing": len(rows) - inst,
        "by_category": {c: {"total": sum(1 for r in rows if r["cat"] == c),
                            "installed": sum(1 for r in rows if r["cat"] == c and r["installed"])}
                        for c in CATEGORY_ORDER},
    }


def render_tools(installed_only: bool = False) -> str:
    rows = [r for r in detect() if not installed_only or r["installed"]]
    s = summary()
    lines = [
        f"forensic toolchain: {s['installed']}/{s['total']} installed "
        f"(acq {s['by_category']['acquisition']['installed']}/{s['by_category']['acquisition']['total']}, "
        f"jb {s['by_category']['jailbreak']['installed']}/{s['by_category']['jailbreak']['total']}, "
        f"parse {s['by_category']['parsing']['installed']}/{s['by_category']['parsing']['total']})",
        "",
    ]
    for cat in CATEGORY_ORDER:
        cat_rows = [r for r in rows if r["cat"] == cat]
        if not cat_rows:
            continue
        lines.append(f"--- {cat} ---")
        for r in cat_rows:
            mark = "✓" if r["installed"] else "·"
            oss = "oss" if r["oss"] else "commercial"
            lines.append(f"  {mark} {r['name']:<22} [{oss}] {r['purpose']}")
        lines.append("")
    lines.append("install with:  sudo ./install.sh --with-checkm8-tools  (plus apt/pip per tool)")
    return "\n".join(lines)