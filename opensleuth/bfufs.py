"""BFU filesystem metadata intelligence.

Even on modern phones (A12+, SEP intact) a BFU pull - usbliter8 ramdisk on
A12/A13, checkm8 on A7-A11 - yields the filesystem metadata and the
protection-class map of every file. That metadata is intelligence:

  - class 0/1 (None): file CONTENT is readable at BFU
  - class 4 (CompleteUntilFirstUserAuthentication): structure/names
    visible, content encrypted until first unlock
  - class 2/5 (Complete*): content encrypted

scans a BFU-mounted or pulled root, reads the com.apple.system.cprotect
xattr per file (exposed by apfs-fuse / ramdisk copies on Linux), classifies
every file, and builds the examiner's pre-decryption picture.

xattrs are read with os.listxattr/getxattr - works on any Linux host
where the pull preserves the cprotect xattr.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

XPATTR = "com.apple.system.cprotect"

# classes: 1=None 2=Complete 3=CompleteUnlessOpen 4=CUFUA
#          5=CUFUAUnlessOpen 0=unknown (fixtures/older)
CLASS_READABLE = {0, 1, 3, 4}   # metadata always; content for 0/1
CLASS_CONTENT_READABLE = {0, 1}

# privacy-interest path patterns -> label
INTEREST_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(chatstorage|telegram|signal|whatsapp|kik|wechat|viber|line)", re.I), "chat"),
    (re.compile(r"(dcim|photos|photo_library|camera)", re.I), "media"),
    (re.compile(r"(health|workout|activity)", re.I), "health"),
    (re.compile(r"(location|significant|places|routined|maps)", re.I), "location"),
    (re.compile(r"(browser|safari|chrome|firefox|history)", re.I), "browser"),
    (re.compile(r"(keychain|keybag|escrow)", re.I), "keychain/keys"),
    (re.compile(r"(sms\.db|callhistory|voicemail|addressbook)", re.I), "comm-logs"),
    (re.compile(r"(instagram|tiktok|snapchat|facebook|messenger)", re.I), "social"),
]


def scan_fs(root: str | Path) -> list[dict[str, Any]]:
    root = Path(root)
    rows = []
    if not root.exists():
        return rows
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        try:
            rel = p.relative_to(root).as_posix()
            size = p.stat().st_size
        except OSError:
            continue
        klass = None
        blob = None
        try:
            xattrs = os.listxattr(p)
            names = [x.decode() if isinstance(x, bytes) else x for x in xattrs]
            for n in names:
                if n.endswith(XPATTR) or n == XPATTR:
                    blob = os.getxattr(p, n if n == XPATTR else n)
                    break
        except (OSError, NotImplementedError):
            pass
        if blob and len(blob) >= 2:
            klass = blob[1]
        rows.append({
            "rel": rel,
            "size": size,
            "class": klass,
            "class_name": _class_name(klass),
            "readable_now": klass in CLASS_CONTENT_READABLE,
            "metadata_only": klass in CLASS_READABLE and klass not in CLASS_CONTENT_READABLE,
            "interest": _interest(rel),
        })
    return rows


def _class_name(klass: int | None) -> str:
    if klass is None:
        return "no-xattr"
    return {0: "None/unknown", 1: "None", 2: "Complete",
            3: "CompleteUnlessOpen", 4: "CUFUA", 5: "CUFUAUnlessOpen"}.get(klass, f"class-{klass}")


def _interest(rel: str) -> str | None:
    for pat, label in INTEREST_PATTERNS:
        if pat.search(rel):
            return label
    return None


def classify(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    by_class = Counter(r["class_name"] for r in rows)
    readable = [r for r in rows if r["readable_now"]]
    metadata = [r for r in rows if r["metadata_only"]]
    interest_counts = Counter(r["interest"] for r in rows if r["interest"])
    return {
        "total_files": total,
        "by_class": dict(by_class),
        "content_readable": len(readable),
        "metadata_visible": len(metadata),
        "by_interest": dict(interest_counts),
        "readable_now": readable,
        "metadata_targets": metadata[:500],
    }


def render_report(rep: dict[str, Any]) -> str:
    lines = [
        f"BFU filesystem intelligence: {rep['total_files']} files",
        f"  per class      : {rep['by_class']}",
        f"  CONTENT readable at BFU: {rep['content_readable']} files",
        f"  metadata visible (CUFUA): {rep['metadata_visible']} files",
        f"  interest map   : {rep['by_interest']}",
        "",
        "== content-readable at BFU (no decryption needed) ==",
    ]
    for r in rep["readable_now"][:60]:
        lines.append(f"  {r['rel']}  ({r['size']:,} B)")
    lines.append("")
    lines.append("== metadata-only targets (decryptable after first unlock / escrow) ==")
    for r in rep["metadata_targets"][:60]:
        lines.append(f"  {r['rel']}  [{r['interest'] or '—'}]")
    lines.append("")
    if rep["readable_now"]:
        lines.append("Readable files are plaintext at BFU: pull + preserve them now.")
    lines.append("Metadata targets: pair with keybag unwrap / escrow to decrypt.")
    return "\n".join(lines)