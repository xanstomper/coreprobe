"""Attack-surface analyst: turn tracked CVEs into research targets.

Groups the tracked public disclosures by acquisition value and research
difficulty - the honest way to pick what to research next. This module
never claims an exploit; it ranks where effort should go based on what
Apple themselves patched (their patch history IS the attack-surface map).

value tiers:
  keychain/root/kernel-exec/network-reachable = PRIME (BFU/acquisition
  relevant)
  sandbox-escape/protected-write/code-signing = HIGH
  info-leak/DoS/privacy = CONTEXT

difficulty: components with repeated kernel-exec CVEs (AVEVideoEncoder,
Kernel, CoreMedia) indicate richer bug classes -> research frontier.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

import re

PRIME = re.compile(r"keychain|root|kernel.?exec|arbitrary code|network", re.I)
HIGH = re.compile(r"sandbox|protected|code.?sign|bypass|credential|restricted", re.I)


def tier(kind: str, impact: str = "") -> str:
    t = f"{kind} {impact}"
    if PRIME.search(t):
        return "PRIME"
    if HIGH.search(t):
        return "HIGH"
    return "CONTEXT"


def analyze(disclosures: list[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    for d in disclosures:
        rows.append({
            "cve": d.get("cve", ""),
            "component": d.get("component", ""),
            "kind": d.get("kind", ""),
            "impact": d.get("impact", ""),
            "patch": d.get("patch", ""),
            "tier": tier(d.get("kind", ""), d.get("impact", "")),
        })
    tiers = Counter(r["tier"] for r in rows)
    by_comp = Counter(r["component"] for r in rows if r["tier"] != "CONTEXT")
    # components with repeats = rich bug classes
    rich = {c: n for c, n in by_comp.items() if n >= 2}
    return {
        "total": len(rows),
        "tiers": dict(tiers),
        "components_noncontext": dict(by_comp),
        "rich_components": rich,
        "rows": rows,
    }


def research_targets(rep: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    """Ranked research targets: rich components with PRIME/HIGH CVEs."""
    targets = []
    for comp, count in sorted(rep["rich_components"].items(),
                               key=lambda kv: -kv[1])[:limit]:
        prime = [r for r in rep["rows"] if r["component"] == comp
                 and r["tier"] == "PRIME"]
        high = [r for r in rep["rows"] if r["component"] == comp
                and r["tier"] == "HIGH"]
        targets.append({
            "component": comp,
            "cves": count,
            "prime_examples": [r["cve"] for r in prime][:3],
            "high_examples": [r["cve"] for r in high][:3],
            "why": (f"{count} non-context CVEs; {len(prime)} PRIME-class "
                    f"(kernel-exec/root/keychain/network) - Apple's own patch "
                    f"history says this surface is repeatedly exploitable"),
        })
    return targets


def render(rep: dict[str, Any], targets_only: bool = False) -> str:
    lines = [f"attack-surface analysis: {rep['total']} tracked disclosures",
             f"  tiers: {rep['tiers']}",
             f"  rich components (2+ non-context CVEs): "
             f"{len(rep['rich_components'])}", ""]
    for t in research_targets(rep):
        lines.append(f"  TARGET {t['component']}  ({t['cves']} CVEs)")
        if t["prime_examples"]:
            lines.append(f"    PRIME: {', '.join(t['prime_examples'])}")
        if t["high_examples"]:
            lines.append(f"    HIGH : {', '.join(t['high_examples'])}")
        lines.append(f"    why  : {t['why'][:100]}")
    lines += ["", "honest note: these are PATCHED public CVEs. They map the",
              "attack surface Apple acknowledges; a NEW usable 0-day must be",
              "found by research (campaign run) - never assumed from this list."]
    return "\n".join(lines)