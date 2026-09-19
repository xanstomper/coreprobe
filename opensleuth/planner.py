"""Honest acquisition planner: fingerprint -> truth-gated method selection.

The standard: the planner may ONLY select capabilities from the operational
pool (REGRESSION_TESTED) of the truth registry. Integrated-but-unvalidated
routes are offered as VALIDATION REQUIRED; documented research routes are
offered as RESEARCH ONLY (with their research reference); anything else is
UNSUPPORTED for this target. The planner never executes an unvalidated
technique and never claims a route works because a version range matches.

Pre-flight: before an operational method is recommended for execution, its
prerequisites are checked against the fingerprint (recorded mismatches).
Post-run verification (expected state observed) lives with the executors;
the planner exposes the checks they must satisfy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import truth as T
from .fingerprint import Fingerprint

METHOD_LABELS = {
    "AVAILABLE": "AVAILABLE (operational)",
    "VALIDATION_REQUIRED": "VALIDATION REQUIRED (integrated, not yet "
                           "lab-validated)",
    "RESEARCH_ONLY": "RESEARCH ONLY (documented, no CoreProbe adapter)",
    "UNSUPPORTED": "UNSUPPORTED for this target",
}


@dataclass
class PlannedMethod:
    capability_id: str
    name: str
    verdict: str                  # AVAILABLE | VALIDATION_REQUIRED | RESEARCH_ONLY | UNSUPPORTED
    reason: str
    prerequisites_met: Optional[bool] = None
    unmet: list[str] = field(default_factory=list)
    research_id: str = ""
    limitations: list[str] = field(default_factory=list)

    def selectable(self) -> bool:
        return self.verdict == "AVAILABLE" and self.prerequisites_met is not False


class Planner:
    def __init__(self, registry: T.TruthRegistry | None = None):
        self.registry = registry or T.default_registry()

    # ------------------------------------------------------------------ plan
    def plan(self, fp: Fingerprint) -> list[PlannedMethod]:
        """Assess every registry capability against the fingerprint."""
        out: list[PlannedMethod] = []
        for cap in sorted(self.registry.all(),
                          key=lambda c: (c.category, c.capability_id)):
            if cap.status == T.OPERATIONAL_STATUS:
                unmet = self._unmet_prerequisites(cap, fp)
                verdict = "AVAILABLE" if not unmet else "UNSUPPORTED"
                reason = ("operational capability, prerequisites satisfied"
                          if not unmet else
                          "prerequisites not met: " + "; ".join(unmet))
                out.append(PlannedMethod(
                    capability_id=cap.capability_id, name=cap.name,
                    verdict=verdict, reason=reason,
                    prerequisites_met=not unmet, unmet=unmet,
                    limitations=list(cap.limitations)))
            elif cap.status == "INTEGRATED":
                unmet = self._unmet_prerequisites(cap, fp)
                out.append(PlannedMethod(
                    capability_id=cap.capability_id, name=cap.name,
                    verdict="VALIDATION_REQUIRED",
                    reason="adapter exists but no recorded lab validation "
                           "(truth registry: INTEGRATED)"
                           + ("" if not unmet else
                              "; also unmet: " + "; ".join(unmet)),
                    prerequisites_met=not unmet, unmet=unmet,
                    research_id=cap.research_id,
                    limitations=list(cap.limitations)))
            else:
                # DOCUMENTED / PUBLIC_POC / LAB_* / BROKEN / RETIRED / UNKNOWN
                applicable, why = self._research_applies(cap, fp)
                verdict = "RESEARCH_ONLY" if applicable else "UNSUPPORTED"
                out.append(PlannedMethod(
                    capability_id=cap.capability_id, name=cap.name,
                    verdict=verdict, reason=why,
                    research_id=cap.research_id,
                    limitations=list(cap.limitations)))
        return out

    # ------------------------------------------------------------ selection
    def selectable_methods(self, fp: Fingerprint) -> list[PlannedMethod]:
        """The ONLY list an automated executor may choose from."""
        return [m for m in self.plan(fp) if m.selectable()]

    def best(self, fp: Fingerprint) -> Optional[PlannedMethod]:
        sel = self.selectable_methods(fp)
        return sel[0] if sel else None

    # ------------------------------------------------------------ internals
    def _unmet_prerequisites(self, cap: T.Capability,
                             fp: Fingerprint) -> list[str]:
        unmet = []
        state = fp.state
        for pre in cap.prerequisites:
            p = pre.lower()
            if "afu" in p and state != "AFU":
                unmet.append(pre)
            elif "dfu" in p and state not in ("DFU", "pwned-dfu"):
                unmet.append(pre)
            elif "attached" in p and state == "absent":
                unmet.append(pre)
            elif "paired" in p and state != "AFU":
                unmet.append(pre)
            elif "gaster installed" in p:
                import shutil
                if not shutil.which("gaster"):
                    unmet.append(pre)
            elif "a7-a11" in p:
                if fp.chip not in ("A7", "A8", "A9", "A10", "A11"):
                    unmet.append(f"{pre} (chip={fp.chip or '?'})")
            elif "a12/a13" in p or "a12/a13" in p:
                if fp.chip not in ("A12", "A13"):
                    unmet.append(f"{pre} (chip={fp.chip or '?'})")
        return unmet

    def _research_applies(self, cap: T.Capability,
                          fp: Fingerprint) -> tuple[bool, str]:
        if fp.chip and fp.chip in ("A7", "A8", "A9", "A10", "A11") and \
                cap.research_id in ("checkm8",):
            return True, ("public research applies to this chip class; "
                          "CoreProbe has no validated adapter")
        if fp.chip in ("A12", "A13") and cap.research_id == "usbliter8":
            return True, ("public research applies to this chip class; "
                          "requires the RP2350 rig (not CoreProbe-executable)")
        if cap.research_id == "dopamine-family":
            return (fp.state == "AFU",
                    "app-based jailbreaks are examiner-installed; CoreProbe "
                    "only detects an already-jailbroken device"
                    if fp.state == "AFU" else
                    "requires AFU (installed app)")
        return False, "research route does not apply to this target"


def render_plan(methods: list[PlannedMethod], fp: Fingerprint) -> str:
    lines = ["", "ACQUISITION PLAN (truth-gated)", "=" * 64]
    lines.append(f"target: chip={fp.chip or '?'} ios={fp.ios or '?'} "
                 f"state={fp.state or '?'}")
    lines.append("=" * 64)
    for m in methods:
        lines.append("")
        lines.append(f"## {m.name}  [{METHOD_LABELS.get(m.verdict, m.verdict)}]")
        lines.append(f"  capability : {m.capability_id}")
        if m.research_id:
            lines.append(f"  research   : {m.research_id}")
        lines.append(f"  reason     : {m.reason}")
        if m.unmet:
            lines.append(f"  unmet      : {'; '.join(m.unmet)}")
        for lim in m.limitations:
            lines.append(f"  limitation : {lim}")
        if m.verdict == "AVAILABLE":
            lines.append("  selectable : YES (automated executor may run this)")
        else:
            lines.append("  selectable : NO")
    n_sel = sum(1 for m in methods if m.selectable())
    lines.append("")
    lines.append(f"selectable methods: {n_sel} "
                 "(only operational+prerequisite-satisfied capabilities)")
    return "\n".join(lines)
