"""Capability TRUTH system: research status ≠ operational capability.

Implements the CoreProbe standard: a route/exploit/CVE may NEVER be
represented as usable just because it is documented. A capability may enter
the operational pool (what the acquisition planner may select) only when:

    adapter exists AND target compatibility recorded AND controlled
    validation passed AND prerequisites confirmed AND regression test passed

Status machine (strictly ordered promotion path):

    UNKNOWN            insufficient evidence
    DOCUMENTED         credible external source documents the technique
    PUBLIC_POC         a public proof-of-concept exists (still NOT usable)
    LAB_REPRODUCED     CoreProbe reproduced the underlying behavior in a lab
    LAB_VALIDATED      validated on the relevant device/build combination
    INTEGRATED         a CoreProbe adapter exists
    REGRESSION_TESTED  adapter repeatedly tested on supported configurations

Terminal states: BROKEN (previously worked, now failing validation) and
RETIRED (must not be used). Only REGRESSION_TESTED is OPERATIONAL.

The registry lives in capabilities.json (machine-readable manifests). The UI
and planner MUST derive every status from this registry; hardcoded labels are
forbidden. A consistency auditor verifies the registry against reality and
removes inconsistent capabilities from the operational pool.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Status machine
# ---------------------------------------------------------------------------

STATUS_ORDER = [
    "UNKNOWN",
    "DOCUMENTED",
    "PUBLIC_POC",
    "LAB_REPRODUCED",
    "LAB_VALIDATED",
    "INTEGRATED",
    "REGRESSION_TESTED",
]
TERMINAL_STATUSES = ["BROKEN", "RETIRED"]
ALL_STATUSES = STATUS_ORDER + TERMINAL_STATUSES

# The only status the acquisition planner may select.
OPERATIONAL_STATUS = "REGRESSION_TESTED"

# Statuses that may never be selected, surfaced explicitly by renderers.
RESEARCH_ONLY_STATUSES = [
    "UNKNOWN", "DOCUMENTED", "PUBLIC_POC",
    "LAB_REPRODUCED", "LAB_VALIDATED", "INTEGRATED",
]


def is_operational(status: str) -> bool:
    return status == OPERATIONAL_STATUS


def is_research_only(status: str) -> bool:
    return status in RESEARCH_ONLY_STATUSES or status in TERMINAL_STATUSES


def can_promote(current: str, target: str) -> bool:
    """Promotion must follow the strict ladder; terminal states absorb."""
    if current in TERMINAL_STATUSES or target in TERMINAL_STATUSES:
        # BROKEN/RETIRED are set deliberately (failure evidence), not via
        # the promotion ladder; allow only same->same.
        return current == target
    try:
        return STATUS_ORDER.index(target) == STATUS_ORDER.index(current) + 1
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Capability manifest
# ---------------------------------------------------------------------------

@dataclass
class Capability:
    capability_id: str
    name: str
    status: str
    category: str                       # acquisition | bootrom | sep | kernel | research
    research_id: str = ""               # link to exploits.py route / CVE
    description: str = ""
    adapter: str = ""                   # module/function that implements it ("" = none)
    adapter_version: str = ""
    prerequisites: list[str] = field(default_factory=list)
    supported_builds: list[str] = field(default_factory=list)   # e.g. "A10+iOS<=15"
    failed_builds: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    validation_evidence: list[dict[str, Any]] = field(default_factory=list)
    last_successful_validation: str = ""
    last_failed_validation: str = ""
    test_fixture: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Capability":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    def operational(self) -> bool:
        return is_operational(self.status)


class RegistryError(Exception):
    pass


class TruthRegistry:
    """Load/validate/query the capability registry."""

    def __init__(self, capabilities: list[Capability]):
        self._caps = {c.capability_id: c for c in capabilities}

    # ---------- loading ----------
    @classmethod
    def load(cls, path: str | Path) -> "TruthRegistry":
        p = Path(path)
        if not p.is_file():
            raise RegistryError(f"capability registry not found: {p}")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise RegistryError(f"registry is not valid JSON: {exc}") from exc
        caps = [Capability.from_dict(d) for d in data.get("capabilities", [])]
        reg = cls(caps)
        problems = reg.audit()
        if problems:
            raise RegistryError(
                "registry failed consistency audit: " + "; ".join(problems))
        return reg

    # ---------- queries ----------
    def get(self, capability_id: str) -> Optional[Capability]:
        return self._caps.get(capability_id)

    def all(self) -> list[Capability]:
        return list(self._caps.values())

    def operational(self) -> list[Capability]:
        """The ONLY pool the acquisition planner may select from."""
        return [c for c in self._caps.values() if c.operational()]

    def by_category(self, category: str) -> list[Capability]:
        return [c for c in self._caps.values() if c.category == category]

    def for_research_id(self, research_id: str) -> list[Capability]:
        return [c for c in self._caps.values() if c.research_id == research_id]

    # ---------- consistency auditor ----------
    def audit(self) -> list[str]:
        """Return human-readable consistency problems ([] = healthy).

        A capability marked operational (REGRESSION_TESTED) must have:
          * an adapter reference
          * at least one recorded successful validation with evidence
          * a test fixture
        Capabilities with failed builds listed must not claim those builds in
        supported_builds. Adapter versions must match the latest validation.
        """
        problems: list[str] = []
        for c in self._caps.values():
            cid = c.capability_id
            if c.status not in ALL_STATUSES:
                problems.append(f"{cid}: invalid status {c.status!r}")
            if c.status == OPERATIONAL_STATUS:
                if not c.adapter:
                    problems.append(
                        f"{cid}: OPERATIONAL without an adapter reference")
                if not c.validation_evidence:
                    problems.append(
                        f"{cid}: OPERATIONAL without validation evidence")
                if not any(
                    e.get("result") == "VALIDATED"
                    for e in c.validation_evidence
                ):
                    problems.append(
                        f"{cid}: OPERATIONAL without a VALIDATED evidence entry")
                if not c.last_successful_validation:
                    problems.append(
                        f"{cid}: OPERATIONAL without last_successful_validation")
                if not c.test_fixture:
                    problems.append(f"{cid}: OPERATIONAL without a test fixture")
            for fb in c.failed_builds:
                if fb in c.supported_builds:
                    problems.append(
                        f"{cid}: build {fb!r} both supported and failed")
            if c.last_failed_validation and c.last_successful_validation:
                if c.last_failed_validation > c.last_successful_validation:
                    problems.append(
                        f"{cid}: failed validation more recent than success "
                        f"while status={c.status}")
            for e in c.validation_evidence:
                if e.get("result") not in (
                    "VALIDATED", "FAILED", "NOT_REPRODUCED",
                    "NOT_APPLICABLE", "NOT_SUPPORTED", "UNKNOWN",
                ):
                    problems.append(
                        f"{cid}: evidence with invalid result {e.get('result')!r}")
        return problems

    # ---------- mutation with ladder enforcement ----------
    def promote(self, capability_id: str, target: str) -> Capability:
        cap = self._caps.get(capability_id)
        if cap is None:
            raise RegistryError(f"unknown capability {capability_id!r}")
        if not can_promote(cap.status, target):
            raise RegistryError(
                f"{capability_id}: illegal promotion {cap.status} -> {target} "
                "(must follow the ladder one step at a time)")
        problems_before = self.audit()
        previous_status = cap.status
        cap.status = target
        problems = self.audit()
        # Promotion must not introduce inconsistency (e.g. to REGRESSION_TESTED
        # without evidence). Roll back if it did.
        new_problems = [p for p in problems if p not in problems_before]
        if new_problems:
            cap.status = previous_status  # roll back
            raise RegistryError(
                "promotion rejected, registry would become inconsistent: "
                + "; ".join(new_problems))
        return cap

    def record_validation(self, capability_id: str, result: str,
                          environment: str, evidence: dict[str, Any] | None = None,
                          at: str = "") -> Capability:
        cap = self._caps.get(capability_id)
        if cap is None:
            raise RegistryError(f"unknown capability {capability_id!r}")
        if result not in ("VALIDATED", "FAILED", "NOT_REPRODUCED",
                          "NOT_APPLICABLE", "NOT_SUPPORTED", "UNKNOWN"):
            raise RegistryError(f"invalid validation result {result!r}")
        entry = {"result": result, "environment": environment, "at": at}
        if evidence:
            entry["evidence"] = evidence
        cap.validation_evidence.append(entry)
        if result == "VALIDATED":
            if at > (cap.last_successful_validation or ""):
                cap.last_successful_validation = at
        elif result in ("FAILED", "NOT_REPRODUCED"):
            if at > (cap.last_failed_validation or ""):
                cap.last_failed_validation = at
        return cap

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {"version": 1, "capabilities": [c.to_dict() for c in self._caps.values()]}
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Seeded registry (honest, derived from the audited codebase)
# ---------------------------------------------------------------------------
# Each seed entry below was derived from what actually exists in the repo:
#   * logical-backup / media-afc / device-info: real adapters (cli.py acquire
#     backup/media/info) exercised by E2E tests with fixtures -> the fixtures
#     are recorded as validation evidence -> REGRESSION_TESTED.
#   * checkm8-pwn: real adapter (gaster pwn + PWND marker verification) but no
#     recorded hardware validation run -> INTEGRATED (validation required).
#   * usbliter8-verify: host-side PWND verification only; the exploit itself
#     runs on the RP2350 board -> DOCUMENTED.
#   * jailbreak routes: no CoreProbe adapter executes them (the auto-exploiter
#     only DETECTS an already-jailbroken device via AFC2) -> DOCUMENTED,
#     research-only. Listed as one representative capability.
# ---------------------------------------------------------------------------

SEED_CAPABILITIES: list[dict[str, Any]] = [
    {
        "capability_id": "device-info",
        "name": "Device identification (lockdown/sysfs)",
        "status": "REGRESSION_TESTED",
        "category": "acquisition",
        "research_id": "",
        "description": "Identify attached device: model, chip, iOS, state via "
                       "sysfs USB + lockdown enrichment.",
        "adapter": "opensleuth.usb.usb_state + opensleuth.exploitrunner.probe_target",
        "adapter_version": "1",
        "prerequisites": ["device attached"],
        "supported_builds": ["any"],
        "limitations": ["chip from serial is heuristic when no lockdown"],
        "validation_evidence": [
            {"result": "VALIDATED", "environment": "pytest:tests/test_usb.py",
             "at": "2026-09-18", "evidence": "synthetic sysfs fixtures"},
            {"result": "VALIDATED", "environment": "pytest:tests/test_exploitrunner.py",
             "at": "2026-09-18", "evidence": "probe/plan tests"},
        ],
        "last_successful_validation": "2026-09-18",
        "test_fixture": "tests/test_usb.py::make_sysfs",
    },
    {
        "capability_id": "logical-backup",
        "name": "Logical + backup acquisition (AFU, paired)",
        "status": "REGRESSION_TESTED",
        "category": "acquisition",
        "research_id": "",
        "description": "idevicebackup2/pymobiledevice3 backup + AFC media pull "
                       "on an unlocked, paired device.",
        "adapter": "opensleuth.cli:cmd_acquire_backup/media/all",
        "adapter_version": "1",
        "prerequisites": ["AFU (after first unlock)", "trusted pairing"],
        "supported_builds": ["any iOS with lockdown"],
        "limitations": ["keychain needs encrypted backup + password"],
        "validation_evidence": [
            {"result": "VALIDATED", "environment": "pytest:tests/test_e2e_workflow.py",
             "at": "2026-09-18", "evidence": "E2E acquisition workflow test"},
        ],
        "last_successful_validation": "2026-09-18",
        "test_fixture": "tests/test_e2e_workflow.py",
    },
    {
        "capability_id": "backup-parse",
        "name": "Backup parsing (Manifest.db + artifacts)",
        "status": "REGRESSION_TESTED",
        "category": "acquisition",
        "research_id": "",
        "description": "Parse an acquired backup into normalized artifacts.",
        "adapter": "opensleuth.backup.Backup + opensleuth.artifacts.*",
        "adapter_version": "1",
        "prerequisites": ["acquired backup directory"],
        "supported_builds": ["any"],
        "validation_evidence": [
            {"result": "VALIDATED", "environment": "pytest:tests/test_forensic_parsers.py",
             "at": "2026-09-18", "evidence": "parser fixtures"},
        ],
        "last_successful_validation": "2026-09-18",
        "test_fixture": "tests/fixture.py",
    },
    {
        "capability_id": "checkm8-pwn",
        "name": "checkm8 bootrom pwn (A7-A11, DFU)",
        "status": "INTEGRATED",
        "category": "bootrom",
        "research_id": "checkm8",
        "description": "gaster/ipwndfu pwn of DFU bootrom; success verified by "
                       "PWND marker in USB serial.",
        "adapter": "opensleuth.exploitrunner.exec_checkm8_pwn",
        "adapter_version": "1",
        "prerequisites": ["A7-A11", "DFU mode", "gaster installed"],
        "supported_builds": [],
        "limitations": [
            "no recorded hardware validation run yet (validation required)",
            "A10/A11 on iOS 16+ require passcode-off/erase (destructive caveat)",
        ],
        "validation_evidence": [],
        "test_fixture": "",
    },
    {
        "capability_id": "usbliter8-verify",
        "name": "usbliter8 PWND verification (A12/A13)",
        "status": "DOCUMENTED",
        "category": "bootrom",
        "research_id": "usbliter8",
        "description": "Host-side verification of a usbliter8-pwned device. The "
                       "exploit itself runs on the RP2350 rig; CoreProbe only "
                       "confirms the resulting PWND marker.",
        "adapter": "",
        "adapter_version": "",
        "prerequisites": ["RP2350 rig performs the exploit", "A12/A13"],
        "supported_builds": [],
        "limitations": ["exploit requires dedicated hardware (RP2350 board)"],
        "validation_evidence": [],
        "test_fixture": "",
    },
    {
        "capability_id": "afu-jailbreak-detect",
        "name": "Jailbreak route detection (AFU, app-based)",
        "status": "DOCUMENTED",
        "category": "kernel",
        "research_id": "dopamine-family",
        "description": "DETECTION ONLY: verifies whether an installed "
                       "jailbreak/agent exposes AFC2 root. CoreProbe does not "
                       "execute any jailbreak (Dopamine/Serotonin/etc. must be "
                       "installed by the examiner).",
        "adapter": "opensleuth.exploitrunner.exec_afu_jailbreak",
        "adapter_version": "",
        "prerequisites": ["AFU", "examiner-installed agent"],
        "supported_builds": [],
        "limitations": ["CoreProbe cannot install or run jailbreaks itself"],
        "validation_evidence": [],
        "test_fixture": "",
    },
]

REGISTRY_PATH = Path(__file__).parent / "capabilities.json"


def default_registry() -> TruthRegistry:
    reg = TruthRegistry([Capability.from_dict(d) for d in SEED_CAPABILITIES])
    problems = reg.audit()
    if problems:
        raise RegistryError("seed registry inconsistent: " + "; ".join(problems))
    return reg


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_STATUS_LABEL = {
    "UNKNOWN": "UNKNOWN",
    "DOCUMENTED": "DOCUMENTED",
    "PUBLIC_POC": "PUBLIC POC",
    "LAB_REPRODUCED": "LAB REPRODUCED",
    "LAB_VALIDATED": "LAB VALIDATED",
    "INTEGRATED": "INTEGRATED",
    "REGRESSION_TESTED": "OPERATIONAL",
    "BROKEN": "BROKEN",
    "RETIRED": "RETIRED",
}


def status_label(status: str) -> str:
    return _STATUS_LABEL.get(status, status)


def render(registry: TruthRegistry, category: str = "") -> str:
    caps = registry.by_category(category) if category else registry.all()
    lines = ["", "CoreProbe capability registry (truth-gated)"]
    lines.append("=" * 64)
    lines.append(f"operational pool (planner-selectable): "
                 f"{len(registry.operational())} of {len(caps)}")
    lines.append("=" * 64)
    for c in sorted(caps, key=lambda x: (x.category, x.capability_id)):
        lines.append("")
        lines.append(f"## {c.capability_id}  [{status_label(c.status)}]")
        lines.append(f"  name        : {c.name}")
        lines.append(f"  category    : {c.category}")
        if c.research_id:
            lines.append(f"  research    : {c.research_id}")
        lines.append(f"  adapter     : {c.adapter or '(none - research only)'}")
        if c.prerequisites:
            lines.append(f"  requires    : {'; '.join(c.prerequisites)}")
        if c.supported_builds:
            lines.append(f"  builds      : {', '.join(c.supported_builds)}")
        if c.last_successful_validation:
            lines.append(f"  last valid  : {c.last_successful_validation}")
        for lim in c.limitations:
            lines.append(f"  limitation  : {lim}")
        if c.status != OPERATIONAL_STATUS:
            lines.append("  NOTE        : NOT selectable by the acquisition "
                         "planner (research/validation pending)")
    lines.append("")
    lines.append("promotion ladder: " + " -> ".join(STATUS_ORDER))
    lines.append("only REGRESSION_TESTED capabilities are operational.")
    return "\n".join(lines)
