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
        """The ONLY pool the acquisition planner may select from.

        Defensive: a capability qualifies only if its status is
        REGRESSION_TESTED AND it passes the per-capability audit checks
        (adapter, VALIDATED evidence, fixture) — so even direct attribute
        mutation cannot smuggle an unvalidated capability into the pool.
        """
        out = []
        for c in self._caps.values():
            if c.status != OPERATIONAL_STATUS:
                continue
            if self._audit_capability(c):
                out.append(c)
        return out

    def _audit_capability(self, c: Capability) -> bool:
        """True when this capability raises no audit problems."""
        saved = self._caps  # audit() reads the whole registry; run targeted
        try:
            single = TruthRegistry.__new__(TruthRegistry)
            single._caps = {c.capability_id: c}
            return not single.audit()
        finally:
            self._caps = saved

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
    # --- Batch 2b expansion (2026-10-22): runnable routes that already have
    # real executors in exploitrunner.py. INTEGRATED is claimed only where a
    # test in tests/test_exploitrunner.py::TestExecutorGating calls the
    # executor directly; executors with no direct fixture (exec_afu_agent,
    # exec_pongo_ramdisk) stay DOCUMENTED with the gap stated as a limitation.
    # No entry here is REGRESSION_TESTED: none has a recorded hardware
    # validation run.
    {
        "capability_id": "palera1n-jailbreak",
        "name": "palera1n jailbreak boot (A8-A11, checkm8)",
        "status": "INTEGRATED",
        "category": "bootrom",
        "research_id": "palera1n",
        "description": "Real palera1n run: enters recovery from a booted state "
                       "when needed, then boots the rootless jailbreak. Success "
                       "is claimed only when an objective state change is "
                       "observed (AFC2 mountable or PongoOS reachable).",
        "adapter": "opensleuth.exploitrunner.exec_palera1n_jailbreak",
        "adapter_version": "1",
        "prerequisites": ["A8-A11 (checkm8 silicon)", "iOS 15+",
                          "palera1n binary installed",
                          "DFU/recovery mode, or booted + paired for recovery entry"],
        "supported_builds": [],
        "limitations": [
            "no recorded hardware validation run yet (validation required)",
            "A11 on iOS 16+ requires the passcode to be disabled (upstream palera1n constraint)",
        ],
        "validation_evidence": [],
        "test_fixture": "tests/test_exploitrunner.py::TestExecutorGating::test_palera1n_jailbreak_requires_tool",
    },
    {
        "capability_id": "checkra1n",
        "name": "checkra1n jailbreak (A7-A11, legacy)",
        "status": "INTEGRATED",
        "category": "bootrom",
        "research_id": "checkra1n",
        "description": "checkra1n CLI run (checkm8) from DFU/recovery. Success "
                       "is claimed only on AFC2 mountable or a PWND marker in "
                       "the USB serial.",
        "adapter": "opensleuth.exploitrunner.exec_checkra1n",
        "adapter_version": "1",
        "prerequisites": ["A7-A11", "checkra1n CLI installed (Linux/macOS)",
                          "device in DFU or recovery mode"],
        "supported_builds": [],
        "limitations": [
            "no recorded hardware validation run yet (validation required)",
            "legacy tool: upstream checkra1n targets the iOS 12-14.x era; not maintained for modern iOS",
        ],
        "validation_evidence": [],
        "test_fixture": "tests/test_exploitrunner.py::TestExecutorGating::test_checkra1n_requires_mode",
    },
    {
        "capability_id": "trollstore-install",
        "name": "TrollStore install / verify (CoreTrust, AFU)",
        "status": "INTEGRATED",
        "category": "acquisition",
        "research_id": "trollstore",
        "description": "Installs an examiner-provided TrollStore .tipa via "
                       "pymobiledevice3 developer services, or verifies an "
                       "existing TrollStore install via the app list. Permanent "
                       "signing happens on-device via the CoreTrust bug.",
        "adapter": "opensleuth.exploitrunner.exec_trollstore_install",
        "adapter_version": "1",
        "prerequisites": ["AFU (unlocked, paired)", "pymobiledevice3 installed",
                          "CoreTrust-vulnerable iOS (TrollStore support window)",
                          "examiner-provided .tipa/.ipa payload, or TrollStore already installed"],
        "supported_builds": [],
        "limitations": [
            "no recorded hardware validation run yet (validation required)",
            "host installs/verifies only; not an extraction route itself",
        ],
        "validation_evidence": [],
        "test_fixture": "tests/test_exploitrunner.py::TestExecutorGating::test_trollstore_requires_afu",
    },
    {
        "capability_id": "afu-agent",
        "name": "AFU agent install + AFC2 verify (app-based jailbreaks)",
        "status": "DOCUMENTED",
        "category": "kernel",
        "research_id": "dopamine-family",
        "description": "Generic AFU agent flow: installs an examiner-provided "
                       "jailbreak/agent .ipa/.tipa via developer services, then "
                       "verifies AFC2 root. Never claims the jailbreak itself "
                       "ran on-device.",
        "adapter": "opensleuth.exploitrunner.exec_afu_agent",
        "adapter_version": "",
        "prerequisites": ["AFU (unlocked, paired)",
                          "examiner-provided agent .ipa/.tipa in a payload directory",
                          "pymobiledevice3 installed"],
        "supported_builds": [],
        "limitations": [
            "executor exists but no test fixture exercises exec_afu_agent directly (only planner strategy presence is asserted) - held at DOCUMENTED until a fixture lands",
            "success requires AFC2 live after the examiner opens the agent app on-device once",
        ],
        "validation_evidence": [],
        "test_fixture": "",
    },
    {
        "capability_id": "pongo-ramdisk",
        "name": "PongoOS ramdisk boot (checkm8, DFU/recovery)",
        "status": "DOCUMENTED",
        "category": "bootrom",
        "research_id": "pongoos",
        "description": "Boots the PongoOS shell via palera1n -p as the "
                       "ramdisk-chain stepping stone. Success is claimed only "
                       "when irecovery answers (PongoOS reachable).",
        "adapter": "opensleuth.exploitrunner.exec_pongo_ramdisk",
        "adapter_version": "",
        "prerequisites": ["checkm8 chip (A8-A11) in DFU/recovery or PWND state",
                          "palera1n binary installed",
                          "payloads (iBSS/iBEC or ramdisk image) available"],
        "supported_builds": [],
        "limitations": [
            "executor exists but no test fixture exercises exec_pongo_ramdisk directly (only planner strategy presence is asserted) - held at DOCUMENTED until a fixture lands",
            "no recorded hardware validation run yet",
        ],
        "validation_evidence": [],
        "test_fixture": "",
    },
    {
        "capability_id": "usbliter8-chain",
        "name": "usbliter8 chain boot (A12/A13, after RP2350 PWND)",
        "status": "INTEGRATED",
        "category": "bootrom",
        "research_id": "usbliter8",
        "description": "Post-PWND chain: with the PWND:[usbliter8] marker "
                       "present, runs usbliter8ctl demote + boot. Success is "
                       "claimed only when PongoOS or recovery/iBoot is reachable "
                       "afterwards.",
        "adapter": "opensleuth.exploitrunner.exec_usbliter8_chain",
        "adapter_version": "1",
        "prerequisites": ["A12/A13",
                          "PWND:[usbliter8] marker present (RP2350 rig already ran the bootrom exploit)",
                          "usbliter8ctl installed"],
        "supported_builds": [],
        "limitations": [
            "no recorded hardware validation run yet (validation required)",
            "CoreProbe does not run the bootrom exploit itself - the RP2350 rig does; this adapter only continues the chain after PWND",
        ],
        "validation_evidence": [],
        "test_fixture": "tests/test_exploitrunner.py::TestExecutorGating::test_usbliter8_chain_requires_marker",
    },
    {
        "capability_id": "misaka-mg",
        "name": "Misaka/Nugget MobileGestalt tool install (iOS 26.0-26.1)",
        "status": "INTEGRATED",
        "category": "kernel",
        "research_id": "misaka26",
        "description": "Host-side eligibility check + install of the "
                       "Misaka/Nugget MobileGestalt tool (.tipa) via developer "
                       "services, or verification that it is already installed. "
                       "The exploit itself runs on-device when the examiner "
                       "opens the app.",
        "adapter": "opensleuth.exploitrunner.exec_misaka_mg",
        "adapter_version": "1",
        "prerequisites": ["AFU (unlocked, paired)", "iOS 26.0-26.1 (patched in 26.2)",
                          "pymobiledevice3 installed",
                          "examiner-provided .tipa payload, or tool already installed"],
        "supported_builds": [],
        "limitations": [
            "no recorded hardware validation run yet (validation required)",
            "userspace MobileGestalt tweaks only - not a filesystem acquisition route",
        ],
        "validation_evidence": [],
        "test_fixture": "tests/test_exploitrunner.py::TestExecutorGating::test_misaka_version_gate",
    },
    {
        "capability_id": "restore-traversal-probe",
        "name": "Restore-traversal research probe (CVE-2026-84598)",
        "status": "INTEGRATED",
        "category": "research",
        "research_id": "cve-2026-84598",
        "description": "Crafted restore-manifest probe: observes whether a "
                       "<26.7 target's restore stack accepts traversal paths. "
                       "Research-safe by design - the harness aborts before any "
                       "file transfer.",
        "adapter": "opensleuth.exploitrunner.exec_restore_traversal",
        "adapter_version": "1",
        "prerequisites": ["AFU + paired", "iOS < 26.7 (patched in 26.7)",
                          "pymobiledevice3 installed"],
        "supported_builds": [],
        "limitations": [
            "no recorded hardware validation run yet (validation required)",
            "research probe only: a positive result is schema acceptance, not acquisition; the Find My gate may block completion",
        ],
        "validation_evidence": [],
        "test_fixture": "tests/test_exploitrunner.py::TestExecutorGating::test_restore_traversal_version_gate",
    },
    {
        "capability_id": "bfu-ramdisk-extract",
        "name": "BFU ramdisk extraction (keybags + metadata, post-PWND)",
        "status": "DOCUMENTED",
        "category": "acquisition",
        "research_id": "bfu-ramdisk-extract",
        "description": "Post-PWND BFU extraction: with a checkm8 (A7-A11) "
                       "or usbliter8 (A12/A13) PWND marker present, loads the "
                       "examiner-provided per-device ramdisk payload set "
                       "(iBSS/iBEC/ramdisk/devicetree/trustcache) over "
                       "irecovery and pulls system/user keybags + fs "
                       "metadata over SSH (opensleuth.bfu.run_ramdisk_extract). "
                       "SEP-gated Complete* classes stay encrypted until "
                       "first unlock.",
        "adapter": "opensleuth.exploitrunner.exec_bfu_ramdisk_extract",
        "adapter_version": "",
        "prerequisites": ["PWND marker in target state (checkm8 PWND on A7-A11, or PWND:[usbliter8] on A12/A13)",
                          "examiner-provided ramdisk payload dir with the full payload set (iBSS, iBEC, ramdisk, devicetree, trustcache)",
                          "irecovery + sshpass installed"],
        "supported_builds": [],
        "limitations": [
            "executor exists and is unit-gated (marker gate + missing-payload gate exercised directly in tests), but there is no recorded hardware validation run - held at DOCUMENTED until a real-device extraction is recorded",
            "payloads are examiner-provided per-device files; CoreProbe never fabricates them, and the executor fails naming exactly which payload files are missing",
            "protected-class (Complete*) content stays SEP-encrypted at BFU; this route yields keybags/metadata/unprotected classes only",
        ],
        "validation_evidence": [],
        "test_fixture": "tests/test_bfu_wiring.py::TestBfuExecutors::test_extract_missing_payloads_lists_exact_files",
    },
    {
        "capability_id": "bfu-intel",
        "name": "BFU yield assessment (expectations + SEP wall, read-only)",
        "status": "INTEGRATED",
        "category": "acquisition",
        "research_id": "bfu-yield-card",
        "description": "Read-only BFU intelligence step: renders the "
                       "per-chip yield card + protection-class expectations "
                       "(opensleuth.bfu.yield_card/expectations) for the "
                       "probed target - what this device can yield before "
                       "first unlock, and the SEP wall stated per device. "
                       "No device writes, no subprocess tooling; honest "
                       "failure only when the chip is unknown.",
        "adapter": "opensleuth.exploitrunner.exec_bfu_intel",
        "adapter_version": "1",
        "prerequisites": ["chip identified by probe (lockdown/serial/iBoot)"],
        "supported_builds": [],
        "limitations": [
            "no recorded hardware validation run yet (validation required)",
            "assessment only: renders expectations/yield from the probed chip/iOS - it acquires nothing by itself",
        ],
        "validation_evidence": [],
        "test_fixture": "tests/test_bfu_wiring.py::TestBfuExecutors::test_bfu_intel_a13_renders_yield_card",
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
