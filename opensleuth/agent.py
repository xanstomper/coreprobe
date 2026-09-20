"""AI agent harness for CoreProbe: fully-automatic, legally-defensible.

Architecture (deliberate, per the examiner-accountability standard):

  * DETERMINISTIC CORE: every evidence operation is a fixed executor
    (subprocess/tool call) whose outputs are objectively verifiable. The
    agent NEVER uses an LLM to collect, modify, or classify evidence.
  * STATE MACHINE: the agent's position is always an explicit state with a
    journal event for every transition. Any observer can reconstruct what
    happened (`opensleuth agent status` / journal replay).
  * APPROVAL GATES: routes that mutate device state or perform terminal
    acquisition require examiner sign-off first (recorded in the journal).
    `--yes`/auto-approve records the consent event with the operator name.
  * LLM AS ADVISOR ONLY: an optional advisor model may summarize results,
    draft narrative notes, and suggest (non-evidence) next actions. Its
    output is recorded as ADVISORY, clearly derived, never observed fact.

States:
  IDLE → DEVICE_DETECTED → IDENTIFYING → ASSESSING → PLANNING →
  AWAITING_APPROVAL → EXECUTING → VERIFYING → PROCESSING → REPORTING →
  CASE_READY
Terminal failures: FAILED, PARTIAL, INTERRUPTED, UNSUPPORTED.

Usage:
  harness = AgentHarness(case_dir, operator="Examiner A")
  while not harness.terminal():
      harness.step()          # deterministic policy advances the machine
  print(harness.status())
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from .journal import SessionJournal, new_session

STATES = [
    "IDLE", "DEVICE_DETECTED", "IDENTIFYING", "ASSESSING", "PLANNING",
    "AWAITING_APPROVAL", "EXECUTING", "VERIFYING", "PROCESSING",
    "REPORTING", "CASE_READY",
]
TERMINAL = {"CASE_READY", "FAILED", "PARTIAL", "INTERRUPTED", "UNSUPPORTED"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class AgentStatus:
    state: str = "IDLE"
    case_dir: str = ""
    operator: str = ""
    session_id: str = ""
    device: dict[str, Any] = field(default_factory=dict)
    plan: list[dict[str, Any]] = field(default_factory=list)
    pending_approval: list[str] = field(default_factory=list)
    approved: bool = False
    executed: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    report: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)

    def summary(self) -> str:
        lines = [f"agent: state={self.state} case={self.case_dir or '-'} "
                 f"operator={self.operator or '-'}"]
        if self.device:
            lines.append(f"  device : {self.device.get('model', '?')} "
                         f"chip={self.device.get('chip', '?')} "
                         f"ios={self.device.get('ios', '?')} "
                         f"state={self.device.get('state', '?')}")
        if self.pending_approval and not self.approved:
            lines.append(f"  AWAITING APPROVAL for: "
                         f"{', '.join(self.pending_approval)}")
        for e in self.executed:
            lines.append(f"  route  : [{e.get('status')}] "
                         f"{e.get('name')} - {str(e.get('detail', ''))[:90]}")
        if self.evidence:
            lines.append(f"  evidence: {len(self.evidence)} object(s)")
        if self.artifacts:
            total = sum(v for v in self.artifacts.values()
                        if isinstance(v, int))
            lines.append(f"  artifacts: {total} parsed rows")
        if self.report:
            lines.append(f"  report : {self.report.get('path', '-')}")
        if self.error:
            lines.append(f"  error  : {self.error}")
        return "\n".join(lines)


class AgentHarness:
    """One agent run over one case directory."""

    def __init__(self, case_dir: str | Path, operator: str = "",
                 auto_approve: bool = False,
                 journal: Optional[SessionJournal] = None,
                 log: Optional[Callable[[str], None]] = None):
        self.case_dir = Path(case_dir)
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.operator = operator or "examiner"
        self.auto_approve = auto_approve
        self.journal = journal or new_session(self.case_dir,
                                              operator=self.operator)
        self.status = AgentStatus(case_dir=str(self.case_dir),
                                  operator=self.operator,
                                  session_id=self.journal.session_id)
        self._log_cb = log
        self._llm = None  # advisor set via attach_advisor()

    # ------------------------------------------------------------------ util
    def _log(self, msg: str) -> None:
        if self._log_cb:
            self._log_cb(msg)

    def _transition(self, new_state: str, payload: dict[str, Any] | None = None):
        old = self.status.state
        self.status.state = new_state
        self.journal.emit("AcquisitionProgress",
                          {"transition": f"{old}->{new_state}",
                           **(payload or {})},
                          severity="notice")
        self._log(f"[agent] {old} -> {new_state}")

    def attach_advisor(self, advisor) -> None:
        """Optional LLM advisor (agentllm). Advisory-only by construction."""
        self._llm = advisor

    def terminal(self) -> bool:
        return self.status.state in TERMINAL

    # ------------------------------------------------------------- the loop
    def step(self) -> AgentStatus:
        """Advance the state machine by one deterministic step."""
        s = self.status.state
        try:
            if s == "IDLE":
                self._step_detect()
            elif s == "DEVICE_DETECTED":
                self._step_identify()
            elif s == "IDENTIFYING":
                self._step_assess()
            elif s == "ASSESSING":
                self._step_plan()
            elif s == "PLANNING":
                self._step_gate()
            elif s == "AWAITING_APPROVAL":
                self._step_wait_approval()
            elif s == "EXECUTING":
                self._step_execute()
            elif s == "VERIFYING":
                self._step_process()
            elif s == "PROCESSING":
                self._step_report()
            elif s == "REPORTING":
                self._step_finalize()
        except KeyboardInterrupt:
            self._fail("INTERRUPTED", "interrupted by operator")
        except Exception as exc:  # noqa: BLE001
            self._fail("FAILED", f"{type(exc).__name__}: {exc}")
        return self.status

    def run(self, max_steps: int = 100) -> AgentStatus:
        for _ in range(max_steps):
            if self.terminal():
                break
            self.step()
        # persist the final state so status/approve can resume or inspect
        try:
            sf = self.case_dir / "agent-state.json"
            sf.write_text(json.dumps(self.status.to_dict(), indent=2,
                                     default=str), encoding="utf-8")
        except OSError:
            pass
        return self.status

    # ------------------------------------------------------------ steps
    def _step_detect(self) -> None:
        from .usb import usb_state
        snap = usb_state()
        if snap.get("any"):
            self.journal.emit("DeviceDetected",
                              {"usb": [{k: v for k, v in d.items()
                                        if k != "sysfs"}
                                       for d in snap["devices"]]})
            self._transition("DEVICE_DETECTED")
        else:
            self._fail("UNSUPPORTED",
                       "no Apple device on USB - connect/unlock the device")

    def _step_identify(self) -> None:
        from .fingerprint import fingerprint_device
        fp = fingerprint_device()
        raw = fp.to_dict()
        d = {}
        for k, v in raw.items():
            if isinstance(v, dict) and "value" in v:
                d[k] = v["value"]
            elif hasattr(v, "value"):
                d[k] = v.value
            else:
                d[k] = v
        self.status.device = d
        self.journal.emit("FingerprintRecorded", raw,
                          device_id=str(d.get("udid", "")))
        self._transition("IDENTIFYING")

    def _step_assess(self) -> None:
        from .planner import Planner
        methods = Planner().plan(_fp_wrapper(self.status.device))
        self.status.plan = [m.__dict__ for m in methods]
        sel = [m.capability_id for m in methods if m.selectable()]
        self.journal.emit("CapabilityAssessed",
                          {"selectable": sel,
                           "verdicts": {m.capability_id: m.verdict
                                        for m in methods}})
        if not sel:
            self._fail("UNSUPPORTED",
                       "no operational acquisition route for this target "
                       "(see plan verdicts)")
            return
        self._transition("ASSESSING")

    def _step_plan(self) -> None:
        from .exploitrunner import Target, build_plan
        d = self.status.device
        t = Target(present=True, chip=str(d.get("chip", "")),
                   ios=str(d.get("ios", "")), state=str(d.get("state", "")))
        self._runner_plan = build_plan(t)
        self.status.plan = self.status.plan + [i.__dict__
                                               for i in self._runner_plan]
        self._transition("PLANNING")

    def _step_gate(self) -> None:
        """Approval gate: terminal acquisitions + destructive routes need
        examiner sign-off (auto_approve records consent)."""
        need = [i.name for i in self._runner_plan
                if getattr(i, "terminal", False) or i.destructive]
        if need and not self.auto_approve:
            self.status.pending_approval = need
            self.journal.emit("Warning",
                              {"awaiting_approval": need,
                               "note": "examiner sign-off required for "
                                       "acquisition routes"},
                              severity="notice")
            self._transition("AWAITING_APPROVAL")
            return
        if need and self.auto_approve:
            self.journal.emit("Warning",
                              {"approval": "AUTO (operator consent flag)",
                               "routes": need}, severity="notice")
        self._transition("EXECUTING")

    def approve(self, note: str = "") -> bool:
        """Examiner approves the pending acquisition routes."""
        if self.status.state != "AWAITING_APPROVAL":
            return False
        self.journal.emit("Warning",
                          {"approval": "EXAMINER",
                           "routes": self.status.pending_approval,
                           "note": note}, severity="notice")
        self.status.approved = True
        self._transition("EXECUTING")
        return True

    def _step_wait_approval(self) -> None:
        # deterministic policy: wait. approve() or auto_approve moves on.
        self._log("[agent] AWAITING APPROVAL - call approve() (or run with "
                  "--yes to record operator consent)")

    def _step_execute(self) -> None:
        from .exploitrunner import run_plan
        rep = run_plan(_target_from(self.status.device), self._runner_plan,
                       log=lambda m: self._log(f"[route] {m}"))
        self.status.executed = [
            {"name": r.name, "status": r.status, "detail": r.detail}
            for r in rep.results]
        # journal each route outcome
        for r in rep.results:
            self.journal.emit(
                "AcquisitionCompleted" if r.status == "succeeded"
                else "Error" if r.status == "failed" else "Warning",
                {"route": r.name, "detail": r.detail},
                severity="info" if r.status == "succeeded" else
                ("error" if r.status == "failed" else "notice"))
        if rep.winner:
            self._transition("VERIFYING", {"winner": rep.winner})
        elif any(r.status == "succeeded" for r in rep.results):
            self._transition("VERIFYING", {"winner": None,
                                           "note": "probes only - no "
                                                   "acquisition landed"})
        else:
            self._fail("PARTIAL",
                       "no route completed acquisition (see route details)")

    def _step_process(self) -> None:
        """Verify acquired evidence on disk (hashes), then parse artifacts."""
        import hashlib
        from .parsers import safe_parse
        ev_root = self.case_dir
        found: list[dict[str, Any]] = []
        # evidence = any backup dirs / info files written under the case
        for cand in sorted(ev_root.rglob("Manifest.*")):
            backup_dir = cand.parent
            h = hashlib.sha256(cand.read_bytes()).hexdigest()
            size = sum(f.stat().st_size
                       for f in backup_dir.rglob("*") if f.is_file())
            rec = self.journal.evidence_created(
                source_path=str(cand), size=size,
                acquisition_method="autoexploit-backup",
                hash_value=h)
            found.append(rec)
            self.journal.custody(rec["evidence_id"], "verified",
                                 reason="auto pipeline hash check")
        self.status.evidence = found
        # parse any backup we can (reuse the proven dump path)
        report_dir = ev_root / "report"
        if found:
            import subprocess, sys
            bdir = Path(found[0]["source_path"]).parent
            rc = subprocess.run(
                [sys.executable, "-m", "opensleuth", "dump", str(bdir),
                 "-o", str(report_dir)],
                capture_output=True, text=True, timeout=900)
            if rc.returncode == 0 and report_dir.exists():
                counts: dict[str, Any] = {}
                aj = report_dir / "artifacts.json"
                if aj.is_file():
                    try:
                        data = json.loads(aj.read_text())
                        counts = {k: (len(v) if isinstance(v, list) else v)
                                  for k, v in data.items()
                                  if isinstance(v, list)}
                    except ValueError:
                        pass
                self.status.artifacts = counts
                self.journal.emit("ArtifactParsed",
                                  {"parser": "opensleuth-dump",
                                   "counts": counts})
            else:
                self.journal.failure("ParserFailure", "dump",
                                     "backup parsing failed",
                                     technical_message=(rc.stderr or "")[-300:])
        self._transition("PROCESSING")

    def _step_report(self) -> None:
        """Write the case report (deterministic) + optional LLM narrative."""
        rep = {
            "generated": _now(),
            "operator": self.operator,
            "session": self.journal.session_id,
            "device": self.status.device,
            "routes": self.status.executed,
            "evidence": self.status.evidence,
            "artifacts": self.status.artifacts,
            "journal_replay": self.journal.replay(),
        }
        # Optional advisory narrative (clearly labeled derived)
        if self._llm is not None:
            try:
                rep["advisory_narrative"] = self._llm.summarize(
                    {"device": self.status.device,
                     "routes": self.status.executed,
                     "evidence_count": len(self.status.evidence),
                     "artifacts": self.status.artifacts})
                rep["advisory_narrative_disclaimer"] = (
                    "LLM-generated narrative. ADVISORY ONLY - derived from "
                    "tool output, not observed fact. Verify against the "
                    "journal replay.")
            except Exception as exc:  # noqa: BLE001
                rep["advisory_narrative_error"] = str(exc)
        out = self.case_dir / "agent-report.json"
        out.write_text(json.dumps(rep, indent=2, default=str),
                       encoding="utf-8")
        self.status.report = {"path": str(out)}
        self.journal.emit("ReportGenerated", {"path": str(out)})
        self._transition("REPORTING")

    def _step_finalize(self) -> None:
        s = self.journal.summary()
        self.journal.complete({"state": "CASE_READY",
                               "evidence": len(self.status.evidence)})
        self._transition("CASE_READY", {"events": s["events"]})

    def _fail(self, state: str, why: str) -> None:
        self.status.error = why
        self.status.state = state
        self.journal.failure("Error", "agent", why)
        self._log(f"[agent] {state}: {why}")


# ------------------------------------------------------------------ helpers


def _fp_wrapper(device: dict[str, Any]):
    from .fingerprint import Fingerprint
    fp = Fingerprint()
    for k in ("chip", "ios", "state", "model", "udid", "product_type"):
        if device.get(k) is not None:
            fp.set(k, device[k], "agent-status", "Observed")
    return fp


def _target_from(device: dict[str, Any]):
    from .exploitrunner import Target
    return Target(present=True, chip=str(device.get("chip", "")),
                  ios=str(device.get("ios", "")),
                  state=str(device.get("state", "")))
