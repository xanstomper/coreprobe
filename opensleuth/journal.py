"""Event-sourced session journal: the audit backbone for cases.

Every significant operation (device detection, capability assessment,
acquisition, evidence hashing, parsing, verification, report) emits a
structured event into an APPEND-ONLY per-session JSONL journal. Nothing
important may live only in terminal output.

Design rules (directive "autonomous case pipeline"):
  * append-only: historical events are never rewritten or deleted
  * corrections are NEW events referencing the original (parent_event_id)
  * every event: event_id, case_id, session_id, utc ts, monotonic ts,
    component+version, event_type, severity, device/evidence refs, payload
  * evidence objects get permanent IDs (EVD-000001, ...) with custody events
  * failures (ERROR/WARNING/TIMEOUT/DISCONNECT/PARSER_FAILURE/...) are
    first-class events, never buried in debug logs
  * case replay renders the journal into a human-auditable timeline

Concurrency: a single inter-process lock (fcntl) guards appends so the web
studio + CLI can both journal into one case safely.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

# Canonical event types (extensible, but these are the audited vocabulary)
EVENT_TYPES = {
    # device lifecycle
    "DeviceDetected", "DeviceIdentified", "DeviceDisconnected",
    "CapabilityAssessed", "FingerprintRecorded",
    # research / truth
    "ResearchMatchFound", "ValidationStarted", "ValidationCompleted",
    # acquisition
    "AcquisitionStarted", "AcquisitionProgress", "AcquisitionCompleted",
    "AcquisitionInterrupted",
    # evidence
    "EvidenceCreated", "EvidenceHashed", "EvidenceVerified",
    "EvidenceDerived", "EvidenceExported",
    "CustodyEvent",
    # processing
    "FilesystemDiscovered", "ArtifactDiscovered", "ArtifactParsed",
    "ParserWarning", "ParserFailure", "TimelineBuilt", "ReportGenerated",
    "SessionStarted", "SessionCompleted",
    # failures
    "Error", "Warning", "Timeout", "IntegrityFailure",
    "UnsupportedVersion",
    # corrections
    "Correction",
}

SEVERITIES = {"debug", "info", "notice", "warning", "error", "critical"}

FAILURE_TYPES = {
    "Error", "Warning", "Timeout", "DeviceDisconnected",
    "AcquisitionInterrupted", "ParserFailure", "ParserWarning",
    "IntegrityFailure", "UnsupportedVersion", "ValidationCompleted",
}

try:
    from . import __version__ as _COMPONENT_VERSION
except ImportError:  # pragma: no cover - standalone use
    _COMPONENT_VERSION = "1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class JournalError(Exception):
    pass


class SessionJournal:
    """Append-only journal for one case session.

    Layout:
        <case_dir>/journal/<session_id>.jsonl     events
        <case_dir>/journal/evidence-index.json    evidence ID counter (locked)
    """

    def __init__(self, case_dir: str | Path, session_id: str,
                 operator: str = "", case_id: str = ""):
        self.case_dir = Path(case_dir)
        self.case_id = case_id or self.case_dir.name
        self.session_id = session_id
        self.operator = operator
        self.journal_dir = self.case_dir / "journal"
        self.journal_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.journal_dir / f"{session_id}.jsonl"
        self._monotonic = time.monotonic()
        self._session_started = False

    # ------------------------------------------------------------------ core
    def emit(self, event_type: str, payload: dict[str, Any] | None = None,
             severity: str = "info", device_id: str = "",
             evidence_id: str = "", parent_event_id: str = "",
             component: str = "core") -> dict[str, Any]:
        """Append one structured event. Returns the event (with its id)."""
        if event_type not in EVENT_TYPES:
            raise JournalError(f"unknown event type {event_type!r}")
        if severity not in SEVERITIES:
            raise JournalError(f"unknown severity {severity!r}")
        event = {
            "event_id": f"EVT-{uuid.uuid4().hex[:12]}",
            "case_id": self.case_id,
            "session_id": self.session_id,
            "timestamp": _now(),
            "monotonic_timestamp": round(time.monotonic() - self._monotonic, 6),
            "component": component,
            "component_version": _COMPONENT_VERSION,
            "event_type": event_type,
            "severity": severity,
            "device_id": device_id,
            "evidence_id": evidence_id,
            "parent_event_id": parent_event_id,
            "operator": self.operator,
            "payload": payload or {},
        }
        line = json.dumps(event, default=str, ensure_ascii=False)
        with open(self.path, "a", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return event

    def start(self, notes: str = "") -> dict[str, Any]:
        if self._session_started:
            raise JournalError("session already started")
        self._session_started = True
        return self.emit("SessionStarted", {"notes": notes})

    def complete(self, summary: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.emit("SessionCompleted", summary or {})

    # ------------------------------------------------------------ failures
    def failure(self, event_type: str, component: str,
                human_message: str, technical_message: str = "",
                error_code: str = "", recovery_attempt: str = "",
                final_status: str = "", device_id: str = "",
                evidence_id: str = "") -> dict[str, Any]:
        """Record a failure as first-class evidence about the process."""
        if event_type not in FAILURE_TYPES:
            raise JournalError(f"{event_type!r} is not a failure event type")
        return self.emit(
            event_type,
            {
                "error_code": error_code,
                "human_message": human_message,
                "technical_message": technical_message,
                "recovery_attempt": recovery_attempt,
                "final_status": final_status,
            },
            severity="error" if event_type not in ("Warning", "ParserWarning")
            else "warning",
            component=component,
            device_id=device_id,
            evidence_id=evidence_id,
        )

    def correct(self, original_event_id: str, correction: str,
                payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Corrections NEVER rewrite history: they append a Correction event
        referencing the original."""
        return self.emit("Correction", {"correction": correction, **(payload or {})},
                         parent_event_id=original_event_id)

    # ------------------------------------------------------------ evidence
    def next_evidence_id(self) -> str:
        """Allocate the next permanent evidence ID (EVD-000001...), guarded by
        an inter-process lock so concurrent writers cannot collide."""
        idx_path = self.journal_dir / "evidence-index.json"
        with open(idx_path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                fh.seek(0)
                raw = fh.read().strip()
                try:
                    counter = json.loads(raw)["next"]
                except (ValueError, KeyError):
                    counter = 1
                ev_id = f"EVD-{counter:06d}"
                fh.seek(0)
                fh.truncate()
                fh.write(json.dumps({"next": counter + 1}))
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return ev_id

    def evidence_created(self, source_path: str, size: int,
                         acquisition_method: str, device_id: str = "",
                         derived_from: str = "",
                         hash_value: str = "", hash_algorithm: str = "sha256",
                         extra: dict[str, Any] | None = None) -> dict[str, Any]:
        ev_id = self.next_evidence_id()
        payload = {
            "evidence_id": ev_id,
            "source_path": source_path,
            "size": size,
            "acquisition_method": acquisition_method,
            "derived_from": derived_from,
            "hash": hash_value,
            "hash_algorithm": hash_algorithm,
            **(extra or {}),
        }
        self.emit("EvidenceCreated", payload, device_id=device_id,
                  evidence_id=ev_id)
        if hash_value:
            self.emit("EvidenceHashed", {
                "evidence_id": ev_id, "hash": hash_value,
                "algorithm": hash_algorithm,
            }, evidence_id=ev_id)
        return payload

    def custody(self, evidence_id: str, action: str, actor: str = "",
                reason: str = "", hash_value: str = "") -> dict[str, Any]:
        if action not in ("created", "transferred", "copied", "verified",
                          "exported", "viewed", "derived"):
            raise JournalError(f"unknown custody action {action!r}")
        return self.emit("CustodyEvent", {
            "action": action, "actor": actor or self.operator,
            "reason": reason, "hash": hash_value,
        }, evidence_id=evidence_id)

    # ------------------------------------------------------------- reading
    def read(self) -> list[dict[str, Any]]:
        """Load all events of this session (for replay/tests)."""
        if not self.path.is_file():
            return []
        events = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                # A torn final line (crash mid-append) is preserved as-is is
                # impossible in an append-only file; we skip invalid lines but
                # surface them as parse failures via replay().
                events.append({"event_type": "JournalCorruption",
                               "raw": line})
        return events

    # -------------------------------------------------------------- replay
    def replay(self) -> str:
        """Human-auditable reconstruction of everything that happened."""
        events = self.read()
        lines = [f"case {self.case_id} · session {self.session_id} "
                 f"({len(events)} events)"]
        lines.append("-" * 64)
        for e in events:
            ts = (e.get("timestamp") or "")[11:23]
            et = e.get("event_type", "?")
            sev = e.get("severity", "")
            sev_tag = f" [{sev.upper()}]" if sev in ("warning", "error",
                                                     "critical") else ""
            ev = f" ({e['evidence_id']})" if e.get("evidence_id") else ""
            dev = f" dev={e['device_id']}" if e.get("device_id") else ""
            detail = ""
            p = e.get("payload") or {}
            if et == "EvidenceCreated":
                detail = f" {p.get('source_path')} ({p.get('size')}B " \
                         f"via {p.get('acquisition_method')})"
            elif et == "AcquisitionStarted":
                detail = f" method={p.get('method')}"
            elif et in FAILURE_TYPES:
                detail = f" {p.get('human_message') or p.get('correction') or ''}"
            elif et == "Correction":
                detail = f" -> {e.get('parent_event_id')}: {p.get('correction')}"
            elif et == "CapabilityAssessed":
                detail = f" {p.get('summary') or ''}"
            lines.append(f"{ts} {et}{sev_tag}{ev}{dev}{detail}")
        return "\n".join(lines)

    # ------------------------------------------------------------- summary
    def summary(self) -> dict[str, Any]:
        events = self.read()
        counts: dict[str, int] = {}
        for e in events:
            counts[e.get("event_type", "?")] = counts.get(e.get("event_type", "?"), 0) + 1
        failures = [e for e in events
                    if e.get("severity") in ("error", "critical")]
        evidence = sorted({e["evidence_id"] for e in events
                           if e.get("evidence_id")})
        return {
            "session_id": self.session_id,
            "case_id": self.case_id,
            "events": len(events),
            "event_counts": counts,
            "failures": len(failures),
            "failure_types": sorted({e.get("event_type") for e in failures}),
            "evidence_ids": evidence,
            "started": next((e["timestamp"] for e in events
                             if e.get("event_type") == "SessionStarted"), ""),
            "completed": next((e["timestamp"] for e in reversed(events)
                               if e.get("event_type") == "SessionCompleted"), ""),
        }


def new_session(case_dir: str | Path, operator: str = "",
                case_id: str = "", notes: str = "") -> SessionJournal:
    """Create a journal for a fresh session (timestamped id)."""
    sid = "S-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") \
        + "-" + uuid.uuid4().hex[:4]
    j = SessionJournal(case_dir, sid, operator=operator, case_id=case_id)
    j.start(notes=notes)
    return j


# ----------------------------------------------------------- integrity check

def verify_journal_file(path: str | Path) -> dict[str, Any]:
    """Structural verification of a journal file (append-only sanity)."""
    p = Path(path)
    if not p.is_file():
        return {"ok": False, "error": "journal file not found"}
    bad = []
    n = 0
    last_ts = ""
    ts_regressions = 0
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        n += 1
        try:
            e = json.loads(line)
        except ValueError:
            bad.append(n)
            continue
        for req in ("event_id", "session_id", "timestamp", "event_type"):
            if req not in e:
                bad.append(n)
                break
        ts = e.get("timestamp", "")
        if ts and last_ts and ts < last_ts:
            ts_regressions += 1
        last_ts = max(last_ts, ts) if ts else last_ts
    return {
        "ok": not bad and ts_regressions == 0,
        "events": n,
        "malformed_lines": bad,
        "timestamp_regressions": ts_regressions,
    }
