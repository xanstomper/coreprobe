"""Zero-day research campaign orchestrator.

Structures exploit discovery as repeatable sessions against lawful
research devices. A campaign ties together: DFU captures -> trace
analysis -> corpus building -> fuzz runs -> leads (anomalies/crashes)
-> verdicts (promising / dead end / escalated). State persists to
~/.coreprobe/campaign.json so the 10-hour sessions compound.

HONESTY RULE (absolute): leads are anomalies we OBSERVED. Nothing is
promoted to a "finding" without a reproduced crash + root-cause
hypothesis. Nothing enters the exploit catalog without a public writeup.
This module never fabricates capability - it records what actually
happened on real hardware.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .dfufuzz import run_fuzz
from .dfutrace import analyze, build_corpus, parse_usbmon_text

DEFAULT_STATE = Path.home() / ".coreprobe" / "campaign.json"

VERDICTS = ("observed", "promising", "dead-end", "escalated", "finding")

LEAD_SCHEMA = {
    "id": str, "ts": str, "session": str, "kind": str, "detail": str,
    "verdict": str, "repro": int, "notes": str,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load(path: Path = DEFAULT_STATE) -> dict[str, Any]:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"campaigns": {}, "sessions": [], "leads": []}


def save(state: dict[str, Any], path: Path = DEFAULT_STATE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2))


def new_campaign(state: dict[str, Any], name: str, target: str,
                 chip: str = "", ios: str = "") -> dict[str, Any]:
    cid = f"{name}-{int(time.time())}"
    state["campaigns"][cid] = {
        "name": name, "target": target, "chip": chip, "ios": ios,
        "created": _now(), "sessions": 0, "leads": 0,
    }
    return {"id": cid, **state["campaigns"][cid]}


def start_session(state: dict[str, Any], campaign_id: str,
                  kind: str = "dfu-fuzz") -> dict[str, Any]:
    sid = f"s{len(state['sessions']) + 1:04d}"
    session = {
        "id": sid, "campaign": campaign_id, "kind": kind,
        "started": _now(), "finished": None,
        "iterations": 0, "sent": 0, "crashes": 0, "hangups": 0,
        "corpus_size": 0,
    }
    state["sessions"].append(session)
    if campaign_id in state["campaigns"]:
        state["campaigns"][campaign_id]["sessions"] += 1
    return session


def finish_session(state: dict[str, Any], sid: str, stats: dict[str, Any]) -> None:
    for s in state["sessions"]:
        if s["id"] == sid:
            s.update({k: v for k, v in stats.items() if k in (
                "iterations", "sent", "crashes", "hangups", "corpus_size")})
            s["finished"] = _now()
            return
    raise KeyError(f"session not found: {sid}")


def add_lead(state: dict[str, Any], session_id: str, kind: str, detail: str,
             campaign_id: str = "", verdict: str = "observed",
             notes: str = "") -> dict[str, Any]:
    lid = f"L{len(state['leads']) + 1:03d}"
    lead = {
        "id": lid, "ts": _now(), "session": session_id,
        "kind": kind, "detail": detail[:500],
        "verdict": verdict if verdict in VERDICTS else "observed",
        "repro": 1, "notes": notes,
    }
    if campaign_id:
        lead["campaign"] = campaign_id
    state["leads"].append(lead)
    if campaign_id in state["campaigns"]:
        state["campaigns"][campaign_id]["leads"] = state["campaigns"][campaign_id].get("leads", 0) + 1
    return lead


def triage_lead(state: dict[str, Any], lead_id: str, verdict: str,
                notes: str = "") -> dict[str, Any]:
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    for lead in state["leads"]:
        if lead["id"] == lead_id:
            lead["verdict"] = verdict
            if notes:
                lead["notes"] = (lead.get("notes", "") + f" | {notes}").strip(" |")
            return lead
    raise KeyError(f"lead not found: {lead_id}")


def record_fuzz_run(state: dict[str, Any], campaign_id: str,
                    capture_text: str, transport: Any,
                    iterations: int = 200, seed: int = 1337,
                    log=print) -> dict[str, Any]:
    """One full research session: parse capture -> analyze -> corpus -> fuzz.

    transport: live device (pyusb) or a simulator in tests. Crashes and
    anomalies become leads automatically (verdict=observed).
    """
    events = parse_usbmon_text(capture_text)
    rep = analyze(events)
    corpus = build_corpus(events)
    if not corpus:
        finish = {"iterations": 0}
        session = start_session(state, campaign_id, kind="dfu-fuzz-empty")
        finish_session(state, session["id"], finish)
        return {"session": session, "analysis": rep, "fuzz": None,
                "note": "no DFU requests in capture; nothing to fuzz"}
    session = start_session(state, campaign_id)
    fz = run_fuzz(transport, corpus, iterations=iterations, seed=seed, log=log)
    finish_session(state, session["id"], {
        "iterations": iterations, "corpus_size": len(corpus), **fz})
    # anomalies from the trace
    for anomaly in rep.get("anomalies", [])[:10]:
        add_lead(state, session["id"], "trace-anomaly", anomaly,
                 campaign_id=campaign_id)
    # crashes observed live
    if fz.get("crashes"):
        add_lead(state, session["id"], "device-death",
                 f"device died after {fz['sent']} sends ({fz['crashes']} death(s))",
                 campaign_id=campaign_id, verdict="promising")
    return {"session": session, "analysis": rep, "fuzz": fz}


def render_status(state: dict[str, Any]) -> str:
    lines = ["research campaign status", "=" * 60]
    if state["campaigns"]:
        lines.append("campaigns:")
        for cid, c in state["campaigns"].items():
            lines.append(f"  {c['name']}  target={c['target']} chip={c['chip'] or '?'} "
                         f"sessions={c['sessions']} leads={c.get('leads', 0)}")
    else:
        lines.append("  (no campaigns yet - create one: opensleuth campaign new ...)")
    lines.append("")
    lines.append(f"leads: {len(state['leads'])}")
    for lead in state["leads"][-15:]:
        mark = {"finding": "★", "escalated": "▲", "promising": "●",
                "dead-end": "·", "observed": "·"}.get(lead["verdict"], "·")
        lines.append(f"  {mark} {lead['id']} [{lead['verdict']}] {lead['kind']}: "
                     f"{lead['detail'][:80]}")
    lines.append("")
    lines.append("verdicts: observed -> promising (repro) -> escalated "
                 "(root cause) -> finding (public writeup)")
    lines.append("rule: nothing enters the exploit catalog without a public writeup")
    return "\n".join(lines)


def render_session(session: dict[str, Any]) -> str:
    return (f"session {session['id']} ({session['kind']}) "
            f"{session['started']} -> {session['finished'] or 'open'}\n"
            f"  sent={session['sent']} crashes={session['crashes']} "
            f"hangups={session['hangups']} corpus={session['corpus_size']}")