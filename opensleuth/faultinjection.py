"""Fault-injection research planner — path 3 (hardware attacks on SEP).

Voltage-glitch / electromagnetic / laser fault injection is a documented
academic-and-industry technique against secure enclaves. This module
plans campaigns: target selection, equipment tiers, glitch-parameter
search spaces, and session logging — the project-management side of FI
research. It does not claim any working fault; a real one is found on
the bench with real hardware.

Attack moments worth glitching (per public literature on secure
enclave / counter research):
  - SEP boot ROM signature-check branch (early, per-boot)
  - SEPOS counter-increment path (passcode wrong-attempt handling)
  - key-unwrapping loop bounds (passcode-derived key derivation)
  - delay-enforcement scheduler entry
Equipment tiers: ChipWhisperer Husky (~$4k, EM/voltage, bench-top) →
template: EM probe station (~$30k) → laser FI station ($100k+).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

TARGET_MOMENTS = [
    {"id": "seprom-sigcheck", "phase": "SEP boot",
     "window": "ROM verify branch (early boot)",
     "goal": "skip signature validation (classic FI goal)",
     "difficulty": "extreme (ROM hardened, narrow window)"},
    {"id": "sepos-counter", "phase": "wrong passcode",
     "window": "counter increment write cycle",
     "goal": "prevent counter persistence -> unlimited attempts",
     "difficulty": "hard (single write, timing discoverable via power trace)"},
    {"id": "key-unwrap", "phase": "passcode entry",
     "window": "key-derivation loop bounds",
     "goal": "corrupt loop bound -> early-exit -> wrong key accepted",
     "difficulty": "hard"},
    {"id": "delay-sched", "phase": "lockout",
     "window": "delay scheduler entry",
     "goal": "skip escalating-delay branch",
     "difficulty": "medium (code path after counter)"},
]

EQUIPMENT = [
    {"tier": "entry", "name": "ChipWhisperer Husky + EM probe",
     "cost_usd": 4000, "can": "voltage + EM glitching, power trace capture",
     "fit": "first bench; enough for scheduler/delay-class targets"},
    {"tier": "mid", "name": "EM probe station + high-zoom stage",
     "cost_usd": 30000, "can": "localized EM faults, semi-automated search",
     "fit": "counter/key-unwrap targets"},
    {"tier": "high", "name": "laser FI station (2-photon)",
     "cost_usd": 150000, "can": "single-gate precision faults",
     "fit": "sigcheck-class targets; professional lab"},
]


@dataclass
class GlitchPlan:
    target_id: str
    width_ns_min: float
    width_ns_max: float
    width_step: float
    offset_ns_min: float
    offset_ns_max: float
    offset_step: float
    repeats: int = 5

    def grid_size(self) -> int:
        w = int((self.width_ns_max - self.width_ns_min) / self.width_step) + 1
        o = int((self.offset_ns_max - self.offset_ns_min) / self.offset_step) + 1
        return w * o * self.repeats


def default_plan(target_id: str) -> GlitchPlan:
    return GlitchPlan(target_id, 20.0, 400.0, 10.0, -2000.0, 2000.0, 25.0)


@dataclass
class Campaign:
    target_id: str
    plan: GlitchPlan
    results: list[dict[str, Any]] = field(default_factory=list)

    def log_result(self, offset_ns: float, width_ns: float,
                   outcome: str, note: str = "") -> None:
        self.results.append({"offset_ns": offset_ns, "width_ns": width_ns,
                             "outcome": outcome, "note": note})

    def interesting(self) -> list[dict[str, Any]]:
        return [r for r in self.results if r["outcome"] != "normal"]


OUTCOMES = ("normal", "reset", "no-effect", "glitch-effect",
            "abnormal-boot", "lockout-skip")


def render_plan(p: GlitchPlan, t: dict[str, Any]) -> str:
    return (f"FI plan: {t['id']} ({t['phase']} — {t['window']})\n"
            f"  goal      : {t['goal']}\n"
            f"  difficulty: {t['difficulty']}\n"
            f"  glitch width : {p.width_ns_min}-{p.width_ns_max} ns step {p.width_step}\n"
            f"  offset       : {p.offset_ns_min} to {p.offset_ns_max} ns step {p.offset_step}\n"
            f"  repeats/point: {p.repeats}\n"
            f"  grid points  : {p.grid_size():,}\n"
            f"  log outcomes as one of: {', '.join(OUTCOMES)}")


def render_equipment() -> str:
    lines = ["equipment tiers:"]
    for e in EQUIPMENT:
        lines.append(f"  [{e['tier']:<5}] {e['name']} (~${e['cost_usd']:,})")
        lines.append(f"          can: {e['can']}")
        lines.append(f"          fit: {e['fit']}")
    return "\n".join(lines)


def render_targets() -> str:
    lines = ["fault-injection target moments:"]
    for t in TARGET_MOMENTS:
        lines.append(f"  * {t['id']} [{t['phase']}] {t['window']}")
        lines.append(f"      goal: {t['goal']} | {t['difficulty']}")
    return "\n".join(lines)
