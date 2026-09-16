"""BFU passcode attack model — path 2 (accelerated guessing research).

This module MODELS the A12+ passcode attack surface honestly: it
computes realistic keyspaces, SEP-enforced attempt budgets, and
escalating-delay timelines so researchers can see exactly what any
brute-force approach must defeat. It does NOT bypass the counter —
that enforcement lives in SEPOS and is the research target.

iOS attempt policy (public knowledge / Apple platform security guide):
  - 6 wrong attempts: 1 min delay
  - 7: 5 min | 8: 15 min | 9: 1 hour | 10: until re-enable w/ device wipe risk
  - 10th wrong (opt-in "Erase Data" off default): 1 hour then increments
  - 4-digit PIN: 10,000 space; 6-digit: 1,000,000; alphanumeric: huge
GrayKey-class tools historically: per-attempt ISP speedups + counter
bugs on specific SEPOS builds. Those bugs are the research targets,
found via the SEPOS analyzer diff flow.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# (attempts_used, delay_seconds) per Apple documentation
DELAY_TABLE = [
    (1, 0), (2, 0), (3, 0), (4, 0), (5, 0),
    (6, 60),           # 1 min
    (7, 300),          # 5 min
    (8, 900),          # 15 min
    (9, 3600),         # 1 hour
]
MAX_DELAY = 3600


@dataclass
class PasscodeSpace:
    kind: str
    size: int
    entropy_bits: float

SPACES: dict[str, PasscodeSpace] = {
    "4-digit": PasscodeSpace("4-digit", 10_000, 13.3),
    "6-digit": PasscodeSpace("6-digit", 1_000_000, 19.9),
    "custom-numeric-8": PasscodeSpace("custom-numeric-8", 100_000_000, 26.6),
    "alphanumeric-6": PasscodeSpace("alphanumeric-6", 62 ** 6, 35.7),
}


def delay_after(wrong_attempts: int) -> int:
    d = 0
    for threshold, delay in DELAY_TABLE:
        if wrong_attempts >= threshold:
            d = delay
    return d


def attempts_per_day(starting_attempts: int = 0, days: int = 1,
                     per_attempt_seconds: float = 0.0) -> int:
    """Model cumulative attempts under stock escalating delays.

    per_attempt_seconds: host-side entry time if simulating human/USB
    entry (0 for pure policy modeling).
    """
    import time as _t  # noqa: F401
    total = 0
    attempts = starting_attempts
    budget = days * 86400.0
    while budget > 0:
        cost = per_attempt_seconds + delay_after(attempts + 1)
        if cost > budget:
            break
        budget -= cost
        attempts += 1
        total += 1
        if attempts > 500:  # policy cap for model sanity
            break
    return total


@dataclass
class AttackModel:
    space: str
    keyspace: int
    attempts_budget: int
    coverage: float          # fraction of keyspace reachable
    wall_clock_days: float
    verdict: str


def model(space: str, days: int = 30, per_attempt_seconds: float = 0.0) -> AttackModel:
    sp = SPACES.get(space)
    if sp is None:
        raise ValueError(f"unknown passcode space: {space}")
    budget = attempts_per_day(days=days, per_attempt_seconds=per_attempt_seconds)
    coverage = min(1.0, budget / sp.size)
    if coverage >= 0.99:
        verdict = "feasible under stock policy (weak passcode)"
    elif coverage >= 0.01:
        verdict = "partial — depends on luck; counter research needed"
    else:
        verdict = "infeasible — requires counter bypass (SEP research)"
    return AttackModel(space, sp.size, budget, coverage, float(days), verdict)


def research_targets() -> list[dict[str, Any]]:
    """What a counter bypass actually needs to break, honestly listed."""
    return [
        {"target": "SEPOS attempt-counter persistence",
         "why": "counter must survive reboot/DFU; any reset path = the bug",
         "approach": "diff counter-handling code across SEPOS builds (sepos.py diff_builds)"},
        {"target": "SEP mailbox request validation",
         "why": "AP->SEP requests (AppleSEPKeyStore) parse attacker data",
         "approach": "kernel r/w (AFU) + fuzz the driver surface; watch SEP panics"},
        {"target": "escalating-delay enforcement path",
         "why": "delay may be enforced in SEP scheduler code reachable via panic states",
         "approach": "power-state transitions mid-delay; FI timing (path 3)"},
        {"target": "effaceable storage (NOR) counter region",
         "why": "counter lives in effaceable storage; write-gating bugs matter",
         "approach": "hardware access during boot; NOR dump tooling"},
    ]


def render(m: AttackModel) -> str:
    return (f"passcode attack model: {m.space}\n"
            f"  keyspace        : {m.keyspace:,}\n"
            f"  policy budget   : {m.attempts_budget:,} attempts in {m.wall_clock_days:.0f} days"
            f" (stock escalating delays)\n"
            f"  coverage        : {m.coverage:.2%} of keyspace\n"
            f"  verdict         : {m.verdict}")


def render_targets() -> str:
    lines = ["counter-bypass research targets (what must actually break):"]
    for t in research_targets():
        lines.append(f"  * {t['target']}")
        lines.append(f"      why    : {t['why']}")
        lines.append(f"      approach: {t['approach']}")
    lines.append("")
    lines.append("honest note: no public counter bypass exists for A12+;")
    lines.append("GrayKey-class tools use unpublished SEP bugs. This model")
    lines.append("shows the gap to close, not a way around it.")
    return "\n".join(lines)
