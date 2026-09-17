"""DFU request mutation fuzzer - drives the corpus into a real device.

This is the original-research path: take the capture corpus, mutate the
control-transfer fields, send through a transport, and watch for device
death/hang/renumeration - the observable signals that precede the
checkm8/usbliter8-class bugs.

Transport is injected so tests run without hardware:
  transport.ctrl_transfer(bmRequestType, bRequest, wValue, wIndex,
                          wLength, timeout) -> bytes
  transport.alive() -> bool   (device still present)
"""

from __future__ import annotations

import random
from typing import Any, Callable

BOUNDARY_LENGTHS = [0, 1, 2, 3, 0x40, 0x100, 0x400, 0x800, 0x1000, 0x2000,
                    0x4000, 0x7FFF, 0x8000, 0xFFFF]
BOUNDARY_VALUES = [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF]


def mutation_variants(base: dict[str, Any], seed: int) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    out = []
    for bl in BOUNDARY_LENGTHS:
        b = dict(base)
        b["wLength"] = bl
        out.append(b)
    for vv in BOUNDARY_VALUES:
        b = dict(base)
        b["wValue"] = vv
        out.append(b)
    # random bit flips
    for _ in range(8):
        b = dict(base)
        field = rng.choice(["wValue", "wIndex", "wLength", "bRequest"])
        b[field] = b[field] ^ (1 << rng.randrange(16))
        out.append(b)
    return out


class Death:
    """A device that stopped responding = crash candidate (the signal)."""


# ---------------------------------------------------------------------------
# Sequence-aware fuzzing. checkm8/usbliter8-class bugs live in *sequences*
# of DFU requests (state-machine confusion), not single spray mutations.
# Each template is a canonical DFU flow; a run mutates ONE step of the
# flow and keeps the rest real, so a kill is attributable to the step
# that caused it.
# ---------------------------------------------------------------------------

def canonical_sequences() -> list[list[dict[str, Any]]]:
    """Standard DFU 1.1 protocol flows (modern-device shapes)."""
    def step(bm, b, wv=0, wi=0, wl=0, name=""):
        return {"bmRequestType": bm, "bRequest": b, "wValue": wv,
                "wIndex": wi, "wLength": wl, "req": name}

    dnload = lambda blk, ln: step(0x21, 0x01, blk, 0, ln, "DNLOAD")
    gstatus = step(0xA1, 0x03, 0, 0, 6, "GETSTATUS")
    gstate = step(0xA1, 0x05, 0, 0, 1, "GETSTATE")
    clr = step(0x21, 0x04, 0, 0, 0, "CLRSTATUS")
    abort = step(0x21, 0x06, 0, 0, 0, "ABORT")
    upload = lambda blk, ln: step(0xA1, 0x02, blk, 0, ln, "UPLOAD")
    detach = step(0x21, 0x00, 0, 0, 0, "DETACH")

    return [
        # firmware download: the checkm8 SHAtter-adjacent flow
        [dnload(0, 0x20), gstatus, dnload(1, 0x20), gstatus, dnload(2, 0x20),
         gstatus],
        # long download (heap growth)
        [dnload(0, 0x1000), gstatus, dnload(1, 0x1000), gstatus,
         dnload(2, 0x1000), gstatus],
        # upload + status poll
        [upload(0, 0x800), gstatus, upload(1, 0x800), gstatus],
        # state confusion: UPLOAD before any DNLOAD, ABORT mid-flow
        [upload(0, 0x100), gstatus, abort, gstatus],
        [dnload(0, 0x20), abort, dnload(1, 0x20), gstatus],
        # status/state churn
        [gstatus, gstate, clr, gstatus],
        # detach into app (observe re-umeration)
        [detach, gstatus],
    ]


def mutate_sequence(seq: list[dict[str, Any]], step_idx: int,
                    seed: int) -> list[dict[str, Any]]:
    """Clone a canonical sequence with ONE step mutated (boundaries +
    bit flips). Returns the mutated flow; the mutated step is tagged
    with 'mutated': True so kills are attributable."""
    out = [dict(s) for s in seq]
    base = out[step_idx]
    variants = mutation_variants(base, seed)
    rng = random.Random(seed)
    v = dict(rng.choice(variants))
    v["bmRequestType"] = base["bmRequestType"]
    v["bRequest"] = base["bRequest"]
    if "req" not in v:
        v["req"] = base.get("req", f"0x{v['bRequest']:02x}")
    v["mutated"] = True
    out[step_idx] = v
    return out


def run_sequence_fuzz(transport: Any, iterations: int = 200,
                      seed: int = 1337,
                      log: Callable[[str], None] = print,
                      timeout_ms: int = 500,
                      resume_wait_s: float = 0.0,
                      on_death: Callable[[dict[str, Any]], None] | None = None,
                      ) -> dict[str, Any]:
    """Sequence-aware fuzz run with death forensics and optional resume.

    Each iteration: pick a canonical flow, mutate exactly one step, run
    the flow step-by-step, check alive() after every step. On death the
    killing request is recorded (seq + step + variant). With
    resume_wait_s > 0 the caller's on_death hook should block until the
    device is re-entered in DFU; the run then continues, so a hunt can
    survive many deaths unattended.
    """
    rng = random.Random(seed)
    seqs = canonical_sequences()
    sent = 0
    crashes = 0
    hangups = 0
    kills: list[dict[str, Any]] = []
    interesting: list[dict[str, Any]] = []
    stop = False
    for i in range(iterations):
        if not transport.alive():
            crashes += 1
            log(f"[death] device gone before iteration {i}")
            if resume_wait_s > 0:
                log(f"[resume] waiting up to {resume_wait_s}s for DFU re-entry")
                if on_death:
                    on_death({})
                if not transport.alive():
                    log("[resume] no device after wait; stopping")
                    break
            else:
                break
        seq = list(rng.choice(seqs))
        step_idx = rng.randrange(len(seq))
        flow = mutate_sequence(seq, step_idx, seed + i)
        for si, r in enumerate(flow):
            try:
                resp = transport.ctrl_transfer(
                    r["bmRequestType"], r["bRequest"], r.get("wValue", 0),
                    r.get("wIndex", 0), r.get("wLength", 0), timeout_ms)
                sent += 1
                if (isinstance(resp, (bytes, bytearray)) and resp
                        and resp != b"\x00"):
                    interesting.append({**r, "resp_len": len(resp),
                                        "seq_step": si})
            except Exception as exc:  # noqa: BLE001
                if str(exc).lower().find("timeout") >= 0:
                    hangups += 1
                    log(f"[hang] {r.get('req')} step{si} len"
                        f"{r.get('wLength', 0):#06x}")
                elif not transport.alive():
                    crashes += 1
                    kill = {"iteration": i, "seq_step": si,
                            "req": r.get("req"), "bmRequestType": r["bmRequestType"],
                            "bRequest": r["bRequest"], "wValue": r.get("wValue"),
                            "wIndex": r.get("wIndex"), "wLength": r.get("wLength"),
                            "mutated": bool(r.get("mutated")), "error": str(exc)}
                    kills.append(kill)
                    log(f"[DEATH] seq step{si} "
                        f"{kill['req']} bm{kill['bmRequestType']:#04x} "
                        f"b{kill['bRequest']:#04x} len{kill['wLength']:#06x} "
                        f"mutated={kill['mutated']}")
                    if resume_wait_s > 0 and on_death:
                        log(f"[resume] waiting up to {resume_wait_s}s for re-entry")
                        on_death(kill)
                        if not transport.alive():
                            log("[resume] no device after wait; stopping")
                            stop = True
                    else:
                        stop = True  # resume disabled: one death ends run
                    break
                else:
                    log(f"[stall] {r.get('req')} step{si} -> {exc}")
        if stop:
            break
    return {"sent": sent, "crashes": crashes, "hangups": hangups,
            "kills": kills, "interesting": interesting}


def run_fuzz(transport: Any, corpus: list[dict[str, Any]],
             iterations: int = 200, seed: int = 1337,
             log: Callable[[str], None] = print,
             timeout_ms: int = 500) -> dict[str, Any]:
    rng = random.Random(seed)
    sent = 0
    crashes = 0
    hangups = 0
    interesting: list[dict[str, Any]] = []
    for i in range(iterations):
        if not transport.alive():
            crashes += 1
            log(f"[death] device gone after {sent} sends")
            break
        base = corpus[rng.randrange(len(corpus))]
        variant = mutation_variants(base, seed + i)[rng.randrange(
            len(mutation_variants(base, seed + i)))]
        variant["bmRequestType"] = base["bmRequestType"]
        variant["bRequest"] = base["bRequest"]
        try:
            resp = transport.ctrl_transfer(
                variant["bmRequestType"], variant["bRequest"],
                variant.get("wValue", 0), variant.get("wIndex", 0),
                variant.get("wLength", 0), timeout_ms)
            sent += 1
            if isinstance(resp, (bytes, bytearray)) and resp and resp != b"\x00":
                interesting.append({**variant, "resp_len": len(resp)})
        except Exception as exc:  # noqa: BLE001
            # timeout / stall are normal; device death is not (it raises on
            # next alive() because enumerate fails)
            if str(exc).lower().find("timeout") >= 0:
                hangups += 1
            elif not transport.alive():
                crashes += 1
                log(f"[death] exception '{exc}' after {sent} sends")
                break
            else:
                log(f"[stall] {variant['req']} bm{base['bmRequestType']:#04x} "
                    f"b{base['bRequest']:#04x} len{variant['wLength']:#06x} -> {exc}")
    return {"sent": sent, "crashes": crashes, "hangups": hangups,
            "interesting": interesting}
