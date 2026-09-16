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
