"""GID key registry — honest per-chip status.

The GID (Group ID) key decrypts SEP firmware payloads. Public GID keys
exist only for the pre-A11 era (published in libgrabkernel-era research).
A12+ GID keys are NOT public anywhere; extracting one requires the
hardware-level pwn (checkm8 A7-A11, usbliter8/RP2350 A12/A13). This
registry tracks status per chip and stores locally-captured keys WITHOUT
fabricating hex values.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# status: public = key published in research; device = must extract from
# your own pwned device; none = nothing public, no extraction path yet
GID_STATUS: list[dict[str, Any]] = [
    {"chip": "A7",   "status": "public", "source": "libgrabkernel-era research"},
    {"chip": "A8",   "status": "public", "source": "libgrabkernel-era research"},
    {"chip": "A9",   "status": "public", "source": "XDV/axi0mX-era tooling"},
    {"chip": "A10",  "status": "public", "source": "PongoOS/Blackbird SEP era"},
    {"chip": "A11",  "status": "public", "source": "checkm8-era research"},
    {"chip": "A12",  "status": "device", "source": "usbliter8 (RP2350) pwn -> gaster-style key dump"},
    {"chip": "A13",  "status": "device", "source": "usbliter8 (RP2350) pwn -> gaster-style key dump"},
    {"chip": "A14",  "status": "none",   "source": "no public pwn; no extraction path"},
    {"chip": "A15",  "status": "none",   "source": "no public pwn; no extraction path"},
    {"chip": "A16",  "status": "none",   "source": "no public pwn; no extraction path"},
    {"chip": "A17PRO", "status": "none", "source": "no public pwn; no extraction path"},
    {"chip": "A18+", "status": "none",   "source": "no public pwn; no extraction path"},
]

KEY_STORE = Path.home() / ".coreprobe" / "gid-keys.json"


def status(chip: str = "") -> list[dict[str, Any]]:
    rows = GID_STATUS
    if chip:
        rows = [r for r in rows if r["chip"].upper() == chip.upper()]
    return rows


def register_key(chip: str, key_file: str | Path) -> dict[str, Any]:
    """Store a key captured from a pwned device into the local registry."""
    p = Path(key_file)
    data = p.read_bytes()
    keys = {}
    if KEY_STORE.exists():
        try:
            keys = json.loads(KEY_STORE.read_text())
        except (json.JSONDecodeError, OSError):
            keys = {}
    keys[chip.upper()] = {"source": str(p), "len": len(data),
                          "sha256": __import__("hashlib").sha256(data).hexdigest()[:16]}
    KEY_STORE.parent.mkdir(parents=True, exist_ok=True)
    KEY_STORE.write_text(json.dumps(keys, indent=2))
    return {"registered": chip.upper(), "stored": str(KEY_STORE),
            "record": keys[chip.upper()]}


def render(rows: list[dict[str, Any]], local: dict[str, Any] | None = None) -> str:
    lines = ["GID key registry (honest):", ""]
    for r in rows:
        mark = {"public": "PUBLIC", "device": "from-your-device",
                "none": "NONE"}.get(r["status"], r["status"])
        lines.append(f"  {r['chip']:<8} [{mark:<16}] {r['source']}")
    if local:
        lines.append("")
        lines.append("locally captured keys:")
        for chip, rec in local.items():
            lines.append(f"  {chip:<8} {rec['source']} ({rec['len']}B sha {rec['sha256']})")
    lines += ["", "honest note: no A12+ GID key is public anywhere. The Pico 2",
              "is not a convenience - it is the only open extraction path.",
              "capture one from your own pwned device: sepos decrypt --gid-key"]
    return "\n".join(lines)
