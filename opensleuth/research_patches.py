"""Public research patch catalog - documented patch classes used by open
jailbreak research. NOT working exploits on their own: these are the
documented modification points that research chains build on, for lawful
research devices.

Each entry cites the public lineage where the patch is documented.
"""

from __future__ import annotations

from typing import Any

PATCHES: list[dict[str, Any]] = [
    {"name": "AMFI bypass (amfid)", "target": "kernel/userspace",
     "lineage": "unc0ver/Electra-era amfid patches",
     "effect": "allows unsigned code execution on research devices",
     "conf": "high", "note": "signature-check bypass; research devices only"},
    {"name": "KTRR/RO kernel text wipe (tfp0/krw)", "target": "kernel",
     "lineage": "checkra1n/palera1n kernel patches",
     "effect": "writes to kernel text region after KTRR strip",
     "conf": "high", "note": "not possible on A12+ without a kernel r/w primitive first"},
    {"name": "iBoot signature check NOP", "target": "iboot",
     "lineage": "gaster/iBSS patching, checkm8 flows",
     "effect": "boot custom iBSS/iBEC during pwned DFU",
     "conf": "high", "note": "requires pwned DFU (checkm8/usbliter8)"},
    {"name": "TZ0/SPTM policy bypass", "target": "sptm",
     "lineage": "usbliter8ra1n trustzone patches",
     "effect": "disable TXM/SPTM policy enforcement on A12/A13 research boots",
     "conf": "med", "note": "published in the usbliter8ra1n boot chain"},
    {"name": "SEP keybag ops via PongoOS (Blackbird)", "target": "sep",
     "lineage": "PongoOS sep pwn / sep decrypt",
     "effect": "SEP AES with GID/UID keys + keybag ops on A10/T2",
     "conf": "high", "note": "the public SEP-keybag path; SEPROM race"},
    {"name": "AMFI trustcache injection", "target": "kernel/userspace",
     "lineage": "jailbreak trustcache flows",
     "effect": "whitelist custom CD hashes via trustcache (see opensleuth trustcache)",
     "conf": "high", "note": "pairs with the trustcache builder"},
]

TARGETS = sorted({p["target"] for p in PATCHES})


def render_list(target: str = "") -> str:
    rows = [p for p in PATCHES if not target or p["target"] == target]
    lines = [f"public research patch catalog: {len(rows)} entries "
             f"(filter: {target or 'all'})", ""]
    for p in rows:
        lines.append(f"{p['name']}  [{p['target']}]  conf={p['conf']}")
        lines.append(f"    effect: {p['effect']}")
        lines.append(f"    source: {p['lineage']}")
        if p.get("note"):
            lines.append(f"    note  : {p['note']}")
        lines.append("")
    lines.append("These are documented modification points for research")
    lines.append("devices you hold authority over - not packaged exploits.")
    return "\n".join(lines)
