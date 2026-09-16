"""Authoritative per-firmware jailbreak status map.

Sourced from theapplewiki per-version status tables (Jailbreak/26.x,
Jailbreak/18.x, Jailbreak main page) as of 2026-09-16. These reflect the
PUBLIC capability state - "no tool" cells mean no public route exists,
which is a statement of the outer capability envelope: anything newer
than the last 'yes' is not publicly jailbreakable as of the date below.

Per-version granularity matters: e.g. iOS 26.0-26.0.1 is jailbreakable
on A12/A13, 26.1 was never public, and iOS 27 (released 2026-09-15)
has zero public routes.
"""

from __future__ import annotations

# (major, minor) -> tools dict of chip-class -> tool name
# chip-class keys match the catalog's naming so exposure() can reuse this.
STATUS_26: dict[str, dict[str, str]] = {
    "26.0":   {"A12/A13": "Dopamine 3.0.9", "arm64-A8A11": "Dopamine 3.0.9",
               "A14-A17 Pro": "—", "A18+": "—"},
    "26.0.1": {"A12/A13": "Dopamine 3.0.9", "arm64-A8A11": "Dopamine 3.0.9",
               "A14-A17 Pro": "—", "A18+": "—"},
    "26.1":   {"A12/A13": "—", "arm64-A8A11": "—", "A14-A17 Pro": "—", "A18+": "—"},
}
# all 26.2-26.6.2 rows are "No Tool Available" for every device - collapse
for _v in ("26.2", "26.2.1", "26.3", "26.3.1", "26.4", "26.4.1", "26.4.2",
           "26.5", "26.5.1", "26.5.2", "26.6", "26.6.1", "26.6.2"):
    STATUS_26[_v] = {k: "—" for k in ("A12/A13", "arm64-A8A11", "A14-A17 Pro", "A18+")}

STATUS_27: dict[str, str] = {}  # iOS 27.0 (2026-09-15): no public tool for any device
STATUS_27["27.0"] = "No public jailbreak (wiki: 'No Jailbreak tool' for every device)"

# iPadOS 26 map (A12/A13 iPads mirror iOS 26 rows; A10 iPad 7 = palera1n)
STATUS_26_IPADOS: dict[str, dict[str, str]] = {
    "26.0":   {"A12 (iPad 8/mini5/Air3)": "Dopamine 3.0.9", "A10 (iPad 7)": "—",
               "A13 (iPad 9)": "Dopamine 3.0.9", "A14+": "—"},
    "26.0.1": {"A12 (iPad 8/mini5/Air3)": "Dopamine 3.0.9", "A10 (iPad 7)": "—",
               "A13 (iPad 9)": "Dopamine 3.0.9", "A14+": "—"},
}
for _v in ("26.1", "26.2", "26.2.1", "26.3", "26.3.1", "26.4", "26.4.1",
           "26.4.2", "26.5", "26.5.2", "26.6", "26.6.1", "26.6.2"):
    STATUS_26_IPADOS[_v] = {k: "—" for k in ("A12 (iPad 8/mini5/Air3)", "A10 (iPad 7)",
                                             "A13 (iPad 9)", "A14+")}

# tvOS 26 + bridgeOS (palera1n 3.0 beta 2)
STATUS_TVOS_26: dict[str, str] = {
    v: "palera1n 3.0 beta 2 (Apple TV HD/4K)"
    for v in ("26.0", "26.0.1", "26.1", "26.2", "26.3", "26.4", "26.5", "26.6")
}
STATUS_BRIDGEOS: dict[str, str] = {
    v: "palera1n 3.0 beta 2 (T2 iBridge)"
    for v in ("10.0", "10.1", "10.2", "10.3", "10.4", "10.5", "10.6")
}


def render_26(ipados: bool = False, ios: str = "") -> str:
    table = STATUS_26_IPADOS if ipados else STATUS_26
    out = ["iOS 26.x public jailbreak status (theapplewiki, 2026-09-16)"]
    out.append("=" * 64)
    if ios:
        if ios in table:
            out.append(f"iOS {ios}:")
            for k, v in table[ios].items():
                out.append(f"  {k:<14} {v}")
            return "\n".join(out)
        out.append(f"iOS {ios}: not in public table (no route recorded)")
        return "\n".join(out)
    header = ("version".ljust(10) + " | ".join(table["26.0"].keys()))
    out.append(header)
    out.append("-" * len(header))
    for v in ("26.0", "26.0.1", "26.1", "26.2", "26.3", "26.4", "26.5", "26.6",
              "26.6.1", "26.6.2"):
        row = table.get(v)
        if not row:
            continue
        cells = " | ".join(v for v in row.values())
        out.append(f"{v:<10} {cells}")
    out.append("")
    out.append("notes: 26.0-26.0.1 only; nothing public 26.1+. iOS 27 (2026-09-15):")
    out.append("       zero public routes across all chips.")
    return "\n".join(out)


def render_27() -> str:
    out = ["iOS 27 (released 2026-09-15): NO public jailbreak for any device",
           "=" * 64]
    for k, v in STATUS_27.items():
        out.append(f"  {k:<6} {v}")
    out.append("")
    out.append("All 126 iOS 27 CVEs patched; exposure report for <27 devices")
    out.append("lists the acquisition-relevant subset (keychain, kernel, sandbox).")
    return "\n".join(out)


def render_all() -> str:
    full = render_26()
    # full table already carries its own title+rule; reuse the rest
    body = "\n".join(full.splitlines()[2:])
    ipados = render_26(ipados=True)
    ipados_body = "\n".join(ipados.splitlines()[2:])
    return "\n".join([
        render_26(), "", ipados_body, "", render_27(), "",
        "tvOS 26.0-26.6: " + STATUS_TVOS_26["26.6"],
        "bridgeOS 10.0-10.6: " + STATUS_BRIDGEOS["10.6"],
    ])
