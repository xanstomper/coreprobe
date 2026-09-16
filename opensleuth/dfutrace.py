"""DFU USB trace analysis + fuzz corpus - the research workbench.

Passive USB capture (dfu-usbmon.sh in the lab kit) produces raw usbmon
text. This module decodes the Apple DFU class requests, highlights
anomalies (the pattern class that produced checkm8's overflow and
usbliter8's DWC2 underflow), and builds a mutation corpus for the
dfu-fuzz harness.

DFU spec requests (USB-IF DFU 1.1, Apple DFU mode):
  DETACH=0 DETACH(0x21)  DNLOAD=1 UPLOAD=2  GETSTATUS=3  CLRSTATUS=4
  GETSTATE=5 ABORT=6     bmRequestType: 0x21 host->dev, 0xA1 dev->host
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path
from typing import Any

REQ_NAMES = {0: "DETACH", 1: "DNLOAD", 2: "UPLOAD", 3: "GETSTATUS",
             4: "CLRSTATUS", 5: "GETSTATE", 6: "ABORT"}

# usbmon text lines:  f9f3a... 1234567890 S Co:1:002:0 s 21 01 0000 0000 0000 000
_LINE_RE = re.compile(
    r"^\S+\s+\d+\s+([SC])\s+(Co|Ci|Bi|Bo):(\d+):(\d+):(\d+)\s+s\s+"
    r"([0-9a-fA-F]{2})\s+([0-9a-fA-F]{2})\s+([0-9a-fA-F]{4})\s+"
    r"([0-9a-fA-F]{4})\s+([0-9a-fA-F]{4})(?:\s+(.*))?$")


def parse_usbmon_text(text: str) -> list[dict[str, Any]]:
    """Parse usbmon text capture into setup-request events."""
    events = []
    for line in text.splitlines():
        m = _LINE_RE.match(line.strip())
        if not m:
            continue
        typ, kind, bus, dev, ep, bmrt, breq, wval, widx, wlen, data = m.groups()
        events.append({
            "phase": typ,               # S submit / C complete
            "kind": kind,               # Co/Ci (control in/out)
            "bus": int(bus), "dev": int(dev), "ep": int(ep),
            "bmRequestType": int(bmrt, 16),
            "bRequest": int(breq, 16),
            "wValue": int(wval, 16),
            "wIndex": int(widx, 16),
            "wLength": int(wlen, 16),
            "data": (data or "").strip(),
        })
    return events


def analyze(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Decode + flag anomalies across the capture."""
    requests = [e for e in events if e["bRequest"] in REQ_NAMES or e["bmRequestType"] in (0x21, 0xA1)]
    decoded = [
        {**e, "req_name": REQ_NAMES.get(e["bRequest"], f"req-{e['bRequest']:#04x}")}
        for e in requests
    ]
    counts = Counter((d["req_name"], d["wLength"], d["wValue"]) for d in decoded)
    anomalies: list[str] = []
    # unusual DNLOAD lengths (not common 0x800/0x1000 chunks)
    for d in decoded:
        if d["req_name"] == "DNLOAD" and d["wLength"] not in (0, 0x100, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000):
            anomalies.append(f"unusual DNLOAD length {d['wLength']:#06x} (value {d['wValue']:#06x})")
        if d["req_name"] == "DNLOAD" and d["wLength"] > 0x8000:
            anomalies.append(f"large DNLOAD length {d['wLength']:#06x} - boundary candidate")
    # GETSTATUS storms
    gs = sum(1 for d in decoded if d["req_name"] == "GETSTATUS")
    if gs > 50:
        anomalies.append(f"GETSTATUS storm: {gs} requests - timeout/error loop signal")
    # detach zero-length
    det = sum(1 for d in decoded if d["req_name"] == "DETACH")
    if det:
        anomalies.append(f"DETACH seen {det}x - app re-entry / renumeration signal")
    # control requests to ep with odd data payload markers
    for d in decoded:
        if d["data"] and len(d["data"]) > 32:
            anomalies.append(f"long inline data ({len(d['data'])}B) on {d['req_name']}")
            break
    return {
        "events": len(events),
        "dfu_requests": len(decoded),
        "request_counts": dict(Counter(d["req_name"] for d in decoded)),
        "unique": sorted((f"{n} len={l:#06x} val={v:#06x}", c) for (n, l, v), c in counts.items()),
        "anomalies": anomalies,
    }


def build_corpus(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Distinct DFU setup requests -> fuzz corpus rows."""
    seen = set()
    rows = []
    for e in events:
        if e["bRequest"] not in REQ_NAMES and e["bmRequestType"] not in (0x21, 0xA1):
            continue
        key = (e["bmRequestType"], e["bRequest"], e["wValue"], e["wIndex"], e["wLength"])
        if key in seen:
            continue
        seen.add(key)
        rows.append({"bmRequestType": e["bmRequestType"], "bRequest": e["bRequest"],
                     "wValue": e["wValue"], "wIndex": e["wIndex"],
                     "wLength": e["wLength"],
                     "req": REQ_NAMES.get(e["bRequest"], f"0x{e['bRequest']:02x}")})
    return rows


def write_corpus(rows: list[dict[str, Any]], path: str | Path) -> int:
    path = Path(path)
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["bmRequestType", "bRequest", "wValue", "wIndex", "wLength", "req"])
        w.writeheader()
        w.writerows(rows)
    return len(rows)


def read_corpus(path: str | Path) -> list[dict[str, Any]]:
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def render(report: dict[str, Any]) -> str:
    lines = [
        f"DFU trace analysis: {report['events']} usbmon events, "
        f"{report['dfu_requests']} DFU-class requests",
        f"request mix: {report['request_counts']}",
        "",
        "anomalies:",
    ]
    if report["anomalies"]:
        lines += [f"  ! {a}" for a in report["anomalies"]]
    else:
        lines.append("  none flagged")
    lines.append("")
    lines.append("distinct requests (corpus):")
    for u, c in report["unique"][:40]:
        lines.append(f"  {c}x {u}")
    return "\n".join(lines)