import os
"""Command line interface for opensleuth."""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import __version__
from .backup import Backup, BackupError
from .artifacts import sms, contacts, calls, safari, plists, keychain, voicemail, notes
from .matrix import chip_for, recommend, render, KNOWN_DEVICES, PROFILES
from .report import build_report


# ------------------------------------------------------------ acquisition
def _run(cmd, **kw):
    print("+", " ".join(map(str, cmd)))
    return subprocess.run(list(map(str, cmd)), check=True, **kw)


def _no_device_exit(tool: str) -> None:
    """Clean examiner-facing exit when a libimobiledevice tool reports
    no device (exit 255 / ifuse exit 1) instead of a raw traceback."""
    sys.exit(
        f"no Apple device detected on USB ({tool} failed). Plug the iPhone in, "
        "unlock it, tap 'Trust' if prompted, then rerun this command. "
        "(BFU note: services are gated until first unlock.)"
    )


def cmd_acquire_backup(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    cmd = ["idevicebackup2"]
    if args.udid:
        cmd += ["-u", args.udid]
    cmd += ["backup", str(out)]
    try:
        _run(cmd)
    except FileNotFoundError:
        sys.exit("idevicebackup2 not found (install libimobiledevice-utils)")
    except subprocess.CalledProcessError:
        _no_device_exit("idevicebackup2")
    print(f"backup written to {out}")


def cmd_acquire_media(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    mnt = Path(tempfile.mkdtemp(prefix="sleuth-mnt-"))
    try:
        _run(["ifuse"] + (["-u", args.udid] if args.udid else []) + [str(mnt)])
    except FileNotFoundError:
        sys.exit("ifuse not found (install ifuse + fuse)")
    except subprocess.CalledProcessError:
        _no_device_exit("ifuse")
    try:
        for d in ("DCIM", "Downloads", "Recordings", "Books", "Podcasts", "Voicemail"):
            src = mnt / d
            if src.exists():
                shutil.copytree(src, out / d)
                print(f"copied {d}")
    finally:
        try:
            _run(["fusermount", "-u", str(mnt)])
        except subprocess.CalledProcessError:
            pass
    print(f"media written to {out}")


def cmd_acquire_info(args):
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = _run(["ideviceinfo"] + (["-u", args.udid] if args.udid else []), capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("ideviceinfo not found (install libimobiledevice-utils)")
    except subprocess.CalledProcessError:
        _no_device_exit("ideviceinfo")
    info = {}
    for line in proc.stdout.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            info[k.strip()] = v.strip()
    out.write_text(json.dumps(info, indent=2), encoding="utf-8")
    print(f"device info written to {out}")


def cmd_acquire_apps(args):
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    apps = []
    for flag in ("-o", "list_user"):
        pass
    try:
        proc = _run(["ideviceinstaller", "-l", "-o", "list_user"], capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("ideviceinstaller not found (install libimobiledevice-utils)")
    except subprocess.CalledProcessError:
        _no_device_exit("ideviceinstaller")
    for line in proc.stdout.splitlines()[1:]:
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) >= 3:
            apps.append({"bundle_id": parts[0], "version": parts[1], "name": parts[2]})
    try:
        proc = _run(["ideviceinstaller", "-l", "-o", "list_system"], capture_output=True, text=True)
        system = 0
        for line in proc.stdout.splitlines()[1:]:
            if line.strip():
                system += 1
        sys = {"system_apps": system, "count": len(apps)}
    except subprocess.CalledProcessError:
        sys = {"system_apps": 0, "count": len(apps)}
    out.write_text(json.dumps({"apps": apps, "summary": sys}, indent=2), encoding="utf-8")
    print(f"app inventory written to {out}")


# ------------------------------------------------------------ parsing
def _extract_artifact(backup, domain, relpath, dest_dir, name):
    path = backup.get_path(domain, relpath)
    if path is None:
        return None
    dest = Path(dest_dir) / name
    shutil.copyfile(path, dest)
    return dest


def cmd_extract(args):
    """Copy app (or all) container trees from a backup to disk, mirroring layout."""
    try:
        backup = Backup(args.backup)
    except BackupError as exc:
        sys.exit(f"error: {exc}")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if args.all:
        domains = None  # every domain in the backup
    elif args.domains:
        domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    else:
        domains = ["AppDomain-%"]  # app containers only (default)
    copied = backup.extract(out, domains=domains)
    print(f"extracted {copied} files to {out}")


def _step(name, fn):
    """Run one acquisition step, log outcome, never abort the chain."""
    try:
        fn()
        print(f"[ok]   {name}")
    except FileNotFoundError as exc:
        print(f"[skip] {name}: missing tool: {exc}")
    except subprocess.CalledProcessError as exc:
        print(f"[fail] {name}: rc={exc.returncode}")
    except Exception as exc:  # noqa: BLE001
        print(f"[fail] {name}: {exc}")


def _free_space_gb(path):
    return shutil.disk_usage(path).free / 2**30


def cmd_acquire_all(args):
    """Maximum logical acquisition: every service the OS exposes to a trusted host."""
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    sub = lambda *p: out.joinpath(*p)  # noqa: E731

    # --- preflight -------------------------------------------------------
    proc = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True)
    udids = [u for u in proc.stdout.split() if u]
    if not udids:
        sys.exit(
            "no Apple device detected on USB (usbmuxd). Plug the iPhone in, unlock it,\n"
            "tap 'Trust' if prompted, then rerun this command."
        )
    print(f"device: {udids[0]}")
    free = _free_space_gb(out)
    print(f"disk free: {free:.1f} GiB" + (" (WARNING: encrypted+unencrypted backups need >= 20 GiB)" if free < 20 else ""))

    # --- device info -----------------------------------------------------
    _step("device info", lambda: cmd_acquire_info(_with_out(args, str(sub("info", "device.json")))))
    _step("mobilegestalt (all keys)", lambda: _run(["pymobiledevice3", "diagnostics", "mg"], capture_output=True) and sub("info", "gestalt.json").write_text(_run(["pymobiledevice3", "diagnostics", "mg"], capture_output=True, text=True).stdout, encoding="utf-8"))
    _step("ioregistry dump", lambda: sub("info", "ioreg.txt").write_text(_run(["pymobiledevice3", "diagnostics", "ioregistry"], capture_output=True, text=True).stdout, encoding="utf-8"))
    _step("battery snapshot", lambda: sub("info", "battery.json").write_text(_run(["pymobiledevice3", "diagnostics", "battery", "single"], capture_output=True, text=True).stdout, encoding="utf-8"))
    _step("wifi registry", lambda: sub("info", "wifi.json").write_text(_run(["pymobiledevice3", "diagnostics", "battery", "wifi"], capture_output=True, text=True).stdout, encoding="utf-8"))
    _step("process list", lambda: sub("info", "processes.json").write_text(_run(["pymobiledevice3", "processes"], capture_output=True, text=True).stdout, encoding="utf-8"))
    _step("app inventory", lambda: cmd_acquire_apps(_with_out(args, str(sub("apps.json")))))

    # --- crash + diagnostics ---------------------------------------------
    _step("crash reports", lambda: _run(["pymobiledevice3", "crash", "pull", str(sub("crash"))]))
    _step("screen orientation", lambda: sub("info", "orientation.json").write_text(_run(["pymobiledevice3", "springboard", "orientation"], capture_output=True, text=True).stdout, encoding="utf-8"))
    _step("wallpaper", lambda: _run(["pymobiledevice3", "springboard", "wallpaper-home-screen", str(sub("media", "wallpaper.png"))]))

    # --- media via AFC ----------------------------------------------------
    _step("media (DCIM/Downloads/Recordings)", lambda: cmd_acquire_media(_with_out(args, str(sub("media")))))

    # --- syslog window ----------------------------------------------------
    def _syslog():
        with open(sub("syslog.txt"), "wb") as fh:
            subprocess.run(["timeout", "30", "pymobiledevice3", "syslog"], stdout=fh, check=True)
    _step("syslog (30s capture)", _syslog)

    # --- backups -----------------------------------------------------------
    def _backup_plain():
        bdir = sub("backup")
        bdir.mkdir(exist_ok=True)
        _run(["pymobiledevice3", "backup2", "backup", str(bdir), "--full"])
    _step("full backup (unencrypted)", _backup_plain)

    if args.password:
        def _backup_enc():
            bdir = sub("backup-enc")
            bdir.mkdir(exist_ok=True)
            # --unback decrypts and unpacks via pyiosbackup (keychain included)
            _run(["pymobiledevice3", "backup2", "backup", str(bdir), "--full",
                  "--password", args.password, "--unback"])
        _step("full encrypted backup + keychain unpack", _backup_enc)

    if args.sysdiagnose:
        _step("sysdiagnose (tap Allowed on phone)",
              lambda: _run(["pymobiledevice3", "crash", "sysdiagnose", str(sub("sysdiagnose"))]))

    print("\nacquisition complete ->", out)
    print("next: opensleuth extract <backup>/<UDID> -o <appdata>   (app containers)")
    print("      opensleuth dump <backup>/<UDID> -o <report>         (artifact report)")


def _with_out(args, out):
    """Namespace copy with a new --out value (argparse Namespace lacks _replace)."""
    import argparse

    ns = argparse.Namespace(**vars(args))
    ns.out = out
    return ns


def _jb_ssh_pull(host, out):
    """Pull user data + keychain from a jailbroken device over SSH (scp/rsync).

    Use when AFC2 is unavailable. Requires openssh client + credentials
    (root SSH on iOS defaults to 'alpine' on legacy jailbreaks; keys preferred).
    """
    targets = ["/var/mobile", "/var/Keychains", "/var/wireless/Library/Preferences"]
    ok = False
    for t in targets:
        dst = out / t.lstrip("/").replace("/", "_")
        try:
            proc = subprocess.run(
                ["scp", "-r", "-o", "StrictHostKeyChecking=no", f"root@{host}:{t}", str(dst)],
                capture_output=True, text=True, timeout=600,
            )
            if proc.returncode == 0:
                print(f"[ssh] pulled {t} -> {dst}")
                ok = True
            else:
                print(f"[ssh] failed {t}: {proc.stderr.strip()[:200]}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print(f"[ssh] failed {t}: {exc}")
    if not ok:
        print("ssh pull produced nothing. Check: jailbreak SSH enabled, host reachable,")
        print("credentials (e.g. root@<device-ip>), or use the AFC2 route instead.")


def cmd_acquire_bfu(args):
    """BFU master path: everything obtainable BEFORE FIRST UNLOCK.

    Routes:
      1. USB identity  (serial, product, PID - always)
      2. usbmuxd UDID  (always)
      3. Recovery/DFU detection + iBoot env (when in those modes)
      4. checkm8 flow (A7-A11 only): pwn DFU + AES keys via gaster/ipwndfu
         when tooling is present; otherwise prints exact commands
      5. lockdown attempt (fails in BFU by design - recorded for the record)
    """
    from .usb import usb_state

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    snap = usb_state()
    usb = [d for d in snap["devices"] if d["mode"] in ("normal", "pwned")]
    rec = [d for d in snap["devices"] if "dfu" in d["mode"] or d["mode"] == "recovery"]
    res = {
        "state": "bfu",
        "usb": usb,
        "recovery_dfu": rec,
        "usb_mode_flags": {k: v for k, v in snap.items() if k != "devices"},
        "checkm8": {"eligible": False, "tool": None, "outcome": None},
    }

    # 2. usbmuxd
    try:
        proc = subprocess.run(["pymobiledevice3", "usbmux", "list"], capture_output=True, text=True, timeout=30)
        res["usbmux"] = proc.stdout.strip()
    except Exception as exc:  # noqa: BLE001
        res["usbmux"] = f"<unavailable: {exc}>"

    # 4. checkm8/usbliter8 eligibility from CLI hint or serial heuristics
    chip = (args.chip or "").upper()
    serial = (res["usb"] + res["recovery_dfu"] + [{}])[0].get("serial") or ""
    if not chip and serial:
        chip = _chip_from_serial(serial)
    if not chip:
        # booted devices show UDID-format serial; fall back to lockdown ProductType
        from .matrix import chip_for as _cf
        try:
            proc = subprocess.run(["ideviceinfo"], capture_output=True, text=True, timeout=20)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if line.startswith("ProductType:"):
                        chip = _cf(line.split(":", 1)[1].strip()) or ""
                        break
        except Exception:  # noqa: BLE001
            pass
    if not chip:
        chip = "unknown"
    res["checkm8"]["chip"] = chip
    from .matrix import CHIP_RANK, USBLITER8_CHIPS

    # usbliter8 marker (PWND:[usbliter8]) in the USB serial string
    res["usbliter8"] = {"pwnd": snap["pwnd_usbliter8"], "chip_eligible": chip in USBLITER8_CHIPS}
    eligible = chip in CHIP_RANK and CHIP_RANK[chip] <= 11
    res["checkm8"]["eligible"] = eligible
    if eligible:
        for tool in ("gaster", "ipwnder32", "ipwndfu"):
            if shutil.which(tool):
                res["checkm8"]["tool"] = tool
                break
        if res["checkm8"].get("tool"):
            mnt_state = "recovery/DFU" if res["recovery_dfu"] else "normal"
            if not res["recovery_dfu"] and not getattr(args, "force", False):
                res["checkm8"]["guidance"] = (
                    "checkm8 tooling present, but the device is NOT in recovery/DFU. "
                    "Enter DFU on the device (or pass --force to attempt anyway, "
                    "e.g. when DFU entry was already anticipated)."
                )
                print(f"[checkm8] {res['checkm8']['guidance']}")
            else:
                print(f"[checkm8] device in {mnt_state}; running {res['checkm8']['tool']} flow")
                try:
                    if res["checkm8"]["tool"] == "gaster":
                        p = subprocess.run(["gaster", "pwn"], capture_output=True, text=True, timeout=120)
                        res["checkm8"]["outcome"] = p.stdout[-400:] or p.stderr[-400:]
                        if p.returncode == 0 and shutil.which("irecovery"):
                            for env in ("serial", "ecid", "boardid", "sxpt"):
                                e = subprocess.run(["irecovery", "-q", "-c", f"getenv {env}"], capture_output=True, text=True, timeout=20)
                                res["checkm8"][f"iBoot_{env}"] = e.stdout.strip() or e.stderr.strip()
                except subprocess.TimeoutExpired:
                    res["checkm8"]["outcome"] = "timed out (is the device in DFU?)"
        else:
            res["checkm8"]["guidance"] = (
                "vulnerable chip (A7-A11) but no checkm8 tooling installed. "
                "Install: sudo apt install gaster libirecovery-utils  (or clone ipwndfu), "
                "put the device into DFU, then rerun with the device attached."
            )
    else:
        if chip == "unknown":
            res["checkm8"]["guidance"] = (
                "chip could not be auto-detected from this connection. "
                "Rerun with --chip (e.g. --chip A10) to plan the checkm8 route."
            )
        elif chip in USBLITER8_CHIPS:
            res["checkm8"]["guidance"] = (
                "chip A12/A13: not checkm8-eligible, but USBLITER8 bootrom route "
                "applies (2026-06-18, Paradigm Shift). Flow: RP2350 board + DFU -> "
                "PWND:[usbliter8] -> usbliter8ctl boot raw iBoot / demote. "
                "Ref: github.com/rav000/usbliter8 (mirror), usbliter8ra1n toolkit."
            )
            if res.get("usbliter8", {}).get("pwnd"):
                print("  !! PWND:[usbliter8] marker present - device is in usbliter8 pwned DFU")
        else:
            res["checkm8"]["guidance"] = "chip not checkm8-eligible (A12+): see usbliter8 route for A12/A13"
    # 5. lockdown attempt (expected to fail in BFU - recorded)
    try:
        p = subprocess.run(["ideviceinfo"], capture_output=True, text=True, timeout=20)
        res["lockdown"] = {"reachable": p.returncode == 0, "detail": p.stderr.strip()[:200] or "gated (BFU) or unpaired"}
    except Exception as exc:  # noqa: BLE001
        res["lockdown"] = {"reachable": False, "detail": str(exc)}

    (out / "bfu.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print("BFU acquisition written to", out / "bfu.json")
    for u in res["usb"] + res["recovery_dfu"]:
        print(f"  USB: {u['product']} serial={u['serial']} pid={u['product_id']} mode={u.get('mode', '?')}")
    if res["recovery_dfu"]:
        print("  device in Recovery/DFU - iBoot-level info may be available")
    status = f"ELIGIBLE ({res['checkm8']['tool']})" if eligible else (
        "unknown chip - pass --chip to plan" if chip == "unknown" else
        ("usbliter8 (A12/A13)" if chip in USBLITER8_CHIPS else "not applicable")
    )
    print(f"  checkm8: {status}")
    if res.get("usbliter8", {}).get("pwnd"):
        print("  usbliter8: device is PWND (pwned DFU) - bootrom control active")
    if res["checkm8"].get("guidance"):
        print("  " + res["checkm8"]["guidance"])
    if res["checkm8"].get("outcome"):
        print("  checkm8 output:", res["checkm8"]["outcome"][:300])

    # per-class expectations + optional payload-driven ramdisk extraction
    from .bfu import (render_expectations, render_usbliter8_plan,
                      render_yield_card, run_ramdisk_extract, yield_card,
                      bfu_runbook)
    chip_used = res.get("checkm8", {}).get("chip", "?")
    if getattr(args, "yield_card", False):
        from .usb import usb_state as _us
        snap = _us()
        card = yield_card(
            chip=chip_used or "?",
            ios=getattr(args, "ios", "") or "",
            device_flags={"attached": bool(snap.get("devices")),
                          "dfu": snap.get("dfu"), "recovery": snap.get("recovery"),
                          "pwnd": snap.get("pwnd")},
            tooling={"gaster": bool(shutil.which("gaster")),
                     "palera1n": bool(shutil.which("palera1n")),
                     "usbliter8ctl": bool(shutil.which("usbliter8ctl")),
                     "sshpass": bool(shutil.which("sshpass"))})
        res["yield_card"] = card
        print()
        print(render_yield_card(card))
    runbook_path = getattr(args, "runbook", None)
    if runbook_path:
        (Path(runbook_path)).write_text(bfu_runbook(chip=chip_used or "?",
                                                    ios=getattr(args, "ios", "") or "",
                                                    case_dir=str(out)))
        print("runbook written:", runbook_path)
    if getattr(args, "watch", False):
        from .usb import watch_dfu
        print()
        print("[watch] waiting for DFU entry (start the DP/vol-down sequence)...")
        snap = watch_dfu(timeout=float(getattr(args, "watch_timeout", 300)))
        res["watch"] = snap
        if snap.get("dfu"):
            print("[watch] DFU detected - pwn now")
            res["checkm8"]["tool"] = "gaster"
            try:
                p = subprocess.run(["gaster", "pwn"], capture_output=True,
                                   text=True, timeout=120)
                res["checkm8"]["outcome"] = (p.stdout or p.stderr)[-400:]
                pwnd = p.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                res["checkm8"]["outcome"] = f"pwn failed: {exc}"
                pwnd = False
            if pwnd:
                print("  pwnd - continuing chain")
                if getattr(args, "keys", False):
                    from .bfu import capture_aes_keys
                    k = capture_aes_keys(out, tool="gaster")
                    res["aes_keys"] = k
                    print("  aes keys:", "captured" if k.get("ok") else k.get("error"))
                if getattr(args, "ramdisk", None):
                    print("  [ramdisk] payload dir:", args.ramdisk)
                    r = run_ramdisk_extract(args.ramdisk, out)
                    res["ramdisk"] = r
                    print("  ramdisk:", r.get("ok"), r.get("error") or r.get("note", ""))
        else:
            print("[watch] no DFU entry within timeout; chain not started")
    route = getattr(args, "route", "").lower()
    if route == "usbliter8":
        print()
        print(render_usbliter8_plan(chip=res.get("checkm8", {}).get("chip", "?") or "?"))
    print()
    print(render_expectations(chip=res.get("checkm8", {}).get("chip", "?"),
                              ios=getattr(args, "ios", "") or ""))
    if getattr(args, "ramdisk", None):
        print()
        print("[ramdisk] payload dir:", args.ramdisk)
        r = run_ramdisk_extract(args.ramdisk, out)
        res["ramdisk"] = r
        print("  ok:", r.get("ok"))
        if r.get("error"):
            print("  error:", r["error"])
        if r.get("note"):
            print("  note:", r["note"])
        if r.get("keybags_tar"):
            print("  keybags tar:", r["keybags_tar"])

    # AES keyset capture (checkm8-pwned device)
    if getattr(args, "keys", False):
        from .bfu import capture_aes_keys
        if not res["recovery_dfu"] and not getattr(args, "force", False):
            print("[aes keys] skipped: device is not in recovery/DFU (pwn it first,"
                  " or pass --force).")
        else:
            print()
            print("[aes keys] capturing device AES keyset from the pwned device")
            k = capture_aes_keys(out, tool="gaster")
            res["aes_keys"] = k
            print("  ok:", k.get("ok"))
            if k.get("error"):
                print("  error:", k["error"])
                if k.get("hint"):
                    print("  hint:", k["hint"])
            for f in k.get("keys", []):
                print("  key file:", f)

    # keybag analysis: any kbagic files found in the output dir
    from .keybag import KeybagError, analyze, render_status as _render_kb
    bags = [f for f in out.iterdir() if f.is_file() and (
        f.suffix in (".kb", ".keybag", ".bag")
        or f.name in ("systembag.kb", "userbag.kb", "backupbag.kb"))]
    if bags:
        res["keybags"] = []
        for bf in bags:
            try:
                a = analyze(bf)
                res["keybags"].append(a)
                print()
                print(_render_kb(bf))
            except KeybagError as exc:
                print(f"  keybag parse failed for {bf}: {exc}")
    import json as _json
    (out / "bfu-report.json").write_text(_json.dumps(res, indent=2, default=str))
    print()
    print("report:", out / "bfu-report.json")


def _chip_from_serial(serial):
    """Best-effort chip guess from USB serial heuristics; empty if unknown."""
    s = serial.upper()
    if s.startswith(("C39", "C3D", "F17", "F18")):
        return "A12"
    if s.startswith(("DNP", "F2L", "C7G")):
        return "A13"
    return ""


def cmd_acquire_checkm8(args):
    """Zero-extra-hardware bootrom route for A7-A11 (checkm8) incl. the
    Blackbird SEP keybag path on A10/T2. Plain PC + USB cable + DFU mode;
    no RP2350 rig needed.

    Flow:
      1. put the device in DFU (or let --watch wait for it)
      2. gaster pwn (or ipwndfu -p) -> PWND DFU
      3. A8-A11: palera1n -> PongoOS -> ramdisk -> full FS via AFC2/SSH
      4. A10/T2: PongoOS 'sep pwn' (Blackbird) -> sep decrypt keybags
    """
    from .usb import usb_state, watch_dfu

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    from .exploits import default_recommendation

    res = {"route": "checkm8 (zero-hardware bootrom)", "chip": (args.chip or "").upper(), "pwnd": False, "tooling": {}, "steps": []}

    # 1) device on USB?
    snap = usb_state()
    usb = [{k: v for k, v in d.items() if k != "sysfs"} for d in snap["devices"]]
    res["usb"] = usb
    if not usb:
        sys.exit("no Apple device on USB. Plug it in and enter DFU first.")

    # 2) tooling inventory (install commands if missing)
    for tool, install in [
        ("gaster", "build from github.com/0x7ff/gaster: gcc -DHAVE_LIBUSB gaster.c lzfse.c -o gaster -lusb-1.0 -lcrypto (needs libusb-1.0-0-dev libssl-dev); the Makefile default targets macOS"),
        ("ipwndfu", "git clone https://github.com/axi0mX/ipwndfu (optional; gaster covers pwn)"),
        ("irecovery", "sudo apt install irecovery libirecovery-1.0-3"),
        ("palera1n", "curl -LO https://github.com/palera1n/palera1n/releases/latest/download/palera1n-linux-x86_64 && install to ~/.local/bin"),
        ("pongoos", "part of palera1n/checkra1n bundle - builds PongoOS from github.com/checkra1n/PongoOS"),
    ]:
        res["tooling"][tool] = shutil.which(tool) or f"MISSING ({install})"
    missing = [t for t, v in res["tooling"].items() if v.startswith("MISSING")]

    # 3) chip check: checkm8-eligible?
    chip = res["chip"]
    if not chip:
        serial = (usb[0].get("serial") or "").upper()
        chip = _chip_from_serial(serial) or ""
    if not chip:
        # booted devices expose UDID-format serial; ask lockdown for ProductType
        try:
            proc = subprocess.run(["ideviceinfo"], capture_output=True, text=True, timeout=20)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if line.startswith("ProductType:"):
                        from .matrix import chip_for as _cf
                        chip = _cf(line.split(":", 1)[1].strip()) or ""
                        break
        except Exception:  # noqa: BLE001
            pass
    res["chip"] = chip or (args.chip or "").upper() or "unknown"
    from .matrix import CHECKM8_CHIPS, USBLITER8_CHIPS
    if chip in CHECKM8_CHIPS:
        res["eligible"] = True
        res["recommendation"] = default_recommendation(chip)
    elif chip in USBLITER8_CHIPS:
        res["eligible"] = False
        res["recommendation"] = ["A12/A13: checkm8 does NOT apply - usbliter8 needs the RP2350 rig (see acquire usbliter8)"]
    else:
        res["eligible"] = False
        res["recommendation"] = ["chip not checkm8-eligible"]

    # 4) DFU state + pwn attempt (with optional watch for DFU entry)
    in_dfu = snap["dfu"]
    res["in_dfu"] = in_dfu
    if not in_dfu and getattr(args, "watch", False):
        print("waiting for DFU entry (press vol-up, vol-down, hold power 10s, then power+vol-down 5s)...")

        def _report(ts, entry):
            print(f"  [{ts}] USB transition: {entry.get('product') or 'device'} -> {entry['mode'].upper()}")

        snap = watch_dfu(timeout=getattr(args, "watch_timeout", 180.0), on_transition=_report)
        in_dfu = snap["dfu"]
        res["in_dfu"] = in_dfu
        res["watched"] = True
    if not in_dfu and not args.force:
        (out / "checkm8.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
        print("checkm8 preflight written to", out / "checkm8.json")
        print("Device is NOT in DFU. Enter DFU (vol-up, vol-down, hold power 10s,"
              "\nthen power+vol-down 5s) or rerun with --force once it is.")
        for t, v in res["tooling"].items():
            print(f"  {t}: {v}")
        if missing:
            print("Install missing tooling first:", "; ".join(missing))
        return

    if args.force or in_dfu:
        # try gaster first, then ipwndfu
        for tool_cmd in (["gaster", "pwn"] if shutil.which("gaster") else None,
                         [sys.executable, "-m", "ipwndfu", "-p"] if shutil.which("ipwndfu") or Path("ipwndfu/ipwndfu").exists() else None):
            if not tool_cmd:
                continue
            try:
                p = subprocess.run(tool_cmd, capture_output=True, text=True, timeout=120)
                res["pwn_output"] = (p.stdout or p.stderr)[-600:]
                # NOTE: gaster pwn BLOCKS indefinitely waiting for a DFU
                # device (wait_usb_handle loop) - with no device we hit the
                # 120s timeout instead. Belt-and-braces: even on rc==0,
                # only trust the pwn when the PWND marker shows in the USB
                # serial via the shared usb module.
                from .usb import usb_state as _usb_state
                if p.returncode == 0 and _usb_state()["pwnd"]:
                    res["pwnd"] = True
                    res["pwn_tool"] = tool_cmd[0]
                    break
                if p.returncode == 0 and not _usb_state()["any"]:
                    res["pwn_output"] = "tool exited 0 but no Apple device on USB (gaster no-op)"
            except subprocess.TimeoutExpired:
                res["pwn_output"] = "pwn timed out - is the device actually in DFU?"
            except FileNotFoundError:
                continue
        if res["pwnd"] and shutil.which("irecovery"):
            env = {}
            for e in ("serial", "ecid", "boardid", "sxpt", "iboot-version"):
                try:
                    r = subprocess.run(["irecovery", "-q", "-c", f"getenv {e}"], capture_output=True, text=True, timeout=20)
                    env[e] = (r.stdout or r.stderr).strip()
                except Exception:  # noqa: BLE001
                    pass
            res["irecovery_env"] = env

    (out / "checkm8.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print("checkm8 state written to", out / "checkm8.json")
    print(f"chip: {res['chip']}   eligible: {res.get('eligible')}   DFU: {res.get('in_dfu')}   PWND: {res.get('pwnd')}")
    if res.get("pwnd"):
        print("  device PWND - bootrom control active (checkm8).")
        print("  Next (A8-A11): palera1n -> PongoOS -> ramdisk -> acquire jailbroken --out <case>/fs")
        if chip in ("A10", "A11"):
            print("  Next (A10/T2 SEP): PongoOS 'sep pwn' -> 'sep decrypt <kbag>' (Blackbird keybag path)")
    else:
        print("  not PWND yet. Ensure DFU, install tooling, rerun.")
        for t, v in res["tooling"].items():
            if v.startswith("MISSING"):
                print(f"  {v}")


def cmd_acquire_usbliter8(args):
    """usbliter8 bootrom route for A12/A13 (first public A12/A13 bootrom exploit,
    Paradigm Shift, 2026-06-18). Pwns SecureROM over USB via an RP2350 board and
    hands control of DFU to the host: boot raw iBoot, demote production mode,
    then ramdisk/AFC flows for full filesystem extraction.

    Flow (tethered, physical):
      1. Flash usbliter8 firmware to an RP2350 board (Waveshare RP2350 USB-A,
         Pico 2, TINY2350...). UF2 images ship in the repo Releases.
      2. Put the iPhone into DFU (NOT via breaking LLB).
      3. Unplug from PC, plug into the RP2350 board, wait for the exploit
         (0.7-1.2s), LED green = PWND. Replug to the PC.
      4. USB serial now ends with `PWND:[usbliter8]` - verify with this command.
      5. Use usbliter8ctl (repo tool) to `demote` or `boot <raw-iBoot>`.

    This command verifies PWND state and records evidence; the actual
    iBoot/ramdisk chain is driven by the usbliter8 repo tooling
    (github.com/rav000/usbliter8 mirror / usbliter8ra1n toolkit).
    """
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    from .matrix import USBLITER8_CHIPS

    res = {"note": "usbliter8 bootrom route (A12/A13, 2026-06-18)", "board": args.board, "pwnd": False, "usb": [], "recovery_dfu": [], "path": "identity/DFU check"}

    # 1) find the Apple device on USB (any state)
    serials = []
    from .usb import apple_devices, usb_state

    snap = usb_state()
    for entry in apple_devices():
        clean = {k: v for k, v in entry.items() if k != "sysfs"}
        res["usb"].append(clean)
        if entry.get("serial"):
            serials.append(entry["serial"])
        if entry["mode"] in ("recovery", "dfu", "pwned-dfu"):
            res["recovery_dfu"].append(clean)

    if not res["usb"] and not res["recovery_dfu"]:
        sys.exit("no Apple device detected on USB. Plug the iPhone in (any state works for this route).")

    chip = (args.chip or "").upper()
    st = (serials + [""])[0].upper()
    if not chip:
        chip = _chip_from_serial(st)
    res["chip"] = chip or "auto-detect in DFU (serial format changes once in DFU)"

    # 2) PWND marker
    res["pwnd"] = snap["pwnd_usbliter8"]

    # 3) state report
    (out / "usbliter8.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print(f"usbliter8 state written to {out / 'usbliter8.json'}")
    for u in res["usb"]:
        print(f"  USB: {u['product']} serial={u['serial']} pid={u['product_id']} mode={u.get('mode', '?')}")
    if res["pwnd"]:
        print("  PWND:[usbliter8] CONFIRMED - device is in usbliter8 pwned DFU.")
        print("  Next: usbliter8ctl boot <raw-iBoot> / demote, then ramdisk flow.")
        if shutil.which("usbliter8ctl"):
            print("  usbliter8ctl found on PATH - run it against this device.")
        else:
            print("  usbliter8ctl not installed. Get it from the usbliter8 repo:")
            print("    git clone https://github.com/rav000/usbliter8 && cd usbliter8")
            print("    pip install pyusb && ./usbliter8ctl boot|demote ...")
    else:
        if res["recovery_dfu"]:
            print("  Device is in DFU/Recovery but NOT PWND yet.")
            print(f"  Flow: unplug from PC -> plug into RP2350 board ({args.board}) ->")
            print("        wait for green LED (~1s) -> replug to PC -> rerun this command.")
            if args.fw:
                print(f"  (verify the board is flashed: {args.fw})")
            else:
                print("  Board firmware: flash the matching UF2 from the usbliter8 Releases")
                print("  (https://github.com/rav000/usbliter8/releases) for", args.board)
        else:
            print("  Device is in normal (booted) state - bootrom route needs DFU.")
            print("  Put it in DFU first (volume-up, volume-down, hold power until")
            print("  recovery, then power+volume-down for DFU), then run this command.")
    if chip and chip not in USBLITER8_CHIPS:
        print("  NOTE: chip is", chip, "- usbliter8 covers A12/A13 only.")


def cmd_acquire_afu(args):
    """AFU master path: every extraction route available after first unlock."""
    print("AFU master acquisition: running the full logical suite")
    cmd_acquire_all(args)


def cmd_acquire_target(args):
    """One-command profile for a specific device (e.g. iPhone 11, iOS 11-era)."""
    from .matrix import profile_info

    key, prof = profile_info(args.name)
    if not prof:
        sys.exit(f"unknown target '{args.name}'. Available: {', '.join(sorted(PROFILES))}")
    print(f"== target: {prof['name']} (chip {prof['chip']}) ==")
    print(f"  BFU: {prof['bfu']}")
    print(f"  AFU: {prof['afu']}")

    # verify a connected device matches the profile
    matched = None
    try:
        proc = subprocess.run(["ideviceinfo"], capture_output=True, text=True, timeout=25)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if line.startswith("ProductType:"):
                    matched = line.split(":", 1)[1].strip()
                    break
    except Exception:  # noqa: BLE001
        pass
    if matched:
        ok = matched in prof["models"]
        print(f"  connected device: {matched} ({KNOWN_DEVICES.get(matched, ('unknown',))[0]}) "
              f"{'<-- matches target' if ok else '<-- DOES NOT match this target'}")
        if ok and args.run:
            print("  running AFU suite for this device...")
            cmd_acquire_all(args)
    else:
        print("  no device connected right now. Plug the target in, unlock it,")
        print("  and rerun with --run to execute the AFU suite.")


def cmd_matrix(args):
    """Print the public extraction capability matrix for a chip/iOS combo."""
    chip = args.chip.upper()
    print(render(chip, args.ios, product_version=args.ios))


def cmd_silicon(args):
    """Print the public silicon-level (bootrom/SEP) exploit envelope.

    The niche catalog: every PUBLIC exploit that lives below iOS - checkm8
    (A7-A11), Blackbird SEPROM (A10/T2, limited A11), usbliter8 (A12/A13,
    2026-06-18 Paradigm Shift). Commercial tools (Cellebrite/Elcomsoft)
    sell exactly this capability; CoreProbe publishes it openly.
    """
    from .silicon import render as silicon_render

    trace_f = getattr(args, "trace", None)
    if trace_f:
        from .dfutrace import analyze, build_corpus, parse_usbmon_text
        from .dfutrace import render as trace_render
        from .dfutrace import write_corpus
        events = parse_usbmon_text(Path(trace_f).read_text(errors="replace"))
        print(trace_render(analyze(events)))
        corpus_out = getattr(args, "corpus", None)
        if corpus_out:
            n = write_corpus(build_corpus(events), corpus_out)
            print(f"corpus: {n} requests -> {corpus_out}")
        return
    nb_dir = getattr(args, "notebook", None)
    if nb_dir:
        from .silicon import notebook, render_notebook
        nb = notebook(nb_dir, note=getattr(args, "note", "") or None)
        print(render_notebook(nb))
        return
    lab_dir = getattr(args, "lab", None)
    if lab_dir:
        from .silicon import lab_kit, render_lab
        print(render_lab(lab_kit(lab_dir, chip=getattr(args, "chip", "") or "A13")))
        return
    print(silicon_render(getattr(args, "chip", "") or args.chip,
                         detailed=getattr(args, "detailed", False)))


def cmd_exploits(args):
    """Print the complete public exploit inventory with hardware needs.

    Distinguishes routes that run on a plain PC + USB cable (no extra
    hardware: checkm8, Blackbird, palera1n) from ones needing a device app
    (kernel/userspace jailbreaks) or a special rig (usbliter8 + RP2350).
    """
    from .exploits import render as exploits_render

    print(exploits_render(
        getattr(args, "chip", ""),
        no_hardware_only=bool(getattr(args, "no_hardware", False)),
        layer=getattr(args, "layer", ""),
        detailed=bool(getattr(args, "detailed", False)),
    ))


def cmd_research(args):
    """Run the public iOS research pipeline: fetch Apple security releases,
    flag new CVEs relevant to acquisition, keep incremental state.

    Folds PUBLIC disclosures into CoreProbe's knowledge the moment they
    land (usbliter8, MobileBackup traversal, kernel primitives, etc).
    """
    from .research import DEFAULT_STATE_PATH, run, render

    state_path = Path(getattr(args, "state") or DEFAULT_STATE_PATH)
    summary = run(state_path=state_path, timeout=getattr(args, "timeout", 30))
    print(render(summary, detailed=bool(getattr(args, "detailed", False))))


def cmd_exposure(args):
    """Print every public route + recent CVE disclosure that applies to a
    specific chip + iOS build (auto-detect from connected device unless
    --chip/--ios are given)."""
    from .exploits import render_exposure
    from .matrix import chip_for as _cf

    chip = (getattr(args, "chip") or "").upper()
    ios = getattr(args, "ios", "")
    if not chip or not ios:
        try:
            proc = subprocess.run(["ideviceinfo"], capture_output=True, text=True, timeout=25)
            info = {}
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        info[k.strip()] = v.strip()
            device_class = info.get("ProductType", "")
            ios = ios or info.get("ProductVersion", "")
            chip = chip or (_cf(device_class) or "")
        except Exception:  # noqa: BLE001
            pass
    if not chip or not ios:
        sys.exit("could not determine device (need it connected+paired, or pass --chip/--ios)")
    print(render_exposure(chip, ios, detailed=bool(getattr(args, "detailed", False))))


def cmd_versions(args):
    """Authoritative public jailbreak status per firmware version."""
    from .versions import render_26, render_27, render_all

    if getattr(args, "ipados", False):
        print(render_26(ipados=True, ios=args.ios or ""))
        return
    if args.ios:
        v = args.ios.strip()
        if v.startswith("27"):
            print(render_27())
            return
        if v.startswith("26"):
            print(render_26(ios=v))
            return
        print(f"per-version table available for iOS 26/27 (got {v!r}); "
              "run `opensleuth versions` for the full view")
        return
    print(render_all())


def cmd_plan(args):
    """Probe a connected device and output the recommended extraction path."""
    # reuse probe internals inline (device must be AFU+paired for full data)
    raw = []
    try:
        proc = subprocess.run(["ideviceinfo"], capture_output=True, text=True, timeout=25)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    raw.append((k.strip(), v.strip()))
        else:
            sys.exit("device not reachable at lockdown level (BFU or unpaired). "
                     "In BFU no version/chip data is exposed; one unlock restores planning.")
    except FileNotFoundError:
        sys.exit("ideviceinfo not found (install libimobiledevice-utils)")
    info = dict(raw)
    device_class = info.get("ProductType", "?")
    ver = info.get("ProductVersion", "?")
    chip = chip_for(device_class)
    print(f"device: {device_class} ({KNOWN_DEVICES.get(device_class, ('unknown model',))[0]})  chip={chip or 'unknown'}")
    print(f"iOS:    {ver}")
    print("recommended extraction route (best first):")
    for i, s in enumerate(recommend(chip, ver), 1):
        print(f"  {i}. {s}")
    pout = Path(args.out)
    pout.mkdir(parents=True, exist_ok=True)
    (pout / "plan.json").write_text(
        json.dumps({"device_class": device_class, "ios": ver, "chip": chip,
                    "steps": recommend(chip, ver)}, indent=2), encoding="utf-8"
    )
    print(f"plan written to {pout / 'plan.json'}")


def cmd_acquire_jailbroken(args):
    """AFU extraction from an already-jailbroken device.

    Primary: AFC2 root mount via ifuse --root (full filesystem).
    Fallback: --ssh host -> pull /var/mobile + /var/Keychains over SSH.
    """
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if args.ssh:
        _jb_ssh_pull(args.ssh, out)
        return
    mnt = Path(tempfile.mkdtemp(prefix="sleuth-jb-"))
    try:
        _run(["ifuse", "--root"] + (["-u", args.udid] if args.udid else []) + [str(mnt)])
    except FileNotFoundError:
        sys.exit("ifuse with --root support not found (apt install ifuse)")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"AFC2 mount failed (rc={exc.returncode}). Is the device jailbroken, "
                 "unlocked, and does it expose com.apple.afc2?")
    try:
        for name in mnt.iterdir():
            if name.name in (".", ".."):
                continue
            dst = out / name.name
            if name.is_dir():
                shutil.copytree(name, dst)
            else:
                shutil.copy2(name, dst)
        keychain = mnt / "var" / "Keychains" / "keychain-2.db"
        print("jailbroken filesystem pulled to", out)
        print("keychain-2.db present:", keychain.exists(), ("(saved at %s)" % (out / "keychain-2.db") if keychain.exists() else ""))
    finally:
        try:
            _run(["fusermount", "-u", str(mnt)])
        except subprocess.CalledProcessError:
            pass


def cmd_acquire_probe(args):
    """Probe a device in ANY state (BFU/AFU/recovery/DFU) for exposed identifiers.

    BFU (before first unlock) still exposes USB-level identity: serial number,
    product info, UDID via usbmuxd. Pairing records and lockdown services stay
    gated until first unlock. This command collects only what the OS leaks.
    """
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    res = {"note": "BFU probe: USB identity only; user data requires AFU + pairing", "usb": [], "usbmux": "", "lockdown": {}, "recovery_dfu": [], "usbliter8": {}}

    # 1) sysfs USB descriptors via shared usb module (every state, no unlock)
    from .usb import usb_state

    snap = usb_state()
    for entry in snap["devices"]:
        if entry.get("mode") in ("recovery", "dfu", "pwned-dfu"):
            res["recovery_dfu"].append({k: v for k, v in entry.items() if k != "sysfs"})
        res["usb"].append({k: v for k, v in entry.items() if k != "sysfs"})

    # usbliter8 marker: PWND:[usbliter8] in USB serial = pwned DFU active
    res["usbliter8"] = {"pwnd": snap["pwnd_usbliter8"], "pwnd_checkm8": snap["pwnd_checkm8"]}

    # 2) usbmuxd view (UDID + connection type; UDID is exposed pre-unlock)
    try:
        proc = subprocess.run(["pymobiledevice3", "usbmux", "list"], capture_output=True, text=True, timeout=30)
        res["usbmux"] = proc.stdout.strip()
    except Exception as exc:  # noqa: BLE001
        res["usbmux"] = f"<unavailable: {exc}>"

    # 3) best-effort lockdown (only works AFU+paired; BFU will fail cleanly)
    try:
        proc = subprocess.run(["ideviceinfo"], capture_output=True, text=True, timeout=25)
        if proc.returncode == 0:
            info = {}
            for line in proc.stdout.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    info[k.strip()] = v.strip()
            res["lockdown"] = {"reachable": True, "data": info}
        else:
            res["lockdown"] = {"reachable": False, "hint": "locked-out: BFU state or unpaired (recoverable only after first unlock)"}
    except Exception as exc:  # noqa: BLE001
        res["lockdown"] = {"reachable": False, "hint": str(exc)}

    (out / "probe.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    state = "recovery/DFU" if res["recovery_dfu"] else ("AFU+paired" if res["lockdown"].get("reachable") else "BFU or unpaired")
    print(f"probe written to {out / 'probe.json'}")
    print(f"device state: {state}")
    for u in res["usb"]:
        print(f"  USB: {u['product']} serial={u['serial']} pid={u['product_id']} mode={u.get('mode', '?')}")
    if res["usbliter8"].get("pwnd"):
        print("  !! PWND:[usbliter8] present: device is in usbliter8 pwned DFU (bootrom control active)")
    if res["usbliter8"].get("pwnd_checkm8"):
        print("  !! PWND:[checkm8] present: gaster-pwned DFU active")
    if res["recovery_dfu"]:
        print("  NOTE: device is in Recovery/DFU - normal services are offline")
    if not res["lockdown"].get("reachable"):
        print("  NOTE: no lockdown access. In BFU this is expected: pairing records are")
        print("        passcode-gated until first unlock. One unlock restores access.")


def cmd_acquire_dfu(args):
    """Watch USB for Apple DFU entry (timing-critical helper).

    Polls /sys/bus/usb/devices and reports every mode transition live,
    exiting 0 the moment a device lands in DFU (PID 1227). Use this while
    pressing the button sequence: start it first, then press vol-up,
    vol-down, hold power 10s, then power+vol-down 5s. Pairs with
    `acquire checkm8 --watch` / the usbliter8 RP2350 flow.
    """
    from .usb import watch_dfu

    print(f"watching USB for Apple DFU entry (timeout {args.timeout}s)...")
    print("press: vol-up, vol-down, hold power 10s, then power+vol-down 5s")

    def _report(ts, entry):
        print(f"  [{ts}] {entry.get('product') or 'Apple device'} -> {entry['mode'].upper()}")

    snap = watch_dfu(timeout=args.timeout, on_transition=_report)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "dfu-watch.json").write_text(
        json.dumps({k: v for k, v in snap.items()}, indent=2, default=str), encoding="utf-8"
    )
    if snap["dfu"]:
        dev = next(d for d in snap["devices"] if "dfu" in d["mode"])
        print(f"DFU ENTERED: pid={dev['product_id']} serial={dev['serial']}")
        print("next: acquire checkm8 (A7-A11) or move to the RP2350 for usbliter8 (A12/A13)")
    elif snap["recovery"]:
        print("device reached RECOVERY but not DFU yet - keep holding power+vol-down")
    else:
        print("timeout: no DFU entry observed")


def cmd_acquire_restore_traversal(args):
    """CVE-2026-84598 research route: crafted restore manifest path probe.

    Builds a minimal backup whose Manifest.mbdb carries dot-dot traversal
    windows (HomeDomain -> ../../Media, -> /var/tmp, SysContainerDomain
    escape), starts a restore session, and OBSERVES the device's file
    requests. Aborts before any file data is transferred so no device
    content is modified. Verifies whether a <26.7 target validates
    manifest-relative paths. Requires Find My iPhone OFF on the target
    (the restore anti-theft gate, MBErrorDomain/211). Schema details are
    first-hand research (docs/research-2026-09-16-afc-26.6.1.md).
    """
    from .cve2026_84598_restore import main as rt_main

    sys.exit(rt_main(["--out", str(args.out)] + (["--watch"] if args.watch else [])))


def cmd_dump(args):
    try:
        backup = Backup(args.backup)
    except BackupError as exc:
        sys.exit(f"error: {exc}")
    work = Path(tempfile.mkdtemp(prefix="sleuth-work-"))
    artifacts = {
        "device": backup.backup_state(),
        "apps": [],
        "messages": [],
        "contacts": [],
        "calls": [],
        "history": [],
        "bookmarks": [],
        "prefs": {},
        "files": {**backup.stats(), "app_domains": backup.app_domains()},
        "generated": __version__,
    }

    homes = ["HomeDomain", "SysContainerDomain-../../../../../../../../root/Library"]
    errs = []

    def run(parser, domain, relpath, name):
        try:
            db = _extract_artifact(backup, domain, relpath, work, name)
            if db is None:
                return None
            return parser(db)
        except Exception as exc:  # noqa: BLE001 - report, don't die
            errs.append(f"{relpath}: {exc}")
            return None

    try:
        res = run(sms.parse, "HomeDomain", "Library/SMS/sms.db", "sms.db")
        if res:
            artifacts["messages"] = res["messages"]
    except Exception as exc:
        errs.append(str(exc))

    contacts_res = run(contacts.parse, "HomeDomain", "Library/AddressBook/AddressBook.sqlitedb", "contacts.sqlitedb")
    if contacts_res:
        artifacts["contacts"] = contacts_res

    calls_res = run(calls.parse, "HomeDomain", "Library/CallHistoryDB/CallHistory.storedata", "calls.storedata")
    if calls_res:
        artifacts["calls"] = calls_res

    hist = run(safari._history, "HomeDomain", "Library/Safari/History.db", "history.db")
    if hist:
        artifacts["history"] = hist
    bm = run(safari._bookmarks, "HomeDomain", "Library/Safari/Bookmarks.db", "bookmarks.db")
    if bm:
        artifacts["bookmarks"] = bm

    try:
        artifacts["prefs"] = plists.parse(backup)
    except Exception as exc:
        errs.append(f"prefs: {exc}")

    # keychain (present in decrypted encrypted-backups and jailbroken pulls)
    kc_path = None
    for rec in backup.find(pattern="%keychain-2.db"):
        p = backup.get_path(rec["domain"], rec["relativePath"])
        if p:
            kc_path = p
            break
    if kc_path:
        try:
            artifacts["keychain"] = keychain.parse(kc_path)
        except Exception as exc:
            errs.append(f"keychain: {exc}")

    vm = run(voicemail.parse, "HomeDomain", "Library/Voicemail/voicemail.db", "voicemail.db")
    if vm:
        artifacts["voicemail"] = vm

    try:
        artifacts["notes"] = notes.parse(backup, blob_dir=Path(args.out) / "notes_blobs")
    except Exception as exc:
        errs.append(f"notes: {exc}")

    # inventory every app database so examiners can drill into any app
    app_dbs = []
    for rec in backup.files():
        rel = (rec["relativePath"] or "").lower()
        if rec["domain"].startswith("AppDomain") and rel.endswith(
            (".sqlite", ".sqlitedb", ".storedata", ".db")
        ):
            app_dbs.append({"domain": rec["domain"], "path": rec["relativePath"], "size": rec["size"]})
    artifacts["app_databases"] = app_dbs[:1000]

    # apps.json next to backup (optional, produced by `acquire apps`)
    apps_json = Path(args.backup).parent / "apps.json"
    if apps_json.exists():
        try:
            artifacts["apps"] = json.loads(apps_json.read_text())["apps"]
        except Exception:
            pass

    # per-file index (streaming, one JSON object per line)
    idx_path = Path(args.out) / "file_index.ndjson"
    idx_path.parent.mkdir(parents=True, exist_ok=True)
    with open(idx_path, "w", encoding="utf-8") as fh:
        for rec in backup.files():
            fh.write(
                json.dumps(
                    {"fileID": rec["fileID"], "domain": rec["domain"], "path": rec["relativePath"], "size": rec["size"]}
                )
                + "\n"
            )
    artifacts["files"]["file_index"] = str(idx_path)
    artifacts["files"]["indexed"] = True

    out = build_report(artifacts, Path(args.out))
    print(f"report written to {out}")
    print(f"  artifacts: messages={len(artifacts['messages'])} contacts={len(artifacts['contacts'])} "
          f"calls={len(artifacts['calls'])} history={len(artifacts['history'])} bookmarks={len(artifacts['bookmarks'])}")
    if errs:
        print("warnings:", *errs, sep="\n  - ")


def cmd_tools(args):
    from . import forensics
    if args.json:
        import json
        print(json.dumps(forensics.detect() if not args.installed else
                         [r for r in forensics.detect() if r["installed"]], indent=2))
        return
    print(forensics.render_tools(installed_only=args.installed))


def cmd_ileapp_run(args):
    from . import ileapp
    r = ileapp.run_iLEAPP(args.input, args.out, itype=args.type)
    if not r.get("ok"):
        print(f"ileapp: {r.get('error')}", file=sys.stderr)
        if r.get("log_tail"):
            print(r["log_tail"][-500:], file=sys.stderr)
        sys.exit(1)
    print(f"iLEAPP completed ({r['returncode']}) -> {r['output_dir']}")
    print("run 'opensleuth ileapp breath <case> --ileapp-out OUT --out REPORT' to merge")
    if r.get("log_tail"):
        print(r["log_tail"][-400:])


def cmd_ileapp_breath(args):
    from . import ileapp
    r = ileapp.breath_report(args.case, args.ileapp_out, args.out)
    print(ileapp.render_breath(r))


def cmd_certify(args):
    from . import certify
    if args.verify:
        pw = os.environ.get(args.passphrase_env) if args.passphrase_env else None
        v = certify.verify(args.verify, passphrase=pw,
                           keyfile=args.keyfile)
        print(certify.render_verify(v))
        return
    if not args.case_dir or not args.out:
        sys.exit("certify: provide <case-dir> --out <dir> --examiner <name> (or --verify <report>)")
    if not args.examiner:
        sys.exit("certify: --examiner is required for the signature block")
    pw = os.environ.get(args.passphrase_env) if args.passphrase_env else None
    r = certify.certify(args.case_dir, args.out, args.examiner,
                        passphrase=pw, keyfile=args.keyfile)
    print(f"certified {r['file_count']} files")
    print(f"  manifest : {r['manifest']}")
    print(f"  report   : {r['report']}")
    print(f"  html     : {r['html']}")
    print(f"  seal     : {r['seal'][:16]}...")
    if r.get("seal_key"):
        print(f"  seal key : {r['seal_key']}  (store securely; needed for verify)")


def cmd_stance(args):
    from . import forensics
    print(forensics.render_stance())


def cmd_appcatalog_list(args):
    from . import appcatalog
    if args.json:
        import json
        print(json.dumps(appcatalog.APP_CATALOG, indent=2))
        return
    print(appcatalog.render_list())


def cmd_appcatalog_inventory(args):
    from . import appcatalog
    import json
    dbs = appcatalog.find_dbs(Path(args.dir))
    inv = []
    for d in dbs:
        i = appcatalog.inventory(Path(d["path"]))
        if i:
            inv.append({**d, **i})
    if args.json:
        print(json.dumps(inv, indent=2))
        return
    print(appcatalog.render_inventory(Path(args.dir)).splitlines()[0])
    for i in inv:
        print(f"\n{i['rel']}  ({i['size']} B)  app={i['app']}")
        for t in i["tables"]:
            print(f"   {t['rows']:>10,} rows  {t['table']}  cols: {', '.join(t['columns'][:8])}")
    print(f"\n{len(inv)} databases; extract any table with: opensleuth appcatalog extract <db> <table> --out x.csv")


def cmd_appcatalog_extract(args):
    from . import appcatalog
    r = appcatalog.extract_table(Path(args.db), args.table, Path(args.out),
                                 limit=args.limit, where=args.where)
    if not r.get("ok"):
        print(f"extract failed: {r.get('error')}")
        return
    print(f"{r['rows']:,} rows x {len(r['columns'])} cols -> {r['csv']}")


def cmd_escrow_sweep(args):
    from . import escrow
    r = escrow.sweep(args.dir, args.out)
    print(escrow.render_sweep(r))


def cmd_escrow_find(args):
    from . import escrow
    print(escrow.render_find(escrow.find_records(args.dir)))


def cmd_escrow_describe(args):
    from .escrow import KeybagError, describe, render_describe
    try:
        print(render_describe(describe(args.file)))
    except KeybagError as exc:
        print(f"escrow: {exc}")


def cmd_escrow_unlock(args):
    from .escrow import unlock_backup
    r = unlock_backup(args.record, args.backup, args.out)
    if r.get("error"):
        print(f"escrow: {r['error']}")
        if r.get("escrow"):
            print(render_escrow_summary(r["escrow"]))
        return
    print("decrypted ->", r["decrypted"])
    print(render_escrow_summary(r["escrow"]))


def render_escrow_summary(esc):
    lines = [f"  escrow {esc.get('type', '?')} keybag:"]
    for c in esc.get("classes", []):
        lines.append(f"    {'+' if c.get('usable_now') else '-'} {c.get('class')}")
    return "\n".join(lines)


def cmd_keybag_status(args):
    from .keybag import KeybagError, render_status
    try:
        print(render_status(args.file))
    except KeybagError as exc:
        print(f"keybag: {exc}")


def cmd_keybag_escrow(args):
    from .keybag import KeybagError, render_escrow
    try:
        print(render_escrow(args.file))
    except KeybagError as exc:
        print(f"escrow: {exc}")


def cmd_doctor(args):
    from . import doctor
    d = doctor.run()
    print(doctor.render(d, json_out=getattr(args, "json", False)))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="opensleuth", description="open-source iOS forensic triage")
    ap.add_argument("--version", action="version", version=f"opensleuth {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    acq = sub.add_parser("acquire", help="pull data from a connected device")
    acq_sub = acq.add_subparsers(dest="acq", required=True)
    b = acq_sub.add_parser("backup", help="full device backup (idevicebackup2)")
    b.add_argument("--out", required=True)
    b.add_argument("--udid")
    b.set_defaults(fn=cmd_acquire_backup)
    m = acq_sub.add_parser("media", help="copy media via AFC (ifuse)")
    m.add_argument("--out", required=True)
    m.add_argument("--udid")
    m.set_defaults(fn=cmd_acquire_media)
    i = acq_sub.add_parser("info", help="device info JSON")
    i.add_argument("--out", required=True)
    i.add_argument("--udid")
    i.set_defaults(fn=cmd_acquire_info)
    a = acq_sub.add_parser("apps", help="app inventory JSON")
    a.add_argument("--out", required=True)
    a.add_argument("--udid")
    a.set_defaults(fn=cmd_acquire_apps)
    al = acq_sub.add_parser("all", help="maximum acquisition: every service in one shot")
    al.add_argument("--out", required=True)
    al.add_argument("--udid")
    al.add_argument("--password", help="backup password -> enables encrypted backup + keychain unpack")
    al.add_argument("--sysdiagnose", action="store_true", help="also pull sysdiagnose (needs on-device approve)")
    al.set_defaults(fn=cmd_acquire_all)
    bfu = acq_sub.add_parser("bfu", help="BFU master: everything obtainable before first unlock")
    bfu.add_argument("--out", required=True)
    bfu.add_argument("--chip", help="chip hint when it cannot be auto-detected (e.g. A10)")
    bfu.add_argument("--ios", help="iOS version for expectations (e.g. 18.7.1)")
    bfu.add_argument("--ramdisk", help="payload dir (iBSS/iBEC/ramdisk/devicetree/trustcache) to run the checkm8 BFU ramdisk pull after pwn")
    bfu.add_argument("--force", action="store_true", help="attempt checkm8 pwn even when no DFU/recovery state is detected")
    bfu.add_argument("--keys", action="store_true", help="capture the device AES keyset (gaster keys) from the pwned device")
    bfu.add_argument("--watch", action="store_true", help="wait for DFU entry, then auto-run pwn -> keys -> ramdisk chain")
    bfu.add_argument("--runbook", help="write a markdown BFU runbook for the case to this file and exit")
    bfu.add_argument("--yield-card", action="store_true", help="print the per-device BFU yield card")
    bfu.add_argument("--watch-timeout", type=float, default=300.0, help="seconds to wait for DFU in --watch mode")
    bfu.add_argument("--route", choices=["usbliter8", ""], default="", help="show the usbliter8 BFU playbook for A12/A13")
    bfu.set_defaults(fn=cmd_acquire_bfu)
    c8 = acq_sub.add_parser("checkm8", help="zero-hardware bootrom route (A7-A11): gaster pwn -> palera1n/PongoOS -> FS + BFU-partial")
    c8.add_argument("--out", required=True)
    c8.add_argument("--chip", help="chip hint (A7-A11) when it cannot be auto-detected")
    c8.add_argument("--force", action="store_true", help="attempt pwn even when DFU state is not detected")
    c8.add_argument("--watch", action="store_true", help="wait for DFU entry (up to --watch-timeout s) before pwn")
    c8.add_argument("--watch-timeout", dest="watch_timeout", type=float, default=180.0, help="DFU watch timeout in seconds (default 180)")
    c8.set_defaults(fn=cmd_acquire_checkm8)
    ul = acq_sub.add_parser("usbliter8", help="usbliter8 bootrom route (A12/A13): PWN DFU + iBoot/ramdisk (2026-06-18)")
    ul.add_argument("--out", required=True)
    ul.add_argument("--chip", help="chip hint (A12/A13) when it cannot be auto-detected")
    ul.add_argument("--board", default="pico2", help="RP2350 board (pico2, waveshare_rp2350_usb_a, ...)")
    ul.add_argument("--fw", help="path to usbliter8 firmware UF2; prints download/install guidance if missing")
    ul.set_defaults(fn=cmd_acquire_usbliter8)
    afu = acq_sub.add_parser("afu", help="AFU master: every extraction route after first unlock")
    afu.add_argument("--out", required=True)
    afu.add_argument("--udid")
    afu.add_argument("--password", help="backup password -> encrypted backup + keychain")
    afu.add_argument("--sysdiagnose", action="store_true", help="also pull sysdiagnose")
    afu.set_defaults(fn=cmd_acquire_afu)
    tg = acq_sub.add_parser("target", help="one-command profile for a specific device (iphone11, ios11era)")
    tg.add_argument("--name", required=True, help="target name: iphone11, ios11era")
    tg.add_argument("--out", required=True)
    tg.add_argument("--password", help="backup password (AFU suite)")
    tg.add_argument("--run", action="store_true", help="execute the AFU suite when device matches")
    tg.set_defaults(fn=cmd_acquire_target)
    p = acq_sub.add_parser("probe", help="identify a device in ANY state (BFU/AFU/recovery/DFU)")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_acquire_probe)
    dw = acq_sub.add_parser("dfu", help="watch USB for Apple DFU entry (timing-critical; pairs with checkm8/usbliter8)")
    dw.add_argument("--out", required=True)
    dw.add_argument("--timeout", type=float, default=180.0, help="seconds to watch (default 180)")
    dw.set_defaults(fn=cmd_acquire_dfu)
    rt = acq_sub.add_parser("restore-traversal", help="CVE-2026-84598 crafted restore manifest probe (research route; requires Find My OFF)")
    rt.add_argument("--out", required=True)
    rt.add_argument("--watch", action="store_true", help="wait for an Apple device on USB first")
    rt.set_defaults(fn=cmd_acquire_restore_traversal)
    jb = acq_sub.add_parser("jailbroken", help="full filesystem pull from an already-jailbroken device (AFC2)")
    jb.add_argument("--out", required=True)
    jb.add_argument("--udid")
    jb.add_argument("--ssh", help="SSH fallback: host (root@IP) instead of AFC2")
    jb.set_defaults(fn=cmd_acquire_jailbroken)

    m = sub.add_parser("matrix", help="public exploitation capability for a chip/iOS combo")
    m.add_argument("chip", help="e.g. A12, A13, A11")
    m.add_argument("ios", help="e.g. 16.6.1")
    m.set_defaults(fn=cmd_matrix)
    sc = sub.add_parser("silicon", help="public bootrom/SEP exploit envelope (checkm8, Blackbird, usbliter8)")
    sc.add_argument("--chip", help="filter the envelope to a chip (e.g. A13)")
    sc.add_argument("--detailed", action="store_true", help="full details per exploit")
    sc.add_argument("--lab", metavar="DIR", help="generate the silicon research lab kit (DFU capture + identity + session log)")
    sc.add_argument("chip", nargs="?", default="", help="filter to a chip (A4..A16); omit for the full catalog")
    sc.add_argument("--trace", metavar="FILE", help="analyze a usbmon DFU capture (text log)")
    sc.add_argument("--corpus", metavar="OUT", help="write the fuzz corpus CSV (with --trace)")
    sc.add_argument("--notebook", metavar="LABDIR", help="research notebook: list or append notes")
    sc.add_argument("--note", default="", help="note to append (with --notebook)")
    sc.set_defaults(fn=cmd_silicon)
    ex = sub.add_parser("exploits", help="complete public exploit inventory with hardware requirements")
    ex.add_argument("chip", nargs="?", default="", help="filter to a chip (A4..A16)")
    ex.add_argument("--no-hardware", action="store_true", help="only routes needing plain PC + USB (no rig, no app)")
    ex.add_argument("--layer", default="", help="bootrom|sep|kernel|userspace|trollstore")
    ex.add_argument("--detailed", action="store_true", help="full notes")
    ex.set_defaults(fn=cmd_exploits)
    pl = sub.add_parser("plan", help="recommended extraction route for the connected device")
    pl.add_argument("--out", required=True)
    pl.set_defaults(fn=cmd_plan)
    rsch = sub.add_parser("research", help="public iOS research pipeline: new CVEs/disclosures relevant to acquisition")
    rsch.add_argument("--detailed", action="store_true", help="include impact/description text")
    rsch.add_argument("--timeout", type=int, default=30, help="fetch timeout seconds")
    rsch.add_argument("--state", default=None, help="state file path (default ~/.coreprobe/research-state.json)")
    rsch.set_defaults(fn=cmd_research)
    expo = sub.add_parser("exposure", help="public routes + CVE disclosures for a chip/iOS (auto-detect connected device)")
    expo.add_argument("--chip", default="", help="chip (A7..A18); auto-detected if omitted")
    expo.add_argument("--ios", default="", help="iOS version (e.g. 26.6.1); auto-detected if omitted")
    expo.add_argument("--detailed", action="store_true", help="include BFU positions")
    expo.set_defaults(fn=cmd_exposure)
    ver = sub.add_parser("versions", help="authoritative per-firmware public jailbreak status (iOS 18/26/27, tvOS, bridgeOS)")
    ver.add_argument("ios", nargs="?", default="", help="specific version, e.g. 26.0.1")
    ver.add_argument("--ipados", action="store_true", help="show the iPadOS 26 table")
    ver.set_defaults(fn=cmd_versions)

    e = sub.add_parser("extract", help="copy app container trees from a backup to disk")
    e.add_argument("backup")
    e.add_argument("-o", "--out", required=True)
    e.add_argument("--domains", help="comma-separated domains, e.g. AppDomain-com.whatsapp,HomeDomain")
    e.add_argument("--all", action="store_true", help="extract every domain in the backup")
    e.set_defaults(fn=cmd_extract)

    d = sub.add_parser("dump", help="parse a backup directory into a report")
    d.add_argument("backup")
    d.add_argument("-o", "--out", required=True)
    d.set_defaults(fn=cmd_dump)

    from . import cxx
    cxx.add_parser(sub)

    from . import forensics
    tk = sub.add_parser("tools", help="forensic toolchain catalog with live installed-status detection")
    tk.add_argument("--installed", action="store_true", help="only show installed tools")
    tk.add_argument("--json", action="store_true", help="machine-readable output")
    tk.set_defaults(fn=cmd_tools)

    st = sub.add_parser("stance", help="honest capability comparison vs Cellebrite/AXIOM/GrayKey/Elcomsoft")
    st.set_defaults(fn=cmd_stance)

    from . import certify as _cert
    ct = sub.add_parser("certify", help="court-ready reporting: chain-of-custody manifest + HMAC integrity seal")
    ct.add_argument("case_dir", nargs="?", help="case/evidence directory to certify")
    ct.add_argument("--out", help="output dir (required with case_dir)")
    ct.add_argument("--examiner", default="", help="examiner name for the signature block")
    ct.add_argument("--keyfile", help="seal key file (default: generated seal.key next to report)")
    ct.add_argument("--passphrase-env", help="env var holding the seal passphrase")
    ct.add_argument("--verify", metavar="REPORT", help="verify a sealed-report.json instead of certifying")
    ct.set_defaults(fn=cmd_certify)

    from . import ileapp as _il
    il = sub.add_parser("ileapp", help="artifact breadth: run iLEAPP (100+ parsers) on an extraction and merge a breath report")
    il_sub = il.add_subparsers(dest="il", required=True)
    ilr = il_sub.add_parser("run", help="run iLEAPP on an extraction")
    ilr.add_argument("input", help="extraction dir or tar/gz/zip")
    ilr.add_argument("--out", required=True)
    ilr.add_argument("--type", default="fs", choices=["fs", "logical", "tar", "gz", "zip"])
    ilr.set_defaults(fn=cmd_ileapp_run)
    ilb = il_sub.add_parser("breath", help="merge CoreProbe DB inventory + iLEAPP outputs into breath-report.json")
    ilb.add_argument("case", help="extraction/case dir")
    ilb.add_argument("--ileapp-out", help="iLEAPP output dir (optional)")
    ilb.add_argument("--out", required=True)
    ilb.set_defaults(fn=cmd_ileapp_breath)

    from . import doctor
    dc = sub.add_parser("doctor", help="workstation + device diagnostics (pre-case sanity pass)")
    dc.add_argument("--json", action="store_true")
    dc.set_defaults(fn=cmd_doctor)

    from . import icloud
    ic = acq_sub.add_parser("icloud", help="iCloud account-level acquisition (REQUIRES lawful authorization: --warrant)")
    ic.add_argument("--username", help="Apple ID email")
    ic.add_argument("--password", help="Apple ID password (or app-specific)")
    ic.add_argument("--warrant", help="warrant/case reference - REQUIRED, gate refuses without it")
    ic.add_argument("--out", required=True)
    ic.set_defaults(fn=icloud.cmd_acquire_icloud)

    from . import appcatalog
    ac = sub.add_parser("appcatalog", help="app artifact breadth: catalog, sqlite inventory, table extraction")
    ac_sub = ac.add_subparsers(dest="appcat", required=True)
    l = ac_sub.add_parser("list", help="show the ~45-app catalog")
    l.add_argument("--json", action="store_true")
    l.set_defaults(fn=cmd_appcatalog_list)
    inv = ac_sub.add_parser("inventory", help="scan an extracted container/image dir for app databases")
    inv.add_argument("dir")
    inv.add_argument("--json", action="store_true")
    inv.set_defaults(fn=cmd_appcatalog_inventory)
    ex = ac_sub.add_parser("extract", help="dump a discovered table to CSV")
    ex.add_argument("db")
    ex.add_argument("table")
    ex.add_argument("--out", required=True)
    ex.add_argument("--limit", type=int, default=100000)
    ex.add_argument("--where", default="", help="SQL where clause (no WHERE keyword)")
    ex.set_defaults(fn=cmd_appcatalog_extract)

    from . import keybag
    kb = sub.add_parser("keybag", help="parse iOS keybags (kbagic) and report BFU-usable protection classes")
    kb_sub = kb.add_subparsers(dest="kb", required=True)
    ks = kb_sub.add_parser("status", help="show per-class key presence of a keybag file")
    ks.add_argument("file")
    ks.set_defaults(fn=cmd_keybag_status)
    ke = kb_sub.add_parser("escrow", help="extract keybags embedded in an iTunes escrow record (plist)")
    ke.add_argument("file")
    ke.set_defaults(fn=cmd_keybag_escrow)

    from . import escrow
    es = sub.add_parser("escrow", help="escrow/paired-computer acquisition (passcode-free path, works on ALL models)")
    es_sub = es.add_subparsers(dest="esc", required=True)
    esf = es_sub.add_parser("find", help="locate escrow records/backup keybags in case materials")
    esf.add_argument("dir")
    esf.set_defaults(fn=cmd_escrow_find)
    esd = es_sub.add_parser("describe", help="classes + passcode material of an escrow record")
    esd.add_argument("file")
    esd.set_defaults(fn=cmd_escrow_describe)
    esu = es_sub.add_parser("unlock", help="attempt encrypted-backup decryption with escrow material")
    esu.add_argument("record")
    esu.add_argument("backup")
    esu.add_argument("--out", required=True)
    esu.set_defaults(fn=cmd_escrow_unlock)
    ess = es_sub.add_parser("sweep", help="batch hunt: find records + try passcode-free unlock against sibling backups")
    ess.add_argument("dir")
    ess.add_argument("--out", required=True)
    ess.set_defaults(fn=cmd_escrow_sweep)

    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()