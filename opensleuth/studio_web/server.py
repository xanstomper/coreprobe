"""
Serve the opensleuth studio web UI from a single built-in Python HTTP server
with REST endpoints for device polling, app enumeration, acquisition, and report.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

ROOT = Path(__file__).parent
STATIC = ROOT / "static"
PORT = int(os.environ.get("OPENSLEUTH_PORT", "9121"))


def _run(cmd, timeout=60):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


_LAST_DEV_STATE = {"udid": None, "state": None}


def _device():
    """Robust device detection.

    Primary source = sysfs USB (usb_state) which needs NO daemon and always
    reflects what is physically attached. Enrichment (chip off ProductType,
    model name, iOS build) comes from lockdown/pymobiledevice3 only when the
    service layer is actually reachable - never lets a usbmuxd outage or a
    non-JSON error line hide a plugged-in device.
    """
    from ..usb import usb_state, chip_from_serial, chip_from_irecovery
    from ..matrix import chip_for, KNOWN_DEVICES

    st = usb_state()
    devs = st.get("devices", [])
    if not devs:
        if _LAST_DEV_STATE.get("udid"):
            _notify("Device Detached", "iOS device was disconnected.", "warning", "DEVICE")
            _LAST_DEV_STATE["udid"] = None
            _LAST_DEV_STATE["state"] = None
        return None
    # Prefer a booted 'normal' device for service-layer data; else the first.
    booted = next((d for d in devs if d.get("mode") == "normal"), devs[0])
    product = booted.get("product") or ""
    serial = booted.get("serial") or ""
    product_id = booted.get("product_id") or ""
    mode = booted.get("mode") or "normal"

    # PWN markers / state from sysfs (no daemon required)
    pwnd = "pwnd" in mode
    state = {"dfu": "DFU", "pwned-dfu": "pwned-dfu", "recovery": "recovery"}.get(mode, "")

    info = {}
    # Try to enrich with ProductType/iOS via pymobiledevice3 usbmux (tolerant)
    try:
        p = _run(["pymobiledevice3", "usbmux", "list"], timeout=10)
        if p.returncode == 0 and p.stdout.strip():
            try:
                parsed = json.loads(p.stdout)
                d0 = (parsed[0] if isinstance(parsed, list) and parsed else
                      parsed.get("devices", [{}])[0] if isinstance(parsed, dict) else {})
                info = d0 if isinstance(d0, dict) else {}
            except (ValueError, IndexError):
                info = {}
    except Exception:
        info = {}

    pt = info.get("ProductType", "")
    if not state:
        # booted -> locked (BFU) or unlocked/paired (AFU)
        state = "AFU" if _paired() else "BFU"

    chip = chip_for(pt) or chip_from_serial(serial) or chip_from_irecovery() or ""
    res = {
        "model": KNOWN_DEVICES.get(pt, (pt or product or "Apple device"))[0],
        "product_type": pt or product or "",
        "ios": info.get("ProductVersion", ""),
        "build": info.get("BuildVersion", ""),
        "udid": info.get("Identifier") or info.get("UniqueDeviceID", "") or serial,
        "state": state,
        "chip": chip or "",
        "mode": mode,
        "serial": serial,
        "product_id": product_id,
        "pwnd": pwnd,
    }
    if res["udid"] and (res["udid"] != _LAST_DEV_STATE.get("udid") or res["state"] != _LAST_DEV_STATE.get("state")):
        title = "Device Connected" if not _LAST_DEV_STATE.get("udid") else f"Device State: {res['state']}"
        _notify(title, f"{res['model']} ({res['chip'] or 'Apple silicon'}) detected in {res['state']} mode.", "success" if res["state"] == "AFU" else "info", "DEVICE")
        _LAST_DEV_STATE["udid"] = res["udid"]
        _LAST_DEV_STATE["state"] = res["state"]
    return res


def _paired():
    """True when a booted device is paired/unlocked (AFU)."""
    try:
        v = _run(["idevicepair", "validate"], timeout=8)
        return v.returncode == 0 and "SUCCESS" in v.stdout
    except Exception:
        return False


def _apps():
    try:
        p = _run([sys.executable, "-m", "pymobiledevice3", "apps", "list", "-t", "User"], timeout=60)
        if p.returncode != 0:
            return []
        data = json.loads(p.stdout)
        out = []
        for bundle, v in data.items():
            out.append({
                "name": v.get("CFBundleDisplayName") or v.get("CFBundleName") or bundle,
                "bundle": bundle,
                "version": v.get("CFBundleShortVersionString") or v.get("CFBundleVersion") or "",
            })
        return out
    except Exception:
        return []


def _cases():
    out = []
    cases_dir = Path.home() / "cases"
    if cases_dir.is_dir():
        seen = set()
        for cj in sorted(cases_dir.glob("*/case.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                out.append(json.loads(cj.read_text()))
                seen.add(cj.parent.name)
            except Exception:
                pass
        # directories with acquired evidence but no case.json still count
        for d in sorted(cases_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if d.is_dir() and d.name not in seen and any((d / k).is_dir() for k in ("backup", "media", "info", "crash")):
                out.append({
                    "case_id": d.name, "description": d.name, "examiner": "",
                    "created": datetime.fromtimestamp(d.stat().st_mtime).isoformat(timespec="seconds"),
                    "destination": str(d), "evidence_items": "1 device",
                    "status": "In Progress", "pseudo": True,
                })
    return out


def _artifacts(case_id):
    if not case_id:
        cs = _cases()
        if not cs:
            return {}
        case_id = cs[0].get("case_id", "")
    dest = Path.home() / "cases" / case_id
    data = {}
    art = dest / "report" / "artifacts.json"
    if not art.is_file():
        _auto_dump(dest)  # generate report on demand if a backup exists
    if art.is_file():
        try:
            data = json.loads(art.read_text())
        except Exception:
            pass
    data["media_index"] = _media_index(case_id)
    data["sqlite_files"] = _sqlite_files(dest)
    data["timeline_preview"] = _timeline(dest)
    data["crash_count"] = len(list((dest / "crash").glob("*"))) if (dest / "crash").is_dir() else 0
    data["info_files"] = sorted(p.name for p in (dest / "info").glob("*")) if (dest / "info").is_dir() else []
    data["backup_present"] = bool(list((dest / "backup").glob("*/Manifest.db")) if (dest / "backup").is_dir() else [])
    return data


def _auto_dump(dest: Path):
    backups = list((dest / "backup").glob("*/Manifest.db")) if (dest / "backup").is_dir() else []
    if not backups:
        return
    try:
        subprocess.run([sys.executable, "-m", "opensleuth", "dump", str(backups[0].parent),
                        "-o", str(dest / "report")], capture_output=True, timeout=600)
    except Exception:
        pass


def _media_index(case_id, limit=300):
    root = Path.home() / "cases"
    dest = root / case_id / "media"
    out = []
    if dest.is_dir():
        exts_img = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic")
        for f in sorted(dest.rglob("*")):
            if not f.is_file():
                continue
            try:
                st = f.stat()
            except OSError:
                continue
            ext = f.suffix.lower()
            thumb = None
            if ext in exts_img and ext != ".heic":
                thumb = "/api/file?path=" + quote(str(f))
            h = None
            if st.st_size < 25 * 1024 * 1024 and ext in (".jpg", ".jpeg", ".png", ".json", ".db", ".sqlite"):
                h = _sha256(str(f)).get("sha256")
            out.append({
                "name": f.name, "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                "thumb": thumb, "hash": h, "source": f.parent.name,
                "path": str(f),
            })
            if len(out) >= limit:
                break
    return out


def _sqlite_files(dest: Path, limit=100):
    out = []
    if dest.is_dir():
        for f in sorted(dest.rglob("*")):
            if f.is_file() and f.suffix.lower() in (".sqlite", ".sqlitedb", ".db", ".storedata"):
                out.append(str(f))
                if len(out) >= limit:
                    break
    return out


def _timeline(dest: Path, limit=300):
    t = dest / "report" / "timeline.csv"
    rows = []
    if t.is_file():
        import csv
        try:
            with open(t, newline="", encoding="utf-8", errors="replace") as fh:
                rdr = csv.reader(fh)
                next(rdr, None)
                for r in rdr:
                    rows.append(r[:3])
                    if len(rows) >= limit:
                        break
        except Exception:
            pass
    return rows


def _sha256(path_str):
    p = Path(path_str).expanduser()
    cases_root = Path.home() / "cases"
    try:
        rp = p.resolve()
        if not rp.is_relative_to(cases_root.resolve()) or not rp.is_file():
            return {"error": "path must be a file under ~/cases"}
        if p.stat().st_size > 200 * 1024 * 1024:
            return {"error": "file too large for on-demand hashing (limit 200 MB)"}
        import hashlib
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return {"sha256": h.hexdigest(), "path": str(p)}
    except Exception as exc:
        return {"error": str(exc)}


def _report(case):
    case_id = case.get("case_id", "")
    dest = Path.home() / "cases" / case_id
    if not case_id or not dest.is_dir():
        return {"error": "unknown case"}
    inner = dest / "backup" / case.get("udid", "")
    try:
        r = subprocess.run([sys.executable, "-m", "opensleuth", "dump", str(inner),
                        "-o", str(dest / "report")], capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            reason = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or ["dump failed"]
            return {"error": "report not generated: " + reason[0][:200]}
        if not (dest / "report" / "report.html").is_file():
            return {"error": "report not generated (no report.html produced)"}
        _notify("Report Generated", f"Forensic report created for case {case_id}.", "success", "EVIDENCE")
        return {"ok": True, "report": str(dest / "report" / "report.html")}
    except Exception as exc:
        return {"error": str(exc)}


def _safe_case_file(path_str):
    """Confine web-accessible files strictly UNDER ~/cases.

    Uses Path.is_relative_to (not startswith) so sibling directories like
    ~/cases-evil cannot bypass the check.
    """
    p = Path(path_str).expanduser()
    root = (Path.home() / "cases").resolve()
    try:
        rp = p.resolve()
        if rp.is_relative_to(root) and rp.is_file():
            return rp
    except OSError:
        pass
    return None


RCONS = {"total": 0, "done": 0, "failed": 0, "running": False}

# Auto-exploiter run state (single active run at a time)
AEXPLOIT = {
    "running": False,
    "report": None,
    "error": None,
    "log": [],
    "finished_at": None,
    "allow_destructive": False,
}


def _aexploit_log(msg):
    AEXPLOIT["log"].append(f"{datetime.now().strftime('%H:%M:%S')} {msg}")
    if len(AEXPLOIT["log"]) > 400:
        AEXPLOIT["log"] = AEXPLOIT["log"][-400:]


def _run_autoexploit(allow_destructive=False):
    """Background worker: probe + plan + run the auto-exploiter."""
    from ..exploitrunner import auto_exploit, render_run

    AEXPLOIT["running"] = True
    AEXPLOIT["error"] = None
    AEXPLOIT["log"] = []
    _notify("Auto-Exploiter Started", "Probing attached device and running applicable exploit routes...", "info", "EXPLOIT")
    sz = AEXPLOIT  # noqa: F841  (aliasing keeps closure reads stable)
    try:
        report = auto_exploit(
            allow_destructive=allow_destructive,
            route_timeout=280,
            log=_aexploit_log,
        )
        rendered = render_run(report, to_json=True)
        AEXPLOIT["report"] = rendered
        if isinstance(rendered, dict) and rendered.get("winner"):
            _notify("Auto-Exploit Hit!", f"Route succeeded: {rendered.get('winner')}", "success", "EXPLOIT")
        else:
            _notify("Auto-Exploiter Completed", "No terminal acquisition route succeeded on attached target.", "warning", "EXPLOIT")
    except Exception as exc:  # noqa: BLE001
        AEXPLOIT["error"] = str(exc)
        _aexploit_log(f"auto-exploit aborted: {exc}")
        _notify("Auto-Exploit Error", f"Execution failed: {exc}", "error", "EXPLOIT")
    finally:
        AEXPLOIT["finished_at"] = datetime.now().isoformat()
        AEXPLOIT["running"] = False


# Structured Notification Store
NOTIFICATIONS = [
    {
        "id": 1,
        "title": "Workstation Online",
        "message": "CoreProbe Forensic Control Plane and Exploit Engine initialized.",
        "level": "success",
        "category": "SYSTEM",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "iso": datetime.now().isoformat(),
    }
]


def _notify(title, message, level="info", category="SYSTEM"):
    now = datetime.now()
    entry = {
        "id": len(NOTIFICATIONS) + 1,
        "title": str(title),
        "message": str(message),
        "level": str(level),
        "category": str(category),
        "timestamp": now.strftime("%H:%M:%S"),
        "iso": now.isoformat(),
    }
    NOTIFICATIONS.append(entry)
    if len(NOTIFICATIONS) > 200:
        del NOTIFICATIONS[:-200]
    return entry


def _get_settings():
    cfg_dir = Path.home() / ".config" / "opensleuth"
    cfg_file = cfg_dir / "settings.json"
    defaults = {
        "examiner": "Forensic Examiner",
        "cases_root": str(Path.home() / "cases"),
        "hash_algo": "Triple-Hash (MD5+SHA256+SHA512)",
        "auto_dump": True,
        "auto_report": True,
        "poll_interval": 4000,
    }
    if cfg_file.is_file():
        try:
            saved = json.loads(cfg_file.read_text())
            defaults.update(saved)
        except Exception:
            pass
    return defaults


def _save_settings(data):
    cfg_dir = Path.home() / ".config" / "opensleuth"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_file = cfg_dir / "settings.json"
    current = _get_settings()
    current.update(data)
    cfg_file.write_text(json.dumps(current, indent=2))
    _notify("Settings Saved", f"Examiner '{current.get('examiner')}' preferences updated.", "success", "SYSTEM")
    return current


def _execute_single_route(route_name, allow_destructive=False):
    """Execute or verify preconditions for any single exploit route from the catalog."""
    from ..exploits import ROUTES, BY_NAME
    from ..exploitrunner import probe_target, _bin, _strategy_for_route, _EXECUTORS

    r = BY_NAME.get(route_name)
    if not r:
        for item in ROUTES:
            if item.get("name") == route_name:
                r = item
                break
    if not r:
        return {"ok": False, "status": "unknown_route", "message": f"Route '{route_name}' not found in catalog."}

    tools = r.get("tooling", [])
    # Three-tier honest deployability:
    #   _DOCUMENTED = no real public weaponization (no public PoC / CISA /
    #                 research-only) -> research_only, no deploy
    #   _ONDEVICE   = layer is kernel/userspace/trollstore/ppl with an
    #                 app-side agent (Dopamine/kfd/TrollStore/NathanLR/...).
    #                 Deploy = sideload the app on an unlocked device, then
    #                 the afu_agent executor verifies via AFC2. The UI labels
    #                 these SIDELOAD (host tool <= ideal, app not auto-installed
    #                 by us - that would be fabrication).
    #   _HOST       = bootrom/sep/bootrom-chain routes run on the host against
    #                 a DFU/locked device (checkm8/gaster, usbliter8ctl,
    #                 palera1n, irecovery, ipwndfu, Blackbird/PongoOS).
    _RO = ("no public poc","no public tooling","research-only",
           "cisa known exploited","documented only","no public weaponization")
    _tl = " ".join(str(t) for t in tools).lower()
    _documented = any(k in _tl for k in _RO)
    _HOST_BINS = {"gaster","ipwndfu","ipwnder32","palera1n","checkra1n",
                  "irecovery","usbliter8ctl","picotool","ideviceenterrecovery",
                  "ideviceinfo","pymobiledevice3","ifuse","ssh","PongoOS",
                  "restored_external","idevicebackup2"}
    layer = r.get("layer", "")
    # HOST tier = the executor runs a real PC-side binary. checkra1n and
    # palera1n are kernel-layer but are HOST-RUN USB tools (never on-device
    # apps), so host is keyed on NAMING A HOST BINARY, not on layer alone.
    def _host_bin_names(tok: str):
        tl = tok.lower()
        for b in _HOST_BINS:
            if b in tl:
                yield b
    _host_named = [b for tok in (str(t) for t in tools) for b in _host_bin_names(tok)]
    _host = bool(_host_named) or layer in ("bootrom","bootrom-chain","sep","iboot")
    _ondev = (not _host) and (layer in ("kernel","userspace","trollstore","ppl")) and r.get("hardware") == "app"
    # Which host binaries this route needs (only meaningful for _host routes).
    def _exec_bins(tok: str):
        tl2 = tok.lower()
        for b in _HOST_BINS:
            if b in tl2:
                yield b
    _needed = sorted({b for tok in (str(t) for t in tools) for b in _exec_bins(tok)})
    _have = [t for t in _needed if _bin(t)]
    missing_tools = []
    if _documented:
        _mode, _deployable = "research_only", False
    elif _host:
        _mode = "host"
        _deployable = bool(_have)  # at least one host executor binary present
        if _deployable:
            missing_tools = [t for t in _needed if t not in _have]  # informational
    elif _ondev:
        _mode = "sideload"
        # On-device app routes are DEPLOYABLE via app install on an unlocked
        # device (afu_agent flow). Host-side we only need a pairing service.
        _deployable = True
        missing_tools = [t for t in _needed if t not in _have]
    else:
        _mode, _deployable = "research_only", False
    target = probe_target()

    strat_map = {
        "checkm8": "checkm8_pwn",
        "usbliter8": "usbliter8_pwn",
        "blackbird": "blackbird_sep",
        "palera1n": "palera1n_jailbreak",
        "checkra1n": "checkra1n",
        "limera1n": "a4_bootrom",
        "pongo_ramdisk": "pongo_ramdisk",
        "dfu_helper": "dfu_helper",
    }
    strat = strat_map.get(route_name) or _strategy_for_route(r)
    executor = _EXECUTORS.get(strat)

    status_info = {
        "route": route_name,
        "layer": r.get("layer", "unknown"),
        "hardware": r.get("hardware", "none"),
        "required_chips": r.get("chips", []),
        "required_tools": tools,
        "missing_tools": missing_tools,
        "deployable": _deployable,
        "deploy_mode": _mode,
        "strategy": strat,
        "target_present": target.present,
        "target_chip": target.chip,
        "target_state": target.state,
    }

    if not _deployable:
        if _documented:
            msg = f"No installable exploit artifact for {route_name} - DOCUMENTED-only (research lead, no public weaponization)."
            return {"ok": False, "status": "research_only", "message": msg, "info": status_info}
        # A real (non-documented) route that lacks its host binary: honest
        # missing_tools, NOT research_only - it IS exploitable, just not
        # tooled-up on this host yet.
        _absent = missing_tools or (_mode == "host" and _needed) or [str(t).split()[0] for t in tools if str(t).split()[0]]
        msg = f"Exploit tooling not installed for {route_name} (mode={_mode}). Install: {' '.join(dict.fromkeys(_absent))[:120]}"
        _notify(f"Route: {route_name}", msg, "warning", "EXPLOIT")
        status_info["missing_tools"] = list(dict.fromkeys(_absent))
        return {"ok": False, "status": "missing_tools", "message": msg, "info": status_info}
    # Deployable route: missing_tools is a non-blocking advisory (the executor
    # falls back between gaster/ipwndfu/palera1n/irecovery). We proceed and
    # let the executor honestly report run success/failure.
    if missing_tools:
        _notify(f"Route: {route_name}", f"Partial tooling: {', '.join(missing_tools)} absent; executor will use present binaries.", "warning", "EXPLOIT")

    if not target.present:
        msg = f"Preconditions verified for {route_name}. Tooling ({', '.join(tools) or 'native'}) ready on host. No iOS target attached."
        _notify(f"Route Checked: {route_name}", msg, "info", "EXPLOIT")
        return {"ok": True, "status": "preconditions_verified", "message": msg, "info": status_info}

    if r.get("chips") and target.chip.upper() not in [c.upper() for c in r.get("chips", [])]:
        msg = f"Target chip mismatch: {target.chip} attached, but {route_name} requires {', '.join(r['chips'])}."
        _notify(f"Route: {route_name}", msg, "warning", "EXPLOIT")
        return {"ok": False, "status": "chip_mismatch", "message": msg, "info": status_info}

    if executor is None:
        msg = f"No execution handler registered for strategy '{strat}'."
        _notify(f"Route: {route_name}", msg, "error", "EXPLOIT")
        return {"ok": False, "status": "no_executor", "message": msg, "info": status_info}

    try:
        ok, detail, output = executor(target, timeout=120)
        level = "success" if ok else "warning"
        msg = f"{route_name}: {detail}"
        _notify(f"Route Executed: {route_name}", msg, level, "EXPLOIT")
        return {"ok": ok, "status": "executed", "detail": detail, "output": output, "message": msg, "info": status_info}
    except Exception as exc:
        msg = f"Execution error on {route_name}: {exc}"
        _notify(f"Route Error: {route_name}", msg, "error", "EXPLOIT")
        return {"ok": False, "status": "error", "message": msg, "info": status_info}


def _generate_timeline(case_id):
    dest = Path.home() / "cases" / case_id
    if not dest.is_dir():
        return {"error": "case directory not found"}
    art = dest / "report" / "artifacts.json"
    if not art.is_file():
        _auto_dump(dest)
    if not art.is_file():
        return {"error": "artifacts.json not found (run acquisition/dump first)"}
    out_csv = dest / "report" / "timeline.csv"
    try:
        r = subprocess.run([sys.executable, "-m", "opensleuth", "timeline", str(art),
                            "-o", str(out_csv)], capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            return {"error": f"timeline generator failed: {r.stderr[:200]}"}
        _notify("Timeline Generated", f"Super-timeline generated for case {case_id}.", "success", "FORENSICS")
        return {"ok": True, "path": str(out_csv)}
    except Exception as exc:
        return {"error": str(exc)}



def _icon(bundle):
    cache = Path.home() / ".cache" / "opensleuth-icons"
    cache.mkdir(parents=True, exist_ok=True)
    p = cache / (bundle.replace("/", "_") + ".png")
    return p if p.exists() else None


def _warm_icons():
    import queue

    q = queue.Queue()
    for b in RCONS["queue"]:
        q.put(b)

    def worker():
        while True:
            try:
                b = q.get_nowait()
            except queue.Empty:
                return
            cache = Path.home() / ".cache" / "opensleuth-icons"
            cache.mkdir(parents=True, exist_ok=True)
            p = cache / (b.replace("/", "_") + ".png")
            if p.exists():
                RCONS["done"] += 1
                continue
            try:
                r = _run([sys.executable, "-m", "pymobiledevice3", "springboard", "icon",
                          b, str(p)], timeout=8)
                if r.returncode == 0 and p.exists():
                    RCONS["done"] += 1
                else:
                    RCONS["failed"] += 1
            except Exception:
                RCONS["failed"] += 1

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    RCONS["running"] = False


def _sqlite(path_str, table=None):
    p = _safe_case_file(path_str)
    if not p:
        return {"error": "file not found under ~/cases"}
    import sqlite3
    try:
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        if not table:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            conn.close()
            return {"tables": tables}
        cur = conn.execute(f'SELECT * FROM "{table}" LIMIT 200')
        cols = [d[0] for d in cur.description]
        rows = []
        for row in cur.fetchall():
            rows.append([("" if row[c] is None else str(row[c])[:120]) for c in cols])
        conn.close()
        return {"columns": cols, "rows": rows}
    except Exception as exc:
        return {"error": str(exc)}


def _export(case_id):
    dest = Path.home() / "cases" / case_id
    if not dest.is_dir():
        return {"error": "unknown case"}
    out = dest / f"{case_id}-export.tar.gz"
    try:
        subprocess.run(["tar", "-czf", str(out), "-C", str(dest),
                        "--exclude=backup", "."], capture_output=True, timeout=300)
        _notify("Export Ready", f"Evidence archive ready for case {case_id} ({out.stat().st_size} bytes).", "info", "EVIDENCE")
        return {"url": "/api/file?path=" + quote(str(out)), "size": out.stat().st_size}
    except Exception as exc:
        return {"error": str(exc)}


def _parse_image(path_str):
    p = Path(path_str).expanduser()
    cases_root = (Path.home() / "cases").resolve()
    try:
        rp = p.resolve()
        if not rp.is_relative_to(cases_root):
            return {"error": "path must be a backup directory under ~/cases"}
    except OSError:
        return {"error": "invalid path"}
    if not (p / "Manifest.db").is_file():
        return {"error": "not a backup directory (Manifest.db missing)"}
    try:
        subprocess.run([sys.executable, "-m", "opensleuth", "dump", str(p),
                        "-o", str(p.parent / "report")], capture_output=True, timeout=600)
        return {"ok": True, "report": str(p.parent / "report" / "report.html")}
    except Exception as exc:
        return {"error": str(exc)}


def _log_tail(case_id, lines=30):
    dest = Path.home() / "cases" / case_id
    log = dest / "acquire.log"
    if not log.is_file():
        return []
    try:
        return log.read_text(errors="replace").splitlines()[-lines:]
    except OSError:
        return []


def _dump_apps(data):
    dest = Path(data.get("destination", ""))
    apps = data.get("apps") or []
    if not dest.is_dir():
        return {"error": "case directory missing"}
    backups = list((dest / "backup").glob("*/Manifest.db")) if (dest / "backup").is_dir() else []
    if not backups:
        return {"error": "no backup yet — run a full acquisition first (requires the phone to be unlocked once)"}
    domains = ",".join(f"AppDomain-{b}" for b in apps)
    try:
        r = subprocess.run(
            [sys.executable, "-m", "opensleuth", "extract", str(backups[0].parent),
             "-o", str(dest / "appdata"), "--domains", domains],
            capture_output=True, text=True, timeout=900)
        return {"ok": r.returncode == 0, "output": (r.stdout + r.stderr)[-400:]}
    except Exception as exc:
        return {"error": str(exc)}


def _bfu(data):
    dest = Path(data.get("destination", ""))
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / "bfu"
    cmd = [sys.executable, "-m", "opensleuth", "acquire", "bfu", "--out", str(out)]
    if data.get("chip"):
        cmd += ["--chip", data["chip"]]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return {"ok": r.returncode == 0, "output": (r.stdout + r.stderr)[-1400:]}
    except Exception as exc:
        return {"error": str(exc)}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/json"):
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            if body is not None:
                self.wfile.write(body if isinstance(body, bytes) else body.encode())
        except (BrokenPipeError, ConnectionResetError, OSError):
            # client (desktop/web poller) disconnected mid-response - ignore
            pass

    def _serve_file(self, path):
        full = STATIC / path.lstrip("/")
        if full.is_dir():
            full = full / "index.html"
        try:
            inside = full.resolve().is_relative_to(STATIC.resolve())
        except OSError:
            inside = False
        if not full.is_file() or not inside:
            self._send(404, b"not found")
            return
        ctype = "text/html"
        if full.suffix == ".css":
            ctype = "text/css"
        elif full.suffix == ".js":
            ctype = "application/javascript"
        elif full.suffix == ".svg":
            ctype = "image/svg+xml"
        elif full.suffix == ".png":
            ctype = "image/png"
        elif full.suffix == ".json":
            ctype = "application/json"
        self._send(200, full.read_bytes(), ctype)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/device":
            self._send(200, json.dumps(_device() or {}))
        elif path == "/api/apps":
            self._send(200, json.dumps(_apps()))
        elif path == "/api/cases":
            self._send(200, json.dumps(_cases()))
        elif path == "/api/artifacts":
            qs = parse_qs(parsed.query)
            self._send(200, json.dumps(_artifacts(qs.get("case", [""])[0])))
        elif path == "/api/matrix":
            qs = parse_qs(parsed.query)
            from ..matrix import recommend
            steps = recommend(qs.get("chip", ["A13"])[0], qs.get("ios", ["?"])[0])
            self._send(200, json.dumps({"steps": steps}))
        elif path == "/api/exploits":
            qs = parse_qs(parsed.query)
            from ..exploits import (RECENT_DISCLOSURES, ROUTES, default_recommendation,
                                    render_disclosures, expose)
            chip = qs.get("chip", [""])[0]
            ios = qs.get("ios", [""])[0]
            layer = qs.get("layer", [""])[0]
            no_hw = qs.get("no_hardware", ["0"])[0] in ("1", "true", "yes")
            routes = ROUTES
            if chip:
                routes = [r for r in routes if chip.upper() in r["chips"]]
            if layer:
                routes = [r for r in routes if r["layer"] == layer]
            if no_hw:
                routes = [r for r in routes if r["hardware"] != "rig"]
            payload = {
                "routes": routes,
                "disclosures": RECENT_DISCLOSURES,
                "count": len(routes),
                "disclosure_count": len(RECENT_DISCLOSURES),
            }
            if chip and ios:
                payload["exposure"] = expose(chip, ios)
            if chip:
                try:
                    payload["recommendation"] = default_recommendation(chip)
                except Exception:
                    payload["recommendation"] = []
            self._send(200, json.dumps(payload, default=str))
        elif path == "/api/notifications":
            self._send(200, json.dumps({"notifications": NOTIFICATIONS}))
        elif path == "/api/settings":
            self._send(200, json.dumps(_get_settings()))
        elif path == "/api/autoexploit":
            self._send(200, json.dumps({
                "running": AEXPLOIT["running"],
                "error": AEXPLOIT["error"],
                "report": AEXPLOIT["report"],
                "log": AEXPLOIT["log"],
                "finished_at": AEXPLOIT["finished_at"],
            }, default=str))
        elif path == "/api/plan2":
            from ..fingerprint import fingerprint_device, render as fp_render
            from ..planner import Planner, render_plan
            fp = fingerprint_device()
            methods = Planner().plan(fp)
            self._send(200, json.dumps({
                "fingerprint": fp.to_dict(),
                "methods": [m.__dict__ for m in methods],
                "selectable": [m.capability_id for m in methods if m.selectable()],
                "text": fp_render(fp) + "\n" + render_plan(methods, fp),
            }, default=str))
        elif path == "/api/journal":
            qs = parse_qs(parsed.query)
            case_id = qs.get("case", [""])[0]
            if not case_id:
                cs = _cases()
                if cs:
                    case_id = cs[0].get("case_id", "")
            if not case_id:
                self._send(200, json.dumps({"sessions": []}))
                return
            case_dir = Path.home() / "cases" / case_id
            jdir = case_dir / "journal"
            sessions = []
            if jdir.is_dir():
                from ..journal import SessionJournal, verify_journal_file
                for f in sorted(jdir.glob("S-*.jsonl")):
                    j = SessionJournal(case_dir, f.stem)
                    s = j.summary()
                    s["verify"] = verify_journal_file(f)
                    s["replay"] = j.replay()
                    sessions.append(s)
            self._send(200, json.dumps({"case": case_id,
                                        "sessions": sessions}, default=str))
        elif path == "/api/tools":
            from .. import forensics
            self._send(200, json.dumps({
                "tools": forensics.detect(),
                "summary": forensics.summary(),
            }))
        elif path == "/api/doctor":
            from .. import doctor
            self._send(200, json.dumps(doctor.run(), default=str))
        elif path == "/api/uco":
            qs = parse_qs(parsed.query)
            case_id = qs.get("case", [""])[0]
            if not case_id:
                cs = _cases()
                if cs:
                    case_id = cs[0].get("case_id", "")
            dest = Path.home() / "cases" / case_id / "report" / "case_uco.jsonld"
            if dest.is_file():
                try:
                    self._send(200, dest.read_text(), "application/ld+json")
                    return
                except Exception:
                    pass
            self._send(404, b'{"error":"case_uco.jsonld not found"}', "application/json")
        elif path == "/api/multihash":
            qs = parse_qs(parsed.query)
            p = _safe_case_file(qs.get("path", [""])[0])
            if not p:
                self._send(400, b'{"error":"invalid path under ~/cases"}', "application/json")
                return
            from .. import cxx
            self._send(200, json.dumps(cxx.multihash_file(p)))
        elif path == "/api/stance":
            from .. import forensics
            self._send(200, json.dumps({
                "competitors": forensics.COMPETITORS,
                "rows": forensics.STANCE_ROWS,
                "status_map": forensics._STATUS,
                "gaps": forensics.GAP_LINES,
            }))
        elif path == "/api/bfu":
            qs = parse_qs(parsed.query)
            from ..bfu import expectations, usbliter8_plan
            chip = (qs.get("chip", [""])[0] or (_device() or {}).get("chip") or "A13").upper()
            ios = qs.get("ios", [""])[0]
            plan = usbliter8_plan(chip)
            self._send(200, json.dumps({
                "expectations": expectations(chip, ios),
                "playbook": plan,
            }, default=str))
        elif path == "/api/escrow":
            qs = parse_qs(parsed.query)
            from .. import escrow
            d = qs.get("dir", [""])[0]
            if not d:
                self._send(400, b'{"error":"dir required"}', "application/json")
                return
            found = escrow.find_records(d)
            self._send(200, json.dumps({"dir": d, "found": found}, default=str))
        elif path == "/api/keybag":
            qs = parse_qs(parsed.query)
            from ..keybag import KeybagError, render_status
            f = qs.get("file", [""])[0]
            if not f:
                self._send(400, b'{"error":"file required"}', "application/json")
                return
            try:
                self._send(200, json.dumps({"ok": True, "text": render_status(f)}))
            except (KeybagError, OSError) as exc:
                self._send(200, json.dumps({"ok": False, "error": str(exc)}))
        elif path == "/api/appcatalog":
            qs = parse_qs(parsed.query)
            from .. import appcatalog
            d = qs.get("dir", [""])[0]
            if not d:
                self._send(400, b'{"error":"dir required"}', "application/json")
                return
            dbs = appcatalog.find_dbs(Path(d))
            inv = []
            for db in dbs:
                i = appcatalog.inventory(Path(db["path"]))
                if i:
                    inv.append({**db, **i})
            self._send(200, json.dumps({"dir": d, "count": len(inv), "databases": inv},
                                       default=str))
        elif path == "/api/escrow/unlock":
            qs = parse_qs(parsed.query)
            from .. import escrow
            rec = qs.get("record", [""])[0]
            bk = qs.get("backup", [""])[0]
            out = qs.get("out", [""])[0]
            if not (rec and bk and out):
                self._send(400, b'{"error":"record, backup and out required"}', "application/json")
                return
            r = escrow.unlock_backup(rec, bk, out)
            self._send(200, json.dumps(r, default=str))
        elif path == "/api/campaign":
            from .. import campaign as C
            from ..dfutrace import analyze, parse_usbmon_text
            qs = parse_qs(parsed.query)
            state = C.load()
            if path.endswith("/campaign") and self.command == "POST":
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                if body.get("action") == "new":
                    c = C.new_campaign(state, body.get("name", "unnamed"),
                                       body.get("target", "DFU"),
                                       chip=body.get("chip", ""),
                                       ios=body.get("ios", ""))
                    C.save(state)
                    self._send(200, json.dumps({"ok": True, "campaign": c}))
                    return
                if body.get("action") == "triage":
                    lead = C.triage_lead(state, body["lead_id"],
                                         body["verdict"], notes=body.get("notes", ""))
                    C.save(state)
                    self._send(200, json.dumps({"ok": True, "lead": lead}))
                    return
                if body.get("action") == "dry-run":
                    capture = body.get("capture", "")
                    rep = analyze(parse_usbmon_text(capture))
                    session = C.start_session(state, body.get("campaign_id", ""), kind="dry-analysis")
                    C.finish_session(state, session["id"], {"iterations": 0})
                    for anomaly in rep.get("anomalies", [])[:10]:
                        C.add_lead(state, session["id"], "trace-anomaly", anomaly,
                                   campaign_id=body.get("campaign_id", ""))
                    C.save(state)
                    self._send(200, json.dumps({"ok": True, "session": session,
                                                "analysis": {"anomalies": rep["anomalies"],
                                                             "dfu_requests": rep["dfu_requests"]}}))
                    return
                self._send(400, b'{"error":"unknown action"}', "application/json")
                return
            self._send(200, json.dumps(state, default=str))
        elif path == "/api/bfufs":
            qs = parse_qs(parsed.query)
            from .. import bfufs
            d = qs.get("dir", [""])[0]
            if not d:
                self._send(400, b'{"error":"dir required"}', "application/json")
                return
            rows = bfufs.scan_fs(d)
            rep = bfufs.classify(rows)
            rep.pop("readable_now", None)
            rep.pop("metadata_targets", None)
            self._send(200, json.dumps({"summary": rep,
                                        "readable": [r for r in rows if r["readable_now"]][:500],
                                        "targets": [r for r in rows if r["metadata_only"]][:500]},
                                       default=str))
        elif path == "/api/certify":
            qs = parse_qs(parsed.query)
            from .. import certify
            if qs.get("verify"):
                v = certify.verify(qs["verify"][0])
                self._send(200, json.dumps(v, default=str))
                return
            self._send(400, b'{"error":"verify=<report> required"}', "application/json")
        elif path == "/api/firmware":
            qs = parse_qs(parsed.query)
            from .. import firmware
            d = qs.get("dir", [""])[0]
            if not d:
                self._send(400, b'{"error":"dir required"}', "application/json")
                return
            self._send(200, json.dumps({"images": firmware.scan_dir(d)}, default=str))
        elif path == "/api/crashlogs":
            qs = parse_qs(parsed.query)
            from .. import crashlogs
            d = qs.get("dir", [""])[0]
            if not d:
                self._send(400, b'{"error":"dir required"}', "application/json")
                return
            rows = crashlogs.scan_dir(d)
            self._send(200, json.dumps({"summary": crashlogs.summarize(rows),
                                        "crashes": rows[:500]}, default=str))
        elif path == "/api/wireless":
            qs = parse_qs(parsed.query)
            from .. import wireless
            d = qs.get("dir", [""])[0]
            if not d:
                self._send(400, b'{"error":"dir required"}', "application/json")
                return
            self._send(200, json.dumps(wireless.scan(d), default=str))
        elif path == "/api/sysdiagnose":
            qs = parse_qs(parsed.query)
            from .. import sysdiagnose as SD
            d = qs.get("dir", [""])[0]
            if not d:
                self._send(400, b'{"error":"dir required"}', "application/json")
                return
            self._send(200, json.dumps(SD.inventory(d), default=str))
        elif path == "/api/knowledgec":
            qs = parse_qs(parsed.query)
            from .. import knowledgec as KC
            d = qs.get("dir", [""])[0]
            if not d:
                self._send(400, b'{"error":"dir required"}', "application/json")
                return
            dbs = KC.find_knowledgec(d)
            rows = []
            for db in dbs[:3]:
                rows.extend(KC.parse_knowledgec(db, limit=5000))
            self._send(200, json.dumps({"dbs": [str(x) for x in dbs],
                                        "events": rows[:5000],
                                        "top_apps": KC.app_usage_summary(rows)}, default=str))
        elif path == "/api/surface":
            from .. import surface
            from ..exploits import RECENT_DISCLOSURES
            rep = surface.analyze(RECENT_DISCLOSURES)
            rep_rows = rep.pop("rows")
            self._send(200, json.dumps({"analysis": rep,
                                        "targets": surface.research_targets(rep),
                                        "rows": rep_rows}, default=str))
        elif path == "/api/doctor":
            from .. import doctor
            self._send(200, json.dumps(doctor.run(), default=str))
        elif path.startswith("/api/icon/"):
            bundle = unquote(path[len("/api/icon/"):])
            p = _icon(bundle)
            if p:
                self._send(200, p.read_bytes(), "image/png")
            else:
                self._send(404, b"")
        elif path == "/api/icons-status":
            self._send(200, json.dumps({**RCONS, "queue": RCONS.get("queue", [])}))
        elif path == "/api/file":
            qs = parse_qs(parsed.query)
            p = _safe_case_file(unquote(qs.get("path", [""])[0]))
            if p:
                import mimetypes
                ctype = mimetypes.guess_type(str(p))[0] or "application/octet-stream"
                self._send(200, p.read_bytes(), ctype)
            else:
                self._send(404, b"")
        elif path == "/api/sqlite":
            qs = parse_qs(parsed.query)
            p = unquote(qs.get("path", [""])[0])
            t = qs.get("table", [None])[0]
            self._send(200, json.dumps(_sqlite(p, t)))
        elif path == "/api/log":
            qs = parse_qs(parsed.query)
            cid = qs.get("case", [""])[0]
            if not cid:
                cs = _cases()
                cid = cs[0]["case_id"] if cs else ""
            self._send(200, json.dumps({"lines": _log_tail(cid)}))
        elif path.startswith("/api/"):
            self._send(404, b"{}" if self.headers.get("Accept", "").startswith("application/json") else b"not found")
        elif path == "/":
            self._serve_file("/index.html")
        else:
            self._serve_file(path)

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        data = json.loads(body) if body else {}
        if parsed.path == "/api/certify":
            from .. import certify
            try:
                r = certify.certify(data.get("case_dir", ""), data.get("out", ""),
                                    data.get("examiner", "UI Examiner"))
                self._send(200, json.dumps({k: v for k, v in r.items()
                                            if k != "seal_key"}, default=str))
            except (FileNotFoundError, OSError) as exc:
                self._send(400, json.dumps({"error": str(exc)}).encode(),
                           "application/json")
            return
        if parsed.path == "/api/campaign":
            from .. import campaign as C
            state = C.load()
            try:
                if data.get("action") == "new":
                    c = C.new_campaign(state, data.get("name", "unnamed"),
                                       data.get("target", "DFU"),
                                       chip=data.get("chip", ""), ios=data.get("ios", ""))
                    C.save(state)
                    self._send(200, json.dumps({"ok": True, "campaign": c}))
                elif data.get("action") == "triage":
                    lead = C.triage_lead(state, data["lead_id"], data["verdict"],
                                         notes=data.get("notes", ""))
                    C.save(state)
                    self._send(200, json.dumps({"ok": True, "lead": lead}))
                elif data.get("action") == "dry-run":
                    from ..dfutrace import analyze, parse_usbmon_text
                    rep = analyze(parse_usbmon_text(data.get("capture", "")))
                    session = C.start_session(state, data.get("campaign_id", ""), kind="dry-analysis")
                    C.finish_session(state, session["id"], {"iterations": 0})
                    for anomaly in rep.get("anomalies", [])[:10]:
                        C.add_lead(state, session["id"], "trace-anomaly", anomaly,
                                   campaign_id=data.get("campaign_id", ""))
                    C.save(state)
                    self._send(200, json.dumps({"ok": True, "session": session,
                                                "anomalies": rep["anomalies"]}))
                else:
                    self._send(400, b'{"error":"unknown action"}', "application/json")
            except (KeyError, ValueError) as exc:
                self._send(400, json.dumps({"error": str(exc)}).encode(), "application/json")
            return
        if parsed.path == "/api/case":
            cases_root = (Path.home() / "cases").resolve()
            default_dest = str(cases_root / data.get("case_id", "default"))
            dest = Path(data.get("destination", default_dest)).expanduser()
            try:
                rp = dest.resolve()
            except OSError:
                self._send(400, json.dumps(
                    {"error": "invalid destination"}).encode(),
                    "application/json")
                return
            if not rp.is_relative_to(cases_root):
                self._send(400, json.dumps(
                    {"error": "destination must be under ~/cases"}).encode(),
                    "application/json")
                return
            dest = rp
            dest.mkdir(parents=True, exist_ok=True)
            cj = dest / "case.json"
            existing = {}
            if cj.is_file():
                try:
                    existing = json.loads(cj.read_text())
                except Exception:
                    pass
            if data.get("add_evidence_source"):
                existing.setdefault("evidence_sources", []).append(data["add_evidence_source"])
                data.pop("add_evidence_source")
            existing.update(data)
            cj.write_text(json.dumps(existing, indent=2))
            self._send(200, json.dumps({"saved": True, "case": existing}))
        elif parsed.path == "/api/icons-warm":
            if not RCONS["running"]:
                apps = _apps()
                RCONS.update(total=len(apps), done=0, failed=0, running=True,
                             queue=[a["bundle"] for a in apps])
                threading.Thread(target=_warm_icons, daemon=True).start()
            self._send(200, json.dumps({"started": RCONS["running"], "total": RCONS["total"]}))
        elif parsed.path == "/api/acquire":
            dest = Path(data.get("destination", ""))
            cases_root = (Path.home() / "cases").resolve()
            try:
                rp = dest.expanduser().resolve()
            except OSError:
                rp = None
            if rp is None or not rp.is_relative_to(cases_root):
                self._send(400, json.dumps(
                    {"error": "destination must be under ~/cases"}).encode(),
                    "application/json")
                return
            dest = rp
            dest.mkdir(parents=True, exist_ok=True)
            # kick off actual acquisition in a background thread
            threading.Thread(target=self._do_acquire, args=(data,), daemon=True).start()
            self._send(200, json.dumps({"started": True, "destination": str(dest)}))
        elif parsed.path == "/api/autoexploit":
            if AEXPLOIT["running"]:
                self._send(200, json.dumps({"started": False, "busy": True}))
                return
            allow_destruct = bool(data.get("allow_destructive"))
            AEXPLOIT["allow_destructive"] = allow_destruct
            threading.Thread(target=_run_autoexploit,
                             args=(allow_destruct,), daemon=True).start()
            self._send(200, json.dumps({"started": True, "allow_destructive": allow_destruct}))
        elif parsed.path == "/api/hash":
            self._send(200, json.dumps(_sha256(data.get("path", ""))))
        elif parsed.path == "/api/report":
            self._send(200, json.dumps(_report(data.get("case", {}))))
        elif parsed.path == "/api/export":
            self._send(200, json.dumps(_export(data.get("case_id", ""))))
        elif parsed.path == "/api/parse-image":
            self._send(200, json.dumps(_parse_image(data.get("path", ""))))
        elif parsed.path == "/api/dump-apps":
            self._send(200, json.dumps(_dump_apps(data)))
        elif parsed.path == "/api/bfu":
            self._send(200, json.dumps(_bfu(data)))
        elif parsed.path == "/api/notifications/clear":
            NOTIFICATIONS.clear()
            self._send(200, b'{"ok":true}')
        elif parsed.path == "/api/settings":
            self._send(200, json.dumps(_save_settings(data)))
        elif parsed.path == "/api/exploit/execute":
            self._send(200, json.dumps(_execute_single_route(data.get("route", ""), data.get("allow_destructive", False))))
        elif parsed.path == "/api/timeline":
            self._send(200, json.dumps(_generate_timeline(data.get("case_id", ""))))
        else:
            self._send(404, b"{}" if self.headers.get("Accept", "").startswith("application/json") else b"not found")

    def _do_acquire(self, data):
        from ..journal import new_session
        dest = Path(data["destination"])
        log_path = dest / "acquire.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        jrn = new_session(dest, operator=data.get("operator", "web-studio"))
        with open(log_path, "a", encoding="utf-8") as fh:
            def log(s):
                fh.write(f"{datetime.now().isoformat()} {s}\n"); fh.flush()
            log("acquire task starting")
            _notify("Acquisition Started", f"Logical acquisition started for {dest.name}.", "info", "FORENSICS")
            jrn.emit("AcquisitionStarted", {"method": "logical-suite",
                                            "destination": str(dest)})
            steps = ["backup", "media", "crash", "diag", "syslog"]
            for step in steps:
                log(f"step={step} starting")
                if step == "backup":
                    cmd = [sys.executable, "-m", "pymobiledevice3", "backup2", "backup",
                           str(dest / "backup"), "--full"]
                    if data.get("password"):
                        cmd += ["--password", data["password"], "--unback"]
                    try:
                        r = subprocess.run(cmd, capture_output=True, text=True, timeout=None)
                        log(f"step=backup rc={r.returncode} err={r.stderr[-200:]}")
                    except Exception as exc:
                        log(f"step=backup exception {exc}")
                    continue
                if step == "media":
                    mnt = tempfile.mkdtemp(prefix="sleuth-web-mnt-")
                    try:
                        r = _run(["ifuse", mnt], timeout=60)
                    except FileNotFoundError:
                        log("step=media ifuse not installed - skipping")
                        shutil.rmtree(mnt, ignore_errors=True)
                        continue
                        if r.returncode == 0:
                            for d in ("DCIM", "Downloads", "Recordings"):
                                src = Path(mnt) / d
                                if src.exists():
                                    _run(["rsync", "-a", str(src) + "/", str(dest / "media" / d) + "/"],
                                         timeout=None)
                                    log(f"media copied {d}")
                    finally:
                        _run(["fusermount", "-u", mnt], timeout=30)
                    continue
                if step == "crash":
                    try:
                        r = _run([sys.executable, "-m", "pymobiledevice3", "crash", "pull",
                                  str(dest / "crash")], timeout=600)
                        log(f"step=crash rc={r.returncode}")
                    except Exception as exc:
                        log(f"step=crash exception {exc}")
                    continue
                if step == "diag":
                    info = dest / "info"
                    info.mkdir(exist_ok=True)
                    try:
                        r = _run(["ideviceinfo"], timeout=60)
                        (info / "device.json").write_text(json.dumps(
                            dict(l.split(": ", 1) for l in r.stdout.splitlines() if ": " in l), indent=2))
                        for name, c in [("gestalt.json", ["diagnostics", "mg"]),
                                        ("battery.json", ["diagnostics", "battery", "single"]),
                                        ("processes.json", ["processes"])]:
                            try:
                                rr = _run([sys.executable, "-m", "pymobiledevice3"] + c, timeout=90)
                                if rr.returncode == 0:
                                    (info / name).write_text(rr.stdout)
                            except Exception:
                                pass
                        log("diagnostics saved")
                    except Exception as exc:
                        log(f"step=diag exception {exc}")
                    continue
                if step == "syslog":
                    try:
                        with open(dest / "syslog.txt", "wb") as fh2:
                            subprocess.run(["timeout", "30", sys.executable, "-m", "pymobiledevice3", "syslog"],
                                           stdout=fh2, timeout=45)
                        log("syslog captured")
                    except Exception as exc:
                        log(f"step=syslog exception {exc}")
                    continue
            backups = list((dest / "backup").glob("*/Manifest.db")) if (dest / "backup").is_dir() else []
            if backups:
                log("parsing backup into artifact report")
                try:
                    subprocess.run([sys.executable, "-m", "opensleuth", "dump",
                                    str(backups[0].parent), "-o", str(dest / "report")],
                                   capture_output=True, timeout=600)
                    log("report ready")
                    jrn.emit("ReportGenerated", {"path": str(dest / "report")})
                except Exception as exc:
                    log(f"dump exception {exc}")
                    jrn.failure("ParserFailure", "dump",
                                "backup parsing failed",
                                technical_message=str(exc))
            log("acquire task complete")
            _notify("Acquisition Complete", f"Extraction completed successfully to {dest.name}.", "success", "FORENSICS")
            jrn.emit("AcquisitionCompleted", {"destination": str(dest)})
            jrn.complete({"destination": str(dest)})


def main(argv=None):
    import argparse

    ap = argparse.ArgumentParser(prog="opensleuth.studio_web")
    ap.add_argument("--host", default=os.environ.get("OPENSLEUTH_HOST", "127.0.0.1"),
                    help="bind address (default 127.0.0.1 - loopback only; "
                         "use 0.0.0.0 only on a trusted network / tunnel)")
    args = ap.parse_args(argv)
    print(f"opensleuth web studio: http://{args.host}:{PORT}")
    HTTPServer((args.host, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
