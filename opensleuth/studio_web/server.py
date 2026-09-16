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


def _device():
    try:
        p = _run(["pymobiledevice3", "usbmux", "list"], timeout=15)
        if p.returncode == 0:
            devs = json.loads(p.stdout)
            if devs:
                d = devs[0]
                state = "BFU"
                try:
                    v = _run(["idevicepair", "validate"], timeout=15)
                    if v.returncode == 0 and "SUCCESS" in v.stdout:
                        state = "AFU"
                except Exception:
                    pass
                from ..matrix import chip_for, KNOWN_DEVICES
                pt = d.get("ProductType", "")
                return {
                    "model": KNOWN_DEVICES.get(pt, (pt, None))[0] or pt,
                    "product_type": pt,
                    "ios": d.get("ProductVersion", "?"),
                    "build": d.get("BuildVersion", "?"),
                    "udid": d.get("Identifier") or d.get("UniqueDeviceID", ""),
                    "state": state,
                    "chip": chip_for(pt) or "?",
                }
    except Exception as exc:
        return {"error": str(exc)}
    return None


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
        if not str(p.resolve()).startswith(str(cases_root.resolve())) or not p.is_file():
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
        return {"ok": True, "report": str(dest / "report" / "report.html")}
    except Exception as exc:
        return {"error": str(exc)}


def _safe_case_file(path_str):
    p = Path(path_str).expanduser()
    root = (Path.home() / "cases").resolve()
    try:
        rp = p.resolve()
        if str(rp).startswith(str(root)) and rp.is_file():
            return rp
    except OSError:
        pass
    return None


RCONS = {"total": 0, "done": 0, "failed": 0, "running": False}


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
        return {"url": "/api/file?path=" + quote(str(out)), "size": out.stat().st_size}
    except Exception as exc:
        return {"error": str(exc)}


def _parse_image(path_str):
    p = Path(path_str).expanduser()
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
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if body is not None:
            self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def _serve_file(self, path):
        full = STATIC / path.lstrip("/")
        if full.is_dir():
            full = full / "index.html"
        if not full.is_file() or str(full.resolve())[:len(str(STATIC.resolve()))] != str(STATIC.resolve()):
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
        elif path == "/api/tools":
            from .. import forensics
            self._send(200, json.dumps({
                "tools": forensics.detect(),
                "summary": forensics.summary(),
            }))
        elif path == "/api/stance":
            from .. import forensics
            self._send(200, json.dumps({
                "competitors": forensics.COMPETITORS,
                "rows": forensics.STANCE_ROWS,
                "status_map": forensics._STATUS,
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
        if parsed.path == "/api/case":
            dest = Path(data.get("destination", str(Path.home() / "cases" / data.get("case_id", "default"))))
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
            dest = Path(data.get("destination"))
            dest.mkdir(parents=True, exist_ok=True)
            # kick off actual acquisition in a background thread
            threading.Thread(target=self._do_acquire, args=(data,), daemon=True).start()
            self._send(200, json.dumps({"started": True, "destination": str(dest)}))
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
        else:
            self._send(404, b"{}" if self.headers.get("Accept", "").startswith("application/json") else b"not found")

    def _do_acquire(self, data):
        dest = Path(data["destination"])
        log_path = dest / "acquire.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as fh:
            def log(s):
                fh.write(f"{datetime.now().isoformat()} {s}\n"); fh.flush()
            log("acquire task starting")
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
                except Exception as exc:
                    log(f"dump exception {exc}")
            log("acquire task complete")


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
