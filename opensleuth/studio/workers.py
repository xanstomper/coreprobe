"""Background workers: device polling, app discovery w/ icons, acquisition runner."""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal

from ..matrix import KNOWN_DEVICES, chip_for


def _run(cmd, timeout=60):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class DeviceWorker(QThread):
    """Poll usbmuxd; report device info + AFU/BFU state."""

    device_found = pyqtSignal(dict)
    lost = pyqtSignal()

    def run(self):
        devices = []
        try:
            p = _run(["pymobiledevice3", "usbmux", "list"], timeout=20)
            if p.returncode == 0:
                devices = json.loads(p.stdout)
        except Exception:
            devices = []
        if not devices:
            self.lost.emit()
            return
        d = devices[0]
        product_type = d.get("ProductType", "")
        friendly = KNOWN_DEVICES.get(product_type, (product_type, None))[0]
        state = "BFU"
        try:
            v = _run(["idevicepair", "validate"], timeout=20)
            if v.returncode == 0 and "SUCCESS" in v.stdout:
                state = "AFU"
        except Exception:
            pass
        self.device_found.emit(
            {
                "model": friendly,
                "product_type": product_type,
                "ios": d.get("ProductVersion", "?"),
                "build": d.get("BuildVersion", "?"),
                "udid": d.get("Identifier") or d.get("UniqueDeviceID", ""),
                "state": state,
                "chip": chip_for(product_type) or "?",
            }
        )


class AppListWorker(QThread):
    """Enumerate user apps, then fetch each icon via SpringBoard (best-effort)."""

    app_found = pyqtSignal(dict)  # {"name","bundle","version","icon":path|None}
    done = pyqtSignal(int)

    def __init__(self, icon_dir, parent=None):
        super().__init__(parent)
        self.icon_dir = Path(icon_dir)
        self.icon_dir.mkdir(parents=True, exist_ok=True)

    def run(self):
        try:
            p = _run(["ideviceinstaller", "-l", "-o", "list_user"], timeout=60)
        except Exception:
            self.done.emit(0)
            return
        apps = []
        for line in p.stdout.splitlines()[1:]:
            parts = [x.strip().strip('"') for x in line.split(",")]
            if len(parts) >= 3 and parts[0]:
                apps.append((parts[2], parts[0], parts[1]))
        for name, bundle, version in apps:
            icon = self.icon_dir / f"{bundle.replace('/', '_')}.png"
            if not icon.exists():
                try:
                    r = _run(["pymobiledevice3", "springboard", "icon", bundle, str(icon)], timeout=15)
                    if r.returncode != 0 or not icon.exists():
                        icon = None
                except Exception:
                    icon = None
            self.app_found.emit({"name": name, "bundle": bundle, "version": version,
                                 "icon": str(icon) if icon else None})
        self.done.emit(len(apps))


class AcquireWorker(QThread):
    """Run the selected acquisition steps sequentially; stream progress."""

    step_start = pyqtSignal(str)
    step_done = pyqtSignal(str, bool, str)
    log = pyqtSignal(str)
    progress = pyqtSignal(int)
    finished_all = pyqtSignal(bool)

    def __init__(self, dest: Path, device: dict, options: dict, selected_apps: list, password: str = ""):
        super().__init__()
        self.dest = Path(dest)
        self.device = device
        self.options = options          # {"backup":bool,"encrypted":bool,"media":bool,"crash":bool,"diag":bool,"syslog":bool,"apps":bool}
        self.selected_apps = selected_apps  # list of bundle ids (AppDomain- prefixed at use time)
        self.password = password

    def _emit_log(self, s):
        for line in str(s).splitlines()[-3:]:
            if line.strip():
                self.log.emit(line.strip()[:300])

    def _step(self, name, fn):
        self.step_start.emit(name)
        try:
            note = fn() or "ok"
            self.step_done.emit(name, True, note)
            return True
        except Exception as exc:  # noqa: BLE001
            self.step_done.emit(name, False, str(exc)[:200])
            return False

    def run(self):
        self.dest.mkdir(parents=True, exist_ok=True)
        steps = []
        if self.options.get("backup"):
            steps.append(("Full backup", self._backup))
        if self.options.get("media"):
            steps.append(("Media (AFC)", self._media))
        if self.options.get("crash"):
            steps.append(("Crash reports", self._crash))
        if self.options.get("diag"):
            steps.append(("Diagnostics + info", self._diag))
        if self.options.get("syslog"):
            steps.append(("Syslog capture", self._syslog))
        if self.options.get("apps") and self.selected_apps:
            steps.append(("App containers", self._app_extract))
        ok = True
        for i, (name, fn) in enumerate(steps, 1):
            ok = self._step(name, fn) and ok
            self.progress.emit(int(i / max(1, len(steps)) * 100))
        self.finished_all.emit(ok)

    # ------------------------------------------------------------- steps
    def _backup(self):
        bdir = self.dest / "backup"
        bdir.mkdir(exist_ok=True)
        cmd = [sys.executable, "-m", "pymobiledevice3", "backup2", "backup", str(bdir), "--full"]
        if self.options.get("encrypted") and self.password:
            cmd += ["--password", self.password, "--unback"]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=None)
        self._emit_log(p.stdout + p.stderr)
        if p.returncode != 0:
            raise RuntimeError(p.stderr.strip()[-200:] or "backup failed")
        return "backup complete"

    def _media(self):
        mnt = Path(tempfile.mkdtemp(prefix="sleuth-media-"))
        try:
            p = subprocess.run(["ifuse", str(mnt)], capture_output=True, text=True, timeout=60)
            if p.returncode != 0:
                raise RuntimeError("ifuse mount failed: " + p.stderr[:150])
            for d in ("DCIM", "Downloads", "Recordings", "Books", "Podcasts"):
                src = mnt / d
                if src.exists():
                    subprocess.run(["rsync", "-a", str(src) + "/", str(self.dest / "media" / d) + "/"],
                                   capture_output=True, timeout=None)
                    self.log.emit(f"copied {d}")
        finally:
            subprocess.run(["fusermount", "-u", str(mnt)], capture_output=True)
        return "media copied"

    def _crash(self):
        out = self.dest / "crash"
        out.mkdir(exist_ok=True)
        p = subprocess.run([sys.executable, "-m", "pymobiledevice3", "crash", "pull", str(out)],
                           capture_output=True, text=True, timeout=600)
        self._emit_log(p.stdout + p.stderr)
        if p.returncode != 0:
            raise RuntimeError("crash pull failed")
        return f"{len(list(out.glob('*')))} reports"

    def _diag(self):
        info = self.dest / "info"
        info.mkdir(exist_ok=True)
        p = _run(["ideviceinfo"], timeout=60)
        (info / "device.json").write_text(
            json.dumps(dict(l.split(": ", 1) for l in p.stdout.splitlines() if ": " in l), indent=2))
        for name, cmd in (
            ("gestalt.json", ["diagnostics", "mg"]),
            ("ioreg.txt", ["diagnostics", "ioregistry"]),
            ("battery.json", ["diagnostics", "battery", "single"]),
            ("wifi.json", ["diagnostics", "battery", "wifi"]),
            ("processes.json", ["processes"]),
            ("orientation.json", ["springboard", "orientation"]),
        ):
            try:
                r = _run([sys.executable, "-m", "pymobiledevice3"] + cmd, timeout=90)
                if r.returncode == 0:
                    (info / name).write_text(r.stdout)
            except Exception as exc:
                self.log.emit(f"skip {name}: {exc}")
        try:
            r = _run([sys.executable, "-m", "pymobiledevice3", "springboard",
                      "wallpaper-home-screen", str(self.dest / "media" / "wallpaper.png")], timeout=60)
            if r.returncode != 0:
                self.log.emit("wallpaper: unavailable (screen locked?)")
        except Exception:
            pass
        return "diagnostics saved"

    def _syslog(self):
        out = self.dest / "syslog.txt"
        with open(out, "wb") as fh:
            subprocess.run(["timeout", "30", sys.executable, "-m", "pymobiledevice3", "syslog"],
                           stdout=fh, timeout=45)
        return "30s captured"

    def _app_extract(self):
        bdir = self.dest / "backup" / self.device.get("udid", "")
        if not (bdir / "Manifest.db").exists():
            raise RuntimeError("needs a completed backup first")
        domains = ",".join(f"AppDomain-{b}" for b in self.selected_apps)
        p = subprocess.run(
            [sys.executable, "-m", "opensleuth", "extract", str(bdir),
             "-o", str(self.dest / "appdata"), "--domains", domains],
            capture_output=True, text=True, timeout=None)
        self._emit_log(p.stdout + p.stderr)
        if p.returncode != 0:
            raise RuntimeError("extract failed")
        return f"{len(self.selected_apps)} apps"


class DumpWorker(QThread):
    """Parse the backup into the artifact report."""

    done = pyqtSignal(dict)

    def __init__(self, dest: Path, udid: str, parent=None):
        super().__init__(parent)
        self.dest = Path(dest)
        self.udid = udid

    def run(self):
        bdir = self.dest / "backup" / self.udid
        out = self.dest / "report"
        counts = {}
        try:
            p = subprocess.run(
                [sys.executable, "-m", "opensleuth", "dump", str(bdir), "-o", str(out)],
                capture_output=True, text=True, timeout=None)
            if p.returncode == 0:
                counts = {"report": str(out)}
                try:
                    data = json.loads((out / "artifacts.json").read_text())
                    for k in ("messages", "contacts", "calls", "history", "bookmarks",
                              "keychain", "voicemail", "notes", "app_databases"):
                        counts[k] = len(data.get(k, []))
                except Exception:
                    pass
        except Exception as exc:  # noqa: BLE001
            counts = {"error": str(exc)}
        self.done.emit(counts)
