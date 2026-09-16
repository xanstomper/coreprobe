"""Native desktop shell for the Forensic Artifact Recovery UI.

Starts the built-in web backend (or reuses a running one) and presents the
workstation interface in a real desktop window via QtWebEngine. Loads the
same UI as the browser build, so every catalog / exploit / report feature is
available natively.

Launch:  python3 -m opensleuth.studio_desktop
"""

import http.server
import json
import socket
import sys
import threading
from urllib.request import urlopen

from PyQt6.QtCore import QUrl, Qt, QTimer
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import QApplication, QMainWindow, QToolBar, QMessageBox
from PyQt6.QtWebEngineWidgets import QWebEngineView

PORT = 9121
VERSION = "CoreProbe 0.2 desktop"

NAV = [
    ("dashboard", "Dashboard", "Ctrl+1"),
    ("exploits", "Exploits", "Ctrl+2"),
    ("research", "Research", "Ctrl+6"),
    ("bfu", "BFU Lab", "Ctrl+7"),
    ("evidence", "Evidence", "Ctrl+8"),
    ("artifacts", "Artifacts", "Ctrl+9"),
    ("reports", "Reports", "Ctrl+3"),
    ("devices", "Devices", "Ctrl+4"),
    ("settings", "Settings", "Ctrl+5"),
]


def ensure_server():
    """Reuse an already-running backend, otherwise start one in-process."""
    s = socket.socket()
    try:
        s.settimeout(1.0)
        s.connect(("127.0.0.1", PORT))
        s.close()
        return PORT
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass

    from .studio_web import server as web_server

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), web_server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return PORT


class MainWindow(QMainWindow):
    def __init__(self, url, port):
        super().__init__()
        self.port = port
        self.setWindowTitle("CoreProbe — Forensic Artifact Recovery")
        self.resize(1520, 950)
        self.setMinimumSize(1220, 780)
        self.setStyleSheet("background:#0a0b0d;")

        self.view = QWebEngineView()
        self.setCentralWidget(self.view)

        self._build_menus()
        self._build_toolbar()
        self._build_statusbar()

        self.view.load(QUrl(url))
        self.view.loadFinished.connect(
            lambda ok: self.statusBar().showMessage(
                "ready — Forensic Artifact Recovery" if ok else "failed to load UI"
            )
        )

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._poll_device)
        self._timer.start(2000)

    # ----- chrome -----
    def _build_menus(self):
        mbar = self.menuBar()
        mbar.setStyleSheet(
            "QMenuBar{background:#0e1013;color:#c9cfd8;} "
            "QMenuBar::item:selected{background:#1a1d24;} "
            "QMenu{background:#0e1013;color:#c9cfd8;border:1px solid #1e2129;}"
        )

        nav = mbar.addMenu("&Navigate")
        for key, label, shortcut in NAV:
            act = QAction(label, self)
            act.setShortcut(QKeySequence(shortcut))
            act.triggered.connect(lambda _=False, k=key: self.view.page().runJavaScript(
                f"location.hash='{k}'"))
            nav.addAction(act)

        view = mbar.addMenu("&View")
        reload_act = QAction("Reload", self)
        reload_act.setShortcut(QKeySequence("Ctrl+R"))
        reload_act.triggered.connect(self.view.reload)
        view.addAction(reload_act)
        zoom_in = QAction("Zoom In", self)
        zoom_in.setShortcut(QKeySequence("Ctrl+="))
        zoom_in.triggered.connect(lambda: self.view.setZoomFactor(self.view.zoomFactor() * 1.1))
        view.addAction(zoom_in)
        zoom_out = QAction("Zoom Out", self)
        zoom_out.setShortcut(QKeySequence("Ctrl+-"))
        zoom_out.triggered.connect(lambda: self.view.setZoomFactor(self.view.zoomFactor() / 1.1))
        view.addAction(zoom_out)

        help_m = mbar.addMenu("&Help")
        about = QAction("About", self)
        about.triggered.connect(self._about)
        help_m.addAction(about)
        web = QAction("GitHub", self)
        web.triggered.connect(lambda: self.view.load(
            QUrl("https://github.com/xanstomper/coreprobe")))
        help_m.addAction(web)

    def _build_toolbar(self):
        tb = QToolBar("Navigation")
        tb.setMovable(False)
        tb.setStyleSheet(
            "QToolBar{background:#0e1013;border:none;spacing:4px;padding:4px;}"
            "QToolButton{color:#c9cfd8;background:#16191f;border:1px solid #232833;"
            "border-radius:4px;padding:4px 12px;} QToolButton:hover{background:#1c2028;}"
        )
        for key, label, _ in NAV:
            tb.addAction(label, lambda _=False, k=key: self.view.page().runJavaScript(
                f"location.hash='{k}'"))
        self.addToolBar(tb)

    def _build_statusbar(self):
        self.statusBar().setStyleSheet(
            "color:#5d6470; background:#0e1013; border-top:1px solid #1e2129;"
        )
        self.statusBar().showMessage("loading workstation…")

    # ----- device polling -----
    def _poll_device(self):
        try:
            with urlopen(f"http://127.0.0.1:{self.port}/api/device", timeout=1) as r:
                d = json.loads(r.read().decode())
        except Exception:
            return
        if not isinstance(d, dict) or not d:
            self.setWindowTitle("CoreProbe — Forensic Artifact Recovery")
            self.statusBar().showMessage(
                f"device: none attached  | backend 127.0.0.1:{self.port}"
            )
            return
        if d.get("error"):
            self.statusBar().showMessage(
                f"device lookup error: {d['error']} | backend 127.0.0.1:{self.port}"
            )
            return
        chip = d.get("chip") or "—"
        ios = d.get("ios") or "—"
        state = d.get("state") or "—"  # AFU / BFU
        model = d.get("model") or (d.get("product_type") or "—")
        self.setWindowTitle(f"CoreProbe — Forensic Artifact Recovery  [{state}]")
        self.statusBar().showMessage(
            f"device: {model} ATTACHED ({state})  "
            f"| chip {chip} | iOS {ios} | backend 127.0.0.1:{self.port}"
        )

    def _about(self):
        QMessageBox.about(
            self, "About CoreProbe",
            f"<b>{VERSION}</b><br><br>Open-source iOS forensic triage and "
            "exploit-catalog workstation for lawful acquisition.<br>"
            "https://github.com/xanstomper/coreprobe",
        )


def main():
    port = ensure_server()
    app = QApplication(sys.argv)
    app.setApplicationName("Forensic Artifact Recovery")
    app.setOrganizationName("opensleuth")
    w = MainWindow(f"http://127.0.0.1:{port}/", port)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()