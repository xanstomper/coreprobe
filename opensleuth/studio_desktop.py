"""Native desktop shell for the Forensic Artifact Recovery UI.

Starts the built-in web backend (or reuses a running one) and presents the
workstation interface in a real desktop window via QtWebEngine.

Launch:  python3 -m opensleuth.studio_desktop
"""

import http.server
import socket
import sys
import threading

from PyQt6.QtCore import QUrl
from PyQt6.QtWidgets import QApplication, QMainWindow
from PyQt6.QtWebEngineWidgets import QWebEngineView

PORT = 9121


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
    def __init__(self, url):
        super().__init__()
        self.setWindowTitle("CoreProbe — Forensic Artifact Recovery")
        self.resize(1520, 950)
        self.setMinimumSize(1220, 780)
        self.setStyleSheet("background:#0a0b0d;")
        self.view = QWebEngineView()
        self.setCentralWidget(self.view)
        self.statusBar().setStyleSheet("color:#5d6470; background:#0e1013; border-top:1px solid #1e2129;")
        self.statusBar().showMessage("loading workstation…")
        self.view.load(QUrl(url))
        self.view.loadFinished.connect(
            lambda ok: self.statusBar().showMessage("ready" if ok else "failed to load UI")
        )


def main():
    port = ensure_server()
    app = QApplication(sys.argv)
    app.setApplicationName("Forensic Artifact Recovery")
    app.setOrganizationName("opensleuth")
    w = MainWindow(f"http://127.0.0.1:{port}/")
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
