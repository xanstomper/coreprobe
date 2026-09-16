"""Headless smoke tests for the Qt desktop shell.

Runs with QT_QPA_PLATFORM=offscreen so no X server is needed; verifies the
backend boots on the loopback port and the window chrome constructs.
"""

import os
import sys
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QPA_PLATFORMTHEME", "")

from PyQt6.QtCore import QUrl  # noqa: E402

from opensleuth import studio_desktop  # noqa: E402


class DesktopShellTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use a non-default port so tests never collide with a live studio.
        cls.old_port = studio_desktop.PORT
        studio_desktop.PORT = cls.port = 13121

        from opensleuth.studio_web import server as web_server
        import http.server
        import threading

        cls.httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", cls.port), web_server.Handler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        studio_desktop.PORT = cls.old_port

    def test_backend_serves_ui(self):
        from urllib.request import urlopen
        with urlopen(f"http://127.0.0.1:{self.port}/", timeout=3) as r:
            body = r.read().decode()
        self.assertIn("Forensic Artifact Recovery", body)
        # Exploits view lives in app.js (nav is rendered dynamically)
        with urlopen(f"http://127.0.0.1:{self.port}/app.js", timeout=3) as r:
            js = r.read().decode()
        self.assertIn("exploits", js)

    def test_backend_device_api(self):
        from urllib.request import urlopen
        with urlopen(f"http://127.0.0.1:{self.port}/api/device", timeout=3) as r:
            import json
            d = json.loads(r.read().decode())
        # Flat shape: {"model", "product_type", "ios", "build", "udid",
        # "state", "chip"} or {} (no device) or {"error": ...}
        self.assertIsInstance(d, dict)
        allowed = {"model", "product_type", "ios", "build", "udid",
                   "state", "chip", "error"}
        self.assertTrue(set(d) <= allowed)
        if "state" in d:
            self.assertIn(d["state"], ("AFU", "BFU"))

    def test_desktop_window_constructs(self):
        app = studio_desktop.QApplication.instance() or studio_desktop.QApplication(
            [sys.argv[0], "-platform", "offscreen"])
        win = studio_desktop.MainWindow(f"http://127.0.0.1:{self.port}/", self.port)
        self.assertIn("CoreProbe", win.windowTitle())
        # QWebEngineView URL may stay empty until the event loop runs; when
        # it has resolved it must point at the local backend.
        app.processEvents()
        url = win.view.url().toString()
        if url:
            self.assertTrue(url.startswith(f"http://127.0.0.1:{self.port}"))
        # NAV covers the hash routes present in the UI
        for key, _, _ in studio_desktop.NAV:
            self.assertIn(key, ("dashboard", "exploits", "reports", "devices", "settings"))
        win.close()
        app.processEvents()

    def test_ensure_server_reuses_or_starts(self):
        # We already run one on self.port; ensure_server with that port must
        # reuse it (returns the port) rather than fail to bind.
        studio_desktop.PORT = self.port
        self.assertEqual(studio_desktop.ensure_server(), self.port)


if __name__ == "__main__":
    unittest.main()