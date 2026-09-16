"""Headless Qt tests for the desktop shell + real web-UI rendering.

Runs with QT_QPA_PLATFORM=offscreen so no X server is needed. IMPORTANT:
QtWebEngine permits exactly ONE live QWebEngineView per process; creating a
second view after destroying the first hangs the engine. All tests therefore
share a single MainWindow+view created once per module-class.

Covers: backend serving, device API contract, window construction, and real
browser-engine rendering of the Tools and Exploits pages (guards against
async render regressions like '[object Promise]' reaching innerHTML).
"""

import os
import sys
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QPA_PLATFORMTHEME", "")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from opensleuth import studio_desktop  # noqa: E402


class DesktopShellTest(unittest.TestCase):
    """One QApplication + one MainWindow view shared across all tests."""

    @classmethod
    def setUpClass(cls):
        import http.server
        import threading
        import time

        from opensleuth.studio_web import server as web_server

        cls.old_port = studio_desktop.PORT
        studio_desktop.PORT = cls.port = 13121
        cls.httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", cls.port), web_server.Handler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

        cls.app = QApplication.instance() or QApplication(
            [sys.argv[0], "-platform", "offscreen"])
        cls.win = studio_desktop.MainWindow(
            f"http://127.0.0.1:{cls.port}/", cls.port)
        cls.win.show()
        # Let the page load (QWebEngine needs the event loop to make progress).
        loaded = {"ok": False}

        def _loaded(ok):
            loaded["ok"] = ok

        cls.win.view.loadFinished.connect(_loaded)
        deadline = time.time() + 15
        while time.time() < deadline and not loaded["ok"]:
            cls.app.processEvents()
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        try:
            # QtWebEngine profile teardown hangs at interpreter exit if the
            # WebEnginePage is not fully deleted; run a short event loop so
            # deleteLater() work is flushed before atexit.
            from PyQt6.QtCore import QTimer
            cls.win.view.page().deleteLater()
            cls.win.view.deleteLater()
            cls.win.deleteLater()
            QTimer.singleShot(1500, cls.app.quit)
            cls.app.exec()
        except Exception:
            pass
        try:
            cls.httpd.shutdown()
        except Exception:
            pass
        studio_desktop.PORT = cls.old_port

    # ----- backend -----
    def test_backend_serves_ui(self):
        from urllib.request import urlopen
        with urlopen(f"http://127.0.0.1:{self.port}/", timeout=3) as r:
            body = r.read().decode()
        self.assertIn("Forensic Artifact Recovery", body)
        with urlopen(f"http://127.0.0.1:{self.port}/app.js", timeout=3) as r:
            js = r.read().decode()
        self.assertIn("exploits", js)

    def test_backend_device_api(self):
        from urllib.request import urlopen
        with urlopen(f"http://127.0.0.1:{self.port}/api/device", timeout=3) as r:
            import json
            d = json.loads(r.read().decode())
        self.assertIsInstance(d, dict)
        allowed = {"model", "product_type", "ios", "build", "udid",
                   "state", "chip", "error"}
        self.assertTrue(set(d) <= allowed)
        if "state" in d:
            self.assertIn(d["state"], ("AFU", "BFU"))

    def test_backend_tools_api(self):
        from urllib.request import urlopen
        with urlopen(f"http://127.0.0.1:{self.port}/api/tools", timeout=3) as r:
            import json
            d = json.loads(r.read().decode())
        self.assertIn("tools", d)
        self.assertIn("summary", d)
        self.assertGreaterEqual(len(d["tools"]), 20)
        self.assertIn("installed", d["tools"][0])

    def test_ensure_server_reuses_or_starts(self):
        studio_desktop.PORT = self.port
        self.assertEqual(studio_desktop.ensure_server(), self.port)

    # ----- window -----
    def test_desktop_window_constructs(self):
        self.assertIn("CoreProbe", self.win.windowTitle())
        url = self.win.view.url().toString()
        if url:
            self.assertTrue(url.startswith(f"http://127.0.0.1:{self.port}"))
        for key, _, _ in studio_desktop.NAV:
            self.assertIn(key, ("dashboard", "exploits", "reports", "devices",
                                "settings", "tools"))

    # ----- real browser-engine rendering -----
    def _wait_for(self, script, needle, timeout=15.0):
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            got = {}

            def cb(v):
                got["v"] = v

            self.win.view.page().runJavaScript(script, cb)
            for _ in range(20):
                self.app.processEvents()
                time.sleep(0.02)
            if needle in (got.get("v") or ""):
                return True
            time.sleep(0.1)
        return False

    def _page_html(self):
        import json
        got = {}

        def cb(v):
            got["html"] = v or ""

        self.win.view.page().runJavaScript(
            "document.getElementById('page').innerHTML", cb)
        for _ in range(20):
            self.app.processEvents()
            import time
            time.sleep(0.02)
        return got.get("html", "")

    def test_tools_page_renders_in_browser(self):
        self.win.view.page().runJavaScript("location.hash = 'tools'")
        self.assertTrue(
            self._wait_for("document.getElementById('page') ? "
                           "document.getElementById('page').innerHTML : ''",
                           "Forensic Toolchain"),
            "tools page did not render")
        html = self._page_html()
        self.assertNotIn("[object Promise]", html)
        self.assertIn("Toolchain", html)
        self.assertIn("installed", html.lower())
        self.assertIn("acquisition", html.lower())

    def test_exploits_page_renders_in_browser(self):
        self.win.view.page().runJavaScript("location.hash = 'exploits'")
        self.assertTrue(
            self._wait_for("document.getElementById('page') ? "
                           "document.getElementById('page').innerHTML : ''",
                           "Routes"),
            "exploits page did not render")
        html = self._page_html()
        self.assertNotIn("[object Promise]", html)
        self.assertIn("Routes", html)

    def test_nav_contains_tools(self):
        nav = {"html": ""}

        def cb(v):
            nav["html"] = v or ""

        self.win.view.page().runJavaScript(
            "document.querySelector('#nav').innerHTML", cb)
        for _ in range(20):
            self.app.processEvents()
            import time
            time.sleep(0.02)
        self.assertIn("Tools", nav["html"])
        self.assertIn("Exploits", nav["html"])


if __name__ == "__main__":
    unittest.main()