"""Adversarial security tests for the web server's path handling.

The standard under test: evidence paths from the web UI are strictly confined
UNDER ~/cases (and static files under STATIC). Prefix tricks like ~/cases-evil
must be rejected. This test suite monkeypatches HOME to a temp dir.
"""

import http.server
import json
import threading
import urllib.request

import pytest

from opensleuth.studio_web import server as S


@pytest.fixture()
def web(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "cases").mkdir()
    port = 9300 + (hash(str(tmp_path)) % 400)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), S.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield tmp_path, port
    httpd.shutdown()


def _get(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}",
                                    timeout=5) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def _post_json(port, path, payload):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


class TestSafeCaseFile:
    def test_sibling_prefix_directory_is_rejected(self, web):
        tmp, port = web
        evil = tmp / "cases-evil"
        evil.mkdir()
        target = evil / "secret.txt"
        target.write_text("stolen")
        status, body = _get(port, f"/api/multihash?path={target}")
        assert status == 400 or '"error"' in body

    def test_inside_cases_works(self, web):
        tmp, port = web
        f = tmp / "cases" / "c1" / "a.txt"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("x")
        status, body = _get(port, f"/api/multihash?path={f}")
        assert status == 200
        assert "sha256" in body


class TestHashEndpoint:
    def test_traversal_outside_cases_rejected(self, web):
        tmp, port = web
        secret = tmp / "etc-passwd"
        secret.write_text("root:x:0:0")
        status, out = _post_json(port, "/api/hash", {"path": str(secret)})
        assert "error" in out

    def test_dotdot_traversal_rejected(self, web):
        tmp, port = web
        base = tmp / "cases" / "c2"
        base.mkdir()
        q = str(base / ".." / ".." / "secret.txt")
        (tmp / "secret.txt").write_text("s")
        status, out = _post_json(port, "/api/hash", {"path": q})
        assert "error" in out


class TestAcquireDestination:
    def test_arbitrary_destination_rejected(self, web):
        tmp, port = web
        status, out = _post_json(port, "/api/acquire",
                                 {"destination": "/tmp/evil-dest"})
        assert status == 400
        assert "must be under ~/cases" in out["error"]

    def test_cases_sibling_destination_rejected(self, web):
        tmp, port = web
        status, out = _post_json(port, "/api/acquire",
                                 {"destination": str(tmp / "cases-evil")})
        assert status == 400

    def test_cases_destination_accepted_without_error(self, web):
        tmp, port = web
        status, out = _post_json(port, "/api/acquire",
                                 {"destination": str(tmp / "cases" / "ok1")})
        # may fail later because no device, but must NOT be a 400 path error
        assert status == 200
        assert out.get("started") is True


class TestCaseDestination:
    def test_case_destination_confined(self, web):
        tmp, port = web
        status, out = _post_json(port, "/api/case",
                                 {"case_id": "x",
                                  "destination": "/tmp/evil-case"})
        assert status == 400
        assert "must be under ~/cases" in out["error"]

    def test_case_default_destination_allowed(self, web):
        tmp, port = web
        status, out = _post_json(port, "/api/case", {"case_id": "normal"})
        assert status == 200
        assert (tmp / "cases" / "normal" / "case.json").is_file()


class TestParseImage:
    def test_parse_image_confined(self, web):
        tmp, port = web
        outside = tmp / "outside"
        outside.mkdir()
        (outside / "Manifest.db").write_bytes(b"not a real db")
        status, out = _post_json(port, "/api/parse-image",
                                 {"path": str(outside)})
        assert "error" in out
        assert "under ~/cases" in out["error"]


class TestStaticServe:
    def test_static_traversal_rejected(self, web):
        tmp, port = web
        status, body = _get(port, "/../opensleuth/cli.py")
        assert status == 404
