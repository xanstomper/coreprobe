"""CLI + GUI wiring for the payload manager (opensleuth/payloads.py).

The bug these guard against: AFU executors told users to run
``opensleuth payloads fetch "<route>"`` but that subcommand did not exist,
and the web GUI had no payload management at all — GUI users hit a dead
end on every SIDELOAD route (Dopamine/TrollStore/Misaka...).

Covers:
* ``opensleuth payloads list`` / ``opensleuth payloads fetch`` (via
  cli.main with an isolated OPENSLEUTH_PAYLOADS_DIR),
* the server helpers _payloads_list / _payloads_fetch in
  opensleuth/studio_web/server.py,
* the real HTTP routes GET /api/payloads and POST /api/payloads/fetch
  (same live-server seam as tests/test_server_security.py).

No network anywhere: fetch of the one downloadable entry (Dopamine) is
exercised through a monkeypatched urllib.request.urlopen, with the
entry's pinned hash temporarily cleared exactly like tests/test_payloads.py
does (the pin itself is verified there).
"""

import hashlib
import http.server
import io
import json
import threading
import urllib.request

import pytest

from opensleuth import cli
from opensleuth import payloads as P
from opensleuth.studio_web import server as S


@pytest.fixture()
def pdir(tmp_path, monkeypatch):
    """Isolated payloads dir via the OPENSLEUTH_PAYLOADS_DIR override."""
    monkeypatch.setenv("OPENSLEUTH_PAYLOADS_DIR", str(tmp_path))
    return tmp_path


class _FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False


def _fake_urlopen(data: bytes):
    def _open(req, *a, **k):
        return _FakeResp(data)
    return _open


def _no_network(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("network access attempted in test")
    monkeypatch.setattr(urllib.request, "urlopen", _boom)


# --------------------------------------------------------------------- CLI


class TestPayloadsCliList:
    def test_list_runs_and_shows_registry(self, pdir, capsys):
        cli.main(["payloads", "list"])
        out = capsys.readouterr().out
        assert f"payloads dir: {pdir}" in out
        for name in ("Dopamine", "TrollStore", "Serotonin", "NathanLR", "Misaka"):
            assert name in out
        assert "MISSING" in out  # empty isolated dir: nothing present yet
        assert "manual (examiner-supplied)" in out
        # the pinned Dopamine hash is displayed, never hidden
        assert P.entry_for_route("Dopamine 3")["sha256"] in out

    def test_list_shows_present_payload(self, pdir, capsys):
        (pdir / "dopamine--Dopamine.ipa").write_bytes(b"fake-ipa")
        cli.main(["payloads", "list"])
        out = capsys.readouterr().out
        assert "present:" in out
        assert "dopamine--Dopamine.ipa" in out


class TestPayloadsCliFetch:
    def test_fetch_manual_entry_is_honest_and_nonzero(self, pdir, capsys,
                                                       monkeypatch):
        _no_network(monkeypatch)
        with pytest.raises(SystemExit) as ei:
            cli.main(["payloads", "fetch", "TrollStore"])
        # sys.exit(msg): msg rides in SystemExit.code (printed to stderr and
        # exit status 1 when it reaches the top level uncaught).
        assert ei.value.code
        assert "examiner-supplied" in str(ei.value.code)
        assert "trollstore--TrollStore.tipa" in str(ei.value.code)
        assert list(pdir.iterdir()) == []  # nothing downloaded or faked

    def test_fetch_unknown_route_is_honest_and_nonzero(self, pdir,
                                                        monkeypatch):
        _no_network(monkeypatch)
        with pytest.raises(SystemExit) as ei:
            cli.main(["payloads", "fetch", "palera1n rootful"])
        assert "no payload registry entry" in str(ei.value.code)

    def test_fetch_downloadable_entry_via_fake_urlopen(self, pdir, capsys,
                                                        monkeypatch):
        entry = P.entry_for_route("Dopamine 3")
        monkeypatch.setitem(entry, "sha256", None)  # pin verified in test_payloads.py
        data = b"payload-bytes-for-cli-test"
        monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(data))
        cli.main(["payloads", "fetch", "Dopamine 3"])
        out = capsys.readouterr().out
        dest = pdir / "dopamine--Dopamine.ipa"
        assert dest.read_bytes() == data
        assert "fetched ->" in out and str(dest) in out
        assert hashlib.sha256(data).hexdigest() in out


# ------------------------------------------------------- server helpers


class TestPayloadsServerHelpers:
    def test_list_helper_returns_registry(self, pdir):
        r = S._payloads_list()
        assert r["payloads_dir"] == str(pdir)
        by_slug = {e["slug"]: e for e in r["payloads"]}
        assert by_slug["dopamine"]["manual"] is False
        assert by_slug["trollstore"]["manual"] is True
        assert by_slug["dopamine"]["present_path"] is None

    def test_fetch_helper_manual_entry_no_network(self, pdir, monkeypatch):
        _no_network(monkeypatch)
        r = S._payloads_fetch("TrollStore")
        assert r["ok"] is False
        assert "examiner-supplied" in r["error"]
        assert list(pdir.iterdir()) == []

    def test_fetch_helper_empty_route(self, pdir):
        assert S._payloads_fetch("")["ok"] is False
        assert S._payloads_fetch(None)["ok"] is False

    def test_fetch_helper_success_via_fake_urlopen(self, pdir, monkeypatch):
        entry = P.entry_for_route("Dopamine 3")
        monkeypatch.setitem(entry, "sha256", None)
        data = b"payload-bytes-for-gui-test"
        monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(data))
        r = S._payloads_fetch("Dopamine 3")
        assert r["ok"] is True
        assert r["sha256"] == hashlib.sha256(data).hexdigest()
        assert (pdir / "dopamine--Dopamine.ipa").read_bytes() == data
        # refreshed listing rides along so the panel can re-render in place
        by_slug = {e["slug"]: e for e in r["payloads"]}
        assert by_slug["dopamine"]["present_path"]


# --------------------------------------------------------- HTTP routes


@pytest.fixture()
def web(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("OPENSLEUTH_PAYLOADS_DIR", str(tmp_path / "payloads"))
    (tmp_path / "cases").mkdir()
    port = 9700 + (hash(str(tmp_path)) % 250)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), S.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield tmp_path, port
    httpd.shutdown()


def _get_json(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}",
                                timeout=5) as r:
        return r.status, json.loads(r.read().decode())


def _post_json(port, path, payload):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, json.loads(r.read().decode())


class TestPayloadsHttp:
    def test_get_api_payloads(self, web):
        tmp, port = web
        status, body = _get_json(port, "/api/payloads")
        assert status == 200
        assert body["payloads_dir"] == str(tmp / "payloads")
        slugs = {e["slug"] for e in body["payloads"]}
        assert {"dopamine", "trollstore", "serotonin"} <= slugs

    def test_post_fetch_manual_entry(self, web):
        # Serotonin is manual=True: payloads.fetch_payload raises before any
        # network access by construction (no-network is proven at the helper
        # level in TestPayloadsServerHelpers with urlopen rigged to explode).
        tmp, port = web
        status, body = _post_json(port, "/api/payloads/fetch",
                                  {"route": "Serotonin"})
        assert status == 200
        assert body["ok"] is False
        assert "examiner-supplied" in body["error"]
