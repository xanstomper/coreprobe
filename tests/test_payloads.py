"""Payload registry tests (opensleuth.payloads) + route-aware runner wiring.

The bug these guard against: AFU app routes (Dopamine / Serotonin /
NathanLR / TrollStore / ...) used to install whichever .ipa/.tipa happened
to be lying in ~/payloads — the runner never told the executor which route
it was running, and CoreProbe had no registry, download, or hash check for
payloads at all.

No network and no physical device are required: fetch is exercised through
a monkeypatched urllib, executors through synthetic targets.
"""

import hashlib
import json
import urllib.request

import pytest

from opensleuth import payloads as P
from opensleuth import exploitrunner as R
from opensleuth.exploitrunner import Target, PlanItem, run_plan


def _target(chip="A13", ios="16.6.1", state="AFU", product_type="iPhone12,1",
            model="iPhone 11"):
    return Target(present=True, chip=chip, ios=ios, product_type=product_type,
                  model=model, state=state)


@pytest.fixture()
def pdir(tmp_path, monkeypatch):
    """Isolated payloads dir via the OPENSLEUTH_PAYLOADS_DIR override."""
    monkeypatch.setenv("OPENSLEUTH_PAYLOADS_DIR", str(tmp_path))
    return tmp_path


# --------------------------------------------------------------------- registry


class TestRegistrySanity:
    def test_slugs_unique_and_wellformed(self):
        slugs = [e["slug"] for e in P.REGISTRY]
        assert len(slugs) == len(set(slugs))
        for e in P.REGISTRY:
            assert e["name"] and e["slug"]
            assert e["manual"] in (True, False)

    def test_downloadable_entries_are_official_https_with_asset(self):
        for e in P.REGISTRY:
            if e["manual"]:
                continue
            # Only verifiable official release assets may be downloadable.
            assert e["url"] and e["url"].startswith("https://github.com/")
            assert e["repo"] and e["url"].startswith(e["repo"] + "/releases/")
            assert e["asset"] and e["kind"] in (".ipa", ".tipa")
            assert e["asset"].endswith(e["kind"])

    def test_hashes_are_none_or_real_sha256_hex(self):
        # NEVER a fabricated hash: a pinned hash must at least be a full
        # SHA-256 hex digest (its correctness is enforced again at fetch).
        for e in P.REGISTRY:
            h = e["sha256"]
            assert h is None or (
                len(h) == 64 and all(c in "0123456789abcdef" for c in h)), e["slug"]

    def test_dopamine_entry_is_official(self):
        e = P.entry_for_route("Dopamine 3")
        assert e is not None and e["slug"] == "dopamine"
        assert e["repo"] == "https://github.com/opa334/Dopamine"
        assert e["manual"] is False

    def test_trollstore_entry_is_honestly_manual(self):
        # The official TrollStore releases ship no installable .ipa/.tipa
        # asset, so the registry must not pretend to download one.
        e = P.entry_for_route("TrollStore 2")
        assert e is not None and e["slug"] == "trollstore"
        assert e["manual"] is True and e["url"] is None


# --------------------------------------------------------------------- matching


class TestRouteMatching:
    def test_route_keywords(self):
        assert "dopamine" in P.route_keywords("Dopamine 3")
        assert "dopamine" in P.route_keywords("Dopamine 2")
        assert "trollstore" in P.route_keywords("TrollStore (CoreTrust)")
        assert P.route_keywords("logical + backup") == []
        assert P.route_keywords("checkm8 (A11)") == []

    def test_entry_for_route(self):
        assert P.entry_for_route("Serotonin")["slug"] == "serotonin"
        assert P.entry_for_route("NathanLR")["slug"] == "nathanlr"
        assert P.entry_for_route("Misaka26 MobileGestalt")["slug"] == "misaka-nugget"
        assert P.entry_for_route("palera1n rootful") is None

    def test_find_prefers_route_specific_over_generic(self, pdir):
        (pdir / "agent.ipa").write_bytes(b"generic")
        (pdir / "serotonin--Serotonin.tipa").write_bytes(b"sero")
        (pdir / "dopamine--Dopamine.ipa").write_bytes(b"dopa")
        assert P.find_payload_for("Dopamine 3", pdir).name == "dopamine--Dopamine.ipa"
        assert P.find_payload_for("Serotonin", pdir).name == "serotonin--Serotonin.tipa"

    def test_find_matches_examiner_named_file(self, pdir):
        (pdir / "Dopamine.ipa").write_bytes(b"dopa")
        assert P.find_payload_for("Dopamine 2", pdir).name == "Dopamine.ipa"

    def test_find_never_hands_over_another_routes_file(self, pdir):
        (pdir / "serotonin--Serotonin.tipa").write_bytes(b"sero")
        # No Dopamine payload and no unclaimed generic file -> no payload,
        # NOT the Serotonin file.
        assert P.find_payload_for("Dopamine 3", pdir) is None

    def test_find_generic_fallback_for_unregistered_route(self, pdir):
        (pdir / "agent.ipa").write_bytes(b"generic")
        (pdir / "dopamine--Dopamine.ipa").write_bytes(b"dopa")
        assert P.find_payload_for("unc0ver", pdir).name == "agent.ipa"
        assert P.find_payload_for("", pdir).name == "agent.ipa"

    def test_find_empty_dir(self, pdir):
        assert P.find_payload_for("Dopamine 3", pdir) is None


# --------------------------------------------------------------------- fetch


class _FakeResp:
    def __init__(self, data: bytes):
        self._data, self._pos = data, 0

    def read(self, n=-1):
        chunk = self._data[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen(data: bytes):
    def _open(req, *a, **k):
        return _FakeResp(data)
    return _open


class TestFetch:
    def test_fetch_manual_entry_refused_with_instructions(self, pdir):
        with pytest.raises(ValueError, match="examiner-supplied"):
            P.fetch_payload("TrollStore")

    def test_fetch_unknown_route_refused(self, pdir):
        with pytest.raises(ValueError, match="no payload registry entry"):
            P.fetch_payload("palera1n rootful")

    def test_fetch_pinned_hash_mismatch_is_hard_failure(self, pdir, monkeypatch):
        # The Dopamine entry pins the publisher digest of its release asset;
        # serving different bytes must fail and leave nothing behind.
        monkeypatch.setattr(urllib.request, "urlopen",
                            _fake_urlopen(b"not the real dopamine"))
        with pytest.raises(RuntimeError, match="hash mismatch"):
            P.fetch_payload("Dopamine 3", pdir)
        assert not (pdir / "dopamine--Dopamine.ipa").exists()
        assert list(pdir.glob("*.part")) == []

    def test_fetch_records_hash_then_enforces_it(self, pdir, monkeypatch):
        # Simulate a not-yet-pinned entry: first fetch records the hash in
        # the manifest; a later fetch of different bytes must then fail.
        entry = P.entry_for_route("Dopamine 3")
        monkeypatch.setitem(entry, "sha256", None)
        data = b"payload-bytes-v1"
        monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(data))
        out = P.fetch_payload("Dopamine 3", pdir)
        assert out.name == "dopamine--Dopamine.ipa"
        assert out.read_bytes() == data
        manifest = json.loads((pdir / "manifest.json").read_text())
        assert manifest["dopamine"]["sha256"] == hashlib.sha256(data).hexdigest()

        monkeypatch.setattr(urllib.request, "urlopen",
                            _fake_urlopen(b"tampered-bytes"))
        with pytest.raises(RuntimeError, match="hash mismatch"):
            P.fetch_payload("Dopamine 3", pdir)
        assert out.read_bytes() == data  # original payload untouched


# --------------------------------------------------------------------- runner wiring


class TestRunPlanRouteDispatch:
    def test_executor_with_route_param_receives_route_name(self, monkeypatch):
        seen = {}

        def fake_agent(t, timeout, route=""):
            seen["route"] = route
            return True, "agent live", ""

        monkeypatch.setitem(R._EXECUTORS, "afu_agent", fake_agent)
        plan = [PlanItem(name="Dopamine 3", layer="userspace", primary="x",
                         strategy="afu_agent", tools=[], bfu=False,
                         terminal=True)]
        rep = run_plan(_target(), plan)
        assert rep.winner == "Dopamine 3"
        assert seen["route"] == "Dopamine 3"

    def test_two_arg_executor_still_works(self, monkeypatch):
        monkeypatch.setitem(R._EXECUTORS, "logical_pull",
                            lambda t, o: (True, "ok", ""))
        plan = [PlanItem(name="logical + backup", layer="userspace",
                         primary="y", strategy="logical_pull", tools=[],
                         bfu=False, terminal=True)]
        rep = run_plan(_target(), plan)
        assert rep.winner == "logical + backup"

    def test_afu_agent_failure_names_needed_payload(self, pdir, monkeypatch):
        monkeypatch.setattr(R, "_afc2_mountable", lambda: (False, "no afc2"))
        # A Serotonin payload is present; a Dopamine route must NOT use it.
        (pdir / "serotonin--Serotonin.tipa").write_bytes(b"sero")
        monkeypatch.setattr(R, "_bin", lambda t: "/usr/bin/" + t)
        ok, detail, _ = R.exec_afu_agent(_target(), route="Dopamine 3")
        assert ok is False
        assert "Dopamine" in detail
        assert 'opensleuth payloads fetch "Dopamine 3"' in detail

    def test_afu_agent_uses_route_payload(self, pdir, monkeypatch):
        installed = []
        monkeypatch.setattr(R, "_afc2_mountable", lambda: (False, "no afc2"))
        monkeypatch.setattr(R, "_bin", lambda t: "/usr/bin/" + t)

        def fake_run_cmd(cmd, timeout):
            installed.append(cmd[-1])
            return 0, "installed"

        monkeypatch.setattr(R, "_run_cmd", fake_run_cmd)
        (pdir / "dopamine--Dopamine.ipa").write_bytes(b"dopa")
        (pdir / "serotonin--Serotonin.tipa").write_bytes(b"sero")
        # AFC2 never comes up, so this fails honestly — but the file it
        # tried to install must be the Dopamine one.
        ok, detail, _ = R.exec_afu_agent(_target(), route="Dopamine 3")
        assert ok is False and "agent installed but AFC2 not yet live" in detail
        assert installed and installed[0].endswith("dopamine--Dopamine.ipa")
