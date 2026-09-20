"""AI agent harness tests.

Standards under test:
- deterministic state machine walks IDLE -> ... -> CASE_READY (or a terminal
  failure) with a journal event for every transition
- approval gate: acquisition routes REQUIRE examiner sign-off; --yes records
  consent; approve() resumes the run
- the LLM advisor is advisory-only (never in the evidence path) and its
  absence degrades gracefully
- no-device failure lands in UNSUPPORTED with an honest reason
"""

import json

import pytest

from opensleuth import agent as A
from opensleuth.agentllm import Advisor


# ------------------------------------------------------------- fakes


class FakeFingerprint:
    def __init__(self, d):
        self._d = d

    def to_dict(self):
        return {k: {"value": v, "source": "test", "confidence": "Observed"}
                for k, v in self._d.items()}


def _fp_monkey(monkeypatch, **dev):
    dev.setdefault("chip", "A13")
    dev.setdefault("ios", "16.6.1")
    dev.setdefault("state", "AFU")
    dev.setdefault("model", "iPhone 11")
    dev.setdefault("udid", "TEST-UDID")
    fp = FakeFingerprint(dev)
    monkeypatch.setattr("opensleuth.fingerprint.fingerprint_device",
                        lambda: fp)
    # pretend a device is attached for the detect step
    monkeypatch.setattr(
        "opensleuth.usb.usb_state",
        lambda: {"devices": [{"product": "iPhone", "serial": "TEST",
                              "product_id": "12a8", "mode": "normal"}],
                 "any": True, "dfu": False, "recovery": False, "pwnd": False,
                 "pwnd_usbliter8": False, "pwnd_checkm8": False})


# ------------------------------------------------------------- lifecycle


class TestStateMachine:
    def test_no_device_fails_unsupported(self, tmp_path, monkeypatch):
        monkeypatch.setattr("opensleuth.usb.usb_state",
                            lambda: {"devices": [], "any": False})
        h = A.AgentHarness(tmp_path / "case1")
        h.run()
        assert h.status.state == "UNSUPPORTED"
        assert "no Apple device" in h.status.error

    def test_reaches_case_ready_with_consent(self, tmp_path, monkeypatch):
        _fp_monkey(monkeypatch)
        # make executors deterministic + fast
        from opensleuth import exploitrunner as R
        monkeypatch.setattr(R, "_run_cmd",
                            lambda cmd, t: (0, "fake-ok"))
        monkeypatch.setattr(R, "usb_state", lambda: {
            "devices": [{"product": "iPhone", "serial": "TEST",
                         "product_id": "12a8", "mode": "normal"}],
            "any": True, "dfu": False, "recovery": False, "pwnd": False,
            "pwnd_usbliter8": False, "pwnd_checkm8": False})
        # force the logical route to "succeed" without a real backup
        monkeypatch.setitem(R._EXECUTORS, "logical_pull",
                            lambda t, o: (True, "REAL acquisition: fake test backup", ""))
        h = A.AgentHarness(tmp_path / "case2", auto_approve=True)
        h.run()
        assert h.status.state == "CASE_READY", h.status.error
        assert any(r["status"] == "succeeded" for r in h.status.executed)
        assert h.status.report.get("path")
        assert (tmp_path / "case2" / "agent-report.json").is_file()

    def test_every_transition_journaled(self, tmp_path, monkeypatch):
        _fp_monkey(monkeypatch)
        from opensleuth import exploitrunner as R
        monkeypatch.setattr(R, "usb_state", lambda: {
            "devices": [{"product": "iPhone", "serial": "TEST",
                         "product_id": "12a8", "mode": "normal"}],
            "any": True, "dfu": False, "recovery": False, "pwnd": False,
            "pwnd_usbliter8": False, "pwnd_checkm8": False})
        monkeypatch.setattr(R, "_bin", lambda t: "/usr/bin/yes")
        from opensleuth import exploitrunner as R
        monkeypatch.setitem(R._EXECUTORS, "logical_pull",
                            lambda t, o: (True, "ok", ""))
        h = A.AgentHarness(tmp_path / "case3", auto_approve=True)
        h.run()
        events = [e["event_type"] for e in h.journal.read()]
        assert "SessionStarted" in events
        assert "DeviceDetected" in events
        assert "FingerprintRecorded" in events
        assert "CapabilityAssessed" in events
        assert "AcquisitionProgress" in events
        assert "SessionCompleted" in events


class TestApprovalGate:
    def test_gates_acquisition_without_consent(self, tmp_path, monkeypatch):
        _fp_monkey(monkeypatch)
        h = A.AgentHarness(tmp_path / "case4", auto_approve=False)
        for _ in range(6):
            if h.terminal() or h.status.state == "AWAITING_APPROVAL":
                break
            h.step()
        assert h.status.state == "AWAITING_APPROVAL"
        assert h.status.pending_approval  # logical + backup listed
        # waiting does not advance
        h.step()
        assert h.status.state == "AWAITING_APPROVAL"
        # journal recorded the wait
        waits = [e for e in h.journal.read()
                 if "awaiting_approval" in str(e.get("payload", {}))]
        assert waits

    def test_approve_resumes_run(self, tmp_path, monkeypatch):
        _fp_monkey(monkeypatch)
        from opensleuth import exploitrunner as R
        monkeypatch.setattr(R, "usb_state", lambda: {
            "devices": [{"product": "iPhone", "serial": "TEST",
                         "product_id": "12a8", "mode": "normal"}],
            "any": True, "dfu": False, "recovery": False, "pwnd": False,
            "pwnd_usbliter8": False, "pwnd_checkm8": False})
        monkeypatch.setattr(R, "_bin", lambda t: "/usr/bin/yes")
        from opensleuth import exploitrunner as R
        monkeypatch.setitem(R._EXECUTORS, "logical_pull",
                            lambda t, o: (True, "ok", ""))
        h = A.AgentHarness(tmp_path / "case5", auto_approve=False)
        for _ in range(6):
            if h.status.state == "AWAITING_APPROVAL":
                break
            h.step()
        assert h.approve(note="examiner consented")
        h.run(max_steps=50)
        assert h.status.state == "CASE_READY", h.status.error
        # consent event journaled
        approvals = [e for e in h.journal.read()
                     if e.get("payload", {}).get("approval") == "EXAMINER"]
        assert approvals

    def test_yes_flag_records_auto_consent(self, tmp_path, monkeypatch):
        _fp_monkey(monkeypatch)
        from opensleuth import exploitrunner as R
        monkeypatch.setattr(R, "usb_state", lambda: {
            "devices": [{"product": "iPhone", "serial": "TEST",
                         "product_id": "12a8", "mode": "normal"}],
            "any": True, "dfu": False, "recovery": False, "pwnd": False,
            "pwnd_usbliter8": False, "pwnd_checkm8": False})
        monkeypatch.setattr(R, "_bin", lambda t: "/usr/bin/yes")
        from opensleuth import exploitrunner as R
        monkeypatch.setitem(R._EXECUTORS, "logical_pull",
                            lambda t, o: (True, "ok", ""))
        h = A.AgentHarness(tmp_path / "case6", auto_approve=True)
        h.run()
        autos = [e for e in h.journal.read()
                 if e.get("payload", {}).get("approval", "").startswith("AUTO")]
        assert autos
        assert h.status.state == "CASE_READY"


class TestAdvisorIsolation:
    def test_advisor_output_labeled_advisory(self, tmp_path, monkeypatch):
        _fp_monkey(monkeypatch)
        from opensleuth import exploitrunner as R
        monkeypatch.setattr(R, "usb_state", lambda: {
            "devices": [{"product": "iPhone", "serial": "TEST",
                         "product_id": "12a8", "mode": "normal"}],
            "any": True, "dfu": False, "recovery": False, "pwnd": False,
            "pwnd_usbliter8": False, "pwnd_checkm8": False})
        monkeypatch.setattr(R, "_bin", lambda t: "/usr/bin/yes")
        from opensleuth import exploitrunner as R
        monkeypatch.setitem(R._EXECUTORS, "logical_pull",
                            lambda t, o: (True, "ok", ""))

        class FakeAdvisor:
            def summarize(self, ctx):
                return "TEST NARRATIVE"

        h = A.AgentHarness(tmp_path / "case7", auto_approve=True)
        h.attach_advisor(FakeAdvisor())
        h.run()
        rep = json.loads((tmp_path / "case7" / "agent-report.json").read_text())
        assert rep["advisory_narrative"] == "TEST NARRATIVE"
        assert "ADVISORY ONLY" in rep["advisory_narrative_disclaimer"]

    def test_advisor_failure_degrades_gracefully(self, tmp_path, monkeypatch):
        _fp_monkey(monkeypatch)
        from opensleuth import exploitrunner as R
        monkeypatch.setattr(R, "usb_state", lambda: {
            "devices": [{"product": "iPhone", "serial": "TEST",
                         "product_id": "12a8", "mode": "normal"}],
            "any": True, "dfu": False, "recovery": False, "pwnd": False,
            "pwnd_usbliter8": False, "pwnd_checkm8": False})
        monkeypatch.setattr(R, "_bin", lambda t: "/usr/bin/yes")
        from opensleuth import exploitrunner as R
        monkeypatch.setitem(R._EXECUTORS, "logical_pull",
                            lambda t, o: (True, "ok", ""))

        class ExplodingAdvisor:
            def summarize(self, ctx):
                raise RuntimeError("no network")

        h = A.AgentHarness(tmp_path / "case8", auto_approve=True)
        h.attach_advisor(ExplodingAdvisor())
        h.run()
        assert h.status.state == "CASE_READY"  # pipeline unaffected
        rep = json.loads((tmp_path / "case8" / "agent-report.json").read_text())
        assert "advisory_narrative" not in rep
        assert rep.get("advisory_narrative_error")

    def test_no_advisor_still_completes(self, tmp_path, monkeypatch):
        _fp_monkey(monkeypatch)
        from opensleuth import exploitrunner as R
        monkeypatch.setattr(R, "usb_state", lambda: {
            "devices": [{"product": "iPhone", "serial": "TEST",
                         "product_id": "12a8", "mode": "normal"}],
            "any": True, "dfu": False, "recovery": False, "pwnd": False,
            "pwnd_usbliter8": False, "pwnd_checkm8": False})
        monkeypatch.setattr(R, "_bin", lambda t: "/usr/bin/yes")
        from opensleuth import exploitrunner as R
        monkeypatch.setitem(R._EXECUTORS, "logical_pull",
                            lambda t, o: (True, "ok", ""))
        h = A.AgentHarness(tmp_path / "case9", auto_approve=True)
        h.run()
        rep = json.loads((tmp_path / "case9" / "agent-report.json").read_text())
        assert "advisory_narrative" not in rep


class TestStatusFile:
    def test_status_written_and_readable(self, tmp_path, monkeypatch):
        monkeypatch.setattr("opensleuth.usb.usb_state",
                            lambda: {"devices": [], "any": False})
        h = A.AgentHarness(tmp_path / "case10")
        h.run()
        sf = tmp_path / "case10" / "agent-state.json"
        assert sf.is_file()
        d = json.loads(sf.read_text())
        assert d["state"] == "UNSUPPORTED"


class TestRealDeviceSmoke:
    """If a device is attached, the harness must at least identify it."""

    def test_live_reaches_gate_or_beyond(self, tmp_path):
        from opensleuth.usb import usb_state
        if not usb_state().get("any"):
            pytest.skip("no device attached")
        h = A.AgentHarness(tmp_path / "case-live", auto_approve=False)
        for _ in range(8):
            if h.terminal() or h.status.state in ("AWAITING_APPROVAL",
                                                  "EXECUTING"):
                break
            h.step()
        assert h.status.state in ("AWAITING_APPROVAL", "EXECUTING",
                                  "CASE_READY", "PARTIAL")
        assert h.status.device.get("chip")
