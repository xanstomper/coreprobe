"""Event-sourced journal tests.

The standard under test: append-only history, corrections as new events,
permanent evidence IDs, first-class failure records, replayable sessions,
and structural verification (no timestamp regressions, no torn lines).
"""

import json

import pytest

from opensleuth import journal as J


@pytest.fixture()
def sesh(tmp_path):
    j = J.new_session(tmp_path / "case1", operator="examiner-a")
    return j


class TestEmit:
    def test_event_has_required_fields(self, sesh):
        e = sesh.emit("DeviceDetected", {"usb": "05ac:1227"})
        for req in ("event_id", "case_id", "session_id", "timestamp",
                    "monotonic_timestamp", "component", "component_version",
                    "event_type", "severity", "device_id", "evidence_id",
                    "parent_event_id", "payload"):
            assert req in e, req
        assert e["event_type"] == "DeviceDetected"
        assert e["operator"] == "examiner-a"

    def test_unknown_event_type_rejected(self, sesh):
        with pytest.raises(J.JournalError, match="unknown event type"):
            sesh.emit("SomethingHappened")

    def test_unknown_severity_rejected(self, sesh):
        with pytest.raises(J.JournalError, match="unknown severity"):
            sesh.emit("Error", {}, severity="loud")

    def test_events_are_appended_not_rewritten(self, sesh, tmp_path):
        e1 = sesh.emit("DeviceDetected", {"n": 1})
        e2 = sesh.emit("DeviceIdentified", {"n": 2})
        events = sesh.read()
        assert len(events) == 3  # SessionStarted + 2
        assert events[1]["event_id"] == e1["event_id"]
        assert events[2]["event_id"] == e2["event_id"]

    def test_double_start_rejected(self, tmp_path):
        j = J.SessionJournal(tmp_path / "c", "S-1")
        j.start()
        with pytest.raises(J.JournalError, match="already started"):
            j.start()


class TestCorrections:
    def test_correction_appends_new_event_referencing_original(self, sesh):
        orig = sesh.emit("DeviceIdentified", {"chip": "A13"})
        sesh.correct(orig["event_id"], "chip was actually A12")
        events = sesh.read()
        corr = events[-1]
        assert corr["event_type"] == "Correction"
        assert corr["parent_event_id"] == orig["event_id"]
        # original untouched
        assert events[1]["payload"] == {"chip": "A13"}


class TestFailures:
    def test_failure_events_are_error_severity(self, sesh):
        e = sesh.failure("Timeout", "acquire", "device did not answer",
                         technical_message="usb timeout after 30s")
        assert e["severity"] == "error"
        assert e["payload"]["human_message"] == "device did not answer"

    def test_warnings_are_warning_severity(self, sesh):
        e = sesh.failure("ParserWarning", "sms", "odd plist")
        assert e["severity"] == "warning"

    def test_non_failure_type_rejected(self, sesh):
        with pytest.raises(J.JournalError, match="not a failure event"):
            sesh.failure("DeviceDetected", "x", "nope")

    def test_failures_surface_in_summary(self, sesh):
        sesh.failure("ParserFailure", "whatsapp", "corrupt db")
        s = sesh.summary()
        assert s["failures"] >= 1
        assert "ParserFailure" in s["failure_types"]


class TestEvidenceIds:
    def test_ids_are_sequential_and_permanent(self, sesh):
        e1 = sesh.evidence_created("/x/backup", 100, "backup")
        e2 = sesh.evidence_created("/x/media", 200, "afc")
        assert e1["evidence_id"] == "EVD-000001"
        assert e2["evidence_id"] == "EVD-000002"

    def test_hash_emits_evidence_hashed_event(self, sesh):
        sesh.evidence_created("/x", 1, "copy", hash_value="ab" * 32)
        types = [e["event_type"] for e in sesh.read()]
        assert "EvidenceCreated" in types
        assert "EvidenceHashed" in types

    def test_derived_evidence_keeps_parent(self, sesh):
        parent = sesh.evidence_created("/fs.img", 5, "full-fs")
        child = sesh.evidence_created("/parsed/messages.json", 1,
                                      "parse", derived_from=parent["evidence_id"])
        assert child["derived_from"] == "EVD-000001"

    def test_concurrent_allocation_is_unique(self, tmp_path):
        """Two journals in one case must not hand out the same EVD id."""
        import threading
        results = []
        def alloc():
            j = J.SessionJournal(tmp_path / "case", "S-" + threading.current_thread().name)
            for _ in range(20):
                results.append(j.next_evidence_id())
        ts = [threading.Thread(target=alloc, name=str(i)) for i in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        assert len(results) == 80
        assert len(set(results)) == 80, "evidence ID collision"


class TestCustody:
    def test_custody_actions(self, sesh):
        e = sesh.custody("EVD-000001", "verified", reason="post-acquisition")
        assert e["event_type"] == "CustodyEvent"
        assert e["evidence_id"] == "EVD-000001"

    def test_unknown_action_rejected(self, sesh):
        with pytest.raises(J.JournalError, match="unknown custody action"):
            sesh.custody("EVD-000001", "shredded")


class TestReplayAndSummary:
    def test_replay_renders_every_event(self, sesh):
        sesh.emit("AcquisitionStarted", {"method": "backup"})
        sesh.evidence_created("/b", 10, "backup", hash_value="cd" * 32)
        sesh.failure("Timeout", "acquire", "syslog stalled")
        text = sesh.replay()
        assert "SessionStarted" in text
        assert "AcquisitionStarted" in text
        assert "EVD-000001" in text
        assert "Timeout" in text
        assert "syslog stalled" in text

    def test_summary_counts(self, sesh):
        sesh.emit("DeviceDetected", {})
        sesh.emit("DeviceDetected", {})
        s = sesh.summary()
        assert s["event_counts"]["DeviceDetected"] == 2


class TestVerifyJournalFile:
    def test_clean_journal_passes(self, tmp_path):
        j = J.new_session(tmp_path / "c")
        j.emit("DeviceDetected", {})
        v = J.verify_journal_file(j.path)
        assert v["ok"] is True
        assert v["events"] >= 2

    def test_torn_line_detected(self, tmp_path):
        j = J.new_session(tmp_path / "c")
        j.emit("DeviceDetected", {})
        with open(j.path, "a") as fh:
            fh.write('{"event_id": "EVT-torn')  # torn write
        v = J.verify_journal_file(j.path)
        assert v["ok"] is False
        assert v["malformed_lines"]

    def test_missing_file_fails_cleanly(self, tmp_path):
        v = J.verify_journal_file(tmp_path / "nope.jsonl")
        assert v["ok"] is False


class TestTypicalWorkflow:
    def test_full_acquisition_session_shape(self, tmp_path):
        """The directive's core workflow journalized end-to-end."""
        j = J.new_session(tmp_path / "case-full", operator="examiner")
        j.emit("DeviceDetected", {"usb_pid": "12a8"})
        j.emit("FingerprintRecorded", {"chip": "A13", "ios": "16.6"})
        j.emit("CapabilityAssessed",
               {"summary": "logical-backup OPERATIONAL; checkm8 INTEGRATED"})
        j.emit("AcquisitionStarted", {"method": "logical-backup"})
        ev = j.evidence_created("/cases/case-full/backup", 123456,
                                "logical-backup", hash_value="ff" * 32)
        j.custody(ev["evidence_id"], "verified", reason="hash match")
        j.emit("ArtifactParsed", {"parser": "sms", "count": 42},
               evidence_id=ev["evidence_id"])
        j.emit("ReportGenerated", {"path": "report.html"})
        j.complete({"evidence": 1, "artifacts": 42})
        s = j.summary()
        assert s["events"] == 11
        assert s["evidence_ids"] == ["EVD-000001"]
        assert s["failures"] == 0
        assert J.verify_journal_file(j.path)["ok"] is True
