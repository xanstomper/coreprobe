"""Event-sourced session journal tests (M3).

The CoreProbe standard under test: every significant operation is a
structured, append-only event. Evidence gets permanent IDs with custody.
Failures are first-class events. History is never rewritten - corrections
reference originals. The journal must survive concurrent writers and
render into a human-auditable replay.
"""

import json
import subprocess
import sys
from multiprocessing import Process
from pathlib import Path

import pytest

from opensleuth import journal as J

ROOT = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------- schema

class TestEventSchema:
    def test_every_event_has_required_fields(self, tmp_path):
        j = J.new_session(tmp_path, operator="examiner-1")
        j.emit("DeviceDetected", {"udid": "00008101-TEST"})
        ev = j.emit("EvidenceCreated", {"path": "x"}, evidence_id="EVD-000001")
        for req in ("event_id", "case_id", "session_id", "timestamp",
                    "monotonic_timestamp", "component", "component_version",
                    "event_type", "severity", "device_id", "evidence_id",
                    "parent_event_id", "operator", "payload"):
            assert req in ev, req
        assert ev["operator"] == "examiner-1"
        assert ev["event_id"].startswith("EVT-")

    def test_unknown_event_type_rejected(self, tmp_path):
        j = J.new_session(tmp_path)
        with pytest.raises(J.JournalError):
            j.emit("NotARealEvent", {})

    def test_unknown_severity_rejected(self, tmp_path):
        j = J.new_session(tmp_path)
        with pytest.raises(J.JournalError):
            j.emit("DeviceDetected", {}, severity="loud")

    def test_timestamps_are_utc_iso(self, tmp_path):
        j = J.new_session(tmp_path)
        events = j.read()
        assert events[0]["timestamp"].endswith("+00:00")

    def test_component_version_tracks_package(self, tmp_path):
        from opensleuth import __version__
        j = J.new_session(tmp_path)
        assert j.read()[0]["component_version"] == __version__


# -------------------------------------------------------------- append-only

class TestAppendOnly:
    def test_events_accumulate_in_order(self, tmp_path):
        j = J.new_session(tmp_path)
        for i in range(5):
            j.emit("Warning", {"i": i}, severity="warning")
        events = j.read()
        assert [e["payload"]["i"] for e in events[1:]] == [0, 1, 2, 3, 4]

    def test_corrections_never_rewrite_history(self, tmp_path):
        j = J.new_session(tmp_path)
        orig = j.emit("DeviceIdentified", {"model": "iPhone12,1"})
        j.correct(orig["event_id"], "model was actually iPhone13,2")
        events = j.read()
        # original untouched
        assert events[1]["payload"] == {"model": "iPhone12,1"}
        # correction appended, referencing original
        corr = events[2]
        assert corr["event_type"] == "Correction"
        assert corr["parent_event_id"] == orig["event_id"]
        assert "actually" in corr["payload"]["correction"]

    def test_start_twice_rejected(self, tmp_path):
        j = J.SessionJournal(tmp_path, "S-MANUAL")
        j.start()
        with pytest.raises(J.JournalError):
            j.start()

    def test_verify_journal_file_ok(self, tmp_path):
        j = J.new_session(tmp_path)
        j.emit("DeviceDetected", {})
        j.complete({})
        v = J.verify_journal_file(j.path)
        assert v["ok"] and v["events"] == 3 and not v["malformed_lines"]

    def test_verify_journal_file_detects_malformed(self, tmp_path):
        j = J.new_session(tmp_path)
        with open(j.path, "a") as fh:
            fh.write("{not json\n")
        v = J.verify_journal_file(j.path)
        assert not v["ok"] and v["malformed_lines"] == [2]

    def test_verify_journal_file_detects_timestamp_regression(self, tmp_path):
        j = J.new_session(tmp_path)
        good = json.loads(j.path.read_text().splitlines()[0])
        evil = dict(good, timestamp="2020-01-01T00:00:00+00:00")
        with open(j.path, "a") as fh:
            fh.write(json.dumps(evil) + "\n")
        v = J.verify_journal_file(j.path)
        assert not v["ok"] and v["timestamp_regressions"] == 1


# ------------------------------------------------------------------ evidence

class TestEvidence:
    def test_evidence_ids_sequential(self, tmp_path):
        j = J.new_session(tmp_path)
        a = j.next_evidence_id()
        b = j.next_evidence_id()
        c = j.next_evidence_id()
        assert (a, b, c) == ("EVD-000001", "EVD-000002", "EVD-000003")

    def test_evidence_created_emits_created_and_hashed(self, tmp_path):
        j = J.new_session(tmp_path)
        rec = j.evidence_created("/cases/c1/backup", 1234,
                                 "idevicebackup2", hash_value="ab" * 32)
        assert rec["evidence_id"] == "EVD-000001"
        assert rec["hash"] == "ab" * 32
        types = [e["event_type"] for e in j.read()]
        assert types == ["SessionStarted", "EvidenceCreated", "EvidenceHashed"]
        assert j.read()[1]["evidence_id"] == "EVD-000001"
        assert j.read()[2]["payload"]["algorithm"] == "sha256"

    def test_no_hash_no_hashed_event(self, tmp_path):
        j = J.new_session(tmp_path)
        j.evidence_created("/tmp/x", 1, "probe")
        assert "EvidenceHashed" not in [e["event_type"] for e in j.read()]

    def test_custody_action_whitelist(self, tmp_path):
        j = J.new_session(tmp_path)
        j.custody("EVD-000001", "created")
        j.custody("EVD-000001", "transferred", actor="courier")
        j.custody("EVD-000001", "exported", reason="defense copy")
        with pytest.raises(J.JournalError):
            j.custody("EVD-000001", "incinerated")

    def test_derived_evidence_links_parent(self, tmp_path):
        j = J.new_session(tmp_path)
        j.evidence_created("/c/backup", 10, "backup", hash_value="ff")
        d = j.evidence_created("/c/report", 5, "dump report",
                               derived_from="EVD-000001", hash_value="ee")
        assert d["derived_from"] == "EVD-000001"


# ------------------------------------------------------------------ failures

class TestFailures:
    def test_failure_is_first_class_event(self, tmp_path):
        j = J.new_session(tmp_path)
        ev = j.failure("Timeout", "acquire-backup",
                       "backup timed out after 600s",
                       "idevicebackup2 rc=124",
                       recovery_attempt="retry once",
                       final_status="failed")
        assert ev["severity"] == "error"
        p = ev["payload"]
        assert p["human_message"] == "backup timed out after 600s"
        assert p["recovery_attempt"] == "retry once"
        assert ev["component"] == "acquire-backup"

    def test_warning_failure_gets_warning_severity(self, tmp_path):
        j = J.new_session(tmp_path)
        ev = j.failure("ParserWarning", "dump", "note table empty")
        assert ev["severity"] == "warning"

    def test_non_failure_type_rejected(self, tmp_path):
        j = J.new_session(tmp_path)
        with pytest.raises(J.JournalError):
            j.failure("DeviceDetected", "x", "not a failure")

    def test_failures_surface_in_summary(self, tmp_path):
        j = J.new_session(tmp_path)
        j.failure("Error", "step-a", "boom")
        j.failure("Timeout", "step-b", "slow")
        s = j.summary()
        assert s["failures"] == 2
        assert s["failure_types"] == ["Error", "Timeout"]


# -------------------------------------------------------------------- replay

class TestReplay:
    def test_replay_renders_human_timeline(self, tmp_path):
        j = J.new_session(tmp_path, case_id="CASE-42")
        j.emit("DeviceDetected", {"udid": "UDID-1"}, device_id="UDID-1")
        j.evidence_created("/c/backup", 999, "idevicebackup2",
                           hash_value="ab" * 32)
        j.failure("Timeout", "step", "too slow")
        j.complete({"dest": "/c/backup"})
        text = j.replay()
        assert "CASE-42" in text
        assert "SessionStarted" in text
        assert "DeviceDetected" in text
        assert "EvidenceCreated" in text and "EVD-000001" in text
        assert "Timeout" in text and "[ERROR]" in text
        assert "SessionCompleted" in text

    def test_summary_counts_and_evidence(self, tmp_path):
        j = J.new_session(tmp_path)
        j.emit("DeviceDetected", {})
        j.evidence_created("/a", 1, "m1")
        j.evidence_created("/b", 2, "m2")
        s = j.summary()
        assert s["events"] == 4  # start, detect, 2x EvidenceCreated (no hashes)
        assert s["evidence_ids"] == ["EVD-000001", "EVD-000002"]
        assert s["event_counts"]["EvidenceCreated"] == 2


# --------------------------------------------------------------- concurrency

def _alloc_worker(case_dir: str, n: int, out_file: str):
    j = J.SessionJournal(case_dir, f"S-WORKER-{n}")
    ids = [j.next_evidence_id() for _ in range(10)]
    Path(out_file).write_text(json.dumps(ids))


class TestConcurrency:
    def test_concurrent_evidence_id_allocation_is_unique(self, tmp_path):
        outs = []
        procs = []
        for i in range(4):
            out = tmp_path / f"ids-{i}.json"
            outs.append(out)
            procs.append(Process(target=_alloc_worker,
                                 args=(str(tmp_path), i, str(out))))
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=30)
        all_ids = [i for o in outs for i in json.loads(o.read_text())]
        assert len(all_ids) == 40
        assert len(set(all_ids)) == 40, "evidence IDs must never collide"
        # and they form the complete 1..40 range with no gaps
        nums = sorted(int(x.split("-")[1]) for x in all_ids)
        assert nums == list(range(1, 41))

    def test_two_journals_one_case_different_sessions(self, tmp_path):
        j1 = J.new_session(tmp_path)
        j2 = J.new_session(tmp_path)
        assert j1.session_id != j2.session_id
        assert j1.path != j2.path
        j1.emit("DeviceDetected", {})
        j2.emit("DeviceDetected", {})
        assert len(j1.read()) == 2 and len(j2.read()) == 2


# ---------------------------------------------------------------- CLI wiring

class TestCliWiring:
    def _fake_bin(self, tmp_path, tool: str, stdout: str) -> Path:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir(exist_ok=True)
        script = bin_dir / tool
        script.write_text(f"#!/bin/sh\necho '{stdout}'\n")
        script.chmod(0o755)
        return bin_dir

    def _run_cli(self, *argv, extra_path: Path | None = None):
        import os
        env = dict(os.environ)
        if extra_path:
            env["PATH"] = f"{extra_path}:{env.get('PATH', '')}"
        return subprocess.run(
            [sys.executable, "-m", "opensleuth", *argv],
            capture_output=True, text=True, cwd=ROOT, timeout=120, env=env)

    def test_acquire_info_journals_evidence_and_completion(self, tmp_path):
        bin_dir = self._fake_bin(
            tmp_path, "ideviceinfo",
            "ProductType: iPhone12,1\\nProductVersion: 18.7.1\\n"
            "UniqueDeviceID: 00008101-TESTUDID")
        case = tmp_path / "case"
        r = self._run_cli("acquire", "info", "--out", str(tmp_path / "device.json"),
                          "--case", str(case), "--examiner", "Jane Doe",
                          extra_path=bin_dir)
        assert r.returncode == 0, r.stderr
        jfiles = list((case / "journal").glob("S-*.jsonl"))
        assert len(jfiles) == 1
        events = [json.loads(x) for x in jfiles[0].read_text().splitlines()]
        types = [e["event_type"] for e in events]
        assert types[0] == "SessionStarted"
        assert "EvidenceCreated" in types and "EvidenceHashed" in types
        assert types[-1] == "SessionCompleted"
        ev = next(e for e in events if e["event_type"] == "EvidenceCreated")
        assert ev["evidence_id"] == "EVD-000001"
        assert ev["device_id"] == "00008101-TESTUDID"
        assert ev["operator"] == "Jane Doe"
        assert ev["payload"]["hash"] and len(ev["payload"]["hash"]) == 64

    def test_acquire_backup_failure_is_journaled(self, tmp_path):
        # idevicebackup2 exists but fails: stub exits non-zero
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "idevicebackup2").write_text("#!/bin/sh\nexit 255\n")
        (bin_dir / "idevicebackup2").chmod(0o755)
        case = tmp_path / "case"
        r = self._run_cli("acquire", "backup", "--out", str(tmp_path / "bk"),
                          "--case", str(case), extra_path=bin_dir)
        assert r.returncode != 0
        jf = next(iter((case / "journal").glob("S-*.jsonl")))
        events = [json.loads(x) for x in jf.read_text().splitlines()]
        failure = [e for e in events if e["severity"] == "error"]
        assert failure, "device failure must be a journaled error event"
        assert failure[0]["event_type"] == "DeviceDisconnected"
        assert "human_message" in failure[0]["payload"]

    def test_dump_writes_provenance_and_journals_parse(self, tmp_path):
        # build the synthetic backup fixture
        fx = tmp_path / "fixture"
        subprocess.run([sys.executable, "tests/fixture.py", str(fx)],
                       cwd=ROOT, check=True, timeout=120)
        case = tmp_path / "case"
        out = tmp_path / "report-out"
        r = self._run_cli("dump", str(fx), "-o", str(out),
                          "--case", str(case), "--examiner", "Jane")
        assert r.returncode == 0, r.stderr
        art = json.loads((out / "artifacts.json").read_text())
        prov = art["provenance"]
        assert prov["parser"] == "opensleuth.artifacts suite"
        assert prov["source_path"] == str(fx)
        assert prov["source_manifest_sha256"]
        assert prov["extracted_at"].endswith("+00:00")
        assert "tool_version" in prov
        jf = next(iter((case / "journal").glob("S-*.jsonl")))
        events = [json.loads(x) for x in jf.read_text().splitlines()]
        types = [e["event_type"] for e in events]
        assert "ArtifactParsed" in types
        assert "SessionCompleted" in types
        assert "EvidenceCreated" in types  # the report itself is evidence

    def test_certify_journals_seal_event(self, tmp_path):
        case = tmp_path / "case"
        case.mkdir()
        (case / "sms.db").write_bytes(b"evidence")
        out = tmp_path / "sealed"
        r = self._run_cli("certify", str(case), "--out", str(out),
                          "--examiner", "Jane Doe")
        assert r.returncode == 0, r.stderr
        jf = next(iter((case / "journal").glob("S-*.jsonl")))
        events = [json.loads(x) for x in jf.read_text().splitlines()]
        types = [e["event_type"] for e in events]
        assert "SessionStarted" in types
        assert "ReportGenerated" in types
        assert types[-1] == "SessionCompleted"

    def test_no_case_flag_means_no_journal(self, tmp_path):
        bin_dir = self._fake_bin(tmp_path, "ideviceinfo",
                                 "ProductType: iPhone12,1")
        r = self._run_cli("acquire", "info", "--out",
                          str(tmp_path / "d.json"), extra_path=bin_dir)
        assert r.returncode == 0
        assert not list((tmp_path).rglob("S-*.jsonl"))


# --------------------------------------------------------- journal + certify

class TestJournalSealInteraction:
    def test_journal_files_are_sealed_into_manifest(self, tmp_path):
        """Certify must include journal files (they are evidence too)."""
        from opensleuth import certify as C
        case = tmp_path / "case"
        j = J.new_session(case, operator="Jane")
        j.evidence_created(str(case / "backup"), 5, "test", hash_value="aa")
        (case / "backup").write_bytes(b"12345")
        out = tmp_path / "sealed"
        r = C.certify(case, out, "Jane")
        rels = {f["relpath"] for f in json.loads(
            (out / C.REPORT_NAME).read_text())["files"]}
        journal_files = [p.relative_to(case).as_posix()
                         for p in (case / "journal").rglob("*") if p.is_file()]
        for rel in journal_files:
            assert rel in rels, f"journal file {rel} missing from seal"
        v = C.verify(out / C.REPORT_NAME)
        assert v["integrity_ok"]
