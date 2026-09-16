"""Campaign orchestrator + timeline tests."""

import json
import tempfile
from pathlib import Path
from unittest import mock

from opensleuth import campaign as C
from opensleuth import timeline as T

CAPTURE = Path("/tmp/dfu-capture.txt").read_text() if Path("/tmp/dfu-capture.txt").exists() else """\
f9f3a01 1000000000 S Co:1:002:0 s 21 01 0000 0000 0800 0000
f9f3a02 1000000200 S Co:1:002:0 s 21 01 0000 0000 ffff 0000
f9f3a03 1000000300 S Ci:1:002:0 s a1 03 0000 0000 0006 0000
"""


def _state(tmp: Path):
    p = tmp / "campaign.json"
    return C.load(p), p


class FakeDev:
    def __init__(self):
        self.n = 0

    def alive(self):
        return self.n < 30

    def ctrl_transfer(self, *a, **k):
        self.n += 1
        return b"\x00"


def test_new_campaign_and_persist(tmp_path):
    state, p = _state(tmp_path)
    c = C.new_campaign(state, "x", "DFU", chip="A13", ios="26.6.1")
    C.save(state, p)
    loaded = C.load(p)
    assert c["id"] in loaded["campaigns"]
    assert loaded["campaigns"][c["id"]]["chip"] == "A13"


def test_session_lifecycle(tmp_path):
    state, p = _state(tmp_path)
    cid = C.new_campaign(state, "x", "DFU")["id"]
    s = C.start_session(state, cid)
    assert s["id"] == "s0001"
    C.finish_session(state, s["id"], {"sent": 42, "crashes": 1})
    C.save(state, p)
    loaded = C.load(p)
    assert loaded["sessions"][0]["sent"] == 42
    assert loaded["campaigns"][cid]["sessions"] == 1


def test_add_and_triage_leads(tmp_path):
    state, p = _state(tmp_path)
    cid = C.new_campaign(state, "x", "DFU")["id"]
    lead = C.add_lead(state, "s0001", "trace-anomaly", "big DNLOAD", campaign_id=cid)
    assert lead["verdict"] == "observed"
    tri = C.triage_lead(state, lead["id"], "promising", notes="reproduced 3x")
    assert tri["verdict"] == "promising"
    assert "reproduced" in tri["notes"]
    assert state["campaigns"][cid]["leads"] == 1


def test_triage_bad_verdict_rejected(tmp_path):
    state, _ = _state(tmp_path)
    lead = C.add_lead(state, "s1", "k", "d")
    try:
        C.triage_lead(state, lead["id"], "super-finding")
        assert False, "should reject"
    except ValueError:
        pass


def test_record_fuzz_run_creates_leads(tmp_path):
    state, p = _state(tmp_path)
    cid = C.new_campaign(state, "x", "DFU")["id"]
    r = C.record_fuzz_run(state, cid, CAPTURE, FakeDev(),
                          iterations=20, log=lambda s: None)
    assert r["fuzz"]["sent"] == 20
    kinds = {l["kind"] for l in state["leads"]}
    assert "trace-anomaly" in kinds
    C.save(state, p)
    assert C.load(p)["leads"]


def test_record_fuzz_run_death_lead(tmp_path):
    class DieDev:
        def __init__(self):
            self.dead = False
            self.n = 0

        def alive(self):
            return not self.dead

        def ctrl_transfer(self, *a, **k):
            self.n += 1
            if self.n >= 2:
                self.dead = True
                raise TimeoutError("timeout")
            return b"\x00"

    state, _ = _state(tmp_path)
    cid = C.new_campaign(state, "x", "DFU")["id"]
    r = C.record_fuzz_run(state, cid, CAPTURE, DieDev(),
                          iterations=50, log=lambda s: None)
    deaths = [l for l in state["leads"] if l["kind"] == "device-death"]
    assert deaths and deaths[0]["verdict"] == "promising"


def test_render_status_honesty_rule(tmp_path):
    state, _ = _state(tmp_path)
    out = C.render_status(state)
    assert "public writeup" in out
    assert "nothing enters the exploit catalog" in out


# ---------------- timeline ----------------

def test_timeline_merge_sorts():
    events = T.merge({
        "sms": [{"date": "2026-09-01 10:00:00", "text": "b"}],
        "calls": [{"date": "2026-08-31 09:00:00", "caller": "x"}],
    })
    assert len(events) == 2
    assert events[0]["source"] == "calls"


def test_timeline_extracts_fields():
    events = T.merge({"notes": [{"created": "2026-09-01", "title": "t"}]})
    assert events[0]["ts"].startswith("2026-09-01")
    assert events[0]["text"] == "t"


def test_timeline_skips_untimestamped():
    events = T.merge({"sms": [{"text": "no ts"}]})
    assert events == []


def test_timeline_apple_epoch():
    events = T.merge({"sms": [{"ts": 700000000.0, "text": "apple"}]})
    assert events and events[0]["ts"].startswith("20")


def test_timeline_from_artifacts_shape():
    arts = {
        "messages": [{"date": "2026-01-01 10:00:00", "text": "m"}],
        "history": [{"date": "2026-01-01 11:00:00", "url": "http://x"}],
        "media_index": [{"n": 1}],  # ignored
    }
    events = T.from_backup_artifacts(arts)
    assert {e["source"] for e in events} == {"sms", "safari"}


def test_timeline_csv_roundtrip(tmp_path):
    events = T.merge({"sms": [{"date": "2026-01-01", "text": "x"}]})
    p = tmp_path / "t.csv"
    n = T.write_csv(events, p)
    assert n == 1
    back = T.load_csv(p)
    assert back[0]["text"] == "x"


def test_timeline_render():
    events = T.merge({"sms": [{"date": "2026-01-01", "text": "hello"}]})
    out = T.render(events)
    assert "super-timeline" in out and "hello" in out
    assert "no timestamped events" in T.render([])