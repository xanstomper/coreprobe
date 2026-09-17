"""DFU research workbench tests: trace analysis, corpus, fuzzer, notebook."""

import tempfile
from pathlib import Path

from opensleuth import dfufuzz as F
from opensleuth import dfutrace as T
from opensleuth import silicon as S

CAPTURE = """\
f9f3a01 1000000000 S Co:1:002:0 s 21 01 0000 0000 0800 0000
f9f3a01 1000000100 C Co:1:002:0 0
f9f3a02 1000000200 S Co:1:002:0 s 21 01 0000 0000 0010 0000
f9f3a03 1000000300 S Ci:1:002:0 s a1 03 0000 0000 0006 0000
f9f3a04 1000000400 C Ci:1:002:0 0
f9f3a05 1000000500 S Co:1:002:0 s 21 00 0000 0000 0000 0000
f9f3a06 1000000600 S Ci:1:002:0 s a1 05 0000 0000 0001 0000
f9f3a07 1000000700 S Co:1:002:0 s 21 01 0000 0000 ffff 0000
"""


def test_parse_usbmon():
    events = T.parse_usbmon_text(CAPTURE)
    assert len(events) == 6  # setup-carrying lines only (C completions lack "s")
    first = events[0]
    assert first["bmRequestType"] == 0x21 and first["bRequest"] == 0x01
    assert first["wLength"] == 0x800


def test_analyze_flags_anomalies():
    rep = T.analyze(T.parse_usbmon_text(CAPTURE))
    assert rep["dfu_requests"] >= 6
    assert any("unusual DNLOAD length 0x0010" in a for a in rep["anomalies"])
    assert any("0xffff" in a and "boundary" in a for a in rep["anomalies"])
    assert any("DETACH" in a for a in rep["anomalies"])
    assert rep["request_counts"]["DNLOAD"] == 3


def test_analyze_rejects_none():
    rep = T.analyze([])
    assert rep["events"] == 0 and rep["anomalies"] == []


def test_build_corpus_dedupes():
    events = T.parse_usbmon_text(CAPTURE)
    rows = T.build_corpus(events)
    keys = [(r["bmRequestType"], r["bRequest"], r["wLength"]) for r in rows]
    assert len(keys) == len(set(keys))
    assert any(r["req"] == "DNLOAD" and r["wLength"] == 0x800 for r in rows)


def test_corpus_roundtrip(tmp_path):
    rows = T.build_corpus(T.parse_usbmon_text(CAPTURE))
    p = tmp_path / "c.csv"
    n = T.write_corpus(rows, p)
    assert n == len(rows)
    back = T.read_corpus(p)
    assert len(back) == n
    assert int(back[0]["wLength"]) == rows[0]["wLength"]


def test_parse_garbage_lines():
    assert T.parse_usbmon_text("not a usbmon line\n") == []


class _Dev:
    def __init__(self, die_after=1000):
        self.n = 0
        self.die_after = die_after

    def alive(self):
        return self.n < self.die_after

    def ctrl_transfer(self, *a, **k):
        self.n += 1
        return b"\x00"


def test_fuzz_runs_and_counts():
    dev = _Dev()
    corpus = [{"bmRequestType": 0x21, "bRequest": 1, "wValue": 0,
               "wIndex": 0, "wLength": 0x800, "req": "DNLOAD"}]
    r = F.run_fuzz(dev, corpus, iterations=50, seed=1, log=lambda s: None)
    assert r["sent"] == 50
    assert r["crashes"] == 0


def test_fuzz_detects_death():
    class DieDev:
        def __init__(self):
            self.n = 0
            self.dead = False

        def alive(self):
            return not self.dead

        def ctrl_transfer(self, *a, **k):
            self.n += 1
            if self.n >= 3:
                self.dead = True
                raise TimeoutError("device timeout")
            return b"\x00"

    dev = DieDev()
    corpus = [{"bmRequestType": 0x21, "bRequest": 1, "wValue": 0,
               "wIndex": 0, "wLength": 0x800, "req": "DNLOAD"}]
    r = F.run_fuzz(dev, corpus, iterations=200, seed=2, log=lambda s: None)
    assert r["crashes"] >= 1


def test_mutation_variants_boundaries():
    base = {"bmRequestType": 0x21, "bRequest": 1, "wValue": 0,
            "wIndex": 0, "wLength": 0x800}
    variants = F.mutation_variants(base, 42)
    lens = {v["wLength"] for v in variants}
    assert 0xFFFF in lens and 0 in lens
    assert len(variants) >= 30


def test_canonical_sequences_cover_flows():
    seqs = F.canonical_sequences()
    assert len(seqs) >= 7
    all_reqs = {r["bRequest"] for s in seqs for r in s}
    assert all_reqs == {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
    # every request is DFU-class (0x21 host->dev, 0xA1 dev->host)
    for s in seqs:
        for r in s:
            assert r["bmRequestType"] in (0x21, 0xA1)
    # upload flow (all-IN) exists alongside download flows (host->dev)
    assert any(all(r["bmRequestType"] == 0xA1 for r in s) for s in seqs)


def test_mutate_sequence_tags_one_step():
    seq = F.canonical_sequences()[0]
    out = F.mutate_sequence(seq, 0, seed=7)
    mutated = [r for r in out if r.get("mutated")]
    assert len(mutated) == 1
    # untouched steps keep canonical values
    assert out[1] == seq[1]


def test_sequence_fuzz_stops_on_first_death():
    class DieDev:
        def __init__(self):
            self.sends = 0

        def alive(self):
            return self.sends < 4

        def ctrl_transfer(self, *a, **k):
            self.sends += 1
            if self.sends >= 4:
                raise TimeoutError("device gone")
            return b"\x00"

    r = F.run_sequence_fuzz(DieDev(), iterations=100, seed=3,
                            log=lambda s: None)
    assert r["crashes"] >= 1
    assert r["sent"] < 100  # stopped at death


def test_sequence_fuzz_records_kill_request():
    class KillDev:
        def __init__(self):
            self.sends = 0
            self.alive_ok = True

        def alive(self):
            return self.alive_ok

        def ctrl_transfer(self, bm, b, wv, wi, wl, timeout):
            self.sends += 1
            if self.sends >= 5:
                self.alive_ok = False
                raise OSError("no such device")
            return b"\x00"

    r = F.run_sequence_fuzz(KillDev(), iterations=100, seed=5,
                            log=lambda s: None)
    assert r["kills"], "expected a recorded kill"
    k = r["kills"][0]
    assert "req" in k and "wLength" in k and "seq_step" in k
    assert "mutated" in k


def test_sequence_fuzz_resumes_after_reentry():
    """Simulates examiner re-entering DFU: alive() recovers, run continues."""

    class ResurrectDev:
        def __init__(self):
            self.sends = 0
            self.dead_until = -1  # send# that kills; stays dead a few polls

        def alive(self):
            if self.dead_until < 0:
                return True
            # recovers after 8 polls (examiner re-enters DFU)
            self.polls = getattr(self, "polls", 0) + 1
            return self.polls >= 8

        def ctrl_transfer(self, bm, b, wv, wi, wl, timeout):
            self.sends += 1
            if self.dead_until < 0 and self.sends == 5:
                self.dead_until = self.sends
                raise OSError("no such device")
            return b"\x00"

    dev = ResurrectDev()

    def _wait_for_reentry(kill):
        # mirrors dfu_live.wait_for_reentry: block until alive() recovers
        for _ in range(200):
            if dev.alive():
                return
            import time
            time.sleep(0.001)

    r = F.run_sequence_fuzz(dev, iterations=60, seed=11,
                            log=lambda s: None, resume_wait_s=5.0,
                            on_death=_wait_for_reentry)
    assert r["crashes"] >= 1
    assert r["kills"]
    assert r["sent"] > 5  # continued after re-entry


def test_lab_kit_includes_fuzzer():
    with tempfile.TemporaryDirectory() as td:
        r = S.lab_kit(td, chip="A13")
        assert "dfu-fuzz.py" in r["files"]
        fz = (Path(td) / "dfu-fuzz.py").read_text()
        assert "run_fuzz" in fz and "pyusb" in fz


def test_notebook_append_and_list():
    with tempfile.TemporaryDirectory() as td:
        nb1 = S.notebook(td, note="baseline capture")
        assert len(nb1["entries"]) == 1
        nb2 = S.notebook(td, note="pwn attempt 1")
        assert len(nb2["entries"]) == 2
        assert nb2["entries"][0]["note"] == "baseline capture"
        assert (Path(td) / "research.json").exists()


def test_render_notebook():
    nb = {"notebook": "/x/research.json",
          "entries": [{"ts": "2026-09-16T00:00:00+00:00", "note": "n1"}]}
    out = S.render_notebook(nb)
    assert "research notebook" in out and "n1" in out