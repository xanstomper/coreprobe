"""Path 1-3 research tooling tests: SEPOS analyzer, passcode model, FI planner."""

import struct
import tempfile
from pathlib import Path

import pytest

from opensleuth import faultinjection as FI
from opensleuth import passattack as PA
from opensleuth import sepos as SE


def _macho(size=124):
    # magic(4) | cputype(4)=arm64 | subtype(4) | flags(4) | ncmds(4 @16)
    body = b"\xfe\xed\xfa\xcf" + struct.pack(">II", 0x0100000C, 0)
    body += b"\x00" * 4 + struct.pack("<I", 12)
    body += b"\x90" * max(0, size - len(body))
    return body


def _tlv(version, entries):
    out = b"SEPOS" + struct.pack("<I", version)
    for tag, payload in entries:
        out += struct.pack("<H", tag) + struct.pack("<I", len(payload)) + payload
    return out


def _im4p(image, desc=b"sep 14.0"):
    def blob(b):
        return struct.pack(">I", len(b)) + b
    return b"IM4P" + b"sepi" + blob(desc) + blob(image) + blob(b"") + blob(b"")


class TestSEPOS:
    def test_extract_and_tlv(self, tmp_path):
        f = tmp_path / "sep-firmware.im4p"
        f.write_bytes(_im4p(_tlv(14, [(1, _macho()), (2, b"RAMDISK!")])))
        inv = SE.extract_sep_image(f)
        assert inv["im4p"]["type"] == "sepi"
        tlv = inv["tlv"]
        assert tlv[0]["container_version"] == 14
        assert tlv[0]["is_macho"] is True
        assert tlv[1]["name"] == "txtramdisk"
        assert inv["sepos_macho"]["arch"] == "arm64"

    def test_non_sepos_tolerated(self, tmp_path):
        f = tmp_path / "x.im4p"
        f.write_bytes(_im4p(b"just some payload"))
        inv = SE.extract_sep_image(f)
        assert inv["tlv"] == []
        assert inv["sepos_macho"] is None

    def test_find_sep_images(self, tmp_path):
        d = tmp_path / "ipsw"
        d.mkdir()
        (d / "sep-firmware.n812.im4p").write_bytes(b"x")
        (d / "kernelcache").write_bytes(b"y")
        hits = SE.find_sep_images(d)
        assert len(hits) == 1 and "sep-firmware" in hits[0].name

    def test_diff_detects_changes(self, tmp_path):
        old = tmp_path / "old.im4p"
        new = tmp_path / "new.im4p"
        old.write_bytes(_im4p(_tlv(14, [(1, _macho()), (2, b"RAMDISK!")])))
        new.write_bytes(_im4p(_tlv(15, [(1, _macho(636)), (2, b"RAMDISK!"), (3, b"PTCH")]),
                              desc=b"sep 15.0"))
        o, n = SE.extract_sep_image(old), SE.extract_sep_image(new)
        changes = SE.diff_builds(o, n)
        assert any("0x0001" in c and "+512" in c for c in changes)
        assert any("0x0003" in c and "ADDED" in c for c in changes)
        assert any("sep 14.0" in c and "sep 15.0" in c for c in changes)

    def test_render(self, tmp_path):
        f = tmp_path / "s.im4p"
        f.write_bytes(_im4p(_tlv(14, [(1, _macho())])))
        out = SE.render(SE.extract_sep_image(f))
        assert "SEP firmware" in out and "sepos-image" in out


class TestPassAttack:
    def test_delay_table(self):
        assert PA.delay_after(5) == 0
        assert PA.delay_after(6) == 60
        assert PA.delay_after(9) == 3600
        assert PA.delay_after(50) == 3600

    def test_model_6digit_infeasible(self):
        m = PA.model("6-digit", days=30)
        assert m.keyspace == 1_000_000
        assert m.coverage < 0.01
        assert "infeasible" in m.verdict

    def test_model_4digit_weak(self):
        m = PA.model("4-digit", days=365)
        # model caps sane attempts (policy + loop guard) — and stays bounded
        assert 0 < m.attempts_budget <= 600
        assert m.coverage <= 1.0

    def test_unknown_space_raises(self):
        with pytest.raises(ValueError):
            PA.model("9-digit")

    def test_research_targets_honest(self):
        t = PA.render_targets()
        assert "no public counter bypass exists" in t
        assert "counter persistence" in t

    def test_render(self):
        out = PA.render(PA.model("6-digit"))
        assert "keyspace" in out and "verdict" in out


class TestFaultInjection:
    def test_targets_present(self):
        ids = {t["id"] for t in FI.TARGET_MOMENTS}
        assert {"sepos-counter", "key-unwrap", "delay-sched"} <= ids

    def test_equipment_tiers(self):
        names = [e["name"] for e in FI.EQUIPMENT]
        assert any("ChipWhisperer" in n for n in names)
        assert any("laser" in n.lower() for n in names)

    def test_plan_grid(self):
        p = FI.default_plan("sepos-counter")
        assert p.grid_size() > 1000
        assert p.repeats == 5

    def test_campaign_logging(self):
        c = FI.Campaign("key-unwrap", FI.default_plan("key-unwrap"))
        c.log_result(100, 50, "normal")
        c.log_result(150, 60, "glitch-effect", note="reset observed")
        assert len(c.interesting()) == 1
        assert c.interesting()[0]["outcome"] == "glitch-effect"

    def test_render_plan(self):
        t = FI.TARGET_MOMENTS[1]
        out = FI.render_plan(FI.default_plan(t["id"]), t)
        assert "goal" in out and "grid points" in out