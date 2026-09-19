"""Honest acquisition planner tests.

The standard under test: the planner may ONLY select operational
(REGRESSION_TESTED) capabilities with satisfied prerequisites. Integrated
routes surface as VALIDATION REQUIRED; documented routes as RESEARCH ONLY.
"""

import pytest

from opensleuth import planner as P
from opensleuth import truth as T
from opensleuth.fingerprint import Fingerprint


def _fp(chip="", ios="", state="AFU", present=True):
    fp = Fingerprint()
    fp.set("present", present, "test", "Observed")
    fp.set("chip", chip, "test", "Inferred")
    fp.set("ios", ios, "test", "Observed")
    fp.set("state", state, "test", "Observed")
    return fp


@pytest.fixture()
def planner():
    return P.Planner(T.default_registry())


class TestOperationalGating:
    def test_afu_device_offers_logical_backup(self, planner):
        methods = planner.plan(_fp(chip="A13", ios="16.6", state="AFU"))
        lb = next(m for m in methods if m.capability_id == "logical-backup")
        assert lb.verdict == "AVAILABLE"
        assert lb.selectable()

    def test_bfu_device_does_not_offer_logical_backup(self, planner):
        methods = planner.plan(_fp(chip="A13", state="BFU"))
        lb = next(m for m in methods if m.capability_id == "logical-backup")
        assert lb.verdict == "UNSUPPORTED"
        assert not lb.selectable()
        assert any("AFU" in u for u in lb.unmet)

    def test_absent_device_still_allows_offline_capabilities(self, planner):
        """device-info/backup-parse require no attached device by design;
        only device-dependent acquisition becomes unselectable."""
        methods = planner.plan(_fp(state="absent", present=False))
        lb = next(m for m in methods if m.capability_id == "logical-backup")
        assert not lb.selectable()
        ids = {m.capability_id for m in methods if m.selectable()}
        assert ids <= {"device-info", "backup-parse"}

    def test_selectable_are_operational_only(self, planner):
        for state in ("AFU", "BFU", "DFU", "recovery", "absent"):
            fp = _fp(chip="A10", state=state)
            for m in planner.plan(fp):
                if m.selectable():
                    cap = planner.registry.get(m.capability_id)
                    assert cap.status == T.OPERATIONAL_STATUS


class TestIntegratedRoutes:
    def test_checkm8_is_validation_required_on_dfu_a10(self, planner):
        methods = planner.plan(_fp(chip="A10", state="DFU"))
        m = next(m for m in methods if m.capability_id == "checkm8-pwn")
        assert m.verdict == "VALIDATION_REQUIRED"
        assert not m.selectable()
        assert "no recorded lab validation" in m.reason

    def test_checkm8_unsupported_on_wrong_chip(self, planner):
        methods = planner.plan(_fp(chip="A14", state="DFU"))
        m = next(m for m in methods if m.capability_id == "checkm8-pwn")
        assert m.verdict == "VALIDATION_REQUIRED"
        assert m.unmet  # A7-A11 prerequisite fails

    def test_checkm8_unsupported_when_not_dfu(self, planner):
        methods = planner.plan(_fp(chip="A10", state="AFU"))
        m = next(m for m in methods if m.capability_id == "checkm8-pwn")
        assert m.unmet


class TestResearchOnly:
    def test_usbliter8_research_only_on_a13(self, planner):
        methods = planner.plan(_fp(chip="A13", state="DFU"))
        m = next(m for m in methods if m.capability_id == "usbliter8-verify")
        assert m.verdict == "RESEARCH_ONLY"
        assert not m.selectable()
        assert "RP2350" in m.reason or "not CoreProbe-executable" in m.reason

    def test_jailbreak_research_only_afu(self, planner):
        methods = planner.plan(_fp(chip="A13", state="AFU"))
        m = next(m for m in methods if m.capability_id == "afu-jailbreak-detect")
        assert m.verdict == "RESEARCH_ONLY"
        assert m.research_id == "dopamine-family"

    def test_research_route_can_never_become_selectable_via_planner(self, planner):
        """Even a perfect fingerprint match keeps research routes unselectable."""
        fp = _fp(chip="A13", ios="16.6", state="AFU")
        ids = {m.capability_id for m in planner.selectable_methods(fp)}
        assert "usbliter8-verify" not in ids
        assert "afu-jailbreak-detect" not in ids
        assert "checkm8-pwn" not in ids


class TestBest:
    def test_best_returns_operational(self, planner):
        best = planner.best(_fp(chip="A13", state="AFU"))
        assert best is not None
        assert best.selectable()

    def test_best_none_when_no_acquisition_selectable(self, planner):
        """A17 BFU: no acquisition path exists; only offline capabilities
        (device-info of nothing, backup parsing) remain — best() must not
        return an acquisition route."""
        best = planner.best(_fp(state="BFU", chip="A17"))
        assert best is None or best.capability_id in ("device-info",
                                                      "backup-parse")


class TestRender:
    def test_render_plan_shows_verdicts(self, planner):
        fp = _fp(chip="A10", state="DFU")
        text = P.render_plan(planner.plan(fp), fp)
        assert "VALIDATION REQUIRED" in text   # checkm8 on its chip
        assert "UNSUPPORTED" in text           # usbliter8/jailbreak for A10/DFU
        assert "selectable : NO" in text
        assert "selectable methods:" in text
        # RESEARCH ONLY appears for an A13 AFU target (usbliter8/jailbreak)
        fp2 = _fp(chip="A13", state="AFU")
        text2 = P.render_plan(planner.plan(fp2), fp2)
        assert "RESEARCH ONLY" in text2
