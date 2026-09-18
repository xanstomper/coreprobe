"""Capability TRUTH system tests.

The CoreProbe standard under test: a documented route is NEVER selectable as
an operational capability; only REGRESSION_TESTED entries with recorded
validation evidence, adapter references, and fixtures enter the operational
pool. Promotion must follow the strict ladder.
"""

import json

import pytest

from opensleuth import truth as T


# --------------------------------------------------------------------- machine


class TestStatusMachine:
    def test_only_regression_tested_is_operational(self):
        for s in T.ALL_STATUSES:
            assert T.is_operational(s) == (s == "REGRESSION_TESTED"), s

    def test_research_only_covers_everything_else(self):
        for s in T.ALL_STATUSES:
            if s != "REGRESSION_TESTED":
                assert T.is_research_only(s), s

    def test_ladder_is_strict_single_step(self):
        assert T.can_promote("UNKNOWN", "DOCUMENTED")
        assert T.can_promote("DOCUMENTED", "PUBLIC_POC")
        assert T.can_promote("INTEGRATED", "REGRESSION_TESTED")
        assert not T.can_promote("UNKNOWN", "REGRESSION_TESTED")   # skipping
        assert not T.can_promote("DOCUMENTED", "LAB_VALIDATED")     # skipping
        assert not T.can_promote("REGRESSION_TESTED", "UNKNOWN")    # backwards
        assert not T.can_promote("INTEGRATED", "INTEGRATED")        # same

    def test_terminal_states_absorb(self):
        assert not T.can_promote("BROKEN", "REGRESSION_TESTED")
        assert not T.can_promote("RETIRED", "DOCUMENTED")
        assert T.can_promote("BROKEN", "BROKEN")


# --------------------------------------------------------------------- registry


class TestSeedRegistry:
    def test_seed_loads_and_is_consistent(self):
        reg = T.default_registry()
        assert reg.audit() == []

    def test_operational_pool_is_small_and_honest(self):
        reg = T.default_registry()
        ops = reg.operational()
        ids = {c.capability_id for c in ops}
        # Only genuinely adapter-backed + fixture-tested capabilities
        assert ids == {"device-info", "logical-backup", "backup-parse"}

    def test_checkm8_is_not_operational(self):
        """checkm8 has a real adapter but no recorded hardware validation ->
        must stay INTEGRATED (research/validation pending), never selectable."""
        reg = T.default_registry()
        cap = reg.get("checkm8-pwn")
        assert cap is not None
        assert cap.status == "INTEGRATED"
        assert cap not in reg.operational()
        assert T.is_research_only(cap.status)

    def test_jailbreak_routes_are_documented_only(self):
        reg = T.default_registry()
        cap = reg.get("afu-jailbreak-detect")
        assert cap.status == "DOCUMENTED"
        assert cap not in reg.operational()

    def test_usbliter8_is_documented_only(self):
        reg = T.default_registry()
        cap = reg.get("usbliter8-verify")
        assert cap.status == "DOCUMENTED"
        assert not cap.adapter  # no CoreProbe adapter executes the exploit


class TestRegistryAudit:
    def _registry_with(self, **overrides):
        base = {
            "capability_id": "cap-x", "name": "X", "status": "REGRESSION_TESTED",
            "category": "acquisition",
        }
        base.update(overrides)
        return T.TruthRegistry([T.Capability.from_dict(base)])

    def test_operational_without_adapter_is_flagged(self):
        reg = self._registry_with(
            adapter="",
            validation_evidence=[{"result": "VALIDATED", "environment": "t",
                                  "at": "2026-01-01"}],
            last_successful_validation="2026-01-01",
            test_fixture="tests/x.py")
        problems = reg.audit()
        assert any("without an adapter" in p for p in problems)

    def test_operational_without_evidence_is_flagged(self):
        reg = self._registry_with(
            adapter="pkg.fn",
            validation_evidence=[],
            last_successful_validation="2026-01-01",
            test_fixture="tests/x.py")
        problems = reg.audit()
        assert any("validation evidence" in p for p in problems)

    def test_operational_without_validated_entry_is_flagged(self):
        reg = self._registry_with(
            adapter="pkg.fn",
            validation_evidence=[{"result": "FAILED", "environment": "t",
                                  "at": "2026-01-01"}],
            last_successful_validation="",
            test_fixture="tests/x.py")
        problems = reg.audit()
        assert any("VALIDATED evidence" in p for p in problems)

    def test_operational_without_fixture_is_flagged(self):
        reg = self._registry_with(
            adapter="pkg.fn",
            validation_evidence=[{"result": "VALIDATED", "environment": "t",
                                  "at": "2026-01-01"}],
            last_successful_validation="2026-01-01",
            test_fixture="")
        problems = reg.audit()
        assert any("test fixture" in p for p in problems)

    def test_build_both_supported_and_failed_is_flagged(self):
        reg = self._registry_with(
            status="DOCUMENTED",
            supported_builds=["A10+iOS15"],
            failed_builds=["A10+iOS15"])
        problems = reg.audit()
        assert any("both supported and failed" in p for p in problems)

    def test_recent_failure_beating_success_is_flagged(self):
        reg = self._registry_with(
            adapter="pkg.fn",
            validation_evidence=[{"result": "VALIDATED", "environment": "t",
                                  "at": "2026-01-01"}],
            last_successful_validation="2026-01-01",
            last_failed_validation="2026-02-01",
            test_fixture="tests/x.py")
        problems = reg.audit()
        assert any("more recent" in p for p in problems)

    def test_invalid_status_is_flagged(self):
        reg = self._registry_with(status="SHIPPED")
        problems = reg.audit()
        assert any("invalid status" in p for p in problems)


class TestPromotion:
    def test_legal_promotion(self):
        """A single legal step with no audit impact succeeds (DOCUMENTED ->
        PUBLIC_POC for the usbliter8 research record)."""
        reg = T.default_registry()
        cap = reg.promote("usbliter8-verify", "PUBLIC_POC")
        assert cap.status == "PUBLIC_POC"
        # still research-only, not operational
        assert "usbliter8-verify" not in {c.capability_id for c in reg.operational()}

    def test_illegal_skip_is_rejected(self):
        reg = T.default_registry()
        with pytest.raises(T.RegistryError, match="illegal promotion"):
            reg.promote("usbliter8-verify", "LAB_VALIDATED")

    def test_promotion_to_operational_without_evidence_rolls_back(self):
        """The auditor must make OPERATIONAL-without-evidence impossible even
        through the API: promote() rolls the status back on inconsistency."""
        reg = T.default_registry()
        cap = reg.get("checkm8-pwn")
        # checkm8 is INTEGRATED -> next step is REGRESSION_TESTED, but it has
        # no validation evidence: the audit must reject and roll back.
        with pytest.raises(T.RegistryError, match="would become inconsistent"):
            reg.promote("checkm8-pwn", "REGRESSION_TESTED")
        assert reg.get("checkm8-pwn").status == "INTEGRATED"

    def test_promotion_after_recording_evidence_succeeds(self):
        reg = T.default_registry()
        reg.record_validation(
            "checkm8-pwn", "VALIDATED",
            environment="lab: iPhone 7 (A10) iOS 15.8 DFU + gaster",
            evidence={"pwnd_marker": "PWND:[checkm8]", "operator": "lab"},
            at="2026-09-18T12:00:00")
        cap = reg.get("checkm8-pwn")
        cap.test_fixture = "lab fixture: A10-iOS15-DFU"
        reg.promote("checkm8-pwn", "REGRESSION_TESTED")
        assert "checkm8-pwn" in {c.capability_id for c in reg.operational()}


class TestValidationRecording:
    def test_invalid_result_rejected(self):
        reg = T.default_registry()
        with pytest.raises(T.RegistryError, match="invalid validation result"):
            reg.record_validation("checkm8-pwn", "SUCCESS", environment="t")

    def test_success_updates_last_successful(self):
        reg = T.default_registry()
        reg.record_validation("checkm8-pwn", "VALIDATED",
                              environment="lab", at="2026-09-18T10:00:00")
        cap = reg.get("checkm8-pwn")
        assert cap.last_successful_validation == "2026-09-18T10:00:00"
        assert any(e["result"] == "VALIDATED" for e in cap.validation_evidence)

    def test_failure_updates_last_failed(self):
        reg = T.default_registry()
        reg.record_validation("checkm8-pwn", "FAILED",
                              environment="lab", at="2026-09-18T10:00:00")
        assert reg.get("checkm8-pwn").last_failed_validation == "2026-09-18T10:00:00"


class TestPersistence:
    def test_save_and_reload_roundtrip(self, tmp_path):
        reg = T.default_registry()
        p = tmp_path / "capabilities.json"
        reg.save(p)
        reg2 = T.TruthRegistry.load(p)
        assert {c.capability_id for c in reg2.all()} == \
               {c.capability_id for c in reg.all()}
        assert {c.capability_id for c in reg2.operational()} == \
               {c.capability_id for c in reg.operational()}

    def test_load_rejects_inconsistent_file(self, tmp_path):
        bad = {"capabilities": [{
            "capability_id": "bad", "name": "Bad",
            "status": "REGRESSION_TESTED", "category": "acquisition",
            # no adapter/evidence/fixture -> audit failure on load
        }]}
        p = tmp_path / "bad.json"
        p.write_text(json.dumps(bad))
        with pytest.raises(T.RegistryError, match="consistency audit"):
            T.TruthRegistry.load(p)

    def test_load_rejects_missing_file(self, tmp_path):
        with pytest.raises(T.RegistryError, match="not found"):
            T.TruthRegistry.load(tmp_path / "nope.json")

    def test_load_rejects_invalid_json(self, tmp_path):
        p = tmp_path / "broken.json"
        p.write_text("{not json")
        with pytest.raises(T.RegistryError, match="not valid JSON"):
            T.TruthRegistry.load(p)


class TestRender:
    def test_render_marks_non_operational(self):
        text = T.render(T.default_registry())
        assert "NOT selectable" in text
        assert "checkm8-pwn" in text
        assert "OPERATIONAL" in text

    def test_status_labels(self):
        assert T.status_label("REGRESSION_TESTED") == "OPERATIONAL"
        assert T.status_label("DOCUMENTED") == "DOCUMENTED"
