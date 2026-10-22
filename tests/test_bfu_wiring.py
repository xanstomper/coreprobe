"""BFU layer wiring tests (opensleuth.bfu -> exploitrunner + TRUTH registry).

The BFU extraction/intelligence layer (bfu.run_ramdisk_extract,
bfu.expectations/yield_card) used to be reachable only from the CLI.
These tests pin the runner wiring: both new executors gate honestly when
called directly, build_plan appends them (extract BEFORE intel) for
checkm8/usbliter8 chips, and the TRUTH registry entries stay in sync
between capabilities.json and truth.py's SEED_CAPABILITIES.
"""

import pytest

from opensleuth import bfu
from opensleuth import exploitrunner as R
from opensleuth.exploitrunner import Target, build_plan


def _pwnd_target(chip="A13", ios="18.5", marker="usbliter8", payload_dir=None):
    st = {"devices": [], "any": True, "dfu": True, "recovery": False,
          "pwnd": marker == "checkm8",
          "pwnd_checkm8": marker == "checkm8",
          "pwnd_usbliter8": marker == "usbliter8"}
    raw = {"usb_state": st}
    if payload_dir is not None:
        raw["bfu_payload_dir"] = str(payload_dir)
    return Target(present=True, chip=chip, ios=ios, state="pwned-dfu",
                  pwnd=marker, raw=raw)


class TestBfuExecutors:
    """Both new executors, called directly (the TRUTH-registry standard)."""

    def test_extract_requires_pwnd_marker(self):
        # pwned-dfu state claimed, but NO marker in the target state
        t = Target(present=True, chip="A13", ios="18.5", state="pwned-dfu",
                   pwnd="", raw={"usb_state": {"pwnd": False,
                                                "pwnd_checkm8": False,
                                                "pwnd_usbliter8": False}})
        ok, detail, _ = R.exec_bfu_ramdisk_extract(t)
        assert ok is False
        assert "PWND" in detail and "marker" in detail

    def test_extract_missing_payloads_lists_exact_files(self, tmp_path, monkeypatch):
        empty = tmp_path / "payloads-empty"
        empty.mkdir()
        # keep the shared payloads dir out of resolution for hermeticity
        monkeypatch.setattr(R.payloads, "payloads_dir",
                            lambda: tmp_path / "shared-nonexistent")
        t = _pwnd_target(payload_dir=empty)
        ok, detail, _ = R.exec_bfu_ramdisk_extract(t)
        assert ok is False
        for f in bfu.RAMDISK_FILES:
            assert f in detail, f"missing file {f} not named in: {detail}"
        assert str(empty) in detail  # says WHERE the payloads belong

    def test_extract_partial_payloads_names_only_missing(self, tmp_path, monkeypatch):
        partial = tmp_path / "payloads-partial"
        partial.mkdir()
        (partial / "iBSS").write_bytes(b"x")
        monkeypatch.setattr(R.payloads, "payloads_dir",
                            lambda: tmp_path / "shared-nonexistent")
        t = _pwnd_target(chip="A10", marker="checkm8", payload_dir=partial)
        ok, detail, _ = R.exec_bfu_ramdisk_extract(t)
        assert ok is False
        for f in ("iBEC", "ramdisk", "devicetree", "trustcache"):
            assert f in detail
        assert "missing payload files: iBSS" not in detail

    def test_extract_delegates_when_gates_pass(self, tmp_path, monkeypatch):
        full = tmp_path / "payloads-full"
        full.mkdir()
        for f in bfu.RAMDISK_FILES:
            (full / f).write_bytes(b"x")
        calls = {}

        def fake_extract(payload_dir, out):
            calls["payload_dir"] = payload_dir
            calls["out"] = out
            return {"ok": True, "steps": [], "keybags_tar": None,
                    "note": "keybags pulled (fake)"}

        monkeypatch.setattr(bfu, "run_ramdisk_extract", fake_extract)
        t = _pwnd_target(payload_dir=full)
        ok, detail, output = R.exec_bfu_ramdisk_extract(t)
        assert ok is True
        assert calls["payload_dir"] == full
        assert "usbliter8" in detail
        assert "keybags pulled (fake)" in output

    def test_bfu_intel_a13_renders_yield_card(self):
        t = Target(present=True, chip="A13", ios="18.5", state="BFU")
        ok, detail, output = R.exec_bfu_intel(t)
        assert ok is True
        assert "BFU yield card" in output
        assert "A13" in output
        assert "SEP" in output  # the wall is documented per device
        assert "usbliter8" in detail

    def test_bfu_intel_checkm8_chip(self):
        t = Target(present=True, chip="A10", ios="15.0", state="DFU")
        ok, detail, output = R.exec_bfu_intel(t)
        assert ok is True and "checkm8" in detail
        assert "BFU yield card" in output

    def test_bfu_intel_unknown_chip_fails_honestly(self):
        t = Target(present=True, chip="", ios="", state="BFU")
        ok, detail, _ = R.exec_bfu_intel(t)
        assert ok is False and "chip unknown" in detail

    def test_executors_registered(self):
        assert R._EXECUTORS["bfu_ramdisk_extract"] is R.exec_bfu_ramdisk_extract
        assert R._EXECUTORS["bfu_intel"] is R.exec_bfu_intel


class TestBfuPlanWiring:
    def test_a13_pwnd_plan_extract_before_intel(self):
        plan = build_plan(_pwnd_target())
        strategies = [i.strategy for i in plan]
        assert "bfu_ramdisk_extract" in strategies
        assert "bfu_intel" in strategies
        assert strategies.index("bfu_ramdisk_extract") < strategies.index("bfu_intel")
        # intel is read-only + always succeeds: it must sort LAST so it
        # can never shadow a real extraction/acquisition route
        assert strategies[-1] == "bfu_intel"
        extract = next(i for i in plan if i.strategy == "bfu_ramdisk_extract")
        intel = next(i for i in plan if i.strategy == "bfu_intel")
        assert extract.bfu is True and intel.bfu is True
        assert intel.tools == []  # no tooling prereq beyond the probe

    def test_checkm8_dfu_plan_has_intel_without_extract(self):
        # not pwned yet: intel (guidance) yes, extraction (needs PWND) no
        plan = build_plan(Target(present=True, chip="A10", ios="15.0",
                                 state="DFU"))
        strategies = [i.strategy for i in plan]
        assert "bfu_intel" in strategies
        assert "bfu_ramdisk_extract" not in strategies

    def test_checkm8_pwnd_plan_has_extract(self):
        t = _pwnd_target(chip="A11", ios="14.0", marker="checkm8")
        strategies = [i.strategy for i in build_plan(t)]
        assert "bfu_ramdisk_extract" in strategies
        assert strategies.index("bfu_ramdisk_extract") < strategies.index("bfu_intel")

    def test_afu_plan_has_no_bfu_items(self):
        # device already unlocked: BFU steps are moot, logical owns the plan
        plan = build_plan(Target(present=True, chip="A13", ios="16.6.1",
                                 state="AFU"))
        strategies = [i.strategy for i in plan]
        assert "bfu_intel" not in strategies
        assert "bfu_ramdisk_extract" not in strategies
        assert strategies[-1] == "logical_pull"

    def test_non_bootrom_chip_has_no_bfu_items(self):
        plan = build_plan(Target(present=True, chip="A14", ios="17.0",
                                 state="BFU"))
        strategies = [i.strategy for i in plan]
        assert "bfu_intel" not in strategies
        assert "bfu_ramdisk_extract" not in strategies


class TestBfuRegistrySync:
    def test_registry_entries_in_sync_and_audit_clean(self):
        from opensleuth import truth as T
        seed = T.default_registry()
        file_reg = T.TruthRegistry.load(T.REGISTRY_PATH)
        assert seed.audit() == [] and file_reg.audit() == []
        seed_map = {c.capability_id: c.status for c in seed.all()}
        file_map = {c.capability_id: c.status for c in file_reg.all()}
        assert seed_map == file_map
        assert file_map["bfu-ramdisk-extract"] == "DOCUMENTED"
        assert file_map["bfu-intel"] == "INTEGRATED"

    def test_operational_pool_unchanged(self):
        from opensleuth import truth as T
        reg = T.default_registry()
        ids = {c.capability_id for c in reg.operational()}
        assert ids == {"device-info", "logical-backup", "backup-parse"}
        assert reg.get("bfu-intel") not in reg.operational()
        assert reg.get("bfu-ramdisk-extract") not in reg.operational()
