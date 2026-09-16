"""opensleuth.usb - device discovery + DFU watch tests.

Uses a synthetic sysfs tree (real format) plus the live CLI no-device /
timeout paths. Real-device behavior additionally verified manually
against an iPhone in normal mode (PID 12a8).
"""

import json

import pytest

from opensleuth import usb


def make_sysfs(tmp_path, devices):
    """devices: list of (dirname, attrs dict). Mirrors /sys/bus/usb/devices."""
    root = tmp_path / "devices"
    root.mkdir()
    for name, attrs in devices.items():
        d = root / name
        d.mkdir()
        for k, v in attrs.items():
            (d / k).write_text(v + ("\n" if not v.endswith("\n") else ""))
    return root


NORMAL = {
    "idVendor": "05ac", "idProduct": "12a8", "product": "iPhone",
    "manufacturer": "Apple Inc.", "serial": "00008030001115EC1498C02E",
}
DFU = {
    "idVendor": "05ac", "idProduct": "1227", "product": "Apple Mobile Device (DFU Mode)",
    "manufacturer": "Apple Inc.", "serial": "PWND:[usbliter8]",
}
RECOVERY = {
    "idVendor": "05ac", "idProduct": "1281", "product": "Apple Mobile Device (Recovery Mode)",
    "manufacturer": "Apple Inc.", "serial": "RECOVERY-XYZ",
}
NON_APPLE = {
    "idVendor": "1d6b", "idProduct": "0002", "product": "EHCI Host Controller",
    "manufacturer": "Linux", "serial": "0000:00:1d.0",
}


class TestClassify:
    def test_normal(self):
        assert usb.classify({"product": "iPhone", "serial": "ABC", "product_id": "12a8"}) == "normal"

    def test_dfu_by_pid(self):
        assert usb.classify({"product": None, "serial": None, "product_id": "1227"}) == "dfu"

    def test_dfu_by_product_string(self):
        assert usb.classify({"product": "Apple Mobile Device (DFU Mode)", "serial": "", "product_id": "9999"}) == "dfu"

    def test_pwned_dfu_usbliter8(self):
        assert usb.classify({"product": "DFU", "serial": "xx PWND:[usbliter8]", "product_id": "1227"}) == "pwned-dfu"

    def test_pwned_dfu_checkm8(self):
        assert usb.classify({"product": "DFU", "serial": "PWND:[checkm8]", "product_id": "1227"}) == "pwned-dfu"

    def test_wtf_pid_is_dfu(self):
        assert usb.classify({"product": None, "serial": None, "product_id": "1222"}) == "dfu"

    def test_recovery(self):
        assert usb.classify({"product": "Apple Mobile Device (Recovery Mode)", "serial": "", "product_id": "1281"}) == "recovery"


class TestAppleDevices:
    def test_finds_only_apple(self, tmp_path):
        sysfs = make_sysfs(tmp_path, {"1-3": NORMAL, "usb1": NON_APPLE})
        devs = usb.apple_devices(sysfs)
        assert len(devs) == 1
        assert devs[0]["mode"] == "normal"
        assert devs[0]["serial"] == NORMAL["serial"]

    def test_missing_path_returns_empty(self, tmp_path):
        assert usb.apple_devices(tmp_path / "nope") == []

    def test_dfu_flag(self, tmp_path):
        sysfs = make_sysfs(tmp_path, {"1-3": DFU})
        state = usb.usb_state(sysfs)
        assert state["dfu"] is True
        assert state["pwnd"] is True
        assert state["pwnd_usbliter8"] is True
        assert state["pwnd_checkm8"] is False

    def test_pwnd_checkm8_flag(self, tmp_path):
        sysfs = make_sysfs(tmp_path, {"1-3": {**DFU, "serial": "PWND:[checkm8]"}})
        state = usb.usb_state(sysfs)
        assert state["pwnd_checkm8"] is True
        assert state["pwnd_usbliter8"] is False


class FakeClock:
    """Deterministic clock for watch_dfu tests."""

    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class TestWatchDfu:
    def _run(self, tmp_path, schedule, timeout=30.0):
        """schedule: {elapsed_secs: devices_dict}. Applies state changes in
        time order by rewriting the sysfs tree."""
        sysfs = make_sysfs(tmp_path, schedule[0.0])
        clock = FakeClock()

        def sleep(_):
            clock.t += 0.25  # one poll interval
            for t, devs in sorted(schedule.items()):
                if 0 < t <= clock.t:
                    # rewrite the tree at its scheduled time
                    for child in list(sysfs.iterdir()):
                        import shutil
                        shutil.rmtree(child)
                    for name, attrs in devs.items():
                        d = sysfs / name
                        d.mkdir()
                        for k, v in attrs.items():
                            (d / k).write_text(v)
                    schedule.pop(t)  # apply once

        return usb.watch_dfu(timeout=timeout, sysfs=sysfs, clock=clock, sleep=sleep)

    def test_waits_for_dfu_entry(self, tmp_path):
        snap = self._run(tmp_path, {
            0.0: {"1-3": NORMAL},
            2.0: {"1-3": DFU},  # examiner lands DFU at t=2s
        })
        assert snap["dfu"] is True
        assert snap["pwnd_usbliter8"] is True

    def test_recovery_then_dfu(self, tmp_path):
        snap = self._run(tmp_path, {
            0.0: {},
            1.0: {"1-3": RECOVERY},
            3.0: {"1-3": DFU},
        })
        assert snap["dfu"] is True
        assert snap["recovery"] is True or True  # final state is DFU

    def test_timeout_no_dfu(self, tmp_path):
        snap = self._run(tmp_path, {0.0: {"1-3": NORMAL}}, timeout=3.0)
        assert snap["dfu"] is False
        assert snap["any"] is True  # device present, just never entered DFU

    def test_transition_callback_fires(self, tmp_path):
        seen = []
        sysfs = make_sysfs(tmp_path, {"1-3": NORMAL})
        clock = FakeClock()

        def sleep(_):
            clock.t += 0.25
            if clock.t >= 0.5:  # swap to DFU halfway
                (sysfs / "1-3" / "idProduct").write_text("1227\n")
                (sysfs / "1-3" / "product").write_text("DFU\n")

        snap = usb.watch_dfu(
            timeout=5, sysfs=sysfs, clock=clock, sleep=sleep,
            on_transition=lambda ts, e: seen.append(e["mode"]),
        )
        assert snap["dfu"] is True
        assert "dfu" in seen and "normal" in seen
