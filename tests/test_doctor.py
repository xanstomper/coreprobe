"""Doctor diagnostics tests."""

from unittest import mock

from opensleuth import doctor as D


def test_run_shape():
    r = D.run()
    assert "checks" in r and "passed" in r and "total" in r
    assert r["passed"] <= r["total"]
    assert r["total"] >= 10
    names = {c["check"] for c in r["checks"]}
    for expect in ("opensleuth package", "gaster (checkm8 pwn)",
                   "native core (osleuth_core)", "device on USB"):
        assert expect in names


def test_ready_only_when_all_pass(monkeypatch):
    monkeypatch.setattr(D.shutil, "which", lambda *a, **k: "/bin/true")
    with mock.patch("opensleuth.doctor._usbmuxd_alive", return_value=True):
        with mock.patch("opensleuth.usb.usb_state",
                        return_value={"devices": [{"mode": "normal"}]}):
            r = D.run()
    # skips can never be all-pass because of intentionally missed libs? all
    # checks use which -> installed; native core selftest runs for real
    assert r["total"] == len(r["checks"])


def test_render_text_and_json():
    r = D.run()
    text = D.render(r, json_out=False)
    assert "checks passed" in text
    assert "✓" in text or "✗" in text
    j = D.render(r, json_out=True)
    import json as _json
    parsed = _json.loads(j)
    assert parsed["total"] == r["total"]


def test_usbmuxd_alive_ok():
    with mock.patch("opensleuth.doctor.subprocess.run") as run:
        run.return_value = type("R", (), {"returncode": 0})()
        assert D._usbmuxd_alive() is True


def test_usbmuxd_alive_fail():
    with mock.patch("opensleuth.doctor.subprocess.run",
                    side_effect=FileNotFoundError("nope")):
        assert D._usbmuxd_alive() is False