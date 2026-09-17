"""Live DFU transport tests: discovery, safety gates, protocol mapping."""

import pytest

from opensleuth import dfu_live as L


class _FakeDev:
    """pyusb lookalike with controllable ctrl_transfer."""

    def __init__(self, pid=L.DFU_PID, bus=1, address=2, responses=None):
        self.idVendor = L.APPLE_VID
        self.idProduct = pid
        self.bus = bus
        self.address = address
        self.manufacturer = "Apple Inc."
        self.product = "Mobile Device (DFU Mode)"
        self.serial_number = "TESTDFU001"
        self.ctrl_calls = []
        self.responses = responses or {}
        self.dead = False

    def ctrl_transfer(self, bmRequestType, bRequest, wValue=0, wIndex=0,
                      data_or_wLength=None, timeout=None):
        self.ctrl_calls.append((bmRequestType, bRequest, wValue, wIndex,
                                data_or_wLength, timeout))
        if self.dead:
            raise OSError("device disconnected")
        key = (bmRequestType, bRequest, wValue, wIndex, data_or_wLength)
        if key in self.responses:
            return self.responses[key]
        return b"\x00" * (data_or_wLength if isinstance(data_or_wLength, int) else 0)


def _patch_find(monkeypatch, dev):
    import usb.core as uc
    monkeypatch.setattr(uc, "find", lambda **kw: dev)
    monkeypatch.setattr(L, "find_dfu_device", lambda: dev)


def test_find_dfu_returns_device(monkeypatch):
    dev = _FakeDev()
    _patch_find(monkeypatch, dev)
    assert L.find_dfu_device() is dev


def test_find_dfu_none_when_no_pyusb(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name.startswith("usb"):
            raise ImportError("no pyusb")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert L.find_dfu_device() is None
    assert L.find_apple_devices() == []


def test_transport_refuses_non_dfu_device():
    dev = _FakeDev(pid=L.RECOVERY_PID)
    with pytest.raises(RuntimeError, match="refusing non-DFU"):
        L.DfuTransport(dev, log=lambda s: None)


def test_transport_requires_device():
    with pytest.raises(RuntimeError, match="no Apple device in DFU mode"):
        L.DfuTransport(None, log=lambda s: None)


def test_in_request_reads_wlength():
    dev = _FakeDev()
    t = L.DfuTransport(dev, log=lambda s: None)
    resp = t.ctrl_transfer(L.DFU_IN, L.GETSTATUS, 0, 0, 6, 500)
    assert len(resp) == 6
    call = dev.ctrl_calls[-1]
    assert call[0] == L.DFU_IN and call[1] == L.GETSTATUS
    assert call[4] == 6  # wLength as int for IN


def test_out_request_without_data_stage():
    dev = _FakeDev()
    t = L.DfuTransport(dev, log=lambda s: None)
    t.ctrl_transfer(L.DFU_OUT, L.CLRSTATUS, 0, 0, 0x800, 500)
    call = dev.ctrl_calls[-1]
    assert call[0] == L.DFU_OUT and call[1] == L.CLRSTATUS
    assert call[4] == b""  # no data stage for non-DNLOAD OUT


def test_dnload_data_stage_capped():
    dev = _FakeDev()
    t = L.DfuTransport(dev, log=lambda s: None)
    t.ctrl_transfer(L.DFU_OUT, L.DNLOAD, 0, 0, 0xFFFF, 500)
    call = dev.ctrl_calls[-1]
    assert call[1] == L.DNLOAD
    assert len(call[4]) == L.MAX_DNLOAD_DATA  # capped, not 0xFFFF


def test_dnload_small_passthrough():
    dev = _FakeDev()
    t = L.DfuTransport(dev, log=lambda s: None)
    t.ctrl_transfer(L.DFU_OUT, L.DNLOAD, 0, 0, 64, 500)
    call = dev.ctrl_calls[-1]
    assert len(call[4]) == 64


def test_non_dfu_class_dropped():
    dev = _FakeDev()
    t = L.DfuTransport(dev, log=lambda s: None)
    resp = t.ctrl_transfer(0x40, 0x01, 0, 0, 8, 500)  # vendor class
    assert resp == b""
    assert len(dev.ctrl_calls) == 0


def test_alive_same_device(monkeypatch):
    dev = _FakeDev()
    monkeypatch.setattr(L, "find_dfu_device", lambda: dev)
    t = L.DfuTransport(dev, log=lambda s: None)
    assert t.alive() is True


def test_alive_false_when_gone(monkeypatch):
    dev = _FakeDev()
    t = L.DfuTransport(dev, log=lambda s: None)
    monkeypatch.setattr(L, "find_dfu_device", lambda: None)
    assert t.alive() is False


def test_alive_rebinds_on_reentry(monkeypatch):
    dev1 = _FakeDev(bus=1, address=2)
    dev2 = _FakeDev(bus=1, address=9)
    # device "re-enters" DFU at a new address after a death: alive() must
    # rebind so the hunt resumes on the fresh handle
    monkeypatch.setattr(L, "find_dfu_device", lambda: dev2)
    t = L.DfuTransport(dev1, log=lambda s: None)
    assert t.alive() is True
    assert t.dev is dev2  # rebound


def test_verify_reports_dfu_mode():
    dev = _FakeDev(responses={
        (L.DFU_IN, L.GETSTATUS, 0, 0, 6): b"\x05\x00\x00\x00\x02\x00",
        (L.DFU_IN, L.GETSTATE, 0, 0, 1): b"\x02",
    })
    t = L.DfuTransport(dev, log=lambda s: None)
    v = t.verify()
    assert v["dfu_mode"] is True
    assert v["status"] == 5 and v["state"] == 2
    assert v["dfu_state"] == 2
    assert "TESTDFU001" in v["device"]


def test_render_verify_mentions_live():
    out = L.render_verify({"device": "x", "bus": 1, "address": 2,
                           "dfu_mode": True})
    assert "--live" in out


def test_get_status_tolerates_errors():
    class BrokenDev(_FakeDev):
        def ctrl_transfer(self, *a, **k):
            raise OSError("timeout")

    t = L.DfuTransport(BrokenDev(), log=lambda s: None)
    st = t.get_status()
    assert "status_error" in st or "state_error" in st


def test_default_corpus_covers_all_requests():
    from opensleuth import dfutrace as T
    rows = T.default_corpus()
    reqs = {r["bRequest"] for r in rows}
    assert reqs == {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
    dns = [r for r in rows if r["bRequest"] == 0x01]
    assert {r["wLength"] for r in dns} >= {0, 0x800, 0x1000}
    status = [r for r in rows if r["bRequest"] == 0x03]
    assert status[0]["wLength"] == 6


def test_record_fuzz_run_accepts_prebuilt_corpus(tmp_path):
    from opensleuth import campaign as C
    from opensleuth import dfutrace as T
    state = C.load(tmp_path / "c.json")
    cid = C.new_campaign(state, "bootstrap", "DFU", chip="A13")["id"]

    class Dev:
        def alive(self):
            return True

        def ctrl_transfer(self, *a, **k):
            return b"\x00"

    r = C.record_fuzz_run(state, cid, "", Dev(), iterations=30,
                          corpus=T.default_corpus(), log=lambda s: None)
    assert r["fuzz"]["sent"] == 30
    assert r["fuzz"]["crashes"] == 0