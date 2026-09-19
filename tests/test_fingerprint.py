"""Device fingerprint provenance tests."""

from opensleuth import fingerprint as F


class TestProperty:
    def test_invalid_confidence_rejected(self):
        import pytest
        with pytest.raises(ValueError, match="invalid confidence"):
            F.Property("x", "src", "Probably")

    def test_roundtrip_dict(self):
        p = F.Property("A13", "table", "Inferred")
        assert p.to_dict() == {"value": "A13", "source": "table",
                               "confidence": "Inferred"}


class TestFingerprint:
    def test_set_get_value(self):
        fp = F.Fingerprint()
        fp.set("chip", "A13", "table", "Inferred")
        assert fp.get("chip").confidence == "Inferred"
        assert fp.value("chip") == "A13"
        assert fp.chip == "A13"

    def test_unknown_property_is_none(self):
        fp = F.Fingerprint()
        assert fp.get("nope") is None
        assert fp.value("nope") is None

    def test_empty_state_defaults(self):
        fp = F.Fingerprint()
        assert fp.chip == "" and fp.ios == "" and fp.state == ""


def _fp_with(**props):
    fp = F.Fingerprint()
    for k, (v, src, conf) in props.items():
        fp.set(k, v, src, conf)
    return fp


class TestRender:
    def test_render_shows_provenance(self):
        fp = _fp_with(
            model=("iPhone 11", "KNOWN_DEVICES table", "Inferred"),
            chip=("A13", "ProductType table", "Inferred"),
            ios=("16.6", "lockdown ProductVersion", "Observed"),
            state=("AFU", "lockdown reachable", "Observed"),
        )
        text = F.render(fp)
        assert "[Observed]" in text and "[Inferred]" in text
        assert "lockdown ProductVersion" in text
        assert "iPhone 11" in text


class TestFingerprintDevice:
    def test_absent_device(self, monkeypatch):
        monkeypatch.setattr(F, "usb_state",
                            lambda: {"devices": [], "any": False})
        fp = F.fingerprint_device()
        assert fp.value("present") is False
        assert fp.value("state") == "absent"

    def test_dfu_device_observed(self, monkeypatch):
        monkeypatch.setattr(F, "usb_state", lambda: {
            "devices": [{"product": "Apple Mobile Device (DFU Mode)",
                         "serial": "ZZZZ", "product_id": "1227",
                         "mode": "dfu"}],
            "any": True, "dfu": True, "recovery": False, "pwnd": False,
            "pwnd_usbliter8": False, "pwnd_checkm8": False})
        monkeypatch.setattr(F, "_lockdown_info", lambda timeout=20: {})
        fp = F.fingerprint_device()
        assert fp.value("state") == "DFU"
        assert fp.get("state").confidence == "Observed"

    def test_pwnd_dfu_records_pwned_by(self, monkeypatch):
        monkeypatch.setattr(F, "usb_state", lambda: {
            "devices": [{"product": "DFU", "serial": "PWND:[checkm8]",
                         "product_id": "1227", "mode": "pwned-dfu"}],
            "any": True, "dfu": True, "recovery": False, "pwnd": True,
            "pwnd_usbliter8": False, "pwnd_checkm8": True})
        fp = F.fingerprint_device()
        assert fp.value("state") == "pwned-dfu"
        assert fp.value("pwnd_by") == "checkm8"
        assert fp.get("pwnd_by").confidence == "Observed"

    def test_booted_locked_is_bfu_inferred(self, monkeypatch):
        monkeypatch.setattr(F, "usb_state", lambda: {
            "devices": [{"product": "iPhone", "serial": "00008030...",
                         "product_id": "12a8", "mode": "normal"}],
            "any": True, "dfu": False, "recovery": False, "pwnd": False,
            "pwnd_usbliter8": False, "pwnd_checkm8": False})
        monkeypatch.setattr(F, "_lockdown_info", lambda timeout=20: {})
        monkeypatch.setattr(F, "chip_from_irecovery", lambda: "")
        fp = F.fingerprint_device()
        assert fp.value("state") == "BFU"
        assert fp.get("state").confidence == "Inferred"

    def test_afu_device_full_identity(self, monkeypatch):
        monkeypatch.setattr(F, "usb_state", lambda: {
            "devices": [{"product": "iPhone", "serial": "00008030...",
                         "product_id": "12a8", "mode": "normal"}],
            "any": True, "dfu": False, "recovery": False, "pwnd": False,
            "pwnd_usbliter8": False, "pwnd_checkm8": False})
        monkeypatch.setattr(F, "_lockdown_info", lambda timeout=20: {
            "ProductType": "iPhone12,1", "ProductVersion": "16.6",
            "BuildVersion": "20G75", "UniqueDeviceID": "UDID-1",
        })
        fp = F.fingerprint_device()
        assert fp.value("state") == "AFU"
        assert fp.value("product_type") == "iPhone12,1"
        assert fp.get("product_type").confidence == "Observed"
        assert fp.chip == "A13"
        assert fp.get("chip").confidence == "Inferred"
        assert fp.value("model") == "iPhone 11"
        assert fp.ios == "16.6"

    def test_chip_falls_back_to_serial_heuristic(self, monkeypatch):
        monkeypatch.setattr(F, "usb_state", lambda: {
            "devices": [{"product": "Apple Mobile Device (DFU Mode)",
                         "serial": "C3G123456789", "product_id": "1227",
                         "mode": "dfu"}],
            "any": True, "dfu": True, "recovery": False, "pwnd": False,
            "pwnd_usbliter8": False, "pwnd_checkm8": False})
        monkeypatch.setattr(F, "_lockdown_info", lambda timeout=20: {})
        monkeypatch.setattr(F, "chip_from_irecovery", lambda: "")
        fp = F.fingerprint_device()
        assert fp.chip == "A10"
        assert fp.get("chip").confidence == "Heuristic"
        assert "serial-prefix" in fp.get("chip").source

    def test_undeterminable_chip_is_unknown(self, monkeypatch):
        monkeypatch.setattr(F, "usb_state", lambda: {
            "devices": [{"product": "DFU", "serial": "QQQQ",
                         "product_id": "1227", "mode": "dfu"}],
            "any": True, "dfu": True, "recovery": False, "pwnd": False,
            "pwnd_usbliter8": False, "pwnd_checkm8": False})
        monkeypatch.setattr(F, "_lockdown_info", lambda timeout=20: {})
        monkeypatch.setattr(F, "chip_from_irecovery", lambda: "")
        fp = F.fingerprint_device()
        assert fp.chip == ""
        assert fp.get("chip").confidence == "Unknown"
