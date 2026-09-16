"""Crash logs + wireless + attack-surface tests."""

import json
import plistlib
import tempfile
from pathlib import Path

from opensleuth import crashlogs as CL
from opensleuth import surface as SF
from opensleuth import wireless as W


def _ips(name="SpringBoard-2026.ips", proc="SpringBoard",
         exc="EXC_BAD_ACCESS (SIGSEGV)"):
    meta = {"name": name, "app_name": proc, "timestamp": "2026-09-01 10:10:10.00 +0000",
            "os_version": "iPhone OS 26.6.1 (23G83)", "bug_type": "309",
            "incident_id": "X-1"}
    body = {"procName": proc, "pid": 456,
            "exception": {"type": exc, "codes": "0x1"},
            "faultingFrame": {"imageIndex": 0, "image": proc,
                              "symbol": "sym_x", "imageOffset": 1234},
            "bundleInfo": {"bundleID": "com.apple." + proc.lower()}}
    return json.dumps(meta) + "\n" + json.dumps(body)


class TestCrashlogs:
    def test_parse_ips(self):
        c = CL.parse_ips(_ips(), source="x.ips")
        assert c["process"] == "SpringBoard"
        assert "SIGSEGV" in c["exception_type"]
        assert c["faulting_symbol"] == "sym_x"
        assert c["os_version"].startswith("iPhone OS 26")

    def test_parse_garbage(self):
        assert CL.parse_ips("not json") is None
        assert CL.parse_ips("") is None

    def test_meta_only_tolerated(self):
        c = CL.parse_ips(json.dumps({"name": "n", "app_name": "a"}),
                         source="m.ips")
        assert c["name"] == "n" and c["exception_type"] is None

    def test_scan_dir(self, tmp_path):
        (tmp_path / "logs").mkdir()
        (tmp_path / "logs" / "a.ips").write_text(_ips())
        (tmp_path / "logs" / "junk.ips").write_text("nope")
        rows = CL.scan_dir(tmp_path)
        assert len(rows) == 1
        assert rows[0]["rel"].endswith("a.ips")

    def test_summarize(self):
        rows = [CL.parse_ips(_ips()), CL.parse_ips(_ips(proc="Telegram")),
                CL.parse_ips(_ips(proc="SpringBoard", exc="EXC_CRASH"))]
        s = CL.summarize(rows)
        assert s["total"] == 3
        assert s["by_process"]["SpringBoard"] == 2

    def test_render(self):
        out = CL.render([CL.parse_ips(_ips())])
        assert "crash logs: 1" in out and "SpringBoard" in out
        assert "no crash logs" in CL.render([])


class TestWireless:
    def test_wifi_parse(self):
        pl = plistlib.dumps({"KnownNetworks": {
            "n1": {"SSIDString": "HomeNet", "BSSID": "aa:bb:cc:dd:ee:ff",
                   "SecurityMode": "WPA3", "LastAutoJoinedAt": "2026-09-01"},
            "n2": {"SSID": b"BytesNet", "HIDDEN_NETWORK": True}}})
        rows = W.parse_wifi_plist(pl, source="wifi.plist")
        assert len(rows) == 2
        by = {r["ssid"] or r["network_id"]: r for r in rows}
        assert by["HomeNet"]["bssid"] == "aa:bb:cc:dd:ee:ff"
        assert by["BytesNet"]["hidden"] is True

    def test_wifi_bad_plist(self):
        assert W.parse_wifi_plist(b"garbage") == []

    def test_bt_parse(self):
        pl = plistlib.dumps({
            "PairedDevices": ["AA:11"],
            "DeviceCache": {"AA:11": {"Name": "Car", "LastSeenTime": "t"}},
            "RecentDevices": ["AirPods"]})
        rows = W.parse_bluetooth_plist(pl, source="bt.plist")
        assert len(rows) == 2
        assert rows[0]["name"] == "Car" and rows[0]["paired"]
        assert rows[1]["name"] == "AirPods" and not rows[1]["paired"]

    def test_scan(self, tmp_path):
        (tmp_path / "SystemPreferences").mkdir()
        (tmp_path / "SystemPreferences" / "com.apple.wifi.plist").write_bytes(
            plistlib.dumps({"KnownNetworks": {"n": {"SSIDString": "X"}}}))
        rows = W.scan(tmp_path)
        assert len(rows["wifi"]) == 1
        assert rows["bluetooth"] == []

    def test_render(self):
        out = W.render({"wifi": [], "bluetooth": []})
        assert "wireless artifacts: 0 networks, 0 bluetooth" in out


class TestSurface:
    def _discs(self):
        return [
            {"cve": "CVE-1", "component": "Kernel", "kind": "root LPE",
             "impact": "root", "patch": "iOS 27"},
            {"cve": "CVE-2", "component": "Kernel", "kind": "kernel write",
             "impact": "root", "patch": "iOS 27"},
            {"cve": "CVE-3", "component": "AVEVideoEncoder",
             "kind": "kernel-exec from sandbox", "impact": "x", "patch": "iOS 26.6"},
            {"cve": "CVE-4", "component": "Notes", "kind": "privacy leak",
             "impact": "fingerprint", "patch": "iOS 27"},
        ]

    def test_tiers(self):
        assert SF.tier("root LPE") == "PRIME"
        assert SF.tier("", "keychain access bypass") == "PRIME"
        assert SF.tier("sandbox escape") == "HIGH"
        assert SF.tier("privacy leak") == "CONTEXT"

    def test_analyze(self):
        rep = SF.analyze(self._discs())
        assert rep["total"] == 4
        assert rep["tiers"]["PRIME"] == 3
        assert rep["rich_components"]["Kernel"] == 2

    def test_research_targets(self):
        rep = SF.analyze(self._discs())
        targets = SF.research_targets(rep)
        assert targets[0]["component"] == "Kernel"
        assert "CVE-1" in targets[0]["prime_examples"] or \
               "CVE-2" in targets[0]["prime_examples"]

    def test_render_honest(self):
        out = SF.render(SF.analyze(self._discs()))
        assert "never assumed" in out
        assert "PATCHED public CVEs" in out