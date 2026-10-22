"""GUI exploitation-chain routing tests.

Regression coverage for the web GUI's single-route execute path
(studio_web.server._execute_single_route) and the shared strategy
resolver (exploitrunner._strategy_for_route):

- EVERY catalog route must resolve to a strategy that has a registered
  executor in _EXECUTORS.
- NO host boot-chain route (bootrom / bootrom-chain / sep / iboot layer)
  may resolve to afu_agent, the AFU sideload-app installer - those routes
  run on the host against DFU/locked devices.
- The GUI dispatch must pass the route name through to route-aware
  executors (like exploitrunner.run_plan does) and must use the
  executor's own default timeout instead of a hardcoded 120s.
"""

import pytest

from opensleuth import exploitrunner as R
from opensleuth.exploitrunner import Target, _strategy_for_route, _EXECUTORS
from opensleuth.exploits import ROUTES
from opensleuth.studio_web import server as S


def _route(name):
    return next(r for r in ROUTES if r["name"] == name)


# ---------------------------------------------------------------- resolver

class TestStrategyForRoute:
    def test_every_route_resolves_to_a_registered_executor(self):
        for r in ROUTES:
            strat = _strategy_for_route(r)
            assert strat in _EXECUTORS, f"{r['name']}: strategy {strat!r} has no executor"

    def test_no_host_boot_layer_route_uses_afu_agent(self):
        for r in ROUTES:
            if r.get("layer") in ("bootrom", "bootrom-chain", "sep", "iboot"):
                strat = _strategy_for_route(r)
                assert strat != "afu_agent", (
                    f"{r['name']} (layer={r['layer']}) misrouted to the "
                    f"AFU sideload installer")

    @pytest.mark.parametrize("name,expected", [
        ("usbliter8ra1n", "usbliter8_chain"),
        ("usbliter8 BFU ramdisk extraction (A12/A13)", "bfu_ramdisk_extract"),
        ("usbliter8", "usbliter8_pwn"),
        ("Blackbird", "blackbird_sep"),
        ("hardbird", "blackbird_sep"),
        ("checkm8", "checkm8_pwn"),
        ("steaks4uce", "a4_bootrom"),
        ("limera1n", "a4_bootrom"),
        ("SHAtter", "a4_bootrom"),
        ("24Kpwn", "a4_bootrom"),
        ("alloc8", "a4_bootrom"),
        ("greenpois0n", "a4_bootrom"),
        ("redsn0w (tethered)", "a4_bootrom"),
        ("De Rebus Antiquis (DRA)", "a4_bootrom"),
        ("Absinthe 2", "a4_bootrom"),
        ("checkra1n", "checkra1n"),
        ("palera1n-roothide", "palera1n_jailbreak"),
        ("palera1n / checkra1n lineage", "palera1n_jailbreak"),
        ("Dopamine / Dopamine 2", "afu_agent"),
        ("TrollStore (install vector)", "trollstore_install"),
        ("Misaka26 / Nugget (MobileGestalt)", "misaka_mg"),
    ])
    def test_named_routes(self, name, expected):
        assert _strategy_for_route(_route(name)) == expected

    def test_case_insensitive(self):
        r = dict(_route("Blackbird"))
        r["name"] = "BLACKBIRD"
        assert _strategy_for_route(r) == "blackbird_sep"
        r = dict(_route("usbliter8ra1n"))
        r["name"] = "USBLITER8RA1N"
        assert _strategy_for_route(r) == "usbliter8_chain"


# ------------------------------------------------------------- GUI dispatch

class TestGuiSingleRouteDispatch:
    """_execute_single_route must dispatch like run_plan: route= passed
    to route-aware executors, executor's own timeout default used."""

    def _target_for(self, route):
        chips = route.get("chips") or ["A13"]
        return Target(present=True, chip=chips[0], ios="16.6",
                      product_type="iPhone12,1", model="iPhone 11",
                      state="AFU")

    def test_route_and_executor_default_timeout_passed(self, monkeypatch):
        route = _route("Dopamine / Dopamine 2")
        calls = {}

        def fake_agent(target, timeout=777, route=""):
            calls.update(timeout=timeout, route=route)
            return True, "fake agent ran", "fake-output"

        monkeypatch.setattr(R, "probe_target", lambda: self._target_for(route))
        monkeypatch.setitem(R._EXECUTORS, "afu_agent", fake_agent)

        res = S._execute_single_route("Dopamine / Dopamine 2")
        assert res["status"] == "executed"
        assert res["ok"] is True
        assert res["info"]["strategy"] == "afu_agent"
        # The route-aware dispatch run_plan shipped must NOT be bypassed:
        assert calls["route"] == "Dopamine / Dopamine 2"
        # Executor's own default (777), not the old hardcoded 120:
        assert calls["timeout"] == 777

    def test_explicit_timeout_overrides_executor_default(self, monkeypatch):
        route = _route("Dopamine / Dopamine 2")
        calls = {}

        def fake_agent(target, timeout=777, route=""):
            calls.update(timeout=timeout, route=route)
            return True, "ok", ""

        monkeypatch.setattr(R, "probe_target", lambda: self._target_for(route))
        monkeypatch.setitem(R._EXECUTORS, "afu_agent", fake_agent)

        res = S._execute_single_route("Dopamine / Dopamine 2", timeout=42)
        assert res["status"] == "executed"
        assert calls["timeout"] == 42

    def test_legacy_two_arg_executor_called_without_route(self, monkeypatch):
        route = _route("usbliter8ra1n")
        calls = {}

        def fake_chain(target, timeout=300):
            calls.update(timeout=timeout)
            return True, "chain ran (fake)", ""

        monkeypatch.setattr(R, "probe_target", lambda: self._target_for(route))
        monkeypatch.setattr(R, "_bin", lambda name: f"/usr/bin/{name}")
        monkeypatch.setitem(R._EXECUTORS, "usbliter8_chain", fake_chain)

        res = S._execute_single_route("usbliter8ra1n")
        assert res["status"] == "executed"
        assert res["info"]["strategy"] == "usbliter8_chain"
        assert calls["timeout"] == 300

    def test_blackbird_strategy_resolved_through_gui(self, monkeypatch):
        # 'Blackbird' (capital B) must resolve to blackbird_sep - the old
        # case-sensitive strat_map missed it and fell back to afu_agent.
        # (Execution itself stops at the tooling gate on this host, which
        # is the honest outcome; the strategy in the report is the point.)
        route = _route("Blackbird")
        monkeypatch.setattr(R, "probe_target", lambda: self._target_for(route))
        res = S._execute_single_route("Blackbird")
        assert res["info"]["strategy"] == "blackbird_sep"
