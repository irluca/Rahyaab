"""Fallback chain for the setup wizard (bug 15, 2026-11-01).

A new node used to end up connected to NOTHING when GRE failed: the
setup job failed and a human requeued ESP, then an overlay, by hand.
run_setup now tries candidates in order and deploys the first one
that measures clean. These tests drive run_setup with injected fakes
(no SSH, no DB): measure_fn fails or succeeds per protocol, and the
test asserts which protocol got deployed and what the job reports.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wizard_setup


def _verdict(protocol):
    return RuntimeError(
        "Protocol %s did not measure cleanly: ['100%% loss']" % protocol)


class _Fakes:
    def __init__(self, measure):
        self.measure_calls = []
        self.deployed = []
        self.installed = []
        self.recorded = []
        self.measure = measure

    def measure_fn(self, pair, protocol):
        self.measure_calls.append(protocol)
        return self.measure(protocol)

    def deploy_fn(self, pair, protocol):
        self.deployed.append(protocol)
        return {"status": "ACTIVE-%s" % protocol}

    def install_fn(self, *args, **kwargs):
        self.installed.append(args[5])
        return {"active": "active", "heartbeat": {"active_tunnel": args[5]}}

    def record_fn(self, *args):
        self.recorded.append(args[2])


def _run(fakes, protocol="GRE"):
    return wizard_setup.run_setup(
        "192.0.2.10", "198.51.100.20", 4, "pair", "/tmp/hub.db",
        "/etc/rahyaab/hub_key", frontend_port=45984, protocol=protocol,
        known_hosts_path="/nonexistent-known-hosts",
        pin_fn=lambda *a: None, ensure_fn=lambda *a, **k: None,
        measure_fn=fakes.measure_fn, deploy_fn=fakes.deploy_fn,
        install_fn=fakes.install_fn, record_fn=fakes.record_fn,
        preflight=False)


def test_first_choice_succeeds_without_fallback():
    fakes = _Fakes(lambda p: {"score": 99.0, "base_rtt_ms": 80.0}
                    if p == "GRE" else (_ for _ in ()).throw(_verdict(p)))
    out = _run(fakes)
    assert out["protocol"] == "GRE"
    assert out["score"] == 99.0
    assert out["tried"] == ["GRE"]
    assert fakes.deployed == ["GRE"]
    assert fakes.installed == ["GRE"]


def test_gre_esp_fail_backhaul_succeeds():
    def measure(p):
        if p in ("GRE", "ESP"):
            raise _verdict(p)
        if p == "backhaul-wss":
            return {"score": 85.48, "base_rtt_ms": 85.0}
        raise AssertionError("should not measure %s" % p)
    fakes = _Fakes(measure)
    out = _run(fakes)
    assert out["protocol"] == "backhaul-wss"
    assert out["score"] == 85.48
    assert out["tried"] == ["GRE", "ESP", "backhaul-wss"]
    assert fakes.deployed == ["backhaul-wss"]
    assert fakes.recorded == [{"backhaul-wss": 85.48}]


def test_zero_score_row_continues_the_chain():
    def measure(p):
        if p == "GRE":
            return {"score": 0.0}
        if p == "ESP":
            return {"score": 80.0, "base_rtt_ms": 82.0}
        raise AssertionError("should not measure %s" % p)
    fakes = _Fakes(measure)
    out = _run(fakes)
    assert out["protocol"] == "ESP"
    assert out["tried"] == ["GRE", "ESP"]


def test_all_fail_reports_every_reason():
    fakes = _Fakes(lambda p: (_ for _ in ()).throw(_verdict(p)))
    with pytest.raises(RuntimeError, match="No protocol measured cleanly"):
        _run(fakes)
    assert fakes.measure_calls == wizard_setup.FALLBACK_ORDER
    assert fakes.deployed == []


def test_infra_error_aborts_immediately():
    calls = []

    def measure(p):
        calls.append(p)
        raise ConnectionError("ssh to foreign host failed")
    fakes = _Fakes(measure)
    with pytest.raises(ConnectionError, match="ssh to foreign host failed"):
        _run(fakes)
    assert calls == ["GRE"]
    assert fakes.deployed == []
