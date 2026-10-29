"""Tests for the healer-side tunnel port change (manual_switch.py
with a frontend_port in the request, plus storage's row setter).

No SSH, no live hosts: a stub monitor carries the pair source, the
runner factory and a stub FailoverManager that records the pair
dicts it is handed, so the tests can prove the forward leg deploys
the new port while the rollback leg redeploys the old one. The
healer row write is a monkeypatched stub — the real setter needs a
healer database, which these tests never create.
"""

import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))

import pytest

import manual_switch


class DummyRunner:
    def __init__(self):
        self.closed = False

    def run(self, *args, **kwargs):
        return 0, "", ""

    def close(self):
        self.closed = True


class PortStubManager:
    """Records every pair dict it is handed, in call order."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []
        self.pairs = []
        self.rollback_flags = []

    def execute_failover(self, pair, current, target, reason,
                         ir_runner=None, fr_runner=None, is_rollback=False):
        self.calls.append((current, target, reason))
        self.pairs.append(dict(pair))
        self.rollback_flags.append(is_rollback)
        return self.outcomes.pop(0)


class PortStubMonitor:
    def __init__(self, manager, active="chisel-wss", frontend=443):
        self.manager = manager
        self._active = active
        self._frontend = frontend
        self._lock = threading.Lock()
        self.runners = []

    def pair_source(self):
        return [{"id": 1, "name": "manag-netlen", "status": "ACTIVE",
                 "active_tunnel": self._active,
                 "frontend_port": self._frontend,
                 "iran": {"host": "192.0.2.10"},
                 "foreign": {"host": "198.51.100.10"}}]

    def runner_factory(self, spec, dry_run=None, host_role="unknown"):
        runner = DummyRunner()
        self.runners.append(runner)
        return runner

    def action_lock(self):
        return self._lock


def _run(monitor, target, tmp_path, port=None):
    result_path = str(tmp_path / "res.json")
    req = {"protocol": target, "request_id": "req-1",
           "requested_at": time.time()}
    if port is not None:
        req["frontend_port"] = port
    out = manual_switch.run_manual_switch(monitor, req, result_path)
    with open(result_path, encoding="utf-8") as f:
        stored = json.load(f)
    assert stored["request_id"] == "req-1"
    return out, stored


@pytest.fixture()
def row_writer(monkeypatch):
    calls = []

    def fake_set(pair_id, port):
        calls.append((pair_id, port))
        return True

    monkeypatch.setattr(manual_switch.storage, "set_pair_frontend_port",
                        fake_set)
    return calls


def test_port_change_success_persists_new_port(tmp_path, row_writer):
    manager = PortStubManager([{"success": True}])
    monitor = PortStubMonitor(manager)
    out, stored = _run(monitor, "chisel-wss", tmp_path, port=23456)
    assert out["status"] == "done"
    assert out["port_from"] == 443 and out["port_to"] == 23456
    assert stored["port_from"] == 443 and stored["port_to"] == 23456
    assert len(manager.calls) == 1
    assert manager.calls[0] == ("chisel-wss", "chisel-wss", "manual-port-change")
    assert manager.pairs[0]["frontend_port"] == 23456
    assert row_writer == [(1, 23456)]
    assert all(r.closed for r in monitor.runners)


def test_same_port_request_is_already(tmp_path, row_writer):
    manager = PortStubManager([])
    monitor = PortStubMonitor(manager)
    out, _ = _run(monitor, "chisel-wss", tmp_path, port=443)
    assert out["status"] == "done" and out["already"] is True
    assert manager.calls == []
    assert row_writer == []


def test_port_change_unplannable_fails_without_deploy(tmp_path, row_writer):
    manager = PortStubManager([])
    monitor = PortStubMonitor(manager)
    out, _ = _run(monitor, "bogus-protocol", tmp_path, port=23456)
    assert out["status"] == "failed" and out["rolled_back"] is False
    assert "cannot plan" in out["detail"]
    assert manager.calls == []
    assert row_writer == []


def test_row_write_failure_rolls_back_to_old_port(tmp_path, monkeypatch):
    manager = PortStubManager([{"success": True}, {"success": True}])
    monitor = PortStubMonitor(manager)
    monkeypatch.setattr(manual_switch.storage, "set_pair_frontend_port",
                        lambda pair_id, port: False)
    out, _ = _run(monitor, "chisel-wss", tmp_path, port=23456)
    assert out["status"] == "failed" and out["rolled_back"] is True
    assert manager.calls == [("chisel-wss", "chisel-wss", "manual-port-change"),
                             ("chisel-wss", "chisel-wss", "manual-rollback")]
    assert manager.rollback_flags == [False, True]
    # The rollback leg redeploys the pair it started from: old port.
    assert manager.pairs[0]["frontend_port"] == 23456
    assert manager.pairs[1]["frontend_port"] == 443


def test_port_change_blocked_is_refused(tmp_path, row_writer):
    manager = PortStubManager([{"success": False, "blocked": True,
                                "reason": "Circuit breaker: too soon"}])
    monitor = PortStubMonitor(manager)
    out, _ = _run(monitor, "chisel-wss", tmp_path, port=23456)
    assert out["status"] == "refused"
    assert row_writer == []
