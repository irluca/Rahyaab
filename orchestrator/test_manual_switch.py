"""Tests for the healer's manual switch (orchestrator/manual_switch.py)
and for the monitor action lock that serialises it against auto passes.

No SSH, no live hosts: a stub monitor carries the pair source, the
runner factory and a stub FailoverManager.
"""

import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))

import pytest

import failover_monitor
import manual_switch


# ---- request/result file protocol ---------------------------------------


def _write(path, payload):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)


def test_load_request_round_trip_and_malformed(tmp_path):
    path = str(tmp_path / "req.json")
    _write(path, {"protocol": "ESP", "request_id": "abc", "requested_at": 1000.0})
    req = manual_switch.load_request(path)
    assert req == {"protocol": "ESP", "request_id": "abc", "requested_at": 1000.0}
    _write(path, {"protocol": "ESP"})  # missing fields
    assert manual_switch.load_request(path) is None
    _write(path, {"protocol": "", "request_id": "abc", "requested_at": 1000.0})
    assert manual_switch.load_request(path) is None
    assert manual_switch.load_request(str(tmp_path / "missing.json")) is None


def test_stale_and_consume(tmp_path):
    req = {"protocol": "ESP", "request_id": "abc", "requested_at": 1000.0}
    assert manual_switch.is_stale(req, now=1000.0 + 601) is True
    assert manual_switch.is_stale(req, now=1000.0 + 599) is False
    path = str(tmp_path / "req.json")
    _write(path, req)
    assert manual_switch.consume(path) == req
    assert not os.path.exists(path)
    assert manual_switch.consume(path) is None


def test_write_result_is_atomic_json(tmp_path):
    path = str(tmp_path / "res.json")
    manual_switch.write_result(path, {"request_id": "abc", "status": "done"})
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert data["request_id"] == "abc" and data["finished_at"] > 0


# ---- run_manual_switch --------------------------------------------------


class DummyRunner:
    def __init__(self):
        self.closed = False

    def run(self, *args, **kwargs):
        return 0, "", ""

    def close(self):
        self.closed = True


class StubManager:
    """Canned execute_failover outcomes, in call order."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []
        self.rollback_flags = []

    def execute_failover(self, pair, current, target, reason,
                         ir_runner=None, fr_runner=None, is_rollback=False):
        self.calls.append((current, target, reason))
        self.rollback_flags.append(is_rollback)
        return self.outcomes.pop(0)


class StubMonitor:
    def __init__(self, manager, active="GRE"):
        self.manager = manager
        self._active = active
        self._lock = threading.Lock()
        self.runners = []

    def pair_source(self):
        return [{"id": 1, "name": "manag-netlen", "status": "ACTIVE",
                 "active_tunnel": self._active,
                 "iran": {"host": "192.0.2.10"},
                 "foreign": {"host": "198.51.100.10"}}]

    def runner_factory(self, spec, dry_run=None, host_role="unknown"):
        runner = DummyRunner()
        self.runners.append(runner)
        return runner

    def action_lock(self):
        return self._lock


def _run(monitor, target, tmp_path):
    result_path = str(tmp_path / "res.json")
    req = {"protocol": target, "request_id": "req-1", "requested_at": time.time()}
    out = manual_switch.run_manual_switch(monitor, req, result_path)
    with open(result_path, encoding="utf-8") as f:
        stored = json.load(f)
    assert stored["request_id"] == "req-1"
    return out, stored


def test_switch_already_is_a_noop(tmp_path):
    monitor = StubMonitor(StubManager([]))
    out, _ = _run(monitor, "GRE", tmp_path)
    assert out["status"] == "done" and out["already"] is True
    assert monitor.manager.calls == []


def test_switch_success(tmp_path):
    monitor = StubMonitor(StubManager([{"success": True}]))
    out, _ = _run(monitor, "ESP", tmp_path)
    assert out["status"] == "done" and out["from"] == "GRE" and out["to"] == "ESP"
    assert monitor.manager.calls == [("GRE", "ESP", "manual-switch")]
    assert all(r.closed for r in monitor.runners)


def test_unplannable_target_fails_without_rollback(tmp_path):
    monitor = StubMonitor(StubManager([]))
    out, _ = _run(monitor, "bogus-protocol", tmp_path)
    assert out["status"] == "failed" and out["rolled_back"] is False
    assert "cannot plan" in out["detail"]
    assert monitor.manager.calls == []  # never deployed, never rolled back


def test_switch_blocked_is_refused_without_touching_units(tmp_path):
    monitor = StubMonitor(StubManager([{"success": False, "blocked": True,
                                        "reason": "Circuit breaker: too soon"}]))
    out, _ = _run(monitor, "ESP", tmp_path)
    assert out["status"] == "refused"
    assert "Circuit breaker" in out["detail"]


def test_switch_smoke_fail_with_quarantine_restores(tmp_path):
    monitor = StubMonitor(StubManager([{"success": False, "restored": True,
                                        "error": "smoke failed"}]))
    out, _ = _run(monitor, "rathole-noise", tmp_path)
    assert out["status"] == "failed" and out["rolled_back"] is True
    assert len(monitor.manager.calls) == 1  # no redeploy needed


def test_switch_smoke_fail_without_quarantine_redeploys_previous(tmp_path):
    monitor = StubMonitor(StubManager([
        {"success": False, "restored": False, "error": "smoke failed"},
        {"success": True},
    ]))
    out, _ = _run(monitor, "ESP", tmp_path)
    assert out["status"] == "failed" and out["rolled_back"] is True
    assert monitor.manager.calls == [("GRE", "ESP", "manual-switch"),
                                     ("ESP", "GRE", "manual-rollback")]
    # The redeploy is a rollback, so it must bypass the breaker: the
    # failed switch's own smoke failure already recorded a failover
    # event, and an unqualified check would refuse the restoration
    # (2026-10-27: ESP -> hysteria2 failed, then its rollback to ESP
    # was refused as "0.4s ago"). The switch itself stays governed.
    assert monitor.manager.rollback_flags == [False, True]


def test_normal_switch_does_not_bypass_breaker(tmp_path):
    monitor = StubMonitor(StubManager([{"success": True}]))
    out, _ = _run(monitor, "ESP", tmp_path)
    assert out["status"] == "done"
    assert monitor.manager.rollback_flags == [False]


def test_switch_and_rollback_both_fail(tmp_path):
    monitor = StubMonitor(StubManager([
        {"success": False, "restored": False, "error": "smoke failed"},
        {"success": False, "error": "rollback smoke failed"},
    ]))
    out, _ = _run(monitor, "ESP", tmp_path)
    assert out["status"] == "failed" and out["rolled_back"] is False
    assert "rollback" in out["detail"]


# ---- monitor action lock -------------------------------------------------


def test_run_once_holds_the_action_lock():
    monitor = failover_monitor.FailoverMonitor(
        host_guard=failover_monitor.NullHostGuard(), dry_run=True,
        pair_source=lambda: [])
    finished = []
    with monitor.action_lock():
        thread = threading.Thread(
            target=lambda: finished.append(monitor.run_once(auto_heal=True)))
        thread.start()
        time.sleep(0.3)
        assert thread.is_alive()  # blocked on the lock, not running a pass
    thread.join(timeout=5)
    assert finished == [[]]


def test_run_once_still_works_without_contention():
    monitor = failover_monitor.FailoverMonitor(
        host_guard=failover_monitor.NullHostGuard(), dry_run=True,
        pair_source=lambda: [])
    assert monitor.run_once(auto_heal=True) == []
