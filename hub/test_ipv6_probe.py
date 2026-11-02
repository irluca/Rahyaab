"""Tests for the IPv6 probe: the hub job handler (spawn + already-
running guard), the backfill that covers pairs never probed, and the
runner's early exits. The probe logic itself lives in
orchestrator/test_ipv6.py; the live TCP directions are measured on
real hosts, never here.
"""

import importlib.util
import os
import sys

import pytest

from hub import jobs
from hub.store import Store


def _pair_store(tmp_path):
    store = Store(tmp_path / "hub.db")
    iran = store.create_server({"name": "iran", "host": "203.0.113.1"})
    foreign = store.create_server({"name": "foreign", "host": "203.0.113.2"})
    pair = store.create_pair({
        "name": "p1", "iran_server_id": iran["id"],
        "foreign_server_id": foreign["id"],
        "current_protocol": "GRE",
        "inner_iran": "10.10.11.1", "inner_foreign": "10.10.11.2",
        "candidate_scores": {"GRE": 99.0},
    })
    return store, pair


def test_handle_ipv6_probe_spawns_scope_unit(tmp_path, monkeypatch):
    store, pair = _pair_store(tmp_path)
    spawned = []
    monkeypatch.setattr(jobs, "_ipv6_probe_running", lambda pid: False)
    monkeypatch.setattr(jobs, "_spawn_sweep", lambda argv: spawned.append(argv))
    job = {"id": 1, "type": "ipv6_probe", "pair_id": pair["id"], "input": {}}
    out = jobs._handle_ipv6_probe(store, job, lambda s: None)
    assert out["status"] == "started"
    assert out["unit"] == "rahyaab-ipv6-probe-p%d.scope" % pair["id"]
    assert len(spawned) == 1
    argv = spawned[0]
    assert argv[0] == "systemd-run" and "--scope" in argv
    assert "--unit=rahyaab-ipv6-probe-p%d" % pair["id"] in argv
    assert "run_ipv6_probe.py" in argv[-1]
    assert "--pair-id %d" % pair["id"] in argv[-1]


def test_handle_ipv6_probe_skips_when_running(tmp_path, monkeypatch):
    store, pair = _pair_store(tmp_path)
    monkeypatch.setattr(jobs, "_ipv6_probe_running", lambda pid: True)

    def _boom(argv):
        raise AssertionError("must not spawn while a probe runs")

    monkeypatch.setattr(jobs, "_spawn_sweep", _boom)
    out = jobs._handle_ipv6_probe(
        store, {"id": 2, "type": "ipv6_probe", "pair_id": pair["id"], "input": {}},
        lambda s: None)
    assert out["status"] == "already-running"


def test_backfill_only_unprobed_pairs(tmp_path):
    store, pair = _pair_store(tmp_path)
    assert jobs.backfill_ipv6_probes(store) == [pair["id"]]
    # A queued probe is never duplicated.
    assert jobs.backfill_ipv6_probes(store) == []
    # Once a verdict exists, the pair is covered for good, even with
    # the earlier queued row still sitting in the queue.
    store.save_ipv6_status(pair["id"], {"reverse_ready": False})
    assert jobs.backfill_ipv6_probes(store) == []


def test_runner_refuses_unknown_pair(tmp_path, monkeypatch):
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "orchestrator", "run_ipv6_probe.py")
    spec = importlib.util.spec_from_file_location("run_ipv6_probe", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    store = Store(tmp_path / "hub.db")
    monkeypatch.setattr(sys, "argv", ["run_ipv6_probe.py", "--pair-id", "999",
                                      "--hub-db", str(store.db_path)])
    monkeypatch.setenv("RAHYAAB_SWEEP_DIR", str(tmp_path))
    assert mod.main() == 1
