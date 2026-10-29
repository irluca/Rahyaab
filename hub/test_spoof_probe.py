"""Tests for the spoof probe: the hub job handler (spawn + already-
running guard), the worker auto-enqueue after a successful full_setup,
the spoof_status column migration on pre-existing hub databases, and
the probe verdict rule.
"""

import importlib.util
import os
import sqlite3
import time

import pytest

from hub import jobs
from hub.store import Store


def _load_probe_runner():
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "orchestrator", "run_spoof_probe.py")
    spec = importlib.util.spec_from_file_location("run_spoof_probe", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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


def _jobs(store):
    conn = sqlite3.connect(store.db_path)
    rows = conn.execute(
        "SELECT type, pair_id, status FROM jobs ORDER BY id").fetchall()
    conn.close()
    return rows


def test_handle_spoof_probe_spawns_scope_unit(tmp_path, monkeypatch):
    store, pair = _pair_store(tmp_path)
    spawned = []
    monkeypatch.setattr(jobs, "_probe_running", lambda pid: False)
    monkeypatch.setattr(jobs, "_spawn_sweep", lambda argv: spawned.append(argv))
    job = {"id": 1, "type": "spoof_probe", "pair_id": pair["id"],
           "input": {"spoof_ips": ["203.0.113.10"]}}
    out = jobs._handle_spoof_probe(store, job, lambda s: None)
    assert out["status"] == "started"
    assert out["unit"] == "rahyaab-spoof-probe-p%d.scope" % pair["id"]
    assert len(spawned) == 1
    argv = spawned[0]
    assert argv[0] == "systemd-run" and "--scope" in argv
    assert "--unit=rahyaab-spoof-probe-p%d" % pair["id"] in argv
    assert "run_spoof_probe.py" in argv[-1]
    assert "--pair-id %d" % pair["id"] in argv[-1]
    assert "--spoof-ips 203.0.113.10" in argv[-1]


def test_handle_spoof_probe_skips_when_running(tmp_path, monkeypatch):
    store, pair = _pair_store(tmp_path)
    monkeypatch.setattr(jobs, "_probe_running", lambda pid: True)

    def _boom(argv):
        raise AssertionError("must not spawn while a probe runs")

    monkeypatch.setattr(jobs, "_spawn_sweep", _boom)
    out = jobs._handle_spoof_probe(
        store, {"id": 2, "type": "spoof_probe", "pair_id": pair["id"],
                "input": {}},
        lambda s: None)
    assert out["status"] == "already-running"


def test_handle_spoof_probe_no_pair(tmp_path):
    store, _pair = _pair_store(tmp_path)
    with pytest.raises(ValueError):
        jobs._handle_spoof_probe(
            store, {"id": 3, "type": "spoof_probe", "pair_id": 9999,
                    "input": {}},
            lambda s: None)


def test_worker_enqueues_sweep_and_probe_after_full_setup(tmp_path, monkeypatch):
    store, pair = _pair_store(tmp_path)
    store.create_job("full_setup", pair["id"], {})
    monkeypatch.setitem(
        jobs.HANDLERS, "full_setup",
        lambda s, j, m: {"protocol": "GRE", "score": 99.0})
    monkeypatch.setitem(
        jobs.HANDLERS, "sweep", lambda s, j, m: {"status": "started"})
    monkeypatch.setitem(
        jobs.HANDLERS, "spoof_probe", lambda s, j, m: {"status": "started"})
    worker = jobs.Worker(store, poll_seconds=0.05)
    worker.start()
    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            types = [t for t, p, _s in _jobs(store) if p == pair["id"]]
            if "sweep" in types and "spoof_probe" in types:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("sweep and spoof_probe jobs were not both enqueued")
    finally:
        worker.stop()
        worker.join(timeout=5)


def test_spoof_status_migrates_on_old_hub_db(tmp_path):
    # A hub.db created before spoof_status existed: raw old schema.
    db = tmp_path / "old-hub.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE servers (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " name TEXT NOT NULL UNIQUE, host TEXT NOT NULL,"
        " port INTEGER NOT NULL DEFAULT 22,"
        " username TEXT NOT NULL DEFAULT 'root', key_path TEXT,"
        " notes TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL)")
    conn.execute(
        "CREATE TABLE pairs (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " name TEXT NOT NULL UNIQUE, iran_server_id INTEGER NOT NULL,"
        " foreign_server_id INTEGER NOT NULL, healer_server_id INTEGER,"
        " frontend_port INTEGER NOT NULL DEFAULT 443, current_protocol TEXT,"
        " inner_iran TEXT, inner_foreign TEXT,"
        " candidate_scores TEXT NOT NULL DEFAULT '{}',"
        " healer_last_status TEXT, healer_last_seen REAL,"
        " created_at REAL NOT NULL)")
    conn.commit()
    conn.close()
    store = Store(db)
    cols = [r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(pairs)")]
    assert "spoof_status" in cols
    iran = store.create_server({"name": "iran", "host": "203.0.113.1"})
    foreign = store.create_server({"name": "foreign", "host": "203.0.113.2"})
    pair = store.create_pair({
        "name": "p1", "iran_server_id": iran["id"],
        "foreign_server_id": foreign["id"]})
    assert store.get_pair(pair["id"])["spoof_status"] == "unknown"
    store.update_pair_spoof_status(pair["id"], "closed")
    assert store.get_pair(pair["id"])["spoof_status"] == "closed"
    with pytest.raises(ValueError):
        store.update_pair_spoof_status(pair["id"], "maybe")


def test_determine_status_rule():
    mod = _load_probe_runner()
    open_dir = {"capable": True}
    closed_dir = {"capable": False}
    unknown_dir = {"capable": None}
    assert mod.determine_status(open_dir, open_dir) == "open"
    assert mod.determine_status(open_dir, closed_dir) == "closed"
    assert mod.determine_status(closed_dir, unknown_dir) == "closed"
    assert mod.determine_status(open_dir, unknown_dir) == "unknown"
    assert mod.determine_status(unknown_dir, unknown_dir) == "unknown"


def test_backfill_enqueues_only_unknown_pairs_without_queued_probe(tmp_path):
    store, pair = _pair_store(tmp_path)
    assert store.get_pair(pair["id"])["spoof_status"] == "unknown"
    # A second pair, already closed, must never be re-probed.
    iran = store.create_server({"name": "iran2", "host": "203.0.113.3"})
    foreign = store.create_server({"name": "foreign2", "host": "203.0.113.4"})
    closed_pair = store.create_pair({
        "name": "p2", "iran_server_id": iran["id"],
        "foreign_server_id": foreign["id"]})
    store.update_pair_spoof_status(closed_pair["id"], "closed")
    assert jobs.backfill_spoof_probes(store) == [pair["id"]]
    # Idempotent: the queued job blocks a duplicate.
    assert jobs.backfill_spoof_probes(store) == []
    types = [(t, p) for t, p, _s in _jobs(store)]
    assert ("spoof_probe", pair["id"]) in types
    assert ("spoof_probe", closed_pair["id"]) not in types
