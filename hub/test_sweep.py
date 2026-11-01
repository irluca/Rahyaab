"""Tests for the auto-sweep: progressive score merging, the sweep job
handler (spawn + already-running guard), and the worker auto-enqueue
after a successful full_setup.
"""

import importlib.util
import os
import sqlite3
import time

import pytest

from hub import jobs
from hub.store import Store


def _load_runner():
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "orchestrator", "run_sweep.py")
    spec = importlib.util.spec_from_file_location("run_sweep", path)
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


def test_merge_scores_keeps_old_and_drops_disqualified():
    run_sweep = _load_runner()
    assert run_sweep.merge_scores(
        {"GRE": 99.0}, {"ESP": 99.5, "GRE": 99.3, "bad": 0.0}) == {
            "GRE": 99.3, "ESP": 99.5}
    assert run_sweep.merge_scores(None, {"GRE": 1.0}) == {"GRE": 1.0}


def test_qualified_from_rows_skips_disqualified():
    run_sweep = _load_runner()
    rows = [
        {"protocol": "GRE", "score": 99.0, "disqualified": 0},
        {"protocol": "ESP", "score": 0.0, "disqualified": 1},
        {"protocol": "frp-TLS", "score": 0.0, "disqualified": 1},
    ]
    assert run_sweep.qualified_from_rows(rows) == {"GRE": 99.0}


def test_read_new_rows_only_this_run_after_id(tmp_path):
    run_sweep = _load_runner()
    db = tmp_path / "healer.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE benchmarks (id INTEGER PRIMARY KEY"
                 " AUTOINCREMENT, protocol TEXT, score REAL,"
                 " disqualified INTEGER, run_id TEXT)")
    conn.execute("INSERT INTO benchmarks (protocol, score, disqualified,"
                 " run_id) VALUES ('GRE', 99.0, 0, 'old')")
    conn.execute("INSERT INTO benchmarks (protocol, score, disqualified,"
                 " run_id) VALUES ('GRE', 99.3, 0, 'new')")
    conn.execute("INSERT INTO benchmarks (protocol, score, disqualified,"
                 " run_id) VALUES ('ESP', 99.7, 0, 'new')")
    conn.commit()
    conn.close()
    rows, max_id = run_sweep.read_new_rows(str(db), "new", 0)
    assert [r["protocol"] for r in rows] == ["GRE", "ESP"]
    rows2, _ = run_sweep.read_new_rows(str(db), "new", max_id)
    assert rows2 == []


def test_apply_rows_merges_and_keeps_current_protocol(tmp_path):
    run_sweep = _load_runner()
    store, pair = _pair_store(tmp_path)
    merged = run_sweep.apply_rows_to_hub(store, pair["id"], [
        {"protocol": "ESP", "score": 99.7, "disqualified": 0},
        {"protocol": "frp-TLS", "score": 0.0, "disqualified": 1},
    ])
    assert merged == {"GRE": 99.0, "ESP": 99.7}
    after = store.get_pair(pair["id"])
    assert after["current_protocol"] == "GRE"
    assert after["candidate_scores"] == {"GRE": 99.0, "ESP": 99.7}


def test_update_pair_scores_merges(tmp_path):
    store, pair = _pair_store(tmp_path)
    merged = store.update_pair_scores(pair["id"], {"ESP": 99.5, "bad": 0})
    assert merged == {"GRE": 99.0, "ESP": 99.5}
    assert store.get_pair(pair["id"])["current_protocol"] == "GRE"


def test_handle_sweep_spawns_scope_unit(tmp_path, monkeypatch):
    store, pair = _pair_store(tmp_path)
    spawned = []
    monkeypatch.setattr(jobs, "_sweep_running", lambda pid: False)
    monkeypatch.setattr(jobs, "_spawn_sweep", lambda argv: spawned.append(argv))
    job = {"id": 1, "type": "sweep", "pair_id": pair["id"], "input": {}}
    out = jobs._handle_sweep(store, job, lambda s: None)
    assert out["status"] == "started"
    assert out["unit"] == "rahyaab-sweep-p%d.scope" % pair["id"]
    assert len(spawned) == 1
    argv = spawned[0]
    assert argv[0] == "systemd-run" and "--scope" in argv
    assert "--unit=rahyaab-sweep-p%d" % pair["id"] in argv
    assert "run_sweep.py" in argv[-1]
    assert "--pair-id %d" % pair["id"] in argv[-1]


def test_handle_sweep_skips_when_running(tmp_path, monkeypatch):
    store, pair = _pair_store(tmp_path)
    monkeypatch.setattr(jobs, "_sweep_running", lambda pid: True)

    def _boom(argv):
        raise AssertionError("must not spawn while a sweep runs")

    monkeypatch.setattr(jobs, "_spawn_sweep", _boom)
    out = jobs._handle_sweep(
        store, {"id": 2, "type": "sweep", "pair_id": pair["id"], "input": {}},
        lambda s: None)
    assert out["status"] == "already-running"


def test_handle_sweep_no_pair(tmp_path):
    store, _pair = _pair_store(tmp_path)
    with pytest.raises(ValueError):
        jobs._handle_sweep(
            store, {"id": 3, "type": "sweep", "pair_id": 9999, "input": {}},
            lambda s: None)


def test_worker_enqueues_sweep_after_full_setup(tmp_path, monkeypatch):
    store, pair = _pair_store(tmp_path)
    store.create_job("full_setup", pair["id"], {})
    monkeypatch.setitem(
        jobs.HANDLERS, "full_setup",
        lambda s, j, m: {"protocol": "GRE", "score": 99.0})
    monkeypatch.setitem(
        jobs.HANDLERS, "sweep", lambda s, j, m: {"status": "started"})
    worker = jobs.Worker(store, poll_seconds=0.05)
    worker.start()
    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            if any(t == "sweep" and p == pair["id"]
                   for t, p, _s in _jobs(store)):
                break
            time.sleep(0.1)
        else:
            raise AssertionError("no sweep job was enqueued")
    finally:
        worker.stop()
        worker.join(timeout=5)
    assert any(t == "full_setup" and s == "done"
               for t, _p, s in _jobs(store))


def test_select_dial_hosts_prefers_live_carrier_match():
    run_sweep = _load_runner()
    hub_pair = {"inner_iran": "10.10.12.1", "inner_foreign": "10.10.12.2"}
    healer = {"underlay_carrier": "gre", "iran_dial_host": "10.10.12.1",
              "foreign_dial_host": "10.10.12.2", "active_tunnel": "ESP"}
    wizard = {"underlay_carrier": "esp", "iran_dial_host": "10.12.13.1",
              "foreign_dial_host": "10.12.13.2"}
    assert run_sweep.select_dial_hosts(hub_pair, healer, wizard) == (
        "10.12.13.1", "10.12.13.2", "wizard")
    healer_live = {"underlay_carrier": "gre", "iran_dial_host": "10.10.11.1",
                   "foreign_dial_host": "10.10.11.2", "active_tunnel": "GRE"}
    assert run_sweep.select_dial_hosts(hub_pair, healer_live, wizard) == (
        "10.10.11.1", "10.10.11.2", "healer")


def test_select_dial_hosts_falls_back_to_hub_inners():
    run_sweep = _load_runner()
    hub_pair = {"inner_iran": "10.10.12.1", "inner_foreign": "10.10.12.2"}
    assert run_sweep.select_dial_hosts(hub_pair, None, None) == (
        "10.10.12.1", "10.10.12.2", "hub")
    assert run_sweep.select_dial_hosts(
        hub_pair, {"underlay_carrier": "", "iran_dial_host": "10.12.13.1",
                   "foreign_dial_host": "10.12.13.2", "active_tunnel": "ESP"},
        None) == ("10.10.12.1", "10.10.12.2", "hub")
    assert run_sweep.select_dial_hosts(
        hub_pair, {"underlay_carrier": "esp", "iran_dial_host": "",
                   "foreign_dial_host": "10.12.13.2", "active_tunnel": "ESP"},
        None) == ("10.10.12.1", "10.10.12.2", "hub")
    assert run_sweep.select_dial_hosts(
        hub_pair, None,
        {"underlay_carrier": "esp", "iran_dial_host": "10.12.13.1",
         "foreign_dial_host": "10.12.13.2"}) == (
        "10.12.13.1", "10.12.13.2", "wizard")


def test_select_dial_hosts_overlay_live_dials_public():
    run_sweep = _load_runner()
    hub_pair = {"inner_iran": "10.10.13.1", "inner_foreign": "10.10.13.2"}
    # Bug 14 (2026-11-01): pair 4's live protocol is an overlay
    # (backhaul-wss) and it never had a carrier, so no store holds a
    # carrier declaration and the hub inners have no interface behind
    # them. Falling back to them made every overlay bench fail at the
    # readiness check, including the live backhaul bench itself.
    assert run_sweep.select_dial_hosts(
        hub_pair, {"underlay_carrier": "", "iran_dial_host": "",
                   "foreign_dial_host": "", "active_tunnel": "backhaul-wss"},
        None) == (None, None, "public")
    assert run_sweep.select_dial_hosts(hub_pair, None, None) == (
        "10.10.13.1", "10.10.13.2", "hub")


def test_read_declaration_rows_reads_both_stores(tmp_path):
    run_sweep = _load_runner()
    healer_db = tmp_path / "healer.db"
    conn = sqlite3.connect(healer_db)
    conn.execute("CREATE TABLE pairs (id INTEGER PRIMARY KEY,"
                 " underlay_carrier TEXT, iran_dial_host TEXT,"
                 " foreign_dial_host TEXT, active_tunnel TEXT)")
    conn.execute("INSERT INTO pairs VALUES (3, '', '', '', 'ESP')")
    conn.commit()
    conn.close()
    wizard_db = tmp_path / "wizard.db"
    conn = sqlite3.connect(wizard_db)
    conn.execute("CREATE TABLE pairs (id INTEGER PRIMARY KEY,"
                 " underlay_carrier TEXT, iran_dial_host TEXT,"
                 " foreign_dial_host TEXT)")
    conn.execute("INSERT INTO pairs VALUES (3, 'esp', '10.12.13.1', '10.12.13.2')")
    conn.commit()
    conn.close()
    run_sweep.WIZARD_DB_PATH = str(wizard_db)
    healer_row, wizard_row = run_sweep.read_declaration_rows(3, str(healer_db))
    assert healer_row["active_tunnel"] == "ESP"
    assert wizard_row["underlay_carrier"] == "esp"
    assert run_sweep.select_dial_hosts(
        {"inner_iran": "10.10.12.1", "inner_foreign": "10.10.12.2"},
        healer_row, wizard_row) == ("10.12.13.1", "10.12.13.2", "wizard")
    missing_healer, missing_wizard = run_sweep.read_declaration_rows(
        3, str(tmp_path / "nope.db"))
    assert missing_healer is None
    run_sweep.WIZARD_DB_PATH = str(tmp_path / "nope-wizard.db")
    _h, missing_wizard = run_sweep.read_declaration_rows(
        3, str(tmp_path / "nope.db"))
    assert missing_wizard is None
