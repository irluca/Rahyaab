"""Quick test + deploy-best (C-Tunnel-style fast test, one-click deploy).

Quick scores live in quick_tests, never in candidate_scores; the
quick suite shares the bench ports with the sweep, so only one bench
suite runs per pair at a time; deploy-best refuses without a finished
test, without a qualified winner, or when already on the winner.
"""

import http.client
import json
import threading

import pytest

from hub import jobs
from hub.server import serve
from hub.ssh import FakeExecutor
from hub.store import Store


@pytest.fixture()
def running(tmp_path, monkeypatch):
    monkeypatch.setenv("RAHYAAB_SWEEP_DIR", str(tmp_path))
    # The worker would otherwise spawn a real quick-test scope process.
    monkeypatch.setattr(jobs, "_spawn_sweep", lambda argv: None)
    store = Store(tmp_path / "hub.db")
    server = serve(store, host="127.0.0.1", port=0,
                   make_executor=lambda s: FakeExecutor({}))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], store
    server.shutdown()
    server.hub.worker.stop()


def _req(port, method, path, payload=None, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    conn.request(method, path,
                 body=json.dumps(payload) if payload is not None else None,
                 headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    cookie_out = resp.getheader("Set-Cookie")
    conn.close()
    return (resp.status,
            cookie_out.split(";")[0] if cookie_out else None,
            json.loads(body or b"{}"))


def _login(port):
    _req(port, "POST", "/api/setup",
         {"username": "admin", "password": "change-me-123"})
    _, cookie, _ = _req(port, "POST", "/api/login",
                        {"username": "admin", "password": "change-me-123"})
    assert cookie
    return cookie


def _pair(port, cookie, protocol="GRE"):
    _, _, iran = _req(port, "POST", "/api/servers",
                      {"name": "iran", "host": "10.0.0.1"}, cookie)
    _, _, foreign = _req(port, "POST", "/api/servers",
                         {"name": "foreign", "host": "10.0.0.2"}, cookie)
    _, _, pair = _req(port, "POST", "/api/pairs",
                      {"name": "p", "iran_server_id": iran["id"],
                       "foreign_server_id": foreign["id"],
                       "current_protocol": protocol}, cookie)
    return pair


def test_store_quick_test_round_trip(tmp_path):
    store = Store(str(tmp_path / "hub.db"))
    iran = store.create_server({"name": "iran", "host": "10.0.0.1"})
    foreign = store.create_server({"name": "foreign", "host": "10.0.0.2"})
    pair = store.create_pair({"name": "p", "iran_server_id": iran["id"],
                              "foreign_server_id": foreign["id"]})
    assert store.latest_quick_test(pair["id"]) is None
    rows = [{"protocol": "GRE", "score": 90.0, "disqualified": False},
            {"protocol": "ESP", "score": 0.0, "disqualified": True}]
    saved = store.save_quick_test(pair["id"], "GRE", rows)
    assert saved["winner"] == "GRE"
    latest = store.latest_quick_test(pair["id"])
    assert latest["winner"] == "GRE" and latest["results"] == rows


def test_quick_test_handler_spawns_quick_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("RAHYAAB_SWEEP_DIR", str(tmp_path))
    store = Store(str(tmp_path / "hub.db"))
    iran = store.create_server({"name": "iran", "host": "10.0.0.1"})
    foreign = store.create_server({"name": "foreign", "host": "10.0.0.2"})
    pair = store.create_pair({"name": "p", "iran_server_id": iran["id"],
                              "foreign_server_id": foreign["id"]})
    spawned = []
    monkeypatch.setattr(jobs, "_spawn_sweep", lambda argv: spawned.append(argv))
    out = jobs._handle_quick_test(store, {"pair_id": pair["id"]}, None)
    assert out["status"] == "started"
    assert out["unit"] == "rahyaab-quicktest-p%d.scope" % pair["id"]
    assert "--quick" in spawned[0][5]
    assert "run_sweep.py" in spawned[0][5]
    # A live quick-test pidfile blocks both a second quick test and a sweep.
    (tmp_path / ("quicktest-p%d.pid" % pair["id"])).write_text("999999999")
    # 999999999 is not a live pid, so use our own pid instead.
    import os
    (tmp_path / ("quicktest-p%d.pid" % pair["id"])).write_text(str(os.getpid()))
    assert jobs._quicktest_running(pair["id"]) is True
    assert jobs._sweep_running(pair["id"]) is True
    out = jobs._handle_quick_test(store, {"pair_id": pair["id"]}, None)
    assert out["status"] == "already-running"


def test_quick_test_routes_and_deploy_best(running):
    port, store = running
    cookie = _login(port)
    pair = _pair(port, cookie, protocol="GRE")
    status, _, body = _req(port, "POST", f"/api/pairs/{pair['id']}/quick_test",
                           {}, cookie)
    assert status == 201 and body["type"] == "quick_test"
    status, _, body = _req(port, "GET", f"/api/pairs/{pair['id']}/quick_test",
                           None, cookie)
    assert status == 200 and body["running"] is False and body["result"] is None
    # Deploy-best refuses without a finished test.
    status, _, body = _req(port, "POST", f"/api/pairs/{pair['id']}/deploy_best",
                           {}, cookie)
    assert status == 400
    # Winner == current protocol: no job, honest answer.
    store.save_quick_test(pair["id"], "GRE", [
        {"protocol": "GRE", "score": 90.0, "disqualified": False}])
    status, _, body = _req(port, "POST", f"/api/pairs/{pair['id']}/deploy_best",
                           {}, cookie)
    assert status == 201 and body["deployed"] is False
    assert store.list_jobs(pair["id"]) == [] or all(
        j["type"] != "switch" for j in store.list_jobs(pair["id"]))
    # Winner != current: a switch job is created.
    store.save_quick_test(pair["id"], "ESP", [
        {"protocol": "ESP", "score": 88.0, "disqualified": False},
        {"protocol": "GRE", "score": 90.0, "disqualified": True}])
    status, _, body = _req(port, "POST", f"/api/pairs/{pair['id']}/deploy_best",
                           {}, cookie)
    assert status == 201 and body["deployed"] is True
    jobs_created = [j for j in store.list_jobs(pair["id"])
                    if j["type"] == "switch"]
    assert jobs_created and jobs_created[0]["input"]["protocol"] == "ESP"
