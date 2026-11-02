"""Panel JSON backup + restore (C-Tunnel-style one-JSON backup).

Export carries servers and pairs but no secrets (key paths only, never
key material; no users, sessions or settings). Restore adds only what
is missing: an existing server or pair is never overwritten, so a
restore cannot change a live pair's port or protocol.
"""

import http.client
import json
import threading

import pytest

from hub.server import serve
from hub.ssh import FakeExecutor
from hub.store import Store


@pytest.fixture()
def running(tmp_path):
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


def _seed(port, cookie):
    _, _, iran = _req(port, "POST", "/api/servers",
                      {"name": "iran", "host": "10.0.0.1",
                       "key_path": "/etc/rahyaab/hub_key",
                       "notes": "main"}, cookie)
    _, _, foreign = _req(port, "POST", "/api/servers",
                         {"name": "foreign", "host": "10.0.0.2"}, cookie)
    _, _, pair = _req(port, "POST", "/api/pairs",
                      {"name": "p", "iran_server_id": iran["id"],
                       "foreign_server_id": foreign["id"],
                       "frontend_port": 21232,
                       "current_protocol": "GRE",
                       "candidate_scores": {"GRE": 99.0}}, cookie)
    return iran, foreign, pair


def test_backup_export_has_no_secrets(running):
    port, _ = running
    cookie = _login(port)
    _seed(port, cookie)
    status, _, body = _req(port, "GET", "/api/backup", None, cookie)
    assert status == 200
    assert body["version"] == 1
    assert len(body["servers"]) == 2 and len(body["pairs"]) == 1
    assert body["pairs"][0]["frontend_port"] == 21232
    assert body["pairs"][0]["candidate_scores"] == {"GRE": 99.0}
    dumped = json.dumps(body)
    assert "PRIVATE KEY" not in dumped and "password" not in dumped.lower()
    # Backup needs a session.
    status, _, _ = _req(port, "GET", "/api/backup")
    assert status == 401


def test_backup_restore_adds_only_missing(running):
    port, store = running
    cookie = _login(port)
    _seed(port, cookie)
    _, _, backup = _req(port, "GET", "/api/backup", None, cookie)
    # Restore into a second, empty hub store via the same API shape:
    # wipe this hub's rows through a fresh store is not possible over
    # HTTP, so restore the same backup twice and check idempotence.
    status, _, out = _req(port, "POST", "/api/backup", backup, cookie)
    assert status == 201
    assert out == {"added_servers": 0, "added_pairs": 0}
    assert len(store.list_servers()) == 2 and len(store.list_pairs()) == 1
    # A pair with the same name+servers but a different port must not
    # overwrite the live pair.
    tampered = json.loads(json.dumps(backup))
    tampered["pairs"][0]["frontend_port"] = 9999
    tampered["pairs"][0]["current_protocol"] = "ESP"
    status, _, out = _req(port, "POST", "/api/backup", tampered, cookie)
    assert status == 201 and out["added_pairs"] == 0
    pair = store.list_pairs()[0]
    assert pair["frontend_port"] == 21232
    assert pair["current_protocol"] == "GRE"
    # A genuinely new pair is added.
    tampered["pairs"].append({
        "name": "p2", "iran_server": {"name": "iran", "host": "10.0.0.1"},
        "foreign_server": {"name": "foreign", "host": "10.0.0.2"},
        "frontend_port": 2083, "current_protocol": "ESP",
        "candidate_scores": {}, "spoof_status": None})
    status, _, out = _req(port, "POST", "/api/backup", tampered, cookie)
    assert status == 201 and out["added_pairs"] == 1
    assert len(store.list_pairs()) == 2


def test_backup_restore_rejects_garbage(running):
    port, _ = running
    cookie = _login(port)
    for bad in ({"version": 2, "servers": [], "pairs": []},
                {"version": 1, "servers": {}, "pairs": []},
                {"version": 1, "servers": [{"name": "x"}], "pairs": []},
                {"version": 1, "servers": [], "pairs": [
                    {"name": "p", "iran_server": {"name": "ghost", "host": "10.0.0.9"},
                     "foreign_server": {"name": "ghost", "host": "10.0.0.9"}}]}):
        status, _, _ = _req(port, "POST", "/api/backup", bad, cookie)
        assert status == 400, bad
