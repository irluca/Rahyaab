"""Tests for Phase 3: the hub serves the dashboard, and history exists
for its charts. Static pages are public (they contain the login form);
every API route stays behind a session.
"""

import http.client
import json
import threading
import time

import pytest

from hub.server import serve
from hub.ssh import FakeExecutor
from hub.store import Store


@pytest.fixture()
def running(tmp_path):
    store = Store(tmp_path / "hub.db")
    fake = FakeExecutor({
        "systemctl is-active": (0, "active\n", ""),
        "cat /var/lib/best-tunnel/healer-heartbeat.json": (
            0, json.dumps({"updated_at": "2099-01-01T00:00:00+00:00",
                           "running": True}), ""),
    })
    server = serve(store, host="127.0.0.1", port=0,
                   make_executor=lambda s: fake)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.hub.worker.stop()


def get(port, path, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, resp.getheader("Content-Type"), body


def post(port, path, payload, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    conn.request("POST", path, body=json.dumps(payload), headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    cookie_out = resp.getheader("Set-Cookie")
    conn.close()
    return resp.status, (cookie_out.split(";")[0] if cookie_out else None), json.loads(body or b"{}")


def test_dashboard_served_and_history_recorded(running):
    port = running
    # The dashboard page itself is public; the API is not.
    status, ctype, body = get(port, "/")
    assert status == 200 and "text/html" in ctype and "رهیاب".encode() in body
    status, _, body = get(port, "/static/app.js")
    assert status == 200 and b"healer_status" in body
    status, _, _ = get(port, "/static/../server.py")
    assert status == 404
    status, _, _ = get(port, "/api/servers")
    assert status == 401
    # Log in, build a pair, refresh its healer status, read history.
    post(port, "/api/setup", {"username": "admin", "password": "change-me-123"})
    _, cookie, _ = post(port, "/api/login", {"username": "admin", "password": "change-me-123"})
    assert cookie
    _, _, iran = post(port, "/api/servers", {"name": "iran", "host": "10.0.0.1"}, cookie)
    _, _, foreign = post(port, "/api/servers", {"name": "foreign", "host": "10.0.0.2"}, cookie)
    _, _, pair = post(port, "/api/pairs",
                      {"name": "p1", "iran_server_id": iran["id"],
                       "foreign_server_id": foreign["id"]}, cookie)
    status, _, body = get(port, f"/api/pairs/{pair['id']}/history", cookie)
    assert status == 200 and json.loads(body)["history"] == []
    status, _, body = get(port, f"/api/pairs/{pair['id']}/healer", cookie)
    assert status == 200
    status, _, body = get(port, f"/api/pairs/{pair['id']}/history", cookie)
    history = json.loads(body)["history"]
    assert len(history) == 1
    assert history[0]["reachable"] == 1 and history[0]["unit_active"] == 1
