"""Private panel base path (C-Tunnel-style random panel URL).

A fresh hub serves its pages only under a random path; the root paths
then 404 instead of revealing the dashboard. The API never moves
(sessions live under /api), so rotation logs nobody out. An older hub
keeps the root until its operator rotates it.
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


def get(port, path, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Cookie": cookie} if cookie else {}
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, body


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
    return resp.status, (cookie_out.split(";")[0] if cookie_out else None), \
        json.loads(body or b"{}")


def _login(port):
    post(port, "/api/setup", {"username": "admin", "password": "change-me-123"})
    _, cookie, _ = post(port, "/api/login",
                        {"username": "admin", "password": "change-me-123"})
    assert cookie
    return cookie


def test_root_serves_pages_by_default(running):
    port, _ = running
    status, body = get(port, "/")
    assert status == 200 and "رهیاب".encode() in body
    status, _ = get(port, "/static/app.js")
    assert status == 200


def test_panel_path_hides_root_and_serves_only_itself(running):
    port, store = running
    cookie = _login(port)
    status, _, body = post(port, "/api/panel_path", {"action": "rotate"}, cookie)
    assert status == 200
    path = body["panel_path"]
    assert path.startswith("panel-") and len(path) > 10
    assert store.get_panel_path() == path
    status, _ = get(port, "/")
    assert status == 404
    status, _ = get(port, "/static/app.js")
    assert status == 404
    status, body = get(port, "/" + path + "/")
    assert status == 200 and "رهیاب".encode() in body
    status, _ = get(port, "/" + path + "/static/app.js")
    assert status == 200
    # Rotation needs a session; clearing restores the root.
    status, _, _ = post(port, "/api/panel_path", {"action": "rotate"})
    assert status == 401
    status, _, body = post(port, "/api/panel_path", {"action": "clear"}, cookie)
    assert status == 200 and body["panel_path"] == ""
    status, _ = get(port, "/")
    assert status == 200


def test_panel_path_validation(tmp_path):
    store = Store(str(tmp_path / "hub.db"))
    store.set_panel_path("panel-abc123")
    assert store.get_panel_path() == "panel-abc123"
    for bad in ("../escape", "has space", "a/b", "x" * 65):
        with pytest.raises(ValueError):
            store.set_panel_path(bad)
