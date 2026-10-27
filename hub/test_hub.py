"""Offline tests for the Rahyaab hub (Phase 2).

Runs the real HTTP server on an ephemeral localhost port against a
temporary database, with a FakeExecutor standing in for SSH. No
network, no real servers, no secrets: the fake healer host answers
`systemctl is-active` and a fresh heartbeat.
"""

import datetime
import http.client
import json
import threading
import time

import pytest

from hub.server import serve
from hub.ssh import FakeExecutor
from hub.store import Store


def _heartbeat_json():
    return json.dumps({
        "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "pid": 1234, "pair_id": 1, "pair_name": "manag-netlen",
        "running": True, "last_pass": "ok", "streaks": {},
        "armed": True, "verdicts": {},
    })


class Client:
    def __init__(self, port):
        self.port = port
        self.cookie = None

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Content-Type": "application/json"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        conn.request(method, path, body=json.dumps(body) if body is not None else None,
                     headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        set_cookie = resp.getheader("Set-Cookie")
        if set_cookie:
            self.cookie = set_cookie.split(";")[0]
        conn.close()
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {}
        return resp.status, payload


@pytest.fixture()
def hub(tmp_path):
    store = Store(tmp_path / "hub.db")
    fake = FakeExecutor({
        "systemctl is-active": (0, "active\n", ""),
        "cat /var/lib/best-tunnel/healer-heartbeat.json": (0, _heartbeat_json(), ""),
        "systemctl restart": (0, "", ""),
        "echo rahyaab-ok": (0, "rahyaab-ok\n", ""),
    })
    server = serve(store, host="127.0.0.1", port=0,
                   make_executor=lambda s: fake)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    yield Client(port), fake
    server.shutdown()
    server.hub.worker.stop()


def _wait_job(client, job_id, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status, job = client.request("GET", f"/api/jobs/{job_id}")
        assert status == 200
        if job["status"] in ("done", "failed"):
            return job
        time.sleep(0.1)
    raise AssertionError("job %s did not finish" % job_id)


def test_full_hub_flow(hub):
    client, fake = hub
    # Health + first-time setup; setup is one-shot.
    status, body = client.request("GET", "/api/health")
    assert status == 200 and body["users"] is False
    status, body = client.request("POST", "/api/setup",
                                  {"username": "admin", "password": "change-me-123"})
    assert status == 201, body
    status, _ = client.request("POST", "/api/setup",
                               {"username": "second", "password": "change-me-123"})
    assert status == 403
    # Unauthenticated access is refused, bad login is refused.
    status, _ = client.request("GET", "/api/servers")
    assert status == 401
    status, _ = client.request("POST", "/api/login",
                               {"username": "admin", "password": "wrong"})
    assert status == 401
    status, _ = client.request("POST", "/api/login",
                               {"username": "admin", "password": "change-me-123"})
    assert status == 200 and client.cookie
    # Fleet: two servers, then a pair between them.
    _, iran = client.request("POST", "/api/servers",
                             {"name": "iran", "host": "203.0.113.10"})
    _, foreign = client.request("POST", "/api/servers",
                                {"name": "foreign", "host": "203.0.113.20"})
    assert iran["id"] != foreign["id"]
    status, _ = client.request("POST", "/api/pairs",
                               {"name": "bad", "iran_server_id": iran["id"],
                                "foreign_server_id": iran["id"]})
    assert status == 400
    status, pair = client.request("POST", "/api/pairs",
                                  {"name": "manag-netlen",
                                   "iran_server_id": iran["id"],
                                   "foreign_server_id": foreign["id"],
                                   "current_protocol": "GRE",
                                   "candidate_scores": {"GRE": 99.96}})
    assert status == 201, pair
    status, _ = client.request("DELETE", f"/api/servers/{iran['id']}")
    assert status == 409  # still used by a pair
    # Healer: live status from the fake host, plus a restart action.
    status, healer = client.request("GET", f"/api/pairs/{pair['id']}/healer")
    assert status == 200 and healer["healthy"] is True, healer
    assert healer["unit_active"] is True
    status, acted = client.request("POST", f"/api/pairs/{pair['id']}/healer/restart")
    assert status == 200 and acted["ok"] is True
    assert any("systemctl restart" in c for c in fake.commands)
    # Jobs: noop runs to done; healer_status refreshes the pair snapshot.
    status, job = client.request("POST", "/api/jobs",
                                 {"type": "noop", "input": {"ping": 1}})
    assert status == 201
    job = _wait_job(client, job["id"])
    assert job["status"] == "done" and job["output"]["echo"] == {"ping": 1}
    status, job = client.request("POST", "/api/jobs",
                                 {"type": "healer_status", "pair_id": pair["id"]})
    assert status == 201
    assert _wait_job(client, job["id"])["status"] == "done"
    status, pair_after = client.request("GET", f"/api/pairs/{pair['id']}")
    assert pair_after["healer_last_status"]["healthy"] is True
    # Events recorded, logout revokes the session.
    status, events = client.request("GET", "/api/events")
    assert status == 200
    assert any(e["kind"] == "pair_created" for e in events["events"])
    status, _ = client.request("POST", "/api/logout")
    assert status == 200
    status, _ = client.request("GET", "/api/servers")
    assert status == 401
