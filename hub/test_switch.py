"""Tests for click-to-switch: the hub switch job, the protocol sync,
and the POST /api/pairs/{id}/switch route.

The fake healer host simulates the request/result files: it captures
the request the hub writes, then answers polls with a canned outcome
for that request_id — the same contract the real healer honors.
"""

import base64
import http.client
import json
import re
import threading
import time

import pytest

from hub import jobs
from hub.server import serve
from hub.store import Store


SCORES = {"GRE": 99.9, "ESP": 99.84, "rathole-noise": 93.06,
          "singbox-ss-2022": 0}


class SwitchFakeExecutor:
    def __init__(self, result_for=None):
        self.commands = []
        self.request = None
        self.result_for = result_for

    def run(self, command, timeout=60):
        self.commands.append(command)
        if command.startswith("printf '%s'"):
            match = re.search(r"'([A-Za-z0-9+/=]+)'", command)
            self.request = json.loads(base64.b64decode(match.group(1)))
            return 0, "", ""
        if command.startswith("cat /var/lib/best-tunnel/switch-result.json"):
            if self.request is None or self.result_for is None:
                return 1, "", "no such file"
            res = self.result_for(self.request)
            if res is None:
                return 1, "", "no such file"
            return 0, json.dumps(res), ""
        return 0, "", ""


def _done_result(request):
    return {"request_id": request["request_id"], "status": "done",
            "from": "GRE", "to": request["protocol"],
            "already": False, "rolled_back": False, "detail": ""}


def _make_pair(store):
    iran = store.create_server({"name": "iran", "host": "203.0.113.10"})
    foreign = store.create_server({"name": "foreign", "host": "203.0.113.20"})
    return store.create_pair({
        "name": "manag-netlen", "iran_server_id": iran["id"],
        "foreign_server_id": foreign["id"], "healer_server_id": iran["id"],
        "current_protocol": "GRE", "candidate_scores": SCORES,
    })


@pytest.fixture()
def store(tmp_path):
    return Store(tmp_path / "hub.db")


def _run_handler(store, pair, fake, protocol):
    job = {"pair_id": pair["id"], "input": {"protocol": protocol}}
    return jobs._handle_switch(store, job, lambda s: fake)


def test_switch_already_never_touches_ssh(store):
    pair = _make_pair(store)
    fake = SwitchFakeExecutor(_done_result)
    out = _run_handler(store, pair, fake, "GRE")
    assert out["status"] == "already"
    assert fake.commands == []


def test_switch_disqualified_or_unknown_is_refused(store):
    pair = _make_pair(store)
    fake = SwitchFakeExecutor(_done_result)
    with pytest.raises(ValueError):
        _run_handler(store, pair, fake, "singbox-ss-2022")
    with pytest.raises(ValueError):
        _run_handler(store, pair, fake, "bogus-protocol")
    assert fake.commands == []


def test_switch_done_updates_protocol_and_logs_event(store):
    pair = _make_pair(store)
    fake = SwitchFakeExecutor(_done_result)
    out = _run_handler(store, pair, fake, "ESP")
    assert out["status"] == "done"
    assert store.get_pair(pair["id"])["current_protocol"] == "ESP"
    events = store.list_events()
    assert any(e["kind"] == "switch" for e in events)


def test_switch_refused_keeps_protocol(store):
    pair = _make_pair(store)

    def refused(request):
        return {"request_id": request["request_id"], "status": "refused",
                "from": "GRE", "to": request["protocol"],
                "already": False, "rolled_back": False,
                "detail": "Circuit breaker: last failover 40 seconds ago"}

    out = _run_handler(store, pair, SwitchFakeExecutor(refused), "ESP")
    assert out["status"] == "refused"
    assert "Circuit breaker" in out["detail"]
    assert store.get_pair(pair["id"])["current_protocol"] == "GRE"


def test_switch_failed_with_rollback_reports_it(store):
    pair = _make_pair(store)

    def failed(request):
        return {"request_id": request["request_id"], "status": "failed",
                "from": "GRE", "to": request["protocol"],
                "already": False, "rolled_back": True,
                "detail": "Smoke verification failed"}

    out = _run_handler(store, pair, SwitchFakeExecutor(failed), "ESP")
    assert out["status"] == "failed"
    assert out["rolled_back"] is True
    assert store.get_pair(pair["id"])["current_protocol"] == "GRE"


def test_switch_unknown_when_healer_never_answers(store, monkeypatch):
    pair = _make_pair(store)
    clock = {"now": 1000.0}

    def fake_time():
        clock["now"] += 300.0
        return clock["now"]

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "sleep", lambda s: None)
    out = _run_handler(store, pair, SwitchFakeExecutor(None), "ESP")
    assert out["status"] == "unknown"


def test_healer_status_syncs_protocol_from_heartbeat(store):
    pair = _make_pair(store)
    store.update_pair_healer(pair["id"], {
        "reachable": True, "unit_active": True, "healthy": True,
        "heartbeat": {"active_tunnel": "ESP"},
    })
    assert store.get_pair(pair["id"])["current_protocol"] == "ESP"
    # A heartbeat without the field leaves the row untouched.
    store.update_pair_healer(pair["id"], {"reachable": True, "heartbeat": {}})
    assert store.get_pair(pair["id"])["current_protocol"] == "ESP"


# ---- HTTP route -------------------------------------------------------


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


def _wait_job(client, job_id, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status, job = client.request("GET", f"/api/jobs/{job_id}")
        assert status == 200
        if job["status"] in ("done", "failed"):
            return job
        time.sleep(0.2)
    raise AssertionError("job %s did not finish" % job_id)


def test_switch_route_end_to_end(tmp_path):
    store = Store(tmp_path / "hub.db")
    fake = SwitchFakeExecutor(_done_result)
    server = serve(store, host="127.0.0.1", port=0,
                   make_executor=lambda s: fake)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = Client(server.server_address[1])
    try:
        status, _ = client.request("POST", "/api/setup",
                                   {"username": "admin", "password": "change-me-123"})
        assert status == 201
        status, _ = client.request("POST", "/api/login",
                                   {"username": "admin", "password": "change-me-123"})
        assert status == 200
        _, iran = client.request("POST", "/api/servers",
                                 {"name": "iran", "host": "203.0.113.10"})
        _, foreign = client.request("POST", "/api/servers",
                                    {"name": "foreign", "host": "203.0.113.20"})
        status, pair = client.request("POST", "/api/pairs", {
            "name": "manag-netlen", "iran_server_id": iran["id"],
            "foreign_server_id": foreign["id"],
            "healer_server_id": iran["id"],
            "current_protocol": "GRE", "candidate_scores": SCORES})
        assert status == 201, pair
        status, job = client.request("POST", f"/api/pairs/{pair['id']}/switch",
                                     {"protocol": "ESP"})
        assert status == 201, job
        assert job["type"] == "switch"
        finished = _wait_job(client, job["id"])
        assert finished["status"] == "done"
        assert finished["output"]["status"] == "done"
        status, pair = client.request("GET", f"/api/pairs/{pair['id']}")
        assert pair["current_protocol"] == "ESP"
        # Unknown pair and missing protocol are refused cleanly.
        status, _ = client.request("POST", "/api/pairs/9999/switch",
                                   {"protocol": "ESP"})
        assert status == 404
        status, _ = client.request("POST", f"/api/pairs/{pair['id']}/switch", {})
        assert status == 400
    finally:
        server.shutdown()
        server.hub.worker.stop()
