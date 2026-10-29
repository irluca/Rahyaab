"""Tests for the tunnel port change: the change_port job handler,
the POST /api/pairs/{id}/change_port route, and the carrier vs
overlay split (hub/jobs.py + hub/server.py).

The fake healer hosts simulate the request/result files and, for
carriers, the port-rewrite script: no real SSH, no live hosts.
"""

import base64
import http.client
import json
import re
import threading
import time

import pytest

from hub import jobs
from hub.server import ApiError, Hub, serve
from hub.ssh import FakeExecutor
from hub.store import Store


def _make_pair(store, protocol="GRE", port=443, healer_port=22,
               iran_id=None, foreign_id=None):
    if iran_id is None:
        iran = store.create_server({"name": "iran", "host": "203.0.113.10",
                                    "port": healer_port})
        iran_id = iran["id"]
    if foreign_id is None:
        foreign = store.create_server({"name": "foreign", "host": "203.0.113.20"})
        foreign_id = foreign["id"]
    return store.create_pair({
        "name": "manag-netlen", "iran_server_id": iran_id,
        "foreign_server_id": foreign_id, "healer_server_id": iran_id,
        "current_protocol": protocol, "frontend_port": port,
        "candidate_scores": {"GRE": 99.9, "chisel-wss": 66.0},
    })


def _run_handler(store, pair, fake, port):
    job = {"pair_id": pair["id"], "input": {"frontend_port": port}}
    return jobs._handle_change_port(store, job, lambda s: fake)


class PortChangeFakeExecutor:
    """Answers switch-request polls with a canned outcome."""

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
        if command.startswith("cat /var/lib/best-tunnel/switch-result"):
            if self.request is None or self.result_for is None:
                return 1, "", "no such file"
            res = self.result_for(self.request)
            if res is None:
                return 1, "", "no such file"
            return 0, json.dumps(res), ""
        return 0, "", ""


class CarrierFakeExecutor:
    """Answers the carrier port-rewrite script with ok, restart with ok."""

    def __init__(self, script_rc=0):
        self.commands = []
        self.script_rc = script_rc

    def run(self, command, timeout=60):
        self.commands.append(command)
        if command.startswith("printf '%s'"):
            return self.script_rc, "ok\n" if self.script_rc == 0 else "", "boom"
        if command.startswith("systemctl restart"):
            return 0, "", ""
        return 0, "", ""


def _done_result(request):
    return {"request_id": request["request_id"], "status": "done",
            "from": request["protocol"], "to": request["protocol"],
            "already": False, "rolled_back": False, "detail": ""}


@pytest.fixture()
def store(tmp_path):
    return Store(tmp_path / "hub.db")


@pytest.fixture(autouse=True)
def _free_socket_table(monkeypatch):
    # The handler reads the live socket table; tests must not depend
    # on this VM's listeners. Default: every port free; the busy
    # tests below override this per test.
    monkeypatch.setattr(jobs, "_ss_port_free", lambda port: True)


def test_endpoint_validates_pair_and_port(store):
    # The worker starts with the Hub, so it gets the carrier fake:
    # the queued job then finishes through the real worker instead
    # of hanging on a real SSH attempt to a documentation address.
    hub = Hub(store, make_executor=lambda s: CarrierFakeExecutor())
    try:
        with pytest.raises(ApiError) as exc:
            hub.change_port_pair(9999, {"frontend_port": 23456})
        assert exc.value.status == 404
        pair = _make_pair(store)
        for bad in (0, 70000, "nope"):
            with pytest.raises(ApiError) as exc:
                hub.change_port_pair(pair["id"], {"frontend_port": bad})
            assert exc.value.status == 400
        job = hub.change_port_pair(pair["id"], {"frontend_port": 23456})
        assert job["type"] == "change_port"
        assert job["input"]["frontend_port"] == 23456
    finally:
        hub.worker.stop()


def test_same_port_is_already_without_ssh(store):
    pair = _make_pair(store, port=23456)
    fake = FakeExecutor()
    out = _run_handler(store, pair, fake, 23456)
    assert out["status"] == "already"
    assert fake.commands == []


def test_reserved_and_pair_used_ports_refused(store):
    pair = _make_pair(store, port=23456, healer_port=2222)
    fake = FakeExecutor()
    for bad in (22, 53, 68, 123, 8890, 2222):
        with pytest.raises(ValueError):
            _run_handler(store, pair, fake, bad)
    # A second pair on the SAME master (iran) holding 34567 blocks it.
    foreign2 = store.create_server({"name": "foreign-2",
                                    "host": "203.0.113.30"})
    second = store.create_pair({
        "name": "second-pair", "iran_server_id": pair["iran_server_id"],
        "foreign_server_id": foreign2["id"],
        "healer_server_id": pair["iran_server_id"],
        "current_protocol": "GRE", "frontend_port": 34567,
        "candidate_scores": {"GRE": 99.9},
    })
    with pytest.raises(ValueError):
        _run_handler(store, pair, fake, 34567)
    assert fake.commands == []


def test_busy_port_refused_before_any_command(store, monkeypatch):
    monkeypatch.setattr(jobs, "_ss_port_free", lambda port: False)
    pair = _make_pair(store, protocol="GRE", port=8443)
    fake = CarrierFakeExecutor()
    with pytest.raises(ValueError, match="busy"):
        _run_handler(store, pair, fake, 23457)
    assert fake.commands == []
    assert store.get_pair(pair["id"])["frontend_port"] == 8443


def test_busy_port_refused_for_overlay_too(store, monkeypatch):
    monkeypatch.setattr(jobs, "_ss_port_free", lambda port: False)
    pair = _make_pair(store, protocol="chisel-wss", port=443)
    fake = PortChangeFakeExecutor(_done_result)
    with pytest.raises(ValueError, match="busy"):
        _run_handler(store, pair, fake, 23456)
    assert fake.commands == []


def test_unreadable_socket_table_accepts_port(store, monkeypatch):
    monkeypatch.setattr(jobs, "_ss_port_free", lambda port: None)
    pair = _make_pair(store, protocol="GRE", port=443)
    out = _run_handler(store, pair, CarrierFakeExecutor(), 23456)
    assert out["status"] == "done"


def test_pair_without_tunnel_refused(store):
    pair = _make_pair(store, protocol="", port=23456)
    with pytest.raises(ValueError):
        _run_handler(store, pair, FakeExecutor(), 34567)


def test_carrier_change_touches_no_tunnel(store):
    pair = _make_pair(store, protocol="GRE", port=443)
    fake = CarrierFakeExecutor()
    out = _run_handler(store, pair, fake, 23456)
    assert out["status"] == "done"
    assert out["tunnel_touched"] is False
    assert out["port_from"] == 443 and out["port_to"] == 23456
    assert store.get_pair(pair["id"])["frontend_port"] == 23456
    assert any(c.startswith("systemctl restart best-tunnel-healer-p") for c in fake.commands)
    assert any(e["kind"] == "change_port" for e in store.list_events())


def test_carrier_script_failure_leaves_row_untouched(store):
    pair = _make_pair(store, protocol="ESP", port=443)
    fake = CarrierFakeExecutor(script_rc=1)
    with pytest.raises(RuntimeError):
        _run_handler(store, pair, fake, 23456)
    assert store.get_pair(pair["id"])["frontend_port"] == 443


def test_overlay_change_goes_through_switch_channel(store):
    pair = _make_pair(store, protocol="chisel-wss", port=443)
    fake = PortChangeFakeExecutor(_done_result)
    out = _run_handler(store, pair, fake, 23456)
    assert out["status"] == "done"
    assert out["tunnel_touched"] is True
    assert out["port_from"] == 443 and out["port_to"] == 23456
    assert fake.request["protocol"] == "chisel-wss"
    assert fake.request["frontend_port"] == 23456
    assert store.get_pair(pair["id"])["frontend_port"] == 23456


def test_overlay_refused_keeps_old_port(store):
    pair = _make_pair(store, protocol="chisel-wss", port=443)

    def refused(request):
        return {"request_id": request["request_id"], "status": "refused",
                "from": "chisel-wss", "to": "chisel-wss",
                "already": False, "rolled_back": False,
                "detail": "Circuit breaker: last failover 40 seconds ago"}

    out = _run_handler(store, pair, PortChangeFakeExecutor(refused), 23456)
    assert out["status"] == "refused"
    assert store.get_pair(pair["id"])["frontend_port"] == 443


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


def test_change_port_route_end_to_end(tmp_path):
    store = Store(tmp_path / "hub.db")
    fake = PortChangeFakeExecutor(_done_result)
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
            "current_protocol": "chisel-wss", "frontend_port": 443,
            "candidate_scores": {"chisel-wss": 66.0}})
        assert status == 201, pair
        status, job = client.request("POST", f"/api/pairs/{pair['id']}/change_port",
                                     {"frontend_port": 23456})
        assert status == 201, job
        assert job["type"] == "change_port"
        finished = _wait_job(client, job["id"])
        assert finished["status"] == "done"
        assert finished["output"]["status"] == "done"
        status, pair = client.request("GET", f"/api/pairs/{pair['id']}")
        assert pair["frontend_port"] == 23456
        status, _ = client.request("POST", "/api/pairs/9999/change_port",
                                   {"frontend_port": 23456})
        assert status == 404
        status, _ = client.request("POST", f"/api/pairs/{pair['id']}/change_port",
                                   {"frontend_port": 0})
        assert status == 400
    finally:
        server.shutdown()
        server.hub.worker.stop()
