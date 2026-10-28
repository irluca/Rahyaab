"""Tests for the protocol-comparison endpoint (hub/benchmarks.py + route).

Builds a small fake healer database with the live schema and checks the
hub serves the newest row per protocol, with factors, behind login.
"""

import http.client
import json
import sqlite3
import threading

import pytest

from hub import benchmarks
from hub.server import serve
from hub.ssh import FakeExecutor
from hub.store import Store


def _healer_db(path):
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE pairs (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)""")
    conn.execute("""CREATE TABLE benchmarks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, pair_id INTEGER NOT NULL,
        protocol TEXT NOT NULL, latency_ms REAL DEFAULT 0.0,
        jitter_ms REAL DEFAULT 0.0, bulk_step INTEGER DEFAULT 0,
        loss_pct REAL DEFAULT 0.0, score REAL DEFAULT 0.0,
        disqualified INTEGER DEFAULT 0, details_json TEXT DEFAULT '{}',
        created_at REAL NOT NULL, throughput_mbps REAL,
        run_id TEXT, throughput_up_mbps REAL, throughput_down_mbps REAL,
        capacity_basis TEXT)""")
    conn.execute("INSERT INTO pairs (id, name) VALUES (1, 'manag-netlen')")
    conn.commit()
    return conn


def _row(conn, proto, score, lat, jit, loss, up, down, dq=0, details=None,
         created=1700000000.0, run="run-1"):
    conn.execute(
        """INSERT INTO benchmarks (pair_id, protocol, latency_ms, jitter_ms,
            loss_pct, score, disqualified, details_json, created_at,
            throughput_mbps, run_id, throughput_up_mbps, throughput_down_mbps,
            capacity_basis) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'measured')""",
        (proto, lat, jit, loss, score, dq, json.dumps(details or {}), created,
         (up + down) / 2.0 if up is not None and down is not None else None,
         run, up, down))
    conn.commit()


def test_newest_row_per_protocol_wins(tmp_path):
    db = tmp_path / "healer.db"
    conn = _healer_db(db)
    _row(conn, "GRE", 90.0, 40.0, 2.0, 0.0, 80.0, 70.0, created=1700000000.0)
    _row(conn, "GRE", 99.96, 37.4, 1.1, 0.0, 94.0, 91.0, created=1700001000.0,
         details={"breakdown": {"seconds_survived": 30.0, "base_rtt": 37.4}})
    _row(conn, "ESP", 99.84, 38.1, 1.4, 0.5, 88.0, 85.0, created=1700001000.0)
    conn.close()
    rows = benchmarks.latest_benchmarks("manag-netlen", str(db))
    assert [r["protocol"] for r in rows] == ["GRE", "ESP"]
    gre = rows[0]
    assert gre["score"] == 99.96 and gre["latency_ms"] == 37.4
    assert gre["throughput_up_mbps"] == 94.0
    assert gre["seconds_survived"] == 30.0


def test_disqualified_row_kept_with_reasons(tmp_path):
    db = tmp_path / "healer.db"
    conn = _healer_db(db)
    _row(conn, "singbox-ss-2022", 0.0, 0.0, 0.0, 100.0, None, None, dq=1,
         details={"dq_reasons": ["Excessive sustained packet loss"]})
    conn.close()
    rows = benchmarks.latest_benchmarks("manag-netlen", str(db))
    assert len(rows) == 1 and rows[0]["disqualified"] is True
    assert rows[0]["dq_reasons"] == ["Excessive sustained packet loss"]


def test_missing_db_and_unknown_pair_are_empty(tmp_path):
    assert benchmarks.latest_benchmarks("manag-netlen", str(tmp_path / "no.db")) == []
    db = tmp_path / "healer.db"
    _healer_db(db).close()
    assert benchmarks.latest_benchmarks("other-pair", str(db)) == []


def test_corrupt_details_json_does_not_break_row(tmp_path):
    db = tmp_path / "healer.db"
    conn = _healer_db(db)
    conn.execute(
        "INSERT INTO benchmarks (pair_id, protocol, latency_ms, score,"
        " details_json, created_at) VALUES (1, 'GRE', 37.4, 99.96, '{bad', 1)")
    conn.commit()
    conn.close()
    rows = benchmarks.latest_benchmarks("manag-netlen", str(db))
    assert len(rows) == 1 and rows[0]["dq_reasons"] == []


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
def api(tmp_path, monkeypatch):
    store = Store(tmp_path / "hub.db")
    server = serve(store, host="127.0.0.1", port=0,
                   make_executor=lambda s: FakeExecutor({}))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = Client(server.server_address[1])
    status, _ = client.request("POST", "/api/setup",
                               {"username": "admin", "password": "change-me-123"})
    assert status == 201
    status, _ = client.request("POST", "/api/login",
                               {"username": "admin", "password": "change-me-123"})
    assert status == 200 and client.cookie
    _, iran = client.request("POST", "/api/servers",
                             {"name": "iran", "host": "203.0.113.10"})
    _, foreign = client.request("POST", "/api/servers",
                                {"name": "foreign", "host": "203.0.113.20"})
    status, pair = client.request("POST", "/api/pairs",
                                  {"name": "manag-netlen",
                                   "iran_server_id": iran["id"],
                                   "foreign_server_id": foreign["id"],
                                   "current_protocol": "GRE"})
    assert status == 201, pair
    db = tmp_path / "healer.db"
    conn = _healer_db(db)
    _row(conn, "GRE", 99.96, 37.4, 1.1, 0.0, 94.0, 91.0,
         details={"breakdown": {"seconds_survived": 30.0}})
    conn.close()
    monkeypatch.setenv("RAHYAAB_HEALER_DB", str(db))
    yield client, pair["id"]
    server.shutdown()
    server.hub.worker.stop()


def test_benchmarks_route_serves_factors_behind_login(api):
    client, pair_id = api
    anon = Client(client.port)
    status, _ = anon.request("GET", f"/api/pairs/{pair_id}/benchmarks")
    assert status == 401
    status, body = client.request("GET", f"/api/pairs/{pair_id}/benchmarks")
    assert status == 200, body
    assert body["benchmarks"][0]["protocol"] == "GRE"
    assert body["benchmarks"][0]["latency_ms"] == 37.4
    status, _ = client.request("GET", "/api/pairs/9999/benchmarks")
    assert status == 404


def test_benchmarks_route_prefers_per_pair_db(api, tmp_path, monkeypatch):
    client, pair_id = api
    db = tmp_path / "healer-p.db"
    conn = _healer_db(db)
    _row(conn, "ESP", 88.0, 38.0, 1.5, 0.0, 80.0, 78.0,
         details={"breakdown": {"seconds_survived": 30.0}})
    conn.close()
    monkeypatch.setattr(benchmarks, "healer_db_path_for_pair",
                        lambda pid: str(db))
    status, body = client.request("GET", f"/api/pairs/{pair_id}/benchmarks")
    assert status == 200, body
    assert body["benchmarks"][0]["protocol"] == "ESP"
