"""Desktop demo panel: seeded fake data, nothing real.

Every demo host must be a TEST-NET address (the repo hygiene audit
forbids routable IPs), the demo login must work, and the seeded pairs
must render the three card states: healthy carrier, healthy overlay
with dash live values, and down.
"""

import http.client
import ipaddress
import json
import threading

import pytest

from hub import demo
from hub.server import serve
from hub.ssh import FakeExecutor
from hub.store import Store

TEST_NETS = [ipaddress.ip_network("192.0.2.0/24"),
             ipaddress.ip_network("198.51.100.0/24"),
             ipaddress.ip_network("203.0.113.0/24")]


def test_demo_seed_is_fake_only_and_renders(tmp_path):
    store = Store(str(tmp_path / "hub.db"))
    seeded = demo.seed_demo_store(store)
    assert seeded == {"servers": 4, "pairs": 3}
    for server in store.list_servers():
        ip = ipaddress.ip_address(server["host"])
        assert any(ip in net for net in TEST_NETS), server["host"]
    pairs = store.list_pairs()
    assert len(pairs) == 3
    main = next(p for p in pairs if p["current_protocol"] == "GRE"
                and p["candidate_scores"])
    assert main["candidate_scores"]["GRE"] == 99.1
    totals = store.get_pair_traffic_total(main["id"])
    assert totals["rx_total"] == 240000 and totals["tx_total"] == 120000
    overlay = next(p for p in pairs if p["current_protocol"] == "backhaul-wss")
    assert store.get_pair_traffic_total(overlay["id"]) == {
        "rx_total": 0, "tx_total": 0}
    down = next(p for p in pairs if not p["candidate_scores"])
    assert down["healer_last_status"]["reachable"] is False


def test_demo_panel_serves_and_logs_in(tmp_path):
    store = Store(str(tmp_path / "hub.db"))
    demo.seed_demo_store(store)
    server = serve(store, host="127.0.0.1", port=0,
                   make_executor=lambda s: FakeExecutor({}))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1",
                                          server.server_address[1], timeout=10)
        conn.request("GET", "/")
        resp = conn.getresponse()
        assert resp.status == 200 and "رهیاب".encode() in resp.read()
        conn.close()
        conn = http.client.HTTPConnection("127.0.0.1",
                                          server.server_address[1], timeout=10)
        conn.request("POST", "/api/login",
                     body=json.dumps({"username": demo.DEMO_USERNAME,
                                      "password": demo.DEMO_PASSWORD}),
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        assert resp.status == 200
        cookie = resp.getheader("Set-Cookie").split(";")[0]
        resp.read()
        conn.close()
        conn = http.client.HTTPConnection("127.0.0.1",
                                          server.server_address[1], timeout=10)
        conn.request("GET", "/api/pairs", headers={"Cookie": cookie})
        resp = conn.getresponse()
        body = json.loads(resp.read())
        assert len(body["pairs"]) == 3
        conn.close()
    finally:
        server.shutdown()
        server.hub.worker.stop()
