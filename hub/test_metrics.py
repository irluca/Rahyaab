"""Offline tests for real metrics collection (Phase 3.5)."""

import time

from hub import metrics
from hub.server import Collector
from hub.ssh import FakeExecutor
from hub.store import Store


def test_parse_server_metrics_and_ping():
    out = "LOAD 0.42\nMEM 61.3\nDISK 23%\nUP 123456.7\n"
    data = metrics.parse_server_metrics(out)
    assert data == {"load1": 0.42, "mem_used_pct": 61.3,
                    "disk_used_pct": 23.0, "uptime_seconds": 123456.7}
    assert metrics.parse_ping_avg(
        "rtt min/avg/max/mdev = 36.1/37.4/38.2/0.5 ms") == 37.4
    assert metrics.parse_ping_avg("no reply") is None


def test_pair_throughput_rate_from_counter_delta(tmp_path):
    store = Store(tmp_path / "hub.db")
    server = store.create_server({"name": "iran", "host": "10.0.0.1"})
    foreign = store.create_server({"name": "foreign", "host": "10.0.0.2"})
    pair = store.create_pair({"name": "p1", "iran_server_id": server["id"],
                              "foreign_server_id": foreign["id"]})
    store.add_pair_metric(pair["id"], {"latency_ms": 37.0,
                                       "rx_bytes": 1000000, "tx_bytes": 2000000},
                          created_at=1000000.0)
    store.add_pair_metric(pair["id"], {"latency_ms": 37.5,
                                       "rx_bytes": 1060000, "tx_bytes": 2030000},
                          created_at=1000060.0)
    points = store.list_pair_metrics(pair["id"])
    assert points[-1]["rx_kbps"] == 8.0
    assert points[-1]["tx_kbps"] == 4.0


def test_collector_writes_real_points(tmp_path):
    store = Store(tmp_path / "hub.db")
    iran = store.create_server({"name": "iran", "host": "10.0.0.1"})
    foreign = store.create_server({"name": "foreign", "host": "10.0.0.2"})
    pair = store.create_pair({"name": "p1", "iran_server_id": iran["id"],
                              "foreign_server_id": foreign["id"],
                              "current_protocol": "GRE",
                              "inner_iran": "10.10.11.1",
                              "inner_foreign": "10.10.11.2"})
    fake = FakeExecutor({
        "echo LOAD": (0, "LOAD 0.42\nMEM 61.3\nDISK 23%\nUP 123456.7\n", ""),
        "ping -c 2": (0, "rtt min/avg/max/mdev = 36.1/37.4/38.2/0.5 ms\n", ""),
        "cat /sys/class/net": (0, "123456\n789012\n", ""),
    })
    Collector(store, make_executor=lambda s: fake).collect_once()
    assert len(store.list_server_metrics(iran["id"])) == 1
    assert len(store.list_server_metrics(foreign["id"])) == 1
    points = store.list_pair_metrics(pair["id"])
    assert len(points) == 1
    assert points[0]["latency_ms"] == 37.4
    assert points[0]["rx_bytes"] == 123456
    assert points[0]["tx_bytes"] == 789012
