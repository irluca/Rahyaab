"""Cumulative traffic totals per pair (C-Tunnel-style durable totals).

Interface counters restart at zero whenever the carrier interface is
recreated, so the totals must fold each sample's delta and never go
backwards: a reset adds the new counter on top of the total folded so
far, and bytes counted before we started watching are not claimed.
"""

from hub import metrics
from hub.store import Store


def _pair(store):
    iran = store.create_server({"name": "iran", "host": "10.0.0.1"})
    foreign = store.create_server({"name": "foreign", "host": "10.0.0.2"})
    return store.create_pair({"name": "p", "iran_server_id": iran["id"],
                              "foreign_server_id": foreign["id"]})


def test_fresh_pair_totals_are_zero(tmp_path):
    store = Store(str(tmp_path / "hub.db"))
    pair = _pair(store)
    assert store.get_pair_traffic_total(pair["id"]) == {"rx_total": 0, "tx_total": 0}


def test_totals_accumulate_forward_deltas(tmp_path):
    store = Store(str(tmp_path / "hub.db"))
    pair = _pair(store)
    store.add_pair_metric(pair["id"], {"rx_bytes": 1000000, "tx_bytes": 2000000},
                          created_at=1000000.0)
    # The first sample only anchors: pre-existing bytes are not claimed.
    assert store.get_pair_traffic_total(pair["id"]) == {"rx_total": 0, "tx_total": 0}
    store.add_pair_metric(pair["id"], {"rx_bytes": 1060000, "tx_bytes": 2030000},
                          created_at=1000060.0)
    assert store.get_pair_traffic_total(pair["id"]) == {"rx_total": 60000,
                                                         "tx_total": 30000}


def test_counter_reset_folds_instead_of_wiping(tmp_path):
    store = Store(str(tmp_path / "hub.db"))
    pair = _pair(store)
    store.add_pair_metric(pair["id"], {"rx_bytes": 1000000, "tx_bytes": 2000000},
                          created_at=1000000.0)
    store.add_pair_metric(pair["id"], {"rx_bytes": 1500000, "tx_bytes": 2500000},
                          created_at=1000060.0)
    # Interface recreated: counters restart small. The folded total
    # keeps the 500000 already counted and adds the new 80000 on top.
    store.add_pair_metric(pair["id"], {"rx_bytes": 80000, "tx_bytes": 90000},
                          created_at=1000120.0)
    assert store.get_pair_traffic_total(pair["id"]) == {"rx_total": 580000,
                                                         "tx_total": 590000}


def test_samples_without_counters_leave_totals_alone(tmp_path):
    store = Store(str(tmp_path / "hub.db"))
    pair = _pair(store)
    store.add_pair_metric(pair["id"], {"latency_ms": 37.0},
                          created_at=1000000.0)
    assert store.get_pair_traffic_total(pair["id"]) == {"rx_total": 0, "tx_total": 0}


def test_carrier_iface_is_pair_aware():
    assert metrics.carrier_iface("GRE", 3) == "grep3"
    assert metrics.carrier_iface("ESP", 4) == "espp4"
    assert metrics.carrier_iface("backhaul-wss", 1) is None
    assert metrics.carrier_iface("", 1) is None
