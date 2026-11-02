"""Desktop demo panel (ctunnel-local-style): the dashboard with
simulated tunnels, for previewing visual changes without touching a
live server.

Run: python3 -m hub.main --demo
Then open the printed local URL and log in with the printed demo
account. Every host here is a TEST-NET address, every pair is fake,
and nothing in this module ever opens an SSH connection: the demo
serves with the collector disabled, so no job reaches a real host.
"""

from __future__ import annotations

import time

from hub import auth

DEMO_USERNAME = "admin"
DEMO_PASSWORD = "demo-1234"

# TEST-NET only: the repo hygiene audit forbids routable IPs anywhere.
_FAKE = {
    "iran": "192.0.2.10",
    "tr": "198.51.100.20",
    "de": "203.0.113.30",
    "nl": "192.0.2.40",
}


def seed_demo_store(store) -> dict:
    """Fill an empty store with three demo pairs. Idempotent only on
    an empty store: callers must pass a fresh (temp) database."""
    if store.user_count() == 0:
        store.create_user(DEMO_USERNAME, auth.hash_password(DEMO_PASSWORD))
    iran = store.create_server({"name": "demo-iran", "host": _FAKE["iran"]})
    tr = store.create_server({"name": "demo-tr", "host": _FAKE["tr"]})
    de = store.create_server({"name": "demo-de", "host": _FAKE["de"]})
    nl = store.create_server({"name": "demo-nl", "host": _FAKE["nl"]})

    main_pair = store.create_pair({
        "name": "demo main pair", "iran_server_id": iran["id"],
        "foreign_server_id": tr["id"], "frontend_port": 21232,
        "current_protocol": "GRE",
        "inner_iran": "10.10.11.1", "inner_foreign": "10.10.11.2",
        "candidate_scores": {"GRE": 99.1, "ESP": 98.7, "backhaul-wss": 86.2,
                             "rathole-noise": 84.0, "xray-reverse": 82.5,
                             "frp-TLS": 80.1, "chisel-wss": 64.3}})
    store.update_pair_healer(main_pair["id"], {
        "healthy": True, "verdict": "HEALTHY",
        "updated_at": "2099-01-01T00:00:00+00:00"})
    for i in range(5):
        store.add_pair_metric(
            main_pair["id"],
            {"latency_ms": 41.0 + i * 0.4,
             "rx_bytes": 1000000 + i * 60000,
             "tx_bytes": 2000000 + i * 30000},
            created_at=1000000.0 + i * 60.0)

    overlay_pair = store.create_pair({
        "name": "demo overlay pair", "iran_server_id": iran["id"],
        "foreign_server_id": de["id"], "frontend_port": 45984,
        "current_protocol": "backhaul-wss",
        "inner_iran": "10.10.12.1", "inner_foreign": "10.10.12.2",
        "candidate_scores": {"kcptun": 87.5, "rathole-noise": 86.7,
                             "backhaul-wss": 82.8, "frp-TLS": 79.8}})
    store.update_pair_healer(overlay_pair["id"], {
        "healthy": True, "verdict": "AMBIGUOUS_DOWN",
        "updated_at": "2099-01-01T00:00:00+00:00"})
    # Overlays carry no carrier counters, so their live values stay
    # dashes exactly like a real overlay pair's.
    store.add_pair_metric(overlay_pair["id"], {"latency_ms": None},
                          created_at=1000000.0)

    down_pair = store.create_pair({
        "name": "demo down pair", "iran_server_id": iran["id"],
        "foreign_server_id": nl["id"], "frontend_port": 2083,
        "current_protocol": "GRE",
        "inner_iran": "10.10.13.1", "inner_foreign": "10.10.13.2",
        "candidate_scores": {}})
    store.update_pair_healer(down_pair["id"], {
        "healthy": False, "reachable": False, "verdict": "DOWN",
        "updated_at": "2099-01-01T00:00:00+00:00"})
    store.log_event("demo", "Demo data seeded: 3 pairs, no real servers")
    return {"servers": 4, "pairs": 3}
