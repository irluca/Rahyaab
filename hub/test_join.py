"""Offline tests for the node join flow (hub/join.py + full_setup job).

No network, no real servers: the store is temporary, the token /
pubkey / known_hosts files are temporary, and the full_setup handler
runs against a fake wizard_setup module.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from hub import join  # noqa: E402
from hub.jobs import _handle_full_setup  # noqa: E402
from hub.server import ApiError, Hub  # noqa: E402
from hub.store import Store  # noqa: E402
from hub.wizard import register_self  # noqa: E402

PUBKEY = "ssh-ed25519 AAAAJOINTEST rahyaab-hub"


@pytest.fixture
def files(tmp_path):
    token_file = tmp_path / "join.token"
    token_file.write_text("a" * 32 + "\n")
    pubkey_file = tmp_path / "hub_key.pub"
    pubkey_file.write_text(PUBKEY + "\n")
    known_hosts = tmp_path / "known_hosts"
    return {
        "token": str(token_file),
        "pubkey": str(pubkey_file),
        "known_hosts": str(known_hosts),
        "hub_key": str(tmp_path / "hub_key"),
    }


@pytest.fixture
def store_with_master(tmp_path):
    db = str(tmp_path / "hub.db")
    master = register_self(db, "203.0.113.10")
    return Store(db), master


def test_join_success_creates_server_pair_and_job(store_with_master, files):
    store, master = store_with_master
    body = {"token": "a" * 32, "host_key_type": "ssh-ed25519",
            "host_key_b64": "AAAANODEKEY"}
    result = join.join_node(store, body, "203.0.113.20",
                            token_file=files["token"],
                            pubkey_file=files["pubkey"],
                            known_hosts=files["known_hosts"],
                            hub_key=files["hub_key"])
    assert result["server"]["host"] == "203.0.113.20"
    assert result["server"]["name"] == "خارج"
    assert result["hub_pubkey"] == PUBKEY
    assert result["pair"]["iran_server_id"] == master["id"]
    assert result["pair"]["foreign_server_id"] == result["server"]["id"]
    assert result["pair"]["inner_iran"] == "10.10.11.1"
    assert result["pair"]["inner_foreign"] == "10.10.11.2"
    assert result["job"]["type"] == "full_setup"
    assert result["job"]["pair_id"] == result["pair"]["id"]
    assert result["job"]["input"]["iran_host"] == "203.0.113.10"
    assert result["job"]["input"]["foreign_host"] == "203.0.113.20"
    with open(files["known_hosts"]) as f:
        assert "203.0.113.20 ssh-ed25519 AAAANODEKEY" in f.read()
    assert not os.path.exists(files["token"])


def test_join_wrong_token_rejected_and_token_survives(store_with_master, files):
    store, _ = store_with_master
    body = {"token": "b" * 32, "host_key_type": "ssh-ed25519",
            "host_key_b64": "AAAANODEKEY"}
    with pytest.raises(join.JoinError) as exc:
        join.join_node(store, body, "203.0.113.20",
                       token_file=files["token"],
                       pubkey_file=files["pubkey"],
                       known_hosts=files["known_hosts"],
                       hub_key=files["hub_key"])
    assert exc.value.status == 403
    assert store.list_servers() != []
    assert len([s for s in store.list_servers() if s["name"] == "خارج"]) == 0
    assert os.path.exists(files["token"])


def test_join_without_master_record_refused(tmp_path, files):
    store = Store(str(tmp_path / "hub.db"))
    body = {"token": "a" * 32, "host_key_type": "ssh-ed25519",
            "host_key_b64": "AAAANODEKEY"}
    with pytest.raises(join.JoinError) as exc:
        join.join_node(store, body, "203.0.113.20",
                       token_file=files["token"],
                       pubkey_file=files["pubkey"],
                       known_hosts=files["known_hosts"],
                       hub_key=files["hub_key"])
    assert exc.value.status == 400


def test_rejoin_updates_host_and_replaces_stale_key(store_with_master, files):
    store, _ = store_with_master
    body = {"token": "a" * 32, "host_key_type": "ssh-ed25519",
            "host_key_b64": "AAAANODEKEY"}
    first = join.join_node(store, body, "203.0.113.20",
                           token_file=files["token"],
                           pubkey_file=files["pubkey"],
                           known_hosts=files["known_hosts"],
                           hub_key=files["hub_key"])
    # Same IP, new host key (node rebuilt keeping its address): the stale
    # line for that host must be replaced, not kept alongside the new one.
    with open(files["token"], "w") as f:
        f.write("c" * 32 + "\n")
    body2 = {"token": "c" * 32, "host_key_type": "ssh-ed25519",
             "host_key_b64": "AAAANEWKEY"}
    join.join_node(store, body2, "203.0.113.20",
                   token_file=files["token"],
                   pubkey_file=files["pubkey"],
                   known_hosts=files["known_hosts"],
                   hub_key=files["hub_key"])
    with open(files["known_hosts"]) as f:
        content = f.read()
    assert "AAAANODEKEY" not in content
    assert "203.0.113.20 ssh-ed25519 AAAANEWKEY" in content
    # New IP (node rebuilt with a new address): the server record moves,
    # and the new host key is pinned next to the old host's leftover line
    # (harmless: that address is simply no longer used).
    with open(files["token"], "w") as f:
        f.write("e" * 32 + "\n")
    body3 = {"token": "e" * 32, "host_key_type": "ssh-ed25519",
             "host_key_b64": "AAAATHIRDKEY"}
    second = join.join_node(store, body3, "203.0.113.99",
                            token_file=files["token"],
                            pubkey_file=files["pubkey"],
                            known_hosts=files["known_hosts"],
                            hub_key=files["hub_key"])
    assert second["server"]["id"] == first["server"]["id"]
    assert second["server"]["host"] == "203.0.113.99"
    assert len([s for s in store.list_servers() if s["name"] == "خارج"]) == 1
    with open(files["known_hosts"]) as f:
        content = f.read()
    assert "203.0.113.99 ssh-ed25519 AAAATHIRDKEY" in content


def test_join_with_existing_protocol_creates_no_job(store_with_master, files):
    store, _ = store_with_master
    body = {"token": "a" * 32, "host_key_type": "ssh-ed25519",
            "host_key_b64": "AAAANODEKEY"}
    result = join.join_node(store, body, "203.0.113.20",
                            token_file=files["token"],
                            pubkey_file=files["pubkey"],
                            known_hosts=files["known_hosts"],
                            hub_key=files["hub_key"])
    store.update_pair_measurement(result["pair"]["id"], {"GRE": 99.9}, "GRE")
    with open(files["token"], "w") as f:
        f.write("d" * 32 + "\n")
    body2 = {"token": "d" * 32, "host_key_type": "ssh-ed25519",
             "host_key_b64": "AAAANODEKEY2"}
    second = join.join_node(store, body2, "203.0.113.20",
                            token_file=files["token"],
                            pubkey_file=files["pubkey"],
                            known_hosts=files["known_hosts"],
                            hub_key=files["hub_key"])
    assert second["job"] is None


def test_generate_token_file_mode(tmp_path):
    path = str(tmp_path / "join.token")
    token = join.generate_token(path)
    assert len(token) == 32 and all(c in "0123456789abcdef" for c in token)
    assert (os.stat(path).st_mode & 0o777) == 0o600
    assert join.read_token(path) == token


def test_full_setup_handler_calls_wizard_chain(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "hub.db"))
    master = register_self(str(tmp_path / "hub.db"), "203.0.113.10")
    node = store.create_server({"name": "خارج", "host": "203.0.113.20",
                                "port": 22, "username": "root",
                                "key_path": None, "notes": ""})
    pair = store.create_pair({
        "name": "جفت اصلی", "iran_server_id": master["id"],
        "foreign_server_id": node["id"], "healer_server_id": master["id"],
        "frontend_port": 443, "current_protocol": None,
        "inner_iran": "10.10.11.1", "inner_foreign": "10.10.11.2",
        "candidate_scores": {}})
    job = store.create_job("full_setup", pair["id"], {
        "iran_host": "203.0.113.10", "foreign_host": "203.0.113.20",
        "pair_name": "جفت اصلی", "hub_key_path": "/etc/rahyaab/hub_key",
        "frontend_port": 443, "protocol": "GRE"})

    calls = {}

    class FakeWizard:
        @staticmethod
        def run_setup(iran, foreign, pid, name, db, key, frontend_port=443,
                      protocol="GRE"):
            calls.update({"iran": iran, "foreign": foreign, "pid": pid,
                          "db": db, "key": key, "protocol": protocol})
            return {"protocol": "GRE", "score": 99.9, "deploy_status": "ACTIVE",
                    "healer_active": "active", "healer_heartbeat": {}}

    monkeypatch.setitem(sys.modules, "wizard_setup", FakeWizard)
    result = _handle_full_setup(store, job, None)
    assert result["protocol"] == "GRE"
    assert calls["iran"] == "203.0.113.10"
    assert calls["foreign"] == "203.0.113.20"
    assert calls["pid"] == pair["id"]
    assert calls["key"] == "/etc/rahyaab/hub_key"


def test_hub_join_node_maps_token_error_to_403(store_with_master, files, monkeypatch):
    store, _ = store_with_master
    monkeypatch.setenv("RAHYAAB_JOIN_TOKEN_PATH", files["token"])
    monkeypatch.setenv("RAHYAAB_HUB_PUBKEY_PATH", files["pubkey"])
    monkeypatch.setenv("RAHYAAB_KNOWN_HOSTS_PATH", files["known_hosts"])
    hub = Hub(store)
    try:
        with pytest.raises(ApiError) as exc:
            hub.join_node({"token": "z" * 32, "host_key_type": "ssh-ed25519",
                           "host_key_b64": "AAAA"}, "203.0.113.20")
        assert exc.value.status == 403
    finally:
        hub.worker.stop()
