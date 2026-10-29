"""Tests for the join-time tunnel port: requested port, random pick,
and the master's socket-table check (hub/join.py).

No network, no real servers: the store is temporary, the token /
pubkey / known_hosts files are temporary, and the socket check is a
fake callable — the real `ss` read is never run here.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from hub import join  # noqa: E402
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


def _join(store, files, ip, port="omit", checker=lambda p: True):
    body = {"token": "a" * 32, "host_key_type": "ssh-ed25519",
            "host_key_b64": "AAAANODEKEY"}
    if port != "omit":
        body["frontend_port"] = port
    return join.join_node(store, body, ip,
                          token_file=files["token"],
                          pubkey_file=files["pubkey"],
                          known_hosts=files["known_hosts"],
                          hub_key=files["hub_key"],
                          free_checker=checker)


def _retoken(files):
    with open(files["token"], "w") as f:
        f.write("a" * 32 + "\n")


def test_requested_port_accepted_and_flows_to_setup_job(store_with_master, files):
    store, _ = store_with_master
    result = _join(store, files, "203.0.113.20", port=23456)
    assert result["pair"]["frontend_port"] == 23456
    assert result["job"]["input"]["frontend_port"] == 23456


@pytest.mark.parametrize("bad", [0, 70000, -1, "abc", 22, 53, 68, 123, 8890])
def test_requested_port_rejected(store_with_master, files, bad):
    store, _ = store_with_master
    with pytest.raises(join.JoinError) as exc:
        _join(store, files, "203.0.113.20", port=bad)
    assert exc.value.status == 400


def test_requested_port_used_by_another_pair_rejected(store_with_master, files):
    store, _ = store_with_master
    _join(store, files, "203.0.113.20", port=23456)
    _retoken(files)
    with pytest.raises(join.JoinError) as exc:
        _join(store, files, "203.0.113.30", port=23456)
    assert exc.value.status == 400


def test_requested_port_bound_on_master_rejected(store_with_master, files):
    store, _ = store_with_master
    with pytest.raises(join.JoinError) as exc:
        _join(store, files, "203.0.113.20", port=23456,
              checker=lambda p: False)
    assert exc.value.status == 400


def test_requested_port_unknown_verdict_accepted(store_with_master, files):
    store, _ = store_with_master
    result = _join(store, files, "203.0.113.20", port=23456,
                   checker=lambda p: None)
    assert result["pair"]["frontend_port"] == 23456


def test_omitted_port_is_random_five_digit(store_with_master, files):
    store, _ = store_with_master
    # Only the first eleven ports of the range read as bound, so the
    # pick re-rolls past them instead of failing.
    blocked = set(range(10000, 10011))
    result = _join(store, files, "203.0.113.20",
                   checker=lambda p: p not in blocked)
    port = result["pair"]["frontend_port"]
    assert 10000 <= port <= 60000
    assert port not in join.RESERVED_FRONTEND_PORTS
    assert port not in blocked


def test_rejoin_never_changes_existing_port(store_with_master, files):
    store, _ = store_with_master
    first = _join(store, files, "203.0.113.20", port=23456)
    _retoken(files)
    second = _join(store, files, "203.0.113.20", port=34567)
    assert second["pair"]["id"] == first["pair"]["id"]
    assert second["pair"]["frontend_port"] == 23456
    assert store.get_pair(first["pair"]["id"])["frontend_port"] == 23456


def test_pick_exhaustion_raises(store_with_master):
    store, master = store_with_master
    with pytest.raises(join.JoinError) as exc:
        join.pick_frontend_port(store, master["id"],
                                free_checker=lambda p: False)
    assert exc.value.status == 500


def test_validate_frontend_port_honours_ssh_port():
    assert join.validate_frontend_port(23456, ssh_port=22) == 23456
    with pytest.raises(join.JoinError):
        join.validate_frontend_port(2222, ssh_port=2222)
    assert join.validate_frontend_port(2222, ssh_port=22) == 2222
