"""Offline tests for the setup wizard's pair registration (hub/wizard.py).

No network, no real servers: everything runs against a temporary
hub database.
"""

from hub.store import Store
from hub.wizard import next_inner_pair, register_pair


def test_register_creates_servers_and_pair(tmp_path):
    db = str(tmp_path / "hub.db")
    pair = register_pair(db, "203.0.113.10", "203.0.113.20")
    assert pair["iran_server_id"] != pair["foreign_server_id"]
    assert pair["healer_server_id"] == pair["iran_server_id"]
    assert pair["frontend_port"] == 443
    assert pair["inner_iran"] == "10.10.11.1"
    assert pair["inner_foreign"] == "10.10.11.2"
    assert pair["candidate_scores"] == {}
    assert pair["current_protocol"] is None
    store = Store(db)
    servers = store.list_servers()
    assert len(servers) == 2
    assert all(s["key_path"] is None for s in servers)


def test_register_is_idempotent_by_pair_name(tmp_path):
    db = str(tmp_path / "hub.db")
    first = register_pair(db, "203.0.113.10", "203.0.113.20")
    second = register_pair(db, "203.0.113.10", "203.0.113.20")
    assert first["id"] == second["id"]
    store = Store(db)
    assert len(store.list_servers()) == 2
    assert len(store.list_pairs()) == 1


def test_second_pair_takes_next_inner_subnet(tmp_path):
    db = str(tmp_path / "hub.db")
    register_pair(db, "203.0.113.10", "203.0.113.20", pair_name="جفت یک")
    second = register_pair(db, "203.0.113.30", "203.0.113.40", pair_name="جفت دو")
    assert second["inner_iran"] == "10.10.12.1"
    assert second["inner_foreign"] == "10.10.12.2"


def test_measurement_update_records_only_measured(tmp_path):
    db = str(tmp_path / "hub.db")
    pair = register_pair(db, "203.0.113.10", "203.0.113.20")
    store = Store(db)
    store.update_pair_measurement(pair["id"], {"GRE": 99.9}, "GRE")
    updated = store.get_pair(pair["id"])
    assert updated["candidate_scores"] == {"GRE": 99.9}
    assert updated["current_protocol"] == "GRE"


def test_register_self_cli_is_idempotent_and_updates_host(tmp_path, capsys):
    import json
    from hub.wizard import main
    db = str(tmp_path / "hub.db")
    assert main(["--db", db, "--self-host", "203.0.113.10"]) == 0
    first = json.loads(capsys.readouterr().out.strip())
    assert main(["--db", db, "--self-host", "203.0.113.99"]) == 0
    second = json.loads(capsys.readouterr().out.strip())
    assert first["id"] == second["id"]
    assert second["host"] == "203.0.113.99"
    assert second["name"] == "ایران"
