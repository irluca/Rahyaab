"""Multi-master hub identity: settings, hub-record inners, job inputs.

A second hub must not reuse the first hub's inner /16 or arrive at the
wizard without its tag and base: the wizard's names and inners derive
from exactly those two values.
"""

import os
import sys

import pytest  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hub.jobs import _handle_full_setup  # noqa: E402
from hub.store import Store  # noqa: E402
from hub.wizard import next_inner_pair, register_self  # noqa: E402


def test_hub_identity_defaults_to_legacy(tmp_path):
    store = Store(str(tmp_path / "hub.db"))
    assert store.get_hub_identity() == {"hub_tag": "", "inner_base": 10}


def test_hub_identity_from_settings(tmp_path):
    store = Store(str(tmp_path / "hub.db"))
    store.set_setting("hub_tag", "a1b2")
    store.set_setting("inner_base", "20")
    assert store.get_hub_identity() == {"hub_tag": "a1b2", "inner_base": 20}
    store.set_setting("inner_base", "bogus")
    assert store.get_hub_identity()["inner_base"] == 10


def test_next_inner_pair_uses_base(tmp_path):
    store = Store(str(tmp_path / "hub.db"))
    master = register_self(str(tmp_path / "hub.db"), "203.0.113.10")
    node = store.create_server({"name": "n", "host": "203.0.113.20",
                                "port": 22, "username": "root",
                                "key_path": None, "notes": ""})
    for inner in ("10.10.11.1", "10.20.11.1"):
        store.create_pair({
            "name": "p-%s" % inner, "iran_server_id": master["id"],
            "foreign_server_id": node["id"], "healer_server_id": master["id"],
            "frontend_port": 443, "current_protocol": None,
            "inner_iran": inner, "inner_foreign": inner[:-1] + "2",
            "candidate_scores": {}})
    assert next_inner_pair(store) == ("10.10.12.1", "10.10.12.2")
    assert next_inner_pair(store, 20) == ("10.20.12.1", "10.20.12.2")


def test_full_setup_handler_passes_identity_to_wizard(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "hub.db"))
    master = register_self(str(tmp_path / "hub.db"), "203.0.113.10")
    node = store.create_server({"name": "n", "host": "203.0.113.20",
                                "port": 22, "username": "root",
                                "key_path": None, "notes": ""})
    pair = store.create_pair({
        "name": "p", "iran_server_id": master["id"],
        "foreign_server_id": node["id"], "healer_server_id": master["id"],
        "frontend_port": 443, "current_protocol": None,
        "inner_iran": "10.20.11.1", "inner_foreign": "10.20.11.2",
        "candidate_scores": {}})
    job = store.create_job("full_setup", pair["id"], {
        "iran_host": "203.0.113.10", "foreign_host": "203.0.113.20",
        "pair_name": "p", "hub_key_path": "/etc/rahyaab/hub_key",
        "frontend_port": 443, "protocol": "GRE",
        "hub_tag": "a1b2", "inner_base": 20})

    calls = {}

    class FakeWizard:
        @staticmethod
        def run_setup(iran, foreign, pid, name, db, key, frontend_port=443,
                      protocol="GRE", hub_tag="", inner_base=10):
            calls.update({"hub_tag": hub_tag, "inner_base": inner_base})
            return {"protocol": "GRE", "score": 99.0, "deploy_status": "ACTIVE",
                    "healer_active": "active", "healer_heartbeat": {}}

    monkeypatch.setitem(sys.modules, "wizard_setup", FakeWizard)
    _handle_full_setup(store, job, None)
    assert calls == {"hub_tag": "a1b2", "inner_base": 20}


def test_full_setup_handler_defaults_for_old_jobs(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "hub.db"))
    master = register_self(str(tmp_path / "hub.db"), "203.0.113.10")
    node = store.create_server({"name": "n", "host": "203.0.113.20",
                                "port": 22, "username": "root",
                                "key_path": None, "notes": ""})
    pair = store.create_pair({
        "name": "p", "iran_server_id": master["id"],
        "foreign_server_id": node["id"], "healer_server_id": master["id"],
        "frontend_port": 443, "current_protocol": None,
        "inner_iran": "10.10.11.1", "inner_foreign": "10.10.11.2",
        "candidate_scores": {}})
    job = store.create_job("full_setup", pair["id"], {
        "iran_host": "203.0.113.10", "foreign_host": "203.0.113.20",
        "pair_name": "p", "hub_key_path": "/etc/rahyaab/hub_key",
        "frontend_port": 443, "protocol": "GRE"})

    calls = {}

    class FakeWizard:
        @staticmethod
        def run_setup(iran, foreign, pid, name, db, key, frontend_port=443,
                      protocol="GRE", hub_tag="", inner_base=10):
            calls.update({"hub_tag": hub_tag, "inner_base": inner_base})
            return {"protocol": "GRE", "score": 99.0, "deploy_status": "ACTIVE",
                    "healer_active": "active", "healer_heartbeat": {}}

    monkeypatch.setitem(sys.modules, "wizard_setup", FakeWizard)
    _handle_full_setup(store, job, None)
    assert calls == {"hub_tag": "", "inner_base": 10}
