"""Multi-master support: one node shared by two hubs must keep working.

A second hub's pair 1 used to deploy the exact same unit names, config
paths, interface names and inner addresses as the first hub's pair 1
onto the same node, so the second deploy either failed or broke the
first tunnel. Pairs now carry their hub's tag and inner base from the
wizard on: names get the tag, inners get the base, and the wizard's
pre-flight refuses a setup whose inners or names already exist instead
of breaking the tunnel that owns them.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import protocols
import wizard_setup


# --- naming and inners -------------------------------------------------------

def test_pair_token_defaults_reproduce_today():
    assert protocols.pair_token(1) == "p1"
    assert protocols.pair_token(1, "") == "p1"
    assert protocols.pair_token(1, "a1b2") == "p1-a1b2"
    assert protocols.pair_tag({}) == ""
    assert protocols.pair_tag({"hub_tag": "a1b2"}) == "a1b2"
    assert protocols.pair_base({}) == 10
    assert protocols.pair_base({"inner_base": 20}) == 20
    assert protocols.pair_base({"inner_base": "bogus"}) == 10


def test_carrier_names_and_inners_with_tag_and_base():
    assert protocols.carrier_iface("GRE", 1, "prod") == "grep1"
    assert protocols.carrier_iface("ESP", 77, "bench") == "espp77b"
    assert protocols.carrier_iface("GRE", 1, "prod", "a1b2") == "grep1a1b2"
    assert protocols.carrier_iface("ESP", 1, "bench", "a1b2") == "espp1a1b2b"
    assert protocols.carrier_inner_pair("GRE", 1, "prod") == ("10.10.11.1", "10.10.11.2")
    assert protocols.carrier_inner_pair("ESP", 3, "prod") == ("10.12.13.1", "10.12.13.2")
    assert protocols.carrier_inner_pair("GRE", 1, "bench") == ("10.11.61.1", "10.11.61.2")
    assert protocols.carrier_inner_pair("GRE", 1, "prod", 20) == ("10.20.11.1", "10.20.11.2")
    assert protocols.carrier_inner_pair("ESP", 1, "prod", 20) == ("10.22.11.1", "10.22.11.2")
    assert protocols.carrier_inner_pair("GRE", 1, "bench", 20) == ("10.21.61.1", "10.21.61.2")
    assert protocols.carrier_inner_pair("ESP", 1, "bench", 20) == ("10.23.61.1", "10.23.61.2")


def test_every_generator_scopes_names_with_tag():
    """Every generator's units and paths carry the pair token, never bare p1."""
    for name, gen in protocols.GENERATORS.items():
        # The gated v6 variant needs an address to plan at all;
        # documentation range, never a live address.
        v6kw = {"iran_v6": "2001:db8::1"} if name == "tcp-lanes-v6" else {}
        plan = gen(1, "192.0.2.10", "198.51.100.20", 45984,
                   namespace="prod", tag="a1b2", base=20, **v6kw)
        units = plan.get("iran_units", []) + plan.get("foreign_units", [])
        assert units, name
        for u in units:
            assert "p1-a1b2" in u, (name, u)
        for fdict in (plan.get("iran_files", {}), plan.get("foreign_files", {})):
            for path in fdict:
                if "p1" in path:
                    assert "p1-a1b2" in path, (name, path)


def test_default_generators_unchanged():
    plan = protocols.generate_backhaul_wss(1, "192.0.2.10", "198.51.100.20", 45984)
    assert "best-tunnel-prod-p1-backhaul-server" in plan["iran_units"]
    assert "/etc/best-tunnel/backhaul/prod-server-p1.toml" in plan["iran_files"]
    gre = protocols.generate_gre(1, "192.0.2.10", "198.51.100.20", 21232)
    assert "best-tunnel-prod-p1-gre" in gre["iran_units"]


# --- pre-flight ---------------------------------------------------------------

class _FakeRunner:
    def __init__(self, addr="", link="", units=""):
        self._out = {"addr show": addr, "link show": link, "list-units": units}

    def run(self, cmd, best_effort=False, **kwargs):
        for key, out in self._out.items():
            if key in cmd:
                return 0, out, ""
        return 0, "", ""

    def close(self):
        pass


_HUB_A_ADDR = "2: grep1    inet 10.10.11.2/30 scope global grep1\n"
_HUB_A_LINK = "2: grep1: <POINTOPOINT,MULTICAST> mtu 1400\n"
_HUB_A_UNITS = ("best-tunnel-prod-p1-backhaul-server.service loaded active running\n"
                "best-tunnel-prod-p1-backhaul-client.service loaded active running\n")


def test_preflight_passes_on_a_clean_node():
    pair = {"id": 1, "hub_tag": "a1b2", "inner_base": 20}
    wizard_setup.preflight_collision_check(pair, _FakeRunner(), _FakeRunner())


def test_preflight_refuses_inner_overlap():
    pair = {"id": 1, "hub_tag": "", "inner_base": 10}
    with pytest.raises(ValueError, match="already has address 10.10.11.2"):
        wizard_setup.preflight_collision_check(
            pair, _FakeRunner(addr=_HUB_A_ADDR), _FakeRunner())


def test_preflight_refuses_existing_carrier_interface():
    pair = {"id": 1, "hub_tag": "", "inner_base": 10}
    with pytest.raises(ValueError, match="already has carrier interface grep1"):
        wizard_setup.preflight_collision_check(
            pair, _FakeRunner(link=_HUB_A_LINK), _FakeRunner())


def test_preflight_refuses_existing_unit():
    pair = {"id": 1, "hub_tag": "", "inner_base": 10}
    with pytest.raises(ValueError, match="already has unit"):
        wizard_setup.preflight_collision_check(
            pair, _FakeRunner(units=_HUB_A_UNITS), _FakeRunner())


def test_preflight_passes_for_second_hub_on_first_hubs_node():
    """Hub B (tag a1b2, base 20) on hub A's pair-1 node: nothing collides."""
    pair = {"id": 1, "hub_tag": "a1b2", "inner_base": 20}
    node = _FakeRunner(addr=_HUB_A_ADDR, link=_HUB_A_LINK, units=_HUB_A_UNITS)
    wizard_setup.preflight_collision_check(pair, node, _FakeRunner())


def test_preflight_refuses_second_hub_with_same_base():
    pair = {"id": 1, "hub_tag": "a1b2", "inner_base": 20}
    with pytest.raises(ValueError, match="already has address 10.20.11.1"):
        wizard_setup.preflight_collision_check(
            pair, _FakeRunner(addr="2: grep1    inet 10.20.11.1/30 scope global grep1\n"),
            _FakeRunner())


def test_preflight_catches_pair_id_wrap():
    """Pair 201 wraps to pair 1's inners ((201 % 200) + 10 == 11)."""
    pair = {"id": 201, "hub_tag": "", "inner_base": 10}
    with pytest.raises(ValueError, match="already has address"):
        wizard_setup.preflight_collision_check(
            pair, _FakeRunner(addr=_HUB_A_ADDR), _FakeRunner())


# --- wizard threading ----------------------------------------------------------

def test_run_setup_threads_identity_to_deploy_ensure_install():
    seen = {}

    def measure_fn(pair, protocol):
        return {"score": 85.0, "base_rtt_ms": 80.0}

    def deploy_fn(pair, protocol):
        seen["pair"] = dict(pair)
        return {"status": "ACTIVE-%s" % protocol}

    def ensure_fn(pair_id, name, iran_host, foreign_host, frontend_port,
                  hub_tag="", inner_base=10):
        seen["ensure"] = (hub_tag, inner_base)

    def install_fn(*args, hub_tag="", inner_base=10, **kwargs):
        seen["install"] = (hub_tag, inner_base)
        return {"active": "active", "heartbeat": {}}

    out = wizard_setup.run_setup(
        "192.0.2.10", "198.51.100.20", 4, "pair", "/tmp/hub.db",
        "/etc/rahyaab/hub_key", frontend_port=45984, protocol="GRE",
        known_hosts_path="/nonexistent-known-hosts",
        pin_fn=lambda *a: None, measure_fn=measure_fn, deploy_fn=deploy_fn,
        install_fn=install_fn, record_fn=lambda *a: None,
        ensure_fn=ensure_fn, hub_tag="a1b2", inner_base=20,
        preflight=False)
    assert seen["pair"]["hub_tag"] == "a1b2"
    assert seen["pair"]["inner_base"] == 20
    assert seen["ensure"] == ("a1b2", 20)
    assert seen["install"] == ("a1b2", 20)
    assert out["hub_tag"] == "a1b2"
    assert out["inner_base"] == 20


# --- storage -------------------------------------------------------------------

def test_ensure_pair_row_stores_identity(monkeypatch, tmp_path):
    import storage
    db = str(tmp_path / "engine.db")
    monkeypatch.setattr(storage, "DB_PATH", db)
    storage.init_db()
    assert storage.ensure_pair_row(7, "pair", "192.0.2.10", "198.51.100.20",
                                   45984, hub_tag="a1b2", inner_base=20)
    row = storage.get_pair(7)
    assert row["hub_tag"] == "a1b2"
    assert row["inner_base"] == 20
    assert storage.ensure_pair_row(8, "pair2", "192.0.2.10", "198.51.100.20", 45984)
    row2 = storage.get_pair(8)
    assert row2["hub_tag"] == ""
    assert row2["inner_base"] == 10


def test_migration_adds_columns_to_old_db(monkeypatch, tmp_path):
    """A database migrated to 14, re-opened after the upgrade, gains v15."""
    import sqlite3
    import storage
    db = str(tmp_path / "old.db")
    monkeypatch.setattr(storage, "DB_PATH", db)
    storage.init_db()
    conn = sqlite3.connect(db)
    conn.execute("ALTER TABLE pairs DROP COLUMN hub_tag")
    conn.execute("ALTER TABLE pairs DROP COLUMN inner_base")
    conn.execute("DELETE FROM schema_version WHERE version = 15")
    conn.commit()
    conn.close()
    storage.init_db()
    conn = sqlite3.connect(db)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(pairs)")}
    assert "hub_tag" in cols and "inner_base" in cols
    assert storage.ensure_pair_row(1, "p", "192.0.2.10", "198.51.100.20", 443)
    assert storage.get_pair(1)["inner_base"] == 10
    conn.close()
