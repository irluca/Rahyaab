"""Offline tests for the wizard's measure/deploy/install chain.

All live steps are injected fakes; no network, no real servers. The
point is the wiring and the honesty guards: pinned keys seeded from
verified known_hosts, a non-positive score refusing the setup, and
the measured score flowing unchanged into the healer install and the
hub record.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import wizard_setup  # noqa: E402


def test_parse_known_hosts(tmp_path):
    kh = tmp_path / "known_hosts"
    kh.write_text(
        "203.0.113.10 ssh-ed25519 AAAABASE64A\n"
        "[203.0.113.20]:2222 ssh-ed25519 AAAABASE64B\n"
        "hosta,hostb ssh-rsa AAAABASE64C\n"
        "|1|HASHEDLINE ssh-ed25519 AAAABASE64D\n"
        "# a comment\n")
    pins = wizard_setup.parse_known_hosts(str(kh))
    assert pins[("203.0.113.10", 22)] == ("ssh-ed25519", "AAAABASE64A")
    assert pins[("203.0.113.20", 2222)] == ("ssh-ed25519", "AAAABASE64B")
    assert pins[("hosta", 22)] == ("ssh-rsa", "AAAABASE64C")
    assert pins[("hostb", 22)] == ("ssh-rsa", "AAAABASE64C")
    assert len(pins) == 4


def test_seed_host_pins_only_known_hosts(tmp_path):
    kh = tmp_path / "known_hosts"
    kh.write_text("203.0.113.10 ssh-ed25519 AAAABASE64A\n")
    calls = []
    seeded = wizard_setup.seed_host_pins(
        str(kh), [("203.0.113.10", 22), ("203.0.113.99", 22)],
        pin_fn=lambda h, p, t, b: calls.append((h, p, t, b)))
    assert seeded == [("203.0.113.10", 22)]
    assert calls == [("203.0.113.10", 22, "ssh-ed25519", "AAAABASE64A")]


def test_pair_spec_uses_key_auth():
    pair = wizard_setup.pair_spec("203.0.113.10", "203.0.113.20",
                                  "/etc/rahyaab/hub_key", 7, 443)
    assert pair["iran"]["auth"] == {"type": "key", "value": "/etc/rahyaab/hub_key"}
    assert pair["foreign"]["auth"] == {"type": "key", "value": "/etc/rahyaab/hub_key"}
    assert pair["frontend"] == 443


def _fakes():
    calls = {}

    def measure_fn(pair, protocol):
        calls["measure"] = (pair, protocol)
        return {"score": 99.9, "base_rtt_ms": 37.5, "disqualified": False}

    def deploy_fn(pair, protocol):
        calls["deploy"] = (pair, protocol)
        return {"status": "ACTIVE-GRE-443"}

    def install_fn(iran, foreign, pid, name, port, protocol, scores, key):
        calls["install"] = (iran, foreign, pid, name, port, protocol, scores, key)
        return {"active": "active", "heartbeat": {"verdicts": {"1": "HEALTHY"}}}

    def record_fn(db, pid, scores, protocol):
        calls["record"] = (db, pid, scores, protocol)

    return calls, measure_fn, deploy_fn, install_fn, record_fn


def test_run_setup_wiring(tmp_path):
    kh = tmp_path / "known_hosts"
    kh.write_text("203.0.113.10 ssh-ed25519 AAAA1\n203.0.113.20 ssh-ed25519 AAAA2\n")
    calls, measure_fn, deploy_fn, install_fn, record_fn = _fakes()
    summary = wizard_setup.run_setup(
        "203.0.113.10", "203.0.113.20", pair_id=1, pair_name="wizard-pair",
        hub_db_path=str(tmp_path / "hub.db"), hub_key_path="/etc/rahyaab/hub_key",
        known_hosts_path=str(kh), pin_fn=lambda h, p, t, b: None,
        measure_fn=measure_fn, deploy_fn=deploy_fn, install_fn=install_fn,
        record_fn=record_fn)
    assert summary["protocol"] == "GRE"
    assert summary["score"] == 99.9
    assert summary["deploy_status"] == "ACTIVE-GRE-443"
    assert summary["healer_active"] == "active"
    assert summary["seeded_host_pins"] == [("203.0.113.10", 22), ("203.0.113.20", 22)]
    assert calls["install"][6] == {"GRE": 99.9}
    assert calls["record"][2] == {"GRE": 99.9}
    assert calls["measure"][0]["iran"]["auth"]["type"] == "key"


def test_run_setup_refuses_non_positive_score(tmp_path):
    kh = tmp_path / "known_hosts"
    kh.write_text("")
    calls, measure_fn, deploy_fn, install_fn, record_fn = _fakes()

    def bad_measure(pair, protocol):
        return {"score": 0.0, "base_rtt_ms": 0.0}

    with pytest.raises(RuntimeError):
        wizard_setup.run_setup(
            "203.0.113.10", "203.0.113.20", pair_id=1, pair_name="wizard-pair",
            hub_db_path=str(tmp_path / "hub.db"), hub_key_path="/etc/rahyaab/hub_key",
            known_hosts_path=str(kh), pin_fn=lambda h, p, t, b: None,
            measure_fn=bad_measure, deploy_fn=deploy_fn, install_fn=install_fn,
            record_fn=record_fn)
    assert "deploy" not in calls
    assert "install" not in calls
    assert "record" not in calls
