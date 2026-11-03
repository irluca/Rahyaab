"""Tests for the underlay-switch helpers in orchestrator/failover.py.

Pure computation, no SSH, no live hosts: the DNAT command filter, the
manifest row filter, the manifest path lookup, and the underlay
resolution that decides which switch shape a pair takes.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import failover
import protocols
from safety import generate_firewall_comment


def test_underlay_protocol_resolution():
    assert failover._underlay_protocol({"underlay_carrier": "gre"}, "frp-TLS") == "GRE"
    assert failover._underlay_protocol({"underlay_carrier": "esp"}, "xray-reverse") == "ESP"
    # A current carrier is its own underlay even with no declaration.
    assert failover._underlay_protocol({}, "GRE") == "GRE"
    assert failover._underlay_protocol({}, "ESP") == "ESP"
    # An overlay with no declaration names nothing: guessing 'gre'
    # would tear down a carrier the pair may not have.
    assert failover._underlay_protocol({}, "frp-TLS") is None
    assert failover._underlay_protocol({"underlay_carrier": ""}, "frp-TLS") is None


def test_carrier_dnat_cmds_gre_and_esp():
    for proto in ("GRE", "ESP"):
        plan = protocols.generate_deployment(proto, 1, "198.51.100.10", "203.0.113.20", 443)
        adds = failover._carrier_dnat_cmds(plan["iran_cmds"])
        dels = failover._carrier_dnat_cmds(plan["teardown_iran"])
        assert len(adds) == 2, (proto, adds)
        assert len(dels) == 2, (proto, dels)
        assert all("PREROUTING" in c and "DNAT" in c for c in adds + dels)
        # Each delete is its add with -A swapped for -D plus the
        # teardown suffix: the cutover and the peel must move exactly
        # the rules the carrier installed, no more and no fewer.
        for add, dele in zip(adds, dels):
            assert dele == add.replace("-A PREROUTING", "-D PREROUTING", 1) + " 2>/dev/null || true"
        # Nothing else in either list mentions the frontend DNAT.
        assert len(failover._carrier_dnat_cmds(plan["foreign_cmds"])) == 0
        assert len(failover._carrier_dnat_cmds(plan["teardown_foreign"])) == 0


def test_frp_client_retries_login_instead_of_dying_on_first_refusal():
    # 2026-10-27 live: the GRE -> frp-TLS switch failed smoke because
    # frpc started ~2s before frps listened on :7000, and frp's
    # default loginFailExit=true killed frpc on that single refused
    # dial instead of retrying. With the flag off, frpc keeps dialing
    # until frps is up, so starting the client before the server is
    # safe and the :443 listener exists by smoke time.
    plan = protocols.generate_deployment("frp-TLS", 1, "198.51.100.10", "203.0.113.20", 443)
    frpc_configs = [c for c in plan["foreign_files"].values() if "serverAddr" in c]
    assert len(frpc_configs) == 1, plan["foreign_files"].keys()
    assert "loginFailExit = false" in frpc_configs[0]


class _FakeIptablesRunner:
    """Simulates one PREROUTING chain: -S lists it, -D removes one copy."""

    def __init__(self, rules):
        self.rules = list(rules)
        self.delete_calls = 0

    def run(self, cmd, best_effort=False, timeout=None, **_kw):
        import re

        if "iptables -t nat -S PREROUTING" in cmd:
            lines = [
                f"-A PREROUTING -p {proto} -j DNAT --to-destination {dest}"
                for proto, dest in self.rules
            ]
            return 0, "\n".join(lines), ""
        if "iptables -t nat -D PREROUTING" in cmd:
            self.delete_calls += 1
            m = re.search(r"-p (tcp|udp).*--to-destination (\S+)", cmd)
            if m and (m.group(1), m.group(2)) in self.rules:
                self.rules.remove((m.group(1), m.group(2)))
            return 0, "", ""
        raise AssertionError(cmd)


def _gre_purge_setup():
    plan = protocols.generate_deployment(
        "GRE", 1, "198.51.100.10", "203.0.113.20", 21232)
    dels = failover._carrier_dnat_cmds(plan["teardown_iran"])
    assert len(dels) == 2, dels
    return dels


def test_purge_carrier_dnat_removes_duplicate_copies():
    # 2026-11-03 live: a stale GRE DNAT ahead of the new ESP DNAT
    # shadowed the successor while the inner ping stayed healthy.
    # A single -D removes one copy; repeated deploys can leave two.
    dels = _gre_purge_setup()
    runner = _FakeIptablesRunner([
        ("tcp", "10.10.11.2:21232"), ("tcp", "10.10.11.2:21232"),
        ("udp", "10.10.11.2:21232"), ("udp", "10.10.11.2:21232"),
        ("tcp", "10.12.11.2:21232"),
    ])
    assert failover.purge_carrier_dnat(runner, dels, "10.10.11.2:21232") is True
    assert runner.rules == [("tcp", "10.12.11.2:21232")]
    assert runner.delete_calls >= 4


def test_purge_carrier_dnat_absent_is_a_noop():
    dels = _gre_purge_setup()
    runner = _FakeIptablesRunner([("tcp", "10.12.11.2:21232")])
    assert failover.purge_carrier_dnat(runner, dels, "10.10.11.2:21232") is True
    assert runner.delete_calls == 0
    assert runner.rules == [("tcp", "10.12.11.2:21232")]


def test_purge_carrier_dnat_reports_a_stuck_rule():
    # Deletes naming the wrong destination never clear the target:
    # the caller must learn that, not assume one round worked.
    esp_plan = protocols.generate_deployment(
        "ESP", 1, "198.51.100.10", "203.0.113.20", 21232)
    dels = failover._carrier_dnat_cmds(esp_plan["teardown_iran"])
    runner = _FakeIptablesRunner([("tcp", "10.10.11.2:21232")])
    assert failover.purge_carrier_dnat(
        runner, dels, "10.10.11.2:21232", max_rounds=2) is False
    assert runner.rules == [("tcp", "10.10.11.2:21232")]


def test_manifest_dnat_rows_and_path():
    for proto, svc in (("GRE", "best-tunnel-prod-p1-gre"), ("ESP", "best-tunnel-prod-p1-esp")):
        plan = protocols.generate_deployment(proto, 1, "198.51.100.10", "203.0.113.20", 443)
        comment = generate_firewall_comment("1-prod", proto)
        rows = protocols.fw_manifest_rows(plan["iran_cmds"], comment)
        dnat = failover._manifest_dnat_rows(rows)
        assert len(dnat) == 2, (proto, dnat)
        for row in dnat:
            parts = row.split("|")
            assert parts[0] == "R" and parts[2] == "PREROUTING" and "DNAT" in parts[5]
        assert failover._carrier_manifest_path(plan) == f"/etc/best-tunnel/firewall/{svc}-fw.rules"
