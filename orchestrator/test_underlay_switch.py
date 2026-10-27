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
