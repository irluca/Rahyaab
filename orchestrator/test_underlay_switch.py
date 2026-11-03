"""Tests for the underlay-switch helpers in orchestrator/failover.py.

Pure computation, no SSH, no live hosts: the DNAT command filter, the
manifest row filter, the manifest path lookup, and the underlay
resolution that decides which switch shape a pair takes.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import re

import failover
import protocols
import storage
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


class _FakeCarrierRunner:
    """Simulates one host for a carrier switch: unit files, unit state,
    PREROUTING DNAT, and per-interface ping loss.

    Only what execute_failover and _restore_carrier actually read is
    modelled: systemctl lifecycle, iptables -A/-D/-S for the DNAT, file
    writes/deletes, `cat` of the firewall manifest, and ping transcripts
    in the shape engine.ping_result parses. Everything else answers 0.
    """

    def __init__(self, gre_loss, esp_loss):
        self.files = {}
        self.units = {}
        self.prerouting = []
        # Keyed by interface family, not by one pair's names: the pair
        # id comes from storage.add_pair, so the live names are
        # grep{pid} / espp{pid}, not grep1 / espp1.
        self.gre_loss = gre_loss
        self.esp_loss = esp_loss

    def write_file(self, path, content, timeout=30):
        self.files[path] = content

    def _dnat(self, cmd):
        m_proto = re.search(r"-p (tcp|udp)", cmd)
        m_dest = re.search(r"--to-destination (\S+)", cmd)
        if m_proto and m_dest:
            return m_proto.group(1), m_dest.group(1)
        return None

    def run(self, cmd, best_effort=False, timeout=None, check=False, **_kw):
        if "iptables -t nat -S PREROUTING" in cmd:
            lines = "".join(
                f"-A PREROUTING -p {p} -j DNAT --to-destination {d}\n"
                for p, d in self.prerouting)
            return 0, lines, ""
        if "iptables" in cmd and "PREROUTING" in cmd and "DNAT" in cmd:
            parsed = self._dnat(cmd)
            if parsed:
                if " -A " in cmd:
                    self.prerouting.append(parsed)
                elif " -D " in cmd and parsed in self.prerouting:
                    self.prerouting.remove(parsed)
            return 0, "", ""
        if cmd.startswith("systemctl is-active "):
            unit = cmd.split()[-1]
            return 0, "active" if self.units.get(unit) else "inactive", ""
        if "systemctl enable --now " in cmd or "systemctl start " in cmd:
            unit = cmd.split()[-1]
            svc = f"/etc/systemd/system/{unit}.service"
            self.units[unit] = svc in self.files
            return 0, "", ""
        if "systemctl stop " in cmd or "systemctl disable " in cmd:
            self.units[cmd.split()[-1]] = False
            return 0, "", ""
        if cmd.startswith("rm -f "):
            for token in cmd.split()[2:]:
                self.files.pop(token, None)
            return 0, "", ""
        if cmd.startswith("cat "):
            return 0, self.files.get(cmd.split()[1], ""), ""
        if "ping -c" in cmd:
            m_cnt = re.search(r"ping -c (\d+)", cmd)
            m_iface = re.search(r"-I (\S+)", cmd)
            cnt = int(m_cnt.group(1)) if m_cnt else 2
            iface = m_iface.group(1) if m_iface else ""
            loss = self.gre_loss if iface.startswith("grep") else self.esp_loss
            recv = int(cnt * (1.0 - loss / 100.0))
            target = cmd.split()[-1]
            return 0, (
                f"PING {target} 56(84) bytes of data.\n"
                f"--- ping statistics ---\n"
                f"{cnt} packets transmitted, {recv} received, {loss:.1f}% packet loss, time 2002ms\n"
                f"rtt min/avg/max/mdev = 36.000/37.000/38.000/1.000 ms\n"), ""
        return 0, "", ""


def _carrier_switch_setup(pid_extra_loss):
    """A pair recorded on ESP with an ESP deployment already in place,
    on fake runners whose GRE path is lossy (28%, as live 2026-11-03)
    and whose ESP path loss is pid_extra_loss."""
    ir_pub, fr_pub = "198.51.100.10", "203.0.113.20"
    pid = storage.add_pair(name="restore_carrier", iran_host=ir_pub,
                           foreign_host=fr_pub, frontend_port=21232)
    storage.update_pair_status(pid, status="ACTIVE", active_tunnel="ESP")
    pair = {"id": pid, "name": "restore_carrier", "frontend": 21232,
            "frontend_port": 21232,
            "iran": {"host": ir_pub, "port": 22},
            "foreign": {"host": fr_pub, "port": 22}}
    esp_plan = protocols.generate_deployment("ESP", pid, ir_pub, fr_pub, 21232)
    esp_peer = protocols.carrier_inner_pair("ESP", pid, "prod", 10)[1]
    esp_unit = esp_plan["iran_units"][0]
    ir = _FakeCarrierRunner(28.0, pid_extra_loss)
    fr = _FakeCarrierRunner(28.0, pid_extra_loss)
    for runner in (ir, fr):
        for path, content in list(esp_plan["iran_files"].items()):
            runner.files[path] = content
        runner.units[esp_unit] = True
    ir.prerouting = [("tcp", f"{esp_peer}:21232"), ("udp", f"{esp_peer}:21232")]
    return pid, pair, ir, fr, esp_plan, esp_peer


def test_failed_carrier_switch_redeploys_predecessor():
    # 2026-11-03 live, pair 1: ESP -> GRE failed its inner-ping smoke
    # (28% loss, TOO_LOSSY), and the pair was left with NO deployment:
    # ESP's files were deleted by the teardown, the guard could only
    # `systemctl start` units that no longer existed, and the healer
    # kept cycling candidates over the same empty state. The switch
    # must now end back on a verified ESP deployment.
    pid, pair, ir, fr, esp_plan, esp_peer = _carrier_switch_setup(0.0)
    try:
        mgr = failover.FailoverManager(min_interval_seconds=0,
                                       max_failovers_per_window=10)
        res = mgr.execute_failover(pair, "ESP", "GRE", reason="test",
                                   dry_run=False, ir_runner=ir, fr_runner=fr)
        assert res["success"] is False
        assert "TOO_LOSSY" in res["error"], res["error"]
        assert res["restored"] is True
        assert res["predecessor_restored"]["verified"] is True
        esp_unit = esp_plan["iran_units"][0]
        gre_unit = protocols.generate_deployment(
            "GRE", pid, "198.51.100.10", "203.0.113.20", 21232)["iran_units"][0]
        assert f"/etc/systemd/system/{esp_unit}.service" in ir.files
        assert f"/etc/systemd/system/{esp_unit}.service" in fr.files
        assert ir.units.get(esp_unit) is True
        assert fr.units.get(esp_unit) is True
        assert f"/etc/systemd/system/{gre_unit}.service" not in ir.files
        assert ir.prerouting == [("tcp", f"{esp_peer}:21232"),
                                 ("udp", f"{esp_peer}:21232")]
        assert storage.get_pair(pid).get("active_tunnel") == "ESP"
    finally:
        storage.delete_pair(pid)


def test_failed_carrier_switch_leaves_predecessor_deployed_when_path_dead():
    # The mirror case: the ESP path itself is still dead (100% loss),
    # so the redeploy cannot verify — and must still be left in place,
    # not torn down again. A deployment whose path recovers heals on
    # the next health pass; a deleted one never does.
    pid, pair, ir, fr, esp_plan, esp_peer = _carrier_switch_setup(100.0)
    try:
        mgr = failover.FailoverManager(min_interval_seconds=0,
                                       max_failovers_per_window=10)
        res = mgr.execute_failover(pair, "ESP", "GRE", reason="test",
                                   dry_run=False, ir_runner=ir, fr_runner=fr)
        assert res["success"] is False
        assert res["restored"] is False
        assert res["predecessor_restored"]["redeployed"] is True
        assert res["predecessor_restored"]["verified"] is False
        esp_unit = esp_plan["iran_units"][0]
        assert f"/etc/systemd/system/{esp_unit}.service" in ir.files
        assert ir.units.get(esp_unit) is True
        assert ir.prerouting == [("tcp", f"{esp_peer}:21232"),
                                 ("udp", f"{esp_peer}:21232")]
    finally:
        storage.delete_pair(pid)
