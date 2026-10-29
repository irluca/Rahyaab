"""Tests for the bale-webrtc protocol generator (offline, no network).

Covers the plan contract every generator must satisfy (units per side,
no secret in any unit, no variable in any ExecStart, safety-passing
commands), plus Bale-specific rules: the join link and cookies are never
generated (provisioned files only), teardown keeps provisioned files,
bench uses a distinct SOCKS port and file set, and the creator binary
is pinned while the joiner (no upstream asset) fails closed.
"""

import re

import binary_manager
import protocols
import safety

IR, FR = "198.51.100.10", "203.0.113.20"
CREATOR_SHA = "fcf69426b83ad06f20a6e2ac2301edbabbc51cbcd1a6a02b9cbdfe743f9aabba"


def _plan(pair_id=71, frontend=443, **kwargs):
    return protocols.generate_deployment("bale-webrtc", pair_id, IR, FR,
                                         frontend, **kwargs)


def _units(plan):
    out = {}
    for side in ("iran_files", "foreign_files"):
        for path, content in plan[side].items():
            if path.endswith(".service"):
                out[path] = content
    return out


def _creds_pass(plan):
    creds = plan["iran_files"]["/etc/best-tunnel/bale/prod-creds-p71"]
    return re.search(r"BALE_SOCKS_PASS=(\S+)", creds).group(1)


def test_plan_shape():
    plan = _plan()
    assert plan["protocol"] == "bale-webrtc"
    assert plan["iran_units"] == ["best-tunnel-prod-p71-bale-joiner",
                                  "best-tunnel-prod-p71-bale-forward"]
    assert plan["foreign_units"] == ["best-tunnel-prod-p71-bale-creator"]
    units = _units(plan)
    assert len([p for p in units if "bale-joiner" in p]) == 1
    assert len([p for p in units if "bale-forward" in p]) == 1
    assert len([p for p in units if "bale-creator" in p]) == 1


def test_no_secrets_or_variables_in_units():
    plan = _plan()
    blob = "\n".join(_units(plan).values())
    for line in blob.splitlines():
        if line.startswith("ExecStart"):
            assert "$" not in line, f"ExecStart interpolates a variable: {line}"
    assert _creds_pass(plan) not in blob
    assert "PRIVATE KEY" not in blob
    # The join link is never generated: no Bale URL anywhere in the plan.
    for content in list(plan["iran_files"].values()) + list(plan["foreign_files"].values()):
        assert "meet.bale.ai" not in content


def test_backend_port_wiring():
    plan = _plan(backend_port=8443)
    fwd = plan["iran_files"]["/usr/local/bin/best-bale-forward-p71-prod.py"]
    assert "BACKEND = 8443" in fwd
    assert "FRONTEND = 443" in fwd
    default = _plan()
    fwd_default = default["iran_files"]["/usr/local/bin/best-bale-forward-p71-prod.py"]
    assert "BACKEND = 443" in fwd_default


def test_bench_namespace_is_distinct():
    prod = _plan()
    bench = protocols.generate_benchmark_plan("bale-webrtc", 71, IR, FR)
    prod_units = set(_units(prod))
    bench_units = set(_units(bench))
    assert not (prod_units & bench_units), "bench units must not collide with prod"
    assert any("bench" in p for p in bench_units)
    prod_fwd = prod["iran_files"]["/usr/local/bin/best-bale-forward-p71-prod.py"]
    bench_fwd = bench["iran_files"]["/usr/local/bin/best-bale-forward-p71-bench.py"]
    assert "SOCKS_PORT = 10871" in prod_fwd
    assert "SOCKS_PORT = 12871" in bench_fwd
    compile(bench_fwd, "best-bale-forward-bench.py", "exec")


def test_teardown_keeps_provisioned_files():
    plan = _plan()
    teardown = "\n".join(plan["teardown_iran"] + plan["teardown_foreign"])
    # Provisioned by the operator, not generated: teardown must not delete them.
    assert "prod-link-p71.txt" not in teardown
    assert "prod-cookies-p71.json" not in teardown
    # Generated files are removed.
    assert "prod-creds-p71" in teardown
    assert "best-bale-joiner-p71-prod.sh" in teardown
    assert "best-bale-forward-p71-prod.py" in teardown


def test_wrapper_reads_provisioned_files_and_uses_dc():
    plan = _plan()
    wrapper = plan["iran_files"]["/usr/local/bin/best-bale-joiner-p71-prod.sh"]
    assert "/etc/best-tunnel/bale/prod-link-p71.txt" in wrapper
    assert "/etc/best-tunnel/bale/prod-creds-p71" in wrapper
    assert "--tunnel-mode dc" in wrapper
    assert "--socks-port 10871" in wrapper
    assert "not provisioned" in wrapper
    assert _creds_pass(plan) not in wrapper


def test_creator_unit_references_provisioned_cookies():
    plan = _plan()
    unit = plan["foreign_files"]["/etc/systemd/system/best-tunnel-prod-p71-bale-creator.service"]
    assert "--cookies /etc/best-tunnel/bale/prod-cookies-p71.json" in unit
    assert "--write-file /var/run/whitelist-bypass/call-prod-p71.txt" in unit


def test_all_commands_pass_safety():
    plan = _plan()
    for cmd in (plan["iran_cmds"] + plan["foreign_cmds"]
                + plan["teardown_iran"] + plan["teardown_foreign"]):
        assert safety.check_command_safe(cmd), f"blocked command: {cmd[:90]}"


def test_binaries_declared_and_creator_pinned():
    assert binary_manager.required_binaries("bale-webrtc") == [
        "headless-bale-creator", "headless-bale-joiner"]
    assert binary_manager.get_pinned_checksum("headless-bale-creator",
                                              "v0.1.2") == CREATOR_SHA
    # The joiner has no upstream release asset: no pin exists (empty
    # checksum), so its verified install fails closed rather than
    # fetching something unchecked. (Pin lands with the source-build step.)
    assert binary_manager.get_pinned_checksum("headless-bale-joiner",
                                              "v0.1.2") == ""


def test_forwarder_script_compiles():
    plan = _plan()
    src = plan["iran_files"]["/usr/local/bin/best-bale-forward-p71-prod.py"]
    compile(src, "best-bale-forward-prod.py", "exec")


def test_backend_target_declared():
    # §8b: the deploy gate refuses a plan with no delivery port, so the
    # forwarder's BACKEND assignment is the artifact the gate reads back.
    plan = _plan()
    info = protocols.backend_target("bale-webrtc", plan)
    assert info["status"] == "declared"
    assert info["port"] == 443
    assert info["lands_on"] == "foreign"
    declared = _plan(backend_port=8443)
    assert protocols.backend_target("bale-webrtc", declared)["port"] == 8443


def test_bale_not_yet_in_supported_protocols():
    # Deliberate sequencing: sweeps stay untouched until the gating item
    # lands (provisioning checks + try-order). The generator works via
    # generate_deployment regardless; only advertisement waits.
    assert "bale-webrtc" not in protocols.get_supported_protocols()
    assert "bale-webrtc" in protocols.ALL_PROTOCOLS
