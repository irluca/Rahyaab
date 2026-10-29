"""Tests for the spoof-wireguard protocol generator (offline, no network).

Covers the plan contract every generator must satisfy (units per side,
no secret in any unit, no variable in any ExecStart, safety-passing
commands), plus spoof-specific rules: the spoof IP list is provisioned
(never generated), teardown keeps it, bench uses a distinct subnet and
port set, the pipe packet builder is wire-correct, and the WireGuard
keypairs are genuine X25519 pairs.
"""

import base64
import re
import socket
import struct

import protocols
import safety
from cryptography.hazmat.primitives.asymmetric import x25519

IR, FR = "198.51.100.10", "203.0.113.20"


def _plan(pair_id=71, frontend=443, **kwargs):
    return protocols.generate_deployment("spoof-wireguard", pair_id, IR, FR,
                                         frontend, **kwargs)


def _units(plan):
    # A list, not a path-keyed dict: Iran and foreign share the pipe
    # unit name (different hosts, different contents), and keying by
    # path would silently drop one side.
    out = []
    for side in ("iran_files", "foreign_files"):
        for path, content in plan[side].items():
            if path.endswith(".service"):
                out.append(content)
    return out


def _pipe_src(plan, side="iran_files", suffix="iran"):
    key = f"/usr/local/bin/best-spoof-pipe-p71-prod-{suffix}.py"
    return plan[side][key]


def test_plan_shape():
    plan = _plan()
    assert plan["protocol"] == "spoof-wireguard"
    assert plan["iran_units"] == ["best-tunnel-prod-p71-spoof-pipe",
                                  "best-tunnel-prod-p71-spoof-forward"]
    assert plan["foreign_units"] == ["best-tunnel-prod-p71-spoof-pipe"]
    units = _units(plan)
    assert len(units) == 3


def test_no_secrets_or_variables_in_units():
    plan = _plan()
    blob = "\n".join(_units(plan))
    for line in blob.splitlines():
        if line.startswith("ExecStart"):
            assert "$" not in line, f"ExecStart interpolates a variable: {line}"
    ir_priv = plan["iran_files"]["/etc/best-tunnel/spoof/prod-key-p71-iran"].strip()
    fr_priv = plan["foreign_files"]["/etc/best-tunnel/spoof/prod-key-p71-foreign"].strip()
    assert ir_priv not in blob and fr_priv not in blob
    assert "PRIVATE KEY" not in blob
    # Keys are referenced by path, never by value.
    assert "private-key /etc/best-tunnel/spoof/prod-key-p71-iran" in blob
    assert "private-key /etc/best-tunnel/spoof/prod-key-p71-foreign" in blob


def test_wireguard_keypairs_are_genuine_x25519():
    plan = _plan()
    units = "\n".join(_units(plan))
    for side, key_path, unit_side in (
            ("iran_files", "/etc/best-tunnel/spoof/prod-key-p71-iran", "foreign"),
            ("foreign_files", "/etc/best-tunnel/spoof/prod-key-p71-foreign", "iran")):
        priv_b64 = plan[side][key_path].strip()
        priv_raw = base64.b64decode(priv_b64)
        assert len(priv_raw) == 32
        pub_raw = x25519.X25519PrivateKey.from_private_bytes(priv_raw).public_key().public_bytes_raw()
        pub_b64 = base64.b64encode(pub_raw).decode("ascii")
        # The peer's unit must pin exactly this public key.
        assert f"peer {pub_b64} " in units, f"{side} pubkey not pinned on the peer"


def test_backend_target_declared():
    plan = _plan()
    info = protocols.backend_target("spoof-wireguard", plan)
    assert info["status"] == "declared"
    assert info["port"] == 443
    assert info["lands_on"] == "foreign"
    declared = _plan(backend_port=8443)
    assert protocols.backend_target("spoof-wireguard", declared)["port"] == 8443


def test_bench_namespace_is_distinct():
    prod = _plan()
    bench = protocols.generate_benchmark_plan("spoof-wireguard", 71, IR, FR)
    prod_units = set(_units(prod))
    bench_units = set(_units(bench))
    assert not (prod_units & bench_units)
    assert any("bench" in p for p in bench_units)
    prod_pipe = _pipe_src(prod)
    bench_pipe = bench["iran_files"]["/usr/local/bin/best-spoof-pipe-p71-bench-iran.py"]
    assert "PIPE_PORT = 51871" in prod_pipe
    assert "PIPE_PORT = 52871" in bench_pipe
    assert "10.14.81.1" in prod_pipe or "10.14" in "\n".join(_units(prod))
    assert "10.15" in "\n".join(_units(bench))
    compile(bench_pipe, "best-spoof-pipe-bench.py", "exec")


def test_teardown_keeps_provisioned_ip_list():
    plan = _plan()
    teardown = "\n".join(plan["teardown_iran"] + plan["teardown_foreign"])
    assert "prod-ips-p71.txt" not in teardown
    assert "prod-key-p71-iran" in teardown
    assert "best-spoof-pipe-p71-prod-iran.py" in teardown
    assert "best-spoof-forward-p71-prod.py" in teardown


def test_pipe_packet_builder_is_wire_correct():
    plan = _plan()
    src = _pipe_src(plan)
    globs = {"__name__": "spoof_pipe_test"}
    exec(compile(src, "best-spoof-pipe.py", "exec"), globs)
    assert globs["PIPE_PORT"] == 51871
    assert globs["WG_PORT"] == 51971
    assert globs["PEER_IP"] == FR
    packet = globs["build_spoof_udp"]("203.0.113.10", "198.51.100.20",
                                      51871, b"hello", ident=7)
    assert packet[0] == 0x45  # IPv4, IHL 5
    assert packet[9] == 17  # UDP
    assert socket.inet_ntoa(packet[12:16]) == "203.0.113.10"
    assert socket.inet_ntoa(packet[16:20]) == "198.51.100.20"
    assert packet[20:28][0:2] == struct.pack("!H", 51871)  # sport = pipe port
    assert packet[-5:] == b"hello"
    checksum = globs["_checksum"]
    assert checksum(packet[:20]) == 0  # IP checksum valid
    udp = packet[20:]
    udp_len = len(udp)
    pseudo = socket.inet_aton("203.0.113.10") + socket.inet_aton("198.51.100.20") + struct.pack("!BBH", 0, 17, udp_len)
    assert checksum(pseudo + udp) == 0  # UDP checksum valid


def test_forwarder_targets_foreign_inner():
    plan = _plan()
    fwd = plan["iran_files"]["/usr/local/bin/best-spoof-forward-p71-prod.py"]
    assert "FRONTEND = 443" in fwd
    assert "BACKEND = 443" in fwd
    assert "10.14.81.2" in fwd  # peer inner: idx = (71 % 200) + 10 = 81
    compile(fwd, "best-spoof-forward.py", "exec")


def test_all_commands_pass_safety():
    plan = _plan()
    for cmd in (plan["iran_cmds"] + plan["foreign_cmds"]
                + plan["teardown_iran"] + plan["teardown_foreign"]):
        assert safety.check_command_safe(cmd), f"blocked command: {cmd[:90]}"


def test_spoof_is_in_supported_protocols_and_skip_env_gates_it(monkeypatch):    # Deliberate flip (2026-10-29): spoof joined the base gated — the
    # sweep skips it for pairs whose probe did not pass, via env.
    assert "spoof-wireguard" in protocols.get_supported_protocols()
    assert "spoof-wireguard" in protocols.ALL_PROTOCOLS
    monkeypatch.setenv("BEST_TUNNEL_SKIP_SPOOF", "1")
    assert "spoof-wireguard" not in protocols.get_supported_protocols()
    monkeypatch.delenv("BEST_TUNNEL_SKIP_SPOOF")
    assert "spoof-wireguard" in protocols.get_supported_protocols()


def test_spoof_required_binaries_declared():
    import binary_manager
    assert binary_manager.required_binaries("spoof-wireguard") == ["wireguard-tools"]
    assert "wireguard-tools" in binary_manager.APT_PACKAGES


def test_selector_sorts_spoof_last(monkeypatch):
    import failover

    def fake_scores(pair_id, allowed=None, pair=None):
        return ({"GRE": 90.0, "bale-webrtc": 95.0,
                 "spoof-wireguard": 99.0}, set())
    monkeypatch.setattr(failover, "median_protocol_scores", fake_scores)
    sel = failover.FailoverCandidateSelector.select_best_candidate
    # An ordinary protocol wins despite a lower score.
    assert sel(71, "ESP",
               allowed_protocols=["GRE", "bale-webrtc", "spoof-wireguard"]) == "GRE"
    # With only last-tier candidates, Bale precedes spoof.
    monkeypatch.setattr(
        failover, "median_protocol_scores",
        lambda pair_id, allowed=None, pair=None: (
            {"bale-webrtc": 95.0, "spoof-wireguard": 99.0}, set()))
    assert sel(71, "ESP",
               allowed_protocols=["bale-webrtc", "spoof-wireguard"]) == "bale-webrtc"
