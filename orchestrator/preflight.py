"""Pre-flight path and host checks (Phase 3).

Before this module, "the protocol is slow" and "the path is misconfigured"
were indistinguishable in a benchmark result: a missing MSS clamp or a
missing BBR module degrades every tunnel on a pair in exactly the shape a
bad protocol would, and the scoring engine would dutifully rank protocols
on a broken path. The reference projects this was modelled on (Hashem's
Path Test and MSS/BBR guidance, Kariz's non-destructive probe) share one
idea: measure the path first, say what is wrong with it in plain words,
and change nothing while doing so.

Everything here is read-only. A pre-flight report is a list of facts plus
findings derived from them by pure rules, so the rules are testable
offline and the same report can be produced for a pair that was never
deployed to. Fixes are separate, explicit operator actions elsewhere.

The spoof capability probe belongs to this module for the same reason:
whether a datacenter lets forged-source packets out (no egress source
validation) is a property of the path that must be known *before* the
spoof emergency mode is offered for a pair, not discovered during an
outage. The probe itself only opens a raw socket and sends nothing.
"""

from __future__ import annotations

import re

PROBE_PORTS = (22, 443, 8443)
PING_COUNT = 10

# One read-only sweep per host. Each fact is printed on its own KEY=VALUE line
# so a partial failure still yields the facts that could be read.
HOST_FACTS_CMD = r"""
echo "kernel=$(uname -r)"
echo "os=$(. /etc/os-release 2>/dev/null; echo ${PRETTY_NAME:-unknown})"
echo "cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
echo "cc_available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)"
echo "bbr_loaded=$(lsmod 2>/dev/null | grep -c '^tcp_bbr' || true)"
echo "mtu_probing=$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null)"
echo "rmem_max=$(sysctl -n net.core.rmem_max 2>/dev/null)"
echo "wmem_max=$(sysctl -n net.core.wmem_max 2>/dev/null)"
IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
echo "iface=$IFACE"
echo "iface_mtu=$(ip link show "$IFACE" 2>/dev/null | grep -o 'mtu [0-9]*' | awk '{print $2}')"
echo "mss_clamp=$(iptables -t mangle -S 2>/dev/null | grep -ci tcpmss || true)"
echo "raw_socket=$(python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW); print("ok")' 2>/dev/null || echo no)"
""".strip()


def parse_host_facts(text: str) -> dict:
    """Parse the KEY=VALUE sweep into typed facts; unreadable values stay None
    rather than becoming a confident-looking zero (the report must be able to
    say "could not read", which is a different finding from "is disabled")."""
    raw = {}
    for line in (text or "").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            raw[key.strip()] = value.strip()

    def as_int(key):
        try:
            return int(raw[key])
        except (KeyError, ValueError):
            return None

    return {
        "kernel": raw.get("kernel") or None,
        "os": raw.get("os") or None,
        "congestion_control": raw.get("cc") or None,
        "cc_available": (raw.get("cc_available") or "").split() or [],
        "bbr_loaded": (as_int("bbr_loaded") or 0) > 0,
        "mtu_probing": as_int("mtu_probing"),
        "rmem_max": as_int("rmem_max"),
        "wmem_max": as_int("wmem_max"),
        "iface": raw.get("iface") or None,
        "iface_mtu": as_int("iface_mtu"),
        # None when the sweep never ran: an unreachable host must not be
        # reported as "no clamp rule", which is a different, actionable claim.
        "mss_clamp_rules": as_int("mss_clamp"),
        "raw_socket": raw.get("raw_socket") == "ok",
    }


_PING_STATS = re.compile(
    r"(?P<sent>\d+) packets transmitted, (?P<received>\d+) received, "
    r"(?P<loss>[\d.]+)% packet loss")
_PING_RTT = re.compile(
    r"rtt min/avg/max/mdev = [\d.]+/(?P<avg>[\d.]+)/[\d.]+/[\d.]+")


def parse_ping(text: str) -> dict:
    """Summarise `ping -c N` output. A run that produced no statistics line is
    reported as unreachable with 100% loss only when ping actually ran; no
    output at all means the measurement itself failed (loss_pct None)."""
    out = {"sent": None, "received": None, "loss_pct": None, "rtt_avg_ms": None}
    if not text:
        return out
    stats = _PING_STATS.search(text)
    if stats:
        out["sent"] = int(stats.group("sent"))
        out["received"] = int(stats.group("received"))
        out["loss_pct"] = float(stats.group("loss"))
    rtt = _PING_RTT.search(text)
    if rtt:
        out["rtt_avg_ms"] = float(rtt.group("avg"))
    return out


def parse_tcp_probe(text: str) -> dict:
    """Parse the per-port lines the probe loop prints: {port: reached_bool}."""
    out = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "PORT":
            try:
                out[int(parts[1])] = parts[2] == "OPEN"
            except ValueError:
                continue
    return out


def _tcp_probe_cmd(peer_ip: str, ports=PROBE_PORTS) -> str:
    loop = "; ".join(
        f'(timeout 4 bash -c "echo > /dev/tcp/{peer_ip}/{p}" 2>/dev/null '
        f'&& echo "PORT {p} OPEN") || echo "PORT {p} SHUT"'
        for p in ports)
    return loop


def collect_host_facts(runner) -> dict:
    _rc, out, _err = runner.run(HOST_FACTS_CMD, check=False, best_effort=True, timeout=60)
    return parse_host_facts(out)


def measure_path(runner, peer_ip: str, ports=PROBE_PORTS) -> dict:
    _rc, ping_out, _ = runner.run(f"ping -c {PING_COUNT} -q -W 2 {peer_ip}",
                                  check=False, best_effort=True, timeout=60)
    _rc, tcp_out, _ = runner.run(_tcp_probe_cmd(peer_ip, ports),
                                 check=False, best_effort=True, timeout=30)
    return {"ping": parse_ping(ping_out), "tcp": parse_tcp_probe(tcp_out)}


def findings_for(iran_facts: dict, foreign_facts: dict,
                 ir_to_fa: dict, fa_to_ir: dict) -> list[str]:
    """Plain-language findings from a pair's facts. Pure and offline-testable:
    the live collectors above only fetch; every judgement lives here."""
    findings = []
    for role, facts in (("iran", iran_facts), ("foreign", foreign_facts)):
        if facts.get("kernel") is None:
            findings.append(
                f"{role}: host facts could not be collected (host unreachable or "
                "the sweep failed); nothing about this host is being claimed")
            continue
        cc = facts.get("congestion_control")
        if cc and cc != "bbr":
            if "bbr" in (facts.get("cc_available") or []) or facts.get("bbr_loaded"):
                findings.append(
                    f"{role}: BBR is available but not active (current: {cc}); "
                    "throughput under loss will suffer on every protocol")
            else:
                findings.append(
                    f"{role}: BBR is not available on this host (current: {cc}); "
                    "the tcp_bbr module is not loaded")
        if facts.get("mss_clamp_rules") == 0:
            findings.append(
                f"{role}: no MSS-clamp rule in the mangle table; tunnelled flows "
                "can hit PMTU black holes that look like a slow protocol")
        # raw_socket is a capability, not a problem: it stays in the facts for
        # the spoof tester to read, and never becomes a finding - a healthy
        # pair must produce an empty findings list.
    for label, path in (("iran->foreign", ir_to_fa), ("foreign->iran", fa_to_ir)):
        ping = path.get("ping") or {}
        if ping.get("loss_pct") == 100.0:
            findings.append(f"{label}: ICMP fully lost - the pair cannot see each other at all")
        elif ping.get("loss_pct"):
            findings.append(
                f"{label}: ICMP loss {ping['loss_pct']}% on the raw path, before any tunnel")
        tcp = path.get("tcp") or {}
        if tcp and not any(tcp.values()):
            findings.append(
                f"{label}: direct TCP unreachable on every probed port "
                f"{sorted(tcp)} - tunnels on this leg must be initiated from the other side "
                "or ride a non-TCP carrier")
    return findings


def build_preflight_report(iran_runner, foreign_runner,
                           iran_ip: str, foreign_ip: str) -> dict:
    """Collect both hosts' facts and both directions of the path, and derive
    the findings. Read-only end to end; safe to run against a live pair."""
    iran_facts = collect_host_facts(iran_runner)
    foreign_facts = collect_host_facts(foreign_runner)
    ir_to_fa = measure_path(iran_runner, foreign_ip)
    fa_to_ir = measure_path(foreign_runner, iran_ip)
    return {
        "iran": iran_facts,
        "foreign": foreign_facts,
        "path": {"iran_to_foreign": ir_to_fa, "foreign_to_iran": fa_to_ir},
        "findings": findings_for(iran_facts, foreign_facts, ir_to_fa, fa_to_ir),
    }
