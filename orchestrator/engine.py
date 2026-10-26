#!/usr/bin/env python3
"""Orchestrator Execution Engine for Tunnel Studio Pro v2.0.
Fully implements:
1. Real isolated benchmark engine for every protocol in protocols.get_supported_protocols():
   - Sets up dedicated benchmark tunnel on test frontend 8898 / transport 8897.
   - Runs test backend on Foreign.
   - Measures latency/jitter/loss THROUGH the tunnel: kernel ICMP for GRE, L7 HTTP round-trips
     for the user-space transports (orchestrator/probe.py).
   - Measures a fixed 30s sustained-availability window, distinct from random packet loss.
   - 4-step bulk ladder (1KB-1MB) with byte-count verification, then multi-stream iperf3.
   - Teardown in a finally block + adaptive cooldowns (30s / 60s).
2. Strict server-side gating for protected port release (rejects unconfirmed release & protects active users).
3. Real 30-second verification window with end-to-end data probing (GRE tunnel ping / TCP frontend probe).
4. Automatic rollback on verification failure or runtime errors.
5. Conntrack tuning applied as a single script (its shell variables must survive) and consistent
   grep{pair_id} interface naming.
"""
import time
import datetime
import re
from mock_ssh import (get_ssh_runner, MockSSHClient, TransientTransportError, transport_flaps)
from safety import (
    is_hard_blacklisted, validate_frontend_port,
    parse_active_connections_count, sanitize_proc_name, sanitize_pid
)
from scoring import evaluate_tunnel_metrics
import typing
import json
import storage
import protocols
import probe
import binary_manager

class BaseRTTResult(typing.NamedTuple):
    base_rtt_ms: float
    is_fallback: bool


class PingResult(typing.NamedTuple):
    sent: int
    received: int
    loss_pct: float
    rtt_avg_ms: float


# Loss thresholds for any verdict built from an ICMP count. These are percentages of a *measured* sample
# rather than the string "0% packet loss", because a probe that only accepts a clean sheet reads ordinary
# loss as an outage: this pair's own GRE rows carry 2-4% random loss on the underlay, and every caller of a
# reachable-verdict acts on it - `deploy_tunnel` refuses, `failover` switches protocol away. A path that
# answered 49 of 50 is up, and saying it is down is the more expensive error.
UNDERLAY_LOSS_ACCEPT_PCT = 4.0
UNDERLAY_LOSS_CLEAN_PCT = 2.0

# 50 samples, not 2. A threshold is only assertable at the granularity the sample can express: with two
# packets the possible answers are 0%, 50% and 100%, so "accept up to 4%" cannot be said at all until the
# count is at least 25, and 50 is the first count that also separates 2% from 4%.
UNDERLAY_PROBE_SAMPLES = 50

_PING_SENT = re.compile(r"(\d+) packets? transmitted")
# `N packets transmitted, N received` - the word "packets" appears once, before "transmitted". An
# earlier draft of this pattern asked for it before "received" too, parsed zero replies on every real
# transcript, and so made every leg read BLOCKED while the loss figure beside it said 0%.
_PING_RECV = re.compile(r"(\d+) received")
_PING_LOSS = re.compile(r"([\d.]+)% packet loss")
_PING_RTT = re.compile(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)")


def ping_result(out: str) -> typing.Optional[PingResult]:
    """Parse a `ping -c N` summary, or None when the text is not one.

    None is a third answer, kept distinct from 100% loss on purpose: "this output is not a measurement"
    (cut-off transcript, ping not installed, permission refused, an unfamiliar locale) and "this path is
    dead" are different faults with different fixes, and collapsing them means a broken probe gets
    diagnosed as an outage. Callers treat None as a refusal - fail-safe - but say which it was.
    """
    m_sent, m_loss = _PING_SENT.search(out), _PING_LOSS.search(out)
    if not m_sent or not m_loss:
        return None
    sent = int(m_sent.group(1))
    if sent <= 0:
        return None
    m_recv, m_rtt = _PING_RECV.search(out), _PING_RTT.search(out)
    return PingResult(sent, int(m_recv.group(1)) if m_recv else 0, float(m_loss.group(1)),
                      float(m_rtt.group(2)) if m_rtt else 0.0)


def icmp_verdict(res: typing.Optional[PingResult], vantage: str) -> tuple:
    """(reachable, band, detail) for one measured ping, against the thresholds above.

    `vantage` names where the probe was issued from, which is not a decoration. This infrastructure drops
    peer-to-peer TCP/UDP/ICMP between the two public addresses, and a probe aimed at an address the issuing
    host owns answers itself - so the same percentage means opposite things depending on who asked, and a
    report that omits the asker is unfalsifiable.
    """
    if res is None:
        return False, "NOT_MEASURED", f"{vantage}: no ping summary to parse"
    # One band per measurement, and reachability read off the band, so the two can never disagree. A
    # path that answered nothing is UNREACHABLE whatever the printed percentage says: `ping` reports
    # 100% loss only after it has given up, and an interface that is not there fails before that line.
    if res.received == 0:
        band, reachable = "UNREACHABLE", False
    elif res.loss_pct > UNDERLAY_LOSS_ACCEPT_PCT:
        band, reachable = "TOO_LOSSY", False
    elif res.loss_pct > UNDERLAY_LOSS_CLEAN_PCT:
        band, reachable = "MARGINAL", True
    else:
        band, reachable = "CLEAN", True
    detail = (f"{vantage}: loss={res.loss_pct:.1f}% replies={res.received}/{res.sent} "
              f"rtt_avg={res.rtt_avg_ms:.1f}ms")
    return reachable, band, detail


# Single Source of Truth: active protocols are resolved on every call so the sing-box opt-in
# toggle is honoured without a stale module-level snapshot.
def get_supported_protocols() -> list[str]:
    """Dynamic resolution of supported protocols adhering to opt-in toggles."""
    return protocols.get_supported_protocols()

def check_port_status(runner, port: int) -> dict:
    """Inspects port listeners and active socket connections."""
    # retryable asks whether a dropped session may re-issue this; safety.is_read_only_command(cmd)
    # then has to agree. Reads of socket state are the case worth recovering: they are the inputs to a
    # health verdict, and losing one to a network flap is how an outage report gets written about a
    # tunnel that was fine.
    _, listen_str, _ = runner.run(f"ss -tlnp | grep -E ':{port} '", best_effort=True, retryable=True)
    listen_str = listen_str.strip()

    _, active_str, _ = runner.run(f"ss -tinp 'sport = :{port}'", best_effort=True, retryable=True)
    active_str = active_str.strip()
    active_count = parse_active_connections_count(active_str, port)

    proc_name = ""
    pid = ""
    m = re.search(r'users:\(\("([^"]+)",pid=([0-9]+)', listen_str)
    if m:
        proc_name = m.group(1)
        pid = m.group(2)

    return {
        "port": port,
        "is_listening": bool(listen_str),
        "listener_raw": listen_str,
        "active_connections": active_count,
        "process_name": proc_name,
        "pid": pid
    }

def validate_server_side_port_release(port_info: dict, force_confirmed: bool = False,
                                      override_active_users: bool = False):
    """Enforces server-side security gates for port release.
    Rejects unauthorized or unsafe release attempts even if frontend modal is bypassed.
    """
    if not port_info["is_listening"]:
        return  # Port is already free, no release needed

    if not force_confirmed:
        raise PermissionError(
            f"SERVER GATE REJECTION: Port {port_info['port']} is occupied by "
            f"'{port_info['process_name']}' (PID {port_info['pid']}). "
            "Explicit user confirmation (force_confirmed=True) is required."
        )

    if port_info["active_connections"] > 0 and not override_active_users:
        raise PermissionError(
            f"SERVER GATE REJECTION: Port {port_info['port']} has {port_info['active_connections']} "
            "active live client connections. Release aborted to protect active sessions."
        )

def release_port_safely(runner, port: int, port_info: dict, dry_run: bool = True) -> dict:
    """Releases a protected port so a tunnel can bind it.

    Graceful, not zero-downtime: the incumbent is backed up, stopped through its systemd unit
    when one owns the listener, and the port is confirmed free before returning. Traffic on
    the displaced service stops here and does not resume.

    F11 (2026-10-24, live): the old code stopped by PROCESS NAME - `systemctl stop backhaul`
    for a unit named best-tunnel-prod-p1-backhaul-server, which does not exist, so the stop
    silently failed - and then killed the PID. systemd saw its unit's main process die and,
    under Restart, resurrected it 5 s later onto the same port, while the new rathole unit
    spun forever on EADDRINUSE and the deploy still reported success (its data probe
    answered through the resurrected incumbent). So: a unit-owned listener is stopped by
    UNIT NAME - an explicit systemctl stop is one systemd does not auto-restart - and the
    kill/fuser fallback runs only when no unit owns the process, where no Restart exists
    to resurrect it. A unit that will not free its port is reported, not killed.
    """
    validate_frontend_port(port)
    ts = int(time.time())
    backup_dir = f"/root/tunnel-backups/port-{port}-{ts}"
    runner.run(f"mkdir -p {backup_dir}", check=True)

    raw_proc = port_info.get("process_name")
    raw_pid = port_info.get("pid")
    proc = sanitize_proc_name(raw_proc) if raw_proc else ""
    pid = sanitize_pid(raw_pid) if (raw_pid and str(raw_pid).isdigit()) else None

    # Step 1: resolve the systemd unit that owns the listener, if any. ps reports the
    # unit for every process under systemd; slices and scopes are not services, so a
    # process started by hand (session scope) correctly resolves to no unit.
    unit = ""
    if pid:
        _, unit_out, _ = runner.run(f"ps -o unit= -p {pid}", best_effort=True)
        candidate = unit_out.strip().split()[0] if unit_out.strip() else ""
        if candidate and not candidate.endswith((".slice", ".scope")):
            unit = candidate

    # Step 2: back up the unit file when it is known, else the old process-name glob.
    if unit:
        runner.run(f"cp /etc/systemd/system/{unit} {backup_dir}/", best_effort=True)
    elif proc:
        runner.run(f"cp /etc/systemd/system/{proc}*.service {backup_dir}/", best_effort=True)

    # Step 3: stop through the unit when one exists; an explicit stop is not restarted.
    if unit:
        runner.run(f"systemctl stop {unit}", best_effort=True)
    elif proc:
        runner.run(f"systemctl stop {proc}", best_effort=True)

    # Step 4: verify the port freed. Only a listener with no owning unit may be killed:
    # killing a unit-owned process is the resurrection bug above.
    time.sleep(0.1 if dry_run else 2)
    st = check_port_status(runner, port)
    if st["is_listening"] and not unit:
        if pid:
            runner.run(f"kill -15 {pid}", best_effort=True)
        runner.run(f"fuser -k -15 {port}/tcp", best_effort=True)
        time.sleep(0.1 if dry_run else 2)
        st = check_port_status(runner, port)
    return {
        "success": not st["is_listening"],
        "backup_dir": backup_dir,
        "previous_proc": proc,
        "previous_pid": pid,
        "previous_unit": unit
    }

def rollback_port_release(runner, release_info: dict):
    """Rolls back port release by restoring previous service."""
    target = release_info.get("previous_unit") or release_info.get("previous_proc")
    if target:
        runner.run(f"systemctl start {target}", best_effort=True)

def measure_direct_base_rtt(ir_runner, fr_ip: str, dry_run: bool = True) -> BaseRTTResult:
    """Measures direct un-tunneled base RTT from Iran to Foreign host via ICMP ping (Senior Architect C3 & P0-4).
    Returns BaseRTTResult(base_rtt_ms, is_fallback).
    """
    if dry_run:
        return BaseRTTResult(42.0, True)

    try:
        _, ping_out, _ = ir_runner.run(f"ping -c 5 -W 2 {fr_ip}", best_effort=True, retryable=True)
        m_rtt = re.search(r'rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)', ping_out)
        if m_rtt:
            return BaseRTTResult(round(float(m_rtt.group(2)), 2), False)
    except Exception:
        pass
    # If un-tunneled ICMP fails, return 0.0 with is_fallback=True (P0-4)
    return BaseRTTResult(0.0, True)

def _leg_mbps(doc: dict, key: str):
    """The completed leg's Mbps, or None when that leg never reported a summary.

    None and 0.0 are different facts and stay different: a leg whose connection was refused was not
    measured, while a leg that completed and carried zero bytes measured a tunnel that carries nothing
    in that direction. Collapsing the two is what let a 1124 Mbps upload stand in for a dead download.
    """
    summary = (doc.get("end") or {}).get(key)
    if not isinstance(summary, dict) or "bits_per_second" not in summary:
        return None
    return round(float(summary.get("bits_per_second") or 0.0) / 1_000_000.0, 2)


def measure_iperf3_throughput(ir_runner, fr_runner, target_ip: str, port: int = 8898, dry_run: bool = False, streams: int = 4, duration: int = 10) -> dict:
    """Measures multi-stream iperf3 throughput in both directions across the active tunnel.

    Each direction is published as its own leg, and the single `throughput_mbps` scalar is the **weakest
    measured leg**, never an average of the two. The live GRE row measured 1124.19 Mbps one way and
    6.50 Mbps the other; averaging them published 565.35 as that tunnel's capacity, which is a number
    no user ever experienced in either direction, and it fed the 40% throughput weight of the
    ultraspeed profile. The weakest direction is what an interactive session is limited by, so it is
    what the scalar claims.
    Returns dict with available, legs, download_mbps, upload_mbps, throughput_mbps, capacity_basis and
    retransmits.
    """

    # 1. Verify iperf3 is present on both endpoints
    _, which_ir, _ = ir_runner.run("which iperf3", best_effort=True, retryable=True)
    _, which_fr, _ = fr_runner.run("which iperf3", best_effort=True, retryable=True)
    if not which_ir.strip() or not which_fr.strip():
        return {"available": False, "reason": "iperf3 binary missing on one or both endpoints"}

    # 2. Ephemeral iperf3 daemon on Foreign endpoint.
    # `fuser -k {port}/tcp` is the handover, and it kills the HTTP test origin too: the origin and iperf3
    # deliberately share the verified tunnel frontend port, because a bench tunnel only forwards that one
    # port. So iperf3 must stay the last stage of run_single_benchmark - nothing after here may assume the
    # origin is still listening.
    fr_runner.run(f"fuser -k {port}/tcp 2>/dev/null || true; kill $(cat /tmp/best-iperf-server.pid 2>/dev/null) 2>/dev/null || true", best_effort=True)
    fr_runner.run(f"nohup iperf3 -s -p {port} >/dev/null 2>&1 & echo $! > /tmp/best-iperf-server.pid", check=True)
    time.sleep(0.5)

    def _leg(reverse: bool) -> tuple[dict, str]:
        # -R makes the server stream for the full duration *after* the control exchange, so the client
        # blocks roughly twice as long as the forward leg. Budgeting it the same duration + 30 turned a
        # slow but working reverse stream into a paramiko channel timeout on the first live xray run.
        # Neither leg may raise: a timeout here means "this one number is unavailable", not "the
        # latency, loss, ladder and stability already measured on this tunnel are worthless".
        budget = (duration * 2 + 30) if reverse else (duration + 30)
        label = "reverse" if reverse else "forward"
        try:
            rc, out, err = ir_runner.run(
                f"iperf3 -c {target_ip} -p {port} -P {streams} -t {duration}{' -R' if reverse else ''} -J",
                best_effort=True, timeout=budget)
            try:
                doc = json.loads(out)
            except Exception:
                return {}, f"{label} leg returned no JSON (rc={rc}, stderr={err.strip()[:100]})"
            # iperf3 answers a failed test with a JSON document too - {"error": "..."} and no end.sum.
            # A parsed-but-empty document used to fall through as a measured 0.0 Mbps, which the first
            # live xray-reverse row reported as download_mbps=0.0 with leg_errors=[]: an unmeasured leg
            # indistinguishable from a leg that carried nothing.
            if doc.get("error"):
                return {}, f"{label} leg failed: {str(doc['error'])[:120]}"
            if "end" not in doc:
                return {}, f"{label} leg returned JSON with no end summary (rc={rc})"
            return doc, ""
        except Exception as ex:
            return {}, f"{label} leg did not complete ({type(ex).__name__}: {str(ex)[:120]})"

    try:
        # 3. Upload test (Iran -> Foreign), then 4. Download test (Foreign -> Iran, -R reverse)
        up_data, up_err = _leg(False)
        down_data, down_err = _leg(True)

        up_mbps = _leg_mbps(up_data, "sum_sent")
        down_mbps = _leg_mbps(down_data, "sum_received")
        retrans = int(((up_data.get("end") or {}).get("sum_sent") or {}).get("retransmits", 0) or 0)

        leg_errors = [e for e in (up_err, down_err) if e]
        legs = [{"direction": "upload", "mbps": up_mbps if up_mbps is not None else 0.0,
                 "measured": up_mbps is not None, "error": up_err},
                {"direction": "download", "mbps": down_mbps if down_mbps is not None else 0.0,
                 "measured": down_mbps is not None, "error": down_err}]
        measured = [l for l in legs if l["measured"]]
        flat = {"download_mbps": down_mbps if down_mbps is not None else 0.0,
                "upload_mbps": up_mbps if up_mbps is not None else 0.0,
                "legs": legs, "leg_errors": leg_errors}
        suffix = f" ({'; '.join(leg_errors)})" if leg_errors else ""

        if not measured:
            return dict(flat, available=False, throughput_mbps=0.0,
                        reason="iperf3 measured neither direction" + suffix)
        if not any(l["measured"] and l["mbps"] > 0 for l in measured):
            # Nothing flowed anywhere: that is an unmeasured capacity, not a capacity of zero, and the
            # ladder number keeps the row's throughput column while the reason says why.
            return dict(flat, available=False, throughput_mbps=0.0,
                        reason="iperf3 completed but carried zero bytes in every direction it measured"
                               + suffix)

        tp_mbps = round(min(l["mbps"] for l in measured), 2)
        out = dict(flat, available=True, throughput_mbps=tp_mbps,
                   capacity_basis="weakest_measured_leg", retransmits=retrans)
        notes = []
        if up_mbps is not None and down_mbps is not None:
            if min(up_mbps, down_mbps) > 0:
                ratio = max(up_mbps, down_mbps) / min(up_mbps, down_mbps)
                out["asymmetry_ratio"] = round(ratio, 1)
                if ratio > 4.0:
                    notes.append(f"legs differ by {ratio:.1f}x (up={up_mbps}, down={down_mbps}); "
                                 f"throughput_mbps is the weaker direction ({tp_mbps}), not an average "
                                 f"of two directions")
            else:
                starved = "upload" if up_mbps == 0 else "download"
                notes.append(f"the {starved} direction completed and carried zero bytes while the "
                             f"other carried {max(up_mbps, down_mbps)} Mbps; throughput_mbps reads "
                             f"{tp_mbps}, which is the finding, not a measurement gap")
        else:
            missing = "download" if down_mbps is None else "upload"
            present = "upload" if down_mbps is None else "download"
            notes.append(f"the {missing} direction was never measured, so throughput_mbps describes "
                         f"the {present} leg ({tp_mbps} Mbps) only")
        if notes:
            out["leg_note"] = "; ".join(notes)
        return out

    finally:
        fr_runner.run(f"kill $(cat /tmp/best-iperf-server.pid 2>/dev/null) 2>/dev/null || true; fuser -k {port}/tcp 2>/dev/null || true; rm -f /tmp/best-iperf-server.pid", best_effort=True)

# A benchmark that could not start is not a benchmark that performed badly, and recording them the
# same way puts a false performance verdict where FailoverCandidateSelector reads evidence about a
# transport. The live sweep (§7.7 step 7) hit this on its first protocol: the bench GRE unit failed
# with `add tunnel "gre0" failed: File exists`, because the kernel keys a GRE tunnel by its
# (local, remote) tuple and the production underlay already holds this host pair's tuple - so the
# bench namespace cannot come up beside a live deployment of the same protocol on the same hosts.
_ENV_BLOCK_PATTERNS = (
    (re.compile(r'add tunnel "[^"]*" failed: File exists|RTNETLINK answers: File exists'),
     "NOT_MEASURABLE: the tunnel this benchmark would create already exists on the host, so the bench "
     "namespace cannot start next to the live deployment. This is a property of the environment, not "
     "a performance verdict on the protocol."),
    (re.compile(r'address already in use|EADDRINUSE', re.IGNORECASE),
     "NOT_MEASURABLE: the benchmark's test port is already held by something else on the host. "
     "This is a property of the environment, not a performance verdict on the protocol."),
)


def classify_environment_block(text: str) -> str:
    """Return the not-measurable explanation for a failure the environment caused, else empty."""
    for pattern, message in _ENV_BLOCK_PATTERNS:
        if pattern.search(text or ""):
            return message
    return ""


# Transports whose entire anti-DPI claim *is* the outer TLS handshake. This is not the same property
# as "uses TLS": chisel-wss, wstunnel-v10, frp-TLS, backhaul-wss and xray-reverse carry their payload
# inside TLS, so a cleartext carrier around them leaks at most the SNI while the content stays
# encrypted. REALITY is different in kind - its payload is a plaintext `direct` relay terminated on the
# server's own loopback (witnessed in the W-series), so what it has to offer the wire is precisely the
# outer ClientHello, and a carrier that shows the wire that ClientHello has taken the one thing the
# transport was chosen for.
CAMOUFLAGE_IS_OUTER_TLS = ("singbox-vless-reality",)

GRE_CARRIER_REFUSAL = (
    "NOT_MEASURABLE: this transport's camouflage is its outer TLS handshake, and this pair's overlay "
    "arrives inside a cleartext GRE envelope (declared underlay carrier 'gre'), which puts that "
    "handshake on the wire where a DPI can read it. Measured on this pair, not assumed: the cover SNI "
    "appeared in cleartext inside IP protocol 47 traffic, and an independent TCP path does not exist "
    "here - TCP, UDP and ICMP from the peer never arrived in either direction (a listener bound on "
    ":50001 logged no connection while the initiator timed out), while protocols 47, 50 and 51 all did. "
    "The remedy is a carrier this product now builds: deploy ESP, which keys an SA by hand over "
    "protocol 50 - IKE is not available on this pair, since UDP 500 and 4500 are inside that dropped "
    "set - declares the pair's underlay as 'esp', and lifts this refusal. A public TCP path does the "
    "same. A refusal here is a fact about the deployment topology, not a performance verdict on the "
    "transport.")


def carrier_camouflage_block(pair: dict, protocol: str) -> str:
    """Refuse to benchmark or deploy a transport whose purpose the available carrier destroys.

    Returns the explanation, or empty when the combination is fine. Silent acceptance is the failure
    mode being avoided: the first live REALITY round scored 54.97 on a tunnel that deployed cleanly,
    measured honestly, and was simultaneously worthless as a deployment because GRE had already
    published its cover SNI to anyone reading the envelope.
    """
    if protocol in CAMOUFLAGE_IS_OUTER_TLS and protocols.dials_gre_underlay(pair):
        return GRE_CARRIER_REFUSAL
    return ""


def declare_carrier(pair_id: int, protocol: str, dry_run: bool) -> None:
    """Persist that this pair's overlay now arrives inside `protocol`'s envelope, with its inner addresses.

    Called on the success path only. The carrier declaration is what the gate above reads to decide
    whether REALITY's camouflage is on the wire in cleartext, so a rolled-back or previewed deployment
    must not leave one behind: a stale 'esp' would un-refuse a pair whose envelope was torn down with the
    attempt, and a dry run that wrote it would let the next preview pass a test nothing deployed.
    """
    if protocol not in protocols.CARRIER_PROTOCOLS or dry_run:
        return
    tun_ir, tun_fr = protocols.carrier_inner_pair(protocol, pair_id, "prod")
    storage.set_pair_underlay(pair_id, protocol.lower(), iran_dial_host=tun_ir,
                              foreign_dial_host=tun_fr)


def retract_carrier(pair_id: int, protocol: str, dry_run: bool) -> None:
    """Undo a carrier declaration: the envelope is gone, so neither it nor its inner addresses stay.

    The addresses go too, deliberately. Leaving them would make every later transport dial a dead /30
    with nothing on the pair to explain it - the failure this project has already been told to treat as a
    verdict on the transport rather than on the topology.
    """
    if protocol not in protocols.CARRIER_PROTOCOLS or dry_run:
        return
    storage.set_pair_underlay(pair_id, "", iran_dial_host="", foreign_dial_host="")


def carrier_inner_reachable(ir_runner, protocol: str, pair_id: int,
                            samples: int = UNDERLAY_PROBE_SAMPLES) -> tuple[bool, str]:
    """Ping the peer's inner address through the carrier interface - the only verdict a carrier accepts.

    A carrier has no daemon and no listening socket: its frontend is an iptables DNAT, which locally
    generated traffic never traverses. So neither `check_port_status` nor the L7 probe says anything about
    it, and that is why a failover *to* a carrier could never pass its smoke test. Inner ICMP through the
    interface is what proves the path: for ESP it also proves the SA pair, because a packet that gets no
    answer either way is indistinguishable only to a probe that does not look at the interface.

    Until #41 this was `"0% packet loss" in out` on a `ping -c 2`, which is not a threshold: the only
    answers it could give were 0%, 50% and 100%, so one dropped packet in two failed a deploy and could
    trigger a switchover on a path carrying 2-4% random loss - the loss this pair's own underlay measures.
    It now counts enough samples for the threshold to mean something and judges the percentage.
    """
    iface = protocols.carrier_iface(protocol, pair_id, "prod")
    target = protocols.carrier_inner_pair(protocol, pair_id, "prod")[1]
    # The SSH read timeout has to outlast the ping's own worst case (packets x interval, plus a -W per
    # unanswered packet), or a lossy path is reported as a transport error instead of as loss - the
    # invariant the benchmark's ping probes at step 4 already state.
    _, out, _ = ir_runner.run(f"ping -c {samples} -i 0.2 -W 1 -I {iface} {target}",
                              best_effort=True, timeout=samples * 0.2 + 25.0, retryable=True)
    reachable, band, detail = icmp_verdict(ping_result(out), f"iran via {iface}")
    return reachable, f"{band} {detail}"


def _local_addresses(pair: dict, side: str) -> set:
    """Every address the issuing side itself holds, so a probe aimed at one of them can be called a loop.

    An answer from an address the prober owns is not evidence about a path: it is the stack replying to
    itself. This round measured the live shape of that - Iran's own frontend :443 answered a probe issued
    *from Iran* while nothing at all was being carried, because a PREROUTING DNAT never intercepts locally
    generated traffic - and a preflight that counts such a reply as success reports a dead tunnel healthy.
    """
    spec = pair.get(side) or {}
    out = {str(spec.get("host") or "").strip(), str(spec.get("dial_host") or "").strip(),
           str(pair.get(f"{side}_dial_host") or "").strip(), str(pair.get(f"{side}_host") or "").strip()}
    carrier = protocols.carrier_kind(pair)
    if carrier in ("gre", "esp"):
        # Side-aware, and it has to be: the tuple is (Iran, Foreign), so the address this host holds is
        # index 0 from Iran and index 1 from Foreign. Reading index 0 on both sides left the Foreign
        # preflight holding Iran's inner address as "local" and its own as a remote target.
        inner = protocols.carrier_inner_pair(carrier.upper(), int(pair.get("id") or 1), "prod")
        out.add(inner[0] if side == "iran" else inner[1])
    out.discard("")
    return out


def _is_self_answer(pair: dict, side: str, target: str) -> bool:
    return bool(target) and (target.startswith("127.") or target in _local_addresses(pair, side))



def underlay_preflight(pair: dict, ir_runner, fr_runner,
                       samples: int = UNDERLAY_PROBE_SAMPLES, dry_run: bool = True) -> dict:
    """Measure the underlay in each direction before a deploy is asked to trust it, with loss in thresholds.

    Why this exists rather than another `check_port_status`: three separate confusions this round had to
    measure out of the way. (1) "Frontend listening" is not "carried by this tunnel"; during a firewall
    outage a local connect to the frontend still returned open with zero rules installed behind it. (2) A
    probe from one endpoint to the other's *public* address tells you nothing on infrastructure that
    filters peer-to-peer ICMP - and on that infrastructure the carrier dataplane is exactly the thing the
    inner probe, and only the inner probe, can name. (3) A ping that loses 1 packet in 2 is not 50% down;
    thresholds need a sample that can express them, so all legs count `samples` packets and are judged by
    `icmp_verdict`, with 2-4% loss reported as MARGINAL rather than as health or as failure.

    Each direction yields: the outer address the carrier envelope is built to (informational - a filtered
    management path reads 100% here and is normal), the carrier's inner peer through its interface (the
    leg that decides for GRE/ESP), and the peer's `dial_host` - the address every non-carrier transport
    dials - reached through the underlay. `ok` is decided by the legs that can name the path, never by the
    outer one when a carrier exists.
    """
    pair_id = int(pair.get("id") or 1)
    carrier = protocols.carrier_kind(pair)
    # `carrier_kind` speaks lowercase ('gre' | 'esp' | 'public') and the interface, inner-pair and
    # dial-address helpers are all keyed on the protocol names in CARRIER_PROTOCOLS, which are uppercase.
    # Comparing one to the other silently reports "no carrier" - so the two spellings are separated here
    # once, rather than at each call.
    has_carrier = carrier in ("gre", "esp")
    proto = carrier.upper() if has_carrier else ""
    frontend = pair.get("frontend_port", pair.get("frontend", 443))
    legs = []
    for side, runner, peer_side in (("iran", ir_runner, "foreign"), ("foreign", fr_runner, "iran")):
        if runner is None and not dry_run:
            continue
        # A dry run has no runners by construction - the dashboard opens none on a dry-run host, and this
        # function's own default is dry - so skipping a side for lacking one would report "0 legs would be
        # measured" to the operator, which is the same silence as not calling the function at all. The dry
        # branch of `record` below never touches the runner.

        def record(kind, target, cmd, vantage, decides):
            """One leg. On a dry run the targets are walked and listed, and nothing is sent.

            Listing them without probing is the point: the caller still sees what the round would have
            measured, and a percentage invented by an unanswered mock ping would be the exact thing this
            function exists to keep out of a verdict.
            """
            if dry_run:
                legs.append({"from": side, "kind": kind, "target": target, "reachable": False,
                             "band": "WOULD_MEASURE", "decides": decides,
                             "detail": f"{vantage}: would probe (dry run)"})
                return
            _, out, _ = runner.run(cmd, best_effort=True, timeout=samples * 0.2 + 25.0, retryable=True)
            reach, band, detail = icmp_verdict(ping_result(out), vantage)
            legs.append({"from": side, "kind": kind, "target": target, "reachable": reach, "band": band,
                         "decides": decides, "detail": detail})

        peer_spec = pair.get(peer_side) or {}
        outer = protocols.dial_address(peer_spec, proto) or str(peer_spec.get("host") or "")
        if _is_self_answer(pair, side, outer):
            legs.append({"from": side, "kind": "outer", "target": outer, "reachable": False,
                         "band": "SELF_ANSWER", "decides": False,
                         "detail": f"{side} -> {outer} is an address this host holds: a reply proves nothing"})
            continue
        record("outer", outer, f"ping -c {samples} -i 0.2 -W 1 {outer}", f"{side} -> outer {outer}",
               not has_carrier)

        if has_carrier:
            iface = protocols.carrier_iface(proto, pair_id, "prod")
            inner = protocols.carrier_inner_pair(proto, pair_id, "prod")
            # (Iran, Foreign) - so which end is *this* host depends on who is asking, and the probe has to
            # be aimed at the other one. Taking index [1] for both sides measures Foreign answering itself,
            # which is the one result a preflight must never print as a pass.
            inner_local, inner_peer = (inner if side == "iran" else (inner[1], inner[0]))
            record("inner", inner_peer, f"ping -c {samples} -i 0.2 -W 1 -I {iface} {inner_peer}",
                   f"{side}({inner_local}) -> inner {inner_peer} via {iface}", True)

            dial = protocols.dial_address(peer_spec, "")
            # A pair whose dial address *is* the carrier's inner peer needs no second probe of it; issuing
            # one anyway would double-count the same fact and make the leg count meaningless.
            if dial and dial not in (outer, inner_peer) and not _is_self_answer(pair, side, dial):
                record("dial_host", dial, f"ping -c {samples} -i 0.2 -W 1 {dial}",
                       f"{side} -> dial_host {dial}", True)

    deciding = [l for l in legs if l["decides"]]
    failing = [l for l in deciding if not l["reachable"]]
    marginal = [l for l in deciding if l["band"] == "MARGINAL"]
    if dry_run:
        summary = (f"DRY_RUN: {len(legs)} legs would be measured across "
                   f"{(proto or 'public').upper()} underlay (thresholds: clean <= "
                   f"{UNDERLAY_LOSS_CLEAN_PCT}%, accept <= {UNDERLAY_LOSS_ACCEPT_PCT}%, "
                   f"{samples} samples)")
        return {"ok": False, "dry_run": True, "carrier": carrier, "samples": samples,
                "frontend": frontend, "thresholds": {"clean_pct": UNDERLAY_LOSS_CLEAN_PCT,
                                                     "accept_pct": UNDERLAY_LOSS_ACCEPT_PCT},
                "legs": legs, "summary": summary}
    if not deciding:
        verdict = "NOT_MEASURED"
    elif failing:
        verdict = "BLOCKED"
    elif marginal:
        verdict = "MARGINAL"
    else:
        verdict = "CLEAN"
    summary = (f"{verdict}: {len(deciding) - len(failing)}/{len(deciding)} deciding legs within "
               f"{UNDERLAY_LOSS_ACCEPT_PCT}% loss over {samples} samples "
               f"({len(marginal)} marginal)")
    if has_carrier and any(l["kind"] == "outer" and l["band"] == "UNREACHABLE" for l in legs):
        summary += "; outer ICMP to the public address is filtered on this infrastructure, which is " \
                   "why the inner leg decides"
    return {"ok": verdict in ("CLEAN", "MARGINAL"), "dry_run": False, "verdict": verdict,
            "carrier": carrier, "samples": samples, "frontend": frontend,
            "thresholds": {"clean_pct": UNDERLAY_LOSS_CLEAN_PCT, "accept_pct": UNDERLAY_LOSS_ACCEPT_PCT},
            "legs": legs, "summary": summary}


# --- Host resource telemetry (round 063, ruling 1) ---------------------------------------------
#
# One command per reading, and every command is already provably inert: this sampler runs on the live
# hosts through the same SafeSSHRunner that gates a deploy, so its vocabulary is bounded by what
# `safety.is_read_only_command` checks in the *text* - which rules out `vmstat`/`iostat`/`nstat` (not
# allowlisted) and rules out piping to `grep`, since a `|` anywhere - even inside a quoted pattern -
# disqualifies the whole line. So the raw files are read and parsed here, in Python. Nothing was widened
# to make this sampler fit; item #53 stands.
#
# `uptime` and `boot_id` are separate readings on purpose. Seconds-since-boot on its own is also what a
# clock reset looks like, and the reboot pentest (ruling 3) needs a witness that distinguishes "this
# kernel started again" from "the monotonic counter moved": boot_id is regenerated by the kernel at each
# boot, so uptime falling while boot_id holds constant is a defect to chase, not a successful reboot.
RESOURCE_SAMPLE_COMMANDS = (
    ("load", "cat /proc/loadavg"),
    ("cpu_count", "nproc"),
    ("memory", "cat /proc/meminfo"),
    ("disk", "df -P / /var"),
    ("uptime", "cat /proc/uptime"),
    ("boot_id", "cat /proc/sys/kernel/random/boot_id"),
    # Round 063 item #70 (open finding #64): Foreign's episodic connection bursts were attributed by
    # hand in report062 because nothing in the product could answer "how many sockets, and how many
    # failed handshakes". These three reads are that instrument. They are still one `cat` of one procfs
    # file each - `ss`, `netstat` and a pipe were not needed and are not used - so `safety`'s own
    # classifier admits them without anything being widened (#53 stands).
    #
    # The addresses in /proc/net/tcp are never kept: the parser counts sockets per TCP state and throws
    # the rows away, so a table of thousands of peer addresses cannot become a table of thousands of
    # peer addresses in the database.
    ("tcp", "cat /proc/net/snmp"),
    ("tcp_ext", "cat /proc/net/netstat"),
    ("sockets", "cat /proc/net/tcp /proc/net/tcp6"),
)
RESOURCE_SAMPLE_TIMEOUT = 15.0

# The states one reading can come back in. They are kept apart because each names a different fault with
# a different fix, and collapsing them is how a missing sensor gets reported as an idle machine:
#   measured  text arrived and every field this parser needs parsed
#   partial   some fields parsed and some did not (a kernel without MemAvailable; a `df` that could not
#             stat one of its two arguments while the other answered, which exits non-zero *and* prints)
#   empty     exit 0 with zero bytes - the read succeeded and returned nothing
#   absent    the host says this file is not there
#   failed    non-zero exit for any other reason (permission, EIO, a truncated transcript)
#   unparsed  text that this parser does not recognise (a wrapped df header, an unfamiliar locale)
RESOURCE_STATES = ("measured", "partial", "empty", "absent", "failed", "unparsed")
# A reading in either of these states carries usable numbers. Everything else carries None.
RESOURCE_USABLE = ("measured", "partial")
# Past this age a stored sample stops describing the host and has to say so. Capacity is sampled when an
# operator asks for it, so a pair page that has been open since before a deploy still holds the numbers
# taken before it; showing them unmarked is how a stale row gets read as a current one.
RESOURCE_STALE_AFTER_SEC = 180

_LOAD_RE = re.compile(r"^\s*([\d.]+)(?:\s+([\d.]+))?(?:\s+([\d.]+))?")
_INT_RE = re.compile(r"^\s*(\d+)")
_MEM_KB = re.compile(r"^(\w+):\s+(\d+)\s*kB", re.M)
_UPTIME_RE = re.compile(r"^\s*([\d.]+)")
_BOOT_ID_RE = re.compile(
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")

# The counters a burst is attributed from, named exactly as the kernel names them so a reader can put the
# stored row next to `cat /proc/net/snmp` and match them by eye. `Tcp:` counters are the connection-level
# story (who opened, who failed, who retransmitted); `TcpExt:` counters are the story of the service not
# keeping up (an accept queue that overflowed is a burst that arrived faster than the listener drained).
TCP_SNMP_COUNTERS = ("ActiveOpens", "PassiveOpens", "AttemptFails", "EstabReseds", "CurrEstab",
                     "InSegs", "OutSegs", "RetransSegs", "OutRsts")
TCP_EXT_COUNTERS = ("ListenOverflows", "ListenDrops", "TCPTimeouts", "TCPSynRetrans")
# Every one of these is monotonic since boot: a value that went *down* between two samples means the
# counters restarted (a real boot, or a kernel module reload), never that traffic stopped. `CurrEstab` is
# deliberately absent - it is a gauge, and gauges are compared to gauges.
TCP_MONOTONIC_COUNTERS = ("ActiveOpens", "PassiveOpens", "AttemptFails", "EstabReseds", "InSegs",
                          "OutSegs", "RetransSegs", "OutRsts", "ListenOverflows", "ListenDrops",
                          "TCPTimeouts", "TCPSynRetrans")
_TCP_STATE_NAMES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
                    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
                    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV"}
# A socket table bigger than this is not sampled further: the count is reported as truncated rather than
# as a number that quietly stopped meaning the whole table.
SOCKET_SCAN_LIMIT = 20000


def _procfs_counter_block(body: str, label: str):
    """The name->raw-value dict of one procfs `label:` block, or None when the file has no such block.

    /proc/net/snmp and /proc/net/netstat print a header line and a value line per protocol, both starting
    with the same label. Matching the label exactly is not pedantry: a `Tcp:` that was really read out of a
    `TcpExt:` block would attribute the listening queue's numbers to the connection counters.
    """
    rows = [ln.split() for ln in (body or "").splitlines() if ln.strip()]
    for i, toks in enumerate(rows):
        if toks[0] != label:
            continue
        names = toks[1:]
        if i + 1 >= len(rows):
            return None
        values = rows[i + 1]
        if values[0] != label or len(values) - 1 < len(names):
            return None
        return dict(zip(names, values[1:]))
    return None


def _count_socket_states(body: str):
    """(counts per TCP state, rows seen, truncated) from /proc/net/tcp[6] text. Addresses are dropped.

    Column 3 of a `/proc/net/tcp` row is the hex state code; `sl` is the header. Anything that is neither
    is not a socket row and is ignored rather than guessed at, so an unfamiliar kernel column layout reads
    as an empty table (and `header_seen` below says which of the two it was) instead of as a count.
    """
    counts: dict = {}
    rows = 0
    truncated = False
    for line in (body or "").splitlines():
        tok = line.split()
        if len(tok) < 4 or tok[0] == "sl":
            continue
        state = _TCP_STATE_NAMES.get(tok[3].upper())
        if state is None:
            continue
        rows += 1
        if rows > SOCKET_SCAN_LIMIT:
            truncated = True
            break
        counts[state] = counts.get(state, 0) + 1
    return counts, rows, truncated


def _reading_state(rc: int, text: str, parsed: bool, complete: bool, err: str = "",
                   multi_source: bool = False) -> str:
    """One verdict per reading, from its own exit status and its own text - never inherited from another.

    `multi_source` is for a command that reads several things at once (`df -P / /var`): there a non-zero
    exit alongside parsed output is one source missing, not the whole read failing. For a single-file read
    the same shape is a failure, because exit 0 from `cat` is the only answer that means the file was read.
    """
    body = text or ""
    if rc != 0 and not (multi_source and parsed):
        return "absent" if "No such file" in (err or "") else "failed"
    if not body.strip():
        return "empty"
    if not parsed:
        return "unparsed"
    # A multi-source command that answered *and* failed is `partial` whatever its fields look like: one of
    # its sources is missing, and reporting that read as `measured` is how a mount stops being watched.
    if rc != 0:
        return "partial"
    return "measured" if complete else "partial"


def parse_resource_reading(name: str, text: str, rc: int = 0,
                           err: str = "") -> tuple[dict, str]:
    """(fields, state) for one raw reading. Pure: no runner, no clock, nothing written.

    Fields that were not found stay None rather than 0. A host whose MemAvailable line is missing is not a
    host with zero available memory, and a df row that failed to parse is not a full disk - both of those
    collapsed readings were paid for earlier in this project, in a capacity score and in a health verdict.
    """
    body = text or ""
    fields: dict = {}
    if name == "load":
        m = _LOAD_RE.search(body)
        vals = [float(g) for g in (m.groups() if m else ()) if g is not None]
        vals += [None] * (3 - len(vals))
        fields = dict(zip(("load1", "load5", "load15"), vals))
        return fields, _reading_state(rc, body, bool(m), all(v is not None for v in vals), err)
    if name == "cpu_count":
        m = _INT_RE.search(body)
        n = int(m.group(1)) if m else None
        fields = {"ncpu": n if (n or 0) > 0 else None}
        return fields, _reading_state(rc, body, bool(m), fields["ncpu"] is not None, err)
    if name == "memory":
        found = {k: int(v) for k, v in _MEM_KB.findall(body)}
        # (source line key, field name this product persists) - an explicit pair, because the key that
        # reads `MemAvailable` and the column that stores it are not required to rhyme with each other.
        want = (("MemTotal", "mem_total_kb"), ("MemAvailable", "mem_available_kb"),
                ("SwapTotal", "swap_total_kb"), ("SwapFree", "swap_free_kb"))
        fields = {out_k: found.get(src_k) for src_k, out_k in want}
        # Every field this source can produce is present as a key even when it was not found, so a caller
        # indexing the dict gets None and not a KeyError halfway through building a row.
        fields["mem_used_kb"] = fields["mem_used_pct"] = None
        total, avail = found.get("MemTotal"), found.get("MemAvailable")
        if total and avail is not None and total >= avail:
            fields["mem_used_kb"] = total - avail
            fields["mem_used_pct"] = round(100.0 * (total - avail) / total, 1)
        # MemTotal without MemAvailable is a partial read, not a failure: the field was added in Linux 3.4
        # and its absence is a fact about this kernel that the caller has to be able to see.
        parsed = any(v is not None for v in fields.values())
        complete = fields["mem_total_kb"] is not None and fields["mem_available_kb"] is not None
        return fields, _reading_state(rc, body, parsed, complete, err)
    if name == "disk":
        mounts = []
        for line in body.splitlines():
            tok = line.split()
            # `df -P` data rows are: fs total used avail pct mount(-may-contain-spaces-tail-excepted).
            # The POSIX format guarantees the five numeric columns precede the mount point, so the last
            # token is the mount and anything before the first of the five numbers is the device name.
            if len(tok) < 6 or not tok[-2].rstrip("%").isdigit():
                continue
            try:
                total, used, avail = (int(tok[-5]), int(tok[-4]), int(tok[-3]))
                pct = float(tok[-2].rstrip("%"))
            except ValueError:
                continue
            mounts.append({"fs": " ".join(tok[:-5]), "mount": tok[-1], "total_kb": total,
                           "used_kb": used, "avail_kb": avail, "used_pct": pct})
        fields = {"mounts": mounts}
        if mounts:
            fullest = max(mounts, key=lambda m: m["used_pct"])
            fields["fullest_mount"] = fullest["mount"]
            fields["fullest_used_pct"] = fullest["used_pct"]
            root = next((m for m in mounts if m["mount"] == "/"), None)
            for key in ("total_kb", "used_kb", "avail_kb", "used_pct"):
                fields[f"root_{key}"] = root[key] if root else None
        return fields, _reading_state(rc, body, bool(mounts), bool(mounts), err, multi_source=True)
    if name == "uptime":
        m = _UPTIME_RE.search(body)
        fields = {"uptime_sec": float(m.group(1)) if m else None}
        return fields, _reading_state(rc, body, bool(m), fields["uptime_sec"] is not None, err)
    if name == "boot_id":
        m = _BOOT_ID_RE.search(body)
        fields = {"boot_id": m.group(1).lower() if m else None}
        return fields, _reading_state(rc, body, bool(m), fields["boot_id"] is not None, err)
    if name in ("tcp", "tcp_ext"):
        label = "Tcp:" if name == "tcp" else "TcpExt:"
        want = TCP_SNMP_COUNTERS if name == "tcp" else TCP_EXT_COUNTERS
        block = _procfs_counter_block(body, label) or {}
        found = {}
        for key in want:
            raw = block.get(key)
            if raw is not None and str(raw).isdigit():
                found[key] = int(raw)
        # Fields that were looked for and not found are present as None, so a caller that reads
        # `fields["ListenDrops"]` gets "not read" and not a KeyError on the way to a stored row.
        fields = {k: found.get(k) for k in want}
        parsed = bool(found)
        complete = len(found) == len(want)
        return fields, _reading_state(rc, body, parsed, complete, err)
    if name == "sockets":
        counts, rows, truncated = _count_socket_states(body)
        header_seen = any(ln.split()[:1] == ["sl"] for ln in body.splitlines())
        fields = {"socket_states": counts, "socket_rows": rows, "socket_truncated": truncated}
        # An empty table with a header is a reading (nothing is connected), while no header at all is not -
        # collapsing the two is how "no sockets" and "cannot see the sockets" would print the same.
        parsed = header_seen
        complete = header_seen and not truncated and rc == 0
        return fields, _reading_state(rc, body, parsed, complete, err, multi_source=True)
    return {}, "unparsed"


def collect_host_resources(runner, pair_id: int = 0, host_role: str = "",
                           dry_run: bool = True, no_session_reason: str = None) -> dict:
    """Read one host's CPU, memory, disk and boot state over an existing session; touch nothing else.

    Returns a per-source verdict plus the flat row a caller can persist. `dry_run` issues no command at
    all and records nothing - the same fail-safe every other entry point in this module obeys, and the
    reason the dashboard can offer a preview of capacity sampling without opening a host session.

    A source that cannot be read is reported as its own state and its numbers stay None. The whole call
    never substitutes a zero: `load1=0.0` on a host whose /proc was unreadable is what an idle machine
    looks like to every consumer of this row, and an operator who acts on that restarts services on the
    host that was actually in trouble.

    `runner=None` is two different sentences and only one of them may be written down: "nobody opened a
    session" (no row, nothing invented) and "a session was asked for and the host refused it" (a
    `reachable=0` row, which is the reboot dark window having a start and an end in the history instead of
    being an absence). The caller proves which one it means by passing `no_session_reason` - the exception
    text it caught - so the ambiguity is refused at the write gate rather than resolved by a guess.
    """
    if dry_run:
        return {"pair_id": pair_id, "host_role": host_role, "dry_run": True, "ok": False,
                "sources": [name for name, _ in RESOURCE_SAMPLE_COMMANDS], "readings": {},
                "row": None,
                "summary": (f"DRY_RUN: {len(RESOURCE_SAMPLE_COMMANDS)} read-only sources would be "
                            f"sampled on {host_role or 'host'} (nothing was sent, nothing recorded)")}
    if runner is None:
        detail = storage.mask_addresses(str(no_session_reason or ""))[:200]
        if not no_session_reason:
            return {"pair_id": pair_id, "host_role": host_role, "dry_run": False, "ok": False,
                    "no_session": True, "refused": "no_session_undocumented", "readings": {},
                    "row": None,
                    "summary": (f"{host_role or 'host'}: no session and no recorded reason, so nothing was "
                                f"written - an untried host is not an unreachable one")}
        readings = {name: {"cmd": cmd, "rc": -1, "state": "failed", "detail": detail,
                           **parse_resource_reading(name, "", rc=-1, err="")[0]}
                    for name, cmd in RESOURCE_SAMPLE_COMMANDS}
        row = resource_row(pair_id, host_role, readings)
        return {"pair_id": pair_id, "host_role": host_role, "dry_run": False, "ok": False,
                "no_session": True, "missing": [name for name, _ in RESOURCE_SAMPLE_COMMANDS],
                "readings": readings, "row": row,
                "summary": (f"0/{len(readings)} sources usable on {host_role or 'host'}: no session could "
                            f"be opened ({detail or 'no reason given'})")}
    readings: dict = {}
    for name, cmd in RESOURCE_SAMPLE_COMMANDS:
        try:
            rc, out, err = runner.run(cmd, best_effort=True, timeout=RESOURCE_SAMPLE_TIMEOUT,
                                      retryable=True)
        except Exception as ex:
            # A session that died is a *reading of "not readable"*, not the absence of a reading. This is
            # the shape the reboot pentest (ruling 3) needs: while a host is coming back, every one of
            # these nine calls raises, and if the first raise escaped, the sampler would store no row at
            # all and the dark window would look identical to "nobody sampled". Here it stores a row whose
            # every source says `failed`, whose `reachable` is 0, and whose detail names the fault - so the
            # gap has a start and an end in the history instead of being a gap.
            readings[name] = {"cmd": cmd, "rc": -1, "state": "failed", "detail": "",
                              **parse_resource_reading(name, "", rc=-1, err="")[0]}
            readings[name]["detail"] = storage.mask_addresses(f"{type(ex).__name__}: {ex}")[:200]
            continue
        fields, state = parse_resource_reading(name, out, rc, err)
        readings[name] = {"cmd": cmd, "rc": int(rc), "state": state, **fields}
        if state not in RESOURCE_USABLE:
            # Error text is kept for the operator and masked on the way in, because the runner prefixes
            # failures with the host it addressed - the exact shape that carried a routable address into
            # the audit log once already (#28).
            readings[name]["detail"] = storage.mask_addresses((err or "").strip())[:200]
    missing = [n for n, _ in RESOURCE_SAMPLE_COMMANDS if readings[n]["state"] not in RESOURCE_USABLE]
    row = resource_row(pair_id, host_role, readings)
    counts = {}
    for r in readings.values():
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    summary = (f"{len(readings) - len(missing)}/{len(readings)} sources usable on "
               f"{host_role or 'host'}: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if missing:
        summary += f"; unusable: {', '.join(missing)}"
    return {"pair_id": pair_id, "host_role": host_role, "dry_run": False, "ok": not missing,
            "missing": missing, "readings": readings, "row": row, "summary": summary}


def resource_row(pair_id: int, host_role: str, readings: dict) -> dict:
    """The flat, persistable projection of a set of readings - None where a source was not usable.

    Derived rather than accumulated: a caller that builds the row by writing fields as it samples can put
    a number in that no successful read produced, which is the laundering path this function closes. Only
    sources in a usable state contribute, and each contributes only the fields its parser actually found.
    """
    def usable(name):
        r = readings.get(name) or {}
        return r if r.get("state") in RESOURCE_USABLE else {}

    load, cpus, mem = usable("load"), usable("cpu_count"), usable("memory")
    disk, upt, boot = usable("disk"), usable("uptime"), usable("boot_id")
    tcp, tcp_ext, socks = usable("tcp"), usable("tcp_ext"), usable("sockets")
    load1, ncpu = load.get("load1"), cpus.get("ncpu")
    counters = {}
    for src, keys in ((tcp, TCP_SNMP_COUNTERS), (tcp_ext, TCP_EXT_COUNTERS)):
        for key in keys:
            # A key that this source was asked for and did not produce is stored as None, so the
            # attribution step sees "this counter was never read" rather than "it read as zero".
            if key in src:
                counters[key] = src.get(key)
    socket_states = dict(socks.get("socket_states") or {})
    return {
        "pair_id": int(pair_id), "host_role": host_role or "",
        "load1": load1, "load5": load.get("load5"), "load15": load.get("load15"), "ncpu": ncpu,
        "load1_per_core_pct": (round(100.0 * load1 / ncpu, 1) if load1 is not None and ncpu else None),
        "mem_total_kb": mem.get("mem_total_kb"), "mem_available_kb": mem.get("mem_available_kb"),
        "mem_used_pct": mem.get("mem_used_pct"),
        "swap_total_kb": mem.get("swap_total_kb"), "swap_free_kb": mem.get("swap_free_kb"),
        "disk_total_kb": disk.get("root_total_kb"), "disk_used_kb": disk.get("root_used_kb"),
        "disk_avail_kb": disk.get("root_avail_kb"), "disk_used_pct": disk.get("root_used_pct"),
        "disk_fullest_mount": disk.get("fullest_mount"),
        "disk_fullest_used_pct": disk.get("fullest_used_pct"),
        "uptime_sec": upt.get("uptime_sec"), "boot_id": boot.get("boot_id"),
        # `tcp_counters` and `socket_states` are the two halves of the burst question: the first is what
        # happened since boot (monotonic, so a *difference* between rows is the event), the second is what
        # is connected right now (a gauge, and the only one that can still show SYN_RECV after the
        # connections that produced the burst have gone away).
        "tcp_counters": counters, "socket_states": socket_states,
        "estab_conns": socket_states.get("ESTABLISHED"),
        # 0 means "this host answered nothing" - the dark window's own witness. It is derived here rather
        # than left to a consumer to infer from nine state strings, because inferring it is the step where
        # a reader reaches for a zero.
        "reachable": (1 if any((readings.get(name) or {}).get("state") in RESOURCE_USABLE
                               for name, _ in RESOURCE_SAMPLE_COMMANDS) else 0),
        "source_states": {name: (readings.get(name) or {}).get("state", "unparsed")
                          for name, _ in RESOURCE_SAMPLE_COMMANDS},
    }


def collect_pair_resources(pair: dict, ir_runner, fr_runner, dry_run: bool = True,
                           record: bool = False, no_session_reasons: dict = None) -> dict:
    """Sample both hosts of a pair and, only when asked and only for real, persist one row per host.

    `record` defaults to False for the reason `destination_pin_block`'s `record` was flipped to False in
    report056: a caller that is judging whether a pair is healthy must not leave a durable row behind, and
    a preview that recorded would make the next preview look like a measurement. A dry run refuses to
    record regardless of the flag - the write path needs a sample that came from a host.

    `no_session_reasons` names, per role, the exception that stopped that host's session from opening. It is
    what lets a pass through a reboot write the outage instead of skipping it, and it is per-role on purpose:
    Foreign refusing a connection says nothing about whether Iran was merely never tried.
    """
    pair_id = int(pair.get("id") or 1)
    sides = (("iran", ir_runner), ("foreign", fr_runner))
    hosts, rows = {}, []
    for role, runner in sides:
        # The dry-run branch comes first, and not by taste: a caller that hands runners *and* dry_run=True
        # is asking for a preview, and a preview that reads the hosts because a session happened to be open
        # is the fail-open this project's default was built to prevent. Found by test_94, not by reading.
        if dry_run:
            sample = collect_host_resources(runner, pair_id, role, dry_run=True)
        elif runner is None:
            sample = collect_host_resources(None, pair_id, role, dry_run=False,
                                            no_session_reason=(no_session_reasons or {}).get(role))
        else:
            sample = collect_host_resources(runner, pair_id, role, dry_run=False)
        hosts[role] = sample
        if sample.get("row"):
            rows.append(sample["row"])
    stored = 0
    if record and not dry_run:
        for row in rows:
            stored += 1 if storage.record_host_resources(row) else 0
    return {"pair_id": pair_id, "dry_run": dry_run, "recorded": stored, "hosts": hosts,
            "ok": bool(rows) and all(h["ok"] for h in hosts.values() if h.get("row") is not None),
            "summary": " | ".join(f"{role}: {h['summary']}" for role, h in hosts.items())}


# --- Connection-burst attribution (round 063, item #70 closing open finding #64) -----------------
#
# Report062 found Foreign taking episodic connection bursts and could only attribute them by hand: an
# operator was SSHed in running `ss` and reading `TcpExt:TCPTimeouts=4643` with five SYN-RECV sockets
# stuck at six retransmits. This is that reading made durable. The kernel's own counters answer two
# different questions and only their combination attributes a burst: `Tcp:`/`TcpExt:` are monotonic since
# boot, so a *difference* between two samples is the event (how many handshakes failed, how many times the
# accept queue overflowed), while `/proc/net/tcp` is a gauge, so it is the only thing that still shows the
# shape of what is connected after the burst itself has gone.
#
# Why there is no "burst threshold" constant to copy from a manual: the baseline is the host's own history.
# A rate three times the median of its own quiet intervals is a burst *on that host*; an absolute
# connections-per-second number would be a guess about a workload nobody here has measured - the same
# mistake as the 42 ms `base_rtt` fallback that put a healthy tunnel one poll from a needless switchover.
# So a short history says `NOT_ENOUGH_HISTORY` instead of deciding, and a counter that went *backwards*
# says `counter_reset` and contributes nothing, because a restart makes every difference below it
# meaningless and reading that as "no traffic" is how an outage is reported as an idle night.
CONN_FAIL_SHARE_STORM = 0.5
CONN_OUTBOUND_DOMINANT = 2.0
CONN_BURST_FACTOR = 3.0
CONN_MIN_BURST_CONNECTIONS = 25
CONN_MIN_BASELINE_INTERVALS = 3


def _row_counters(row: dict) -> dict:
    """The stored JSON columns of one row, parsed defensively: a damaged blob reads as "not recorded"."""
    out = {}
    for key in ("tcp_counters", "socket_states", "source_states"):
        raw = row.get(key)
        if isinstance(raw, str):
            try:
                raw = json.loads(raw or "{}")
            except Exception:
                raw = {}
        if isinstance(raw, dict):
            out[key] = raw
        else:
            out[key] = {}
    return out


def _counter_int(value):
    """An int when the value really is one, else None - never 0 - so an absent counter stays absent."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _median(values: list):
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def attribute_connection_bursts(rows: list, role: str = "", now_sec: float = None,
                                stale_after_sec: float = None, max_bursts: int = 12) -> dict:
    """Attribute the connection bursts in one host's stored history. Pure: no runner, no DB, no clock.

    `rows` are `host_resources` rows for one role, in either order (they are re-sorted here); a caller
    that pre-sorts newest-first cannot silently reverse the deltas, which is the difference between
    "43 new connections" and "-43".

    Every interval the function declines to use is returned with the reason it was declined. A verdict
    that silently rested on two of forty samples would be a guess, and the operator reading the panel is
    the one who has to be able to see that.
    """
    seq = [_row_counters(r) | {"raw": r} for r in rows or []]
    for item in seq:
        item["at"] = _counter_int(item["raw"].get("collected_at")) or item["raw"].get("collected_at")
    seq = [i for i in seq if isinstance(i["at"], (int, float))]
    seq.sort(key=lambda i: i["at"])

    skipped, intervals = [], []
    for prev, cur in zip(seq, seq[1:]):
        at = cur["at"]
        dt = cur["at"] - prev["at"]
        if dt <= 0:
            skipped.append({"at": at, "reason": "non_monotonic_clock"})
            continue
        pb, cb = str(prev["raw"].get("boot_id") or ""), str(cur["raw"].get("boot_id") or "")
        if pb and cb and pb != cb:
            # A real boot between samples: the counters restarted, so no difference across this interval
            # describes traffic at all. This is also the reboot pentest's own window - the history is
            # expected to say "boot", never "the host went quiet".
            skipped.append({"at": at, "reason": "boot_between_samples"})
            continue
        # A sample from a host that answered nothing bounds nothing, and it is named as the cause: the
        # missing counters are its effect. Reading an unreachable sample as "zero connections in this
        # interval" would make every dark window look like a quiet night and every reboot look like a drop
        # in traffic.
        #
        # `== 0` and not `not in (0, None)`: a row written before migration 10 has NULL here, which means
        # "this column did not exist", not "the host was down". Declining that as `no_counters` below keeps
        # the honest reason and stops the attribution from accusing a host of an outage it never had.
        rc_, rp_ = _counter_int(cur["raw"].get("reachable")), _counter_int(prev["raw"].get("reachable"))
        if rc_ == 0 or rp_ == 0:
            skipped.append({"at": at, "reason": "host_unreachable"})
            continue
        if not (cur["tcp_counters"] or cur["socket_states"]):
            skipped.append({"at": at, "reason": "no_counters"})
            continue

        d = {}
        reset = False
        for key in TCP_MONOTONIC_COUNTERS:
            a, b = _counter_int(prev["tcp_counters"].get(key)), _counter_int(cur["tcp_counters"].get(key))
            if a is None or b is None:
                d[key] = None
                continue
            if b < a:
                reset = True
                break
            d[key] = b - a
        if reset:
            skipped.append({"at": at, "reason": "counter_reset"})
            continue

        inbound, outbound = d.get("PassiveOpens"), d.get("ActiveOpens")
        new_conns = ((inbound or 0) + (outbound or 0)
                     if (inbound is not None or outbound is not None) else None)
        gauges = cur["socket_states"]
        intervals.append({
            "from": prev["at"], "at": at, "span_sec": round(dt, 3),
            "new_connections": new_conns,
            "rate_per_sec": (round(new_conns / dt, 3) if new_conns is not None and dt > 0 else None),
            "inbound": inbound, "outbound": outbound,
            "attempt_fails": d.get("AttemptFails"), "estab_resets": d.get("EstabReseds"),
            "retrans_segs": d.get("RetransSegs"), "out_rsts": d.get("OutRsts"),
            "in_segs": d.get("InSegs"), "listen_overflows": d.get("ListenOverflows"),
            "listen_drops": d.get("ListenDrops"), "tcp_timeouts": d.get("TCPTimeouts"),
            "syn_retrans": d.get("TCPSynRetrans"),
            "established": _counter_int(gauges.get("ESTABLISHED")),
            "syn_recv": _counter_int(gauges.get("SYN_RECV")),
            "time_wait": _counter_int(gauges.get("TIME_WAIT")),
            "listen": _counter_int(gauges.get("LISTEN")),
            "curr_estab_kernel": _counter_int(cur["tcp_counters"].get("CurrEstab")),
        })

    rates = [i["rate_per_sec"] for i in intervals if i["rate_per_sec"] is not None]
    median = _median(rates)
    baseline_available = len(rates) >= CONN_MIN_BASELINE_INTERVALS
    totals = {"new_connections": 0, "inbound": 0, "outbound": 0, "attempt_fails": 0,
              "listen_overflows": 0, "listen_drops": 0, "tcp_timeouts": 0, "retrans_segs": 0}
    uncounted = 0
    for i in intervals:
        # An interval whose counter was never read contributes nothing rather than a zero, and says how
        # many such intervals there were. A window that reports "0 new connections" while three of its
        # eight intervals carried no ActiveOpens would otherwise read as a quiet night.
        if i["new_connections"] is None:
            uncounted += 1
        for key in totals:
            totals[key] += (i.get(key) or 0)
    totals["intervals"] = len(intervals)
    totals["intervals_without_counter"] = uncounted

    bursts = []
    for i in intervals:
        new = i["new_connections"]
        if new is None or new < CONN_MIN_BURST_CONNECTIONS:
            continue
        if baseline_available and median and i["rate_per_sec"] is not None:
            if i["rate_per_sec"] < CONN_BURST_FACTOR * median:
                continue
            basis = f"rate {i['rate_per_sec']}/s vs own median {round(median, 3)}/s"
        else:
            basis = f"absolute floor of {CONN_MIN_BURST_CONNECTIONS} new connections (no baseline yet)"
        bursts.append(dict(i, basis=basis, cause=_burst_cause(i)))

    skipped_counts = {}
    for s in skipped:
        skipped_counts[s["reason"]] = skipped_counts.get(s["reason"], 0) + 1

    newest = seq[-1]["at"] if seq else None
    stale = None
    if now_sec is not None and newest is not None and stale_after_sec is not None:
        stale = (now_sec - newest) > stale_after_sec

    if not seq:
        verdict = "NO_HISTORY"
    elif not intervals:
        verdict = "NO_USABLE_INTERVALS"
    elif bursts:
        verdict = f"BURSTS({len(bursts)})"
    else:
        verdict = "NO_BURSTS"
    if verdict != "NO_HISTORY" and not baseline_available and intervals:
        verdict += "_UNCALIBRATED"
    if stale:
        verdict += "_STALE"

    summary = (f"{verdict}: {len(bursts)} burst(s) over {len(intervals)} usable interval(s) from "
               f"{len(seq)} sample(s); {totals['new_connections']} new connections in the window"
               f"{' (baseline: median ' + str(round(median, 3)) + '/s)' if baseline_available and median is not None else ' (no baseline: fewer than ' + str(CONN_MIN_BASELINE_INTERVALS) + ' usable intervals)'}"
               f"{'; ' + str(skipped_counts) if skipped_counts else ''}")
    return {"role": role or "", "samples": len(seq), "intervals": intervals,
            "skipped": skipped, "skipped_counts": skipped_counts,
            "baseline": {"available": baseline_available, "intervals_with_rate": len(rates),
                         "min_intervals": CONN_MIN_BASELINE_INTERVALS,
                         # None until the baseline exists, even though a median of one or two intervals is
                         # arithmetically available: a consumer that reads this field without checking
                         # `available` would be quoting a baseline the engine itself calls uncalibrated,
                         # which is the NULL-vs-zero mistake wearing a different hat.
                         "median_new_conn_per_sec": (round(median, 4) if (baseline_available and median is not None) else None),
                         "factor": CONN_BURST_FACTOR, "min_connections": CONN_MIN_BURST_CONNECTIONS},
            "window": ({"from": seq[0]["at"], "to": seq[-1]["at"],
                        "span_sec": round(seq[-1]["at"] - seq[0]["at"], 3)} if seq else None),
            "totals": totals, "stale": stale,
            "bursts": bursts[-int(max_bursts):], "burst_count": len(bursts), "verdict": verdict,
            "summary": summary}


def _burst_cause(interval: dict) -> str:
    """One attribution per burst interval, from the kernel's own account of what a burst cost.

    The order is a claim about causes, not a preference among strings: an accept queue that overflowed is
    a burst the *service* failed to absorb, failed handshakes are a burst that never became traffic (the
    scanner and the censored-probe signature), and retransmit growth is a path problem wearing a load
    costume. Only when none of those speak does the direction of the connections decide, and the split
    between "the world dialling this host" and "this host dialling the world" is the difference between
    an inbound storm and a client gone feral.
    """
    new = interval.get("new_connections") or 0
    if (interval.get("listen_overflows") or 0) > 0 or (interval.get("listen_drops") or 0) > 0:
        return "accept_queue_overflow"
    fails = interval.get("attempt_fails")
    if fails is not None and new > 0 and (fails / new) >= CONN_FAIL_SHARE_STORM:
        return "failed_handshakes"
    inbound, outbound = interval.get("inbound"), interval.get("outbound")
    retrans, timeouts = interval.get("syn_retrans"), interval.get("tcp_timeouts")
    if ((retrans or 0) + (timeouts or 0)) > max(1, new) and new > 0:
        return "retransmit_growth"
    if outbound is not None and (inbound or 0) <= max(1, outbound / CONN_OUTBOUND_DOMINANT):
        return "outbound_storm"
    if inbound is not None and new > 0:
        return "inbound_storm"
    return "unattributed"



CARRIER_DNAT_CONFLICT = (
    "NOT_MEASURABLE: this pair's frontend is already DNATed somewhere else, so the carrier being "
    "deployed would never see inbound traffic ({conflict}). The failure is invisible from inside the "
    "carrier: the SAs install, the inner ping answers, the unit is active and the deployment verifies, "
    "while the packets a censor can read still enter the other envelope. PREROUTING is first-match and a "
    "carrier appends its rule, so the rule that already exists wins. Tear the other carrier down, or "
    "give this one a frontend of its own.")


def carrier_dnat_conflict(prerouting: str, frontend, inner_peer: str) -> str:
    """Name a PREROUTING DNAT that would shadow this carrier's entry point, or return ''.

    A carrier's frontend is one rule: `-A PREROUTING -p tcp ! -i <carrier iface> --dport F -j DNAT
    --to-destination P:F`, where P is that carrier's own inner peer address (the `! -i` token arrived with
    report062's hairpin fix, and it is why this parser tests substrings instead of one pattern over the
    line - an interface match sits between `-p` and `--dport` now, in both the `-A` and the `-S` spelling).
    Because iptables evaluates the chain in order and a deploy appends, any matching rule that predates it
    decides where the packet goes. The case this catches is not
    hypothetical: a pair that still holds its GRE carrier and is given ESP on the same frontend keeps
    sending inbound traffic into proto 47, which for REALITY is exactly the cleartext envelope the carrier
    gate exists to refuse - arrived at by rule order instead of by declaration, and invisible to every
    check the carrier itself can make.

    The description carries the shadowing rule's own comment, which is what identifies the pair and
    protocol that owns it, and the destination through the same masking every persisted field goes
    through - an operator reading a terminal needs to see which address is in force, and this product does
    not print routable addresses to make that sentence legible. The comment is read in both spellings
    because the live hosts (Debian 13, iptables-nft) print `-S` output with the comment *unquoted*
    (`--comment best-tunnel-1-prod-GRE`), while the quoted form is what a legacy iptables prints and what a
    test fixture naturally writes; a parser that only accepted the quotes reported every real rule as
    "unlabelled" on the first live run of this check.
    """
    want = f"--to-destination {inner_peer}:{frontend}"
    for line in (prerouting or "").splitlines():
        if "DNAT" not in line or "--dport" not in line:
            continue
        if not re.search(rf"--dport {frontend}(\s|$)", line):
            continue
        if want in line:
            continue
        owner = re.search(r'--comment "([^"]*)"', line) or re.search(r"--comment (\S+)", line)
        dest = re.search(r"--to-destination (\S+)", line)
        return (f"{owner.group(1) if owner else 'unlabelled rule'} -> "
                f"{storage.mask_addresses(dest.group(1)) if dest else '?'}")
    return ""


CARRIER_VTI_CONFLICT = (
    "NOT_MEASURABLE: a VTI interface already holds this pair's outer endpoint pair on {role} "
    "({occupant}), so the ESP carrier being deployed could not be created there. Measured on both live "
    "hosts in an isolated namespace (2026-10-11): the collision is by the ordered (local, remote) address "
    "pair - a different tunnel key is refused, a different interface name is refused, and only a different "
    "endpoint pair is accepted - so no name this product could invent is free while another VTI holds the "
    "tuple, and rotating the key derivation cannot free it either. Consequence for the operator: at most "
    "one ESP carrier can exist between these two hosts in a given direction, so a second pair on the same "
    "hosts, or a benchmark carrier overlapping a production one, must be refused rather than renamed. The "
    "occupant is usually a stopped leftover of an earlier carrier - under the interface-reuse design no "
    "lifecycle operation removes an interface, because a removal of a loaded VTI parks forever in this "
    "kernel's unregister_netdevice wait. Tear that carrier down (its own unit's stop plus its xfrm "
    "objects), or benchmark ESP on a pair that does not already have it.")


CARRIER_VTI_UNREADABLE = (
    "NOT_MEASURABLE: the VTI listing that decides who owns this pair's outer endpoint pair could not be "
    "read on {role} - neither `ip -d -o link show type vti` nor the unfiltered listing returned success. "
    "Refusing on an unknown is deliberate: that read ends in `2>/dev/null`, so a failing read prints "
    "exactly what an empty one prints, and treating 'could not look' as 'nobody is home' is how a deploy "
    "gets to write both hosts' files and firewall rules before the kernel refuses it with `RTNETLINK "
    "answers: File exists`. No diagnostic text is quoted here because a netlink error can echo an address, "
    "and an address does not belong in a stored reason. Fix how this host answers `ip -d -o link show`, or "
    "deploy this carrier on a pair whose hosts do.")


def carrier_vti_conflict(runner, role: str, local_ip: str, remote_ip: str, iface: str) -> str:
    """Refuse an ESP carrier whose outer endpoint pair another VTI already owns on this host.

    Returns the explanation, or '' when the tuple is free. What this replaces is a deploy that wrote both
    hosts' files and firewall rules, started the unit, and then reported `Main process exited, code=exited,
    status=2/INVALIDARGUMENT` - the real reason, `RTNETLINK answers: File exists`, sitting in a journal line
    that the engine's rollback had already orphaned by the time anyone read the failure.

    One half of the rule is deliberately *not* checked here: the reversed direction (`local B remote A`
    where `local A remote B` exists) was measured as creatable on both hosts, so matching the unordered pair
    would refuse deployments the kernel accepts. A gate that over-refuses is a defect of the same family as
    one that under-refuses, and this one is written to the measured boundary.

    The address pair is read per host and in that host's own orientation, because each side builds its
    interface with itself as `local`: on Iran the tuple is (iran, foreign), on Foreign it is (foreign,
    iran), and a check that sent the same orientation to both would find nothing on the second host.

    A read that *fails* is refused rather than treated as an empty listing. `VTI_LISTING_CMD` carries
    `2>/dev/null`, so a host whose iproute2 rejects the `type vti` filter prints nothing - and nothing is
    byte-identical to "this host has no VTI". Guessing 'free' there reproduces the exact failure this gate
    was written to prevent, and the standing rule for an indeterminate outcome is that it may not authorise
    a write. The unfiltered listing is retried first because it answers the same question, then the deploy
    is refused with a reason that says the check could not be made.
    """
    rc, out, _ = runner.run(protocols.VTI_LISTING_CMD, best_effort=True, retryable=True, timeout=45)
    if rc:
        rc, out, _ = runner.run(protocols.VTI_LISTING_FALLBACK_CMD, best_effort=True,
                                retryable=True, timeout=45)
    if rc:
        return CARRIER_VTI_UNREADABLE.format(role=role)
    occupant = protocols.vti_occupant(out or "", local_ip, remote_ip, iface)
    return CARRIER_VTI_CONFLICT.format(role=role, occupant=occupant) if occupant else ""


CARRIER_SLOT_RULE_TEXT = (
    "قاعده: بستر ESP محدودیتِ یکِ بستر در هر جهت دارد — the kernel keys one VTI device on the ordered "
    "(local, remote) endpoint pair, so a second ESP carrier between the same two hosts is refused before "
    "any file or firewall rule is written, whatever interface name it asks for. The reversed direction is "
    "legal and is a separate slot.")


def carrier_slot_rule(pairs) -> list:
    """The one-ESP-carrier-per-direction rule, computed from stored declarations with no host touched.

    `carrier_vti_conflict` is the live gate and asks the kernel who owns the tuple. It can only answer at
    deploy time, which leaves the operator discovering the rule from a refusal - and the manager's ruling
    on report059 §11.3 asked for the rule to be visible *as a rule* instead. This is the same boundary
    derived from the pair rows the dashboard already has: pairs that declare `underlay_carrier = esp` and
    share an ordered endpoint pair occupy one slot, first by id holds it, the rest would be refused.

    No address is returned. The endpoint tuple is a grouping key only; the emitted fields are role names,
    pair ids, pair names and interface nameplates, which is what a rendered page needs and nothing that
    can route to a host.
    """
    by_slot = {}
    for p in pairs:
        if str(p.get("underlay_carrier") or "").strip().lower() != "esp":
            continue
        ir, fr = p.get("iran_host") or "", p.get("foreign_host") or ""
        if not ir or not fr:
            continue
        for role, local, remote in (("iran", ir, fr), ("foreign", fr, ir)):
            by_slot.setdefault((role, local, remote), []).append(p)
    slots = []
    for (role, _local, _remote), claimants in by_slot.items():
        claimants.sort(key=lambda p: int(p["id"]))
        holding = claimants[0]
        slots.append({
            "host_role": role,
            "pair_id": int(holding["id"]),
            "pair_name": holding.get("name") or f"pair {holding['id']}",
            "iface": protocols.carrier_iface("ESP", int(holding["id"]), "prod"),
            "claimants": len(claimants),
            "would_be_refused": [
                {"pair_id": int(c["id"]), "pair_name": c.get("name") or f"pair {c['id']}",
                 "iface": protocols.carrier_iface("ESP", int(c["id"]), "prod")} for c in claimants[1:]],
        })
    return sorted(slots, key=lambda s: (s["host_role"], s["pair_id"]))


DESTINATION_ANCHOR_REFUSAL = (
    "NOT_MEASURABLE: {protocol} is a transport whose client authenticates the destination, but the "
    "config this generation emitted does not carry that material ({status}). The failure is invisible "
    "at runtime: a client whose trust file is missing or unparseable still completes the handshake "
    "against whatever answers the port, so both a benchmark and a deployment would proceed happily on "
    "a tunnel that is MITM-able by construction - witnessed on the live pair as report049's wstunnel "
    "client started with no CA at all. This is a generator or plan defect, not a property of the "
    "transport; the fix belongs in the emitted config, not in this gate.")


def destination_pin_block(pair_id: int, protocol: str, plan: dict, record: bool = False) -> str:
    """Refuse a plan whose client is supposed to verify the destination but cannot.

    Only the two regression statuses refuse. A pin that *differs from the stored one* does not, and
    that is a measured fact rather than a choice: every anchored transport here generates its keying
    material inside the plan (protocols.py:90/:141 for the certificates, :1051-1058 for REALITY's
    x25519 pair, :465/:479 for rathole's static key), so two consecutive generations of an unchanged
    pair and protocol already disagree - probed in scratch/probe_anchor_rotation.py, all six pinned
    transports reported ROTATES. Refusing on mismatch would therefore reject every legitimate redeploy
    and hide the one case it exists for. Until the anchors persist per pair, the mismatch is recorded
    and audited (`storage.record_destination_pin`), which makes a replacement visible without
    pretending to be a control that fires on it.

    `record` is the caller's answer to "did anything actually get deployed?". A dry run still refuses
    (catching a generator regression is the whole point of previewing one) but writes nothing durable:
    a pin row would describe a tunnel that does not exist, and since each generation rotates the
    anchor, a dry run would also raise a DESTINATION_PIN_ROTATED WARNING - "somebody replaced the key"
    - for a command that opened no session. Measured before the fix in scratch/probe_dryrun_pin.py.
    The default is therefore False: a future fourth call site inherits "judge, but do not remember",
    which is the direction that cannot corrupt state by omission.
    """
    info = protocols.destination_pin(protocol, plan)
    status = info["status"]
    if status.startswith("no-anchor") or status.startswith("anchor-missing"):
        return DESTINATION_ANCHOR_REFUSAL.format(protocol=protocol, status=status)
    if status == "pinned" and record:
        # Ephemeral benchmark anchors are not the production tunnel's identity, so a bench plan is
        # gated but never recorded - otherwise the pin table fills with material nothing depends on.
        storage.record_destination_pin(pair_id, protocol, info["mechanism"], info["fingerprint"])
    return ""


def _blocked_row(protocol: str, profile: str, base_rtt: float, reason: str,
                 preflight=None) -> dict:
    """The row shape a benchmark that never started has to keep, so readers see one kind of result.

    The preflight key is always present, so a blocked row and a failed
    row keep the same shape (test_59): None when nothing was collected -
    the pre-session refusal collects nothing by design, because
    collecting would open the session the refusal exists to avoid -
    and the collected report when the block was found after collection.
    """
    return {
        "preflight": preflight,
        "protocol": protocol,
        "score": 0.0,
        "profile": profile,
        "scores_by_profile": {"balanced": 0.0, "gaming": 0.0, "ultraspeed": 0.0},
        "disqualified": True,
        "not_measurable": True,
        "dq_reasons": [reason],
        "bulk_step": 0,
        "jitter_ms": 0.0,
        "throughput_mbps": 0.0,
        "throughput_measured": False,
        "ladder_error": reason[:200],
        "base_rtt_ms": base_rtt,
        "breakdown": {"lat_avg": 0.0, "jitter_ms": 0.0, "loss_pct": 0.0, "s_lat": 0.0, "s_jit": 0.0,
                      "s_bulk": 0.0, "s_stab": 0.0, "loss_penalty": 0.0, "ramp_multiplier": 0.0,
                      "seconds_survived": 0.0, "throughput_mbps": 0.0, "base_rtt": base_rtt,
                      "overhead_ratio": 0.0},
        "logs": {},
        "unit_timestamps": {},
        "run_start_utc": "",
        "stages_measured": [],
        "iperf3": None,
    }


def _open_pair_sessions(pair: dict, dry_run: bool):
    """Open both control sessions for one protocol, or neither.

    A session that opened and then had to be abandoned is the leak this prevents: the first live sweep
    died because `paramiko` raised `No existing session` while opening the *second* host, and the row
    that would have recorded it was never reached.
    """
    ir_runner = get_ssh_runner(pair["iran"], dry_run=dry_run, host_role="iran")
    try:
        return ir_runner, get_ssh_runner(pair["foreign"], dry_run=dry_run, host_role="foreign")
    except Exception:
        ir_runner.close()
        raise


def run_single_benchmark(pair: dict, protocol: str, dry_run: bool = True, ir_runner=None, fr_runner=None, profile: str = "balanced", base_rtt: float = 0.0) -> dict:
    """Executes isolated benchmark for a protocol THROUGH its own temporary test tunnel."""
    blocked = carrier_camouflage_block(pair, protocol)
    if blocked:
        # Checked before a runner exists, so a refusal provably deploys nothing and opens no session.
        return _blocked_row(protocol, profile,
                            base_rtt or float(pair.get("base_rtt_ms") or 0.0), blocked)

    # Everything that needs no session is read before one exists: a pair whose config will not resolve,
    # or whose recorded baseline already answers the question, is decided without a control channel that
    # could be left behind.
    pair_id = pair.get("id", 1)
    ir_ip = protocols.dial_address(pair["iran"], protocol)
    fr_ip = protocols.dial_address(pair["foreign"], protocol)
    test_frontend = 8898
    test_transport = 8897
    test_iperf_port = 8898
    cooldown_needed = 0
    bplan = None
    ladder_err = ""
    unit_timestamps = {}
    run_start_utc = ""
    ir_start_utc = ""
    fr_start_utc = ""
    probe_failed = False
    probe_err_msg = ""
    # Each stage of a live benchmark overwrites these as it lands, and the failure path below reads
    # them: None means "this stage never ran", which is a different fact from a measured 0.0.
    lat = None
    jit = None
    loss = None
    survived = None
    bulk_step = 0
    throughput_mbps = 0.0
    throughput_measured = False
    iperf_metrics = None

    owned_runners = []
    try:
        if ir_runner is None and fr_runner is None:
            ir_runner, fr_runner = _open_pair_sessions(pair, dry_run)
            owned_runners = [ir_runner, fr_runner]
        elif ir_runner is None:
            ir_runner = get_ssh_runner(pair["iran"], dry_run=dry_run, host_role="iran")
            owned_runners.append(ir_runner)
        elif fr_runner is None:
            fr_runner = get_ssh_runner(pair["foreign"], dry_run=dry_run, host_role="foreign")
            owned_runners.append(fr_runner)

        if base_rtt <= 0.0:
            base_rtt = float(pair.get("base_rtt_ms") or 0.0)
        if base_rtt <= 0.0:
            is_mock_runner = getattr(ir_runner, "__class__", None).__name__ == "MockSSHClient"
            if dry_run or is_mock_runner:
                base_rtt = 42.0
            else:
                rtt_res = measure_direct_base_rtt(ir_runner, fr_ip, dry_run=dry_run)
                base_rtt = rtt_res.base_rtt_ms
    except BaseException:
        # #72, the same class as the #71 fix two routes down. The close that owns these sessions is in
        # the `finally` of the main body below, so anything raised between opening a session and reaching
        # that `try` - a `dial_address` that does not resolve, a baseline probe whose channel died - left
        # the session open for the life of the process, one per failed protocol row per sweep. This guard
        # closes and re-raises rather than swallowing: the row's own failure attribution must not change,
        # and it deliberately does not enter the main body's `finally`, which would run benchmark
        # teardown commands against hosts this call never deployed to.
        for runner in owned_runners:
            runner.close()
        raise

    # Preflight wiring (Phase 3): the path/host facts are collected once per
    # live benchmark, before any bench tunnel is written, and travel in the
    # row (persisted via details_json) so a score is always read next to the
    # conditions it was measured under. Dry runs stay deterministic and skip
    # it. Findings are advisory, never a gate: a warning about missing BBR
    # must not void a measurement, and a host that cannot be reached will
    # fail the benchmark on its own evidence anyway. Collection itself is
    # best-effort: a failed collector must not take the benchmark down.
    preflight_report = None
    if not dry_run:
        try:
            import preflight
            preflight_report = preflight.build_preflight_report(
                ir_runner, fr_runner, pair["iran"]["host"], pair["foreign"]["host"])
        except Exception as exc:
            # Findings-only: this is a preflight report that failed to
            # collect, not an operational pair spec, so it carries no
            # iran/foreign/path sections for the test_68 census to mistake
            # for one - a reader that needs the sections uses .get().
            preflight_report = {
                "findings": [f"preflight collection failed ({exc}); proceeding without it"]}

    try:
        if dry_run:
            # Deterministic simulation values for local offline verification
            lat_map = {"GRE": 46.2, "kcptun": 48.5, "singbox-vless-reality": 47.1, "singbox-ss-2022": 49.3, "rathole-noise": 51.8, "backhaul-wss": 52.1, "wstunnel-v10": 52.8, "frp-TLS": 53.5, "chisel-wss": 54.0, "xray-reverse": 55.4, "hysteria2": 56.0}
            jit_map = {"GRE": 2.1, "kcptun": 2.8, "singbox-vless-reality": 2.4, "singbox-ss-2022": 3.1, "rathole-noise": 3.8, "wstunnel-v10": 4.1, "backhaul-wss": 4.5, "frp-TLS": 4.9, "chisel-wss": 5.2, "xray-reverse": 6.0, "hysteria2": 4.0}
            tp_map = {"GRE": 94.2, "singbox-vless-reality": 88.6, "kcptun": 82.5, "singbox-ss-2022": 81.4, "rathole-noise": 78.4, "wstunnel-v10": 74.2, "backhaul-wss": 71.0, "frp-TLS": 68.5, "chisel-wss": 65.1, "xray-reverse": 59.3}
            lat = lat_map.get(protocol, 55.0)
            jit = jit_map.get(protocol, 5.0)
            bulk_step = 4
            survived = 28.5
            loss = 0.0
            throughput_mbps = tp_map.get(protocol, 50.0)
            iperf_metrics = {
                "available": True,
                "download_mbps": throughput_mbps,
                "upload_mbps": throughput_mbps,
                "legs": [{"direction": "upload", "mbps": throughput_mbps, "measured": True, "error": ""},
                         {"direction": "download", "mbps": throughput_mbps, "measured": True,
                          "error": ""}],
                "throughput_mbps": throughput_mbps,
                "capacity_basis": "simulated",
                "retransmits": 1
            }
        else:
            # REAL LIVE BENCHMARK ENGINE (Phase 2+)
            is_mock = isinstance(ir_runner, MockSSHClient)
            
            # Per-host Clock anchors: remote dates to prevent clock-drift issues
            _, o_ir_date, _ = ir_runner.run("date -u +'%Y-%m-%d %H:%M:%S'", best_effort=True, retryable=True)
            ir_date = o_ir_date.strip()
            ir_start_utc = ir_date if ir_date else datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            _, o_fr_date, _ = fr_runner.run("date -u +'%Y-%m-%d %H:%M:%S'", best_effort=True, retryable=True)
            fr_date = o_fr_date.strip()
            fr_start_utc = fr_date if fr_date else ir_start_utc

            # Clean Execution Checklist 1: Strict Pre-clean on Iran & Foreign
            # Scoped strictly to best-tunnel-bench-* to never interfere with production units
            #
            # Wildcard stop, so its budget has to cover the slowest unit that matches, and a bench ESP
            # carrier is one of them. `TimeoutStopUSec` is per unit and systemd only returns once they are
            # all done, so 30 s was not "enough for a down" - it was enough for nothing at all if any unit
            # in the set was still stopping.
            ir_runner.run("systemctl stop 'best-tunnel-bench-*'", best_effort=True,
                          timeout=protocols.TEARDOWN_TIMEOUT_SEC)
            ir_runner.run("systemctl disable 'best-tunnel-bench-*'", best_effort=True)
            ir_runner.run("fuser -k 8897/tcp 8898/tcp", best_effort=True)
            ir_runner.run("rm -f /tmp/best* /tmp/test*", best_effort=True)

            fr_runner.run("kill $(cat /tmp/best-test-backend.pid 2>/dev/null)", best_effort=True)
            fr_runner.run("systemctl stop 'best-tunnel-bench-*'", best_effort=True,
                          timeout=protocols.TEARDOWN_TIMEOUT_SEC)
            fr_runner.run("systemctl disable 'best-tunnel-bench-*'", best_effort=True)
            fr_runner.run("fuser -k 8897/tcp 8898/tcp", best_effort=True)
            fr_runner.run("rm -f /tmp/best* /tmp/test*", best_effort=True)

            if not is_mock:
                time.sleep(1)

            # Clean Execution Checklist 2: Start test backend on Foreign listening on 0.0.0.0:8898
            fr_backend_script = f"""cat > /tmp/best_test_backend.py <<'EOF'
import http.server

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        sz = {{'/test_1k': 1024, '/test_10k': 10240, '/test_100k': 102400, '/test_1m': 1048576}}.get(self.path, 16)
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(sz))
        self.end_headers()
        chunk = b'B' * min(sz, 65536)
        rem = sz
        while rem > 0:
            w = min(rem, len(chunk))
            self.wfile.write(chunk[:w])
            rem -= w
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Length', '16')
        self.end_headers()
    def log_message(self, *a): pass

class ReusableServer(http.server.HTTPServer):
    allow_reuse_address = True

server = ReusableServer(('0.0.0.0', {test_frontend}), H)
server.serve_forever()
EOF
kill $(cat /tmp/best-test-backend.pid 2>/dev/null) 2>/dev/null || true
nohup python3 -u /tmp/best_test_backend.py >/dev/null 2>&1 & echo $! > /tmp/best-test-backend.pid
"""
            fr_runner.run(fr_backend_script, check=True)
            if not is_mock:
                time.sleep(1)

            # Clean Execution Checklist 3: Verify Foreign backend is responding with 200 before proceeding
            backend_ready = False
            for _ in range(5):
                _, o_be_chk, _ = fr_runner.run(f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{test_frontend}/test_1k", best_effort=True)
                if "200" in o_be_chk:
                    backend_ready = True
                    break
                time.sleep(0.5)

            if not backend_ready and not is_mock:
                raise RuntimeError(f"Foreign test backend failed to respond with 200 on http://127.0.0.1:{test_frontend}/test_1k")

            # F6: the bench plan's units name userspace binaries, and until now nothing on this
            # path installed them - deploy_tunnel has had the gate since F3, the benchmark never
            # got it. On a host where the protocol was never deployed, systemd answered 203/EXEC
            # in a crash loop (first seen live on the 2026-10-23 test pair) and the row blamed a
            # 25 s readiness timeout instead of the missing binary. Same fail-closed rule as the
            # deploy path, answered in the row shape this path returns.
            for role, runner in (("iran", ir_runner), ("foreign", fr_runner)):
                for binary in binary_manager.required_binaries(protocol):
                    ok, msg = binary_manager.verify_and_install_binary(
                        runner, binary, dry_run=False)
                    if not ok:
                        return _blocked_row(
                            protocol, profile, base_rtt,
                            f"binary pre-flight: {binary} on the {role} host could not be "
                            f"installed or verified: {msg}",
                            preflight=preflight_report)

            # Clean Execution Checklist 4: Deploy temporary test tunnel (namespace='bench')
            bplan = protocols.generate_benchmark_plan(protocol, pair_id, ir_ip, fr_ip, test_frontend=test_frontend, test_transport=test_transport)
            blocked_pin = destination_pin_block(pair_id, protocol, bplan, record=False)
            if blocked_pin:
                # Judged on the plan that is about to be written, not on a separately generated one:
                # a gate that inspects a different artifact than the deployment uses proves nothing.
                # Nothing of this tunnel has reached the hosts yet - the checklist above only started
                # the test backend - and the `finally` teardown below removes that.
                cooldown_needed = 60
                return _blocked_row(protocol, profile, base_rtt, storage.mask_addresses(blocked_pin),
                                    preflight=preflight_report)
            if protocol == "ESP":
                # Same rule the production deploy applies, and the benchmark is the path that earned it: the
                # interface that blocked the live carrier on 2026-10-11 was `espp4b`, a *benchmark* carrier's
                # own stopped leftover, holding the endpoint pair that pair 1's production carrier needed.
                # Judged on the bench nameplate because that is the interface this plan creates; a prod
                # carrier of the same pair is the occupant it will collide with, and vice versa.
                for role, r, local, remote in (("iran", ir_runner, ir_ip, fr_ip),
                                               ("foreign", fr_runner, fr_ip, ir_ip)):
                    blocked_vti = carrier_vti_conflict(
                        r, role, local, remote, protocols.carrier_iface("ESP", pair_id, "bench"))
                    if blocked_vti:
                        cooldown_needed = 60
                        return _blocked_row(protocol, profile, base_rtt,
                                            storage.mask_addresses(blocked_vti))
            for c in bplan.get("iran_cmds", []): ir_runner.run(c, check=True)
            for c in bplan.get("foreign_cmds", []): fr_runner.run(c, check=True)
            for fpath, content in bplan.get("iran_files", {}).items():
                ir_runner.write_file(fpath, content)
            for fpath, content in bplan.get("foreign_files", {}).items():
                fr_runner.write_file(fpath, content)

            # Clean Execution Checklist 5: Fresh restart with systemctl restart & record ActiveEnterTimestamp
            # Notice: Do NOT enable benchmark test units; keep them strictly ephemeral!
            #
            # `restart` is a stop followed by a start, and systemd only answers once both phases are done,
            # so the caller's budget has to cover the unit's declared `TimeoutStopUSec`. check=True makes
            # this path raise rather than record, and a 30 s TimeoutError on a carrier whose stop phase was
            # merely slow was the false-timeout class this ruling closes.
            if bplan.get("foreign_units"):
                fr_runner.run("systemctl daemon-reload", check=True)
                for u in bplan["foreign_units"]:
                    fr_runner.run(f"systemctl restart {u}", check=True,
                                  timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                    ts_str = ""
                    for _ in range(5):
                        _, o_ts, _ = fr_runner.run(f"systemctl show -p ActiveEnterTimestamp {u}",
                                               best_effort=True, retryable=True)
                        ts_str = o_ts.strip()
                        if ts_str and not ts_str.endswith("ActiveEnterTimestamp="):
                            break
                        time.sleep(0.2)
                    unit_timestamps[f"foreign_{u}"] = ts_str

            if bplan.get("iran_units"):
                ir_runner.run("systemctl daemon-reload", check=True)
                for u in bplan["iran_units"]:
                    ir_runner.run(f"systemctl restart {u}", check=True,
                                  timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                    ts_str = ""
                    for _ in range(5):
                        _, o_ts, _ = ir_runner.run(f"systemctl show -p ActiveEnterTimestamp {u}",
                                               best_effort=True, retryable=True)
                        ts_str = o_ts.strip()
                        if ts_str and not ts_str.endswith("ActiveEnterTimestamp="):
                            break
                        time.sleep(0.2)
                    unit_timestamps[f"iran_{u}"] = ts_str

            # Deploy the L7 probe to a persistent path outside /tmp so the failover health
            # checker can still reach it after this benchmark's teardown has run.
            ir_runner.run(probe.install_script(), check=True)

            if protocol in protocols.INNER_PROBED:
                # A carrier is measured on its inner address: nothing listens on a loopback frontend,
                # the thing under test is whether packets cross the envelope.
                tun_inner_ip = protocols.carrier_inner_pair(protocol, pair_id, "bench")[1]
                inner_iface = protocols.carrier_iface(protocol, pair_id, "bench")
                target_ip = tun_inner_ip
            else:
                target_ip = "127.0.0.1"

            # 3. Active Readiness Poll (up to 25s) before running benchmark probes
            is_mock = isinstance(ir_runner, MockSSHClient)
            readiness_deadline = time.time() + (0.1 if is_mock else 25.0)
            ready = False

            while time.time() < readiness_deadline:
                if is_mock or dry_run:
                    ready = True
                    break

                if protocol in protocols.INNER_PROBED:
                    # Check if the carrier interface is up and its peer inner address answers
                    _, o_chk, _ = ir_runner.run(f"ping -c 1 -W 1 -I {inner_iface} {tun_inner_ip}",
                                                best_effort=True, retryable=True)
                    if "0% packet loss" in o_chk:
                        ready = True
                        break
                else:
                    # An open frontend socket is not a usable tunnel: on a reverse overlay the
                    # frontend listener appears before the control channel to the far-side origin
                    # exists, so the first requests fail. Readiness is one complete HTTP round trip
                    # through the tunnel, which is exactly what the probes below then measure.
                    _, o_chk, _ = ir_runner.run(
                        probe.cmd("ladder", target_ip, test_frontend, "/test_1k", 1024, 4),
                        best_effort=True, timeout=probe.cmd_timeout("ladder", "/test_1k", 1024, 4),
                        retryable=True)
                    if "LADDER_STEP_OK" in o_chk:
                        ready = True
                        break

                time.sleep(1)

            if not ready and not (is_mock or dry_run):
                raise TimeoutError(
                    f"Tunnel readiness check failed for {protocol} after 25s: "
                    + (f"no inner reply on {target_ip} via {inner_iface}"
                       if protocol in protocols.INNER_PROBED else
                       f"no complete HTTP round trip through {target_ip}:{test_frontend}"))

            # 4. Probe metrics THROUGH THE TUNNEL (P0-4: Strict verification with NO synthetic fallbacks)
            probe_failed = False
            probe_err_msg = ""
            if protocol in protocols.INNER_PROBED:
                # Probe inner tunnel interface via kernel ICMP. The SSH read timeout must outlast the
                # ping's own worst case (packets x interval, plus a -W timeout per unanswered packet),
                # or a lossy path is reported as an execution error instead of as loss.
                _, ping_out, _ = ir_runner.run(f"ping -c 10 -W 2 -I {inner_iface} {tun_inner_ip}",
                                               best_effort=True, timeout=35, retryable=True)
                m_rtt = re.search(r'rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)', ping_out)
                _, loss_out, _ = ir_runner.run(f"ping -c 30 -i 0.2 -W 1 -I {inner_iface} {tun_inner_ip}",
                                               best_effort=True, timeout=50, retryable=True)
                m_loss = re.search(r'([0-9.]+)% packet loss', loss_out)

                if m_rtt and m_loss:
                    lat, jit = float(m_rtt.group(2)), float(m_rtt.group(4))
                    loss = float(m_loss.group(1))
                else:
                    probe_failed = True
                    probe_err_msg = f"{protocol} kernel ping probe failed to parse (rtt_match={bool(m_rtt)}, loss_match={bool(m_loss)})"
                    lat, jit, loss = 999.0, 99.0, 100.0
            else:
                # Probe user-space tunnel through local frontend 127.0.0.1:8898 (true L7 HTTP round-trip)
                _, lat_str, _ = ir_runner.run(probe.cmd("lat", target_ip, test_frontend),
                                              best_effort=True, timeout=probe.cmd_timeout("lat"),
                                              retryable=True)
                m_avg = re.search(r'AVG:([0-9.]+)\s+MDEV:([0-9.]+)', lat_str)

                _, loss_str, _ = ir_runner.run(probe.cmd("loss", target_ip, test_frontend),
                                               best_effort=True, timeout=probe.cmd_timeout("loss"),
                                               retryable=True)
                m_loss = re.search(r'LOSS:([0-9.]+)', loss_str)

                if m_avg and m_loss:
                    lat, jit = float(m_avg.group(1)), float(m_avg.group(2))
                    loss = float(m_loss.group(1))
                else:
                    probe_failed = True
                    # The raw output is the diagnosis: "AVG:NOSAMPLE" means no request completed,
                    # which is a different outage than a probe that printed nothing at all.
                    probe_err_msg = (f"L7 tunnel probe failed to parse (lat_match={bool(m_avg)}, "
                                     f"loss_match={bool(m_loss)}; lat={lat_str.strip()[:60]!r}, "
                                     f"loss={loss_str.strip()[:40]!r})")
                    lat, jit, loss = 999.0, 99.0, 100.0

            # 4b. Sustained-availability window. Measures how long the tunnel stayed serviceable
            # before a real outage, which is distinct from random packet loss (already penalised
            # quadratically in scoring.py). The window is fixed, so the result does not depend on
            # how long the rest of the benchmark happened to take.
            _, stab_str, _ = ir_runner.run(probe.stability_cmd(target_ip, test_frontend),
                                            best_effort=True,
                                            timeout=probe.cmd_timeout(
                                                "stability", probe.STABILITY_SAMPLES,
                                                probe.STABILITY_INTERVAL, probe.OUTAGE_GAP),
                                            retryable=True)
            m_stab = re.search(r'STAB_SURVIVED:([0-9.]+)', stab_str)
            if m_stab:
                survived = min(probe.STABILITY_WINDOW, float(m_stab.group(1)))
            else:
                probe_failed = True
                probe_err_msg = f"Stability probe failed to parse (output={stab_str.strip()[:60]!r})"
                survived = 0.0

            # 5. Real 4-step bulk throughput ladder THROUGH THE TUNNEL with byte verification
            bulk_step = 0
            throughput_mbps = 0.0
            throughput_measured = False
            ladder_steps = [
                (1, "/test_1k", 1024, 6),
                (2, "/test_10k", 10240, 8),
                (3, "/test_100k", 102400, 12),
                (4, "/test_1m", 1048576, 20)
            ]
            ladder_err = ""
            for step_idx, path, exp_len, to_sec in ladder_steps:
                _, out_step, _ = ir_runner.run(
                    probe.cmd("ladder", target_ip, test_frontend, path, exp_len, to_sec),
                    best_effort=True, timeout=probe.cmd_timeout("ladder", path, exp_len, to_sec),
                    retryable=True
                )
                out_step = out_step.strip()
                if "LADDER_STEP_OK" in out_step:
                    bulk_step = step_idx
                    m_dt = re.search(r'in ([0-9.]+)s', out_step)
                    if m_dt and step_idx == 4:
                        dt_val = float(m_dt.group(1))
                        if dt_val > 0:
                            throughput_mbps = round((1048576 * 8) / (dt_val * 1000000.0), 2)
                else:
                    ladder_err = f"Step {step_idx} ({path}): {out_step}"
                    break

            # Serial handover from HTTP ladder to iperf3 on test_frontend port (Senior Auditor Finding 3-1)
            # Cleanly terminates HTTP test server on Foreign and clears socket before starting iperf3
            fr_runner.run(
                f"kill $(cat /tmp/best-test-backend.pid 2>/dev/null) 2>/dev/null || true; fuser -k {test_frontend}/tcp 2>/dev/null || true; rm -f /tmp/best-test-backend.pid",
                best_effort=True
            )
            if not is_mock:
                time.sleep(0.5)

            # Multi-stream bidirectional iperf3 measurement across the validated tunnel (port 8898, duration 10s)
            iperf_metrics = measure_iperf3_throughput(ir_runner, fr_runner, target_ip, port=test_iperf_port, dry_run=dry_run, duration=10)
            ladder_download_mbps = throughput_mbps
            if iperf_metrics.get("available"):
                # A measured capacity supersedes the ladder figure *including when it is 0.0*: a
                # direction that completed and carried nothing is a verdict, and letting it fall through
                # to the ladder number would launder "this tunnel does not carry downloads" into the
                # score of a tunnel that did carry a 1 MB object.
                throughput_mbps = iperf_metrics["throughput_mbps"]
                throughput_measured = True
                down_leg = next((l for l in iperf_metrics["legs"] if l["direction"] == "download"), {})
                if not down_leg.get("measured") and ladder_download_mbps > 0:
                    # The 1 MB ladder step measures the direction the reverse leg would have: content
                    # arriving in Iran. With -R never completed, that is the only download reading there
                    # is, and publishing the upload leg alone would repeat the average's mistake - one
                    # fat direction standing in for a starved one.
                    throughput_mbps = round(min(throughput_mbps, ladder_download_mbps), 2)
                    iperf_metrics["download_source"] = "ladder_1mb_step"
                    iperf_metrics["leg_note"] = (
                        (iperf_metrics.get("leg_note", "") + "; " if iperf_metrics.get("leg_note") else "")
                        + f"the download figure is the completed 1 MB ladder step "
                          f"({ladder_download_mbps} Mbps), not iperf3 -R")

        metrics = evaluate_tunnel_metrics(lat, jit, bulk_step, survived, loss, profile=profile,
                                          throughput_mbps=throughput_mbps,
                                          throughput_measured=throughput_measured, base_rtt=base_rtt)
        if probe_failed:
            metrics["disqualified"] = True
            metrics["dq_reasons"].append(f"MEASUREMENT_FAILED: {probe_err_msg}")
            metrics["score"] = 0.0

        metrics["protocol"] = protocol
        metrics["bulk_step"] = bulk_step
        metrics["jitter_ms"] = jit
        metrics["throughput_mbps"] = throughput_mbps
        metrics["throughput_measured"] = throughput_measured
        metrics["ladder_error"] = ladder_err
        metrics["base_rtt_ms"] = base_rtt
        metrics["iperf3"] = iperf_metrics
        if iperf_metrics is not None and not iperf_metrics.get("capacity_basis"):
            # A row that carries a throughput number must also carry where it came from: publishing the
            # 1 MB ladder's download figure under the same column name as an iperf3 weakest-leg reading
            # is how one number quietly becomes two different claims.
            iperf_metrics["capacity_basis"] = ("ladder_download_only" if throughput_mbps > 0
                                               else "not_measured")
        flap = transport_flaps(ir_runner, fr_runner)
        if flap:
            # A number measured across a link that had to be re-opened mid-run is still a number, but
            # the row says so: "survived three reconnects" and "quiet the whole time" are different
            # evidence about the same tunnel.
            metrics["transport"] = flap
        if preflight_report is not None:
            metrics["preflight"] = preflight_report

        success_logs = {"iran": "", "foreign": ""}
        if not dry_run and bplan:
            since_ir = f"--since '{ir_start_utc}' -n 200" if ir_start_utc else "-n 200"
            for u in bplan.get("iran_units", []):
                try:
                    _, o_u, _ = ir_runner.run(f"journalctl -u {u} {since_ir} --no-pager",
                                             best_effort=True, retryable=True)
                    success_logs["iran"] += f"=== IRAN LOG ({u}) ===\n" + o_u.strip() + "\n"
                except Exception:
                    pass
            since_fr = f"--since '{fr_start_utc}' -n 200" if fr_start_utc else "-n 200"
            for u in bplan.get("foreign_units", []):
                try:
                    _, o_u, _ = fr_runner.run(f"journalctl -u {u} {since_fr} --no-pager",
                                              best_effort=True, retryable=True)
                    success_logs["foreign"] += f"=== FOREIGN LOG ({u}) ===\n" + o_u.strip() + "\n"
                except Exception:
                    pass
        metrics["logs"] = success_logs
        metrics["unit_timestamps"] = unit_timestamps
        metrics["run_start_utc"] = ir_start_utc
        metrics.setdefault("not_measurable", False)
        cooldown_needed = 30 if not metrics["disqualified"] else 60
        return metrics

    except Exception as ex:
        cooldown_needed = 60
        err_logs = {"iran": "", "foreign": ""}
        if not dry_run and bplan:
            since_ir = f"--since '{ir_start_utc}' -n 200" if ir_start_utc else "-n 200"
            for u in bplan.get("iran_units", []):
                try:
                    _, o_u, _ = ir_runner.run(f"journalctl -u {u} {since_ir} --no-pager",
                                             best_effort=True, retryable=True)
                    err_logs["iran"] += f"=== IRAN LOG ({u}) ===\n" + o_u.strip() + "\n"
                except Exception:
                    pass
            since_fr = f"--since '{fr_start_utc}' -n 200" if fr_start_utc else "-n 200"
            for u in bplan.get("foreign_units", []):
                try:
                    _, o_u, _ = fr_runner.run(f"journalctl -u {u} {since_fr} --no-pager",
                                              best_effort=True, retryable=True)
                    err_logs["foreign"] += f"=== FOREIGN LOG ({u}) ===\n" + o_u.strip() + "\n"
                except Exception:
                    pass
        blocked = classify_environment_block(f"{ex} {err_logs['iran']} {err_logs['foreign']}")
        # The exception type has to be in the text: a live benchmark failure raised an exception whose
        # str() was empty, and "Execution error: " told the operator nothing about what to fix.
        err_text = f"{type(ex).__name__}: {ex}"[:200]
        row = {
            "protocol": protocol,
            "score": 0.0,
            "profile": profile,
            "scores_by_profile": {"balanced": 0.0, "gaming": 0.0, "ultraspeed": 0.0},
            "disqualified": True,
            "not_measurable": bool(blocked),
            "dq_reasons": ([blocked] if blocked else []) + [f"Execution error: {err_text}"],
            "bulk_step": bulk_step,
            "jitter_ms": jit if jit is not None else 0.0,
            "throughput_mbps": throughput_mbps,
            "throughput_measured": throughput_measured,
            "ladder_error": err_text,
            "base_rtt_ms": base_rtt,
            "breakdown": {"lat_avg": 0.0, "jitter_ms": 0.0, "loss_pct": 100.0, "s_lat": 0.0, "s_jit": 0.0, "s_bulk": 0.0, "s_stab": 0.0, "loss_penalty": 0.0, "ramp_multiplier": 0.0, "seconds_survived": 0.0, "throughput_mbps": 0.0, "base_rtt": base_rtt, "overhead_ratio": 0.0},
            "logs": err_logs,
            "unit_timestamps": unit_timestamps,
            "run_start_utc": ir_start_utc,
            "stages_measured": [],
            "iperf3": iperf_metrics,
            "preflight": preflight_report,
        }
        flap = transport_flaps(ir_runner, fr_runner)
        if flap:
            row["transport"] = flap
        # A run that stopped partway is not comparable to a full one, so it stays disqualified and
        # unscored - but the stages that did finish measured the real tunnel, and zeroing them made the
        # first live xray-reverse run report 0 ms latency and 100% loss for a tunnel that had just
        # served a complete 1 MB ladder step. Unmeasured stages default to their worst value.
        if lat is not None:
            carried = evaluate_tunnel_metrics(
                lat, jit, bulk_step,
                survived if survived is not None else 0.0,
                loss if loss is not None else 100.0,
                profile=profile, throughput_mbps=throughput_mbps,
                throughput_measured=throughput_measured, base_rtt=base_rtt)
            row["breakdown"] = carried["breakdown"]
            row["dq_reasons"] = carried["dq_reasons"] + row["dq_reasons"]
            row["stages_measured"].append("probe")
        if survived is not None:
            row["stages_measured"].append("stability")
        if bulk_step:
            row["stages_measured"].append(f"ladder_step_{bulk_step}")
        if iperf_metrics is not None:
            row["stages_measured"].append("iperf3")
        return row
    finally:
        # Best-effort teardown of the benchmark tunnel and test backend. Runs unconditionally so a
        # failed measurement cannot leave benchmark units behind; each step is independent, so a
        # failure partway through leaves residue rather than rolling back.
        #
        # `timeout=protocols.TEARDOWN_TIMEOUT_SEC` rather than mock_ssh's 30 s default: `systemctl stop`
        # blocks until systemd's own `TimeoutStopUSec` budget expires, which the carrier unit declares as
        # `protocols.CARRIER_STOP_BUDGET_SEC`. A caller that outlasts that declaration reads a real
        # "stop is slow" as "the SSH channel died", and a timeout raised here is not absorbed by
        # best_effort - it aborts the remaining teardown steps and leaves units behind.
        if not dry_run:
            if bplan:
                for tc in bplan.get("teardown_iran", []):
                    ir_runner.run(tc, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                for tc in bplan.get("teardown_foreign", []):
                    fr_runner.run(tc, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                for u in bplan.get("iran_units", []):
                    ir_runner.run(f"systemctl stop {u}; systemctl disable {u}", best_effort=True,
                                  timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                for u in bplan.get("foreign_units", []):
                    fr_runner.run(f"systemctl stop {u}; systemctl disable {u}", best_effort=True,
                                  timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                if protocol == "GRE":
                    ir_runner.run(f"ip tunnel del grep{pair_id}b", best_effort=True)
                    fr_runner.run(f"ip tunnel del grep{pair_id}b", best_effort=True)
            ir_runner.run("fuser -k 8897/tcp 8898/tcp; rm -f /tmp/best-test-* /tmp/best_test* /tmp/test*", best_effort=True)
            fr_runner.run("kill $(cat /tmp/best-test-backend.pid 2>/dev/null); fuser -k 8897/tcp 8898/tcp; rm -f /tmp/best-test-* /tmp/best_test_backend.py /tmp/best-test-backend.pid", best_effort=True)
        for runner in owned_runners:
            runner.close()
        is_mock = isinstance(ir_runner, MockSSHClient)
        time.sleep(0.01 if (dry_run or is_mock) else cooldown_needed)

def run_all_benchmarks(pair: dict, dry_run: bool = True, callback=None, profile: str = "balanced", run_id: str = "") -> list[dict]:
    """Runs ladder benchmarks across all supported protocols and ranks them with run_id tracking."""
    import uuid
    results = []
    pair_id = pair.get("id", 1)
    run_identifier = run_id or f"run-{uuid.uuid4().hex[:8]}"

    # Pre-benchmark Phase: Measure direct Base RTT outside the tunnel (Senior Architect C3)
    base_rtt_error = ""
    try:
        ir_runner = get_ssh_runner(pair["iran"], dry_run=dry_run, host_role="iran")
    except (TransientTransportError, ConnectionError, OSError) as ex:
        # One host that will not answer the control channel is not eight broken tunnels. The sweep goes
        # on with no baseline - which the scorer already treats as "overhead cannot be judged" - and
        # each protocol row reports its own failure when its session fails too. Aborting here is what
        # cost the first live sweep every row it had already measured.
        ir_runner = None
        base_rtt, is_fallback = 0.0, True
        base_rtt_error = storage.mask_addresses(f"{type(ex).__name__}: {str(ex)[:160]}")
    if ir_runner is not None:
        # The session opened above is closed whether the measurement answers or not. Before this, a
        # raise out of `measure_direct_base_rtt` skipped the straight-line `close()` (one stranded Iran
        # session per sweep, the #71 shape) and left `base_rtt`/`is_fallback` unbound for the row that
        # was about to be written. A baseline that could not be measured is the same verdict as a host
        # that would not answer the control channel, so it degrades the same way.
        try:
            rtt_res = measure_direct_base_rtt(ir_runner, protocols.dial_address(pair["foreign"]),
                                             dry_run=dry_run)
            base_rtt = rtt_res.base_rtt_ms
            is_fallback = rtt_res.is_fallback
        except (TransientTransportError, ConnectionError, OSError) as ex:
            base_rtt, is_fallback = 0.0, True
            base_rtt_error = storage.mask_addresses(f"{type(ex).__name__}: {str(ex)[:160]}")
        finally:
            ir_runner.close()

    try:
        storage.update_pair_base_rtt(pair_id, base_rtt, is_fallback=is_fallback)
    except Exception:
        pass
    pair["base_rtt_ms"] = base_rtt

    for proto in protocols.get_supported_protocols():
        if callback:
            callback(proto, "TESTING")
        try:
            res = run_single_benchmark(pair, proto, dry_run=dry_run, profile=profile, base_rtt=base_rtt)
        except (TransientTransportError, ConnectionError, OSError) as ex:
            # Disqualified and not_measurable, never scored: a protocol was not slow here, it was not
            # measured at all, and letting that enter the ranking is how an unrelated network flap
            # decides which tunnel the report recommends.
            reason = (f"SSH_UNREACHABLE: no control channel to the hosts, so nothing was measured for "
                      f"{proto}: {type(ex).__name__}: {str(ex)[:160]}")
            if base_rtt_error:
                reason += f" (same transport failure seen while measuring base RTT: {base_rtt_error})"
            res = _blocked_row(proto, profile, base_rtt, storage.mask_addresses(reason))
            res["transport_error"] = True
        res["run_id"] = run_identifier
        results.append(res)
        storage.record_benchmark(pair_id, proto, res, run_id=run_identifier)

    results.sort(key=lambda r: r.get("score", 0.0), reverse=True)
    return results

def backend_listener_state(runner, port: int) -> tuple[str, str]:
    """Is anything listening on `port` on the peer host? Answer with a read that can fail three ways.

    This replaces a one-line instrument of the form `ss -H -tln 2>/dev/null | grep -c ':PORT\\b' || true`
    whose rc was discarded: `grep` exits 1 on no match and `ss` exits non-zero when it is missing, and both
    landed in the operator's message as `listeners on peer :9443=0` - the product reporting "no backend"
    on evidence it had not actually read (invariant 19: a discarded rc plus `2>/dev/null` is a fail-open).

    Two independent reads must agree before `no-backend` is claimed:
      1. `ss -H -tln` in full, with the port matched in Python off the Local Address:Port column. Parsing
         the column rather than grepping the text kills the substring bug this project already recorded
         (#73: `grep ':443'` counts `:4433`), and reading the whole table gives a positive control - a
         host with zero LISTEN rows at all is a host this instrument cannot read, not a host with no
         backend.
      2. `ss`'s own `sport` filter, which is a different code path through the same kernel socket table.

    Returns (state, detail). `detail` is an empty string only for `answered`.
    """
    try:
        rc, out, err = runner.run("ss -H -tln", best_effort=True, retryable=True)
    except Exception as ex:
        return "unreadable", f"control channel failed: {type(ex).__name__}"
    if rc != 0:
        return "unreadable", f"ss rc={rc} {(err or out).strip()[:80]}"
    def _listen_rows(text: str) -> list[list[str]]:
        # The state column decides, not the line count. `ss` without `-H` prints a header whose 4th field is
        # the literal `Address:Port`, and a header is not a row: counting it would give every host at least
        # one row and silence the positive control below.
        rows = [ln.split() for ln in (text or "").splitlines() if ln.strip()]
        return [f for f in rows if len(f) >= 4 and f[0].upper() in ("LISTEN", "UNCONN")]

    rows = _listen_rows(out)
    if not rows:
        return "unreadable", "ss returned no LISTEN rows: instrument cannot read this host"

    first = sum(1 for f in rows if f[3].rpartition(":")[2] == str(port))
    try:
        rc2, out2, err2 = runner.run(f"ss -H -tln '( sport = :{port} )'", best_effort=True, retryable=True)
    except Exception as ex:
        return "unreadable", f"second read failed: {type(ex).__name__}"
    if rc2 != 0:
        return "unreadable", f"filtered ss rc={rc2} {(err2 or out2).strip()[:80]}"
    second = sum(1 for f in _listen_rows(out2) if f[3].rpartition(":")[2] == str(port))
    if first or second:
        if first != second:
            # Two reads of one kernel table that disagree: say so instead of picking one.
            return "unreadable", f"reads disagree ({first} vs {second})"
        return "answered", ""
    return "no-backend", ""


def backend_target_block(protocol: str, frontend: int, backend_port, plan: dict) -> str:
    """Refuse a plan whose delivery end is unknown, or whose artifact does not carry the port declared.

    Two failures, both measured rather than inferred:
      * `undeclared-target` - a transport that must deliver somewhere writes no delivery port at all. That
        is a generator regression, and it is the one status the deploy cannot discover later: the tunnel
        comes up, the frontend binds, and the traffic goes nowhere.
      * mismatch - the operator declared backend port B and the emitted artifact says C. A generator that
        ignores a kwarg it was given is exactly as dangerous as one that never had it, and the read-back
        is what makes the declaration a control instead of a form field.

    Returns "" when the plan may proceed, so the call site phrases its own refusal the way
    `carrier_camouflage_block` and `destination_pin_block` do.
    """
    info = protocols.backend_target(protocol, plan)
    if info["status"] == "undeclared-target":
        return (f"{protocol} emits no delivery port for the traffic it carries: the tunnel would come up "
                f"and deliver into nothing. This is a generator defect, not a host condition - see "
                f"protocols.BACKEND_TARGETS (§8b).")
    if backend_port not in (None, "", 0) and int(backend_port) != int(info["port"] or 0):
        return (f"{protocol} was told the delivery port is {backend_port} but the config it generated "
                f"delivers to {info['port']} at {info['source'] or 'no named artifact'}. Refusing to "
                f"deploy a plan that does not match its own declaration.")
    return ""


def declare_backend(pair_id: int, protocol: str, frontend: int, backend_port,
                    state: str, dry_run: bool) -> None:
    """Persist what the delivery end of this deploy actually is, so the monitor judges a declared fact.

    `failover_monitor` has to distinguish 'the transport is dead' from 'the transport works and nothing
    answers behind it', and until #63 the only way it could do that was to infer from the shape of the
    samples. Writing the state here is what turns that inference into a record: the deploy is the moment
    the product knows, on its own read, whether the port it delivers into is answered.
    """
    if dry_run:
        return
    effective = int(backend_port) if backend_port not in (None, "", 0) else int(frontend)
    state = state if state in storage.BACKEND_STATES else "unreadable"
    storage.set_pair_backend(pair_id, backend_port=effective, backend_state=state)


# The deploy verification probe, run on the Iran host against the frontend.
# F8 (found live, 2026-10-23): the original probe sent one plaintext HTTP HEAD
# and required response bytes. That silently fails a whole class of healthy
# backends - a TLS-first service (the test pair's Xray inbound on :443)
# drops non-TLS input without replying, so the deploy rolled back a tunnel
# that was carrying data correctly, with backend_listener_state confirming
# the service was there ("answered") the whole time. The probe now tries two
# shapes and accepts the first that exchanges data: the HTTP HEAD, then a
# real TLS handshake (a completed handshake is bytes in both directions by
# definition). It stays fail-closed: a backend that completes neither -
# silence, EOF, timeout - still reports NO_DATA, and the absent-backend
# decision below is untouched.
DATA_PROBE_PROGRAM = r"""
import socket, ssl
def attempt(tls):
    try:
        s = socket.create_connection(('127.0.0.1', __FRONTEND__), 3)
    except Exception:
        return False
    try:
        s.settimeout(3)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(s, server_hostname='www.google.com')
            ss.close()
            return True
        s.sendall(b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n')
        return len(s.recv(512)) > 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass
ok = attempt(False) or attempt(True)
print('PROBE_DATA_EXCHANGED' if ok else 'NO_DATA')
""".strip()


def data_probe_command(frontend: int) -> str:
    """The remote command that runs DATA_PROBE_PROGRAM against `frontend`."""
    return 'python3 -c "' + DATA_PROBE_PROGRAM.replace(
        "__FRONTEND__", str(int(frontend))) + '"'


def deploy_tunnel(pair: dict, choice: str, dry_run: bool = True,
                  force_confirmed: bool = False, override_active_users: bool = False,
                  verification_timeout: float = 30.0, ir_runner=None, fr_runner=None) -> dict:
    """Fully deploys a selected tunnel with server-side gating, data probe verification, and rollback."""
    pair_id = pair.get("id", 1)
    frontend = pair.get("frontend", 443)
    # The declared delivery port, or None meaning "deliver where the frontend number says". Read from the
    # pair rather than from a call argument because it is topology: it survives a redeploy and is answered
    # by whatever service the operator put on the peer host, not by this function.
    backend_port = pair.get("backend_port") or None
    ir_spec = pair["iran"]
    fr_spec = pair["foreign"]
    blocked = carrier_camouflage_block(pair, choice)
    if blocked:
        # A production deploy has to refuse for the same reason the benchmark does, or the gate only
        # protects the report and the operator still ships the tunnel it was warned about.
        raise ValueError(blocked)
    ir_ip = protocols.dial_address(ir_spec, choice)
    fr_ip = protocols.dial_address(fr_spec, choice)

    # The plan is generated here rather than inside the try below, and it is the object the rest of the
    # deploy writes, because the destination-anchor gate has to judge the artifact that actually lands
    # on the hosts. It also has to run before `release_port_safely`: a refusal raised after the frontend
    # was freed would enter the rollback branch, and that branch tears down the *current* deployment of
    # this protocol - so a gate that fires before anything is touched refuses without taking a live
    # tunnel down with it.
    plan = protocols.generate_deployment(choice, pair_id, ir_ip, fr_ip, frontend,
                                         backend_port=backend_port)
    blocked_target = backend_target_block(choice, frontend, backend_port, plan)
    if blocked_target:
        # Same placement rule as the two gates below it: decide before the frontend is released, because a
        # refusal raised after that enters the rollback branch and tears down the tunnel that was already
        # carrying traffic - an outage caused by declining to make a broken change.
        raise ValueError(blocked_target)
    blocked_pin = destination_pin_block(pair_id, choice, plan, record=not dry_run)
    if blocked_pin:
        raise ValueError(blocked_pin)

    # Server-side validation of frontend port against SSH/reserved ports
    validate_frontend_port(frontend, ir_spec.get("port", 22), fr_spec.get("port", 22))

    owned_runners = []
    try:
        if ir_runner is None:
            ir_runner = get_ssh_runner(ir_spec, dry_run=dry_run, host_role="iran")
            owned_runners.append(ir_runner)
        if fr_runner is None:
            fr_runner = get_ssh_runner(fr_spec, dry_run=dry_run, host_role="foreign")
            owned_runners.append(fr_runner)

        # F3: every userspace binary this deployment is about to start is first installed
        # through the pinned-checksum path (binary_manager), on both hosts. Until now that
        # installer was called only by tests and a scratch bootstrap script, so a production
        # deploy started whatever binary happened to be on the host - missing, stale or
        # tampered, it was neither checked nor reported. The check sits in this gate window
        # on purpose: a refusal here closes the sessions and leaves the tunnel that is
        # currently serving traffic untouched, where a failure discovered after the
        # frontend was released would enter the rollback branch. In dry-run / mock mode
        # verify_and_install_binary answers for itself without touching the host.
        for role, runner in (("iran", ir_runner), ("foreign", fr_runner)):
            for binary in binary_manager.required_binaries(choice):
                ok, msg = binary_manager.verify_and_install_binary(
                    runner, binary, dry_run=dry_run)
                if not ok:
                    raise ValueError(
                        f"Refusing to deploy {choice}: {binary} on the {role} host failed "
                        f"checksum-verified installation: {msg}")

        # A carrier shares its frontend with whatever DNAT rule already owns that port, and the rule that
        # predates it wins, so this is decided here - before a port is released, a file is written or a unit
        # is enabled - for the same reason the anchor gate above is: a refusal that fires later would either
        # take a live tunnel down on the way out or certify an envelope that never sees a packet.
        if choice in protocols.INNER_PROBED and not dry_run:
            _, o_pre, _ = ir_runner.run("iptables -t nat -S PREROUTING", best_effort=True)
            conflict = carrier_dnat_conflict(o_pre, frontend,
                                            protocols.carrier_inner_pair(choice, pair_id, "prod")[1])
            if conflict:
                raise ValueError(CARRIER_DNAT_CONFLICT.format(conflict=conflict))
            # The other way a carrier can be pre-empted on these hosts, and the one that actually happened on
            # 2026-10-11: a VTI that already owns the outer endpoint pair. Checked per host with that host's own
            # orientation, using the same two `dial_address` values the plan above was generated with, so the
            # gate judges the tuple the unit is about to ask for rather than a paraphrase of it. It runs before
            # `release_port_safely` for the reason the anchor gate has: a refusal raised after the frontend was
            # freed enters the rollback branch and tears down the current deployment of this protocol, which for
            # a carrier means an outage caused by declining to make a change.
            if choice == "ESP":
                iface = protocols.carrier_iface("ESP", pair_id, "prod")
                for role, r, local, remote in (("iran", ir_runner, ir_ip, fr_ip),
                                               ("foreign", fr_runner, fr_ip, ir_ip)):
                    blocked_vti = carrier_vti_conflict(r, role, local, remote, iface)
                    if blocked_vti:
                        raise ValueError(blocked_vti)
    except BaseException:
        # #72, and the reason the gates above no longer carry their own close loops: those discharged the
        # obligation for the two verdicts the gate knew about, and for nothing else. Anything raised inside
        # this window - a `run` whose channel died mid-read, a classifier that raised, the second host
        # refusing to connect - used to leave both sessions open for the life of the process, because the
        # `finally` that closes them belongs to the try below, which this never entered. Closing here and
        # re-raising unchanged keeps every refusal byte-identical, and deliberately does not enter that
        # try's rollback branch: reaching it would tear down the deployment these gates exist to protect.
        for runner in owned_runners:
            runner.close()
        raise

    release_info = None
    try:
        # 1. Server-side check for protected port
        port_st = check_port_status(ir_runner, frontend)
        if port_st["is_listening"]:
            validate_server_side_port_release(port_st, force_confirmed, override_active_users)
            release_info = release_port_safely(ir_runner, frontend, port_st, dry_run=dry_run)
            if not release_info["success"]:
                # F11: starting the new units while the incumbent still holds the
                # frontend produces a shadowed deploy that reports success through
                # the incumbent. Refuse here instead: nothing new has started yet,
                # and the rollback branch restores the previous service.
                raise ValueError(
                    f"Refusing to deploy {choice}: frontend {frontend} is still held by "
                    f"'{port_st['process_name']}' (PID {port_st['pid']}) after release")

        # 2. The deployment plan (namespace='prod') was generated and gated above, before a port was
        #    released or a session opened; reusing that object is what makes the gate meaningful.

        # 3. Execute setup commands on Iran and Foreign
        for c in plan.get("iran_cmds", []):
            ir_runner.run(c, check=True)
        for c in plan.get("foreign_cmds", []):
            fr_runner.run(c, check=True)

        # 4. Upload configuration files and units with 0600 permissions guaranteed.
        #    Written over the channel's stdin rather than as a heredoc in a command line: these files
        #    carry the REALITY private key, the chisel/wstunnel key material and the ESP SA keys, and a
        #    heredoc makes all of that an argument of a remote shell - visible in /proc/<pid>/cmdline,
        #    which is the same exposure this product already refuses inside a systemd unit.
        for fpath, content in plan.get("iran_files", {}).items():
            ir_runner.write_file(fpath, content)
        for fpath, content in plan.get("foreign_files", {}).items():
            fr_runner.write_file(fpath, content)

        # 5. Start systemd units
        if plan.get("iran_units"):
            ir_runner.run("systemctl daemon-reload", check=True)
            for u in plan["iran_units"]:
                ir_runner.run(f"systemctl enable --now {u}", check=True)
        if plan.get("foreign_units"):
            fr_runner.run("systemctl daemon-reload", check=True)
            for u in plan["foreign_units"]:
                fr_runner.run(f"systemctl enable --now {u}", check=True)

        # 6. Apply conntrack tuning as one script so the shell variables computed inside it survive
        for ct in protocols.conntrack_tuning_cmds():
            ir_runner.run(ct, check=True)
            fr_runner.run(ct, check=True)

        # 7. Real Verification Window (30s) with active data probing
        verified = False
        flow_reason = ""
        # A deploy that never reaches the failure branch makes no claim about the delivery end, so the
        # default is the one that asserts nothing.
        transport_only = False
        backend_state = "not-applicable"
        deadline = time.time() + (0.5 if dry_run else verification_timeout)

        is_mock = isinstance(ir_runner, MockSSHClient)
        st_after = {"is_listening": False}
        while time.time() < deadline:
            st_after = check_port_status(ir_runner, frontend)
            if dry_run or is_mock:
                verified = True
                break

            # Live verification with real data probe
            if choice in protocols.INNER_PROBED:
                # A carrier: inner ICMP through its interface, plus the DNAT that puts traffic into it.
                reached, o_v = carrier_inner_reachable(ir_runner, choice, pair_id)
                _, o_nat, _ = ir_runner.run("iptables -t nat -S PREROUTING", best_effort=True,
                                            retryable=True)
                inner_peer = protocols.carrier_inner_pair(choice, pair_id, "prod")[1]
                # The destination, not the port. `--dport 443` is present in this chain whether or not the
                # rule that answers it is the one this carrier just appended, and PREROUTING is
                # first-match, so a dport-only test certifies an envelope whose traffic goes elsewhere -
                # the same shadowing the pre-flight refusal above looks for, now measured after the fact.
                shadowed = carrier_dnat_conflict(o_nat, frontend, inner_peer)
                in_force = (f"--to-destination {inner_peer}:{frontend}" in o_nat) and not shadowed
                if reached and in_force:
                    verified = True
                    break
                flow_reason = (f"carrier inner path {'ok' if reached else 'dark'}"
                               f"{' (no answer: ' + o_v[:80] + ')' if o_v else ''}, "
                               f"dnat_rule_for_:{frontend}_in_force={in_force}"
                               + (f" (shadowed by {shadowed})" if shadowed else ""))
            else:
                # For user-space reverse tunnel: verify socket listening AND data byte exchange
                if st_after["is_listening"]:
                    _, o_v, _ = ir_runner.run(
                        data_probe_command(frontend),
                        best_effort=True
                    )
                    if "PROBE_DATA_EXCHANGED" in o_v:
                        verified = True
                        # Something on the peer answered through the tunnel, which is the delivery end
                        # being live - recorded rather than inferred later from the absence of a failure.
                        backend_state = "answered"
                        break
                    # The frontend is bound, so the transport is up, and the probe still got nothing back.
                    # A working tunnel that fronts an absent service is indistinguishable from a broken one
                    # by this probe alone, and the old message said only "no data flow" - which rolled back
                    # healthy deploys and sent the operator to journald. The delivery end is now read once,
                    # after the window, by `backend_listener_state`, and it decides the outcome below
                    # (`engine.backend_listener_state`); guessing it from a discarded-rc `grep -c` here was
                    # the fail-open this closes.

            time.sleep(0.1 if dry_run else 2)

        if not verified:
            # "No verified data flow" has at least three causes - the unit never came up, the peer cannot
            # reach the transport port, or nothing answers behind the frontend - and the old message
            # reported none of them, so every failure became a manual journald hunt. Unit state is the one
            # discriminator the control channel can always see.
            causes: list[str] = []
            backend_state = "not-applicable"
            units_active = True
            if not (dry_run or is_mock):
                for runner, units in ((ir_runner, plan.get("iran_units", [])),
                                      (fr_runner, plan.get("foreign_units", []))):
                    for unit in units:
                        state = runner.run(f"systemctl is-active {unit} 2>&1 | head -1",
                                           best_effort=True)[1].strip() or "unknown"
                        if state != "active":
                            units_active = False
                        causes.append(f"{unit}={state}")
                causes.append(f"frontend:{frontend}_listening={st_after['is_listening']}")
                if flow_reason:
                    causes.append(flow_reason)
                if choice in protocols.INNER_PROBED:
                    # A carrier's delivery is layer-3 to the peer host itself and its own verdict is inner
                    # ICMP, which already failed above; there is no listener claim to make or unmake.
                    backend_state = "not-applicable"
                else:
                    read_port = int(backend_port) if backend_port else int(frontend)
                    backend_state, why = backend_listener_state(fr_runner, read_port)
                    causes.append(f"backend:{read_port}={backend_state}"
                                  + (f" ({why})" if why else ""))

                if (backend_state == "no-backend" and st_after["is_listening"] and units_active
                        and choice not in protocols.INNER_PROBED):
                    # The transport is proven up (frontend bound, both units active, the reverse forward
                    # established) and the port it delivers into is proven unlistened-to by two agreeing
                    # reads. Nothing here is wrong with the tunnel: there is no application behind it on
                    # the peer. Rolling this back would replace an outage nobody has with a 15 s switchover
                    # and a different transport that delivers into the same absent port - which is precisely
                    # what pair 2 was subjected to before this branch existed.
                    #
                    # `answered` and `unreadable` both fall through to the failure below: the first is a
                    # real transport fault, and the second is indeterminate evidence, which does not get to
                    # certify a deployment either.
                    verified = True
                    transport_only = True

            if not verified:
                detail = f" ({'; '.join(causes)})" if causes else ""
                raise RuntimeError(
                    f"Deployment verification FAILED after {verification_timeout:.0f}s: "
                    f"No verified data flow on frontend :{frontend}{detail}. Automatic rollback initiated."
                )

        # 8. A carrier is the one deployment that changes what the *pair* is, not just what runs on it:
        #    record the envelope the gate above reads, so REALITY on this pair is judged against ESP
        #    rather than against the GRE inference that was true until a minute ago.
        declare_carrier(pair_id, choice, dry_run)
        declare_backend(pair_id, choice, frontend, backend_port, backend_state, dry_run)

        return {
            "ok": True,
            "status": (f"ACTIVE-TRANSPORT-ONLY-{choice}-{frontend}" if transport_only
                       else f"ACTIVE-{choice}-{frontend}"),
            "protocol": choice,
            "frontend": frontend,
            "transport_only": transport_only,
            "backend_state": backend_state,
            "pair_id": pair_id
        }

    except Exception as ex:
        # Automatic rollback on failure
        if release_info:
            rollback_port_release(ir_runner, release_info)
        # Regenerated, and for a carrier that is only safe because the SPI and reqid are derived from the
        # pair rather than random: a rolled-back ESP must delete the SAs this attempt installed, and an
        # ephemeral SPI would have named states that never existed while the real ones stayed put.
        plan = protocols.generate_deployment(choice, pair_id, ir_ip, fr_ip, frontend,
                                            backend_port=backend_port)
        # A rollback step that cannot complete must not become the reported failure. Measured on the live
        # pair on 2026-10-11: the ESP carrier's `ip link del` on the Foreign host blocked in the kernel for
        # minutes (`unregister_netdevice: waiting for espp1 to become free. Usage count = -895`, seven
        # parked tasks after seven teardowns), the stop/teardown step ran out its 30s budget, and because
        # `best_effort` absorbs a non-zero exit but not a dropped or timed-out transport, that TimeoutError
        # propagated out of the `except` block and replaced the exception the rollback exists to report.
        # The operator saw "timed out on systemctl stop" for a deploy that had failed for an unrelated
        # reason, and the unit files and the boot-enabled state were left behind because the loop never
        # reached them. So every step is attempted, the count of steps that did not complete is audited,
        # and the original cause is what is raised.
        #
        # Two independent fixes meet here. The carrier unit no longer unregisters its interface at all
        # (`protocols.unit_for`: `ExecStop=/sbin/ip link set ... down`), so the 450 s block is off the
        # rollback path by design. The budget below is still required: it is what turns any future slow
        # stop into a completed step instead of a masked exception, and it is derived from the same
        # constant the unit declares, so the two cannot drift apart.
        stalled = []
        for role, runner, key in (("iran", ir_runner, "teardown_iran"),
                                  ("foreign", fr_runner, "teardown_foreign")):
            for tc in plan.get(key, []):
                try:
                    runner.run(tc, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                except Exception as tex:
                    stalled.append(f"{role}:{type(tex).__name__}")
        if choice == "GRE":
            for role, runner in (("iran", ir_runner), ("foreign", fr_runner)):
                try:
                    runner.run(f"ip tunnel del grep{pair_id}", best_effort=True,
                               timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                except Exception as tex:
                    stalled.append(f"{role}:{type(tex).__name__}")
        if stalled:
            storage.log_audit(pair_id, "DEPLOY_ROLLBACK", "PARTIAL",
                              f"{len(stalled)} teardown step(s) did not complete for {choice}: "
                              f"{', '.join(stalled[:8])}")
        retract_carrier(pair_id, choice, dry_run)
        raise ex
    finally:
        # Only the sessions this call opened. The live witness measured what the unconditional close did:
        # it was handed two sessions, deployed through them, and every inspection command after the
        # return died on `DeadSessionError`, because the caller's sessions had been closed underneath it.
        # A function that closes what it was not given also cannot be called twice in a row on one pair.
        for runner in owned_runners:
            runner.close()
