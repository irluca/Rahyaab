#!/usr/bin/env python3
"""Automated Failover & Self-Healing Engine for Tunnel Studio Pro v2.0 (Phase 2).
Enforces continuous health checking, benchmark-driven candidate selection, staged
protocol switchover (service gap, see execute_failover), anti-flapping circuit
breaker, and audit traceability.
"""
import time
import json
import re
import typing
import storage
import protocols
import scoring
import probe
import engine
import monitoring
from mock_ssh import get_ssh_runner

class TunnelHealthReport(typing.NamedTuple):
    status: str             # "HEALTHY", "DEGRADED", "DOWN", "TRANSPORT-ONLY"
    loss_pct: float
    latency_ms: float
    overhead_ratio: float    # lat / base_rtt, i.e. 2.5 means 2.5x; scoring's same-named key is the
                             # excess above base (1.5 there == 2.5 here), hence the shared ceiling
    is_unit_active_iran: bool
    is_unit_active_foreign: bool
    is_socket_listening: bool
    details: str
    # The delivery end of the tunnel, read on the host it lands on: "answered", "no-backend",
    # "unreadable", or "" for a carrier, which has no local delivery to ask about. Defaulted so every
    # earlier construction still compiles - and so an absent read stays visibly absent rather than
    # defaulting to a claim.
    backend_state: str = ""
    # The RST-injection signal from monitoring.ttl_verdict: "clean",
    # "injection_suspected", "inconclusive", or "" when it was not sampled
    # (dry run, or too few replies to judge). A signal, never a status input:
    # an injector follows the traffic to whichever protocol replaces the
    # tunnel, so switching on it would pay a switchover gap for nothing.
    ttl_state: str = ""

class TunnelHealthChecker:
    """Probes the operational health and SLA adherence of active tunnel deployments."""

    @staticmethod
    def check_health(ir_runner, fr_runner, pair: dict, active_protocol: str,
                     base_rtt: float = 0.0, dry_run: bool = False) -> TunnelHealthReport:
        """Inspects remote systemd units, listening sockets, latency, and packet loss."""
        pair_id = pair.get("id", 1)
        ir_ip = protocols.dial_address(pair["iran"], active_protocol)
        fr_ip = protocols.dial_address(pair["foreign"], active_protocol)
        frontend = pair.get("frontend_port", pair.get("frontend", 443))

        # A pair that has never been benchmarked carries base_rtt_ms = 0.0, and the fallback that used
        # to sit here (42ms) substituted a guess for a measurement. On the live test pair the L7
        # latency through a working tunnel measured 380-620ms with 0% loss, so the guess scored 9-15x
        # overhead and reported DEGRADED - and evaluate_and_heal switches protocols on anything other
        # than HEALTHY, which put a fresh, healthy deployment one poll away from a needless
        # switchover. With no baseline the ratio is not a measurement, so it decides nothing here.
        baseline = float(base_rtt or 0.0) or float(pair.get("base_rtt_ms") or 0.0)
        has_baseline = baseline > 0.0

        # 1. Fetch deployment plan to locate active systemd units. Deliberately generated without the pair's
        # declared backend port: a health check names the units to interrogate, and a refusal raised here
        # would turn an inconsistent declaration into an ERROR sample instead of a measurement.
        plan = protocols.generate_deployment(active_protocol, pair_id, ir_ip, fr_ip, frontend)
        ir_units = plan.get("iran_units", [])
        fr_units = plan.get("foreign_units", [])

        ir_active = True
        for u in ir_units:
            # A health check is the input to a decision that can tear a tunnel down, so a sample lost
            # to a dropped SSH session must never be readable as a dead unit. retryable is the
            # intent; safety.is_read_only_command() is the machine's own check, and the monitor's
            # ERROR path stays reachable because a transport failure is still raised, not swallowed.
            _, o, _ = ir_runner.run(f"systemctl is-active {u}", best_effort=True, retryable=True)
            if o.strip() != "active":
                ir_active = False
                break

        fr_active = True
        for u in fr_units:
            _, o, _ = fr_runner.run(f"systemctl is-active {u}", best_effort=True, retryable=True)
            if o.strip() != "active":
                fr_active = False
                break

        # 2. Inspect frontend socket listener on Iran. Read for every protocol, but it only decides for
        # one that owns a socket: a carrier's frontend is a PREROUTING DNAT rule, so `ss` shows nothing
        # while the envelope is passing traffic perfectly.
        _, o_sock, _ = ir_runner.run(f"ss -tlnp | grep -E ':{frontend} '", best_effort=True,
                                     retryable=True)
        sock_listening = bool(o_sock.strip())
        is_carrier = active_protocol in protocols.INNER_PROBED

        # 3. Measure latency and packet loss through the tunnel endpoint (P0-5), with the instrument the
        # protocol can actually answer.
        #
        # A user-space transport is measured as one HTTP round trip, with the agent re-installed on demand
        # from the persistent path in probe.py - it must not depend on /tmp, because the benchmark that
        # first deployed it wipes /tmp/best* on teardown. A carrier has no L7 endpoint at all: what is being
        # asked is whether inner packets cross the envelope, which is kernel ICMP through the interface and
        # needs no agent on the host.
        #
        # The distinction is load-bearing rather than tidy: evaluate_and_heal switches protocols on anything
        # other than HEALTHY, and a carrier measured by the L7 test can never be HEALTHY. A monitor polling
        # a working ESP underlay would therefore "repair" it - by tearing down the envelope every transport
        # on the pair is riding on.
        loss_val, lat_val, lat_sampled = 100.0, 999.0, False
        if is_carrier:
            iface = protocols.carrier_iface(active_protocol, pair_id, "prod")
            peer_inner = protocols.carrier_inner_pair(active_protocol, pair_id, "prod")[1]
            instrument = f"inner ICMP via {iface} to {peer_inner}"
            _, o_ping, _ = ir_runner.run(f"ping -c 10 -i 0.2 -W 1 -I {iface} {peer_inner}",
                                         best_effort=True, timeout=25, retryable=True)
            m_rtt = re.search(r'rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)', o_ping)
            m_loss = re.search(r'([0-9.]+)% packet loss', o_ping)
            if m_loss:
                loss_val = float(m_loss.group(1))
            if m_rtt:
                lat_val, lat_sampled = float(m_rtt.group(2)), True
            probe_available = True
        else:
            instrument = f"L7 round trip through 127.0.0.1:{frontend}"
            probe_available = probe.ensure_probe(ir_runner)
            o_loss = o_lat = ""
            if probe_available:
                # Same budget rule as the benchmark: a probe prints only at the end, so the SSH read has
                # to outlast its samples. On the live pair the L7 round trip measured 620ms, which puts 30
                # samples close to the 30s default - and a TimeoutError here would abort the health check
                # of a tunnel that is merely slow.
                _, o_loss, _ = ir_runner.run(probe.cmd("loss", "127.0.0.1", frontend),
                                             best_effort=True, timeout=probe.cmd_timeout("loss"),
                                             retryable=True)
                _, o_lat, _ = ir_runner.run(probe.cmd("lat", "127.0.0.1", frontend),
                                            best_effort=True, timeout=probe.cmd_timeout("lat"),
                                            retryable=True)

            m_loss = re.search(r'LOSS:([0-9.]+)', o_loss)
            if m_loss:
                loss_val = float(m_loss.group(1))
            else:
                # If probe cannot run or output is unparseable, this is an active outage (100% loss)
                loss_val = 100.0

            m_lat = re.search(r'AVG:([0-9.]+)', o_lat)
            lat_val = float(m_lat.group(1)) if m_lat else 999.0
            lat_sampled = bool(m_lat)

        ratio = round(lat_val / baseline, 2) if baseline > 0 and lat_val else 0.0
        judged = f"loss={loss_val}%, lat={lat_val:.1f}ms, overhead={ratio}x base RTT ({instrument})"
        if not lat_sampled:
            # 999 is only an internal budget, never a measurement: a report that prints it as a
            # latency tells the operator the tunnel is slow when in fact no request completed.
            judged = (f"loss={loss_val}%, lat=no completed sample within the probe budget "
                      f"(overhead not judgeable; {instrument})")

        # 3b. Read the delivery end of the tunnel itself, on the host that is supposed to receive it.
        #
        # This is the question #63 was opened on: a reverse transport delivers into a port on the peer, and
        # if nothing listens there then the L7 probe above is not measuring the tunnel at all - it is
        # measuring the absence of an application, and reporting it as 100% loss. Pair 2 carried that
        # misread for a week: `xray portal active, :9443 listening, loss 100%` scored the transport as dead
        # while the transport was the only part that worked.
        #
        # A carrier is skipped: its delivery is layer-3 into the peer host's own stack, and its verdict is
        # the inner ICMP above. Asking a listener table about it is the category error that made an ESP
        # underlay un-monitorable when the L7 probe was the only instrument.
        backend_state, backend_why, backend_port = "", "", None
        if not is_carrier:
            backend_port = int(pair.get("backend_port") or frontend)
            backend_state, backend_why = engine.backend_listener_state(fr_runner, backend_port)
            if not dry_run:
                # Refresh the record on every health pass, state only: the declaration belongs to the
                # operator, the read belongs to this moment. `set_pair_backend` audits a change, not a
                # confirmation, so a poll that agrees with the last poll costs no log line.
                storage.set_pair_backend(pair_id, backend_state=backend_state)

        # 4. Status classification
        transport_up = ir_active and fr_active and (is_carrier or sock_listening)
        if not probe_available:
            status = "DOWN"
            details = f"Measurement agent unavailable at {probe.PROBE_PATH} (fail-safe: treated as outage)"
        elif (backend_state == "no-backend" and transport_up and loss_val >= 25.0):
            # Not a healthy pair - a client that connects here still gets nothing - and not an outage of
            # the transport either. The name says which of the two the operator is looking at.
            status = "TRANSPORT-ONLY"
            details = (f"Transport up, nothing behind it (ir_act={ir_active}, fr_act={fr_active}, "
                       f"sock={sock_listening}, delivery port {backend_port} has no listener on the peer; "
                       f"L7 loss={loss_val}% is a statement about the application, not this tunnel)")
        elif not ir_active or not fr_active or loss_val >= 25.0 or (not is_carrier and not sock_listening):
            status = "DOWN"
            sock_note = ("n/a - carrier frontend is a DNAT, not a listener" if is_carrier
                         else str(sock_listening))
            details = f"Unit/Socket failure (ir_act={ir_active}, fr_act={fr_active}, sock={sock_note}, loss={loss_val}%)"
        elif loss_val > 5.0 or (baseline > 0 and ratio > scoring.LAT_OVERHEAD_CEILING + 1.0):
            status = "DEGRADED"
            details = f"Performance degradation ({judged})"
        else:
            status = "HEALTHY"
            details = (f"Operational normal ({judged})" if baseline > 0 else
                       f"Operational normal ({judged}, no baseline recorded so overhead is not judged; "
                       f"run a benchmark)")

        # TTL families of the peer's replies, sampled on the outer path. Where
        # ICMP does not cross at all the sample set is empty and the verdict
        # stays unknown - the report then carries "", not an accusation.
        ttl_state = ""
        if not dry_run:
            ttl = monitoring.ttl_verdict(monitoring.collect_ttl_samples(ir_runner, fr_ip))
            if ttl["state"] != "unknown":
                ttl_state = ttl["state"]
            if ttl["state"] == "injection_suspected":
                details += f" [ttl: {ttl['note']}]"

        if backend_state == "no-backend" and status in ("HEALTHY", "DEGRADED"):
            # Traffic crossed the tunnel while the peer's listener table says nothing listens on the port
            # the config delivers into. Both cannot be true of the same instant: either the application
            # binds a different port than the plan declares (a stale or wrong declaration), or one of the
            # two reads is stale. Said out loud rather than picking the convenient reading - pair 2's whole
            # history is what happens when this product's evidence disagrees with itself silently.
            details += (" [contradiction: L7 traffic crossed while the delivery port reads unlistened-to;"
                        " check the declared backend port against what actually serves]")

        return TunnelHealthReport(
            status=status,
            loss_pct=loss_val,
            latency_ms=lat_val,
            overhead_ratio=ratio,
            is_unit_active_iran=ir_active,
            is_unit_active_foreign=fr_active,
            is_socket_listening=sock_listening,
            details=details,
            backend_state=backend_state,
            ttl_state=ttl_state
        )

def _median(vals: list[float]) -> float:
    vals = sorted(vals)
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2.0

class FailoverCandidateSelector:
    """Selects the best replacement protocol based on historical benchmark scores."""

    @staticmethod
    def select_best_candidate(pair_id: int, current_protocol: str,
                              allowed_protocols: list[str] = None,
                              pair: dict = None) -> str | None:
        """Queries SQLite benchmark table and ranks viable alternatives by score.

        `pair` is optional but decides something real: given the topology it drops any candidate the
        carrier gate refuses, so a switchover is not proposed onto a transport that the executor will
        immediately reject. Without it the selector cannot know the carrier, and the refusal still
        happens in execute_failover - a proposal is never the safety boundary.
        """
        if allowed_protocols is None:
            allowed_protocols = protocols.get_supported_protocols()

        def refused_candidate(proto: str) -> bool:
            if pair is None:
                return False
            if engine.carrier_camouflage_block(pair, proto):
                return True
            # A candidate that cannot deliver where this pair's application actually listens is not a
            # candidate. The declaration is read from the pair, the refusal from the same function the
            # deploy calls, and an unset declaration refuses nothing: a switchover whose successor would
            # move the delivery port back to the frontend would take a working tunnel down in order to
            # build one that answers nothing - an outage manufactured by a repair.
            return bool(protocols.backend_port_refusal(
                proto, pair.get("frontend_port", pair.get("frontend", 443)),
                pair.get("backend_port") or None))

        # Rank by the median of every qualified run, not by the latest one.
        #
        # Five isolated live runs of one unchanged wstunnel-v10 configuration, minutes apart:
        #   score  77.78  45.00  78.58  79.05  72.35     lat  68.9  96.5  68.5  67.3  73.5 ms
        # Four agree near 68 ms; one reached 96.5 ms, which crosses the s_lat floor and costs 33
        # points. `select_best_candidate` read the newest row only, and rows arrive newest-first
        # (storage.get_benchmarks orders by id DESC), so a failover choice for a TLS-over-WebSocket
        # transport was one draw from that distribution.
        #
        # The median is the smallest honest change: with one run it returns that run, so a freshly
        # benchmarked pair ranks exactly as it did before. The sample itself lives in
        # median_protocol_scores so the selector and auto mode cannot disagree.
        candidates, disqualified = median_protocol_scores(
            pair_id, allowed_protocols, pair)
        candidates.pop(current_protocol, None)

        if candidates:
            # Rank by score, but last-resort protocols sort after every
            # ordinary one no matter what they scored: in hard
            # conditions the healer tries ordinary protocols first, then
            # Bale, then spoof as the final fallback. Within the last
            # tier Bale precedes spoof. A last-resort protocol with a
            # higher score must never jump the queue ahead of a working
            # ordinary protocol.
            _LAST_TIER = {"bale-webrtc": 1, "spoof-wireguard": 2}
            sorted_candidates = sorted(
                candidates.items(),
                key=lambda x: (_LAST_TIER.get(x[0], 0), -x[1]))
            return sorted_candidates[0][0]

        # Deterministic fallback list if no benchmark exists yet
        default_order = [
            "GRE", "wstunnel-v10", "rathole-noise", "chisel-wss",
            "backhaul-wss", "hysteria2", "frp-TLS", "kcptun", "xray-reverse"
        ]
        for p in default_order:
            # A protocol that was measured and disqualified must not come back through the fallback:
            # every row being disqualified reads exactly like no row at all, and on the live pair GRE
            # is permanently unmeasurable beside its own production underlay, so switching to it there
            # would fail to start. No evidence and contradicted evidence are not the same case.
            if p in disqualified:
                continue
            if refused_candidate(p):
                continue
            if p in allowed_protocols and p != current_protocol:
                return p

        return None

def median_protocol_scores(pair_id: int, allowed_protocols: list[str] = None,
                           pair: dict = None) -> tuple[dict[str, float], set[str]]:
    """Median qualified score per protocol, from the same evidence the
    selector reads: measured rows only (simulated dry-run rows are not
    evidence), disqualified rows excluded from the sample but remembered
    as a set. This is the shared sample so the selector and the auto mode
    cannot disagree about what the evidence says.
    """
    if allowed_protocols is None:
        allowed_protocols = protocols.get_supported_protocols()

    def refused_candidate(proto: str) -> bool:
        if pair is None:
            return False
        if engine.carrier_camouflage_block(pair, proto):
            return True
        return bool(protocols.backend_port_refusal(
            proto, pair.get("frontend_port", pair.get("frontend", 443)),
            pair.get("backend_port") or None))

    scores: dict[str, list[float]] = {}
    disqualified: set[str] = set()
    for b in storage.get_benchmarks(pair_id):
        proto = b.get("protocol")
        if not proto or proto not in allowed_protocols:
            continue
        if refused_candidate(proto):
            continue
        if (b.get("capacity_basis") or "") == "simulated":
            continue
        if b.get("disqualified", 0) == 1:
            disqualified.add(proto)
            continue
        scores.setdefault(proto, []).append(float(b.get("score", 0.0)))
    return ({proto: _median(vals) for proto, vals in scores.items()},
            disqualified)


# A challenger must beat the current transport by this much before auto
# mode even proposes a move: benchmark medians wobble by a point or two
# between sweeps, and a pair that flip-flops on noise is worse than one
# that stays on a transport a hair worse than the latest winner.
AUTO_SWITCH_MARGIN = 2.0


def auto_winner(pair_id: int, current_protocol: str, pair: dict = None,
                allowed_protocols: list[str] = None) -> tuple[str | None, float]:
    """The transport an auto pair should be on, and by how much it leads.

    Returns (current, 0.0) when the current transport already leads or the
    challenger's lead is inside the margin - "stay" is a decision, not a
    missing answer. Returns (None, 0.0) when no protocol has qualified
    evidence at all: auto mode cannot choose from nothing, and the caller
    falls back to the selector's deterministic list.
    """
    scores, _ = median_protocol_scores(pair_id, allowed_protocols, pair)
    if not scores:
        return None, 0.0
    winner = max(scores.items(), key=lambda kv: kv[1])[0]
    if winner == current_protocol:
        return current_protocol, 0.0
    current_score = scores.get(current_protocol)
    if current_score is None:
        # The current transport was never measured: any measured winner
        # leads by its whole score, which is exactly what "unmeasured"
        # means here - the evidence favours the measured one.
        return winner, scores[winner]
    margin = scores[winner] - current_score
    if margin < AUTO_SWITCH_MARGIN:
        return current_protocol, margin
    return winner, margin


def refresh_auto_choice(pair_id: int, current_protocol: str, pair: dict = None) -> str | None:
    """Recomputes the auto winner from current evidence and remembers it.

    Called after a benchmark sweep and after a heal, so the pair card and
    the monitor's drift note always describe the evidence as it stands,
    not the sweep that happened to run first.
    """
    winner, _ = auto_winner(pair_id, current_protocol, pair=pair)
    if winner:
        storage.set_pair_auto_protocol(pair_id, winner)
    return winner


def _underlay_protocol(pair: dict, current_protocol: str) -> str | None:
    """The carrier underneath the current transport, if any.

    The declared underlay first (set by engine.declare_carrier on a
    carrier's success path, cleared by retract_carrier when the envelope
    goes); a current carrier is its own underlay. An overlay with no
    declaration names nothing: guessing 'gre' here would tear down a
    carrier the pair may not have, so an undeclared overlay simply has
    no underlay for switch purposes.
    """
    declared = (pair.get("underlay_carrier") or "").strip().lower()
    if declared in ("gre", "esp"):
        return declared.upper()
    if current_protocol in protocols.CARRIER_PROTOCOLS:
        return current_protocol
    return None


def _carrier_dnat_cmds(cmds: list[str]) -> list[str]:
    """The carrier frontend's PREROUTING DNAT commands (tcp + udp) from a plan's command list.

    Both carriers build exactly two: one per protocol, forwarding the
    frontend to the peer's inner address. Filtering on the two tokens
    rather than the full rule keeps this true for GRE and ESP alike
    without duplicating either generator's template.
    """
    return [c for c in cmds if "PREROUTING" in c and "DNAT" in c]


def _manifest_dnat_rows(rows: list[str]) -> list[str]:
    """Manifest rows (R|table|PREROUTING|verb|pos|spec) that install a DNAT.

    The carrier's firewall manifest is what its unit re-applies on boot,
    so a cutover that only deletes the live rules would be undone by the
    next reboot, re-shadowing the overlay. These rows are the ones a
    cutover drops from the manifest and a peel puts back.
    """
    out = []
    for row in rows:
        parts = row.split("|")
        if len(parts) == 6 and parts[0] == "R" and parts[2] == "PREROUTING" and "DNAT" in parts[5]:
            out.append(row)
    return out


def _carrier_manifest_path(plan: dict) -> str | None:
    """The carrier manifest file path from its plan, or None if the plan has none."""
    for key in plan.get("iran_files", {}):
        if key.endswith("-fw.rules"):
            return key
    return None


class FailoverManager:
    """Orchestrates staged switchover, anti-flapping hysteresis, and circuit breaker."""

    # One switchover is recorded twice on purpose: record_failover_event keeps the in-process
    # timestamp and execute_failover's audit row keeps the durable one. They are the same fact, so a
    # persisted event within this tolerance of a remembered one is merged instead of counted twice.
    # Two genuinely different failovers of one pair cannot fall inside it - Stage 3 to Stage 7 tear
    # units down, rewrite configs and wait for an L7 round trip, and min_interval is minutes.
    DEDUP_WINDOW_S = 2.0

    def __init__(self, min_interval_seconds: int = 180, max_failovers_per_window: int = 3, window_seconds: int = 900):
        self.min_interval = min_interval_seconds
        self.max_failovers = max_failovers_per_window
        self.window_seconds = window_seconds
        # In-memory history tracking: pair_id -> list of float timestamps
        self._history: dict[int, list[float]] = {}

    def is_flapping(self, pair_id: int) -> tuple[bool, str]:
        """Checks if failover requests for pair_id violate anti-flapping limits.

        This process's in-memory history is merged with the persisted audit events, because the
        breaker has to survive whatever restarts the process or rebuilds the manager: with memory
        alone, a pair that crash-loops across restarts met an empty window every time and was torn
        down again without limit. Only completed switchovers count: a failed attempt ends on the
        protocol it started on, so it never consumes the breaker's budget (see
        storage.recent_failover_events).
        """
        now = time.time()
        overlay = [t for t in self._history.get(pair_id, []) if (now - t) <= self.window_seconds]
        # The tolerance merges a persisted event with the in-memory one that describes the same
        # switchover - never with another persisted event. Merging those collapsed a rapid burst of
        # real failovers into a single one, which is the exact case the breaker exists for.
        timestamps = overlay + [seen for seen in storage.recent_failover_events(pair_id, self.window_seconds)
                                if not any(abs(seen - t) < self.DEDUP_WINDOW_S for t in overlay)]
        timestamps.sort()
        self._history[pair_id] = timestamps

        if timestamps:
            time_since_last = now - timestamps[-1]
            if time_since_last < self.min_interval:
                return True, f"Anti-flapping: Last failover was {time_since_last:.1f}s ago (min {self.min_interval}s)"

        if len(timestamps) >= self.max_failovers:
            return True, f"Circuit Breaker TRIPPED: {len(timestamps)} failovers within {self.window_seconds}s"

        return False, ""

    def record_failover_event(self, pair_id: int):
        """Records timestamp of an executed failover."""
        now = time.time()
        if pair_id not in self._history:
            self._history[pair_id] = []
        self._history[pair_id].append(now)

    # How long a replaced transport stays restorable after a successful
    # switchover. Long enough for the operator (or the next monitor pass)
    # to notice a bad successor, short enough that a stale config cannot
    # linger unnoticed: the monitor purges expired records on its passes.
    QUARANTINE_GRACE_SEC = 600.0

    def execute_failover(self, pair: dict, current_protocol: str, target_protocol: str,
                         reason: str, dry_run: bool = False,
                         ir_runner=None, fr_runner=None,
                         quarantine: bool = True, is_rollback: bool = False) -> dict:
        """Switches a pair from current_protocol to target_protocol.

        This is NOT zero-downtime and NOT make-before-break: Stage 3 stops the old units
        before Stage 5 starts the new ones, so there is a real service gap on `frontend`. What it
        does guarantee is that the successor plan is generated and its files staged first, so a
        failure in Stage 1 or 2 aborts while the live tunnel is still serving traffic.

        Quarantine (default on, carriers excepted): Stage 3 stops and
        disables the old units but does NOT delete their unit files or
        configs, and records them. If the successor then fails its smoke
        check, the old transport is restored by re-enabling those units -
        a rollback in seconds, not a redeploy. A successful switchover
        leaves the record until the grace window expires, when the
        monitor's purge finally runs the stored teardown.

        is_rollback: this execution restores the transport that was
        healthy before the switch being undone. It skips the circuit
        breaker check: the failed switch itself recorded a failover
        event (its smoke failure already interrupted service), so an
        unqualified check blocks the very restoration the breaker exists
        to protect and strands the pair with no working tunnel
        (2026-10-27: ESP -> hysteria2 smoke-failed, then its rollback to
        ESP was refused as "0.4s ago"). A rollback is a restoration,
        not a flap: it runs at most once per failed switch, all other
        gates still apply, and a successful rollback still records a
        failover event, so everything after it stays breaker-governed.

        Underlay switches: when the current transport is a carrier and
        the target is an overlay, the carrier is KEPT as the underlay.
        The overlay is deployed first (it dials through the carrier
        inners), smoke-checked, and only then does the carrier's
        frontend DNAT move aside so client traffic reaches the overlay's
        listener; the carrier interface, its peer route and its firewall
        manifest stay, minus the two DNAT rows, so a reboot cannot
        re-shadow the overlay. A failed overlay deploy leaves the
        carrier untouched, so there is nothing to roll back. When the
        current transport is an overlay riding an underlay and the
        target is a carrier, the cheap path peels the overlay off and
        restores the underlay's DNAT (verified by inner reachability);
        if the underlay is dead, the switch falls through to a full
        redeploy of the carrier, tearing the dead underlay down first
        so the fresh deploy starts clean.
        """
        pair_id = pair.get("id", 1)
        frontend = pair.get("frontend_port", pair.get("frontend", 443))

        # Each plan resolves its own peer addresses: a switchover away from GRE needs the public outer
        # endpoint for the old unit (GRE builds the underlay) and the dial_host for the new one, so one
        # pair-wide address cannot describe both halves.
        def plan_for(protocol: str, backend_port=None) -> dict:
            """The plan for one side of a switchover.

            `backend_port` is passed only for the successor, by the caller that has already refused any
            target which cannot honour it. The old plan is generated without it: it exists to name the
            units and files to remove, neither of which depends on the delivery port, and a pair whose
            *current* transport cannot take the declaration (a carrier, an egress proxy) must still be
            switchable away from - raising here would strand the pair on the transport the operator is
            trying to leave.
            """
            return protocols.generate_deployment(
                protocol, pair_id,
                protocols.dial_address(pair["iran"], protocol),
                protocols.dial_address(pair["foreign"], protocol),
                frontend, backend_port=backend_port)

        # The carrier gate is the same single function the benchmark and the deploy path consult.
        # A switchover writes configs and starts units directly, without ever calling
        # engine.deploy_tunnel, so before this it could move a live pair onto the one transport the
        # project refuses to deploy - and it would do that unprompted, as a "repair", on top of an
        # outage. Failing over *away* from such a transport stays allowed; only the target is judged.
        blocked_by_carrier = engine.carrier_camouflage_block(pair, target_protocol)
        blocked_by_backend = protocols.backend_port_refusal(
            target_protocol, frontend, pair.get("backend_port") or None)
        if blocked_by_carrier or blocked_by_backend:
            blocked_by = blocked_by_carrier or blocked_by_backend
            storage.log_audit(pair_id, "FAILOVER_BLOCKED",
                              "CARRIER_REFUSAL" if blocked_by_carrier else "BACKEND_REFUSAL",
                              blocked_by)
            return {
                "success": False,
                "blocked": True,
                "not_measurable": True,
                "reason": blocked_by,
                "current_protocol": current_protocol,
                "attempted_protocol": target_protocol
            }

        # Check circuit breaker — unless this execution IS the rollback of
        # the switch that just failed. A rollback is a restoration, not
        # a flap: it runs at most once per failed switch, and a
        # successful one still records an event, so everything after it
        # stays breaker-governed. Without the exemption, a real move
        # that happened just before the failure would refuse the
        # restoration and strand the pair with no working tunnel
        # (2026-10-27: ESP -> hysteria2 smoke-failed, then its rollback
        # to ESP was refused as "0.4s ago" under the old rule that
        # counted failures).
        if not is_rollback:
            is_flap, flap_msg = self.is_flapping(pair_id)
            if is_flap:
                storage.log_audit(pair_id, "FAILOVER_BLOCKED", "CIRCUIT_BREAKER", flap_msg)
                return {
                    "success": False,
                    "blocked": True,
                    "reason": flap_msg,
                    "current_protocol": current_protocol
                }

        created_ir = (ir_runner is None)
        created_fr = (fr_runner is None)
        try:
            if ir_runner is None:
                ir_runner = get_ssh_runner(pair["iran"], dry_run=dry_run, host_role="iran")
            if fr_runner is None:
                fr_runner = get_ssh_runner(pair["foreign"], dry_run=dry_run, host_role="foreign")
            t_start = time.time()
        except BaseException:
            # #72, and this is the shape the original claim described: the second open connects and
            # authenticates, so a pair whose Foreign host is unreachable raises here - outside the try
            # below - and the Iran session this call had just created was never handed to the `finally`
            # that closes it. One session stranded per attempted switchover, on the pair that is already
            # broken, which is the worst possible time to run out of control channels. Closes only what
            # this call created and re-raises unchanged: a caller-supplied session stays its caller's
            # obligation, and the abort must still propagate as an abort.
            if created_ir and hasattr(ir_runner, "close"):
                ir_runner.close()
            if created_fr and hasattr(fr_runner, "close"):
                fr_runner.close()
            raise

        try:
            # Peel: the current transport is an overlay riding an
            # underlay, and the target is that underlay carrier. The
            # carrier never left — its interface and peer route are
            # still there — so try the cheap path first. A None result
            # means the underlay is dead: fall through to the full
            # redeploy below, which tears the dead underlay down first.
            _underlay = _underlay_protocol(pair, current_protocol)
            if (current_protocol not in protocols.CARRIER_PROTOCOLS
                    and target_protocol in protocols.CARRIER_PROTOCOLS
                    and _underlay == target_protocol):
                _peeled = self._peel_to_underlay(
                    pair, plan_for, current_protocol, target_protocol,
                    reason, dry_run, ir_runner, fr_runner, t_start)
                if _peeled is not None:
                    return _peeled

            # Stage 1: Generate the successor plan BEFORE touching the live deployment, so a
            # generation or validation failure aborts without having caused an outage.
            try:
                new_plan = plan_for(target_protocol, pair.get("backend_port") or None)
            except Exception as plan_err:
                err_msg = f"Failed to generate target deployment plan for {target_protocol}: {plan_err}"
                storage.log_audit(pair_id, "FAILOVER_ABORTED", "PLAN_ERROR", err_msg)
                return {
                    "success": False,
                    "error": err_msg,
                    "current_protocol": current_protocol
                }

            # Stage 1b: judge the successor's own config before it is written anywhere. A switchover
            # does not go through engine.deploy_tunnel, so without this the transport that a deploy
            # would refuse is the one an outage promotes - and by Stage 2 the old units are already
            # gone, which turns "refuse" into "blackout". A dry run judges and refuses but records
            # nothing: it deployed no tunnel, and recording one would raise a false rotation warning.
            blocked_pin = engine.destination_pin_block(pair_id, target_protocol, new_plan,
                                                       record=not dry_run)
            if blocked_pin:
                storage.log_audit(pair_id, "FAILOVER_BLOCKED", "DESTINATION_ANCHOR_REFUSAL",
                                  blocked_pin)
                return {
                    "success": False,
                    "blocked": True,
                    "not_measurable": True,
                    "reason": blocked_pin,
                    "current_protocol": current_protocol,
                    "attempted_protocol": target_protocol
                }

            # Stage 1c: the carrier-specific host check, in the same position as the anchor gate and for
            # the same reason - a switchover bypasses engine.deploy_tunnel, so a rule enforced only there
            # is a rule an outage can step over. ESP is the case that matters here: promoting a pair to an
            # ESP carrier while another VTI owns the pair's outer endpoint pair does not fail cleanly, it
            # fails after Stage 3 has removed the current tunnel, and the unit that cannot be created then
            # belongs to a pair with no working envelope at all.
            if target_protocol == "ESP":
                ir_ip_t = protocols.dial_address(pair["iran"], target_protocol)
                fr_ip_t = protocols.dial_address(pair["foreign"], target_protocol)
                for role, r, local, remote in (("iran", ir_runner, ir_ip_t, fr_ip_t),
                                               ("foreign", fr_runner, fr_ip_t, ir_ip_t)):
                    blocked_vti = engine.carrier_vti_conflict(
                        r, role, local, remote, protocols.carrier_iface("ESP", pair_id, "prod"))
                    if blocked_vti:
                        # The audit record has to say which of the two refusals fired. Logging a conflict
                        # when the read simply failed would put an unobserved fact in the permanent log, and
                        # this is decided by comparing against the same constant the gate formats rather
                        # than by sniffing the text of a message that is free to be reworded.
                        vti_key = ("CARRIER_VTI_UNREADABLE"
                                   if blocked_vti == engine.CARRIER_VTI_UNREADABLE.format(role=role)
                                   else "CARRIER_VTI_CONFLICT")
                        storage.log_audit(pair_id, "FAILOVER_BLOCKED", vti_key, blocked_vti)
                        return {
                            "success": False,
                            "blocked": True,
                            "not_measurable": True,
                            "reason": blocked_vti,
                            "current_protocol": current_protocol,
                            "attempted_protocol": target_protocol
                        }

            # Overlay on a live carrier: the current transport is the
            # envelope the target dials through, so tearing it down
            # first is what made every carrier -> overlay switch fail
            # its smoke check. Deploy the overlay first (client traffic
            # keeps flowing through the carrier DNAT meanwhile), smoke
            # it, and only then move the DNAT aside. A failed overlay
            # leaves the carrier untouched: restored without a rollback.
            if (current_protocol in protocols.CARRIER_PROTOCOLS
                    and target_protocol not in protocols.CARRIER_PROTOCOLS):
                return self._overlay_on_carrier(
                    pair, plan_for, new_plan, current_protocol, target_protocol,
                    reason, dry_run, ir_runner, fr_runner, t_start)

            # Stage 2: Stage new files to disk with strict 0600 permissions.
            #
            # The parent directory is created by the writer rather than left to the plan's own setup
            # commands, because those run in Stage 4 - after Stage 3 has already torn the live tunnel
            # down. On a host where a protocol's config directory has never existed, writing into it
            # answers "No such file or directory", so the first switchover to that protocol produced an
            # outage followed by a failed repair: the exact outcome this staged-before-teardown order
            # exists to prevent. mkdir is a no-op where the directory is already there.
            for fpath, content in new_plan.get("iran_files", {}).items():
                ir_runner.write_file(fpath, content)
            for fpath, content in new_plan.get("foreign_files", {}).items():
                fr_runner.write_file(fpath, content)

            # Stage 3: Teardown old degraded units only once new configs are safely staged
            #
            # The budget is `protocols.TEARDOWN_TIMEOUT_SEC`, not mock_ssh's 30 s default, and on this
            # path the reason is sharper than "a slow stop would abort the rest": a mid-switchover step
            # that times out is an ambiguous outcome, and ambiguity must never look like a failure the
            # monitor has to react to. Measured on the live pair on 2026-10-11 - an ESP carrier that has
            # transformed traffic took 450 s to unregister, every step of that teardown ran out 30 s, and
            # the resulting TimeoutError is exactly the signal that makes a health checker trust nothing
            # it is seeing.
            old_plan = plan_for(current_protocol)
            quarantined = None
            _underlay = _underlay_protocol(pair, current_protocol)
            if (current_protocol not in protocols.INNER_PROBED
                    and target_protocol in protocols.CARRIER_PROTOCOLS
                    and _underlay):
                # Leaving an overlay for a carrier: the overlay's
                # underlay must go too, or the fresh carrier deploys
                # over a dead envelope — and the overlay must be torn
                # down, not quarantined, because its restore would ride
                # that dead envelope. (The peel above already tried the
                # cheap path when the target IS the underlay; reaching
                # here means the underlay is dead, or the target is a
                # different carrier.)
                for cmd in old_plan.get("teardown_iran", []):
                    ir_runner.run(cmd, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                for cmd in old_plan.get("teardown_foreign", []):
                    fr_runner.run(cmd, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                _underlay_plan = plan_for(_underlay)
                for cmd in _underlay_plan.get("teardown_iran", []):
                    ir_runner.run(cmd, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                for cmd in _underlay_plan.get("teardown_foreign", []):
                    fr_runner.run(cmd, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                engine.retract_carrier(pair_id, _underlay, dry_run)
            elif quarantine and current_protocol not in protocols.INNER_PROBED:
                # Quarantine instead of teardown: the units stop (so the
                # frontend frees) but their files and configs stay, and the
                # teardown that would delete them is stored, not run.
                # Carriers are excepted: their interfaces are never removed
                # by design, and retracting the declaration is what the
                # existing path does - quarantining one would leave a stale
                # 'esp' declaration pointing at a carrier that is gone.
                for u in old_plan.get("iran_units", []):
                    ir_runner.run(f"systemctl stop {u}; systemctl disable {u}",
                                  best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                for u in old_plan.get("foreign_units", []):
                    fr_runner.run(f"systemctl stop {u}; systemctl disable {u}",
                                  best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                quarantined = storage.record_quarantine(
                    pair_id, current_protocol, old_plan, self.QUARANTINE_GRACE_SEC)
            else:
                for cmd in old_plan.get("teardown_iran", []):
                    ir_runner.run(cmd, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
                for cmd in old_plan.get("teardown_foreign", []):
                    fr_runner.run(cmd, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
            # A carrier is not just another unit: tearing it down removes the envelope every other
            # transport is judged against, so its declaration leaves with it. Left behind, a later REALITY
            # deploy would read 'esp' on a pair that can now only offer cleartext proto 47.
            engine.retract_carrier(pair_id, current_protocol, dry_run)

            # Ensure frontend port is strictly released before activating new successor
            ir_runner.run(f"fuser -k {frontend}/tcp 2>/dev/null || true", best_effort=True)

            # Stage 4: Run initial setup commands for new successor
            for cmd in new_plan.get("iran_cmds", []):
                ir_runner.run(cmd, check=True)
            for cmd in new_plan.get("foreign_cmds", []):
                fr_runner.run(cmd, check=True)

            # Stage 5: Reload systemd and start new units
            if new_plan.get("foreign_units"):
                fr_runner.run("systemctl daemon-reload", check=True)
                for u in new_plan["foreign_units"]:
                    fr_runner.run(f"systemctl enable --now {u}", check=True)

            if new_plan.get("iran_units"):
                ir_runner.run("systemctl daemon-reload", check=True)
                for u in new_plan["iran_units"]:
                    ir_runner.run(f"systemctl enable --now {u}", check=True)

            # Stage 6: Post-switch Smoke Verification
            # `systemctl is-active` only proves the daemon stayed up. On the live pair the transport
            # that follows this stage can be running and still carry nothing (no route over the
            # underlay, peer unit not yet listening, auth rejected), and stamping the pair ACTIVE on
            # that verdict hides the outage from both the operator and the next health check. So the
            # requirement is the same one engine.deploy_tunnel holds a fresh deployment to - traffic
            # actually crosses - asked in the one form the successor is able to answer.
            smoke_ok = True
            smoke_detail = ""
            for u in new_plan.get("iran_units", []):
                _, o_st, _ = ir_runner.run(f"systemctl is-active {u}", best_effort=True)
                if o_st.strip() != "active":
                    smoke_ok = False
                    smoke_detail = f"unit {u} reported '{o_st.strip()}'"
                    break

            if smoke_ok and not dry_run:
                if target_protocol in protocols.INNER_PROBED:
                    # A carrier has no listener to ask: its frontend is an iptables DNAT in PREROUTING,
                    # which traffic this host generates itself never traverses. Probing 127.0.0.1 against it
                    # reports "no round trip" for a tunnel that is carrying traffic fine, so a switchover
                    # *to* a carrier was refused by a test it could not pass. Inner ICMP is the verdict
                    # engine.deploy_tunnel uses for the same shape, reused here rather than paraphrased.
                    reached, o_ping = engine.carrier_inner_reachable(ir_runner, target_protocol, pair_id)
                    if not reached:
                        smoke_ok = False
                        peer = protocols.carrier_inner_pair(target_protocol, pair_id, "prod")[1]
                        smoke_detail = (f"no inner reply on {peer} via "
                                        f"{protocols.carrier_iface(target_protocol, pair_id, 'prod')} "
                                        f"(ping: {o_ping[:60]!r})")
                elif not probe.ensure_probe(ir_runner):
                    smoke_ok = False
                    smoke_detail = "L7 probe could not be installed on Iran"
                else:
                    # Give the successor a moment to establish its peer channel before deciding.
                    time.sleep(2)
                    _, o_smoke, _ = ir_runner.run(probe.cmd("lat", "127.0.0.1", frontend),
                                                  best_effort=True,
                                                  timeout=probe.cmd_timeout("lat"))
                    if not re.search(r'AVG:([0-9.]+)', o_smoke):
                        smoke_ok = False
                        smoke_detail = (f"no L7 round-trip on 127.0.0.1:{frontend} "
                                        f"(probe output: {o_smoke.strip()[:60]!r})")

            duration_ms = round((time.time() - t_start) * 1000.0, 1)

            if not smoke_ok:
                err_msg = f"Smoke verification failed for replacement protocol {target_protocol}: {smoke_detail}"
                storage.log_audit(pair_id, "FAILOVER_FAILED", "SMOKE_ERROR", err_msg)
                restored = False
                if quarantined is not None:
                    # The whole point of the quarantine: the old units are
                    # still on disk with their configs, so restoring them
                    # is an enable, not a redeploy. The pair goes back to
                    # ACTIVE on the old protocol; the failure is still
                    # reported, because the switchover did not happen.
                    for u in quarantined["foreign_units"]:
                        fr_runner.run(f"systemctl enable --now {u}", best_effort=True)
                    for u in quarantined["iran_units"]:
                        ir_runner.run(f"systemctl enable --now {u}", best_effort=True)
                    storage.update_pair_status(pair_id, status="ACTIVE",
                                               active_tunnel=current_protocol)
                    storage.clear_quarantine(pair_id)
                    restored = True
                    storage.log_audit(pair_id, "FAILOVER_ROLLBACK", "RESTORED",
                                      f"Successor {target_protocol} failed smoke; "
                                      f"restored {current_protocol} from quarantine")
                return {
                    "success": False,
                    "error": err_msg,
                    "restored": restored,
                    "current_protocol": current_protocol,
                    "attempted_protocol": target_protocol
                }

            # Stage 7: Success commit: Record audit log, record event in history, update SQLite state
            self.record_failover_event(pair_id)
            storage.update_pair_status(pair_id, status="ACTIVE", active_tunnel=target_protocol)
            # Only now: the declaration describes a carrier that has been verified to be carrying.
            engine.declare_carrier(pair_id, target_protocol, dry_run)
            storage.log_audit(
                pair_id, "FAILOVER", "SUCCESS",
                f"Successfully failed over {current_protocol} -> {target_protocol} in {duration_ms}ms. Trigger: {reason}"
            )

            return {
                "success": True,
                "old_protocol": current_protocol,
                "new_protocol": target_protocol,
                "duration_ms": duration_ms,
                "reason": reason,
                "quarantined": ({"protocol": quarantined["protocol"],
                                 "expires_at": quarantined["expires_at"]}
                                if quarantined else None)
            }

        except Exception as e:
            err_msg = f"Exception during failover switchover: {str(e)}"
            storage.log_audit(pair_id, "FAILOVER_FAILED", "EXCEPTION", err_msg)
            return {
                "success": False,
                "error": err_msg,
                "current_protocol": current_protocol,
                "attempted_protocol": target_protocol
            }
        finally:
            if created_ir and hasattr(ir_runner, "close"):
                ir_runner.close()
            if created_fr and hasattr(fr_runner, "close"):
                fr_runner.close()

    def _manifest_set_dnat(self, ir_runner, carrier_plan, protocol, pair_id, keep):
        """Drop (keep=False) or restore (keep=True) the carrier's DNAT rows in its firewall manifest.

        The manifest is what the carrier unit re-applies on boot. A
        cutover that leaves the rows behind is undone by the next
        reboot, re-shadowing the overlay; a peel that leaves them out
        loses the DNAT on the next reboot. A missing manifest (a deploy
        from before manifests) is not an error: there is nothing a
        reboot would restore, so the live rules are the whole story.
        Returns False only when a manifest was read but could not be
        written back — the caller treats that as a failed cutover
        rather than leaving a reboot time-bomb.
        """
        path = _carrier_manifest_path(carrier_plan)
        if not path:
            return True
        _, content, _ = ir_runner.run(f"cat {path}", best_effort=True)
        if not content.strip():
            return True
        comment = protocols.generate_firewall_comment(f"{pair_id}-prod", protocol)
        try:
            rows = protocols.fw_manifest_rows(carrier_plan.get("iran_cmds", []), comment)
        except Exception:
            return True
        dnat_rows = _manifest_dnat_rows(rows)
        if not dnat_rows:
            return True
        lines = content.splitlines()
        if keep:
            new_lines = lines + [r for r in dnat_rows if r not in lines]
        else:
            new_lines = [ln for ln in lines if ln not in dnat_rows]
        if new_lines == lines:
            return True
        try:
            ir_runner.write_file(path, "\n".join(new_lines) + "\n")
        except Exception:
            return False
        return True

    def _peel_to_underlay(self, pair, plan_for, current_protocol, target_protocol,
                          reason, dry_run, ir_runner, fr_runner, t_start):
        """Peel an overlay off its live underlay carrier; None to fall through to a full redeploy.

        The carrier never left: its interface and peer route are still
        there, so the cheap path is stop the overlay, restore the
        carrier's frontend DNAT (live rules + manifest rows, so a
        reboot keeps it), and verify the carrier answers on its inners.
        Success commits like any failover. A dead carrier (no inner
        reply, or the DNAT not back in force) returns None: the caller
        falls through to a full redeploy of the carrier, which tears
        the dead underlay down first. Never returns a failure: a peel
        that cannot verify must not strand the pair on a verdict — the
        redeploy path is the honest next step.
        """
        pair_id = pair.get("id", 1)
        frontend = pair.get("frontend_port", pair.get("frontend", 443))
        try:
            old_plan = plan_for(current_protocol)
            carrier_plan = plan_for(target_protocol)
        except Exception:
            return None
        for cmd in old_plan.get("teardown_iran", []):
            ir_runner.run(cmd, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
        for cmd in old_plan.get("teardown_foreign", []):
            fr_runner.run(cmd, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
        # Restore the frontend DNAT the overlay's cutover removed. The
        # check-then-add keeps a half-restored chain from doubling a rule.
        for add in _carrier_dnat_cmds(carrier_plan.get("iran_cmds", [])):
            check = add.replace("-A PREROUTING", "-C PREROUTING", 1)
            ir_runner.run(f"{check} || {add}", best_effort=True)
        self._manifest_set_dnat(ir_runner, carrier_plan, target_protocol, pair_id, keep=True)
        reached, _ = engine.carrier_inner_reachable(ir_runner, target_protocol, pair_id)
        _, o_nat, _ = ir_runner.run("iptables -t nat -S PREROUTING", best_effort=True)
        inner_peer = protocols.carrier_inner_pair(target_protocol, pair_id, "prod")[1]
        dnat_in_force = f"--to-destination {inner_peer}:{frontend}" in o_nat
        if not reached or not dnat_in_force:
            return None
        duration_ms = round((time.time() - t_start) * 1000.0, 1)
        self.record_failover_event(pair_id)
        storage.update_pair_status(pair_id, status="ACTIVE", active_tunnel=target_protocol)
        engine.declare_carrier(pair_id, target_protocol, dry_run)
        storage.log_audit(
            pair_id, "FAILOVER", "SUCCESS",
            f"Successfully failed over {current_protocol} -> {target_protocol} in {duration_ms}ms. "
            f"Trigger: {reason} (peeled to live underlay)"
        )
        return {
            "success": True,
            "old_protocol": current_protocol,
            "new_protocol": target_protocol,
            "duration_ms": duration_ms,
            "reason": reason,
            "quarantined": None
        }

    def _overlay_on_carrier(self, pair, plan_for, new_plan, current_protocol, target_protocol,
                            reason, dry_run, ir_runner, fr_runner, t_start):
        """Deploy an overlay on top of the live carrier; the carrier is never torn down.

        Order is the whole design: the overlay deploys and smoke-checks
        while client traffic still flows through the carrier DNAT, and
        only then does the DNAT move aside, so the cutover itself has
        no gap. A failed overlay is torn down and the carrier — never
        touched — keeps serving: restored=True with no rollback needed.
        The overlay's client must survive starting before its server:
        frpc retries login (loginFailExit=false), so a refused first
        dial while frps is still coming up cannot strand the switch.
        A cutover that cannot be verified (a DNAT rule still in force,
        or the manifest not updated) is reverted the same way rather
        than leaving a half-moved frontend or a reboot time-bomb.
        """
        pair_id = pair.get("id", 1)
        frontend = pair.get("frontend_port", pair.get("frontend", 443))

        def _teardown_overlay():
            for cmd in new_plan.get("teardown_iran", []):
                ir_runner.run(cmd, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
            for cmd in new_plan.get("teardown_foreign", []):
                fr_runner.run(cmd, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)

        def _failed(detail):
            _teardown_overlay()
            return {
                "success": False,
                "error": detail,
                "restored": True,
                "current_protocol": current_protocol,
                "attempted_protocol": target_protocol
            }

        # Stage 2/4/5 for the overlay only: files, setup, units. The
        # carrier's units, interface and rules are not touched here.
        for fpath, content in new_plan.get("iran_files", {}).items():
            ir_runner.write_file(fpath, content)
        for fpath, content in new_plan.get("foreign_files", {}).items():
            fr_runner.write_file(fpath, content)
        for cmd in new_plan.get("iran_cmds", []):
            ir_runner.run(cmd, check=True)
        for cmd in new_plan.get("foreign_cmds", []):
            fr_runner.run(cmd, check=True)
        if new_plan.get("foreign_units"):
            fr_runner.run("systemctl daemon-reload", check=True)
            for u in new_plan["foreign_units"]:
                fr_runner.run(f"systemctl enable --now {u}", check=True)
        if new_plan.get("iran_units"):
            ir_runner.run("systemctl daemon-reload", check=True)
            for u in new_plan["iran_units"]:
                ir_runner.run(f"systemctl enable --now {u}", check=True)

        # Smoke: the same verdict the main flow holds an overlay to —
        # units up, then (live only) a real L7 round trip through the
        # peer channel the carrier inners just gave it.
        smoke_ok = True
        smoke_detail = ""
        for u in new_plan.get("iran_units", []):
            _, o_st, _ = ir_runner.run(f"systemctl is-active {u}", best_effort=True)
            if o_st.strip() != "active":
                smoke_ok = False
                smoke_detail = f"unit {u} reported '{o_st.strip()}'"
                break
        if smoke_ok and not dry_run:
            if not probe.ensure_probe(ir_runner):
                smoke_ok = False
                smoke_detail = "L7 probe could not be installed on Iran"
            else:
                time.sleep(2)
                _, o_smoke, _ = ir_runner.run(probe.cmd("lat", "127.0.0.1", frontend),
                                              best_effort=True,
                                              timeout=probe.cmd_timeout("lat"))
                if not re.search(r'AVG:([0-9.]+)', o_smoke):
                    smoke_ok = False
                    smoke_detail = (f"no L7 round-trip on 127.0.0.1:{frontend} "
                                    f"(probe output: {o_smoke.strip()[:60]!r})")
        if not smoke_ok:
            err_msg = f"Smoke verification failed for replacement protocol {target_protocol}: {smoke_detail}"
            storage.log_audit(pair_id, "FAILOVER_FAILED", "SMOKE_ERROR", err_msg)
            return _failed(err_msg)

        # Cutover: move the carrier's frontend DNAT aside, live rules
        # and manifest together, so client traffic reaches the
        # overlay's listener — and a reboot cannot move it back.
        try:
            carrier_plan = plan_for(current_protocol)
        except Exception as plan_err:
            return _failed(f"Failed to generate carrier plan for cutover: {plan_err}")
        for cmd in _carrier_dnat_cmds(carrier_plan.get("teardown_iran", [])):
            ir_runner.run(cmd, best_effort=True, timeout=protocols.TEARDOWN_TIMEOUT_SEC)
        if not self._manifest_set_dnat(ir_runner, carrier_plan, current_protocol, pair_id, keep=False):
            # Manifest read but not writable: revert the live cutover
            # rather than leave a reboot that re-shadows the overlay.
            for add in _carrier_dnat_cmds(carrier_plan.get("iran_cmds", [])):
                check = add.replace("-A PREROUTING", "-C PREROUTING", 1)
                ir_runner.run(f"{check} || {add}", best_effort=True)
            return _failed("carrier firewall manifest could not be updated for cutover")
        if not dry_run:
            _, o_nat, _ = ir_runner.run("iptables -t nat -S PREROUTING", best_effort=True)
            inner_peer = protocols.carrier_inner_pair(current_protocol, pair_id, "prod")[1]
            if f"--to-destination {inner_peer}:{frontend}" in o_nat:
                for add in _carrier_dnat_cmds(carrier_plan.get("iran_cmds", [])):
                    check = add.replace("-A PREROUTING", "-C PREROUTING", 1)
                    ir_runner.run(f"{check} || {add}", best_effort=True)
                self._manifest_set_dnat(ir_runner, carrier_plan, current_protocol, pair_id, keep=True)
                return _failed("carrier frontend DNAT still in force after cutover")
        duration_ms = round((time.time() - t_start) * 1000.0, 1)
        self.record_failover_event(pair_id)
        storage.update_pair_status(pair_id, status="ACTIVE", active_tunnel=target_protocol)
        storage.log_audit(
            pair_id, "FAILOVER", "SUCCESS",
            f"Successfully failed over {current_protocol} -> {target_protocol} in {duration_ms}ms. "
            f"Trigger: {reason} (overlay on live {current_protocol} underlay)"
        )
        return {
            "success": True,
            "old_protocol": current_protocol,
            "new_protocol": target_protocol,
            "duration_ms": duration_ms,
            "reason": reason,
            "quarantined": None
        }

    def purge_quarantine(self, pair: dict, dry_run: bool = False,
                         ir_runner=None, fr_runner=None) -> bool:
        """Finally removes a quarantined transport whose grace expired.

        Runs the teardown commands stored at quarantine time and clears
        the record. A live (non-expired) quarantine is left alone: purging
        it early would delete the fallback while the successor is still
        inside its proving window. Returns False when there was nothing
        to purge or the record is still live.
        """
        import time as _time
        pair_id = pair.get("id", 1)
        rec = storage.get_quarantine(pair_id)
        if not rec or rec.get("expires_at", 0) > _time.time():
            return False
        if ir_runner is not None:
            for cmd in rec.get("teardown_iran", []):
                ir_runner.run(cmd, best_effort=True,
                              timeout=protocols.TEARDOWN_TIMEOUT_SEC)
        if fr_runner is not None:
            for cmd in rec.get("teardown_foreign", []):
                fr_runner.run(cmd, best_effort=True,
                              timeout=protocols.TEARDOWN_TIMEOUT_SEC)
        storage.clear_quarantine(pair_id)
        storage.log_audit(pair_id, "QUARANTINE_PURGED", "SUCCESS",
                          f"Grace expired for {rec.get('protocol')}; teardown ran")
        return True

    def evaluate_and_heal(self, pair: dict, dry_run: bool = False,
                          ir_runner=None, fr_runner=None,
                          heal_on_degraded: bool = False, health=None,
                          exclude_protocols: list[str] = None) -> dict:
        """Evaluates health of pair and triggers one failover if it is down.

        `active_tunnel` must be recorded, never guessed. The default used to be "GRE", which on a
        chisel pair checked GRE units, reported them inactive -> DOWN, and switched a tunnel that was
        serving traffic. An empty field means unknown, and unknown is not a licence to touch hosts.
        """
        pair_id = pair.get("id", 1)
        active_proto = (pair.get("active_tunnel") or "").strip()
        if not active_proto:
            return {"action": "ABORT_NO_ACTIVE_PROTOCOL",
                    "reason": f"Pair #{pair_id} has no recorded active_tunnel - refusing to guess one "
                              f"and check the wrong units",
                    "active_protocol": ""}

        # Runners created here belong to this call. The path used to open them and never close them,
        # which was invisible while evaluate_and_heal was dead code and becomes a session leak per
        # poll the moment a monitor calls it on an interval.
        #
        # `health` lets a monitor that has already sampled (and has decided the outage is confirmed)
        # hand the verdict over instead of paying for a second probe: two samplings of one event would
        # disagree with each other, and the decision would then rest on whichever one ran second.
        created_ir = created_fr = False
        try:
            if health is None:
                created_ir = ir_runner is None
                created_fr = fr_runner is None
                if ir_runner is None:
                    ir_runner = get_ssh_runner(pair["iran"], dry_run=dry_run, host_role="iran")
                if fr_runner is None:
                    fr_runner = get_ssh_runner(pair["foreign"], dry_run=dry_run, host_role="foreign")
                health = TunnelHealthChecker.check_health(ir_runner, fr_runner, pair, active_proto,
                                                          dry_run=dry_run)

            if health.status == "HEALTHY":
                return {"action": "NONE", "health": health._asdict(), "active_protocol": active_proto}

            if health.status == "DEGRADED" and not heal_on_degraded:
                # A degraded sample is not an outage. Switching costs a measured ~15s blackout on the
                # live pair, and one sample of a lossy path is exactly the kind of single measurement
                # that already ranked protocols wrong here. Report it, move nothing.
                return {
                    "action": "SKIP_DEGRADED",
                    "health": health._asdict(),
                    "active_protocol": active_proto,
                    "reason": f"DEGRADED ({health.details}) - below the outage threshold, and a single "
                              f"sample is not a reason to pay a switchover gap"
                }

            # A pair whose transport is up and whose delivery port has no listener is not a candidate for a
            # switchover, and no policy flag changes that: the successor would be handed the same absent
            # application on the same peer host. This is not a judgement the monitor is allowed to make
            # from a shape either - `no-backend` is the product's own two-reading-agree measurement of the
            # port the generated config names, which is what distinguishes it from the inference that made
            # an absent backend and a stalled transport look identical.
            if health.status == "TRANSPORT-ONLY":
                return {
                    "action": "SKIP_NO_BACKEND",
                    "health": health._asdict(),
                    "active_protocol": active_proto,
                    "reason": f"TRANSPORT-ONLY ({health.details}) - the tunnel is delivering into a port "
                              f"with nothing listening on it; a protocol change cannot start an application"
                }

            # Select candidate. The pair is passed so the carrier gate can drop a refused transport
            # before it is proposed, not only before it is started.
            # exclude_protocols is the server-side healer's memory of this outage: a candidate whose
            # switch was already attempted and failed must not be proposed again on the next
            # confirmed pass, or the healer would retry the same dead transport forever instead of
            # cycling to the next one. The call shape without an exclusion is kept byte-identical
            # to the old one on purpose: stubbed selectors in the suite (and any other caller)
            # accept (pair_id, current, pair=...), and a new keyword on the common path would break
            # them for no benefit.
            if exclude_protocols:
                excluded = set(exclude_protocols)
                allowed = [p for p in protocols.get_supported_protocols()
                           if p not in excluded]
                next_candidate = FailoverCandidateSelector.select_best_candidate(
                    pair_id, active_proto, allowed_protocols=allowed, pair=pair)
            else:
                next_candidate = FailoverCandidateSelector.select_best_candidate(
                    pair_id, active_proto, pair=pair)
            if not next_candidate:
                storage.log_audit(pair_id, "FAILOVER_NO_CANDIDATE", "ABORT",
                                  f"No eligible candidate found for pair {pair_id}")
                return {
                    "action": "ABORT_NO_CANDIDATE",
                    "health": health._asdict(),
                    "active_protocol": active_proto
                }

            # Trigger failover. A live switchover runs under the atomic swap
            # guard (Phase 3): a dead-man rollback is armed on both hosts
            # first, and the successor must re-verify as HEALTHY inside the
            # window or the hosts restore the old protocol themselves - a
            # heal that strands the pair is worse than the outage it answered.
            # A dry run arms nothing and keeps the plain staged path.
            trigger_reason = f"Health check returned {health.status}: {health.details}"
            if dry_run:
                failover_res = self.execute_failover(
                    pair, active_proto, next_candidate, reason=trigger_reason,
                    dry_run=dry_run, ir_runner=ir_runner, fr_runner=fr_runner
                )
            else:
                import atomic_swap

                def _verify_successor():
                    try:
                        report = TunnelHealthChecker.check_health(
                            ir_runner, fr_runner, pair, next_candidate, dry_run=False)
                    except Exception:
                        return False
                    # F10 (2026-10-24, live): HEALTHY-only verification
                    # can never pass on a pair whose steady state is
                    # DEGRADED - the full-stack L7 cost through the peer's
                    # application keeps every serving overlay above the
                    # HEALTHY overhead line - so every automated heal
                    # rolled back a successor that was actually serving
                    # (observed: backhaul-wss deployed in 29 s, then
                    # rolled back). The guard exists to prevent stranding
                    # the pair on a non-serving transport, not to demand
                    # pristine quality: HEALTHY and DEGRADED both carry
                    # traffic, while DOWN and TRANSPORT-ONLY do not. A
                    # DEGRADED successor keeps alerting quality through
                    # the monitor's later passes, so nothing is hidden.
                    return report.status in ("HEALTHY", "DEGRADED")

                failover_res = atomic_swap.guarded_failover(
                    pair, active_proto, next_candidate, reason=trigger_reason,
                    ir_runner=ir_runner, fr_runner=fr_runner,
                    failover_fn=lambda p, cur, tgt, rsn, dr, ir, fr:
                        self.execute_failover(p, cur, tgt, reason=rsn, dry_run=dr,
                                              ir_runner=ir, fr_runner=fr),
                    verify_fn=_verify_successor)
            action = ("FAILOVER_BLOCKED" if failover_res.get("blocked")
                      else "FAILOVER_EXECUTED" if failover_res.get("success")
                      else "FAILOVER_ATTEMPTED")
            # target_protocol is the healer's handle on this attempt: on
            # FAILOVER_ATTEMPTED it names the candidate that failed, so the
            # next confirmed pass can exclude it and cycle on instead of
            # proposing the same dead transport again.
            return {
                "action": action,
                "health": health._asdict(),
                "failover_result": failover_res,
                "target_protocol": next_candidate,
            }
        finally:
            if created_ir and hasattr(ir_runner, "close"):
                ir_runner.close()
            if created_fr and hasattr(fr_runner, "close"):
                fr_runner.close()
