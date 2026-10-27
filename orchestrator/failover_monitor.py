#!/usr/bin/env python3
"""Continuous tunnel health monitor with opt-in automatic healing (report051 §7 item 1).

failover.FailoverManager could already check health, pick a successor and switch to it, but nothing
called it on a schedule: `evaluate_and_heal` was dead code, so in production a dead tunnel stayed dead
until an operator noticed. That is the gap this module closes.

What it deliberately is not: a fast reactor. The switchover it may trigger is not make-before-break -
Stage 3 tears the old units down before Stage 5 starts the new ones, and the client-visible blackout
measured on the live pair was 15.02 s. Paying that for a single noisy sample is worse than paying it
after a confirmed outage, so an outage has to survive `MonitorPolicy.down_streak` consecutive DOWN
samples before anything touches the hosts, and a DEGRADED sample never authorises a switchover. A DOWN
sample whose units are active and whose frontend is listening is recorded as AMBIGUOUS_DOWN and never
confirmed either: that shape is what an application missing *behind* the tunnel looks like, and no
protocol switchover can restart it.

Since round 064 that shape is normally resolved rather than guessed. The health check reads the pair's
declared delivery port on the peer host, and a tunnel that is up but delivers into a port nothing listens
on arrives as TRANSPORT-ONLY, which this monitor reports and never heals (verdict NO_BACKEND). The shape
inference above is the backstop for the samples where that read was not possible.
"""
import os
import threading
import time
import typing

import storage
import alerter
import eventbus
import failover
import monitoring
import protocols
from mock_ssh import get_ssh_runner, is_dry_run_enabled, transport_flaps

AUTOHEAL_ENV = "BEST_TUNNEL_AUTOHEAL"
_TRUTHY = ("1", "true", "yes", "on")


def auto_heal_enabled(env=None) -> bool:
    """Whether the monitor may change host state. Unset means NO.

    Same doctrine as BEST_TUNNEL_DRY_RUN: this tool rewrites systemd units and kills listeners over
    SSH as root, so automation is opted into and never inherited from a missing variable. A monitor
    that heals by default would switch protocols on a pair whose operator was mid-deploy.
    """
    source = os.environ if env is None else env
    return (source.get(AUTOHEAL_ENV) or "").strip().lower() in _TRUTHY


class NullHostGuard:
    """A guard that always grants. Only correct when the hosts are mocks."""

    def acquire(self, hosts: list[str]) -> bool:
        return True

    def release(self, hosts: list[str]):
        pass


class MonitorPolicy(typing.NamedTuple):
    interval_seconds: int = 60
    down_streak: int = 3
    saturation_window_seconds: float = 5.0
    saturation_enabled: bool = True


def best_measured_capacity_mbps(pair_id: int, protocol: str) -> float | None:
    """The best throughput this pair/protocol has actually demonstrated.

    Saturation without a measured capacity is a guess, and monitoring.py
    already refuses to guess: the helper returns None and the pass reports
    saturation as unknown rather than inventing an alert line.
    """
    best = None
    for b in storage.get_benchmarks(pair_id):
        if (b.get("protocol") or "") != protocol:
            continue
        if (b.get("capacity_basis") or "") == "simulated" or b.get("disqualified", 0) == 1:
            continue
        try:
            tp = float(b.get("throughput_mbps") or 0.0)
        except (TypeError, ValueError):
            continue
        if tp > 0 and (best is None or tp > best):
            best = tp
    return best


def sample_saturation(ir_runner, pair: dict, window_s: float) -> dict | None:
    """Capacity-relative load of the pair's carrier interface, or None.

    The carrier interface is the right meter: the overlays are userspace
    processes with no interface of their own, while every byte of tunnel
    traffic crosses the carrier. A pair with no carrier (public underlay)
    has nothing to measure, and neither has a pair whose capacity was
    never measured - both report None, never a number.
    """
    kind = protocols.carrier_kind(pair)
    if kind not in ("gre", "esp"):
        return None
    iface = protocols.carrier_iface(kind.upper(), pair.get("id", 1), "prod")
    c1 = monitoring.read_iface_counters(ir_runner, iface)
    if window_s and window_s > 0:
        time.sleep(window_s)
    c2 = monitoring.read_iface_counters(ir_runner, iface)
    vals = (c1.get("rx_bytes"), c1.get("tx_bytes"),
            c2.get("rx_bytes"), c2.get("tx_bytes"))
    if any(v is None for v in vals):
        return {"iface": iface, "pct": None, "state": "unknown",
                "capacity_mbps": None, "note": "interface counters unreadable"}
    delta = (c2["rx_bytes"] - c1["rx_bytes"]) + (c2["tx_bytes"] - c1["tx_bytes"])
    capacity = best_measured_capacity_mbps(pair.get("id"), pair.get("active_tunnel", ""))
    pct = monitoring.saturation_pct(delta, window_s, capacity)
    return {"iface": iface, "pct": pct,
            "state": monitoring.saturation_state(pct),
            "capacity_mbps": capacity,
            "note": (f"load {pct}% of demonstrated {capacity} Mbps"
                     if pct is not None else "no measured capacity for this protocol")}


def pairs_from_storage() -> list[dict]:
    """Pairs in the shape the monitor consumes, topology read from the persisted columns.

    No credential is attached here, so a live pass reports SKIP_NO_CREDENTIALS rather than failing
    inside paramiko; the dashboard injects a source that merges its session auth.
    """
    out = []
    for row in storage.get_pairs():
        out.append({
            "id": row["id"],
            "name": row.get("name", ""),
            "status": (row.get("status") or "").upper(),
            "active_tunnel": (row.get("active_tunnel") or "").strip(),
            "mode": (row.get("mode") or "manual").strip().lower(),
            "auto_protocol": (row.get("auto_protocol") or "").strip(),
            "frontend_port": row.get("frontend_port", 443),
            # The declared delivery port travels with the pair or the health check reads the frontend
            # instead: a pair deployed with backend_port=18080 would be probed at :8898 on the peer,
            # find a listener that the contract does not use, and certify delivery as "answered" on
            # evidence from the wrong socket. NULL means "not declared", which failover.py resolves to
            # the frontend - the same default the generator used at deploy time.
            "backend_port": row.get("backend_port") or None,
            "base_rtt_ms": row.get("base_rtt_ms", 0.0) or 0.0,
            # The carrier declaration travels with the pair, or the gate that the monitor's candidate
            # ranking consults falls back to inferring 'gre' from the presence of a dial_host - which is
            # fail-closed but wrong for an ESP underlay, and would keep REALITY out of the ranking on a
            # pair whose envelope is encrypted.
            "underlay_carrier": row.get("underlay_carrier", ""),
            "iran": {"host": row["iran_host"], "port": row.get("iran_port", 22), "user": "root",
                     **({"dial_host": row["iran_dial_host"]} if row.get("iran_dial_host") else {})},
            "foreign": {"host": row["foreign_host"], "port": row.get("foreign_port", 22), "user": "root",
                        **({"dial_host": row["foreign_dial_host"]}
                           if row.get("foreign_dial_host") else {})},
        })
    return out


class FailoverMonitor:
    """Samples every deployed pair and heals a confirmed outage through FailoverManager."""

    def __init__(self, manager: "failover.FailoverManager" = None, policy: MonitorPolicy = None,
                 pair_source=None, runner_factory=None, host_guard=None, dry_run: bool = None,
                 alerter_obj=None, event_bus=None, healer_mode: bool = False):
        # healer_mode is the server-side healer's contract, and nothing
        # else's: the dashboard monitor keeps exactly its old behaviour
        # (one attempt per outage, then defer to the operator). With it on,
        # a confirmed outage first restarts the current tunnel's dead units
        # and only then switches, and a switch that was attempted but did
        # not serve does not defer the pair: the next confirmed pass tries
        # the next candidate, until one serves or the list is exhausted and
        # a fresh cycle starts. That is the unattended server's job - there
        # is no operator to defer to - and it is deliberately not the
        # dashboard's, where deferring is the safe default.
        self._healer_mode = bool(healer_mode)
        self._failed: dict[int, list[str]] = {}
        self._last_attempt_alert: dict[int, float] = {}
        # Acting without a concurrency guard can overlap a deploy or a benchmark holding the same
        # hosts, and both paths tear units down. There is no safe default for a guard, so the caller
        # has to state one - NullHostGuard is the explicit way to say "these hosts are mocks".
        if host_guard is None:
            raise ValueError("FailoverMonitor needs a host_guard: healing concurrently with a "
                             "deploy would tear down units the deploy is still writing")
        self.manager = manager or failover.FailoverManager()
        self.policy = policy or MonitorPolicy()
        self.pair_source = pair_source or pairs_from_storage
        self.runner_factory = runner_factory or get_ssh_runner
        self.host_guard = host_guard
        self.dry_run = is_dry_run_enabled() if dry_run is None else bool(dry_run)
        # Phase 5: None means no notifications at all (the previous
        # behaviour). A configured alerter fires only on sampled-verdict
        # transitions (see _note); a notification failure is swallowed
        # there, so alerting can never break a monitor pass.
        self.alerter = alerter_obj
        # Phase 6 live feed: None means no publishing (the previous
        # behaviour). A bus receives exactly the transitions the audit
        # log records, plus monitor errors - never repeats, never
        # no-sample passes.
        self.event_bus = event_bus
        self._streak: dict[int, int] = {}
        self._armed: set[int] = set()
        self._verdict: dict[int, str] = {}
        # Serialises a monitor pass against an out-of-band switch (the
        # healer's manual switch): both tear units down on the same
        # hosts, so they must never run at the same time. run_once holds
        # it for the whole pass; the manual path holds it for the whole
        # switch, including its rollback.
        self._action_lock = threading.Lock()
        # Last verdict that actually sampled the tunnel, per pair. SKIP
        # and LOCK passes must not overwrite it: a lock-held pass between
        # an outage alert and the recovery would otherwise swallow the
        # "recovered" message the operator is waiting for.
        self._last_sampled: dict[int, str] = {}
        self._last_pass: dict = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.daily_summary_file: str | None = None

    def action_lock(self):
        """Mutex shared by run_once and the healer's manual switch.

        The caller holds it for the whole action (pass or switch). The
        other side blocks until the action finishes, then proceeds
        against the state the action left behind.
        """
        return self._action_lock

    # ---- one pass ------------------------------------------------------------

    def run_once(self, auto_heal: bool = None) -> list[dict]:
        """Sample every monitored pair once and return one decision dict per pair."""
        with self._action_lock:
            return self._run_once_locked(auto_heal)

    def _run_once_locked(self, auto_heal: bool = None) -> list[dict]:
        may_act = auto_heal_enabled() if auto_heal is None else bool(auto_heal)
        results = []
        for pair in self.pair_source():
            try:
                results.append(self._pass_pair(pair, may_act))
            except Exception as exc:
                # One unreachable pair must not end the pass for the others: the monitor is the only
                # thing that would notice an outage on the remaining pairs.
                pid = pair.get("id")
                reason = storage.mask_addresses(f"{type(exc).__name__}: {exc}")
                # mask_addresses because a paramiko failure quotes the host it could not reach, and
                # this string is both audited and returned to whoever asked for the pass.
                results.append(self._note(pid, "ERROR", reason))
        self._last_pass = {"at": time.time(), "auto_heal": may_act,
                           "pairs": len(results),
                           "actions": sorted({r["action"] for r in results})}
        return results

    def _pass_pair(self, pair: dict, may_act: bool) -> dict:
        pid = pair.get("id")
        active = (pair.get("active_tunnel") or "").strip()
        status = (pair.get("status") or "").upper()
        if "status" not in pair or "active_tunnel" not in pair:
            # Guessing whether a tunnel is deployed is how the old dead code managed to check GRE
            # units on a chisel pair. A source that omits the fields is refused, not assumed about.
            return self._note(pid, "SKIP_PAIR_SHAPE",
                                "pair dict carries no status/active_tunnel; the monitor does not "
                                "guess whether a tunnel is deployed")
        if status != "ACTIVE":
            return self._note(pid, "SKIP_NOT_ACTIVE", f"pair status is {status or 'empty'}")
        if not active:
            return self._note(pid, "SKIP_NO_ACTIVE_PROTOCOL",
                                f"pair #{pid} has no recorded active_tunnel")

        hosts = [pair["iran"].get("host"), pair["foreign"].get("host")]
        missing = [side for side in ("iran", "foreign")
                   if not ((pair[side].get("auth") or {}).get("value"))]
        if not self.dry_run and missing:
            return self._note(pid, "SKIP_NO_CREDENTIALS",
                                f"no session credential for {', '.join(missing)} - this process "
                                f"cannot log in, so it must not try to heal")

        if not self.host_guard.acquire(hosts):
            return self._note(pid, "LOCK_BUSY",
                                f"a benchmark or deploy holds {len([h for h in hosts if h])} host(s)")

        ir_runner = fr_runner = None
        try:
            ir_runner = self.runner_factory(pair["iran"], dry_run=self.dry_run, host_role="iran")
            fr_runner = self.runner_factory(pair["foreign"], dry_run=self.dry_run, host_role="foreign")
            if not self.dry_run and hasattr(self.manager, "purge_quarantine"):
                # Grace expiry is the monitor's job: a quarantine whose
                # successor proved itself is dead weight on disk until
                # something finally runs its teardown. Stub managers in
                # tests have no such method, and dry runs touch nothing.
                try:
                    self.manager.purge_quarantine(pair, dry_run=self.dry_run,
                                                  ir_runner=ir_runner, fr_runner=fr_runner)
                except Exception:
                    pass
            health = failover.TunnelHealthChecker.check_health(
                ir_runner, fr_runner, pair, active, dry_run=self.dry_run)
            verdict, detail, streak = self._classify_for(pid, health)
            out = {"pair_id": pid, "action": verdict, "protocol": active, "health": health._asdict(),
                   "down_streak": streak, "auto_heal": may_act}
            if verdict == "HEAL_CONFIRMED" and may_act and self._healer_mode:
                # Restart-first, before any switchover is considered: a
                # dead unit is the cheapest outage there is, and switching
                # protocols to fix a process that only needed a restart
                # pays a blackout for nothing. The retry re-samples, so a
                # recovery is a fresh HEALTHY/DEGRADED verdict (with the
                # streak and arm reset that _classify_for already does),
                # and a still-down resample is fresher evidence for the
                # heal branch below than the sample the restart ran on.
                recovered, new_health = self._healer_restart_retry(
                    pid, pair, active, ir_runner, fr_runner)
                if recovered and new_health is not None:
                    verdict, detail, streak = self._classify_for(pid, new_health)
                    health = new_health
                    out["action"] = verdict
                    out["health"] = health._asdict()
                    out["down_streak"] = streak
                    if detail:
                        out["reason"] = detail
                elif new_health is not None:
                    health = new_health
                    out["health"] = health._asdict()
            if self.policy.saturation_enabled:
                # Saturation is a warning, never a verdict: a HEALTHY tunnel at
                # 95% of its demonstrated capacity is still HEALTHY, but the
                # operator who only reads verdicts learns about the queueing
                # collapse after it happens. The sample rides the same pass
                # (same runners, before they are closed) so it costs one
                # 5 s window, not a second SSH session per pair.
                sat = sample_saturation(ir_runner, pair,
                                        self.policy.saturation_window_seconds)
                if sat is not None:
                    out["saturation"] = sat
                    if sat["state"] == "high":
                        out["saturation_alert"] = (
                            f"carrier {sat['iface']} at {sat['pct']}% of "
                            f"demonstrated {sat['capacity_mbps']} Mbps "
                            f"(alert line {monitoring.SATURATION_ALERT_PCT:.0f}%) - "
                            f"one burst from queueing collapse")

            if (pair.get("mode") or "manual") == "auto" and active:
                # Auto drift is a recommendation, never a verdict either:
                # the pair stays on its current transport until an outage
                # (handled by the heal path) or the operator acts on the
                # note. Switching a HEALTHY tunnel on a fresh median would
                # pay a 15 s blackout for a margin that may be noise, which
                # is why the margin rule lives in auto_winner, not here.
                winner, margin = failover.auto_winner(pid, active, pair=pair)
                if winner and winner != active:
                    out["auto_drift"] = {
                        "winner": winner, "margin": margin, "current": active,
                        "note": (f"auto evidence now favours {winner} over "
                                 f"{active} by {margin:.1f} points; the pair "
                                 f"stays put until an outage or an operator "
                                 f"applies the switch")}

            flap = transport_flaps(ir_runner, fr_runner)
            if flap:
                # A verdict is a claim about the transport as well as about the tunnel: a HEALTHY that
                # had to re-open two sessions to get its numbers must not print identically to a quiet
                # pass, or the operator reads "no problems" where the truth is "the link is flaky and
                # the sample happened to survive it".
                out["transport"] = flap
            if detail:
                out["reason"] = detail

            if verdict == "HEAL_CONFIRMED" and not may_act:
                out["action"] = "OBSERVE_DOWN"
                out["reason"] = (f"{streak} consecutive DOWN samples would authorise a failover, but "
                                 f"{AUTOHEAL_ENV} is not set - observing only")
            elif verdict == "HEAL_CONFIRMED" and pid in self._armed:
                # One automated attempt per continuous outage. The streak keeps growing while the
                # tunnel stays down, so without this gate the monitor re-attempts on the breaker's
                # min_interval forever - repeating an attempt that already failed for the same reason
                # and filling the audit log the operator needs for the transition itself. Recovery
                # re-arms the pair, because a healthy sample resets the streak and clears the flag.
                out["action"] = "HEAL_DEFERRED"
                out["reason"] = (f"outage already healed once automatically (streak {streak}); waiting "
                                 f"for recovery or an operator")
            elif verdict == "HEAL_CONFIRMED":
                self._armed.add(pid)
                heal_kwargs = {}
                if self._healer_mode and self._failed.get(pid):
                    # Candidates already attempted-and-failed in this
                    # outage are excluded, so the next attempt cycles to
                    # the next protocol instead of re-proposing the same
                    # dead transport. Only passed when non-empty, so a
                    # stub manager with the old signature still works.
                    heal_kwargs["exclude_protocols"] = list(self._failed[pid])
                res = self.manager.evaluate_and_heal(pair, dry_run=self.dry_run, ir_runner=ir_runner,
                                                     fr_runner=fr_runner, health=health,
                                                     **heal_kwargs)
                out["action"] = res.get("action", "FAILOVER_ATTEMPTED")
                out["heal"] = res
                out["reason"] = f"automated heal after {streak} consecutive DOWN samples"
                # evaluate_and_heal reports its own verdict, with the switchover result nested under
                # failover_result, so the success flag is not on this dict. Reading res["success"] here
                # would have read None on every heal that worked and left the pair permanently armed.
                if out["action"] == "FAILOVER_EXECUTED":
                    self._streak.pop(pid, None)
                    self._armed.discard(pid)
                    self._verdict.pop(pid, None)
                    if self._healer_mode:
                        self._failed.pop(pid, None)
                elif out["action"] == "FAILOVER_ATTEMPTED" and self._healer_mode:
                    # Cycle, don't defer: the attempted candidate is
                    # remembered and the pair is disarmed, so the next
                    # confirmed pass tries the next candidate instead of
                    # waiting for an operator who is not there. A switch
                    # that was refused for safety (FAILOVER_BLOCKED) is
                    # not an attempted candidate and keeps the old defer.
                    target = (res.get("target_protocol")
                              or (res.get("failover_result") or {}).get("new_protocol"))
                    if target and target not in self._failed.setdefault(pid, []):
                        self._failed[pid].append(target)
                    self._armed.discard(pid)
                elif out["action"] == "ABORT_NO_CANDIDATE" and self._healer_mode:
                    # The list is exhausted: start a fresh cycle on the
                    # next confirmed outage rather than deferring forever.
                    # The streak delay between cycles is the backoff, and
                    # path conditions do change while the healer waits.
                    self._failed.pop(pid, None)
                    self._armed.discard(pid)
                    if (pair.get("mode") or "manual") == "auto":
                        # The heal just proved the winner in practice; the
                        # remembered auto choice follows the pair, not the
                        # last sweep that happened to run before the outage.
                        new_proto = (out.get("heal") or {}).get(
                            "failover_result", {}).get("new_protocol")
                        if new_proto:
                            storage.set_pair_auto_protocol(pid, new_proto)
            if out["action"] not in self.NO_SAMPLE:
                # Phase 6 Health Center: every sampled verdict is history,
                # not just a transition line. The write is guarded so a
                # storage failure can never break a monitor pass.
                try:
                    sat = out.get("saturation") or {}
                    storage.record_health_sample(
                        pid, out["action"], protocol=active,
                        loss_pct=getattr(health, "loss_pct", 0.0),
                        latency_ms=getattr(health, "latency_ms", 0.0),
                        saturation_pct=sat.get("pct"),
                        saturation_state=sat.get("state", ""),
                        auto_drift=(out.get("auto_drift") or {}).get("winner", ""))
                except Exception:
                    pass
            self._note(pid, out["action"], out.get("reason", ""),
                       protocol=active,
                       saturation_alert=out.get("saturation_alert", ""),
                       iran_host=(pair.get("iran") or {}).get("host", ""),
                       foreign_host=(pair.get("foreign") or {}).get("host", ""))
            return out
        finally:
            for runner in (ir_runner, fr_runner):
                if runner is not None and hasattr(runner, "close"):
                    runner.close()
            self.host_guard.release(hosts)

    def _healer_restart_retry(self, pid, pair, active, ir_runner, fr_runner):
        """Restart-first for healer mode. Returns (recovered, new_health).

        Only units that are not active are restarted: restarting a live
        unit every pass would flap a transport whose problem is the path,
        not the process - the old resident agent's rule, kept here for the
        same reason. Carrier units restart the same way: a GRE/ESP unit's
        ExecStart re-applies its tunnel commands, so a restart
        re-establishes a dead carrier instead of abandoning it for an
        overlay that cannot work without it. Any failure to run the retry
        returns (False, None) and the original sample stands; a retry that
        ran but did not recover returns (False, new_health) so the heal
        branch works from fresher evidence.
        """
        try:
            ir_ip = protocols.dial_address(pair["iran"], active)
            fr_ip = protocols.dial_address(pair["foreign"], active)
            frontend = pair.get("frontend_port", pair.get("frontend", 443))
            plan = protocols.generate_deployment(active, pid, ir_ip, fr_ip, frontend)
        except Exception:
            return False, None
        try:
            for runner, units in ((ir_runner, plan.get("iran_units", [])),
                                  (fr_runner, plan.get("foreign_units", []))):
                for unit in units:
                    _, state, _ = runner.run(f"systemctl is-active {unit}",
                                             best_effort=True, retryable=True)
                    if state.strip() != "active":
                        runner.run(f"systemctl restart {unit}", best_effort=True)
            new_health = failover.TunnelHealthChecker.check_health(
                ir_runner, fr_runner, pair, active, dry_run=self.dry_run)
        except Exception:
            return False, None
        recovered = new_health.status in ("HEALTHY", "DEGRADED")
        try:
            storage.log_audit(pid, "HEALER_RESTART",
                              "RECOVERED" if recovered else "STILL_DOWN",
                              f"restarted {active} units; resample {new_health.status}")
        except Exception:
            pass
        return recovered, new_health

    def _classify_for(self, pid, health) -> tuple[str, str, int]:
        if health.status == "TRANSPORT-ONLY":
            # Neither of the two verdicts this monitor has ever been able to give. Not HEALTHY: a client
            # that connects here gets nothing, and pretending otherwise would put a working-looking pair
            # in front of an operator who is being served nothing. Not evidence of a transport outage
            # either: the delivery port named in this pair's own generated config was read twice on the
            # peer and had no listener, so the next transport would deliver into the same silence.
            # The pair is disarmed for the same reason DEGRADED does not arm it, and the reason travels
            # with the verdict so `status()` shows an operator what to fix: an application, not a tunnel.
            self._streak.pop(pid, None)
            self._armed.discard(pid)
            return ("NO_BACKEND",
                    f"transport up, delivery unlistened-to ({health.details}); a switchover cannot start "
                    f"an application on the peer - observing, not healing", 0)
        if health.status == "DOWN":
            # A switchover can only fix what a switchover can reach. Units active on both sides plus a
            # listening frontend means the transport itself is answering, while the L7 probe completed
            # no request - which on this tool is most often the application *behind* the tunnel being
            # absent, exactly as the live pair behaved on 2026-10-10 (pair #2: xray portal active,
            # :9443 listening, nothing answering the reverse forward's destination on the far side,
            # loss 100%). Tearing down a working transport for 15 s to replace it with another working
            # transport, because a customer process is not running, is a worse outage than the one
            # being observed. The streak is dropped rather than grown: this sample is not evidence of
            # the kind of outage this monitor is allowed to act on.
            #
            # Since #63 this shape is usually resolved upstream, by the declared delivery port being read
            # on the peer, and that verdict arrives as TRANSPORT-ONLY instead of DOWN. This branch stays
            # as the backstop for the samples where that read was not possible - the peer's socket table
            # unreadable, a pair with no declaration recorded yet - where the shape is genuinely all there
            # is, and the honest name for it is ambiguous.
            transport_answered = (health.is_unit_active_iran and health.is_unit_active_foreign
                                  and health.is_socket_listening)
            if transport_answered:
                self._streak.pop(pid, None)
                self._armed.discard(pid)
                return ("AMBIGUOUS_DOWN",
                        "units are active and the frontend is listening while the L7 probe completed no "
                        "request: an empty application behind the tunnel and a stalled transport look "
                        "identical from here, and a protocol switchover cannot restart either one - "
                        "observing, not healing", 0)
            streak = self._streak.get(pid, 0) + 1
            self._streak[pid] = streak
            if streak >= max(1, int(self.policy.down_streak)):
                return "HEAL_CONFIRMED", "", streak
            return ("DOWN_PENDING",
                    f"DOWN sample {streak}/{max(1, int(self.policy.down_streak))} - not acting on an "
                    f"unconfirmed outage", streak)
        # HEALTHY proves the tunnel carries traffic. So does DEGRADED, more slowly: units are active,
        # the socket is listening and loss is under the outage threshold. Either way the evidence for
        # an outage stops being consecutive, so the streak resets instead of accumulating across an
        # unrelated sample - and the pair is re-armed, because a later outage is a different outage.
        # The entry is dropped rather than zeroed: `status()["streaks"]` is what an operator reads to
        # see which pairs are heading toward a switchover, and a pair with a zero streak is not one.
        self._streak.pop(pid, None)
        self._armed.discard(pid)
        if health.status == "DEGRADED":
            return ("DEGRADED", f"performance below SLA ({health.details}); no switchover is authorised "
                                f"by a degraded sample", 0)
        return "HEALTHY", "", 0

    #: Verdicts for a pass that never looked at the tunnel.
    NO_SAMPLE = ("SKIP_PAIR_SHAPE", "SKIP_NOT_ACTIVE", "SKIP_NO_ACTIVE_PROTOCOL",
                 "SKIP_NO_CREDENTIALS", "LOCK_BUSY", "ERROR")

    def _note(self, pid, verdict: str, detail: str = "", protocol: str = "",
              saturation_alert: str = "", iran_host: str = "",
              foreign_host: str = "") -> dict:
        """Build a decision dict, expire any stale outage evidence, and audit on transitions only.

        A pass every 60s would otherwise bury the operator's audit log in repeats of the same refusal,
        and the transition is the one line they need to find. The decision dict is still returned every
        time, so nothing is hidden from the caller that asked for this pass.

        A pass that produced no sample (host busy, no credential, pair not deployed) also drops the
        stored outage streak. Without that, three DOWN samples before a 30-minute deploy plus one
        sample after it would add up to a "confirmed" continuous outage, and the monitor would act on
        evidence that was never consecutive.

        Phase 5: the same transition-only rule drives Telegram alerts.
        A configured alerter is told about sampled-verdict transitions
        (never SKIP/LOCK passes, never a repeated verdict), and any
        failure to send is swallowed here - the monitor's job is the
        tunnel, and a dead chat API must not become a second outage.
        """
        if verdict in self.NO_SAMPLE:
            self._streak.pop(pid, None)
            self._armed.discard(pid)
        if self._verdict.get(pid) != verdict:
            self._verdict[pid] = verdict
            storage.log_audit(pid, "FAILOVER_MONITOR", verdict, detail or verdict)
            # Phase 6 live feed: the same transition, once. ERROR is a
            # no-sample verdict but a real event (the monitor itself
            # failed to sample); SKIP/LOCK passes are absences, not
            # events, and stay out of the feed.
            if self.event_bus is not None and (
                    verdict not in self.NO_SAMPLE or verdict == "ERROR"):
                try:
                    self.event_bus.publish("verdict", pid, verdict,
                                           detail or verdict)
                except Exception:
                    pass
        if verdict not in self.NO_SAMPLE and self.alerter is not None:
            previous = self._last_sampled.get(pid, "")
            self._last_sampled[pid] = verdict
            text = alerter.alert_for_transition(
                previous, verdict, pid, protocol or "?",
                detail=detail, saturation_alert=saturation_alert,
                iran_host=iran_host, foreign_host=foreign_host)
            if text and self._healer_mode and verdict == "FAILOVER_ATTEMPTED":
                # An unattended cycle tries a candidate every minute or
                # two for as long as the outage lasts; one attempt alert
                # per 15 minutes says the same thing without burying the
                # operator's chat. The audit log still records every
                # transition, so nothing is hidden, only the pings thin.
                now = time.time()
                if now - self._last_attempt_alert.get(pid, 0.0) < 900:
                    text = ""
                else:
                    self._last_attempt_alert[pid] = now
            if text:
                try:
                    self.alerter.send(text)
                except Exception:
                    pass
        out = {"pair_id": pid, "action": verdict}
        if detail:
            out["reason"] = detail
        return out

    def _maybe_daily_summary(self, today=None) -> bool:
        """Send the once-a-day health summary, at most once per date.

        Called from the monitor loop (the dashboard's own thread), so it
        only fires while the operator's laptop is actually running the
        monitor - a summary the laptop cannot send is not a promise the
        product makes. Returns True when a summary was sent. Every
        failure path returns False instead of raising, for the same
        reason _note swallows send failures.
        """
        if self.alerter is None or not self.alerter.configured:
            return False
        try:
            import datetime
            day = (today or datetime.date.today()).isoformat()
            state_file = self.daily_summary_file or os.path.join(
                os.path.dirname(storage.DB_PATH), "daily_summary_sent.txt")
            try:
                with open(state_file) as f:
                    if f.read().strip() == day:
                        return False
            except OSError:
                pass
            rows = []
            for pair in self.pair_source():
                pid = pair.get("id")
                summary = storage.health_uptime_summary(
                    pid, since_ts=time.time() - 86400)
                rows.append({"pair_id": pid,
                             "protocol": pair.get("active_tunnel") or "?",
                             "iran_host": (pair.get("iran") or {}).get("host", ""),
                             "foreign_host": (pair.get("foreign") or {}).get("host", ""),
                             "uptime_pct": summary.get("uptime_pct"),
                             "outages_24h": summary.get("outages", 0),
                             "failovers": storage.count_failovers(pid)})
            if not self.alerter.send(alerter.build_daily_summary(rows)):
                return False
            with open(state_file, "w") as f:
                f.write(day)
            return True
        except Exception:
            return False

    # ---- lifecycle -----------------------------------------------------------

    def loop(self, auto_heal=None):
        while not self._stop.is_set():
            try:
                self.run_once(auto_heal=auto_heal)
            except Exception as exc:
                storage.log_audit(None, "FAILOVER_MONITOR", "LOOP_ERROR",
                                  storage.mask_addresses(f"{type(exc).__name__}: {exc}"))
            # Phase 5 daily summary: cheap date check, guarded inside.
            self._maybe_daily_summary()
            self._stop.wait(self.policy.interval_seconds)

    def start(self, auto_heal=None) -> bool:
        """Start the monitor thread. Returns False when one is already running.

        auto_heal passes straight through to run_once: None keeps the
        environment gate (the dashboard's behaviour), while the
        server-side healer passes True explicitly - its own existence as
        a dedicated service is its authorisation, and it has no
        environment to inherit one from.
        """
        if self._thread is not None and self._thread.is_alive():
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self.loop, daemon=True, name="failover-monitor",
                                        kwargs={"auto_heal": auto_heal})
        self._thread.start()
        return True

    def stop(self, timeout: float = 5.0) -> bool:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            alive = self._thread.is_alive()
            if not alive:
                self._thread = None
            return not alive
        return True

    def status(self) -> dict:
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "dry_run": self.dry_run,
            "auto_heal": auto_heal_enabled(),
            "interval_seconds": self.policy.interval_seconds,
            "down_streak_required": max(1, int(self.policy.down_streak)),
            "streaks": dict(self._streak),
            "armed": sorted(self._armed),
            "verdicts": dict(self._verdict),
            "last_pass": dict(self._last_pass),
        }
