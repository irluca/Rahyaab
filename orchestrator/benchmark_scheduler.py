#!/usr/bin/env python3
"""Scheduled benchmark sweeps (Phase 3 completion).

A benchmark row is a measurement with a shelf life: the path that scored
rathole 77 in October may score it 50 in December, and a failover ranking
built on October's rows would keep choosing it anyway. This module is the
counterweight - a loop in the FailoverMonitor's shape that re-runs the
full sweep for every ACTIVE pair on an interval, so the evidence the
selector and auto mode read stays current.

It deliberately reuses run_all_benchmarks rather than reimplementing a
sweep: the sweep already records every row (including disqualified ones)
and sorts by score, so the scheduler's only jobs are timing, guarding,
and refreshing the auto choice afterwards. One pair's failure never ends
the pass for the others, and a sweep never runs while a deploy or the
failover monitor holds the same hosts - the host guard is mandatory for
the same reason it is in the monitor.
"""
import threading
import time
import typing
import uuid

import storage
import failover
from failover_monitor import NullHostGuard


class BenchmarkPolicy(typing.NamedTuple):
    interval_hours: float = 24.0
    profile: str = "balanced"


def active_pairs_from_storage() -> list[dict]:
    """ACTIVE pairs in the shape a sweep consumes, with steering attached."""
    out = []
    for row in storage.get_pairs():
        if (row.get("status") or "").upper() != "ACTIVE":
            continue
        out.append({
            "id": row["id"],
            "name": row.get("name", ""),
            "status": (row.get("status") or "").upper(),
            "active_tunnel": (row.get("active_tunnel") or "").strip(),
            "frontend_port": row.get("frontend_port", 443),
            "backend_port": row.get("backend_port") or None,
            "base_rtt_ms": row.get("base_rtt_ms", 0.0) or 0.0,
            "underlay_carrier": row.get("underlay_carrier", ""),
            "mode": (row.get("mode") or "manual").strip().lower(),
            "iran": {"host": row["iran_host"], "port": row.get("iran_port", 22),
                     **({"dial_host": row["iran_dial_host"]}
                        if row.get("iran_dial_host") else {})},
            "foreign": {"host": row["foreign_host"], "port": row.get("foreign_port", 22),
                        **({"dial_host": row["foreign_dial_host"]}
                           if row.get("foreign_dial_host") else {})},
        })
    return out


class BenchmarkScheduler:
    """Re-sweeps ACTIVE pairs on an interval and refreshes auto choices."""

    def __init__(self, policy: BenchmarkPolicy = None, pair_source=None,
                 host_guard=None, dry_run: bool = True, sweep_fn=None):
        if host_guard is None:
            raise ValueError("BenchmarkScheduler needs a host_guard: a sweep "
                             "tears bench units down, and running one while a "
                             "deploy holds the same hosts would corrupt both")
        self.policy = policy or BenchmarkPolicy()
        self.pair_source = pair_source or active_pairs_from_storage
        self.host_guard = host_guard
        self.dry_run = bool(dry_run)
        self.sweep_fn = sweep_fn
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_pass: dict = {}

    def run_once(self) -> list[dict]:
        """One sweep over every ACTIVE pair; returns one summary per pair."""
        results = []
        for pair in self.pair_source():
            pid = pair.get("id")
            # The ACTIVE filter is enforced here, not just in the default
            # source: a caller that hands over a mixed list must not get
            # sweeps on pairs that are not deployed.
            if pair.get("status") is not None and (pair.get("status") or "").upper() != "ACTIVE":
                results.append({"pair_id": pid, "action": "SKIP_NOT_ACTIVE"})
                continue
            hosts = [pair["iran"].get("host"), pair["foreign"].get("host")]
            if not self.host_guard.acquire(hosts):
                results.append({"pair_id": pid, "action": "LOCK_BUSY"})
                continue
            try:
                run_id = f"sched-{uuid.uuid4().hex[:8]}"
                if self.sweep_fn is not None:
                    rows = self.sweep_fn(pair, dry_run=self.dry_run,
                                         profile=self.policy.profile,
                                         run_id=run_id)
                else:
                    import engine
                    rows = engine.run_all_benchmarks(
                        pair, dry_run=self.dry_run,
                        profile=self.policy.profile, run_id=run_id)
                summary: dict = {"pair_id": pid, "action": "SWEPT",
                                 "rows": len(rows or []),
                                 "run_id": run_id}
                active = (pair.get("active_tunnel") or "").strip()
                if (pair.get("mode") or "manual") == "auto" and active:
                    winner = failover.refresh_auto_choice(pid, active, pair=pair)
                    summary["auto_winner"] = winner
                results.append(summary)
            except Exception as exc:
                results.append({"pair_id": pid, "action": "ERROR",
                                "reason": storage.mask_addresses(
                                    f"{type(exc).__name__}: {exc}")})
            finally:
                self.host_guard.release(hosts)
        self._last_pass = {"at": time.time(), "pairs": len(results),
                           "actions": sorted({r["action"] for r in results})}
        return results

    def loop(self):
        interval = max(60.0, self.policy.interval_hours * 3600.0)
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:
                storage.log_audit(None, "BENCHMARK_SCHEDULER", "LOOP_ERROR",
                                  storage.mask_addresses(
                                      f"{type(exc).__name__}: {exc}"))
            self._stop.wait(interval)

    def start(self) -> bool:
        if self._thread is not None and self._thread.is_alive():
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self.loop, daemon=True,
                                        name="benchmark-scheduler")
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
        return {"running": bool(self._thread and self._thread.is_alive()),
                "dry_run": self.dry_run,
                "interval_hours": self.policy.interval_hours,
                "profile": self.policy.profile,
                "last_pass": dict(self._last_pass)}
