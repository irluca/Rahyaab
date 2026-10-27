#!/usr/bin/env python3
"""Server-side healer: the failover monitor, moved onto the Iran host.

The dashboard monitor heals only while the operator's laptop is on and
its AUTOHEAL flag is set. This service removes both conditions: it runs
as a systemd unit on the Iran host, samples the tunnel on an interval,
and heals a confirmed outage by itself - first restarting the current
tunnel's dead units, then switching to the next benchmark-ranked
protocol, cycling until one serves. No laptop, no dashboard, no operator.

Why the Iran host is the controller: inbound TCP to Iran is dropped, so
only Iran can open a session to the foreign host. The healer therefore
manages the Iran leg locally (LocalRunner, no network) and the foreign
leg over SSH with a dedicated keypair that lives only on the Iran host
(/etc/best-tunnel/healer_key, 0600). It never carries a password.

What it reuses, unchanged: FailoverMonitor (in healer_mode),
FailoverManager, the health checker, the deploy engine and the Telegram
alerter. The only new logic is this entrypoint: config, a one-pair
database seeded from the install-time export, and a heartbeat file so an
operator can see the healer is alive without reading its journal.

Single-writer rule (read this before touching anything else): while the
healer owns a pair, nothing else may deploy, switch or benchmark that
pair - not the dashboard, not the old resident agents. The installer
stops and disables the agents for exactly this reason: two controllers
tearing units down on the same hosts will fight mid-switch, and the
loser resurrects the unit the winner just replaced. Stop the healer
first (systemctl stop best-tunnel-healer), then use the dashboard again.

The one channel through the rule is the manual-switch request file
(see orchestrator/manual_switch.py): the hub may write a request, but
only the healer decides and executes it, with the same machinery as an
automatic failover. The hub never deploys.

Configuration (/etc/best-tunnel/healer.json, 0600) is written by
install_healer.py from the laptop's pair row and benchmark medians. It
carries no password; the Telegram token inside it is optional, and the
pair's SSH password is never written anywhere by this tool.
"""

import argparse
import datetime
import json
import os
import signal
import sys
import threading
import time

# The healer runs from orchestrator/, so flat imports resolve.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import alerter
import failover
import failover_monitor
import manual_switch
import storage
from local_runner import LocalRunner
from mock_ssh import get_ssh_runner

DEFAULT_CONFIG_PATH = "/etc/best-tunnel/healer.json"
DEFAULT_DB_PATH = "/var/lib/best-tunnel/healer.db"
DEFAULT_HEARTBEAT_PATH = "/var/lib/best-tunnel/healer-heartbeat.json"
EXPORT_RUN_ID = "healer-export"

REQUIRED_CONFIG_KEYS = (
    "pair_id", "pair_name", "iran", "foreign", "key_path",
    "frontend_port", "active_tunnel", "candidate_scores",
)


class HealerHostGuard:
    """Always grants, on the single-writer premise documented above.

    The dashboard's guard coordinates threads inside one process; it
    cannot coordinate a laptop process with a service on another
    machine. There is no shared lock to take, so the guard states the
    rule instead of pretending to enforce it: the healer is the only
    writer for its pair, and anything else must stop it first.
    """

    def acquire(self, hosts):
        return True

    def release(self, hosts):
        pass


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    missing = [k for k in REQUIRED_CONFIG_KEYS if k not in cfg]
    if missing:
        raise ValueError(f"healer config {path} is missing keys: {', '.join(missing)}")
    for side in ("iran", "foreign"):
        spec = cfg[side]
        if not spec.get("host") or not spec.get("port") or not spec.get("user"):
            raise ValueError(f"healer config {path}: {side} needs host, port and user")
    if not isinstance(cfg["candidate_scores"], dict) or not cfg["candidate_scores"]:
        raise ValueError(f"healer config {path}: candidate_scores must be a non-empty map")
    return cfg


def seed_db(cfg: dict) -> None:
    """Create the healer's one-pair database from the install export.

    Idempotent across restarts, and careful about one thing: a restart
    must not rewind a healed switch. A pair row that already exists keeps
    its recorded status and active_tunnel - the switch the healer made
    before the reboot is still the truth. Only a missing row is created
    from the config, and benchmark rows are seeded only when the table
    is empty, so a re-install (which wipes the database) picks up fresh
    medians while a plain restart keeps the evidence it already has.
    """
    pid = int(cfg["pair_id"])
    storage.init_db()
    row = storage.get_pair(pid)
    if row is None:
        with storage.db_session() as conn:
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO pairs (id, name, iran_host, iran_port, foreign_host, foreign_port,
                                      frontend_port, status, iran_dial_host, foreign_dial_host,
                                      created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?)""",
                (pid, cfg["pair_name"], cfg["iran"]["host"], cfg["iran"]["port"],
                 cfg["foreign"]["host"], cfg["foreign"]["port"], cfg["frontend_port"],
                 cfg.get("iran_dial_host", "") or "", cfg.get("foreign_dial_host", "") or "",
                 time.time(), time.time()))
        storage.update_pair_status(pid, "ACTIVE", cfg["active_tunnel"])
        if cfg.get("underlay_carrier"):
            storage.set_pair_underlay(pid, cfg["underlay_carrier"])
        if cfg.get("iran_dial_host") or cfg.get("foreign_dial_host"):
            storage.set_pair_dial_hosts(pid, cfg.get("iran_dial_host", "") or "",
                                        cfg.get("foreign_dial_host", "") or "")
        if cfg.get("base_rtt_ms"):
            storage.update_pair_base_rtt(pid, float(cfg["base_rtt_ms"]))
    else:
        # Topology is stable; refresh it from the config, but never the
        # recorded tunnel - see the docstring.
        if cfg.get("underlay_carrier"):
            storage.set_pair_underlay(pid, cfg["underlay_carrier"])
        if cfg.get("iran_dial_host") or cfg.get("foreign_dial_host"):
            storage.set_pair_dial_hosts(pid, cfg.get("iran_dial_host", "") or "",
                                        cfg.get("foreign_dial_host", "") or "")
        if cfg.get("base_rtt_ms"):
            storage.update_pair_base_rtt(pid, float(cfg["base_rtt_ms"]))
    if not storage.get_benchmarks(pid):
        for protocol, score in sorted(cfg["candidate_scores"].items()):
            storage.record_benchmark(pid, protocol, {
                "score": float(score),
                "breakdown": {"lat_avg": 0.0, "loss_pct": 0.0},
                "iperf3": {"capacity_basis": "measured"},
            }, run_id=EXPORT_RUN_ID)


def build_pair_source(cfg: dict):
    """One pair, in the shape the monitor consumes, auth injected.

    The active tunnel is read from the healer database on every pass, so
    a switch the healer just made is what the next pass samples - the
    same reason the dashboard merges session auth into pairs_from_storage
    instead of caching the dict. The Iran leg needs no credential (local
    runner) but the monitor refuses a live pair with an empty auth value,
    so it carries the marker "local"; the foreign leg carries the key.
    """
    pid = int(cfg["pair_id"])

    def pair_source():
        row = storage.get_pair(pid)
        if row is None:
            return []
        pair = {
            "id": pid,
            "name": row.get("name", cfg["pair_name"]),
            "status": (row.get("status") or "ACTIVE").upper(),
            "active_tunnel": (row.get("active_tunnel") or cfg["active_tunnel"]).strip(),
            "mode": (row.get("mode") or "manual").strip().lower(),
            "auto_protocol": (row.get("auto_protocol") or "").strip(),
            "frontend_port": row.get("frontend_port", cfg["frontend_port"]),
            "backend_port": row.get("backend_port") or cfg.get("backend_port"),
            "base_rtt_ms": row.get("base_rtt_ms", cfg.get("base_rtt_ms", 0.0)) or 0.0,
            "underlay_carrier": row.get("underlay_carrier", cfg.get("underlay_carrier", "")),
            "iran": {"host": cfg["iran"]["host"], "port": cfg["iran"]["port"],
                     "user": cfg["iran"]["user"], "auth": {"value": "local"}},
            "foreign": {"host": cfg["foreign"]["host"], "port": cfg["foreign"]["port"],
                        "user": cfg["foreign"]["user"],
                        "auth": {"type": "key", "value": cfg["key_path"]}},
        }
        for side, key in (("iran", "iran_dial_host"), ("foreign", "foreign_dial_host")):
            dial = row.get(key) or cfg.get(key, "")
            if dial:
                pair[side]["dial_host"] = dial
        return [pair]

    return pair_source


def build_runner_factory():
    def runner_factory(spec, dry_run=None, host_role="unknown"):
        if host_role == "iran":
            return LocalRunner(hostname=spec.get("host", "localhost"))
        return get_ssh_runner(spec, dry_run=False, host_role=host_role)

    return runner_factory


def build_monitor(cfg: dict) -> failover_monitor.FailoverMonitor:
    telegram = cfg.get("telegram") or {}
    alert = None
    if telegram.get("bot_token") and telegram.get("chat_id"):
        alert = alerter.TelegramAlerter(telegram["bot_token"], telegram["chat_id"])
    policy = failover_monitor.MonitorPolicy(
        interval_seconds=int(cfg.get("check_interval_seconds", 20)),
        down_streak=int(cfg.get("down_streak", 3)),
        saturation_enabled=False,
    )
    return failover_monitor.FailoverMonitor(
        manager=failover.FailoverManager(),
        policy=policy,
        pair_source=build_pair_source(cfg),
        runner_factory=build_runner_factory(),
        host_guard=HealerHostGuard(),
        dry_run=False,
        alerter_obj=alert,
        healer_mode=True,
    )


def write_heartbeat(path: str, cfg: dict, monitor: failover_monitor.FailoverMonitor) -> None:
    status = monitor.status()
    payload = {
        "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "pid": os.getpid(),
        "pair_id": cfg["pair_id"],
        "pair_name": cfg["pair_name"],
        "running": status["running"],
        "last_pass": status["last_pass"],
        "streaks": status["streaks"],
        "armed": status["armed"],
        "verdicts": status["verdicts"],
    }
    try:
        # The hub syncs its displayed protocol from this field, so a
        # switch (manual or automatic) moves the dashboard's green
        # light even if the hub job that asked for it never reports.
        # Best-effort: a locked database must not break the heartbeat.
        pairs = monitor.pair_source()
        if pairs:
            active = (pairs[0].get("active_tunnel") or "").strip()
            if active:
                payload["active_tunnel"] = active
    except Exception:
        pass
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Tunnel Studio Pro server-side healer")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--db", default=None,
                        help="database path (default: config db_path or %s)" % DEFAULT_DB_PATH)
    parser.add_argument("--once", action="store_true",
                        help="run one pass with healing authorised and print the decisions")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    storage.DB_PATH = args.db or cfg.get("db_path") or DEFAULT_DB_PATH
    seed_db(cfg)
    monitor = build_monitor(cfg)

    if args.once:
        decisions = monitor.run_once(auto_heal=True)
        print(json.dumps(decisions, indent=2, default=str))
        return 0

    stop = {"flag": False}

    def _handle(signum, frame):
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    monitor.start(auto_heal=True)
    heartbeat_path = cfg.get("heartbeat_path") or DEFAULT_HEARTBEAT_PATH
    # At most one manual switch runs at a time, in its own thread, so
    # the heartbeat keeps writing while a switch deploys. The switch
    # holds the monitor's action lock, so an auto pass waits it out
    # instead of tearing down the same units mid-switch.
    switch_thread = None
    try:
        while not stop["flag"]:
            try:
                write_heartbeat(heartbeat_path, cfg, monitor)
            except Exception as exc:
                print(f"healer: heartbeat write failed: {exc}", file=sys.stderr)
            try:
                if switch_thread is not None and not switch_thread.is_alive():
                    switch_thread = None
                if switch_thread is None:
                    request = manual_switch.consume(manual_switch.REQUEST_PATH)
                    if request is not None:
                        if manual_switch.is_stale(request):
                            manual_switch.write_result(
                                manual_switch.RESULT_PATH,
                                {"request_id": request["request_id"],
                                 "status": "refused", "from": "", "to": request["protocol"],
                                 "already": False, "rolled_back": False,
                                 "detail": "switch request expired before the healer read it"})
                        else:
                            switch_thread = threading.Thread(
                                target=manual_switch.run_manual_switch,
                                args=(monitor, request, manual_switch.RESULT_PATH),
                                daemon=True, name="manual-switch")
                            switch_thread.start()
            except Exception as exc:
                print(f"healer: switch request check failed: {exc}", file=sys.stderr)
            for _ in range(10):
                if stop["flag"]:
                    break
                time.sleep(1)
    finally:
        monitor.stop(timeout=10.0)
        if switch_thread is not None:
            switch_thread.join(timeout=30.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
