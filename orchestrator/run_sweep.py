#!/usr/bin/env python3
"""Background auto-sweep runner, spawned detached by the hub.

After a pair's first tunnel (GRE) is up, the hub starts this script in a
systemd scope unit so it survives hub restarts. It runs the full
protocol benchmark ladder against the pair's LIVE tunnel — benches never
touch prod units, overlays ride the live underlay, and the healer keeps
running throughout — and as each protocol's row lands in the pair's
healer database, it merges that protocol's qualified score into the hub
pair row. The dashboard therefore fills in gradually over ~20-30
minutes instead of appearing all at once at the end. When the ladder
finishes it also writes the merged scores into the healer config and
restarts the healer (so auto-failover knows the full candidate set),
removes bench leftovers from both hosts (notably the stale bench ESP
interface that would block a later ESP switch), and logs a hub event.
The live tunnel is never touched and current_protocol is never changed:
the sweep measures, it does not switch.

Usage (the hub builds this command; operators rarely run it by hand):
    python3 run_sweep.py --pair-id 1 --hub-db /var/lib/rahyaab/hub.db
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
import traceback

HUB_KEY = "/etc/rahyaab/hub_key"
POLL_SECONDS = 15.0

CLEAN_SCRIPT = r"""#!/usr/bin/env bash
for u in $(systemctl list-units --all --no-legend 2>/dev/null | awk '$1 ~ /bench/ {print $1}'); do
  systemctl stop "$u" 2>/dev/null || true
  [ -f "/etc/systemd/system/$u" ] && rm -f "/etc/systemd/system/$u"
done
systemctl daemon-reload 2>/dev/null || true
for i in $(ip -brief link 2>/dev/null | awk '{print $1}' | sed 's/@.*//' | grep -iE 'bench|^grep1b$|^espp1b$'); do
  ip link delete "$i" 2>/dev/null || true
done
rm -rf /tmp/best_tunnel_* 2>/dev/null || true
echo CLEAN-DONE
"""


def ipv6_reverse_address(store, pair_id: int) -> str | None:
    """Probed Iran IPv6 for the tcp-lanes-v6 bench gate, or None.

    Only a probe that passed the reverse direction counts, and only
    its first Iran address: a stale or unpassed address must never
    reach a bench dial.
    """
    status = store.get_ipv6_status(pair_id) or {}
    addrs = status.get("iran_v6") or []
    if status.get("reverse_ready") and addrs:
        return addrs[0]
    return None


def pidfile_dir() -> str:
    return os.environ.get("RAHYAAB_SWEEP_DIR", "/var/lib/rahyaab")


def pidfile_path(pair_id: int) -> str:
    return os.path.join(pidfile_dir(), "sweep-p%d.pid" % int(pair_id))


def pid_alive(pid: int) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError):
        return False


def merge_scores(existing: dict, new: dict) -> dict:
    """Merge qualified scores in; a disqualified protocol never erases
    a previous score, and nothing else in the map is touched."""
    merged = dict(existing or {})
    for proto, score in (new or {}).items():
        if score and score > 0:
            merged[proto] = score
    return merged


def qualified_from_rows(rows: list) -> dict:
    """Benchmark rows -> {protocol: score} for qualified rows only."""
    out = {}
    for row in rows:
        if row.get("disqualified"):
            continue
        score = row.get("score") or 0
        if score > 0:
            out[row["protocol"]] = score
    return out


def apply_quick_profile() -> None:
    """Shorten the bench for a quick test: a 10 s stability window
    instead of 30 s, and no iperf3 legs (the bulk ladder stands in for
    throughput, exactly as it does when iperf3 is missing). The DPI
    gates — deploy, base RTT, latency/jitter/loss probes, bulk ladder —
    all stay, so a quick score is comparable among quick scores, just
    not with a full sweep's. Quick results are stored separately and
    never merged into candidate_scores."""
    import probe
    probe.STABILITY_SAMPLES = 10
    probe.STABILITY_WINDOW = 10.0
    import engine
    engine.measure_iperf3_throughput = (
        lambda *a, **k: {"available": False,
                         "reason": "quick test skips iperf3"})


def read_quick_rows(healer_db: str, run_id: str) -> list:
    """All rows of a quick run, with the fields the dashboard shows."""
    conn = sqlite3.connect(healer_db, timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(
            "SELECT protocol, score, disqualified, latency_ms, jitter_ms,"
            " loss_pct FROM benchmarks WHERE run_id = ? ORDER BY id",
            (run_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def read_new_rows(healer_db: str, run_id: str, after_id: int):
    """Rows for this run with id > after_id, in order. Returns
    (rows, max_id) where rows are plain dicts."""
    conn = sqlite3.connect(healer_db, timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(
            "SELECT id, protocol, score, disqualified FROM benchmarks"
            " WHERE run_id = ? AND id > ? ORDER BY id",
            (run_id, after_id))
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    max_id = max([r["id"] for r in rows], default=after_id)
    return rows, max_id


def apply_rows_to_hub(store, pair_id: int, rows: list) -> dict:
    """Merge newly qualified rows into the hub pair row. Returns the
    merged map (unchanged when nothing new qualified)."""
    qualified = qualified_from_rows(rows)
    if not qualified:
        pair = store.get_pair(pair_id) or {}
        return dict(pair.get("candidate_scores") or {})
    return store.update_pair_scores(pair_id, qualified)


def update_healer_config(pair_id: int, qualified: dict) -> bool:
    """Merge qualified scores into the healer config. Returns True when
    the file changed (caller restarts the healer only then)."""
    import healer_paths
    path = healer_paths.config_path(pair_id)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return False
    merged = merge_scores(cfg.get("candidate_scores") or {}, qualified)
    if merged == (cfg.get("candidate_scores") or {}):
        return False
    cfg["candidate_scores"] = merged
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2, sort_keys=True)
    return True


def cleanup_bench(iran_host: str, foreign_host: str, log) -> None:
    """Remove bench leftovers from both hosts. Best effort: a cleanup
    failure is logged, never fatal to the sweep results."""
    try:
        subprocess.run(["bash", "-c", CLEAN_SCRIPT], timeout=120,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("bench cleanup: local host done")
    except Exception as exc:
        log("bench cleanup: local host failed: %s" % exc)
    try:
        subprocess.run(
            ["ssh", "-i", HUB_KEY, "-o", "BatchMode=yes",
             "root@%s" % foreign_host, "bash -s"],
            input=CLEAN_SCRIPT.encode(), timeout=120,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("bench cleanup: foreign host done")
    except Exception as exc:
        log("bench cleanup: foreign host failed: %s" % exc)


# The store deploys declare into (hub/jobs.py:422, wizard_setup.py:31).
# The sweep's bench rows live in the healer store; the declaration does
# not necessarily live there too.
WIZARD_DB_PATH = "/var/lib/rahyaab/wizard.db"


def read_declaration_rows(pair_id, healer_db):
    """Read the pair's declaration rows from both deploy stores (read-only).

    Returns (healer_row, wizard_row), each a dict with underlay_carrier,
    iran_dial_host, foreign_dial_host (and active_tunnel on the healer row),
    or None when the store has no row or is unreadable. Direct sqlite3
    reads: the sweep must not depend on storage.DB_PATH, which points at
    the healer DB by the time engine is imported.
    """
    def _read(path):
        try:
            conn = sqlite3.connect(path, timeout=60)
            try:
                conn.execute("PRAGMA busy_timeout = 60000")
                cur = conn.cursor()
                cols = [c[1] for c in cur.execute("PRAGMA table_info(pairs)")]
                if not cols:
                    return None
                row = cur.execute(
                    "SELECT * FROM pairs WHERE id = ?", (pair_id,)).fetchone()
                return dict(zip(cols, row)) if row else None
            finally:
                conn.close()
        except Exception:
            return None
    return _read(healer_db), _read(WIZARD_DB_PATH)


def _complete_declaration(row):
    if not row:
        return False
    carrier = str(row.get("underlay_carrier") or "").strip().lower()
    return (carrier in ("gre", "esp") and bool(row.get("iran_dial_host"))
            and bool(row.get("foreign_dial_host")))


def select_dial_hosts(hub_pair, healer_row, wizard_row):
    """Dial hosts for overlay benches + which store they came from.

    Preference: a complete declaration whose carrier is the live carrier
    (the healer row's active_tunnel — the tunnel the healer actually
    runs); else the wizard store's complete declaration (deploys); else
    the healer store's; else the hub row's inners. Bug 12 (2026-11-01):
    pair 3's hub inners were creation-time 10.10.12.x while its live ESP
    carrier used 10.12.13.x, and no store held a declaration at all (the
    wizard path never created the pair row), so every overlay bench
    dialed a dead /30 and failed identically.
    Bug 14 (2026-11-01): pair 4's live protocol is an overlay
    (backhaul-wss) and it never had a carrier, so no store holds a
    carrier declaration and the hub inners (10.10.13.x) have no
    interface behind them. Falling back to them made every overlay
    bench fail identically at the 25 s readiness check — including the
    live backhaul bench itself, which is proven working. With no
    carrier declaration and an overlay live tunnel, there is no
    carrier underlay to dial, so the benches dial the public host
    exactly like the wizard's overlay measure does (dial_host unset
    makes peer_address fall back to host).
    """
    live = str((healer_row or {}).get("active_tunnel") or "").strip().lower()
    if live:
        for row, src in ((healer_row, "healer"), (wizard_row, "wizard")):
            if (_complete_declaration(row)
                    and str(row.get("underlay_carrier")).strip().lower() == live):
                return row["iran_dial_host"], row["foreign_dial_host"], src
    for row, src in ((wizard_row, "wizard"), (healer_row, "healer")):
        if _complete_declaration(row):
            return row["iran_dial_host"], row["foreign_dial_host"], src
    if live and live not in ("gre", "esp"):
        return None, None, "public"
    return hub_pair.get("inner_iran"), hub_pair.get("inner_foreign"), "hub"


def run_sweep(pair_id: int, hub_db: str, log, quick: bool = False) -> dict:
    """Run the ladder in a thread, apply scores progressively, then
    finalize. Returns a summary dict.

    quick=True runs the same gates with the quick profile and stores
    the ranking as a quick test instead of touching candidate_scores,
    the healer config, or the live tunnel."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from hub.store import Store
    import healer_paths

    store = Store(hub_db)
    pair = store.get_pair(pair_id)
    if pair is None:
        raise ValueError("no pair %d in hub db" % pair_id)
    iran = store.get_server(pair["iran_server_id"])
    foreign = store.get_server(pair["foreign_server_id"])
    if iran is None or foreign is None:
        raise ValueError("pair %d has no servers" % pair_id)
    healer_db = healer_paths.db_path(pair_id)
    run_id = "%s-%d-%d" % ("quick" if quick else "sweep", pair_id,
                           int(time.time()))

    def spec(server, dial_host):
        return {"host": server["host"], "port": int(server.get("port") or 22),
                "user": "root",
                "auth": {"type": "key", "value": HUB_KEY},
                "dial_host": dial_host}

    # Bench names and bench inners derive from this hub's identity, so
    # two hubs benching the same node at once never share a bench
    # interface or bench /30. The pair's production tag/base live in the
    # engine row and are irrelevant to transient bench units.
    _identity = store.get_hub_identity()
    engine_pair = {
        "id": pair_id,
        "iran": spec(iran, pair["inner_iran"]),
        "foreign": spec(foreign, pair["inner_foreign"]),
        "frontend_port": int(pair.get("frontend_port") or 443),
        "base_rtt_ms": 0.0,  # the engine measures its own baseline
        "underlay_carrier": (pair.get("current_protocol") or "GRE").lower(),
        "hub_tag": _identity["hub_tag"],
        "inner_base": _identity["inner_base"],
    }

    # Spoof is probe-gated, not score-gated: the ladder benches it only
    # for pairs whose probe passed on both sides. Every other pair
    # skips it entirely instead of benching a tunnel that cannot work.
    if (pair.get("spoof_status") or "unknown") != "open":
        os.environ["BEST_TUNNEL_SKIP_SPOOF"] = "1"
    else:
        os.environ.pop("BEST_TUNNEL_SKIP_SPOOF", None)

    # tcp-lanes-v6 is gated the same way, but additive: the ladder
    # benches it only for pairs whose IPv6 probe passed the reverse
    # direction, dialing the probed Iran address. Any other pair never
    # sees the variant, so no bench ever dials a guessed address.
    _iran_v6 = ipv6_reverse_address(store, pair_id)
    if _iran_v6:
        os.environ["BEST_TUNNEL_IPV6_REVERSE"] = _iran_v6
    else:
        os.environ.pop("BEST_TUNNEL_IPV6_REVERSE", None)

    # storage.DB_PATH is read at engine import time, so the env var must
    # be set before the import — exactly like a hand-run sweep script.
    os.environ["BEST_TUNNEL_DB_PATH"] = healer_db
    import engine
    if quick:
        apply_quick_profile()

    # Dial hosts must be the LIVE carrier's addresses, not the hub row's
    # creation-time inners (bug 12, 2026-11-01: pair 3's hub inners were
    # 10.10.12.x while its live ESP carrier used 10.12.13.x, so every
    # overlay bench dialed a dead /30 and failed identically). The
    # declaration is read from both deploy stores — wizard (deploys) and
    # healer (switches) — and the live carrier breaks the tie; anything
    # else keeps the hub inners, so pairs without a declaration behave
    # exactly as today.
    _healer_row, _wizard_row = read_declaration_rows(pair_id, healer_db)
    _iran_dh, _foreign_dh, _src = select_dial_hosts(
        pair, _healer_row, _wizard_row)
    if _src == "public":
        # Bug 14: no carrier declaration and the live tunnel is an
        # overlay, so there is no carrier underlay to dial. Unset the
        # dial hosts so overlay benches dial the public host, exactly
        # like the wizard's overlay measure.
        log("dial hosts: public (live protocol is an overlay; "
            "no carrier underlay to dial)")
        engine_pair["iran"]["dial_host"] = None
        engine_pair["foreign"]["dial_host"] = None
    elif (_iran_dh, _foreign_dh) != (pair["inner_iran"], pair["inner_foreign"]):
        log("dial hosts overridden by live carrier declaration (%s)" % _src)
        engine_pair["iran"]["dial_host"] = _iran_dh
        engine_pair["foreign"]["dial_host"] = _foreign_dh

    errors = []

    def _thread_main():
        try:
            engine.run_all_benchmarks(
                engine_pair, dry_run=False, profile="balanced",
                run_id=run_id, callback=lambda p, s: log("[%s] %s" % (p, s)))
        except Exception:
            errors.append(traceback.format_exc())

    thread = threading.Thread(target=_thread_main, daemon=True)
    thread.start()
    seen_id = 0
    total_rows = 0
    while thread.is_alive():
        thread.join(timeout=POLL_SECONDS)
        try:
            rows, seen_id = read_new_rows(healer_db, run_id, seen_id)
        except Exception as exc:
            log("row poll failed: %s" % exc)
            continue
        if rows:
            total_rows += len(rows)
            if quick:
                for row in rows:
                    log("quick %s score=%s" % (row["protocol"], row["score"]))
            else:
                merged = apply_rows_to_hub(store, pair_id, rows)
                for row in rows:
                    log("applied %s score=%s (dashboard now: %d protocols)"
                        % (row["protocol"], row["score"], len(merged)))
    thread.join()
    try:
        rows, seen_id = read_new_rows(healer_db, run_id, seen_id)
    except Exception as exc:
        log("final row poll failed: %s" % exc)
        rows = []
    if rows:
        total_rows += len(rows)
        if not quick:
            apply_rows_to_hub(store, pair_id, rows)
    if quick:
        qrows = read_quick_rows(healer_db, run_id)
        qualified_rows = [r for r in qrows
                          if not r.get("disqualified") and (r.get("score") or 0) > 0]
        winner = (sorted(qualified_rows, key=lambda r: (-r["score"], r["protocol"]))[0]["protocol"]
                  if qualified_rows else None)
        store.save_quick_test(pair_id, winner, qrows)
        if errors:
            log("engine thread failed:\n%s" % errors[0])
        log("quick test done: winner=%s (%d protocols)" % (winner, len(qrows)))
        cleanup_bench(iran["host"], foreign["host"], log)
        summary = {
            "run_id": run_id, "rows": total_rows,
            "qualified": {r["protocol"]: r["score"] for r in qualified_rows},
            "winner": winner,
            "engine_error": bool(errors),
        }
        store.log_event("quick_test",
                        "Quick test for pair %s done: winner %s"
                        % (pair.get("name") or pair_id, winner),
                        pair_id=pair_id, data=summary)
        return summary
    final_pair = store.get_pair(pair_id) or {}
    qualified = dict(final_pair.get("candidate_scores") or {})

    if errors:
        log("engine thread failed:\n%s" % errors[0])
    changed = update_healer_config(pair_id, qualified)
    if changed:
        subprocess.run(["systemctl", "restart", healer_paths.unit_name(pair_id)],
                       timeout=60, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        log("healer config updated and restarted")
    cleanup_bench(iran["host"], foreign["host"], log)
    summary = {
        "run_id": run_id, "rows": total_rows,
        "qualified": qualified,
        "healer_config_changed": changed,
        "engine_error": bool(errors),
    }
    store.log_event("sweep",
                    "Auto-sweep for pair %s done: %d protocols qualified"
                    % (pair.get("name") or pair_id, len(qualified)),
                    pair_id=pair_id, data=summary)
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pair-id", type=int, required=True)
    parser.add_argument("--hub-db", required=True)
    parser.add_argument("--quick", action="store_true",
                        help="quick test: shorter stability window, no iperf3,"
                             " results stored separately from sweep scores")
    args = parser.parse_args(argv)
    pair_id = args.pair_id

    def log(msg):
        print(msg, flush=True)

    # The pidfile matches the scope the job handler spawned: a quick
    # run must not leave a sweep pidfile behind (or a later sweep
    # would refuse as already-running while nothing runs).
    pidfile = os.path.join(pidfile_dir(),
                            ("quicktest-p%d.pid" if args.quick
                             else "sweep-p%d.pid") % pair_id)
    try:
        os.makedirs(os.path.dirname(pidfile), exist_ok=True)
        with open(pidfile, "w") as f:
            f.write(str(os.getpid()))
    except OSError as exc:
        log("pidfile write failed (continuing): %s" % exc)
    try:
        summary = run_sweep(pair_id, args.hub_db, log, quick=args.quick)
        log("qualified: %s" % json.dumps(summary["qualified"], sort_keys=True))
        log("QUICK_DONE" if args.quick else "SWEEP_DONE")
        return 0 if summary["rows"] > 0 else 1
    except Exception:
        traceback.print_exc()
        log("QUICK_FAILED" if args.quick else "SWEEP_FAILED")
        return 1
    finally:
        try:
            os.unlink(pidfile)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
