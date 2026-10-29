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


def run_sweep(pair_id: int, hub_db: str, log) -> dict:
    """Run the ladder in a thread, apply scores progressively, then
    finalize. Returns a summary dict."""
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
    run_id = "sweep-%d-%d" % (pair_id, int(time.time()))

    def spec(server, dial_host):
        return {"host": server["host"], "port": int(server.get("port") or 22),
                "user": "root",
                "auth": {"type": "key", "value": HUB_KEY},
                "dial_host": dial_host}

    engine_pair = {
        "id": pair_id,
        "iran": spec(iran, pair["inner_iran"]),
        "foreign": spec(foreign, pair["inner_foreign"]),
        "frontend_port": int(pair.get("frontend_port") or 443),
        "base_rtt_ms": 0.0,  # the engine measures its own baseline
        "underlay_carrier": (pair.get("current_protocol") or "GRE").lower(),
    }

    # Spoof is probe-gated, not score-gated: the ladder benches it only
    # for pairs whose probe passed on both sides. Every other pair
    # skips it entirely instead of benching a tunnel that cannot work.
    if (pair.get("spoof_status") or "unknown") != "open":
        os.environ["BEST_TUNNEL_SKIP_SPOOF"] = "1"
    else:
        os.environ.pop("BEST_TUNNEL_SKIP_SPOOF", None)

    # storage.DB_PATH is read at engine import time, so the env var must
    # be set before the import — exactly like a hand-run sweep script.
    os.environ["BEST_TUNNEL_DB_PATH"] = healer_db
    import engine

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
        apply_rows_to_hub(store, pair_id, rows)
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
    args = parser.parse_args(argv)
    pair_id = args.pair_id

    def log(msg):
        print(msg, flush=True)

    pidfile = pidfile_path(pair_id)
    try:
        os.makedirs(os.path.dirname(pidfile), exist_ok=True)
        with open(pidfile, "w") as f:
            f.write(str(os.getpid()))
    except OSError as exc:
        log("pidfile write failed (continuing): %s" % exc)
    try:
        summary = run_sweep(pair_id, args.hub_db, log)
        log("qualified: %s" % json.dumps(summary["qualified"], sort_keys=True))
        log("SWEEP_DONE")
        return 0 if summary["rows"] > 0 else 1
    except Exception:
        traceback.print_exc()
        log("SWEEP_FAILED")
        return 1
    finally:
        try:
            os.unlink(pidfile)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
