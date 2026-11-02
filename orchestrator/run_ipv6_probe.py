#!/usr/bin/env python3
"""Per-pair IPv6 readiness probe runner, spawned detached by the hub.

Mirrors run_spoof_probe.py: the hub enqueues an ipv6_probe job after
full_setup (and backfills pairs that predate the gate), the handler
spawns this script in a systemd scope unit so it survives hub
restarts and never blocks the job worker, and the script writes its
verdict to the hub's pair_ipv6_status table plus an event log row.

The probe itself lives in ipv6_readiness.py and is pure reads: each
host's global IPv6 addresses plus one TCP connect per direction to
the peer's IPv6 :22. No tunnel, firewall or config is touched.

Verdict (see ipv6_readiness.probe_pair):
  reverse_ready - Iran has global IPv6 AND foreign->Iran TCP passes.
    This is what gates the tcp-lanes-v6 candidate in sweeps.
  outbound_ok   - foreign has global IPv6 AND Iran->foreign TCP passes.
    Informational: no shipped protocol dials IPv6 from Iran yet.
Any direction that could not be tested stays "unknown" in its detail
field, never reported as blocked.

Usage (the hub builds this command; operators rarely run it by hand):
    python3 run_ipv6_probe.py --pair-id 1 --hub-db /var/lib/rahyaab/hub.db
"""

import argparse
import os
import sys
import traceback


def pidfile_dir() -> str:
    return os.environ.get("RAHYAAB_SWEEP_DIR", "/var/lib/rahyaab")


def pidfile_path(pair_id: int) -> str:
    return os.path.join(pidfile_dir(), "ipv6-probe-p%d.pid" % int(pair_id))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pair-id", type=int, required=True)
    ap.add_argument("--hub-db", required=True)
    args = ap.parse_args()
    pair_id = args.pair_id

    os.makedirs(pidfile_dir(), exist_ok=True)
    with open(pidfile_path(pair_id), "w") as f:
        f.write(str(os.getpid()))

    try:
        here = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, here)
        repo_root = os.path.dirname(here)
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        from hub.store import Store
        import ipv6_readiness
        from run_spoof_probe import SSHRunner

        store = Store(args.hub_db)
        pair = store.get_pair(pair_id)
        if pair is None:
            print("no pair %d in hub db" % pair_id, file=sys.stderr)
            return 1
        iran = store.get_server(pair["iran_server_id"])
        foreign = store.get_server(pair["foreign_server_id"])
        if iran is None or foreign is None:
            print("pair %d has no servers" % pair_id, file=sys.stderr)
            return 1

        ir_runner = SSHRunner(iran["host"], int(iran.get("port") or 22))
        fr_runner = SSHRunner(foreign["host"], int(foreign.get("port") or 22))
        payload = ipv6_readiness.probe_pair(ir_runner, fr_runner)

        store.save_ipv6_status(pair_id, payload)
        store.log_event(
            "ipv6_probe",
            "IPv6 probe for pair %s: reverse_ready=%s outbound_ok=%s "
            "(iran %s, foreign %s)"
            % (pair["name"], payload["reverse_ready"], payload["outbound_ok"],
               payload["iran_v6"], payload["foreign_v6"]),
            pair_id=pair_id, data=payload)
        print("ipv6 probe pair %d: reverse_ready=%s"
              % (pair_id, payload["reverse_ready"]))
        return 0
    except Exception:
        traceback.print_exc()
        return 1
    finally:
        try:
            os.unlink(pidfile_path(pair_id))
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
