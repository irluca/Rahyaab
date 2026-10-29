#!/usr/bin/env python3
"""Per-pair spoof probe runner, spawned detached by the hub.

For every pair, the hub enqueues a spoof_probe job after full_setup;
the handler spawns this script in a systemd scope unit so it survives
hub restarts and never blocks the job worker (one direction takes
~20 seconds: an 8-second listen window plus sender time).

The probe is the engine's spoof_test in both directions: the receiver
listens for ICMP echo packets whose source is forged to be its own
address, and the sender fires them. Arrival is unambiguous proof that
the path lets forged-source packets out; zero arrivals on a completed
probe is a genuine negative, not a tooling failure.

Verdict written to the hub pair row:
  open    - both directions arrived (the pair may use spoof)
  closed  - at least one direction completed with zero arrivals
  unknown - at least one direction did not complete (SSH failure, ...)
If spoof_ips are given and the verdict is open, the same list is
written to the provisioned IP files on both hosts (prod and bench
namespaces), so the pipe daemon and the bench both find it. Without
an IP list the verdict is still recorded; the tunnel simply cannot
deploy until an operator provisions one.

Usage (the hub builds this command; operators rarely run it by hand):
    python3 run_spoof_probe.py --pair-id 1 --hub-db /var/lib/rahyaab/hub.db [--spoof-ips 203.0.113.10,198.51.100.20]
"""

import argparse
import os
import socket
import sqlite3
import sys
import time
import traceback

HUB_KEY = "/etc/rahyaab/hub_key"
KNOWN_HOSTS = "/root/.ssh/known_hosts"
SPOOF_DIR = "/etc/best-tunnel/spoof"


def pidfile_dir() -> str:
    return os.environ.get("RAHYAAB_SWEEP_DIR", "/var/lib/rahyaab")


def pidfile_path(pair_id: int) -> str:
    return os.path.join(pidfile_dir(), "spoof-probe-p%d.pid" % int(pair_id))


def determine_status(dir_a: dict, dir_b: dict) -> str:
    """open iff both directions arrived; closed iff either completed
    with zero arrivals; unknown iff either direction never completed."""
    caps = [dir_a.get("capable"), dir_b.get("capable")]
    if all(c is True for c in caps):
        return "open"
    if any(c is False for c in caps):
        return "closed"
    return "unknown"


class SSHRunner:
    """Paramiko runner implementing the engine's run() contract:
    run(cmd, check, best_effort, timeout, retryable) -> (rc, out, err).
    Key-only, host keys must already be pinned (RejectPolicy)."""

    def __init__(self, host: str, port: int = 22):
        self.host = host
        self.port = port

    def run(self, cmd, check=True, best_effort=False, timeout=30, retryable=False):
        import paramiko
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if os.path.exists(KNOWN_HOSTS):
            client.load_host_keys(KNOWN_HOSTS)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(self.host, port=self.port, username="root",
                           key_filename=HUB_KEY, timeout=20,
                           banner_timeout=30, auth_timeout=30,
                           allow_agent=False, look_for_keys=False)
            _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            rc = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
        except socket.timeout as exc:
            raise TimeoutError(str(exc))
        finally:
            client.close()
        if check and not best_effort and rc != 0:
            raise RuntimeError("command failed (rc=%d): %s" % (rc, cmd[:120]))
        return rc, out, err


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pair-id", type=int, required=True)
    ap.add_argument("--hub-db", required=True)
    ap.add_argument("--spoof-ips", default="")
    args = ap.parse_args()
    pair_id = args.pair_id

    os.makedirs(pidfile_dir(), exist_ok=True)
    with open(pidfile_path(pair_id), "w") as f:
        f.write(str(os.getpid()))

    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        from hub.store import Store
        import spoof_test

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
        dir_ir_fr = spoof_test.run_direction(ir_runner, fr_runner,
                                             iran["host"], foreign["host"])
        dir_fr_ir = spoof_test.run_direction(fr_runner, ir_runner,
                                             foreign["host"], iran["host"])
        status = determine_status(dir_ir_fr, dir_fr_ir)

        ips = [ip.strip() for ip in args.spoof_ips.split(",") if ip.strip()]
        provisioned = False
        provision_error = ""
        if status == "open" and ips:
            body = "\n".join(ips) + "\n"
            try:
                for ns in ("prod", "bench"):
                    path = "%s/%s-ips-p%d.txt" % (SPOOF_DIR, ns, pair_id)
                    for runner in (ir_runner, fr_runner):
                        runner.run("mkdir -p %s && cat > %s <<'EOF'\n%sEOF\n"
                                   % (SPOOF_DIR, path, body),
                                   check=True, timeout=30)
                provisioned = True
            except Exception as exc:  # capability stands; provisioning retries on re-probe
                provision_error = str(exc)[:200]

        store.update_pair_spoof_status(pair_id, status)
        store.log_event(
            "spoof_probe",
            "Spoof probe for pair %s: %s (iran->foreign %s, foreign->iran %s)"
            % (pair["name"], status,
               dir_ir_fr.get("capable"), dir_fr_ir.get("capable")),
            pair_id=pair_id,
            data={"iran_to_foreign": dir_ir_fr,
                  "foreign_to_iran": dir_fr_ir,
                  "spoof_ips_provisioned": provisioned,
                  "provision_error": provision_error})
        print("spoof probe pair %d: %s" % (pair_id, status))
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
