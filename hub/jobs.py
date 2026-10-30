"""Background job worker for the hub.

Jobs are rows, claimed atomically (store.claim_queued_job), so a
second worker — or a hub restart — can never run the same job twice.
Handlers are small functions; Phase 4 adds benchmark/deploy handlers
that call into the orchestrator engine. Handlers receive the store,
an executor factory, and the job row, and return an output dict.

Job types shipped in Phase 2:
- healer_status: refresh a pair's healer snapshot from its healer host.
- connectivity:   run `echo rahyaab-ok` on a pair's healer host.
- noop:          test/scaffolding handler; returns its input.

Manual switch (added with click-to-switch):
- switch: validate the target against the pair's qualified candidates,
  write a switch request file for the healer, and poll the healer's
  result file until it answers. The hub never deploys: the healer is
  the pair's only controller. A switch outcome (done / failed /
  refused / unknown) is the job's output, not a job error — the job
  itself only fails on infrastructure problems (no pair, no SSH,
  request file unwritable). One worker thread means a long switch
  (up to 10 minutes of polling) delays other jobs; switches are rare
  and operator-initiated, so that trade is accepted.

Node join (added with the join flow):
- full_setup: measure one protocol, deploy the first tunnel and
  install the healer for a freshly joined pair, via the wizard chain
  (orchestrator/wizard_setup.run_setup). Runs on the hub host
  itself, so it needs no executor. A long chain (benchmark + deploy
  + healer install) holds the single worker thread; joins are rare,
  so that trade is accepted like the switch one.

Auto-sweep (added with the staged dashboard):
- sweep: after a full_setup succeeds, the worker enqueues a sweep job
  for the pair. The handler only spawns a detached systemd scope unit
  running orchestrator/run_sweep.py and returns at once — the 20-30
  minute ladder must never hold the worker thread, or switch and
  status jobs would queue behind it. The runner merges each
  protocol's qualified score into the hub pair row as it is measured,
  so the dashboard fills in gradually; it never touches the live
  tunnel or current_protocol. A second sweep for the same pair is
  refused while one's scope unit or pidfile is alive.

Spoof probe (added with the spoof gate):
- spoof_probe: after a full_setup succeeds, the worker also enqueues
  a probe job for the pair, and the operator can re-queue it any
  time. The handler only spawns a detached systemd scope unit
  running orchestrator/run_spoof_probe.py and returns at once — the
  probe takes ~40 seconds for both directions and must never hold
  the worker thread. The runner writes the verdict (open / closed /
  unknown) to the pair row and logs an event; 'open' on both sides
  is what lets the sweep bench spoof and the healer consider it,
  and 'closed' is what the dashboard names instead of silently
  lacking the protocol. A second probe for the same pair is refused
  while one's scope unit or pidfile is alive.

Tunnel port change (added with the install-time port prompt):
- change_port: move a pair's frontend port — the listener on the
  master that user traffic dials. A carrier current protocol
  (GRE/ESP) binds no frontend port, so the handler only rewrites
  the healer's pair row and config and restarts the healer: the
  tunnel itself is never touched. An overlay current protocol goes
  through the healer's switch channel with the same protocol and
  the new port, so it gets the switch's plan-first abort, smoke
  check and rollback; on success the hub pair row takes the new
  port. The hub never deploys: the healer is the pair's only
  controller, exactly as with switch.
"""

from __future__ import annotations

import threading
import time
import uuid

from . import healerctl
from .join import _ss_port_free
from .ssh import executor_for_server


def _healer_executor(store, job, make_executor):
    pair = store.get_pair(job["pair_id"]) if job.get("pair_id") else None
    if pair is None:
        raise ValueError("job has no pair")
    server = store.get_server(pair["healer_server_id"])
    if server is None:
        raise ValueError("pair has no healer server")
    return pair, executor_for_server(server, fake=make_executor(server))


def _handle_healer_status(store, job, make_executor):
    pair, executor = _healer_executor(store, job, make_executor)
    try:
        result = healerctl.status(executor, pair["id"])
    except Exception as exc:  # SSH failure is a result, not a crash
        result = {"reachable": False, "error": str(exc)}
    store.update_pair_healer(pair["id"], result)
    store.log_event("healer_status", "Healer status refreshed for pair %s" % pair["name"],
                    pair_id=pair["id"], data=result)
    return result


def _handle_connectivity(store, job, make_executor):
    pair, executor = _healer_executor(store, job, make_executor)
    try:
        rc, out, err = executor.run("echo rahyaab-ok", timeout=20)
        result = {"reachable": rc == 0, "output": out.strip(), "error": err.strip()}
    except Exception as exc:
        result = {"reachable": False, "error": str(exc)}
    store.log_event("connectivity", "Connectivity check for pair %s: %s"
                    % (pair["name"], "ok" if result["reachable"] else "failed"),
                    pair_id=pair["id"], data=result)
    return result


def _handle_noop(store, job, make_executor):
    return {"echo": job["input"]}


def _handle_switch(store, job, make_executor):
    pair = store.get_pair(job["pair_id"]) if job.get("pair_id") else None
    if pair is None:
        raise ValueError("job has no pair")
    protocol = ((job.get("input") or {}).get("protocol") or "").strip()
    if not protocol:
        raise ValueError("switch job has no protocol")
    current = (pair.get("current_protocol") or "").strip()
    if protocol == current:
        return {"status": "already", "from": current, "to": protocol,
                "rolled_back": False, "detail": ""}
    scores = pair.get("candidate_scores") or {}
    if protocol not in scores or float(scores[protocol]) <= 0:
        raise ValueError(
            "protocol %s is not a qualified candidate for this pair" % protocol)
    _, executor = _healer_executor(store, job, make_executor)
    request_id = uuid.uuid4().hex
    req = healerctl.request_switch(executor, pair["id"], protocol, request_id)
    if not req.get("ok"):
        raise RuntimeError("could not write switch request: %s" % req.get("error"))
    deadline = time.time() + 600
    while time.time() < deadline:
        res = healerctl.switch_result(executor, pair["id"], request_id)
        if res is not None:
            status = res.get("status")
            output = {"status": status, "from": res.get("from"),
                      "to": res.get("to"), "rolled_back": bool(res.get("rolled_back")),
                      "transport_only": bool(res.get("transport_only")),
                      "detail": res.get("detail") or ""}
            if status == "done":
                store.update_pair_protocol(pair["id"], protocol)
                store.log_event("switch", "Pair %s switched %s -> %s"
                                % (pair["name"], res.get("from"), protocol),
                                pair_id=pair["id"], data=res)
            elif status in ("failed", "refused"):
                store.log_event("switch", "Switch of pair %s to %s ended %s"
                                % (pair["name"], protocol, status),
                                pair_id=pair["id"], data=res)
            return output
        time.sleep(5)
    return {"status": "unknown", "from": current, "to": protocol,
            "rolled_back": False,
            "detail": "healer did not report within 600 seconds"}


def _carrier_protocols():
    """Protocols that bind no frontend port, from the engine's own list.

    The hub reads the orchestrator's CARRIER_PROTOCOLS when it can
    (same path dance as _handle_full_setup) so the two never drift;
    the literal fallback keeps the hub working — and tested — without
    the orchestrator on path.
    """
    try:
        import os
        import sys
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(root, "orchestrator")
        if path not in sys.path:
            sys.path.insert(0, path)
        import protocols
        return tuple(protocols.CARRIER_PROTOCOLS)
    except Exception:
        return ("GRE", "ESP")


# Runs on the healer host (the master) for a carrier pair's port
# change. Carriers bind no frontend *socket*, but the frontend port
# is very much live in their firewall: the DNAT match and target
# ports. Changing the records alone leaves the kernel forwarding
# the old port, which is exactly the split-brain a dashboard port
# change must not create. So this script moves the firewall too:
# delete the old port's rules (looped until absent, because
# repeated deploys have left duplicate rules on live hosts),
# rewrite the pair's manifest to the new port, re-apply it with
# the carrier's own reapply script, and verify new-present plus
# old-absent before touching the healer row or config. A failure
# anywhere before the row update leaves every record on the old
# port, and a retry is safe: the delete and rewrite steps are
# idempotent in both directions.
# Base64-wrapped like healerctl's request payload so no quoting
# can mangle it; argv carries only ids and ports, never a secret.
# Paths come from the environment only for offline tests; on the
# host they default to the production locations.
_CARRIER_PORT_SCRIPT = """
import json, os, re, sqlite3, subprocess, sys
pid, old_port, new_port = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
db = os.path.join(os.environ.get("BT_HEALER_DB_DIR", "/var/lib/best-tunnel"),
                   "healer-p%d.db" % pid)
cfg_path = os.path.join(os.environ.get("BT_HEALER_CFG_DIR", "/etc/best-tunnel"),
                        "healer-p%d.json" % pid)
fw_dir = os.environ.get("BT_FW_DIR", "/etc/best-tunnel/firewall")
ipt = os.environ.get("BT_IPTABLES", "iptables")
reapply = os.environ.get("BT_FW_REAPPLY", "/usr/local/sbin/best-tunnel-fw-reapply.sh")

def ipt_cmd(row, op):
    parts = row.split("|")
    table, chain = parts[1], parts[2]
    args = []
    if table != "filter":
        args += ["-t", table]
    args += [op, chain] + parts[5].split()
    return args

def ipt_check(row):
    return subprocess.run([ipt] + ipt_cmd(row, "-C"),
                          capture_output=True).returncode == 0

def swap_port(row, frm, to):
    row = re.sub(r"(--dport\\s+)%d(?!\\d)" % frm, r"\\g<1>%d" % to, row)
    row = re.sub(r"(--to-destination\\s+\\S+:)%d(?!\\d)" % frm,
                 r"\\g<1>%d" % to, row)
    return row

def row_ports(row):
    ports = set()
    for m in re.finditer(r"--dport\\s+(\\d+)", row):
        ports.add(int(m.group(1)))
    for m in re.finditer(r"--to-destination\\s+\\S+:(\\d+)", row):
        ports.add(int(m.group(1)))
    return ports

import glob
cands = []
for proto in ("gre", "esp"):
    cands += glob.glob(os.path.join(
        fw_dir, "best-tunnel-*-p%d-%s-fw.rules" % (pid, proto)))
if len(cands) != 1:
    print("expected exactly one carrier manifest, found %d" % len(cands))
    raise SystemExit(1)
manifest_path = cands[0]
with open(manifest_path, encoding="utf-8") as f:
    text = f.read()
rows = [ln for ln in text.splitlines() if ln.startswith("R|")]
port_rows = [r for r in rows if old_port in row_ports(r)
             or new_port in row_ports(r)]
if not port_rows:
    print("manifest names no rule on either port")
    raise SystemExit(1)
for row in port_rows:
    old_row = swap_port(row, new_port, old_port)
    for _ in range(20):
        if not ipt_check(old_row):
            break
        gone = subprocess.run([ipt] + ipt_cmd(old_row, "-D"),
                              capture_output=True).returncode == 0
        if not gone:
            print("could not delete rule: %s" % old_row)
            raise SystemExit(1)
    else:
        print("rule would not delete: %s" % old_row)
        raise SystemExit(1)
new_text = "\\n".join(
    swap_port(ln, old_port, new_port) if ln.startswith("R|") else ln
    for ln in text.splitlines()) + "\\n"
tmp = manifest_path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(new_text)
os.replace(tmp, manifest_path)
r = subprocess.run(["/bin/bash", reapply, manifest_path],
                   capture_output=True, text=True)
if r.returncode != 0:
    print("reapply failed: %s" % (r.stdout.strip() or r.stderr.strip()))
    raise SystemExit(1)
for row in port_rows:
    new_row = swap_port(row, old_port, new_port)
    old_row = swap_port(row, new_port, old_port)
    if not ipt_check(new_row):
        print("new rule missing: %s" % new_row)
        raise SystemExit(1)
    if ipt_check(old_row):
        print("old rule still present: %s" % old_row)
        raise SystemExit(1)
conn = sqlite3.connect(db)
cur = conn.execute(
    "UPDATE pairs SET frontend_port = ? WHERE id = ?", (new_port, pid))
if cur.rowcount == 0:
    print("no healer pair row")
    raise SystemExit(1)
conn.commit()
conn.close()
with open(cfg_path, encoding="utf-8") as f:
    cfg = json.load(f)
cfg["frontend_port"] = new_port
tmp = cfg_path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, sort_keys=True)
os.replace(tmp, cfg_path)
print("ok")
"""


def _handle_change_port(store, job, make_executor):
    pair = store.get_pair(job["pair_id"]) if job.get("pair_id") else None
    if pair is None:
        raise ValueError("job has no pair")
    try:
        new_port = int((job.get("input") or {}).get("frontend_port") or 0)
    except (TypeError, ValueError):
        raise ValueError("change_port job has no valid frontend_port")
    if not 1 <= new_port <= 65535:
        raise ValueError("frontend_port %d is out of range" % new_port)
    current_port = int(pair.get("frontend_port") or 443)
    if new_port == current_port:
        return {"status": "already", "from": pair.get("current_protocol") or "",
                "to": pair.get("current_protocol") or "",
                "port_from": current_port, "port_to": new_port,
                "tunnel_touched": False, "rolled_back": False, "detail": ""}
    healer_server = store.get_server(pair["healer_server_id"])
    ssh_port = int((healer_server or {}).get("port") or 22)
    if new_port in {22, 53, 68, 123, 8890, ssh_port}:
        raise ValueError("frontend_port %d is reserved" % new_port)
    for other in store.list_pairs():
        if (other["id"] != pair["id"]
                and other.get("iran_server_id") == pair.get("iran_server_id")
                and int(other.get("frontend_port") or 0) == new_port):
            raise ValueError(
                "frontend_port %d is already used by another pair" % new_port)
    # A port another service already listens on must never be taken:
    # on a carrier the DNAT would shadow that service's inbound
    # traffic. The hub runs on the master, so the local socket
    # table is authoritative. None (unreadable) accepts the port,
    # as at join time; the deploy stays the backstop. This runs
    # before any executor is created, so a refusal touches nothing.
    if _ss_port_free(new_port) is False:
        raise ValueError(
            "frontend_port %d is busy on the master" % new_port)
    current = (pair.get("current_protocol") or "").strip()
    if not current:
        raise ValueError("pair has no active tunnel to move")
    _, executor = _healer_executor(store, job, make_executor)
    if current in _carrier_protocols():
        # Carriers bind no frontend socket, but their DNAT match
        # and target ports ARE the frontend port: the script moves
        # the firewall rules with the records, or the dashboard
        # would show a port no traffic follows. The tunnel
        # interfaces are never touched. Restart the healer so the
        # config half takes effect (a restart never cuts the
        # tunnel), then take the new port in the hub row.
        import base64
        blob = base64.b64encode(_CARRIER_PORT_SCRIPT.encode()).decode()
        rc, out, err = executor.run(
            f"printf '%s' '{blob}' | base64 -d | python3 - "
            f"{pair['id']} {current_port} {new_port}", timeout=60)
        if rc != 0 or "ok" not in out:
            raise RuntimeError("could not move carrier port: %s"
                               % (err.strip() or out.strip()))
        restarted = healerctl.restart(executor, pair["id"])
        if not restarted.get("ok"):
            raise RuntimeError("could not restart healer: %s"
                               % restarted.get("error"))
        store.update_pair_frontend_port(pair["id"], new_port)
        store.log_event("change_port",
                        "Pair %s tunnel port %d -> %d (carrier: interfaces untouched, DNAT moved)"
                        % (pair["name"], current_port, new_port),
                        pair_id=pair["id"])
        return {"status": "done", "from": current, "to": current,
                "port_from": current_port, "port_to": new_port,
                "tunnel_touched": False, "rolled_back": False, "detail": ""}
    request_id = uuid.uuid4().hex
    req = healerctl.request_switch(executor, pair["id"], current, request_id,
                                   frontend_port=new_port)
    if not req.get("ok"):
        raise RuntimeError("could not write port change request: %s"
                           % req.get("error"))
    deadline = time.time() + 600
    while time.time() < deadline:
        res = healerctl.switch_result(executor, pair["id"], request_id)
        if res is not None:
            status = res.get("status")
            output = {"status": status, "from": res.get("from"),
                      "to": res.get("to"), "port_from": current_port,
                      "port_to": new_port, "tunnel_touched": True,
                      "rolled_back": bool(res.get("rolled_back")),
                      "detail": res.get("detail") or ""}
            if status == "done":
                store.update_pair_frontend_port(pair["id"], new_port)
                store.log_event("change_port",
                                "Pair %s tunnel port %d -> %d"
                                % (pair["name"], current_port, new_port),
                                pair_id=pair["id"], data=res)
            elif status in ("failed", "refused"):
                store.log_event("change_port",
                                "Port change of pair %s to %d ended %s"
                                % (pair["name"], new_port, status),
                                pair_id=pair["id"], data=res)
            return output
        time.sleep(5)
    return {"status": "unknown", "from": current, "to": current,
            "port_from": current_port, "port_to": new_port,
            "tunnel_touched": True, "rolled_back": False,
            "detail": "healer did not report within 600 seconds"}


def _handle_full_setup(store, job, make_executor):
    pair = store.get_pair(job["pair_id"]) if job.get("pair_id") else None
    if pair is None:
        raise ValueError("full_setup job has no pair")
    inp = job.get("input") or {}
    import os
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.environ.setdefault("BEST_TUNNEL_DB_PATH", "/var/lib/rahyaab/wizard.db")
    sys.path.insert(0, os.path.join(root, "orchestrator"))
    import wizard_setup
    result = wizard_setup.run_setup(
        inp["iran_host"], inp["foreign_host"], pair["id"],
        pair.get("name") or "", str(store.db_path),
        inp.get("hub_key_path") or "/etc/rahyaab/hub_key",
        frontend_port=int(inp.get("frontend_port") or 443),
        protocol=inp.get("protocol") or "GRE")
    store.log_event("full_setup",
                    "Pair %s set up: %s (score %s)"
                    % (pair["name"], result["protocol"], result["score"]),
                    pair_id=pair["id"], data=result)
    return result


def _sweep_script_path():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "orchestrator", "run_sweep.py")


def _sweep_pidfile(pair_id):
    import os
    base = os.environ.get("RAHYAAB_SWEEP_DIR", "/var/lib/rahyaab")
    return os.path.join(base, "sweep-p%d.pid" % int(pair_id))


def _sweep_running(pair_id):
    """True while a sweep scope unit is active or its pidfile is alive.

    The unit check is primary (the runner survives hub restarts in its
    own scope); the pidfile covers runners started outside systemd.
    Any check failure means 'not running' — a stale marker must never
    block a fresh sweep forever.
    """
    import os
    import subprocess
    try:
        rc = subprocess.run(
            ["systemctl", "is-active",
             "rahyaab-sweep-p%d.scope" % int(pair_id)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        if rc == 0:
            return True
    except Exception:
        pass
    try:
        with open(_sweep_pidfile(pair_id)) as f:
            pid = int(f.read().strip().split()[0])
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def _spawn_sweep(argv):
    import subprocess
    return subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            start_new_session=True)


def _probe_script_path():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "orchestrator", "run_spoof_probe.py")


def _probe_pidfile(pair_id):
    import os
    base = os.environ.get("RAHYAAB_SWEEP_DIR", "/var/lib/rahyaab")
    return os.path.join(base, "spoof-probe-p%d.pid" % int(pair_id))


def _probe_running(pair_id):
    """Mirror of _sweep_running for the probe scope unit."""
    import os
    import subprocess
    try:
        rc = subprocess.run(
            ["systemctl", "is-active",
             "rahyaab-spoof-probe-p%d.scope" % int(pair_id)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        if rc == 0:
            return True
    except Exception:
        pass
    try:
        with open(_probe_pidfile(pair_id)) as f:
            pid = int(f.read().strip().split()[0])
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def _handle_spoof_probe(store, job, make_executor):
    import os
    import shlex
    import sys
    pair = store.get_pair(job["pair_id"]) if job.get("pair_id") else None
    if pair is None:
        raise ValueError("spoof_probe job has no pair")
    pair_id = pair["id"]
    if _probe_running(pair_id):
        return {"status": "already-running", "pair_id": pair_id}
    script = _probe_script_path()
    if not os.path.exists(script):
        raise FileNotFoundError("spoof probe runner not found: %s" % script)
    log = "/var/log/rahyaab-spoof-probe-p%d.log" % pair_id
    ips = (job.get("input") or {}).get("spoof_ips") or []
    if isinstance(ips, str):
        ips = [ips]
    ips_arg = (" --spoof-ips %s" % shlex.quote(",".join(ips))) if ips else ""
    inner = ("%s %s --pair-id %d --hub-db %s%s > %s 2>&1; echo EXIT_CODE:$? >> %s" % (
        shlex.quote(sys.executable), shlex.quote(script), pair_id,
        shlex.quote(str(store.db_path)), ips_arg,
        shlex.quote(log), shlex.quote(log)))
    argv = ["systemd-run", "--scope", "--unit=rahyaab-spoof-probe-p%d" % pair_id,
            "bash", "-c", inner]
    _spawn_sweep(argv)
    return {"status": "started", "pair_id": pair_id,
            "unit": "rahyaab-spoof-probe-p%d.scope" % pair_id, "log": log}


def _handle_sweep(store, job, make_executor):
    import os
    import shlex
    import sys
    pair = store.get_pair(job["pair_id"]) if job.get("pair_id") else None
    if pair is None:
        raise ValueError("sweep job has no pair")
    pair_id = pair["id"]
    if _sweep_running(pair_id):
        return {"status": "already-running", "pair_id": pair_id}
    script = _sweep_script_path()
    if not os.path.exists(script):
        raise FileNotFoundError("sweep runner not found: %s" % script)
    log = "/var/log/rahyaab-sweep-p%d.log" % pair_id
    inner = "%s %s --pair-id %d --hub-db %s > %s 2>&1; echo EXIT_CODE:$? >> %s" % (
        shlex.quote(sys.executable), shlex.quote(script), pair_id,
        shlex.quote(str(store.db_path)), shlex.quote(log), shlex.quote(log))
    argv = ["systemd-run", "--scope", "--unit=rahyaab-sweep-p%d" % pair_id,
            "bash", "-c", inner]
    _spawn_sweep(argv)
    return {"status": "started", "pair_id": pair_id,
            "unit": "rahyaab-sweep-p%d.scope" % pair_id, "log": log}


HANDLERS = {
    "healer_status": _handle_healer_status,
    "connectivity": _handle_connectivity,
    "noop": _handle_noop,
    "switch": _handle_switch,
    "change_port": _handle_change_port,
    "full_setup": _handle_full_setup,
    "sweep": _handle_sweep,
    "spoof_probe": _handle_spoof_probe,
}


def backfill_spoof_probes(store) -> list[int]:
    """Enqueue a probe for every pair whose verdict is still unknown.

    Called once at hub start (production entry point only, never from
    the worker): pairs joined after the spoof gate get their probe
    from the full_setup path, but pairs created before it would
    otherwise never be checked, and the rule is every pair. A pair
    with a queued probe is never duplicated; a pair whose probe
    failed stays unknown and re-queues on the next start, which
    self-heals once the runner exists.
    """
    enqueued = []
    for pair in store.list_pairs():
        if (pair.get("spoof_status") or "unknown") != "unknown":
            continue
        try:
            if store.has_queued_job("spoof_probe", pair["id"]):
                continue
            store.create_job("spoof_probe", pair["id"], {})
            enqueued.append(pair["id"])
        except Exception:
            pass
    return enqueued


class Worker(threading.Thread):
    """Polls for queued jobs and runs them, one at a time."""

    def __init__(self, store, make_executor=None, poll_seconds: float = 0.5):
        super().__init__(daemon=True, name="rahyaab-job-worker")
        self.store = store
        self.make_executor = make_executor  # fn(server) -> Executor | None
        self.poll_seconds = poll_seconds
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                job = self.store.claim_queued_job()
            except Exception:
                # A transient store error must never kill job processing
                # silently; back off and try again.
                self._stop_event.wait(self.poll_seconds)
                continue
            if job is None:
                self._stop_event.wait(self.poll_seconds)
                continue
            handler = HANDLERS.get(job["type"])
            try:
                if handler is None:
                    raise ValueError("unknown job type: %s" % job["type"])
                output = handler(self.store, job,
                                 (lambda s: self.make_executor(s))
                                 if self.make_executor else (lambda s: None))
                self.store.finish_job(job["id"], output, None)
                if job["type"] == "full_setup" and job.get("pair_id"):
                    # The first tunnel is up; measure the rest in the
                    # background so the dashboard fills in gradually,
                    # and probe spoof for this pair so its verdict is
                    # known (open / closed) rather than assumed.
                    # A failed enqueue must never break the worker loop.
                    try:
                        self.store.create_job("sweep", job["pair_id"], {})
                    except Exception:
                        pass
                    try:
                        self.store.create_job("spoof_probe", job["pair_id"], {})
                    except Exception:
                        pass
            except Exception as exc:
                self.store.finish_job(job["id"], None, str(exc))
            time.sleep(0)
