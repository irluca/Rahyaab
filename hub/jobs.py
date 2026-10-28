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
"""

from __future__ import annotations

import threading
import time
import uuid

from . import healerctl
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


HANDLERS = {
    "healer_status": _handle_healer_status,
    "connectivity": _handle_connectivity,
    "noop": _handle_noop,
    "switch": _handle_switch,
    "full_setup": _handle_full_setup,
}


class Worker(threading.Thread):
    """Polls for queued jobs and runs them, one at a time."""

    def __init__(self, store, make_executor=None, poll_seconds: float = 0.5):
        super().__init__(daemon=True, name="rahyaab-job-worker")
        self.store = store
        self.make_executor = make_executor  # fn(server) -> Executor | None
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                job = self.store.claim_queued_job()
            except Exception:
                # A transient store error must never kill job processing
                # silently; back off and try again.
                self._stop.wait(self.poll_seconds)
                continue
            if job is None:
                self._stop.wait(self.poll_seconds)
                continue
            handler = HANDLERS.get(job["type"])
            try:
                if handler is None:
                    raise ValueError("unknown job type: %s" % job["type"])
                output = handler(self.store, job,
                                 (lambda s: self.make_executor(s))
                                 if self.make_executor else (lambda s: None))
                self.store.finish_job(job["id"], output, None)
            except Exception as exc:
                self.store.finish_job(job["id"], None, str(exc))
            time.sleep(0)
