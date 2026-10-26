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
"""

from __future__ import annotations

import threading
import time

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
        result = healerctl.status(executor)
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


HANDLERS = {
    "healer_status": _handle_healer_status,
    "connectivity": _handle_connectivity,
    "noop": _handle_noop,
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
