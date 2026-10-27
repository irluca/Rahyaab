#!/usr/bin/env python3
"""Manual (operator-requested) tunnel switch, executed by the healer.

Design, and the reason this module exists at all: healer.py's
single-writer rule says that while the healer owns a pair, nothing else
may deploy, switch or benchmark it. The hub therefore never deploys. It
writes a switch request file on the healer host; the healer — the only
controller for the pair — consumes it and performs the switch with the
same FailoverManager.execute_failover the auto-healer uses. A manual
switch thus gets exactly the same guarantees: plan-first abort (a bad
plan never touches the live tunnel), the carrier gate, the circuit
breaker, quarantine restore, and a smoke check before the switch
commits. Where the auto path cannot restore (a carrier predecessor has
no quarantine), this module redeploys the previous protocol itself, so
a failed manual switch still ends on a working tunnel whenever the
previous protocol can be restored at all.

Request file (written by the hub, consumed by the healer):
    {"protocol": "ESP", "request_id": "<uuid>", "requested_at": <epoch>}
Result file (written by the healer, polled by the hub job):
    {"request_id", "status": "done" | "failed" | "refused",
     "from": <protocol>, "to": <protocol>, "already": bool,
     "rolled_back": bool, "detail": str, "finished_at": <epoch>}

A request older than REQUEST_MAX_AGE_SECONDS is refused, never
executed: a healer that was down when the request arrived must not
surprise-switch a pair long after the operator gave up waiting.

A target no plan can be generated for is failed before any unit is
touched, so a typo can never trigger a rollback redeploy of a healthy
tunnel: execute_failover's failure path would otherwise redeploy the
previous protocol as a "rollback" for a switch that never took the old
tunnel down.
"""

import json
import os
import time

# Flat import: the healer runs from orchestrator/ (see healer.py), and
# the tests insert this directory on sys.path the same way.
import protocols

REQUEST_PATH = "/var/lib/best-tunnel/switch-request.json"
RESULT_PATH = "/var/lib/best-tunnel/switch-result.json"
REQUEST_MAX_AGE_SECONDS = 600


def load_request(path: str):
    """Parse a request file; None when absent or malformed."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    protocol = (data.get("protocol") or "").strip()
    request_id = (data.get("request_id") or "").strip()
    try:
        requested_at = float(data.get("requested_at") or 0)
    except (TypeError, ValueError):
        return None
    if not protocol or not request_id or requested_at <= 0:
        return None
    return {"protocol": protocol, "request_id": request_id,
            "requested_at": requested_at}


def is_stale(request: dict, max_age_seconds: int = REQUEST_MAX_AGE_SECONDS,
             now: float | None = None) -> bool:
    return (now if now is not None else time.time()) - request["requested_at"] > max_age_seconds


def write_result(path: str, payload: dict) -> None:
    payload = dict(payload)
    payload["finished_at"] = time.time()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def consume(path: str):
    """Read a request file and remove it; None when absent or malformed.

    Removal is best-effort: a request that survives its read is refused
    as stale on the next cycle, never executed twice, because the
    result file carries the request_id it already answered.
    """
    request = load_request(path)
    try:
        os.unlink(path)
    except OSError:
        pass
    return request


def _runners(monitor, pair: dict):
    """Fresh runners for one switch leg; the caller closes them."""
    ir_runner = monitor.runner_factory(pair["iran"], dry_run=False, host_role="iran")
    try:
        fr_runner = monitor.runner_factory(pair["foreign"], dry_run=False, host_role="foreign")
    except BaseException:
        if hasattr(ir_runner, "close"):
            ir_runner.close()
        raise
    return ir_runner, fr_runner


def _close(ir_runner, fr_runner) -> None:
    for runner in (ir_runner, fr_runner):
        if runner is not None and hasattr(runner, "close"):
            try:
                runner.close()
            except Exception:
                pass


def run_manual_switch(monitor, request: dict, result_path: str = RESULT_PATH) -> dict:
    """Execute one manual switch under the monitor's action lock.

    Runs in its own thread on the healer: the lock makes an auto pass
    wait out the switch (and vice versa), and the heartbeat keeps
    writing from the healer's main thread throughout. Always writes a
    result file, so the hub job polling for request_id terminates.
    """
    target = request["protocol"]
    request_id = request["request_id"]
    result = {"request_id": request_id, "status": "failed", "from": "",
              "to": target, "already": False, "rolled_back": False,
              "detail": "manual switch did not run"}
    try:
        with monitor.action_lock():
            pairs = monitor.pair_source()
            pair = pairs[0] if pairs else None
            if pair is None:
                result["detail"] = "healer database has no pair"
                write_result(result_path, result)
                return result
            current = (pair.get("active_tunnel") or "").strip()
            result["from"] = current
            if not current:
                result["detail"] = "pair has no recorded active_tunnel"
                write_result(result_path, result)
                return result
            if target == current:
                result.update(status="done", already=True,
                              detail="pair is already on %s" % target)
                write_result(result_path, result)
                return result
            # Plan-first, before any unit is touched: a target no plan
            # can be generated for (unknown protocol, unplannable
            # shape) is failed here, never handed to execute_failover.
            # This mirrors execute_failover's own plan_for exactly.
            try:
                protocols.generate_deployment(
                    target, pair["id"],
                    protocols.dial_address(pair["iran"], target),
                    protocols.dial_address(pair["foreign"], target),
                    pair.get("frontend_port", pair.get("frontend", 443)),
                    backend_port=pair.get("backend_port") or None)
            except Exception as exc:
                result.update(status="failed",
                              detail="cannot plan %s: %s" % (target, exc))
                write_result(result_path, result)
                return result
            ir_runner, fr_runner = _runners(monitor, pair)
            try:
                out = monitor.manager.execute_failover(
                    pair, current, target, reason="manual-switch",
                    ir_runner=ir_runner, fr_runner=fr_runner)
            finally:
                _close(ir_runner, fr_runner)
            if out.get("success"):
                result.update(status="done",
                              detail="switched %s -> %s" % (current, target))
                write_result(result_path, result)
                return result
            if out.get("blocked"):
                result.update(status="refused",
                              detail=out.get("reason") or "switch refused")
                write_result(result_path, result)
                return result
            detail = out.get("error") or "switch failed"
            if out.get("restored"):
                # Non-carrier predecessor: the quarantine restore inside
                # execute_failover already put the old tunnel back.
                result.update(rolled_back=True, detail=detail)
                write_result(result_path, result)
                return result
            # Carrier predecessor (and every exception path) has no
            # quarantine to restore from: redeploy the previous
            # protocol explicitly, and report whether that worked.
            ir_runner, fr_runner = _runners(monitor, pair)
            try:
                rollback = monitor.manager.execute_failover(
                    pair, target, current, reason="manual-rollback",
                    ir_runner=ir_runner, fr_runner=fr_runner)
            finally:
                _close(ir_runner, fr_runner)
            if rollback.get("success"):
                result.update(rolled_back=True, detail=detail)
            else:
                result.update(
                    rolled_back=False,
                    detail="%s; rollback to %s also failed: %s" % (
                        detail, current,
                        rollback.get("error") or rollback.get("reason") or "unknown"))
            write_result(result_path, result)
            return result
    except Exception as exc:  # never leave the hub job polling forever
        result["detail"] = "manual switch raised %s: %s" % (type(exc).__name__, exc)
        try:
            write_result(result_path, result)
        except Exception:
            pass
        return result
