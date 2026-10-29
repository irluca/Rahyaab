"""Control and observation of the server-side healer from the hub.

Each pair has its own healer instance on its healer server (normally
the Iran side): unit `best-tunnel-healer-p{pair_id}`, heartbeat at
/var/lib/best-tunnel/healer-heartbeat-p{pair_id}.json, switch files
switch-request-p{pair_id}.json / switch-result-p{pair_id}.json. The
scheme mirrors orchestrator/healer_paths.py; keep the two in sync.

The hub reads only the unit state and the heartbeat — it never cats
/etc/best-tunnel/healer-p*.json, which may one day hold a Telegram
token, and it never returns raw config to a client.

A heartbeat older than 120 seconds (six 20-second passes) counts as
stale: the unit may claim to be active while the monitor itself has
stopped writing.
"""

from __future__ import annotations

import base64
import datetime
import json
import time


def unit_name(pair_id: int) -> str:
    return "best-tunnel-healer-p%d" % int(pair_id)


def heartbeat_path(pair_id: int) -> str:
    return "/var/lib/best-tunnel/healer-heartbeat-p%d.json" % int(pair_id)


# Manual-switch protocol (see orchestrator/manual_switch.py): the hub
# only writes the request; the healer is the only controller that acts.
def switch_request_path(pair_id: int) -> str:
    return "/var/lib/best-tunnel/switch-request-p%d.json" % int(pair_id)


def switch_result_path(pair_id: int) -> str:
    return "/var/lib/best-tunnel/switch-result-p%d.json" % int(pair_id)


STALE_AFTER_SECONDS = 120


def _parse_heartbeat(raw: str) -> dict | None:
    try:
        data = json.loads(raw) if raw.strip() else None
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def status(executor, pair_id: int) -> dict:
    rc, active_out, _ = executor.run(f"systemctl is-active {unit_name(pair_id)}", timeout=20)
    unit_active = rc == 0 and active_out.strip() == "active"
    rc, raw, _ = executor.run(f"cat {heartbeat_path(pair_id)}", timeout=20)
    heartbeat = _parse_heartbeat(raw) if rc == 0 else None
    age = None
    if heartbeat and heartbeat.get("updated_at"):
        try:
            updated = datetime.datetime.fromisoformat(
                heartbeat["updated_at"].replace("Z", "+00:00"))
            age = time.time() - updated.timestamp()
        except ValueError:
            age = None
    return {
        "reachable": True,
        "unit_active": unit_active,
        "heartbeat": heartbeat,
        "heartbeat_age_seconds": round(age, 1) if age is not None else None,
        "heartbeat_stale": age is None or age > STALE_AFTER_SECONDS,
        "healthy": bool(unit_active and heartbeat and age is not None
                        and age <= STALE_AFTER_SECONDS),
    }


def start(executor, pair_id: int) -> dict:
    rc, out, err = executor.run(f"systemctl start {unit_name(pair_id)}", timeout=60)
    return {"ok": rc == 0, "output": out.strip(), "error": err.strip()}


def stop(executor, pair_id: int) -> dict:
    rc, out, err = executor.run(f"systemctl stop {unit_name(pair_id)}", timeout=60)
    return {"ok": rc == 0, "output": out.strip(), "error": err.strip()}


def restart(executor, pair_id: int) -> dict:
    rc, out, err = executor.run(f"systemctl restart {unit_name(pair_id)}", timeout=60)
    return {"ok": rc == 0, "output": out.strip(), "error": err.strip()}


def request_switch(executor, pair_id: int, protocol: str, request_id: str,
                   frontend_port: int | None = None) -> dict:
    """Ask the healer to switch to `protocol`, by request file.

    The payload is base64-wrapped so no quoting can mangle it, and the
    file is root-only: it is a control channel for the pair's only
    controller, not a world-writable trigger. `frontend_port`, when
    given, turns the request into a port change: same protocol, new
    frontend port — the healer redeploys that protocol on the new
    port with the switch's smoke check and rollback.
    """
    payload = {"protocol": protocol, "request_id": request_id,
               "requested_at": time.time()}
    if frontend_port is not None:
        payload["frontend_port"] = int(frontend_port)
    blob = base64.b64encode(json.dumps(payload).encode()).decode()
    path = switch_request_path(pair_id)
    rc, out, err = executor.run(
        f"printf '%s' '{blob}' | base64 -d > {path} "
        f"&& chmod 600 {path}", timeout=30)
    return {"ok": rc == 0, "output": out.strip(), "error": err.strip()}


def switch_result(executor, pair_id: int, request_id: str) -> dict | None:
    """The healer's result for `request_id`, or None if not answered yet.

    Results for other request ids are ignored: a stale result file
    from an earlier switch must never satisfy a later poll.
    """
    rc, raw, _ = executor.run(f"cat {switch_result_path(pair_id)}", timeout=20)
    if rc != 0:
        return None
    try:
        data = json.loads(raw) if raw.strip() else None
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or data.get("request_id") != request_id:
        return None
    return data
