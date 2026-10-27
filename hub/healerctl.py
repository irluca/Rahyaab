"""Control and observation of the server-side healer from the hub.

The healer lives on one fleet server per pair (normally the Iran
side) as the `best-tunnel-healer` systemd unit, with its heartbeat
at /var/lib/best-tunnel/healer-heartbeat.json. The hub reads only
the unit state and the heartbeat — it never cats /etc/best-tunnel/
healer.json, which may one day hold a Telegram token, and it never
returns raw config to a client.

A heartbeat older than 120 seconds (six 20-second passes) counts as
stale: the unit may claim to be active while the monitor itself has
stopped writing.
"""

from __future__ import annotations

import base64
import datetime
import json
import time

UNIT = "best-tunnel-healer"
HEARTBEAT_PATH = "/var/lib/best-tunnel/healer-heartbeat.json"
STALE_AFTER_SECONDS = 120
# Manual-switch protocol (see orchestrator/manual_switch.py): the hub
# only writes the request; the healer is the only controller that acts.
SWITCH_REQUEST_PATH = "/var/lib/best-tunnel/switch-request.json"
SWITCH_RESULT_PATH = "/var/lib/best-tunnel/switch-result.json"


def _parse_heartbeat(raw: str) -> dict | None:
    try:
        data = json.loads(raw) if raw.strip() else None
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def status(executor) -> dict:
    rc, active_out, _ = executor.run(f"systemctl is-active {UNIT}", timeout=20)
    unit_active = rc == 0 and active_out.strip() == "active"
    rc, raw, _ = executor.run(f"cat {HEARTBEAT_PATH}", timeout=20)
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


def start(executor) -> dict:
    rc, out, err = executor.run(f"systemctl start {UNIT}", timeout=60)
    return {"ok": rc == 0, "output": out.strip(), "error": err.strip()}


def stop(executor) -> dict:
    rc, out, err = executor.run(f"systemctl stop {UNIT}", timeout=60)
    return {"ok": rc == 0, "output": out.strip(), "error": err.strip()}


def restart(executor) -> dict:
    rc, out, err = executor.run(f"systemctl restart {UNIT}", timeout=60)
    return {"ok": rc == 0, "output": out.strip(), "error": err.strip()}


def request_switch(executor, protocol: str, request_id: str) -> dict:
    """Ask the healer to switch to `protocol`, by request file.

    The payload is base64-wrapped so no quoting can mangle it, and the
    file is root-only: it is a control channel for the pair's only
    controller, not a world-writable trigger.
    """
    payload = json.dumps({"protocol": protocol, "request_id": request_id,
                          "requested_at": time.time()})
    blob = base64.b64encode(payload.encode()).decode()
    rc, out, err = executor.run(
        f"printf '%s' '{blob}' | base64 -d > {SWITCH_REQUEST_PATH} "
        f"&& chmod 600 {SWITCH_REQUEST_PATH}", timeout=30)
    return {"ok": rc == 0, "output": out.strip(), "error": err.strip()}


def switch_result(executor, request_id: str) -> dict | None:
    """The healer's result for `request_id`, or None if not answered yet.

    Results for other request ids are ignored: a stale result file
    from an earlier switch must never satisfy a later poll.
    """
    rc, raw, _ = executor.run(f"cat {SWITCH_RESULT_PATH}", timeout=20)
    if rc != 0:
        return None
    try:
        data = json.loads(raw) if raw.strip() else None
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or data.get("request_id") != request_id:
        return None
    return data
