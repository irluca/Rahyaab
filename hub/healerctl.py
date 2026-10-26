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

import datetime
import json
import time

UNIT = "best-tunnel-healer"
HEARTBEAT_PATH = "/var/lib/best-tunnel/healer-heartbeat.json"
STALE_AFTER_SECONDS = 120


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
