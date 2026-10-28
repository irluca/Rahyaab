"""Latest per-protocol benchmark factors, read from the healer database.

The healer owns benchmark history (it runs beside the tunnels); the hub only
reads it, read-only, to render the protocol comparison. A missing,
unreadable, or old-schema healer DB is an empty comparison, never a 500:
the dashboard shows dashes until a sweep with full factors lands.
"""

import json
import os
import sqlite3

DEFAULT_HEALER_DB = "/var/lib/best-tunnel/healer.db"


def healer_db_path() -> str:
    return os.environ.get("RAHYAAB_HEALER_DB", DEFAULT_HEALER_DB)


def healer_db_path_for_pair(pair_id: int) -> str:
    """Per-pair healer DB (multi-node scheme, mirrors healer_paths)."""
    return "/var/lib/best-tunnel/healer-p%d.db" % int(pair_id)


def _col(row: dict, name: str):
    return row.get(name)


def latest_benchmarks(pair_name: str, db_path: str | None = None) -> list[dict]:
    """Newest benchmark row per protocol for one pair, best score first.

    A row counts as measured only when its latency is positive: the
    medians-only rows the installer wrote carry 0.0 factors, and a real
    ping is never 0.0, so latency separates "score only" from "factors".
    """
    path = db_path or healer_db_path()
    if not os.path.exists(path):
        return []
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10.0)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error:
        return []
    try:
        row = conn.execute(
            "SELECT id FROM pairs WHERE name = ? ORDER BY id DESC LIMIT 1",
            (pair_name,)).fetchone()
        if row is None:
            return []
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM benchmarks WHERE pair_id = ? ORDER BY id DESC",
            (row["id"],)).fetchall()]
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    latest: dict[str, dict] = {}
    for r in rows:
        proto = r.get("protocol")
        if not proto or proto in latest:
            continue
        details = {}
        try:
            details = json.loads(r.get("details_json") or "{}")
        except (ValueError, TypeError):
            details = {}
        if not isinstance(details, dict):
            details = {}
        bd = details.get("breakdown") or {}
        if not isinstance(bd, dict):
            bd = {}
        latest[proto] = {
            "protocol": proto,
            "score": _col(r, "score") or 0.0,
            "disqualified": bool(_col(r, "disqualified")),
            "latency_ms": _col(r, "latency_ms"),
            "jitter_ms": _col(r, "jitter_ms"),
            "loss_pct": _col(r, "loss_pct"),
            "bulk_step": _col(r, "bulk_step"),
            "throughput_mbps": _col(r, "throughput_mbps"),
            "throughput_up_mbps": _col(r, "throughput_up_mbps"),
            "throughput_down_mbps": _col(r, "throughput_down_mbps"),
            "seconds_survived": bd.get("seconds_survived"),
            "base_rtt_ms": bd.get("base_rtt"),
            "dq_reasons": details.get("dq_reasons") or [],
            "run_id": _col(r, "run_id"),
            "measured_at": _col(r, "created_at"),
        }
    return sorted(latest.values(), key=lambda x: x["score"], reverse=True)
