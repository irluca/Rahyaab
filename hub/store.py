"""SQLite storage for the hub: users, servers, pairs, jobs, events.

One connection per operation (sqlite3, WAL off, short transactions);
the hub is a single-process control plane, so this is plenty, and it
keeps the code free of an ORM. All JSON columns are stored as text
and decoded on read. No secret is ever stored here for a managed
server — servers carry a key *path*, never a key or a password.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL DEFAULT 'root',
    key_path TEXT,
    notes TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS pairs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    iran_server_id INTEGER NOT NULL REFERENCES servers(id),
    foreign_server_id INTEGER NOT NULL REFERENCES servers(id),
    healer_server_id INTEGER REFERENCES servers(id),
    frontend_port INTEGER NOT NULL DEFAULT 443,
    current_protocol TEXT,
    inner_iran TEXT,
    inner_foreign TEXT,
    candidate_scores TEXT NOT NULL DEFAULT '{}',
    healer_last_status TEXT,
    healer_last_seen REAL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    pair_id INTEGER REFERENCES pairs(id),
    status TEXT NOT NULL DEFAULT 'queued',
    input TEXT NOT NULL DEFAULT '{}',
    output TEXT,
    error TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    kind TEXT NOT NULL,
    pair_id INTEGER REFERENCES pairs(id),
    server_id INTEGER REFERENCES servers(id),
    message TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS healer_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pair_id INTEGER NOT NULL REFERENCES pairs(id),
    created_at REAL NOT NULL,
    reachable INTEGER NOT NULL,
    unit_active INTEGER NOT NULL,
    healthy INTEGER NOT NULL,
    heartbeat_age_seconds REAL
);
CREATE TABLE IF NOT EXISTS server_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL REFERENCES servers(id),
    created_at REAL NOT NULL,
    load1 REAL,
    mem_used_pct REAL,
    disk_used_pct REAL,
    uptime_seconds REAL
);
CREATE TABLE IF NOT EXISTS pair_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pair_id INTEGER NOT NULL REFERENCES pairs(id),
    created_at REAL NOT NULL,
    latency_ms REAL,
    rx_bytes INTEGER,
    tx_bytes INTEGER,
    rx_kbps REAL,
    tx_kbps REAL
);
"""


def _decode(row: sqlite3.Row) -> dict:
    out = dict(row)
    for key in ("candidate_scores", "healer_last_status", "input", "output", "data"):
        if key in out and isinstance(out[key], str):
            try:
                out[key] = json.loads(out[key])
            except json.JSONDecodeError:
                out[key] = {} if key != "output" else None
    return out


class Store:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    # -- users / sessions -------------------------------------------------
    def user_count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def create_user(self, username: str, password_hash: str) -> dict:
        now = time.time()
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, now),
            )
            return {"id": cur.lastrowid, "username": username, "created_at": now}

    def get_user(self, username: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            return dict(row) if row else None

    def create_session(self, token_hash: str, user_id: int, expires_at: float) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, expires_at)"
                " VALUES (?, ?, ?, ?)",
                (token_hash, user_id, time.time(), expires_at),
            )

    def get_session(self, token_hash: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE token_hash = ? AND expires_at > ?",
                (token_hash, time.time()),
            ).fetchone()
            return dict(row) if row else None

    def delete_session(self, token_hash: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    # -- servers ----------------------------------------------------------
    def create_server(self, data: dict) -> dict:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO servers (name, host, port, username, key_path, notes, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (data["name"], data["host"], data.get("port", 22),
                 data.get("username", "root"), data.get("key_path"),
                 data.get("notes", ""), time.time()),
            )
            server_id = cur.lastrowid
        # Read after the insert transaction commits; a second
        # connection cannot see the row before that.
        return self.get_server(server_id)

    def get_server(self, server_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
            return dict(row) if row else None

    def list_servers(self) -> list[dict]:
        with self._connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM servers ORDER BY id")]

    def delete_server(self, server_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
            return cur.rowcount > 0

    # -- pairs ------------------------------------------------------------
    def create_pair(self, data: dict) -> dict:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO pairs (name, iran_server_id, foreign_server_id,"
                " healer_server_id, frontend_port, current_protocol, inner_iran,"
                " inner_foreign, candidate_scores, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (data["name"], data["iran_server_id"], data["foreign_server_id"],
                 data.get("healer_server_id") or data["iran_server_id"],
                 data.get("frontend_port", 443), data.get("current_protocol"),
                 data.get("inner_iran"), data.get("inner_foreign"),
                 json.dumps(data.get("candidate_scores") or {}), time.time()),
            )
            pair_id = cur.lastrowid
        return self.get_pair(pair_id)

    def get_pair(self, pair_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM pairs WHERE id = ?", (pair_id,)).fetchone()
            return _decode(row) if row else None

    def list_pairs(self) -> list[dict]:
        with self._connect() as conn:
            return [_decode(r) for r in conn.execute("SELECT * FROM pairs ORDER BY id")]

    def update_pair_healer(self, pair_id: int, status: dict) -> None:
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                "UPDATE pairs SET healer_last_status = ?, healer_last_seen = ? WHERE id = ?",
                (json.dumps(status), now, pair_id),
            )
            # The heartbeat carries the healer's recorded protocol, so
            # the displayed protocol follows any switch (manual or
            # automatic) even when the switch job itself never reports.
            # A heartbeat without the field leaves the row untouched.
            heartbeat = (status or {}).get("heartbeat") or {}
            active = (heartbeat.get("active_tunnel") or "").strip()
            if active:
                conn.execute(
                    "UPDATE pairs SET current_protocol = ? WHERE id = ?",
                    (active, pair_id),
                )
            # Every refresh appends one history point. Charts in Phase 3
            # draw only from this table: no measured point, no point.
            conn.execute(
                "INSERT INTO healer_history (pair_id, created_at, reachable,"
                " unit_active, healthy, heartbeat_age_seconds)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (pair_id, now, 1 if status.get("reachable") else 0,
                 1 if status.get("unit_active") else 0,
                 1 if status.get("healthy") else 0,
                 status.get("heartbeat_age_seconds")),
            )

    def update_pair_protocol(self, pair_id: int, protocol: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE pairs SET current_protocol = ? WHERE id = ?",
                (protocol, pair_id),
            )

    def list_healer_history(self, pair_id: int, limit: int = 200) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT created_at, reachable, unit_active, healthy,"
                " heartbeat_age_seconds FROM healer_history"
                " WHERE pair_id = ? ORDER BY id DESC LIMIT ?",
                (pair_id, limit))
            points = [dict(r) for r in rows]
            points.reverse()
            return points

    def delete_pair(self, pair_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM pairs WHERE id = ?", (pair_id,))
            return cur.rowcount > 0

    # -- jobs -------------------------------------------------------------
    def create_job(self, job_type: str, pair_id: int | None, input_data: dict) -> dict:
        now = time.time()
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO jobs (type, pair_id, status, input, created_at, updated_at)"
                " VALUES (?, ?, 'queued', ?, ?, ?)",
                (job_type, pair_id, json.dumps(input_data or {}), now, now),
            )
            job_id = cur.lastrowid
        return self.get_job(job_id)

    def get_job(self, job_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            return _decode(row) if row else None

    def list_jobs(self, pair_id: int | None = None, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            if pair_id is None:
                rows = conn.execute(
                    "SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,))
            else:
                rows = conn.execute(
                    "SELECT * FROM jobs WHERE pair_id = ? ORDER BY id DESC LIMIT ?",
                    (pair_id, limit))
            return [_decode(r) for r in rows]

    def claim_queued_job(self) -> dict | None:
        """Atomically move the oldest queued job to running, or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM jobs WHERE status = 'queued' ORDER BY id LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE jobs SET status = 'running', updated_at = ? WHERE id = ? AND status = 'queued'",
                (time.time(), row["id"]),
            )
            if conn.execute("SELECT changes()").fetchone()[0] != 1:
                return None
            return _decode(row)

    def finish_job(self, job_id: int, output: dict | None, error: str | None) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE jobs SET status = ?, output = ?, error = ?, updated_at = ? WHERE id = ?",
                ("failed" if error else "done",
                 json.dumps(output) if output is not None else None,
                 error, time.time(), job_id),
            )

    # -- events -----------------------------------------------------------
    def log_event(self, kind: str, message: str, pair_id=None, server_id=None,
                  data: dict | None = None) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO events (created_at, kind, pair_id, server_id, message, data)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (time.time(), kind, pair_id, server_id, message,
                 json.dumps(data or {})),
            )

    def list_events(self, limit: int = 100) -> list[dict]:
        with self._connect() as conn:
            return [_decode(r) for r in conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]

    # -- metrics (Phase 3.5: real numbers for the rich dashboard) ---------
    def add_server_metric(self, server_id: int, data: dict,
                          created_at: float | None = None) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO server_metrics (server_id, created_at, load1,"
                " mem_used_pct, disk_used_pct, uptime_seconds)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (server_id, created_at or time.time(), data.get("load1"),
                 data.get("mem_used_pct"), data.get("disk_used_pct"),
                 data.get("uptime_seconds")))

    def list_server_metrics(self, server_id: int, limit: int = 120) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT created_at, load1, mem_used_pct, disk_used_pct,"
                " uptime_seconds FROM server_metrics WHERE server_id = ?"
                " ORDER BY id DESC LIMIT ?", (server_id, limit))
            points = [dict(r) for r in rows]
            points.reverse()
            return points

    def add_pair_metric(self, pair_id: int, data: dict,
                        created_at: float | None = None) -> None:
        now = created_at or time.time()
        rx_kbps = tx_kbps = None
        with self._connect() as conn:
            prev = conn.execute(
                "SELECT created_at, rx_bytes, tx_bytes FROM pair_metrics"
                " WHERE pair_id = ? AND rx_bytes IS NOT NULL"
                " ORDER BY id DESC LIMIT 1", (pair_id,)).fetchone()
            if prev and data.get("rx_bytes") is not None and prev["rx_bytes"] is not None:
                dt = now - prev["created_at"]
                if dt > 0:
                    rx_kbps = max(0.0, (data["rx_bytes"] - prev["rx_bytes"]) * 8 / dt / 1000)
                    tx_kbps = max(0.0, (data["tx_bytes"] - prev["tx_bytes"]) * 8 / dt / 1000)
            conn.execute(
                "INSERT INTO pair_metrics (pair_id, created_at, latency_ms,"
                " rx_bytes, tx_bytes, rx_kbps, tx_kbps)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (pair_id, now, data.get("latency_ms"), data.get("rx_bytes"),
                 data.get("tx_bytes"), rx_kbps, tx_kbps))

    def list_pair_metrics(self, pair_id: int, limit: int = 180) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT created_at, latency_ms, rx_bytes, tx_bytes, rx_kbps, tx_kbps"
                " FROM pair_metrics WHERE pair_id = ? ORDER BY id DESC LIMIT ?",
                (pair_id, limit))
            points = [dict(r) for r in rows]
            points.reverse()
            return points
