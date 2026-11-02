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
from collections.abc import Iterator
from contextlib import contextmanager
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
    spoof_status TEXT NOT NULL DEFAULT 'unknown',
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
-- Quick-test results: one row per finished quick test. Quick scores
-- live here, never in candidate_scores: a quick test measures with a
-- shorter stability window and no iperf3 legs, so its numbers are
-- comparable among themselves but not with a full sweep's.
CREATE TABLE IF NOT EXISTS quick_tests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pair_id INTEGER NOT NULL REFERENCES pairs(id),
    created_at REAL NOT NULL,
    winner TEXT,
    results TEXT NOT NULL
);
-- Cumulative traffic per pair. Interface counters restart at zero
-- whenever the carrier interface is recreated, so the collector folds
-- each sample's delta into these totals instead of trusting the raw
-- counter: a reset adds the new counter's bytes on top of the total
-- folded so far, and the total never goes backwards or resets.
CREATE TABLE IF NOT EXISTS pair_traffic_totals (
    pair_id INTEGER PRIMARY KEY REFERENCES pairs(id),
    rx_total INTEGER NOT NULL DEFAULT 0,
    tx_total INTEGER NOT NULL DEFAULT 0,
    last_rx INTEGER,
    last_tx INTEGER,
    updated_at REAL NOT NULL
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
            # CREATE TABLE IF NOT EXISTS never adds a column to a hub.db
            # created before the column existed; migrate in place.
            cols = [r[1] for r in conn.execute("PRAGMA table_info(pairs)")]
            if "spoof_status" not in cols:
                conn.execute("ALTER TABLE pairs ADD COLUMN "
                             "spoof_status TEXT NOT NULL DEFAULT 'unknown'")
            conn.execute("CREATE TABLE IF NOT EXISTS settings ("
                         "key TEXT PRIMARY KEY, value TEXT NOT NULL)")

    def get_setting(self, key: str, default: str = "") -> str:
        """One hub setting by key; missing keys return the default."""
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?",
                               (key,)).fetchone()
        return row[0] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO settings (key, value) "
                         "VALUES (?, ?)", (key, value))

    def get_panel_path(self) -> str:
        """The dashboard's private base path, or "" for the root.

        A fresh hub gets a random path (panel-<hex>) seeded by the
        installer; an older hub keeps the root until its operator
        rotates it. The API always stays at /api, only the served
        pages move under the path, so probing / finds nothing.
        """
        return self.get_setting("panel_path", "") or ""

    def set_panel_path(self, value: str) -> None:
        import re
        if value != "" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
            raise ValueError("panel path must be empty or a plain path segment")
        self.set_setting("panel_path", value)

    def get_hub_identity(self) -> dict:
        """This hub's multi-master identity, seeded by the installer.

        Unset (a hub installed before multi-master, or any hub whose
        installer predates it) means the legacy identity: no tag and
        inner base 10, which reproduces today's names and inners exactly.
        A hub installed after multi-master carries a short random tag and
        its own inner base (20, 30, ...), so its pairs never collide
        with another hub's on a shared node.
        """
        try:
            base = int(self.get_setting("inner_base", "10") or 10)
        except ValueError:
            base = 10
        return {"hub_tag": self.get_setting("hub_tag", "") or "",
                "inner_base": base}

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """One connection per operation, always closed on exit.

        The old version returned a bare connection and every caller used
        `with conn:` — but sqlite3's `__exit__` only commits or rolls
        back; it never closes. A fraction of those connections landed in
        reference cycles, so only the cyclic GC reclaimed them, and under
        dashboard polling the leak outran collection: the hub hit its
        1024-fd soft limit, accept() failed with EMFILE, the serve loop
        spun, and the panel wedged (bug 13, 2026-11-01). This wrapper
        keeps the old commit-on-success / rollback-on-error semantics
        and adds the close that was missing.
        """
        conn = sqlite3.connect(self.db_path, timeout=60.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        # A hub write (metrics, jobs) can briefly hold the lock while the
        # dashboard deletes a pair; without a busy timeout that delete
        # fails instead of waiting a moment (seen 2026-11-01).
        conn.execute("PRAGMA busy_timeout = 60000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

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

    def update_server_host(self, server_id: int, host: str, port: int = 22) -> None:
        """Re-join case: a rebuilt node keeps its name but gets a new address."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE servers SET host = ?, port = ? WHERE id = ?",
                (host, port, server_id),
            )

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

    def update_pair_spoof_status(self, pair_id: int, status: str) -> None:
        """Record a pair's spoof probe verdict: 'unknown', 'open', or
        'closed'. 'open' means the forged-source probe arrived on both
        sides; 'closed' means at least one side dropped it; 'unknown'
        means the probe itself did not complete. The dashboard reads
        this column, and the sweep reads it to decide whether the
        spoof ladder runs at all."""
        if status not in ("unknown", "open", "closed"):
            raise ValueError("invalid spoof_status: %r" % (status,))
        with self._connect() as conn:
            conn.execute(
                "UPDATE pairs SET spoof_status = ? WHERE id = ?",
                (status, pair_id),
            )

    def update_pair_protocol(self, pair_id: int, protocol: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE pairs SET current_protocol = ? WHERE id = ?",
                (protocol, pair_id),
            )

    def update_pair_frontend_port(self, pair_id: int, port: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE pairs SET frontend_port = ? WHERE id = ?",
                (int(port), pair_id),
            )

    def update_pair_measurement(self, pair_id: int, candidate_scores: dict,
                                current_protocol: str | None = None) -> None:
        """Wizard step: record measured scores (never invented ones).

        Replaces the whole candidate_scores map with the measured
        values; a protocol never measured is absent, not zero.
        """
        with self._connect() as conn:
            if current_protocol is not None:
                conn.execute(
                    "UPDATE pairs SET candidate_scores = ?, current_protocol = ?"
                    " WHERE id = ?",
                    (json.dumps(candidate_scores), current_protocol, pair_id),
                )
            else:
                conn.execute(
                    "UPDATE pairs SET candidate_scores = ? WHERE id = ?",
                    (json.dumps(candidate_scores), pair_id),
                )

    def update_pair_scores(self, pair_id: int, new_scores: dict) -> dict:
        """Auto-sweep step: merge newly measured scores into the pair row.

        Only qualified scores (score > 0) are merged in; a disqualified
        protocol never erases a previous score, and current_protocol is
        never touched — the sweep measures, it does not switch. Returns
        the merged map.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT candidate_scores FROM pairs WHERE id = ?",
                (pair_id,),
            ).fetchone()
            current = json.loads(row["candidate_scores"]) if row else {}
            merged = dict(current)
            for proto, score in (new_scores or {}).items():
                if score and score > 0:
                    merged[proto] = score
            conn.execute(
                "UPDATE pairs SET candidate_scores = ? WHERE id = ?",
                (json.dumps(merged), pair_id),
            )
            return merged

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

    def has_queued_job(self, job_type: str, pair_id: int) -> bool:
        """True while a job of this type for this pair still waits."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM jobs WHERE type = ? AND pair_id = ?"
                " AND status = 'queued'",
                (job_type, pair_id)).fetchone()
            return row[0] > 0

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

    def requeue_orphaned_jobs(self) -> list[int]:
        """Move jobs left 'running' by a dead worker back to 'queued'.

        A hub restart (or crash) mid-job orphans the claimed job: the
        worker only ever claims 'queued' jobs, so the orphan would sit
        'running' forever and the pair's setup would stall with a
        yellow, unmonitored dashboard. At worker start no worker is
        running yet, so any 'running' row is orphaned by definition
        and safe to re-queue; handlers tolerate a re-run (deploy
        rewrites the same tunnel, switch returns 'already' for the
        current protocol, sweep refuses a second concurrent scope).
        Returns the re-queued job ids.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id FROM jobs WHERE status = 'running' ORDER BY id"
            ).fetchall()
            ids = [r[0] for r in rows]
            if ids:
                conn.execute(
                    "UPDATE jobs SET status = 'queued', updated_at = ?"
                    " WHERE status = 'running'",
                    (time.time(),),
                )
            return ids

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
            # Fold this sample into the cumulative total. A counter that
            # moved forward adds its delta; a counter that went backwards
            # was recreated, so its new value counts on top of the total
            # folded so far instead of wiping it. The first sample only
            # anchors the counters: bytes counted before we started
            # watching are not ours to claim.
            rx, tx = data.get("rx_bytes"), data.get("tx_bytes")
            if rx is not None and tx is not None:
                row = conn.execute(
                    "SELECT rx_total, tx_total, last_rx, last_tx"
                    " FROM pair_traffic_totals WHERE pair_id = ?",
                    (pair_id,)).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO pair_traffic_totals"
                        " (pair_id, rx_total, tx_total, last_rx, last_tx, updated_at)"
                        " VALUES (?, 0, 0, ?, ?, ?)", (pair_id, rx, tx, now))
                else:
                    rx_add = rx - row["last_rx"] if rx >= row["last_rx"] else rx
                    tx_add = tx - row["last_tx"] if tx >= row["last_tx"] else tx
                    conn.execute(
                        "UPDATE pair_traffic_totals SET rx_total = rx_total + ?,"
                        " tx_total = tx_total + ?, last_rx = ?, last_tx = ?,"
                        " updated_at = ? WHERE pair_id = ?",
                        (max(0, rx_add), max(0, tx_add), rx, tx, now, pair_id))

    def save_quick_test(self, pair_id: int, winner: str | None,
                        results: list, created_at: float | None = None) -> dict:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO quick_tests (pair_id, created_at, winner, results)"
                " VALUES (?, ?, ?, ?)",
                (pair_id, created_at or time.time(), winner,
                 json.dumps(results)))
            row_id = cur.lastrowid
        return {"id": row_id, "pair_id": pair_id, "winner": winner,
                "results": results}

    def latest_quick_test(self, pair_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, pair_id, created_at, winner, results FROM quick_tests"
                " WHERE pair_id = ? ORDER BY id DESC LIMIT 1",
                (pair_id,)).fetchone()
        if row is None:
            return None
        out = dict(row)
        out["results"] = json.loads(out["results"])
        return out

    def get_pair_traffic_total(self, pair_id: int) -> dict:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT rx_total, tx_total FROM pair_traffic_totals"
                " WHERE pair_id = ?", (pair_id,)).fetchone()
        if row is None:
            return {"rx_total": 0, "tx_total": 0}
        return {"rx_total": row["rx_total"], "tx_total": row["tx_total"]}

    def list_pair_metrics(self, pair_id: int, limit: int = 180) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT created_at, latency_ms, rx_bytes, tx_bytes, rx_kbps, tx_kbps"
                " FROM pair_metrics WHERE pair_id = ? ORDER BY id DESC LIMIT ?",
                (pair_id, limit))
            points = [dict(r) for r in rows]
            points.reverse()
            return points
