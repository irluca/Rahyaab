#!/usr/bin/env python3
"""SQLite Persistence Engine for Tunnel Studio Pro v2.0.
Provides durable storage for pairs, benchmarks, and immutable audit logs.
STRICT PRIVACY POLICY: Never writes passwords, private keys, or tokens to SQLite database.
Sensitive authentication data is held strictly in volatile process memory for active sessions.
"""
import os
import re
import sqlite3
import time
import json
from contextlib import contextmanager

# Host *addresses* are not credentials, but they are operational data about live servers, and
# SSH TOFU pinning plus audit lines write them here on the very first connection
# (mock_ssh.TOFUHostKeyPolicy). Inside the repo tree they become reachable by every search,
# index and report of a normal working session - which is how the previous servers' addresses
# ended up quoted in review documents. A live run therefore points the database outside the
# repository; unset keeps the historical in-repo location, which is what the tests assume.
DB_PATH = os.environ.get("BEST_TUNNEL_DB_PATH") or os.path.join(os.path.dirname(__file__), "best_tunnel.db")

# The newest migration this file implements. Tests that mean "the database reached the current schema"
# read this constant instead of a literal, because a pinned number has to be edited to stay true and so
# stops being a control: when v9 landed, two unrelated persistence tests failed on `== 8` - the migrations
# they were checking had run correctly. Bump it in the same change as the migration it names; test_93
# fails if the two drift apart in either direction.
SCHEMA_VERSION = 14

# A failed remote command is recorded as an execution error, and the runner's error text starts with
# the hostname it was talking to ("Remote command failed (exit 1) on 203.0.113.20: systemctl ...").
# Row 1 of the live test database carried exactly that, with the live server's routable address, in
# both `dq_reasons` and `ladder_error` - so a report generated from SQLite would leak the address the
# same way the previous servers' addresses reached review documents. Loopback and the private ranges
# are kept: they describe the bench topology (the GRE underlay) and identify nothing outside it.
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Kept as written, because these identify no host and some of them are functional text that a
# reader or a diff has to be able to act on:
#   0.0.0.0            the wildcard bind. Recorded in bind fields and in Go's own error text
#                      ("listen tcp 0.0.0.0:8897: bind: address already in use"); replacing it with
#                      [addr] turns an actionable "this port is taken" line into an unusable one,
#                      which is how #28 was found while scrubbing the live database.
#   127.0.0.0/8        loopback (also matches the older 127. rule below)
#   10/8, 192.168/16, 172.16/12   RFC 1918 - the GRE underlay and docker0
#   169.254/16         link-local: the host's own address on its own LAN, and DHCP-failure text
#   224-239            multicast group ranges
#   255.255.255.255    broadcast
# No routable public address can start with any of these, so this stays a fail-closed *default*:
# anything unrecognised is still masked.
KEEP_ADDR_RE = re.compile(
    r"^(?:"
    r"0\.0\.0\.0"
    r"|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\."
    r"|169\.254\."
    r"|2(?:2[4-9]|3\d)\."
    r"|255\.255\.255\.255"
    r")")

# IPv6 was not masked at all until this round measured the cost: a live `ss -tunap` census on Foreign
# printed its rows in bracket form, `IPV4_RE` passed `[2a01:…::1]` through untouched, and twenty-one
# copies of that host's own routable v6 address landed in an artifact inside the repository. A host with
# a public v4 nearly always has a public v6, so the same rule has to cover both.
#
# Matched on the text, not with `ipaddress`, and scoped to global unicast (2000::/3 - a first hextet
# beginning 2 or 3), which is what leaves an identity:
#   ::1, [::]:443, fe80::/10 link-local, fc00::/7 ULA, ff00::/8 multicast and the `::ffff:<v4>` mapped form
#   all start with something else and stay as written, because they are functional text in bind lines, unit
#   files and `ip -6 route` rows. `ipaddress.is_global` answers True for `ff00::`, so that property is not
#   what this scope means - measured while writing the scrub that found this round's leak.
# The first hextet has to be exactly four hex digits, and that costs nothing: a group written with fewer
# digits is below 0x1000, so it cannot fall inside 2000::/3 at all - `2::1` is not a missed global unicast
# address, it is a different block. What the four-digit rule buys is that `23:59:01` - a timestamp in a log
# line - does not look like an address, and masking clock text in a diagnostic would cost more than any
# shorthand form is worth. Over-masking a MAC address (`2a:01:…`) and a block name written as a prefix are
# the accepted directions of the same trade: a masked MAC or prefix name costs nothing, an unmasked address
# breaks the invariant.
#
# Up to seven further groups, because a fully written address has eight hextets: the scrub that found this
# rule's first gap left one row unmasked in an artifact precisely because the bound was six.
GLOBAL_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])"
    r"[23][0-9A-Fa-f]{3}(?::[0-9A-Fa-f]{0,4}){2,7}"
    r"(?::(?:\d{1,3}\.){3}\d{1,3})?"
    r"(?![0-9A-Fa-f:.])")


def repo_root() -> str:
    """The working tree this code lives in: orchestrator/ plus the installers beside it."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def db_is_inside_repo() -> bool:
    """True when the resolved database sits anywhere in this repository's working tree.

    A live session writes the hosts it touches into that file: SSH TOFU pins the hostname verbatim
    (mock_ssh.py:315) and the audit log records the connection. BEST_TUNNEL_DB_PATH is how a live run
    points those writes outside the repository, and until now the rule was only a comment - one
    command that forgot it pinned two live servers into orchestrator/best_tunnel.db.

    The predicate covers the repository root, not just orchestrator/. A live run created
    `UsersDELL.best_tunnellive.db` in the root after an unquoted Windows path lost its backslashes;
    the file was empty, but a gate scoped to orchestrator/ would have called it safe, and `*.db` in
    .gitignore is concealment, not containment - the file was still one `git add -A` from a commit.
    """
    root = os.path.abspath(repo_root())
    target = os.path.abspath(DB_PATH)
    return os.path.normcase(target).startswith(os.path.normcase(root) + os.sep)

def mask_addresses(value):
    """Replace routable IPv4 and global IPv6 literals with [addr] anywhere they appear in persisted text."""
    if isinstance(value, dict):
        return {k: mask_addresses(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [mask_addresses(v) for v in value]
    if isinstance(value, str):
        # v6 first. The claim that the order decides whether an embedded IPv4 leaks was measured and is
        # wrong - `2001:db8::192.0.2.1` is masked in either order, because after the v4 tail becomes
        # `[addr]` the v6 pattern still matches the `2001:db8::` prefix. What the order buys is legibility:
        # one `[addr]` for the literal rather than `[addr][addr]`. Recorded in
        # scratch/seal_mask6_062.out, where that case is the one the seal refuses to score as a catch.
        return IPV4_RE.sub(lambda m: m.group(0) if KEEP_ADDR_RE.match(m.group(0)) else "[addr]",
                           GLOBAL_IPV6_RE.sub("[addr]", value))
    return value

@contextmanager
def db_session():
    # The live database lives outside the repo (db_is_inside_repo), under the operator's
    # ~/.best_tunnel directory - which a fresh machine may not have yet. sqlite refuses a
    # path whose directory is missing with an opaque "unable to open database file", so the
    # directory is created here, at the one place every caller passes through, instead of
    # depending on each launcher remembering to create it first (F2).
    parent = os.path.dirname(os.path.abspath(DB_PATH))
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def get_column_names(conn: sqlite3.Connection, table_name: str) -> set[str]:
    """Returns set of column names for a given table."""
    cur = conn.execute(f"PRAGMA table_info({table_name});")
    return {row[1] for row in cur.fetchall()}

def get_schema_version() -> int:
    """Returns current active schema version."""
    with db_session() as conn:
        try:
            cur = conn.execute("SELECT MAX(version) FROM schema_version;")
            row = cur.fetchone()
            return int(row[0]) if (row and row[0] is not None) else 0
        except sqlite3.OperationalError:
            return 0

def init_db():
    """Initializes tables, indices, and applies sequential schema migrations (R-54 / Notice 1)."""
    with db_session() as conn:
        # Step 1: Base schema_version table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at REAL NOT NULL,
            description TEXT NOT NULL
        );
        """)

        # Fetch currently applied migrations
        cur = conn.execute("SELECT version FROM schema_version;")
        applied_versions = {row[0] for row in cur.fetchall()}
        now = time.time()

        # Migration 1: Base core tables
        if 1 not in applied_versions:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS pairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                iran_host TEXT NOT NULL,
                iran_port INTEGER DEFAULT 22,
                foreign_host TEXT NOT NULL,
                foreign_port INTEGER DEFAULT 22,
                frontend_port INTEGER DEFAULT 443,
                status TEXT DEFAULT 'NEW',
                active_tunnel TEXT DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS benchmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pair_id INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                latency_ms REAL DEFAULT 0.0,
                jitter_ms REAL DEFAULT 0.0,
                bulk_step INTEGER DEFAULT 0,
                loss_pct REAL DEFAULT 0.0,
                score REAL DEFAULT 0.0,
                disqualified INTEGER DEFAULT 0,
                details_json TEXT DEFAULT '{}',
                created_at REAL NOT NULL,
                FOREIGN KEY(pair_id) REFERENCES pairs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pair_id INTEGER,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT DEFAULT '',
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS host_keys (
                hostname TEXT NOT NULL,
                port INTEGER NOT NULL,
                key_type TEXT NOT NULL,
                key_base64 TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (hostname, port)
            );

            CREATE INDEX IF NOT EXISTS idx_benchmarks_pair ON benchmarks(pair_id, created_at);
            """)
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) VALUES (1, ?, ?)",
                         (now, "Initial core tables and indices"))

        # Migration 2: Add throughput_mbps column to benchmarks
        if 2 not in applied_versions:
            cols = get_column_names(conn, "benchmarks")
            if "throughput_mbps" not in cols:
                conn.execute("ALTER TABLE benchmarks ADD COLUMN throughput_mbps REAL DEFAULT 0.0;")
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) VALUES (2, ?, ?)",
                         (now, "Add throughput_mbps to benchmarks"))

        # Migration 3: Add base_rtt_ms column to pairs
        if 3 not in applied_versions:
            cols = get_column_names(conn, "pairs")
            if "base_rtt_ms" not in cols:
                conn.execute("ALTER TABLE pairs ADD COLUMN base_rtt_ms REAL DEFAULT 0.0;")
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) VALUES (3, ?, ?)",
                         (now, "Add base_rtt_ms to pairs"))

        # Migration 4: Add run_id column to benchmarks and create run_id index
        if 4 not in applied_versions:
            cols = get_column_names(conn, "benchmarks")
            if "run_id" not in cols:
                conn.execute("ALTER TABLE benchmarks ADD COLUMN run_id TEXT DEFAULT '';")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_benchmarks_run_id ON benchmarks(run_id);")
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) VALUES (4, ?, ?)",
                         (now, "Add run_id to benchmarks with index"))

        # Migration 5: persist the tunnel dial address per side.
        #
        # `dial_host` separates the address SSH is managed at from the address the overlay dials, and
        # until now it only existed in the volatile auth cache (dashboard.AUTH_CACHE, TTL-bounded and
        # cleared by /api/purge_auth). A pair whose underlay was supplied once therefore lost it on
        # restart, and every transport went back to dialing the public address - on infrastructure that
        # drops direct TCP between the two hosts, that is an unreachable peer, and it also silently
        # disarms the carrier gate in engine.carrier_camouflage_block, which reads the same field.
        # Defaults are empty so existing rows keep their previous single-address behaviour.
        if 5 not in applied_versions:
            cols = get_column_names(conn, "pairs")
            for col in ("iran_dial_host", "foreign_dial_host"):
                if col not in cols:
                    conn.execute(f"ALTER TABLE pairs ADD COLUMN {col} TEXT DEFAULT '';")
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) "
                         "VALUES (5, ?, ?)", (now, "Add iran_dial_host/foreign_dial_host to pairs"))

        # Migration 6: give every benchmark row its two iperf3 legs separately.
        #
        # The table held one throughput number whose meaning had quietly become "the average of two
        # opposite directions", so the live GRE row - 1124.19 Mbps one way, 6.50 the other - was kept as
        # 565.35 and nothing on disk let any later reader discover that no direction carried 565. The legs
        # become columns now (NULL = that direction was never measured, which is not the same fact as 0.0 =
        # it completed and carried nothing), and capacity_basis records which rule produced the scalar -
        # because rows written before this change carry an average under the same column name, and a
        # report must be able to tell the two apart.
        if 6 not in applied_versions:
            cols = get_column_names(conn, "benchmarks")
            backfilled = 0
            if cols:
                for col, ddl in (("throughput_up_mbps", "REAL"), ("throughput_down_mbps", "REAL"),
                                 ("capacity_basis", "TEXT DEFAULT ''")):
                    if col not in cols:
                        conn.execute(f"ALTER TABLE benchmarks ADD COLUMN {col} {ddl};")
                for row_id, blob in conn.execute(
                        "SELECT id, details_json FROM benchmarks "
                        "WHERE throughput_up_mbps IS NULL AND throughput_down_mbps IS NULL").fetchall():
                    legs = _legs_from_details(blob)
                    if not legs:
                        continue
                    conn.execute("UPDATE benchmarks SET throughput_up_mbps = ?, "
                                 "throughput_down_mbps = ?, capacity_basis = ? WHERE id = ?",
                                 (legs["upload"], legs["download"], legs["basis"], row_id))
                    backfilled += 1
            # An empty `cols` means the database never had a benchmarks table at all - a partially
            # restored legacy file that marks migrations 1-4 applied. Creating that table is migration
            # 1's job, so this one records itself and moves on rather than crashing the whole init.
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) "
                         "VALUES (6, ?, ?)",
                         (now, "Add per-leg throughput columns to benchmarks "
                               f"(backfilled {backfilled} legacy row(s))"))

        # Migration 7: remember what authenticates each deployed tunnel's destination.
        #
        # Every TLS transport in this product trusts a certificate *this* code generated, and until now
        # nothing recorded which one. Without a record, "the same tunnel restarted" and "the same port,
        # somebody else's key" are the same observation, and an operator comparing two deployments has
        # nothing to compare against. `record_destination_pin` below explains why this table is an audit
        # trail rather than a refusal: the anchors are regenerated inside every plan, so a mismatch is
        # what a redeploy looks like. The durable destination pin this product already has is the SSH
        # host key (`host_keys` above); this table makes the inner, per-tunnel identity visible so the
        # day those anchors persist, the refusal has something honest to fire on.
        #
        # One row per (pair, protocol): the pin is a property of the deployed tunnel, not of a benchmark
        # instance, so ephemeral bench plans never write here. `changed_at` stays 0 for a pin that never
        # moved, which is how a reader distinguishes a long-stable tunnel from one that was just recorded.
        if 7 not in applied_versions:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS destination_pins (
                    pair_id INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    mechanism TEXT DEFAULT '',
                    fingerprint TEXT DEFAULT '',
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    changed_at REAL NOT NULL DEFAULT 0,
                    PRIMARY KEY (pair_id, protocol)
                );
            """)
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) "
                         "VALUES (7, ?, ?)", (now, "Add destination_pins (per-pair destination identity)"))

        # Migration 8: declare which carrier the pair's overlay actually arrives in.
        #
        # Until now "has a dial_host" and "is wrapped in cleartext proto 47" were one fact, because GRE
        # was the only generator able to build an underlay, and engine.carrier_camouflage_block refused
        # REALITY on that inference. The ESP carrier splits them: an ESP underlay also sets dial_host, and
        # refusing a transport whose camouflage an *encrypted* envelope protects would be exactly
        # backwards - so the carrier has to be stated, not inferred. It is declared rather than derived
        # from `active_tunnel` because the carrier outlives the tunnel riding on it: REALITY deployed over
        # ESP sets active_tunnel to its own protocol while the envelope stays ESP.
        #
        # Empty means "not declared", and protocols.carrier_kind then falls back to the old fail-closed
        # inference, so every pre-v8 pair keeps the refusal it has today. Default is empty for the same
        # reason migration 5 chose empty: existing rows must keep their previous behaviour untouched.
        if 8 not in applied_versions:
            cols = get_column_names(conn, "pairs")
            if "underlay_carrier" not in cols:
                conn.execute("ALTER TABLE pairs ADD COLUMN underlay_carrier TEXT DEFAULT '';")
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) "
                         "VALUES (8, ?, ?)", (now, "Add underlay_carrier declaration to pairs"))

        # Migration 9: capacity telemetry for the hosts themselves (round 063, ruling 1).
        #
        # Every number this database already held was a verdict about a *tunnel* - latency, loss,
        # capacity, score. Nothing recorded anything about the two machines carrying it, so the two
        # questions that come before a capacity question were unanswerable from history: is the Foreign
        # host's episodic burst (#64) visible in its socket or memory counters, and what was this host
        # doing at the moment a tunnel failed? A benchmark row says a transport scored 47; it cannot say
        # whether the host had 40 MB free.
        #
        # Every measured column is nullable, and that is the design rather than an omission. engine's
        # sampler reports a per-source state precisely because "the read did not happen" and "the reading
        # is zero" are different facts with different fixes - storing 0 for an unread /proc would make a
        # host whose counters could not be read look idle, and an operator would act on that. A row of
        # NULLs with `source_states` naming the fault is the honest shape; a row of zeros is a lie.
        #
        # `uptime_sec` and `boot_id` travel together for ruling 3's reboot pentest: seconds-since-boot
        # alone is also what a clock reset looks like, while boot_id is regenerated by the kernel on each
        # real boot. The pair is what lets a report say "this host booted" instead of "this host's
        # counter got smaller".
        if 9 not in applied_versions:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS host_resources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pair_id INTEGER NOT NULL,
                    host_role TEXT NOT NULL,
                    collected_at REAL NOT NULL,
                    load1 REAL, load5 REAL, load15 REAL,
                    ncpu INTEGER,
                    load1_per_core_pct REAL,
                    mem_total_kb INTEGER, mem_available_kb INTEGER, mem_used_pct REAL,
                    swap_total_kb INTEGER, swap_free_kb INTEGER,
                    disk_total_kb INTEGER, disk_used_kb INTEGER, disk_avail_kb INTEGER,
                    disk_used_pct REAL,
                    disk_fullest_mount TEXT DEFAULT '',
                    disk_fullest_used_pct REAL,
                    uptime_sec REAL,
                    boot_id TEXT DEFAULT '',
                    source_states TEXT DEFAULT ''
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_host_resources_pair "
                         "ON host_resources (pair_id, host_role, collected_at DESC);")
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) "
                         "VALUES (9, ?, ?)",
                         (now, "Add host_resources (per-host CPU/memory/disk/uptime telemetry)"))

        # Migration 10: the columns that turn a capacity row into an attributable one (round 063, #70).
        #
        # Open finding #64 was that Foreign's episodic connection bursts could only be explained by an
        # operator SSHing in during one and reading `TcpExt:TCPTimeouts` by hand. Report062's rows could
        # answer "was the CPU busy" but not "how many handshakes failed in that minute", because nothing
        # in the sample carried the kernel's own counters. `tcp_counters` holds the monotonic values
        # (engine differences consecutive rows to get the events), `socket_states` holds the per-state
        # gauge (the only thing that still shows a SYN-RECV backlog after the burst has passed), and
        # `reachable` marks a row taken from a host that answered nothing.
        #
        # Three columns are nullable because "this host was never asked" and "this host answered zero"
        # are different facts - the same rule migration 9 wrote for load and memory, and the reason
        # `estab_conns` is INTEGER rather than REAL DEFAULT 0. `reachable` is deliberately not given a
        # DEFAULT 1: pre-migration rows come back NULL, and NULL reads as "not recorded", which is true of
        # them. A default of 1 would have made every historical row silently claim a host that answered.
        if 10 not in applied_versions:
            cols = get_column_names(conn, "host_resources")
            if cols:
                for col, ddl in (("tcp_counters", "TEXT DEFAULT ''"),
                                 ("socket_states", "TEXT DEFAULT ''"),
                                 ("estab_conns", "INTEGER"), ("reachable", "INTEGER")):
                    if col not in cols:
                        conn.execute(f"ALTER TABLE host_resources ADD COLUMN {col} {ddl};")
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) "
                         "VALUES (10, ?, ?)",
                         (now, "Add TCP counters, socket-state gauges and a reachable flag "
                               "to host_resources (connection-burst attribution, #70)"))

        # Migration 11: the delivery end of a tunnel becomes a recorded fact (round 064, #63).
        #
        # `backend_port` is the port on the peer host the transport delivers into. It is NULL, not 0 and
        # not the frontend, when nobody declared one: "not declared" and "declared as port 0" are different
        # statements, and a default that silently means "same as the frontend" would make every historical
        # pair look declared after the operator edited one.
        #
        # `backend_state` is the product's own read of that port, written by the deploy and by a re-check,
        # never inferred at render time. It is what `failover_monitor` needs in order to stop treating an
        # absent application behind a working transport as a transport outage - the misread that cost pair 2
        # a scored 100% loss and would otherwise cost it a switchover.
        #
        # `backend_checked_at` is the freshness stamp. A state read at 03:00 is not a state at 15:00, and a
        # dashboard that renders one without saying when it was measured has turned a measurement into a
        # claim.
        if 11 not in applied_versions:
            cols = get_column_names(conn, "pairs")
            for col, ddl in (("backend_port", "INTEGER"),
                             ("backend_state", "TEXT DEFAULT ''"),
                             ("backend_checked_at", "REAL DEFAULT 0")):
                if col not in cols:
                    conn.execute(f"ALTER TABLE pairs ADD COLUMN {col} {ddl};")
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) "
                         "VALUES (11, ?, ?)",
                         (now, "Add backend delivery port, verified state and check timestamp to pairs "
                               "(the backend contract, #63)"))

        # Migration 12: per-pair auto mode (Phase 3 completion, 2026-10-24).
        #
        # `mode` is the pair's steering: 'manual' (the operator chooses every
        # transport) or 'auto' (the pair follows the best median benchmark
        # evidence, with a margin, and remembers it). `auto_protocol` is the
        # last winner the evidence produced - written by refresh_auto_choice
        # after a sweep or a heal, read by the monitor's drift note and the
        # dashboard's pair card. Both default to the manual behaviour, so
        # every existing pair keeps exactly the steering it had.
        if 12 not in applied_versions:
            cols = get_column_names(conn, "pairs")
            for col, ddl in (("mode", "TEXT DEFAULT 'manual'"),
                             ("auto_protocol", "TEXT DEFAULT ''")):
                if col not in cols:
                    conn.execute(f"ALTER TABLE pairs ADD COLUMN {col} {ddl};")
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) "
                         "VALUES (12, ?, ?)",
                         (now, "Add per-pair auto mode and remembered auto winner (Phase 3)"))

        # Migration 13: failover quarantine (Phase 3 completion, 2026-10-24).
        #
        # A switchover used to delete the old transport's units and configs
        # in the same breath as stopping it, so a successor that failed its
        # smoke check left the pair with nothing to fall back to except a
        # full redeploy. The quarantine table keeps one stopped-but-intact
        # transport per pair: its units and the teardown commands that
        # would finally remove it, plus a grace expiry. One row per pair
        # (PRIMARY KEY pair_id) because a pair has exactly one live
        # transport and therefore exactly one thing to fall back to.
        if 13 not in applied_versions:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantines (
                    pair_id INTEGER PRIMARY KEY,
                    protocol TEXT NOT NULL,
                    iran_units TEXT DEFAULT '[]',
                    foreign_units TEXT DEFAULT '[]',
                    teardown_iran TEXT DEFAULT '[]',
                    teardown_foreign TEXT DEFAULT '[]',
                    quarantined_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
            """)
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) "
                         "VALUES (13, ?, ?)",
                         (now, "Add failover quarantine table (Phase 3)"))

        # Migration 14: persistent health history (Phase 6 Health Center).
        #
        # Until now the monitor's verdicts lived only in the audit log's
        # transition lines and in process memory: the dashboard could show
        # the current state but not "how often was this pair down this
        # week". health_history records one row per sampled pass - verdict,
        # loss, latency, saturation, auto drift - capped per pair so a
        # 60 s monitor cannot grow it without bound. Rows are never
        # edited: history is append-only, like the audit log.
        if 14 not in applied_versions:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS health_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pair_id INTEGER NOT NULL,
                    verdict TEXT NOT NULL,
                    protocol TEXT DEFAULT '',
                    loss_pct REAL DEFAULT 0.0,
                    latency_ms REAL DEFAULT 0.0,
                    saturation_pct REAL,
                    saturation_state TEXT DEFAULT '',
                    auto_drift TEXT DEFAULT '',
                    recorded_at REAL NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_health_history_pair "
                         "ON health_history(pair_id, recorded_at DESC);")
            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at, description) "
                         "VALUES (14, ?, ?)",
                         (now, "Add persistent health history (Phase 6 Health Center)"))


def _legs_from_details(blob):
    """The two iperf3 legs recorded inside a stored row's details_json, or None when it carries none.

    Used to backfill the leg columns on rows written before they existed. Those rows store unmeasured
    directions as 0.0, which is why the reconstructed basis is labelled legacy instead of pretending the
    old scalar meant what the new one does.
    """
    try:
        ip = json.loads(blob or "{}").get("iperf3") or {}
    except Exception:
        return None
    if not isinstance(ip, dict) or not ip.get("available"):
        return None
    up = down = None
    for leg in (ip.get("legs") or []):
        if isinstance(leg, dict) and leg.get("measured"):
            if leg.get("direction") == "upload":
                up = float(leg.get("mbps") or 0.0)
            elif leg.get("direction") == "download":
                down = float(leg.get("mbps") or 0.0)
    if up is not None or down is not None:
        # A row that stored legs but no `capacity_basis` was written between the legs becoming visible
        # and the scalar becoming the weakest direction, and that intermediate scalar was the average.
        # Inheriting "weakest_measured_leg" for it would relabel history as something it never was.
        return {"upload": up, "download": down,
                "basis": ip.get("capacity_basis") or
                         ("legacy-average" if (up and down) else "legacy-single-leg")}
    up = float(ip.get("upload_mbps") or 0.0) or None
    down = float(ip.get("download_mbps") or 0.0) or None
    if up is None and down is None:
        return None
    return {"upload": up, "download": down,
            "basis": "legacy-average" if (up and down) else "legacy-single-leg"}


def update_pair_base_rtt(pair_id: int, base_rtt_ms: float, is_fallback: bool = False):
    """Updates direct base RTT baseline for a pair with audit distinction between measured and fallback."""
    now = time.time()
    with db_session() as conn:
        conn.execute("UPDATE pairs SET base_rtt_ms = ?, updated_at = ? WHERE id = ?", (base_rtt_ms, now, pair_id))
    tag = "BASE_RTT_FALLBACK" if is_fallback else "BASE_RTT_MEASURED"
    log_audit(pair_id, "BASE_RTT", tag, f"Direct base RTT ({tag}): {base_rtt_ms:.2f}ms")

def add_pair(name: str, iran_host: str, foreign_host: str, frontend_port: int = 443,
             iran_port: int = 22, foreign_port: int = 22,
             iran_dial_host: str = "", foreign_dial_host: str = "") -> int:
    """Adds a pair to SQLite. Passwords/keys are NEVER saved here."""
    now = time.time()
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO pairs (name, iran_host, iran_port, foreign_host, foreign_port, frontend_port,
                               status, iran_dial_host, foreign_dial_host, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'NEW', ?, ?, ?, ?)
        """, (name, iran_host, iran_port, foreign_host, foreign_port, frontend_port,
              iran_dial_host or "", foreign_dial_host or "", now, now))
        pair_id = cur.lastrowid
    log_audit(pair_id, "ADD_PAIR", "SUCCESS", f"Added pair {name} ({iran_host} -> {foreign_host} :{frontend_port})")
    return pair_id

def set_pair_dial_hosts(pair_id: int, iran_dial_host: str = "", foreign_dial_host: str = "") -> bool:
    """Records the underlay address each side's tunnels dial, separately from the SSH address.

    The audit line names the pair, not the addresses: a dial host is topology, and the report is read
    by people who do not need it. `get_pairs()` does not mask, because pairs.iran_host is a functional
    identity column the engine has to dial.
    """
    now = time.time()
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE pairs SET iran_dial_host = ?, foreign_dial_host = ?, updated_at = ? "
                    "WHERE id = ?", (iran_dial_host or "", foreign_dial_host or "", now, pair_id))
        updated = cur.rowcount > 0
    if updated:
        log_audit(pair_id, "DIAL_HOSTS", "SUCCESS",
                  f"Dial addresses set: iran={'yes' if iran_dial_host else 'unset'}, "
                  f"foreign={'yes' if foreign_dial_host else 'unset'}")
    return updated

# The carrier declarations this product knows how to build. A value outside this set is a programming
# error at the call site, not data: silently storing "ess" would leave protocols.carrier_kind falling
# back to the fail-closed GRE inference, and the pair would then be refused for a reason nobody wrote.
UNDERLAY_CARRIERS = ("", "gre", "esp")

def set_pair_underlay(pair_id: int, underlay_carrier: str,
                      iran_dial_host: str | None = None,
                      foreign_dial_host: str | None = None) -> bool:
    """Declare which carrier the pair's overlay arrives in, and the addresses that carrier provides.

    This is the write side of the carrier gate. `carrier_kind` can no longer infer the envelope from the
    presence of a dial_host, because the ESP carrier sets one too and an encrypted envelope is the answer
    to the very objection the gate raises, so the thing that *makes* the carrier true - deploying ESP -
    has to record it. Declaring the carrier without the addresses is allowed (a GRE underlay built by an
    operator keeps its manually supplied dial hosts); `None` means "leave stored", `""` means "clear".

    The audit row names the carrier and never the addresses: a dial host is topology, and the log is read
    by people who do not need it - which is also why `log_audit` masks addresses in the first place.
    """
    carrier = (underlay_carrier or "").strip().lower()
    if carrier not in UNDERLAY_CARRIERS:
        raise ValueError(f"unknown underlay carrier {underlay_carrier!r}, "
                         f"expected one of {UNDERLAY_CARRIERS}")
    now = time.time()
    sets, args = ["underlay_carrier = ?", "updated_at = ?"], [carrier, now]
    for col, value in (("iran_dial_host", iran_dial_host), ("foreign_dial_host", foreign_dial_host)):
        if value is not None:
            sets.append(f"{col} = ?")
            args.append(value)
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute(f"UPDATE pairs SET {', '.join(sets)} WHERE id = ?", (*args, pair_id))
        updated = cur.rowcount > 0
    if updated:
        detail = f"underlay carrier set to '{carrier or 'none'}'"
        if iran_dial_host is not None or foreign_dial_host is not None:
            detail += (f", dial addresses {'cleared' if not (iran_dial_host or foreign_dial_host) else 'supplied'}")
        log_audit(pair_id, "UNDERLAY", "SUCCESS", detail)
    return updated

# The only verdicts the backend contract is allowed to store. Anything else is a programming error at the
# call site, and storing it would let the monitor read a state it has no branch for - which is how
# `carrier_kind`'s silent GRE fallback produced a refusal nobody had written.
BACKEND_STATES = ("answered", "no-backend", "unreadable", "not-applicable")

def set_pair_backend(pair_id: int, backend_port=None, backend_state=None) -> bool:
    """Record the delivery end of this pair's tunnel and what the product's own read found there.

    `backend_port=None` means leave the stored declaration alone; `0` means clear it (NULL is written).
    The two have to be different words: a form that submits an empty field to remove a declaration would
    otherwise be a no-op that answers `ok`, and the pair would go on delivering to a port its operator
    believes was removed - with the monitor reading that stale port as if it were the intent.

    `backend_state=None` means leave the recorded witness alone; `""` means un-record it back to the
    column's never-read default. A changed declaration needs the un-record: the previous read answered a
    *different* port, and leaving it stamped on the row lets the card describe the new intent with evidence
    about the old one.
    """
    if backend_state is not None and backend_state != "" and backend_state not in BACKEND_STATES:
        raise ValueError(f"unknown backend state {backend_state!r}, expected one of {BACKEND_STATES}")
    port = None
    if backend_port is not None:
        port = int(backend_port)
        if port != 0 and not (1 <= port <= 65535):
            raise ValueError(f"backend port {port} out of range")
    now = time.time()
    sets, args = ["updated_at = ?"], [now]
    if backend_port is not None:
        sets.append("backend_port = ?")
        # 0 is the clear token, and NULL is what "not declared" is stored as - never a literal 0, which
        # every downstream reader would have to re-interpret as "not a port" instead of "port zero".
        args.append(None if port == 0 else port)
    if backend_state is not None:
        sets.extend(["backend_state = ?", "backend_checked_at = ?"])
        args.extend([backend_state, now])
    with db_session() as conn:
        cur = conn.cursor()
        row = cur.execute("SELECT backend_port, backend_state FROM pairs WHERE id = ?",
                          (pair_id,)).fetchone()
        if row is None:
            return False
        previous = row["backend_state"] if row["backend_state"] is not None else ""
        previous_port = row["backend_port"]
        cur.execute(f"UPDATE pairs SET {', '.join(sets)} WHERE id = ?", (*args, pair_id))
        updated = cur.rowcount > 0
    if not updated:
        return False
    # Both transitions are logged, and only transitions. A monitor that re-reads a port every cycle would
    # otherwise write one line per cycle for a fact that has not moved, and the log - which is how an
    # operator reconstructs an incident - would bury the change inside its own confirmations. Ports are
    # logged because they are the identity of the delivery; addresses are not logged anywhere, and none
    # appear here.
    if backend_state is not None and backend_state != previous:
        log_audit(pair_id, "BACKEND", "SUCCESS",
                  f"Backend delivery state: {'not recorded' if not previous else previous} -> "
                  f"{'not recorded' if not backend_state else backend_state}"
                  + (f" (port {port})" if port else ""))
    if backend_port is not None and port != previous_port:
        log_audit(pair_id, "BACKEND", "SUCCESS",
                  f"Backend delivery port declaration: "
                  f"{'not declared' if not previous_port else previous_port} -> "
                  f"{'cleared' if not port else port}")
    return True


def set_pair_frontend_port(pair_id: int, port: int) -> bool:
    """Move a pair's frontend port in the healer database.

    This row is what the monitor reads on every pass (see
    healer.build_pair_source), so it is the live truth for the
    frontend port: a port change that only rewrote the healer
    config would be ignored until a reinstall, because seed_db
    never overwrites an existing row's frontend_port. The hub pair
    row is updated separately by the hub job, from the same change.
    """
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError(f"frontend port {port} out of range")
    with db_session() as conn:
        cur = conn.cursor()
        row = cur.execute("SELECT frontend_port FROM pairs WHERE id = ?",
                          (pair_id,)).fetchone()
        if row is None:
            return False
        previous = row["frontend_port"]
        cur.execute("UPDATE pairs SET frontend_port = ?, updated_at = ? "
                    "WHERE id = ?", (port, time.time(), pair_id))
        updated = cur.rowcount > 0
    if updated and port != previous:
        log_audit(pair_id, "FRONTEND", "SUCCESS",
                  f"Frontend port: {previous} -> {port}")
    return updated


def get_pairs() -> list[dict]:
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM pairs ORDER BY id DESC")
        return [dict(row) for row in cur.fetchall()]

def delete_pair(pair_id: int) -> bool:
    """Deletes a pair along with its associated benchmarks while preserving immutable audit logs."""
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM benchmarks WHERE pair_id = ?", (pair_id,))
        cur.execute("UPDATE audit_logs SET pair_id = NULL WHERE pair_id = ?", (pair_id,))
        cur.execute("DELETE FROM pairs WHERE id = ?", (pair_id,))
        deleted = cur.rowcount > 0
    if deleted:
        log_audit(None, "DELETE_PAIR", "SUCCESS", f"Deleted pair {pair_id} (audit trail preserved)")
    return deleted

def get_pair(pair_id: int) -> dict | None:
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM pairs WHERE id = ?", (pair_id,))
        row = cur.fetchone()
        return dict(row) if row else None

def set_pair_mode(pair_id: int, mode: str) -> bool:
    """Sets a pair's steering mode: 'manual' (default) or 'auto'.

    Anything else is refused rather than stored: a typo in a steering
    column would silently pin a pair to manual while the dashboard shows
    auto, and the monitor reads this column every pass.
    """
    mode = (mode or "").strip().lower()
    if mode not in ("manual", "auto"):
        return False
    now = time.time()
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE pairs SET mode = ?, updated_at = ? WHERE id = ?",
                    (mode, now, pair_id))
        return cur.rowcount > 0


def record_quarantine(pair_id: int, protocol: str, plan: dict, grace_sec: float) -> dict:
    """Stops a transport's removal at the stop step: units and configs stay
    on disk, the teardown commands that would delete them are stored, and
    the record expires after grace_sec. Replaces any older quarantine for
    the pair - a pair has one fallback, and it is the transport that was
    just replaced, not the one before it.
    """
    now = time.time()
    rec = {"pair_id": pair_id, "protocol": protocol,
           "iran_units": list(plan.get("iran_units", [])),
           "foreign_units": list(plan.get("foreign_units", [])),
           "teardown_iran": list(plan.get("teardown_iran", [])),
           "teardown_foreign": list(plan.get("teardown_foreign", [])),
           "quarantined_at": now, "expires_at": now + grace_sec}
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO quarantines
            (pair_id, protocol, iran_units, foreign_units, teardown_iran,
             teardown_foreign, quarantined_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (pair_id, protocol, json.dumps(rec["iran_units"]),
              json.dumps(rec["foreign_units"]), json.dumps(rec["teardown_iran"]),
              json.dumps(rec["teardown_foreign"]), rec["quarantined_at"],
              rec["expires_at"]))
    return rec


def get_quarantine(pair_id: int) -> dict | None:
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM quarantines WHERE pair_id = ?", (pair_id,))
        row = cur.fetchone()
        if not row:
            return None
        rec = dict(row)
        for key in ("iran_units", "foreign_units", "teardown_iran", "teardown_foreign"):
            try:
                rec[key] = json.loads(rec[key] or "[]")
            except (TypeError, ValueError):
                rec[key] = []
        return rec


def clear_quarantine(pair_id: int) -> bool:
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM quarantines WHERE pair_id = ?", (pair_id,))
        return cur.rowcount > 0


HEALTH_HISTORY_KEEP_ROWS = 10000

#: Verdicts that count as "up" / "down" for uptime math. Everything else
#: (skips, errors, ambiguous shapes, missing backends) is not a sample of
#: the tunnel at all, so it enters neither side of the fraction.
HEALTH_UP_VERDICTS = ("HEALTHY", "DEGRADED")
HEALTH_DOWN_VERDICTS = ("DOWN_PENDING", "HEAL_CONFIRMED", "OBSERVE_DOWN",
                        "HEAL_DEFERRED", "FAILOVER_EXECUTED", "FAILOVER_ATTEMPTED")


def record_health_sample(pair_id: int, verdict: str, protocol: str = "",
                         loss_pct: float = 0.0, latency_ms: float = 0.0,
                         saturation_pct=None, saturation_state: str = "",
                         auto_drift: str = "") -> int:
    """Appends one monitor verdict to the pair's health history."""
    now = time.time()
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO health_history
            (pair_id, verdict, protocol, loss_pct, latency_ms,
             saturation_pct, saturation_state, auto_drift, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (pair_id, verdict, protocol or "", float(loss_pct or 0.0),
              float(latency_ms or 0.0),
              None if saturation_pct is None else float(saturation_pct),
              saturation_state or "", auto_drift or "", now))
        sample_id = cur.lastrowid
        cur.execute("""
            DELETE FROM health_history WHERE pair_id = ?
              AND id NOT IN (SELECT id FROM health_history
                              WHERE pair_id = ? ORDER BY id DESC LIMIT ?)
        """, (pair_id, pair_id, int(HEALTH_HISTORY_KEEP_ROWS)))
    return sample_id


def get_health_history(pair_id: int, limit: int = 200) -> list[dict]:
    """Newest-first health samples for a pair (capped for the dashboard)."""
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM health_history WHERE pair_id = ? "
                    "ORDER BY id DESC LIMIT ?", (pair_id, int(limit)))
        return [dict(row) for row in cur.fetchall()]


def health_uptime_summary(pair_id: int, since_ts: float = 0.0) -> dict:
    """Uptime math over a pair's samples since a timestamp.

    uptime_pct counts only samples that actually judged the tunnel; a
    pass that never sampled (lock busy, no credentials) is not an
    uptime vote in either direction. outages counts transitions into
    the down set, so one long outage is one outage, not sixty.
    """
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT verdict FROM health_history WHERE pair_id = ? "
                    "AND recorded_at >= ? ORDER BY id ASC",
                    (pair_id, float(since_ts)))
        verdicts = [r[0] for r in cur.fetchall()]
    up = sum(1 for v in verdicts if v in HEALTH_UP_VERDICTS)
    down = sum(1 for v in verdicts if v in HEALTH_DOWN_VERDICTS)
    outages = 0
    prev_down = False
    for v in verdicts:
        is_down = v in HEALTH_DOWN_VERDICTS
        if is_down and not prev_down:
            outages += 1
        prev_down = is_down
    judged = up + down
    return {"samples": len(verdicts), "up": up, "down": down,
            "outages": outages,
            "uptime_pct": (round(100.0 * up / judged, 2) if judged else None)}


def count_failovers(pair_id: int) -> int:
    """Successful switchovers for a pair: the reconnect counter the
    live cards show. Audit rows are the record - a switchover that was
    never logged never happened, as far as the card is concerned.
    """
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM audit_logs WHERE pair_id = ? "
                    "AND action = 'FAILOVER' AND status = 'SUCCESS'", (pair_id,))
        row = cur.fetchone()
        return int(row[0]) if row else 0


def set_pair_auto_protocol(pair_id: int, protocol: str) -> bool:
    """Records the last transport the auto evidence chose for this pair."""
    now = time.time()
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE pairs SET auto_protocol = ?, updated_at = ? WHERE id = ?",
                    ((protocol or "").strip(), now, pair_id))
        return cur.rowcount > 0


def update_pair_status(pair_id: int, status: str, active_tunnel: str | None = None):
    """Records a state transition. Omit active_tunnel to keep the recorded tunnel.

    A caller that only changes the lifecycle status must not be able to erase which tunnel is
    running: with a blank default, every TESTING / TESTED / DEPLOY_FAILED write cleared the column
    while the tunnel itself kept serving, and its readers then fall back to a guessed protocol
    (dashboard.py 'or \"GRE\"') or to the empty string itself (failover.py uses .get with a default,
    which does not fire on an existing empty value).
    """
    now = time.time()
    with db_session() as conn:
        cur = conn.cursor()
        if active_tunnel is None:
            cur.execute("UPDATE pairs SET status = ?, updated_at = ? WHERE id = ?",
                        (status, now, pair_id))
        else:
            cur.execute("UPDATE pairs SET status = ?, active_tunnel = ?, updated_at = ? WHERE id = ?",
                        (status, active_tunnel, now, pair_id))
    kept = (" (active=%s)" % active_tunnel) if active_tunnel is not None else " (active unchanged)"
    log_audit(pair_id, "UPDATE_STATUS", "SUCCESS", f"Status updated to {status}{kept}")

# Retention for the two tables that grew without bound (F5). host_resources already had
# this shape - a cap enforced at insert time, oldest evicted first - and these follow it.
# Benchmarks are kept per (pair, protocol) because that is the history the failover
# ranking reads (a median over one protocol's runs): 200 rows is 200 full sweeps of that
# protocol on that pair. The audit log is a single trail across pairs, so its cap is
# global; 10,000 rows at one row per operator action or benchmark is a long service
# history, and what falls off the end is the oldest routine entries, never the newest.
BENCHMARK_KEEP_ROWS = 200
AUDIT_LOG_KEEP_ROWS = 10000


def record_benchmark(pair_id: int, protocol: str, metrics: dict, run_id: str = "") -> int:
    now = time.time()
    throughput = float(metrics.get("throughput_mbps", 0.0))
    run_identifier = run_id or metrics.get("run_id", "")
    ip = metrics.get("iperf3") or {}
    up_mbps = down_mbps = None
    basis = ""
    if isinstance(ip, dict):
        basis = ip.get("capacity_basis", "") or ""
        for leg in (ip.get("legs") or []):
            if isinstance(leg, dict) and leg.get("measured"):
                if leg.get("direction") == "upload":
                    up_mbps = float(leg.get("mbps") or 0.0)
                elif leg.get("direction") == "download":
                    down_mbps = float(leg.get("mbps") or 0.0)
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO benchmarks (pair_id, protocol, latency_ms, jitter_ms, bulk_step, throughput_mbps, throughput_up_mbps, throughput_down_mbps, capacity_basis, loss_pct, score, disqualified, details_json, run_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pair_id,
            protocol,
            metrics.get("breakdown", {}).get("lat_avg", 0.0),
            metrics.get("breakdown", {}).get("jitter_ms", metrics.get("jitter_ms", 0.0)),
            metrics.get("bulk_step", 0),
            throughput,
            up_mbps,
            down_mbps,
            basis,
            metrics.get("breakdown", {}).get("loss_pct", 0.0),
            metrics.get("score", 0.0),
            1 if metrics.get("disqualified") else 0,
            json.dumps(mask_addresses(metrics)),
            run_identifier,
            now
        ))
        bench_id = cur.lastrowid
        cur.execute("""
            DELETE FROM benchmarks
             WHERE pair_id = ? AND protocol = ?
               AND id NOT IN (SELECT id FROM benchmarks
                               WHERE pair_id = ? AND protocol = ?
                               ORDER BY id DESC LIMIT ?)
        """, (pair_id, protocol, pair_id, protocol, int(BENCHMARK_KEEP_ROWS)))
    log_audit(pair_id, "BENCHMARK", "SUCCESS" if not metrics.get("disqualified") else "DISQUALIFIED",
              f"Benchmarked {protocol}: score={metrics.get('score')} dq={metrics.get('disqualified')} run_id={run_identifier}")
    return bench_id

def get_benchmarks(pair_id: int, limit: int | None = None) -> list[dict]:
    """One pair's benchmark rows, newest first. `limit=None` keeps the historical
    all-rows behaviour the failover ranking relies on; bounded callers (the dashboard's
    polling GET) pass a limit so a long-lived pair cannot make every page load ship its
    entire history (F5)."""
    with db_session() as conn:
        cur = conn.cursor()
        if limit is None:
            cur.execute("SELECT * FROM benchmarks WHERE pair_id = ? ORDER BY id DESC",
                        (pair_id,))
        else:
            cur.execute("SELECT * FROM benchmarks WHERE pair_id = ? ORDER BY id DESC LIMIT ?",
                        (pair_id, int(limit)))
        return [dict(row) for row in cur.fetchall()]

def log_audit(pair_id: int | None, action: str, status: str, details: str = ""):
    now = time.time()
    # Same rule as record_benchmark: an audit line quoting a failed remote command starts with the
    # host it addressed, and the audit log is the table a report is written from.
    details = mask_addresses(details)
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO audit_logs (pair_id, action, status, details, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (pair_id, action, status, details, now))
        cur.execute("""
            DELETE FROM audit_logs
             WHERE id NOT IN (SELECT id FROM audit_logs ORDER BY id DESC LIMIT ?)
        """, (int(AUDIT_LOG_KEEP_ROWS),))

def get_audit_logs(limit: int = 100) -> list[dict]:
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]


# The actions that mean "something this pair cares about went wrong, or was accepted". A routine
# SUCCESS row is not an event: `ADD_PAIR` and `BENCHMARK` fire on every ordinary minute of a healthy
# deployment, and a panel that lists them says nothing. Derived as a named constant rather than
# inlined in the query so the dashboard and the test can both assert against the same list the read
# uses - the set is the product's claim about what is worth showing, and it should not live twice.
# `FAILOVER_BLOCKED` is in it because the anchor refusal (failover.py:474) is recorded under that
# action, and a switchover that stopped because the destination key moved is exactly the event an
# operator has to be able to see without re-triggering it.
SECURITY_EVENT_ACTIONS = ("DESTINATION_PIN_ROTATED", "UNPIN_DESTINATION", "FAILOVER_BLOCKED",
                          "FAILOVER_ABORTED", "DEPLOY_ROLLBACK")


def recent_security_events(pair_id: int, limit: int = 8) -> list[dict]:
    """The newest audit rows for one pair that are not routine. Newest first.

    This is the reader the audit table never had: `get_audit_logs` above was called by tests and by
    nothing in the product, so a rotation warning written by `record_destination_pin` could only be
    found by opening SQLite by hand. `log_audit` masked addresses on the way in, and the details are
    still masked here on the way out - the second mask is not redundant, it is what lets the dashboard
    serve a row written by an older build.
    """
    placeholders = ", ".join("?" for _ in SECURITY_EVENT_ACTIONS)
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT id, pair_id, action, status, details, created_at FROM audit_logs "
                    f"WHERE pair_id = ? AND action IN ({placeholders}) "
                    f"ORDER BY id DESC LIMIT ?",
                    (pair_id, *SECURITY_EVENT_ACTIONS, limit))
        return [{**dict(row), "details": mask_addresses(row["details"])} for row in cur.fetchall()]

def recent_failover_events(pair_id: int, window_seconds: float) -> list[float]:
    """Timestamps (oldest first) of completed switchovers for the pair.

    The anti-flapping breaker kept its history inside a FailoverManager instance, so anything that
    built a new manager - a process restart, or the dashboard constructing one per request - reset the
    window to empty and a crash-looping pair could be torn down and rebuilt without limit. The audit
    log is the durable record, so the breaker reads from it.

    Only a switchover that actually moved the tunnel counts: FAILOVER/SUCCESS. A failed attempt is
    logged for visibility (FAILOVER_FAILED) but never counts, because it ends on the protocol it
    started on - on the overlay-on-carrier path it never touches the live tunnel at all, and on the
    teardown path the old transport is restored from quarantine. Counting failures let one harmless
    failure block the next attempt for 180 s (2026-10-27: a smoke-failed wstunnel attempt refused
    the backhaul attempt that followed it, while the pair sat healthy on chisel). A blocked or
    plan-refused call likewise never moved the tunnel. Returns timestamps only, never the detail
    text, so no address can travel through this path.
    """
    cutoff = time.time() - float(window_seconds)
    with db_session() as conn:
        cur = conn.execute("""
            SELECT created_at FROM audit_logs
             WHERE pair_id = ?
               AND action = 'FAILOVER' AND status = 'SUCCESS'
               AND created_at >= ?
             ORDER BY created_at ASC
        """, (pair_id, cutoff))
        return [float(row[0]) for row in cur.fetchall()]

def pin_host_key(hostname: str, port: int, key_type: str, key_base64: str):
    now = time.time()
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO host_keys (hostname, port, key_type, key_base64, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(hostname, port) DO UPDATE SET
                key_type = excluded.key_type,
                key_base64 = excluded.key_base64,
                created_at = excluded.created_at
        """, (hostname, port, key_type, key_base64, now))

def get_pinned_host_key(hostname: str, port: int) -> dict | None:
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM host_keys WHERE hostname = ? AND port = ?", (hostname, port))
        row = cur.fetchone()
        return dict(row) if row else None

def unpin_host_key(hostname: str, port: int) -> bool:
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM host_keys WHERE hostname = ? AND port = ?", (hostname, port))
        deleted = cur.rowcount > 0
    if deleted:
        log_audit(None, "UNPIN_HOST_KEY", "SUCCESS", f"Unpinned host key for {hostname}:{port}")
    return deleted

def get_destination_pin(pair_id: int, protocol: str) -> dict | None:
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM destination_pins WHERE pair_id = ? AND protocol = ?",
                    (pair_id, protocol))
        row = cur.fetchone()
        return dict(row) if row else None

def record_destination_pin(pair_id: int, protocol: str, mechanism: str, fingerprint: str) -> dict:
    """Record the destination identity a deployment rests on, and report whether it moved.

    `new` is trust-on-first-use. `match` is the boring case: the same material as last time. `rotated`
    means the pair's tunnel now authenticates against different keying material than the row held, and
    the row is updated to it - because on this product a rotation is what a redeploy *does*, not an
    attack signature: the generators create the anchor inside every plan (protocols.py:90/:141/:1051),
    so an unchanged pair re-keys on every deploy (measured: scratch/probe_anchor_rotation.py, all six
    pinned transports rotate). A control that refused on mismatch would reject every legitimate
    redeploy, so this records and leaves an audit trail instead. The refusal belongs to the case with
    no legitimate reading: `engine.destination_pin_block` rejecting a plan whose client carries no
    anchor at all.

    The old value is never dropped silently: it goes into the audit row with the timestamp of the pin
    it replaces, so a replacement that was *not* a redeploy is still reconstructible from the log.
    `unpin_destination` below is the operator's way to declare a rotation expected.
    """
    now = time.time()
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT fingerprint, mechanism, first_seen FROM destination_pins "
                    "WHERE pair_id = ? AND protocol = ?", (pair_id, protocol))
        row = cur.fetchone()
        if row is None:
            cur.execute("INSERT INTO destination_pins (pair_id, protocol, mechanism, fingerprint, "
                        "first_seen, last_seen, changed_at) VALUES (?, ?, ?, ?, ?, ?, 0)",
                        (pair_id, protocol, mechanism, fingerprint, now, now))
            return {"status": "new", "previous": "", "current": fingerprint}
        previous = row[0] or ""
        if previous == fingerprint:
            cur.execute("UPDATE destination_pins SET last_seen = ?, mechanism = ? "
                        "WHERE pair_id = ? AND protocol = ?", (now, mechanism, pair_id, protocol))
            return {"status": "match", "previous": previous, "current": fingerprint}
        first_seen = row[2] if row and row[2] else 0.0
        cur.execute("UPDATE destination_pins SET mechanism = ?, fingerprint = ?, last_seen = ?, "
                    "changed_at = ? WHERE pair_id = ? AND protocol = ?",
                    (mechanism, fingerprint, now, now, pair_id, protocol))
    seen_when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(first_seen))
    log_audit(pair_id, "DESTINATION_PIN_ROTATED", "WARNING",
              f"{protocol}: the anchor this pair's client trusts moved. Recorded pin was {previous} "
              f"(first seen {seen_when}); this deployment presents {fingerprint}. Expected from a "
              f"redeploy, which regenerates the anchor; if no deploy happened between the two "
              f"timestamps, the material was replaced out of band and the tunnel must be re-keyed.")
    return {"status": "rotated", "previous": previous, "current": fingerprint}

def unpin_destination(pair_id: int, protocol: str) -> bool:
    """Drop a recorded pin so the next deployment re-learns it - the sanctioned way to accept a
    certificate rotation, mirroring `unpin_host_key` above. The audit row that warns about a rotation
    points here, but no dashboard endpoint calls it yet: today the remedy is a storage-layer call,
    unlike host keys, which have `/api/unpin_host_key`."""
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM destination_pins WHERE pair_id = ? AND protocol = ?",
                    (pair_id, protocol))
        deleted = cur.rowcount > 0
    if deleted:
        log_audit(pair_id, "UNPIN_DESTINATION", "SUCCESS",
                  f"Forgot the recorded destination pin for {protocol}; the next deploy re-learns it")
    return deleted


# --- Host resource telemetry (round 063, ruling 1) ---------------------------------------------

# Written in this order; the placeholder count below is derived from it so the two cannot disagree.
_HOST_RESOURCE_COLUMNS = (
    "pair_id", "host_role", "collected_at", "load1", "load5", "load15", "ncpu",
    "load1_per_core_pct", "mem_total_kb", "mem_available_kb", "mem_used_pct",
    "swap_total_kb", "swap_free_kb", "disk_total_kb", "disk_used_kb", "disk_avail_kb",
    "disk_used_pct", "disk_fullest_mount", "disk_fullest_used_pct", "uptime_sec", "boot_id",
    "source_states", "tcp_counters", "socket_states", "estab_conns", "reachable",
)
# How much history a host keeps. Continuous sampling is the point of the panel, and an unbounded table is
# its cost: at one row per host per 30 s this is ~24 h of coverage per host, which is enough to answer
# "what was this machine doing when the tunnel failed" without growing forever. Rows are dropped oldest
# first, per pair *and* per host, so a busy pair cannot evict a quiet one.
HOST_RESOURCE_KEEP_ROWS = 4000


def record_host_resources(row: dict) -> int:
    """Persist one host's sample. Returns the new row id.

    NULL is written deliberately wherever `row` carries None. A capacity panel that renders 0 for an
    unreadable sensor is worse than no panel: 0% memory used and "we could not read memory" look the same
    to whoever is deciding whether the host is idle, and this project has already paid for that collapse
    once in a throughput score (report054: a leg that never reported had to be kept distinct from a leg
    that reported zero).

    No audit row is written here. The audit log is an operator-action trail, and a monitor sampling every
    30 seconds would bury every other entry in it within a day; the telemetry has its own table.
    """
    now = row.get("collected_at") or time.time()
    states = row.get("source_states")
    if not isinstance(states, str):
        states = json.dumps(mask_addresses(states or {}), sort_keys=True)
    # The two counter blobs are serialised the same way `source_states` is, and masked in the same call:
    # `/proc/net/tcp` is read for its *state histogram*, so by the time a value reaches here the addresses
    # are already gone - but the mask is what makes that a property of the storage layer rather than a
    # property of one parser, and a parser is exactly the thing that changes.
    #
    # A JSON `null` inside `tcp_counters` is kept as one. It means "this counter was looked for and this
    # kernel did not have it", and flattening it to 0 is the collapse the whole nullable-column design
    # exists to prevent: a zero AttemptFails and an unread AttemptFails would otherwise go on to author
    # different burst verdicts from the same evidence.
    def json_col(key):
        val = row.get(key)
        if isinstance(val, str):
            return val
        return json.dumps(mask_addresses(val or {}), sort_keys=True)

    values = [row.get("pair_id"), str(row.get("host_role") or ""), now,
              row.get("load1"), row.get("load5"), row.get("load15"), row.get("ncpu"),
              row.get("load1_per_core_pct"), row.get("mem_total_kb"), row.get("mem_available_kb"),
              row.get("mem_used_pct"), row.get("swap_total_kb"), row.get("swap_free_kb"),
              row.get("disk_total_kb"), row.get("disk_used_kb"), row.get("disk_avail_kb"),
              row.get("disk_used_pct"), mask_addresses(str(row.get("disk_fullest_mount") or "")),
              row.get("disk_fullest_used_pct"), row.get("uptime_sec"),
              str(row.get("boot_id") or ""), states,
              json_col("tcp_counters"), json_col("socket_states"), row.get("estab_conns"),
              row.get("reachable")]
    marks = ", ".join("?" for _ in _HOST_RESOURCE_COLUMNS)
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute(f"INSERT INTO host_resources ({', '.join(_HOST_RESOURCE_COLUMNS)}) "
                    f"VALUES ({marks})", values)
        new_id = cur.lastrowid
        cur.execute("""
            DELETE FROM host_resources
             WHERE pair_id = ? AND host_role = ?
               AND id NOT IN (SELECT id FROM host_resources
                               WHERE pair_id = ? AND host_role = ?
                               ORDER BY collected_at DESC LIMIT ?)
        """, (row.get("pair_id"), str(row.get("host_role") or ""), row.get("pair_id"),
              str(row.get("host_role") or ""), int(HOST_RESOURCE_KEEP_ROWS)))
    return int(new_id or 0)


def latest_host_resources(pair_id: int) -> dict:
    """The newest sample per host role for one pair: {"iran": row|None, "foreign": row|None}.

    A host that has never been sampled reads None rather than a row of zeros, so the dashboard can say
    "not sampled yet" instead of rendering an idle machine.
    """
    out = {"iran": None, "foreign": None}
    with db_session() as conn:
        for role in out:
            cur = conn.execute("SELECT * FROM host_resources WHERE pair_id = ? AND host_role = ? "
                               "ORDER BY collected_at DESC, id DESC LIMIT 1", (pair_id, role))
            row = cur.fetchone()
            if row:
                out[role] = dict(row)
    return out


def host_resource_history(pair_id: int, host_role: str = "", limit: int = 120) -> list[dict]:
    """Recent samples, newest first, for one host or for both when `host_role` is empty.

    Returns rows as stored, including NULLs and `source_states`, so a caller can distinguish a dip in
    load from a gap in sampling.
    """
    with db_session() as conn:
        if host_role:
            cur = conn.execute("SELECT * FROM host_resources WHERE pair_id = ? AND host_role = ? "
                               "ORDER BY collected_at DESC, id DESC LIMIT ?",
                               (pair_id, host_role, int(limit)))
        else:
            cur = conn.execute("SELECT * FROM host_resources WHERE pair_id = ? "
                               "ORDER BY collected_at DESC, id DESC LIMIT ?", (pair_id, int(limit)))
        return [dict(row) for row in cur.fetchall()]


init_db()
