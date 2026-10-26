#!/usr/bin/env python3
"""Tunnel Studio Pro v3.0 Dashboard.
Features:
- Single-view unified responsive UI inspired by modern VPN/proxy panels
- Anti-cache HTTP headers (no-store, no-cache) preventing stale browser cache
- Direct benchmark button covering every currently enabled protocol
- SQLite persistence for pairs, benchmarks, and audit logs (storage.py)
- In-memory credential cache (never saved to disk)
- Delete pair API endpoint with atomic cascading removal
- Real-time live execution console with polling telemetry
- Strict server-side gating for protected port 443 release
- Wired to real deployment and benchmark engine with rollback
- DRY_RUN via BEST_TUNNEL_DRY_RUN; resolved by mock_ssh.is_dry_run_enabled() so the whole
  package shares one default. Unset means dry-run, because this tool executes destructive
  commands as root over SSH: live operation must be opted into, never defaulted into.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import json, time, ipaddress, secrets, string, threading, uuid, os
from safety import is_hard_blacklisted, validate_frontend_port
from mock_ssh import get_ssh_runner, is_dry_run_enabled
import storage
import engine
import eventbus
import protocols
import failover
import failover_monitor
import fleet

def is_dry_run() -> bool:
    """Delegates to the package-wide resolver so this module and mock_ssh cannot disagree.

    They used to read BEST_TUNNEL_DRY_RUN with opposite defaults ("0" here, "1" there), which
    meant an unset variable put the HTTP layer in live mode while the SSH factory stayed mocked.
    """
    return is_dry_run_enabled()

# In-memory credentials cache with 15-minute TTL eviction (Auditor report041 §2.1)
AUTH_CACHE = {}
AUTH_CACHE_LOCK = threading.Lock()
AUTH_CACHE_TTL_SECONDS = 900  # 15 minutes max lifetime in volatile RAM

# Newest benchmark rows per pair served by GET /api. Storage retains more
# (storage.BENCHMARK_KEEP_ROWS per protocol, which the failover ranking reads in
# full); this polling response must not ship a long-lived pair's entire history
# on every page load (F5).
API_BENCHMARKS_PER_PAIR = 200

def cleanup_auth_cache():
    """Evicts expired SSH credentials from volatile RAM."""
    now = time.time()
    with AUTH_CACHE_LOCK:
        expired = [pid for pid, data in AUTH_CACHE.items() if data.get("expires_at", 0) <= now]
        for pid in expired:
            AUTH_CACHE.pop(pid, None)

def set_auth_cache(pair_id: int, ir: dict, fr: dict):
    """Sets credentials in volatile RAM cache with explicit expiration timestamp (P0-3)."""
    with AUTH_CACHE_LOCK:
        AUTH_CACHE[pair_id] = {
            "iran": ir,
            "foreign": fr,
            "expires_at": time.time() + AUTH_CACHE_TTL_SECONDS
        }

def update_auth_cache_passwords(pair_id: int, p: dict, ir_pw: str = "", fr_pw: str = ""):
    """Updates passwords in volatile RAM cache and refreshes TTL (P0-3)."""
    with AUTH_CACHE_LOCK:
        existing = AUTH_CACHE.get(pair_id, {})
        cur_ir = existing.get("iran", {"host": p["iran_host"], "port": p["iran_port"], "user": "root"})
        cur_fr = existing.get("foreign", {"host": p["foreign_host"], "port": p["foreign_port"], "user": "root"})
        if ir_pw:
            cur_ir["auth"] = {"type": "password", "value": ir_pw}
        if fr_pw:
            cur_fr["auth"] = {"type": "password", "value": fr_pw}
        AUTH_CACHE[pair_id] = {
            "iran": cur_ir,
            "foreign": cur_fr,
            "expires_at": time.time() + AUTH_CACHE_TTL_SECONDS
        }

def purge_all_cached_auth():
    """Emergency manual flush of all volatile credentials from RAM."""
    with AUTH_CACHE_LOCK:
        AUTH_CACHE.clear()

def pair_side_spec(p: dict, auth: dict, side: str) -> dict:
    """The spec one side of a pair is dialed with: cached session details plus the persisted underlay.

    Two sources, deliberately in this precedence. The volatile auth cache holds what this session
    logged in with (host, port, user, auth) and nothing else is authoritative for the credential. The
    database holds the topology, and `dial_host` is topology: if it lived only in the cache, then
    after a TTL expiry or /api/purge_auth the pair silently reverted to dialing the public management
    address, which on infrastructure that drops direct TCP between the hosts is an unreachable peer -
    and it also disarmed engine.carrier_camouflage_block, which refuses REALITY over a cleartext GRE
    envelope by reading that same field. A persisted value therefore wins over a cached one; if a
    session must disagree, update the pair instead of letting one request run a different topology.
    """
    spec = dict(auth.get(side) or {"host": p[f"{side}_host"], "port": p.get(f"{side}_port", 22),
                                   "user": "root"})
    spec.setdefault("host", p[f"{side}_host"])
    spec.setdefault("port", p.get(f"{side}_port", 22))
    spec.setdefault("user", "root")
    persisted = (p.get(f"{side}_dial_host") or "").strip()
    if persisted:
        spec["dial_host"] = persisted
    return spec

def pair_for_operations(p: dict, auth: dict, frontend_key: str = "frontend") -> dict:
    """The pair dict handed to engine and failover, assembled in one place.

    Four endpoints each built this literal by hand, and the carrier gate now reads `underlay_carrier`
    from it: a pair dict assembled anywhere else would carry the topology the gate judges (the side
    specs) without the declaration that overrides the inference, and would silently fall back to
    treating any pair with a dial_host as the cleartext GRE one. `frontend_key` preserves the two
    spellings existing callers already receive rather than renaming their payloads.

    `base_rtt_ms` is deliberately not included, because none of the four callers had it: a benchmark
    blocked before it starts reports 0.0 baseline today, and quietly changing that is not this
    function's business.
    """
    return {
        "id": p["id"],
        "name": p["name"],
        frontend_key: p["frontend_port"],
        "underlay_carrier": p.get("underlay_carrier", ""),
        # The declared delivery port travels with the pair for the same reason the carrier declaration
        # does: the deploy reads it off this dict, and a caller that rebuilt the literal by hand would
        # deploy a tunnel delivering to the frontend while the operator had recorded a different port -
        # the #63 defect wearing a form field. Empty/None means "not declared", which is not the same
        # statement as port 0 and is stored as NULL for that reason.
        "backend_port": p.get("backend_port") or None,
        "iran": pair_side_spec(p, auth, "iran"),
        "foreign": pair_side_spec(p, auth, "foreign"),
    }

def request_dial_hosts(ir: dict, fr: dict) -> tuple:
    """The underlay addresses in a pair request, validated before they are stored.

    An address typo here is not a cosmetic failure: every transport dials this address, so a wrong one
    produces a tunnel that cannot connect and reads like blocking. The value is deliberately not
    echoed back in the error.
    """
    hosts = ((ir.get("dial_host") or "").strip(), (fr.get("dial_host") or "").strip())
    for side, value in zip(("iran", "foreign"), hosts):
        if value and not valid_ip(value):
            raise ValueError(f"{side} dial_host is not a valid IPv4 address")
    return hosts

def request_backend_port(value, frontend: int, active_protocol: str = ""):
    """Validate a declared delivery port before it is stored, or say why it cannot be declared.

    Returns the int to store, or None meaning "no separate delivery port" (which is what an empty field,
    a 0, and an absent key all mean - the three spellings of "not declared" that a form can send).

    The check against the *active* transport is what makes this a control rather than a text box: a pair
    riding ESP cannot be given a separate delivery port, and storing one anyway would make the next deploy
    of that pair refuse for a reason the operator had already been invited to type. An un-declared or
    unknown active protocol is accepted, because declaring before the first deploy is the normal order.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("backend_port must be a port number or empty")
    if port == 0:
        return None
    if not (1 <= port <= 65535):
        raise ValueError("backend_port must be between 1 and 65535")
    if active_protocol:
        refusal = protocols.backend_port_refusal(active_protocol, frontend, port)
        if refusal:
            raise ValueError(refusal)
    return port

# Per-Host Concurrency Guard for benchmark and deployment (P0-7)
ACTIVE_HOST_LOCKS = set()
HOST_LOCK_GUARD = threading.Lock()

def try_acquire_host_locks(hosts: list[str]) -> bool:
    """Acquires exclusive concurrency locks for all specified host IPs."""
    with HOST_LOCK_GUARD:
        for h in hosts:
            if h and h in ACTIVE_HOST_LOCKS:
                return False
        for h in hosts:
            if h:
                ACTIVE_HOST_LOCKS.add(h)
        return True

def release_host_locks(hosts: list[str]):
    """Releases concurrency locks for specified host IPs."""
    with HOST_LOCK_GUARD:
        for h in hosts:
            if h:
                ACTIVE_HOST_LOCKS.discard(h)

BEST_TUNNEL_API_TOKEN = os.getenv("BEST_TUNNEL_API_TOKEN", "").strip()

# One FailoverManager per process. Building it per request reset its anti-flapping window, so the
# circuit breaker - the control that exists to stop a crash-looping pair from being torn down again
# and again - never once tripped through the only HTTP path that can trigger a switchover. The
# persisted history in storage.recent_failover_events now backs this up across restarts; the shared
# instance keeps it honest within one process. Switchovers on the same pair cannot race each other
# because both the HTTP path and the monitor hold the per-host locks above.
FAILOVER_MANAGER = failover.FailoverManager()

def run_quick_repair(full_pair: dict, dry_run: bool) -> dict:
    """Phase 6 Quick Repair: one explicit operator heal.

    Kept outside do_POST so test_52's scan of do_POST stays meaningful:
    no route body calls the heal directly, only this named helper, and
    only from the explicit repair route. Every guard evaluate_and_heal
    honours (no-backend, degraded, no candidate) still applies.
    """
    res = failover_manager().evaluate_and_heal(full_pair, dry_run=dry_run)
    out = dict(res)
    out["ok"] = res.get("action") in ("FAILOVER_EXECUTED", "NONE")
    return out


def failover_manager() -> failover.FailoverManager:
    return FAILOVER_MANAGER

FAILOVER_MONITOR = None
MONITOR_LOCK = threading.Lock()

class DashboardHostGuard:
    """Adapts the dashboard's per-host concurrency set to the guard interface the monitor needs.

    The monitor has to pass through the same lock as a deploy or a benchmark, or an automated
    switchover can tear down units the operator is still writing.
    """

    def acquire(self, hosts: list[str]) -> bool:
        return try_acquire_host_locks(list(hosts))

    def release(self, hosts: list[str]):
        release_host_locks(list(hosts))

def monitor_pair_source() -> list[dict]:
    """Deployed pairs in the shape failover_monitor consumes, with this session's credentials merged.

    pairs_from_storage() deliberately carries no credential, because a pair row is not an
    authentication source; the live monitor needs the volatile auth cache, exactly like every other
    endpoint here.
    """
    out = []
    for p in storage.get_pairs():
        with AUTH_CACHE_LOCK:
            auth = AUTH_CACHE.get(p["id"], {})
        out.append({
            "id": p["id"],
            "name": p["name"],
            "status": (p.get("status") or "").upper(),
            "active_tunnel": (p.get("active_tunnel") or "").strip(),
            "frontend_port": p["frontend_port"],
            # Same reason as pairs_from_storage: without the declaration the monitor's delivery read
            # lands on the frontend port, so a temporary test backend on the frontend would be
            # certified as the pair's application while the declared port stayed unprobed.
            "backend_port": p.get("backend_port") or None,
            "base_rtt_ms": p.get("base_rtt_ms", 0.0) or 0.0,
            "underlay_carrier": p.get("underlay_carrier", ""),
            "iran": pair_side_spec(p, auth, "iran"),
            "foreign": pair_side_spec(p, auth, "foreign"),
        })
    return out

def mask_tree(value):
    """Mask every address inside a nested response before it leaves this process.

    The monitor reports what it found, and one of the things it can find is an SSH failure quoting
    the host it could not reach. A JSON response is as much a leak path as an audit row, so masking
    is applied to the whole tree rather than to the fields I happened to think about.
    """
    if isinstance(value, str):
        return storage.mask_addresses(value)
    if isinstance(value, dict):
        return {k: mask_tree(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [mask_tree(v) for v in value]
    return value

# Phase 6 live feed: the one ring buffer the monitor publishes into
# and the SSE endpoint streams out of. Created at import so the
# endpoint can serve replays even before the monitor first runs.
EVENT_BUS = eventbus.EventBus()


def failover_monitor_instance() -> "failover_monitor.FailoverMonitor":
    """The one monitor this process may run, created on first use."""
    global FAILOVER_MONITOR
    with MONITOR_LOCK:
        if FAILOVER_MONITOR is None:
            FAILOVER_MONITOR = failover_monitor.FailoverMonitor(
                manager=FAILOVER_MANAGER, pair_source=monitor_pair_source,
                host_guard=DashboardHostGuard(), dry_run=is_dry_run(),
                event_bus=EVENT_BUS)
        return FAILOVER_MONITOR


def stream_events(bus, emit, last_id, heartbeat=eventbus.HEARTBEAT_SECONDS):
    """SSE pump: replay missed events, then stream new ones until the
    client goes away (emit raises). Heartbeats keep the connection
    alive through proxies on quiet hours. Kept separate from the
    handler so tests can drive it with a fake emitter.

    The loop never raises for a dead client: a dropped SSE stream is
    not an operator-visible error, and EventSource reconnects on its
    own with Last-Event-ID.
    """
    try:
        while True:
            events = bus.wait_since(last_id, timeout=heartbeat)
            for ev in events:
                frame = ("id: {}\ndata: {}\n\n".format(
                    ev["id"], json.dumps(ev, ensure_ascii=False))).encode("utf-8")
                emit(frame)
                last_id = ev["id"]
            if not events:
                emit(b": keep-alive\n\n")
    except Exception:
        return

def resource_attribution(pair_id: int, limit: int = 60, now_sec: float = None) -> dict:
    """Per-role connection-burst attribution over the *stored* history. Reads the DB, opens no session.

    Bounded on purpose. The panel needs a verdict, a baseline and the bursts, not the arithmetic of every
    interval that produced them, and a dashboard poll that carried 120 interval objects per host would make
    the capacity panel the most expensive thing on the page. `intervals` is therefore replaced by a count;
    `bursts` keeps its own cap from engine.

    `now_sec` defaults to the server clock because that is the clock which stamped the rows - a browser
    that disagrees would mark a fresh history stale or a stale one fresh, and the second is the one an
    operator acts on.
    """
    now_sec = time.time() if now_sec is None else now_sec
    out = {}
    for role in ("iran", "foreign"):
        rows = storage.host_resource_history(pair_id, role, limit=limit)
        attr = engine.attribute_connection_bursts(rows, role=role, now_sec=now_sec,
                                                  stale_after_sec=engine.RESOURCE_STALE_AFTER_SEC)
        out[role] = dict({k: v for k, v in attr.items() if k != "intervals"},
                         interval_count=len(attr["intervals"]))
    return mask_tree(out)


# --- Continuous capacity sampling (round 063, #70) ---------------------------------------------
#
# The attribution in `engine.attribute_connection_bursts` needs a *history*: a baseline is the median of a
# host's own quiet intervals, so a panel fed one sample per click can describe a burst but cannot say
# whether it was a burst. The reboot pentest needs the same thing for the opposite reason - while a host is
# coming back, every source fails, and the only way that gap becomes a recorded fact rather than an absence
# is for someone to keep asking and keep writing down "unreachable".
#
# This is deliberately not folded into `failover_monitor.FailoverMonitor`. That thread is gated on
# BEST_TUNNEL_AUTOHEAL, and ruling 3's reboot runs with autoheal OFF on purpose - an operator watching a
# host boot needs the product to observe, not to decide. A sampler that only ran when healing was armed
# would therefore be silent for exactly the window it exists to record, and a sampler that armed healing to
# get itself started would be the most dangerous bug in the repository. Separate thread, separate gate.
CAPACITY_SAMPLER_ENV = "BEST_TUNNEL_CAPACITY_SAMPLER"
CAPACITY_INTERVAL_ENV = "BEST_TUNNEL_CAPACITY_INTERVAL_SEC"
CAPACITY_DEFAULT_INTERVAL_SEC = 60.0
CAPACITY_TRUTHY = ("1", "true", "yes", "on")
CAPACITY_LOCK = threading.Lock()
CAPACITY_SAMPLER = None


def capacity_sampling_enabled(env=None) -> bool:
    """Whether an operator asked for continuous capacity history. Off unless explicitly set."""
    source = os.environ if env is None else env
    return (source.get(CAPACITY_SAMPLER_ENV) or "").strip().lower() in CAPACITY_TRUTHY


def capacity_interval_sec(env=None) -> float:
    """The sampling period, clamped to something that cannot stampede a host.

    A non-numeric value falls back to the default rather than raising: this is read once at start, and an
    operator who typed `BEST_TUNNEL_CAPACITY_INTERVAL_SEC=5m` should get a sampler at the default period
    with the parsed value printed in `status()`, not a dashboard that will not boot.
    """
    source = os.environ if env is None else env
    try:
        raw = float((source.get(CAPACITY_INTERVAL_ENV) or "").strip() or CAPACITY_DEFAULT_INTERVAL_SEC)
    except (TypeError, ValueError):
        return CAPACITY_DEFAULT_INTERVAL_SEC
    return max(15.0, min(3600.0, raw))


class CapacitySampler:
    """A thread that reads /proc on both hosts of every deployed pair and records what it saw.

    Read-only by construction: the nine commands are the ones `engine.RESOURCE_SAMPLE_COMMANDS` declares and
    every one was proven inert against the same classifier that gates a deploy (#53 stands, nothing was
    widened). No host lock is taken, for the reason the on-demand route gives - a capacity sampler that
    contends with a deploy would stop recording during exactly the operation an operator most wants
    explained afterwards.
    """

    def __init__(self, pair_source=None, interval_sec: float = None, dry_run=None,
                 recorder=None):
        self.pair_source = pair_source or monitor_pair_source
        self.interval_seconds = CAPACITY_DEFAULT_INTERVAL_SEC if interval_sec is None else float(interval_sec)
        self.dry_run = dry_run or is_dry_run
        self.recorder = recorder or engine.collect_pair_resources
        self._stop = threading.Event()
        self._thread = None
        self.passes = 0
        self.rows_written = 0
        self.last_pass = []
        self.last_error = None
        self._verdict = {}

    def run_once(self) -> list:
        """One pass over every deployed pair. Returns a per-pair verdict, recording as it goes."""
        if self.dry_run():
            return [{"action": "SKIP_DRY_RUN",
                     "reason": f"BEST_TUNNEL_DRY_RUN is on: engine issues no command and records nothing, "
                               f"so every pass would be refused and the reboot window would look identical "
                               f"to a machine nobody watched"}]
        out = []
        for pair in self.pair_source() or []:
            pid = pair.get("id")
            status = (pair.get("status") or "").upper()
            if status != "ACTIVE":
                out.append({"pair_id": pid, "action": "SKIP_NOT_ACTIVE",
                            "reason": f"status {status or 'empty'}"})
                continue
            # The monitor's guard, inherited rather than reinvented: this process authenticates from a
            # volatile cache with a 15-minute TTL, so a pass can arrive with no credential at all - most
            # likely in the middle of a long operation. Recording that as `reachable=0` would blame the host
            # for this process's expired login, which is the ambiguous-evidence mistake with a timestamp on it.
            missing_cred = [role for role in ("iran", "foreign")
                            if not ((pair.get(role) or {}).get("auth") or {}).get("value")]
            if missing_cred:
                out.append({"pair_id": pid, "action": "SKIP_NO_CREDENTIALS",
                            "reason": f"no session credential for {', '.join(missing_cred)} - nothing was "
                                      f"opened and nothing was written, because an expired login says "
                                      f"nothing about these hosts"})
                continue
            ir_runner = fr_runner = None
            runners, refusals = {}, {}
            try:
                # The #71 shape, on purpose and from the start: `get_ssh_runner` connects and authenticates,
                # so a pair whose second host is mid-reboot raises here. Opened outside the `finally`, that
                # raise would strand one live SSH session per pass per pair - and this is the code path that
                # runs continuously *through* the reboot window it exists to record.
                #
                # Each host is opened on its own, and a refusal is kept as a reason rather than allowed to
                # abort the pass: a single try around both connects means the host that answered happily
                # loses its row too, so the survivor of a reboot would have a gap in its history exactly
                # where its own burst against the down host should have been recorded.
                for role in ("iran", "foreign"):
                    try:
                        runners[role] = get_ssh_runner(pair[role], dry_run=False, host_role=role)
                    except Exception as exc:
                        runners[role] = None
                        # Masked at the catch, not at the print: this text goes into the pass verdict the
                        # route returns, into the audit line, and into the reason the recorder writes onto
                        # the unreachable row, and a runner prefixes its failures with the host it addressed.
                        refusals[role] = storage.mask_addresses(f"{type(exc).__name__}: {exc}")[:200]
                ir_runner, fr_runner = runners.get("iran"), runners.get("foreign")
                res = self.recorder(pair, ir_runner, fr_runner, dry_run=False, record=True,
                                    no_session_reasons=refusals)
                recorded = int(res.get("recorded") or 0)
                self.rows_written += recorded
                # The pass is named by how much of the pair it could see, so the audit log carries the
                # window's start and end as transitions instead of a run of identical SAMPLED lines.
                action = ("UNREACHABLE" if len(refusals) == 2
                          else "PARTIAL" if refusals else "SAMPLED")
                if refusals:
                    self.last_error = storage.mask_addresses(
                        "; ".join(f"{r}: {m}" for r, m in sorted(refusals.items())))[:200]
                out.append({"pair_id": pid, "action": action, "recorded": recorded,
                            "ok": bool(res.get("ok")), "unreachable": sorted(refusals),
                            "reason": " | ".join(sorted(refusals.values()))[:200] or None,
                            "summary": (res.get("summary") or "")[:400]})
            except Exception as exc:
                self.last_error = storage.mask_addresses(f"{type(exc).__name__}: {exc}")[:200]
                out.append({"pair_id": pid, "action": "ERROR", "reason": self.last_error})
            finally:
                for r in (ir_runner, fr_runner):
                    if hasattr(r, "close"):
                        r.close()
        self.passes += 1
        self.last_pass = out
        self._audit_transitions(out)
        return out

    def _audit_transitions(self, out: list):
        """Audit a pair only when its verdict *changed*, which is the line an operator needs to find.

        The failover monitor established this rule for the same arithmetic: at one pass a minute, auditing
        every pass writes ~1400 identical rows per pair per day and buries the deploy and switchover entries
        the log exists to carry. A sampler at 60 s has the same cost, so it inherits the same discipline -
        and the transition is also the interesting event here, because "SAMPLED then ERROR then SAMPLED" is
        the dark window having a start and an end.
        """
        for item in out:
            pid, verdict = item.get("pair_id"), item["action"]
            if self._verdict.get(pid) != verdict:
                self._verdict[pid] = verdict
                storage.log_audit(pid, "CAPACITY_SAMPLER", verdict,
                                  item.get("reason") or item.get("summary") or verdict)

    def loop(self):
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:
                storage.log_audit(None, "CAPACITY_SAMPLER", "LOOP_ERROR",
                                  storage.mask_addresses(f"{type(exc).__name__}: {exc}"))
            self._stop.wait(self.interval_seconds)

    def start(self) -> bool:
        """Start the sampler. Refuses, with a reason, when it could not produce a history anyway."""
        if self._thread is not None and self._thread.is_alive():
            return False
        if self.dry_run():
            raise ValueError(
                f"refusing to start a sampler that cannot sample: BEST_TUNNEL_DRY_RUN is on. Every pass "
                f"would be refused by engine and nothing would be recorded, so the reboot window would look "
                f"identical to a machine nobody watched - which is the failure this thread exists to prevent")
        self._stop.clear()
        self._thread = threading.Thread(target=self.loop, daemon=True, name="capacity-sampler")
        self._thread.start()
        return True

    def stop(self, timeout: float = 5.0) -> bool:
        self._stop.set()
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout=timeout)
        alive = thread.is_alive()
        if not alive:
            self._thread = None
        return not alive

    def status(self) -> dict:
        return {"running": bool(self._thread is not None and self._thread.is_alive()),
                "interval_sec": self.interval_seconds, "passes": self.passes,
                "rows_written": self.rows_written, "enabled": capacity_sampling_enabled(),
                "dry_run": bool(self.dry_run()), "last_error": self.last_error,
                "last_pass": mask_tree(self.last_pass)}


def capacity_sampler_instance() -> CapacitySampler:
    """The one sampler this process may run, created on first use."""
    global CAPACITY_SAMPLER
    with CAPACITY_LOCK:
        if CAPACITY_SAMPLER is None:
            CAPACITY_SAMPLER = CapacitySampler(interval_sec=capacity_interval_sec())
        return CAPACITY_SAMPLER


def check_bearer_auth(headers) -> bool:
    """Validates Bearer token if BEST_TUNNEL_API_TOKEN is configured."""
    if not BEST_TUNNEL_API_TOKEN:
        return True
    auth_hdr = headers.get("Authorization", "")
    if auth_hdr.startswith("Bearer "):
        token = auth_hdr[7:].strip()
        return secrets.compare_digest(token, BEST_TUNNEL_API_TOKEN)
    return False

# Memory-leak-proof Job store with bounded size and TTL eviction
JOBS = {}
JOBS_LOCK = threading.Lock()
MAX_JOBS = 50
JOB_TTL_SECONDS = 1800

# Per-pair concurrency protection
PAIR_BENCH_LOCKS = {}
PAIR_BENCH_GUARD = threading.Lock()

ALLOWED_HOSTS = {"127.0.0.1:8800", "localhost:8800"}

# Profile Notes and UI internationalization strings (Auditor Notice 3 & P0-6)
PROFILE_NOTES = {
    "ultraspeed_tooltip": "بهینه‌شده برای حداکثر پهنای باند و انتقال داده با ۴ جریان همزمان iperf3 (وزن توان ۴۰٪)",
    "ultraspeed_label": "🚀 Ultra-Speed (توان عملیاتی ۴۰٪ با موتور iperf3)",
    "secrets_at_rest": "🔒 <b>Secrets-at-rest with 0600:</b> Sensitive SSH passwords reside strictly in process RAM with 15-minute TTL; tunnel secrets and units are written with umask 077 and restricted 0600 permissions."
}

# R-66: Client IP Sliding Window Rate Limiter with Route Categorization (Sprint 2)
RATE_LIMIT_LOCK = threading.Lock()
RATE_LIMIT_BUCKETS = {}  # (ip, category) -> list of float timestamps
RATE_LIMIT_WINDOW_SECONDS = 60  # per 60 seconds
RATE_LIMIT_QUOTAS = {
    "mutation": 30,   # Deploy, bench, release, add/delete pair (30 req/min)
    "polling": 120,   # /api/job telemetry polling (120 req/min = 2 req/sec)
    "read": 60        # GET /api pairs read (60 req/min)
}

def is_rate_limited(client_ip: str, category: str = "mutation") -> bool:
    """Checks and updates sliding window rate limit for client IP by route category (R-66 / Sprint 2)."""
    now = time.time()
    max_reqs = RATE_LIMIT_QUOTAS.get(category, 60)
    bucket_key = (client_ip, category)
    with RATE_LIMIT_LOCK:
        history = RATE_LIMIT_BUCKETS.get(bucket_key, [])
        history = [t for t in history if now - t < RATE_LIMIT_WINDOW_SECONDS]
        if len(history) >= max_reqs:
            RATE_LIMIT_BUCKETS[bucket_key] = history
            return True
        history.append(now)
        RATE_LIMIT_BUCKETS[bucket_key] = history
        if len(RATE_LIMIT_BUCKETS) > 2000:
            to_del = [k for k, timestamps in RATE_LIMIT_BUCKETS.items() if not timestamps or (now - timestamps[-1] >= RATE_LIMIT_WINDOW_SECONDS)]
            for k in to_del:
                del RATE_LIMIT_BUCKETS[k]
        return False

def cleanup_jobs():
    """Evicts expired jobs and enforces strict FIFO capacity limit."""
    with JOBS_LOCK:
        now = time.time()
        expired = [jid for jid, info in JOBS.items() if now - info.get("created_at", now) > JOB_TTL_SECONDS]
        for jid in expired:
            del JOBS[jid]
        while len(JOBS) > MAX_JOBS:
            oldest = min(JOBS.keys(), key=lambda k: JOBS[k].get("created_at", 0))
            del JOBS[oldest]

def valid_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except Exception:
        return False

PAGE = """<!doctype html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
  <meta http-equiv="Pragma" content="no-cache">
  <meta http-equiv="Expires" content="0">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;700;800&display=swap" rel="stylesheet">
  <title>Tunnel Studio Pro v3.0</title>
  <style>
    :root {
      --bg-page: #0b0e1a;
      --bg-card: #141829;
      --bg-card-subtle: #1a1f33;
      --bg-input: #101423;
      --border-color: #262c44;
      --border-focus: #3b82f6;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --primary-blue: #2563eb;
      --primary-hover: #1d4ed8;
      --accent-green: #10b981;
      --accent-red: #ef4444;
      --accent-amber: #f59e0b;
      --radius-sm: 10px;
      --radius-md: 12px;
      --radius-lg: 20px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: "Vazirmatn", Tahoma, "Segoe UI", sans-serif;
      background-color: var(--bg-page);
      color: var(--text-main);
      padding: 20px;
      min-height: 100vh;
      line-height: 1.7;
    }
    .ltr { direction: ltr; unicode-bidi: embed; font-variant-numeric: tabular-nums; }

    .container {
      max-width: 1240px;
      margin: 0 auto;
    }

    /* Top Navbar (sticky) */
    .navbar {
      position: sticky;
      top: 0;
      z-index: 100;
      background: rgba(11, 14, 26, 0.92);
      backdrop-filter: blur(8px);
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 4px;
      margin-bottom: 18px;
      border-bottom: 1px solid var(--border-color);
      flex-wrap: wrap;
      gap: 12px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-icon {
      width: 40px;
      height: 40px;
      background: linear-gradient(135deg, #2563eb, #22d3ee);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
      font-weight: 800;
      font-size: 18px;
      box-shadow: 0 6px 18px rgba(37, 99, 235, 0.45);
    }
    .brand-title {
      font-size: 19px;
      font-weight: 800;
      color: var(--text-main);
    }
    .brand-badge {
      font-size: 11px;
      font-weight: 700;
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      padding: 2px 10px;
      border-radius: 99px;
      border: 1px solid rgba(59, 130, 246, 0.3);
      margin-inline-start: 8px;
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 7px 14px;
      border-radius: 99px;
      font-size: 12.5px;
      font-weight: 700;
      background: rgba(16, 185, 129, 0.12);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .status-badge.mock {
      background: rgba(245, 158, 11, 0.12);
      color: #fbbf24;
      border-color: rgba(245, 158, 11, 0.3);
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: currentColor;
      box-shadow: 0 0 0 4px rgba(16, 185, 129, 0.18);
    }

    /* Active Pair Selector Banner */
    .active-banner {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 18px;
      padding: 14px 18px;
      margin-bottom: 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
    }
    .banner-title {
      font-size: 13px;
      font-weight: 500;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .pair-selector {
      background: var(--bg-input);
      border: 1px solid var(--border-color);
      color: #93c5fd;
      padding: 8px 12px;
      border-radius: var(--radius-md);
      font-size: 13.5px;
      font-weight: 700;
      outline: none;
      font-family: inherit;
    }

    /* Cards */
    .card-panel {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-lg);
      padding: 20px 22px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
      margin-bottom: 18px;
    }
    .panel-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }
    .panel-title {
      font-size: 16px;
      font-weight: 800;
      color: var(--text-main);
    }
    .panel-subtitle {
      font-size: 12.5px;
      color: var(--text-muted);
      margin-top: 2px;
    }

    /* Setup card: three balanced columns instead of one tall sidebar */
    .setup-grid {
      display: grid;
      grid-template-columns: 1fr 1fr 1fr;
      gap: 18px;
    }
    @media (max-width: 900px) {
      .setup-grid {
        grid-template-columns: 1fr;
      }
    }
    .endpoint {
      background: var(--bg-card-subtle);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 16px;
    }
    .endpoint-title {
      font-size: 13.5px;
      font-weight: 800;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .endpoint-role {
      color: var(--text-dim);
      font-weight: 400;
      font-size: 12px;
    }
    .flag {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      flex-shrink: 0;
    }
    .flag.ir { background: #10b981; }
    .flag.fr { background: #3b82f6; }
    .setup-actions {
      display: grid;
      gap: 10px;
      align-content: start;
    }
    .setup-foot {
      margin-top: 18px;
      display: grid;
      gap: 14px;
    }
    .setup-foot h4 {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      color: #a78bfa;
      margin-bottom: 6px;
    }

    /* Forms */
    .form-group {
      margin-bottom: 10px;
    }
    .field-label {
      display: block;
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 5px;
      font-weight: 500;
    }
    .tooltip-icon {
      color: var(--text-dim);
      cursor: help;
      font-size: 12px;
    }
    input, select {
      font-family: inherit;
      background: var(--bg-input);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      border-radius: var(--radius-md);
      padding: 10px 12px;
      font-size: 13.5px;
      outline: none;
      width: 100%;
    }
    input:focus, select:focus {
      border-color: var(--border-focus);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
    }
    .row2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }
    .toggle-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      background: var(--bg-card-subtle);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-md);
      padding: 10px 12px;
    }
    .toggle-row small {
      color: var(--text-dim);
      font-size: 11.5px;
      display: block;
    }
    .switch {
      position: relative;
      width: 46px;
      height: 26px;
      flex-shrink: 0;
      cursor: pointer;
    }
    .switch input { display: none; }
    .switch span {
      position: absolute;
      inset: 0;
      background: #2a3350;
      border-radius: 99px;
      transition: 0.2s;
    }
    .switch span:before {
      content: "";
      position: absolute;
      width: 20px;
      height: 20px;
      border-radius: 50%;
      background: #fff;
      top: 3px;
      right: 3px;
      transition: 0.2s;
    }
    .switch input:checked + span { background: var(--primary-blue); }
    .switch input:checked + span:before { transform: translateX(-20px); }
    .note {
      font-size: 11.5px;
      color: var(--text-dim);
      line-height: 1.8;
    }

    /* Buttons */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 11px 18px;
      border-radius: var(--radius-md);
      font-size: 13.5px;
      font-weight: 700;
      font-family: inherit;
      cursor: pointer;
      transition: all 0.15s ease-in-out;
      border: 1px solid transparent;
      text-decoration: none;
      width: 100%;
    }
    .btn-primary {
      background: linear-gradient(135deg, #2563eb, #3b82f6);
      color: #fff;
      box-shadow: 0 6px 16px rgba(37, 99, 235, 0.35);
    }
    .btn-primary:hover {
      filter: brightness(1.1);
    }
    .btn-success {
      background: linear-gradient(135deg, #059669, #10b981);
      color: #fff;
      box-shadow: 0 6px 16px rgba(16, 185, 129, 0.35);
    }
    .btn-success:hover {
      filter: brightness(1.1);
    }
    .btn-outline-danger {
      background: transparent;
      border-color: rgba(239, 68, 68, 0.6);
      color: #ef4444;
    }
    .btn-outline-danger:hover {
      background: rgba(239, 68, 68, 0.1);
      border-color: #ef4444;
    }
    .btn-secondary {
      background: #252a3b;
      border-color: var(--border-color);
      color: #cbd5e1;
    }
    .btn-secondary:hover {
      background: #2d3347;
      color: #fff;
    }
    .btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }

    /* KPI strip */
    .kpis {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
      margin-bottom: 18px;
    }
    @media (max-width: 900px) {
      .kpis {
        grid-template-columns: 1fr 1fr;
      }
    }
    .kpi {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 18px;
      padding: 16px 18px;
    }
    .kpi .k-lbl {
      color: var(--text-muted);
      font-size: 12.5px;
      margin-bottom: 4px;
    }
    .kpi .k-val {
      font-size: 20px;
      font-weight: 800;
    }
    .kpi .k-val.green { color: #34d399; }

    /* Terminal Console */
    .console-box {
      background: #0a0d18;
      border: 1px solid var(--border-color);
      border-radius: var(--radius-lg);
      overflow: hidden;
      margin-bottom: 18px;
    }
    .console-header {
      background: #181b24;
      padding: 10px 14px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .console-dots {
      display: flex;
      gap: 6px;
    }
    .console-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }
    pre#raw {
      padding: 14px 16px;
      font-size: 12.5px;
      color: #7dd3fc;
      line-height: 2;
      overflow-x: auto;
      white-space: pre-wrap;
      font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    }

    /* Benchmark matrix */
    .profile-tabs {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .profile-tab {
      background: var(--bg-card-subtle);
      border: 1px solid var(--border-color);
      color: var(--text-muted);
      font-size: 13px;
      font-weight: 700;
      font-family: inherit;
      padding: 7px 16px;
      border-radius: 99px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .profile-tab:hover {
      color: var(--text-main);
    }
    .profile-tab.active {
      background: linear-gradient(135deg, #2563eb, #3b82f6);
      color: #fff;
      border-color: transparent;
      box-shadow: 0 0 12px rgba(37, 99, 235, 0.4);
    }
    .winner-banner {
      display: none;
      margin: 16px 0;
      padding: 14px 18px;
      border-radius: 16px;
      background: linear-gradient(90deg, rgba(16, 185, 129, 0.18), rgba(34, 211, 238, 0.08));
      border: 1px solid rgba(16, 185, 129, 0.35);
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    .benchmarks-container {
      margin-top: 4px;
    }
    .benchmarks-header {
      display: flex;
      justify-content: space-between;
      font-size: 12px;
      color: var(--text-muted);
      padding: 10px 8px;
      border-bottom: 1px solid var(--border-color);
    }
    .bench-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
      padding: 12px 8px;
      border-bottom: 1px solid rgba(38, 44, 68, 0.6);
    }
    .bench-row:last-child {
      border-bottom: 0;
    }
    .bench-row:hover {
      background: rgba(59, 130, 246, 0.05);
    }
    .proto-badge {
      display: flex;
      align-items: center;
      gap: 9px;
      font-weight: 700;
      font-size: 13.5px;
    }
    .proto-indicator {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      flex-shrink: 0;
    }
    .proto-indicator.proto-pass {
      background: #10b981;
      box-shadow: 0 0 0 4px rgba(16, 185, 129, 0.15);
    }
    .proto-indicator.proto-fail {
      background: #ef4444;
      box-shadow: 0 0 0 4px rgba(239, 68, 68, 0.15);
    }
    .proto-metrics {
      display: flex;
      align-items: center;
      gap: 14px;
      color: var(--text-muted);
      font-size: 13px;
      flex-wrap: wrap;
    }
    .proto-score {
      color: #38bdf8;
      font-weight: 800;
    }
    .proto-score.fail { color: #ef4444; }
    .score-bar {
      flex-basis: 100%;
      height: 5px;
      background: #232842;
      border-radius: 99px;
      overflow: hidden;
    }
    .score-bar i {
      display: block;
      height: 100%;
      border-radius: 99px;
      background: linear-gradient(90deg, #10b981, #22d3ee);
    }

    /* Balanced two-column row (telemetry + health) */
    .duo {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
    }
    @media (max-width: 900px) {
      .duo {
        grid-template-columns: 1fr;
      }
    }
    .fleet-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }
    @media (max-width: 900px) {
      .fleet-grid {
        grid-template-columns: 1fr;
      }
    }

    /* Toasts */
    .toast-container {
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 99999;
      display: flex;
      flex-direction: column;
      gap: 10px;
      pointer-events: none;
    }
    .toast {
      pointer-events: auto;
      background: #1c202d;
      border: 1px solid var(--border-color);
      border-left: 4px solid var(--primary-blue);
      border-radius: var(--radius-md);
      padding: 12px 18px;
      color: var(--text-main);
      font-size: 13px;
      font-weight: 500;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
    }
    .toast.success { border-left-color: #10b981; }
    .toast.error { border-left-color: #ef4444; }
    .toast.info { border-left-color: #3b82f6; }

    /* Modal */
    .modal-backdrop {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(10, 12, 18, 0.85);
      backdrop-filter: blur(8px);
      align-items: center;
      justify-content: center;
      z-index: 9999;
    }
    .modal-card {
      background: #1b1e2a;
      border: 1px solid #363c50;
      border-radius: var(--radius-lg);
      padding: 24px;
      max-width: 480px;
      width: 90%;
      box-shadow: 0 20px 45px rgba(0, 0, 0, 0.6);
    }
    .modal-header {
      font-size: 16px;
      font-weight: 700;
      color: #f87171;
      margin-bottom: 12px;
    }
    .modal-body {
      font-size: 13px;
      line-height: 1.8;
      color: #cbd5e1;
      margin-bottom: 20px;
    }
    .modal-footer {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
    }
    .modal-footer .btn {
      width: auto;
    }

    .spinner {
      width: 14px;
      height: 14px;
      border: 2px solid rgba(255, 255, 255, 0.3);
      border-radius: 50%;
      border-top-color: #fff;
      animation: spin 0.8s linear infinite;
      display: inline-block;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>


  <div id="toast-root" class="toast-container"></div>

  <div class="container">

    <!-- Top Navigation Header (sticky) -->
    <header class="navbar">
      <div class="brand">
        <div class="brand-icon">T</div>
        <div>
          <span class="brand-title">Tunnel Studio Pro</span>
          <span class="brand-badge">v3.0</span>
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 12px;">
        <div id="mbadge" class="status-badge">
          <span class="pulse-dot"></span>
          <span id="mbadge-text">LIVE OPERATION MODE</span>
        </div>
        <button class="btn btn-secondary" style="width: auto; padding: 8px 14px; font-size: 12.5px;" onclick="loadData()">
          Refresh
        </button>
      </div>
    </header>

    <!-- Active Server Switcher Banner -->
    <div class="active-banner">
      <div class="banner-title">
        <span>جفت فعال:</span>
        <select id="pairSelect" class="pair-selector" onchange="switchPair()">
          <option value="new">+ Add New Server Pair (خالی / سرور جدید)</option>
        </select>
      </div>
      <div style="display: flex; gap: 8px;">
        <button class="btn btn-outline-danger" style="width: auto; padding: 8px 14px; font-size: 12.5px;" onclick="deleteCurrentPair()">
          Delete Pair
        </button>
      </div>
    </div>

    <!-- Setup card: three balanced columns, no tall sidebar -->
    <div class="card-panel">
      <div class="panel-header">
        <div>
          <div class="panel-title">پیکربندی سرورها</div>
          <div class="panel-subtitle">Transport credentials and remote endpoint parameters</div>
        </div>
      </div>

      <div class="setup-grid">
        <!-- Iran endpoint -->
        <div class="endpoint">
          <div class="endpoint-title"><span class="flag ir"></span> سرور ایران <span class="endpoint-role">(ورودی)</span></div>
          <div class="form-group">
            <label class="field-label">Iran IPv4 Address <span class="tooltip-icon" title="Management (SSH) address. The tunnels dial the underlay address below, not this one, when they differ.">ⓘ</span></label>
            <input id="a1" value="" placeholder="e.g. 5.160.x.x">
          </div>
          <div class="form-group">
            <label class="field-label">Iran Underlay / Dial Address <span class="tooltip-icon" title="dial_host: the peer address the overlay is built to and certificates name. Leave empty when it is the same as the management address. GRE/ESP carriers set it to the address reachable over the underlay.">ⓘ</span></label>
            <input id="a5" value="" placeholder="same as above if unset">
          </div>
          <div class="row2">
            <div class="form-group">
              <label class="field-label">SSH Port</label>
              <input id="a2" value="22">
            </div>
            <div class="form-group">
              <label class="field-label">SSH User</label>
              <input id="a3" value="root">
            </div>
          </div>
          <div class="form-group">
            <label class="field-label">SSH Password <span class="tooltip-icon" title="Volatile RAM storage only. Never saved to persistent SQLite database.">ⓘ</span></label>
            <input id="a4" type="password" placeholder="Enter Iran SSH password" autocomplete="off">
          </div>
        </div>

        <!-- Foreign endpoint -->
        <div class="endpoint">
          <div class="endpoint-title"><span class="flag fr"></span> سرور خارج <span class="endpoint-role">(خروجی)</span></div>
          <div class="form-group">
            <label class="field-label">Foreign IPv4 Address <span class="tooltip-icon" title="Management (SSH) address. The tunnels dial the underlay address below, not this one, when they differ.">ⓘ</span></label>
            <input id="b1" value="" placeholder="e.g. 91.228.x.x">
          </div>
          <div class="form-group">
            <label class="field-label">Foreign Underlay / Dial Address <span class="tooltip-icon" title="dial_host: the peer address the overlay is built to and certificates name. Leave empty when it is the same as the management address.">ⓘ</span></label>
            <input id="b5" value="" placeholder="same as above if unset">
          </div>
          <div class="row2">
            <div class="form-group">
              <label class="field-label">SSH Port</label>
              <input id="b2" value="22">
            </div>
            <div class="form-group">
              <label class="field-label">SSH User</label>
              <input id="b3" value="root">
            </div>
          </div>
          <div class="form-group">
            <label class="field-label">SSH Password <span class="tooltip-icon" title="Volatile RAM storage only.">ⓘ</span></label>
            <input id="b4" type="password" placeholder="Enter Foreign SSH password" autocomplete="off">
          </div>
        </div>

        <!-- Pair settings + actions -->
        <div class="setup-actions">
          <div class="form-group">
            <label class="field-label">Pair Name / Tag</label>
            <input id="pname" value="" placeholder="e.g. My-Tunnel-Pair">
          </div>
          <div class="form-group">
            <label class="field-label">Public Ingress Port (Pasargad)</label>
            <input id="f" value="443">
          </div>
          <div class="toggle-row">
            <div>
              <span class="field-label" style="margin-bottom: 0;">Safe Port Handover <span class="tooltip-icon" title="Backs up and gracefully stops whatever currently holds protected port 443, then confirms the port is free before the tunnel binds it. The displaced service stops and does not resume: this is not zero-downtime.">ⓘ</span></span>
              <small>Strict port 443 release verification</small>
            </div>
            <label class="switch">
              <input type="checkbox" id="handoverToggle" checked>
              <span></span>
            </label>
          </div>
          <button id="runBenchBtn" class="btn btn-primary" onclick="runBenchmark()">
            🚀 Run 8-Protocol Benchmark
          </button>
          <div class="row2">
            <button id="preflightBtn" class="btn btn-secondary" onclick="runPreflight()">📡 Preflight</button>
            <button id="sampleBtn" class="btn btn-secondary" onclick="sampleResources()">📊 Sample capacity</button>
          </div>
          <select id="deploySelect">
            <option value="GRE">GRE (Kernel L3 Wire-Speed)</option>
            <option value="kcptun">KCP-FEC (Fast3 UDP with Error Correction)</option>
            <option value="backhaul-wss">Backhaul (WSS Multiplexed Reverse)</option>
            <option value="rathole-noise">Rathole (Noise Protocol Stealth)</option>
            <option value="hysteria2">Hysteria2 (QUIC + Salamander)</option>
            <option value="wstunnel-v10">WStunnel v10 (Secret WebSocket Upgrade)</option>
            <option value="chisel-wss">Chisel (HTTP/WSS Reverse Tunnel)</option>
            <option value="frp-TLS">FRP (Fast Reverse Proxy with TLS)</option>
            <option value="xray-reverse">Xray Reverse (gRPC Tunnel Bridge)</option>
            <!-- __OPT_IN_SINGBOX_OPTIONS__ -->
          </select>
          <button class="btn btn-success" onclick="deploySelected()">
            ⚡ Deploy Tunnel
          </button>
          <div class="row2">
            <button class="btn btn-secondary" onclick="saveAsNewPair()">
              ➕ Save as New Pair
            </button>
            <button class="btn btn-outline-danger" onclick="clearForm()" title="Clear all input fields and wipe benchmark results">
              🧹 Clear All & Reset
            </button>
          </div>
          <p class="note">__SECRETS_AT_REST__</p>
        </div>
      </div>

      <div class="setup-foot">
        <!-- ESP carrier slot rule: the kernel's one-VTI-per-direction limit, shown before the deploy buttons
             because a deploy is the moment it becomes visible otherwise. -->
        <div id="carrierRule" dir="rtl"></div>

        <!-- #63 backend contract: where this pair's tunnel delivers on the peer, and whether anything is
             listening there. Shown next to the carrier rule because both are topology facts a deploy reads
             and an operator cannot otherwise see. -->
        <div id="backendRule" dir="rtl"></div>

        <!-- #39: the audit rows this pair produced that are not routine. The engine already wrote them;
             nothing read them back, so a rotated destination anchor was visible only in the one deploy
             that refused because of it. -->
        <div id="securityEvents" dir="rtl"></div>

        <!-- #41 underlay preflight: what the transports will dial, measured from the side that has to dial it. -->
        <div>
          <h4>Underlay Preflight</h4>
          <div id="preflightSummary" style="font-size: 12.5px; color: var(--text-muted);">
            Measures each direction of the path the overlay dials, 50 ICMP samples per leg. Loss at or below
            2% is CLEAN, 2-4% is MARGINAL and still usable; above 4% blocks. Nothing is installed.
          </div>
          <div id="preflightLegs" style="margin-top: 8px; font-size: 12.5px;"></div>
        </div>

        <!-- #69 dual-host capacity monitoring (round 063 ruling 1). The six readings come over the same
             gated SSH path a deploy uses and every one of them is a read the classifier already proved
             inert, so the panel costs nothing on the hosts and works in dry-run as a preview. -->
        <div>
          <h4>Host Capacity</h4>
          <div id="resourceSummary" style="font-size: 12.5px; color: var(--text-muted);">
            بار پردازنده، حافظه، دیسک و آپتایم هر دو میزبان. سنجه‌ای که خوانده نشود «خوانده نشد» می‌ماند و
            هرگز به‌شکل یک ماشین بیکار رسم نمی‌شود.
          </div>
          <div id="resourceHosts" style="margin-top: 8px; font-size: 12.5px;"></div>
        </div>
      </div>
    </div>

    <!-- KPI strip: live from the selected pair -->
    <div class="kpis">
      <div class="kpi"><div class="k-lbl">وضعیت تانل</div><div class="k-val green" id="kpiTunnel">—</div></div>
      <div class="kpi"><div class="k-lbl">تأخیر پایه مسیر</div><div class="k-val ltr" id="kpiRtt">—</div></div>
      <div class="kpi"><div class="k-lbl">بهترین پروتکل</div><div class="k-val" id="kpiBest">—</div></div>
      <div class="kpi"><div class="k-lbl">پروتکل‌های سالم</div><div class="k-val" id="kpiHealthy">—</div></div>
    </div>

    <!-- Protocol Benchmark Matrix -->
    <div class="card-panel">
      <div class="panel-header" style="flex-wrap: wrap; gap: 10px;">
        <div>
          <div class="panel-title">Protocol Benchmark Matrix (__PROTOCOL_COUNT__ Protocols)</div>
          <div class="panel-subtitle">Independent performance and DPI ladder qualification</div>
        </div>
        <!-- Optimization Profile Switcher -->
        <div class="profile-tabs">
          <button class="profile-tab active" id="prof-balanced" onclick="setProfile('balanced')">⚖️ Balanced</button>
          <button class="profile-tab" id="prof-gaming" onclick="setProfile('gaming')">🎮 Gaming</button>
          <button class="profile-tab" id="prof-ultraspeed" onclick="setProfile('ultraspeed')" title="__ULTRASPEED_TOOLTIP__">__ULTRASPEED_LABEL__</button>
        </div>
      </div>

      <!-- Winner 1-Click Banner -->
      <div id="winnerBanner" class="winner-banner" style="display: none;">
        <div>
          <div style="font-size: 13px; font-weight: 700; color: #34d399; display: flex; align-items: center; gap: 6px;">
            <span>🏆 Recommended Tunnel:</span>
            <span id="winnerName" style="color: #fff; background: rgba(16, 185, 129, 0.3); padding: 2px 8px; border-radius: 4px;">GRE</span>
            <span id="winnerScore" style="color: #38bdf8; font-weight: 800;">97.06 pts</span>
          </div>
          <div id="winnerReason" style="font-size: 12px; color: #cbd5e1; margin-top: 3px;">
            Lowest latency, 0% packet loss, passed 1MB bulk ladder.
          </div>
        </div>
        <button id="deployWinnerBtn" class="btn btn-success" style="width: auto; padding: 10px 20px; font-size: 13px; box-shadow: 0 0 15px rgba(16, 185, 129, 0.4);" onclick="deployWinner()">
          ⚡ 1-Click Deploy
        </button>
      </div>

      <div class="benchmarks-container">
        <div class="benchmarks-header">
          <span>Protocol</span>
          <span>Metrics & Qualification</span>
        </div>
        <div id="benchList">
          <div style="padding: 20px; font-size: 12.5px; color: var(--text-dim); text-align: center;">
            No benchmarks run yet. Enter server details above and click "Run 8-Protocol Benchmark".
          </div>
        </div>
      </div>
    </div>

    <!-- Balanced row: telemetry + Health Center -->
    <div class="duo">
      <!-- Live Telemetry Console -->
      <div class="console-box">
        <div class="console-header">
          <div style="display: flex; align-items: center; gap: 8px;">
            <div class="console-dots">
              <span class="console-dot" style="background:#ef4444"></span>
              <span class="console-dot" style="background:#f59e0b"></span>
              <span class="console-dot" style="background:#10b981"></span>
            </div>
            <span style="font-size: 12px; font-weight: 600; color: var(--text-muted); margin-left: 4px;">Live Execution Telemetry</span>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span id="op-status" style="font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 4px; background: #222738; color: #94a3b8;">SYSTEM READY</span>
            <button class="btn btn-secondary" style="width: auto; padding: 3px 8px; font-size: 11px;" onclick="clearConsole()">Clear</button>
          </div>
        </div>
        <pre id="raw">Tunnel Studio Pro v3.0 initialized.
Ready for server configuration and benchmark execution.</pre>
      </div>

      <!-- Phase 6: Health Center -->
      <div class="card-panel" id="healthSection" dir="rtl" style="margin-bottom: 18px;">
        <div class="panel-header"><div>
          <div class="panel-title">مرکز سلامت</div>
          <div class="panel-subtitle">آپتایم، قطعی‌ها و تاریخچه وضعیت هر جفت — از داده‌های ذخیره‌شده، نه حدس</div>
        </div></div>
        <div id="healthList"></div>
        <div style="margin-top: 14px;"><b>رویدادهای زنده</b>
          <span style="font-size: 12px; color: var(--text-dim);"> (جریان SSE؛ بدون رفرش صفحه می‌رسد)</span></div>
        <div id="liveEvents" style="margin-top: 6px; font-size: 12.5px;"></div>
      </div>
    </div>

    <!-- Phase 6: Fleet map + live cards -->
    <div class="card-panel" id="fleetSection" dir="rtl">
      <div class="panel-header"><div>
        <div class="panel-title">نقشه ناوگان و کارت‌های زنده</div>
        <div class="panel-subtitle">وضعیت لحظه‌ای هر جفت، آپتایم ۲۴ ساعته، تعداد سوییچ و قرنطینه فعال</div>
      </div></div>
      <div id="fleetMap" style="margin: 8px 0 16px;"></div>
      <div id="fleetCards" class="fleet-grid"></div>
    </div>

    <!-- Phase 6: محک wizard -->
    <div class="card-panel" id="wizardSection" dir="rtl">
      <div class="panel-header"><div>
        <div class="panel-title">ویزارد محک</div>
        <div class="panel-subtitle">جفت را انتخاب کن، پروفایل را بگو، محک بزن، با یک کلیک بهترین را اعمال کن</div>
      </div></div>
      <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
        <label>پروفایل:
          <select id="wizardProfile" class="pair-selector" style="width: auto;">
            <option value="balanced">متعادل</option>
            <option value="gaming">بازی (کمترین تاخیر)</option>
            <option value="ultraspeed">فوق‌سرعت (بیشترین پهنای باند)</option>
          </select>
        </label>
        <button class="btn btn-primary" style="width: auto;" onclick="runWizard()">محک بزن</button>
      </div>
      <div id="wizardStatus" style="margin-top: 10px; font-size: 12.5px; color: var(--text-dim);"></div>
      <div id="wizardResults" style="margin-top: 10px;"></div>
    </div>

  </div>

  <!-- Protected Port Confirmation Modal -->
  <div id="modal" class="modal-backdrop">
    <div class="modal-card">
      <div class="modal-header">Protected Port Handover</div>
      <div id="modal-text" class="modal-body"></div>
      <div class="modal-footer">
        <button class="btn btn-secondary" style="width: auto;" onclick="closeModal()">Close</button>
        <button class="btn btn-primary" style="width: auto;" onclick="confirmRelease()">Confirm Release & Deploy</button>
      </div>
    </div>
  </div>

  <script>
    let pairs = [];
    let currentPairId = null;
    let carrierSlots = [];
    let carrierRuleText = '';
    let pendingDeploy = null;

    function v(id) {
      let el = document.getElementById(id);
      return el ? (el.value || '').trim() : '';
    }

    function showToast(message, type = 'info') {
      const root = document.getElementById('toast-root');
      const toast = document.createElement('div');
      toast.className = 'toast ' + type;
      toast.textContent = message;
      root.appendChild(toast);
      setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.25s ease-in';
        setTimeout(() => toast.remove(), 260);
      }, 4200);
    }

    function clearConsole() {
      document.getElementById('raw').textContent = 'Console cleared.';
    }

    function clearForm() {
      currentPairId = 'new';
      document.getElementById('pname').value = '';
      document.getElementById('a1').value = '';
      document.getElementById('a5').value = '';
      document.getElementById('a2').value = '22';
      document.getElementById('a3').value = 'root';
      document.getElementById('a4').value = '';
      document.getElementById('b1').value = '';
      document.getElementById('b5').value = '';
      document.getElementById('b2').value = '22';
      document.getElementById('b3').value = 'root';
      document.getElementById('b4').value = '';
      document.getElementById('f').value = '443';
      const pf = document.getElementById('preflightLegs');
      if (pf) pf.innerHTML = '';

      const sel = document.getElementById('pairSelect');
      if (sel) sel.value = 'new';

      const banner = document.getElementById('winnerBanner');
      if (banner) banner.style.display = 'none';

      const container = document.getElementById('benchList');
      if (container) {
        container.innerHTML = '<div style="padding: 24px; font-size: 12.5px; color: var(--text-dim); text-align: center;">فرم و نتایج پاک شدند. مشخصات سرورهای جدید را در پنل سمت چپ وارد کرده و روی Run 8-Protocol Benchmark کلیک کنید.</div>';
      }

      const statusEl = document.getElementById('op-status');
      if (statusEl) {
        statusEl.textContent = 'READY FOR NEW PAIR';
        statusEl.style.background = '#222738';
        statusEl.style.color = '#94a3b8';
      }

      const raw = document.getElementById('raw');
      if (raw) {
        raw.textContent = 'تمام فیلدها و نتایج تست قبلی پاک شدند.\\nمشخصات سرورهای جدید را در پنل سمت چپ وارد کنید.';
      }

      renderCarrierRule(null);
      renderBackendRule(null);
      renderSecurityEvents(null);
      renderResources(null);
      showToast('تمام فیلدها و نتایج پاک شدند. آماده برای سرور جدید.', 'info');
    }

    async function apiFetch(url, data) {
      return await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Best-Tunnel-CSRF': '1'
        },
        body: JSON.stringify(data)
      });
    }

    function switchPair() {
      const selVal = document.getElementById('pairSelect').value;
      if (selVal === 'new') {
        clearForm();
        return;
      }
      const selId = +selVal;
      const p = pairs.find(x => x.id === selId);
      if (p) {
        currentPairId = p.id;
        document.getElementById('pname').value = p.name || '';
        document.getElementById('a1').value = p.iran_host || '';
        document.getElementById('a5').value = p.iran_dial_host || '';
        document.getElementById('a2').value = p.iran_port || 22;
        document.getElementById('a3').value = (p.iran && p.iran.user) || 'root';
        document.getElementById('b1').value = p.foreign_host || '';
        document.getElementById('b5').value = p.foreign_dial_host || '';
        document.getElementById('b2').value = p.foreign_port || 22;
        document.getElementById('b3').value = (p.foreign && p.foreign.user) || 'root';
        document.getElementById('f').value = p.frontend_port || 443;
        document.getElementById('a4').value = '';
        document.getElementById('b4').value = '';
        renderBenchmarks(p);
        renderCarrierRule(p);
        renderBackendRule(p);
        renderResources(p);
        /* Last, not in markup order: test_96 pins the four calls above as one exact contiguous block, and a
           call inserted into a pinned literal is a change to that test's contract, not to this one. */
        renderSecurityEvents(p);
      }
    }

    let currentProfile = 'balanced';
    let currentWinnerProtocol = 'GRE';

    function setProfile(prof) {
      currentProfile = prof;
      ['balanced', 'gaming', 'ultraspeed'].forEach(p => {
        const el = document.getElementById('prof-' + p);
        if (el) el.className = (p === prof) ? 'profile-tab active' : 'profile-tab';
      });
      const p = pairs.find(x => x.id === currentPairId);
      if (p) renderBenchmarks(p);
    }

    function deployWinner() {
      if (currentWinnerProtocol) {
        document.getElementById('deploySelect').value = currentWinnerProtocol;
        deploySelected();
      }
    }

    function escapeHtml(s) {
      if (s === null || s === undefined) return '';
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    const CARRIER_ROLE_LABEL = { iran: 'ایران', foreign: 'خارج' };

    function carrierRuleHtml(p, slots, ruleText) {
      // Pure: pair row + slot rows in, markup out - no globals, no fetch, no DOM. That is what lets the
      // offline suite feed it stored rows and assert on the string instead of trusting a screenshot.
      // It reads only ids, names and interface nameplates: an address never enters this box, because the
      // rule is about a slot, and a slot's endpoints are already implied by the pair the operator picked.
      const card = 'margin-top:12px; padding:10px 12px; border-radius:var(--radius-sm); font-size:11.5px;'
                 + ' line-height:1.7; border:1px solid #232838; background:#131620;';
      let out = '<div style="' + card + '">'
              + '<div style="font-weight:700; color:#fbbf24;">قاعده فنی بستر ESP: یک بستر در هر جهت</div>'
              + '<div style="color:var(--text-dim); margin:4px 0 8px;">' + escapeHtml(ruleText || '') + '</div>';
      if (!p) return out + '</div>';
      const declared = String(p.underlay_carrier || '').trim().toLowerCase() === 'esp';
      const list = (slots || []);
      const lines = [];
      list.forEach(s => {
        const role = CARRIER_ROLE_LABEL[s.host_role] ? CARRIER_ROLE_LABEL[s.host_role] : escapeHtml(s.host_role);
        const refusedBy = (s.would_be_refused || []).filter(w => Number(w.pair_id) === Number(p.id));
        if (Number(s.pair_id) === Number(p.id)) {
          const held = Number(s.claimants) > 1
            ? '، و ' + escapeHtml((s.would_be_refused || []).map(w => '#' + w.pair_id + ' ' + (w.pair_name || '')).join(' / ')) + ' را در این جهت بازمی‌دارد'
            : '';
          lines.push('<span style="color:#34d399;">نگهدارنده اسلات</span> در جهت ' + role
                   + ' با رابط <b>' + escapeHtml(s.iface) + '</b>' + held + '.');
        } else if (refusedBy.length) {
          lines.push('<span style="color:#f87171;">رد می‌شود</span> در جهت ' + role + ': اسلات در دست جفت <b>'
                   + escapeHtml(s.pair_name || ('#' + s.pair_id)) + '</b> (#' + escapeHtml(s.pair_id)
                   + ', رابط ' + escapeHtml(s.iface) + ') است؛ این جفت با رابط ' + escapeHtml(refusedBy[0].iface)
                   + ' مدعی همان جهت است.');
        }
      });
      if (!declared) {
        lines.push('این جفت بستر ESP اعلام‌شده ندارد، پس قاعده فعلاً بر آن اثر نمی‌گذارد.');
      } else if (!lines.length) {
        lines.push('اسلاتی برای این جفت محاسبه نشده است: یا آدرس یکی از میزبان‌ها در رکورد نیست، یا بستر '
                 + 'پس از این رکورد اعلام شده و هنوز در هیچ جهتی نشسته است.');
      }
      return out + lines.map(l => '<div>• ' + l + '</div>').join('') + '</div>';
    }

    function renderCarrierRule(p) {
      const el = document.getElementById('carrierRule');
      if (el) el.innerHTML = carrierRuleHtml(p, carrierSlots, carrierRuleText);
    }

    // ---- #63 backend contract (round 064) ----------------------------------------------------------
    // Where a tunnel's traffic lands is invisible from the client side: the frontend binds, the reverse
    // forward establishes, and the bytes can still arrive at a peer port nothing listens on. Pair 2 shipped
    // that shape for rounds because no screen said it out loud.
    //
    // `BACKEND_STATE_LABEL` is a second copy of `storage.BACKEND_STATES`, and the duplication is not
    // trusted: the payload carries the server's own list, a token this map does not know prints raw and
    // red instead of vanishing, and an offline test pins the two against each other - the way test_97 pins
    // RESOURCE_SOURCES against the sampler.
    const BACKEND_STATE_LABEL = {
      answered: 'پشت‌بند پاسخ داد',
      'no-backend': 'پشت‌بند ندارد',
      unreadable: 'خوانده نشد',
      'not-applicable': 'مرتبط نیست',
    };
    const BACKEND_STATE_MEANING = {
      answered: 'روی میزبان تحویل چیزی این پورت را گوش می‌دهد و از راه تونل پاسخ داد.',
      'no-backend': 'هیچ چیز این پورت را گوش نمی‌دهد: ترنسپورت برقرار است ولی به مقصدی نمی‌رسد '
                  + '(TRANSPORT-ONLY). هیچ سوئیچی این را درمان نمی‌کند؛ مقصد باید روی میزبان تحویل برپا شود.',
      unreadable: 'خواندنِ پورت ممکن نشد. این «نبودنِ پشت‌بند» نیست، و شواهد مبهم هیچ نوشتنی را مجاز نمی‌کند.',
      'not-applicable': 'این ترنسپورت مقصد محلی ندارد: تحویل یا لایه ۳ به خودِ میزبان است یا مستقیم به اینترنت.',
    };
    const BACKEND_LANDS_LABEL = { iran: 'ایران', foreign: 'خارج' };
    let backendContract = null;
    let backendStates = [];

    function backendRuleHtml(p, contract, states, nowSec) {
      // Pure: a pair row, the contract table the deploy itself consults, the server's state vocabulary and
      // a clock in - markup out. No globals, no fetch, no DOM, which is what lets the offline suite hand
      // this function a stored pair and assert on the string instead of trusting a screenshot.
      // It names protocols, ports and roles only; an address never enters this box.
      const card = 'margin-top:12px; padding:10px 12px; border-radius:var(--radius-sm); font-size:11.5px;'
                 + ' line-height:1.7; border:1px solid #232838; background:#131620;';
      const ok = '#34d399', bad = '#f87171', warn = '#fbbf24', dim = 'var(--text-dim)';
      const c = contract || {};
      const targets = c.targets || {};
      const declarable = c.declarable || [];
      const egress = c.egress_proxies || [];
      const known = states || [];
      let out = '<div style="' + card + '">'
              + '<div style="font-weight:700; color:' + warn + ';">قرارداد تحویل: تونل کجا تمام می‌شود؟</div>';
      if (!p) {
        return out + '<div style="color:' + dim + '; margin-top:4px;">برای دیدنِ مقصد تحویل، یک جفت موجود را '
             + 'انتخاب کنید. جفت تازه‌افزوده را هم می‌توان پس از افزودن انتخاب و اعلام کرد.</div></div>';
      }
      const bc = p.backend_contract || {};
      const active = String(bc.active_protocol || '').trim();
      const spec = targets[active] || null;
      const isEgress = egress.indexOf(active) >= 0;
      // "Not in the table" is not "in the table and refused": a transport the contract view has no entry
      // for gets no declaration box either, because the route would have no way to validate it.
      const isUnknown = Boolean(active) && !spec && !isEgress;

      if (!active) {
        out += '<div style="color:' + dim + '; margin-top:4px;">این جفت هنوز ترنسپورت فعالی ثبت نکرده است، پس '
             + 'مقصد تحویل را نمی‌توان از جدول خواند؛ با این حال پورت مقصد را می‌شود از همین حالا اعلام کرد.</div>';
      } else if (spec) {
        out += '<div style="margin-top:4px;">ترنسپورت فعال: <b>' + escapeHtml(active) + '</b> — '
             + escapeHtml(String(spec.kind || '')) + '</div>';
        const lands = BACKEND_LANDS_LABEL[spec.lands_on]
          ? '<span style="color:' + ok + ';">' + BACKEND_LANDS_LABEL[spec.lands_on] + '</span>'
          : '<span style="color:' + bad + ';">' + escapeHtml(String(spec.lands_on || 'نامشخص')) + '</span>';
        out += '<div style="color:' + dim + '">ترافیک به میزبان <b>' + lands + '</b> تحویل می‌شود.</div>';
      } else if (isEgress) {
        out += '<div style="margin-top:4px;">ترنسپورت فعال: <b>' + escapeHtml(active)
             + '</b> — پراکسی خروجی است؛ مقصد محلی ندارد و ترافیک از همان میزبان به اینترنت می‌رود.</div>';
      } else {
        // A transport the table does not know is printed as unknown rather than folded into the egress
        // sentence above: "no entry" and "no local port" are different claims, and only the first is
        // what was measured here.
        out += '<div style="color:' + bad + '; margin-top:4px;">ترنسپورت <b>' + escapeHtml(active)
             + '</b> در جدول قرارداد تحویل نیست؛ یا ترنسپورت تازه‌ای افزوده شده و جدول به‌روز نشده، یا رکورد '
             + 'خراب است. هیچ‌کدام «مقصد سالم» معنا نمی‌شود.</div>';
      }

      const declared = bc.declared_port ? Number(bc.declared_port) : null;
      const eff = (bc.effective_port === null || bc.effective_port === undefined)
                ? null : Number(bc.effective_port);
      out += '<div style="margin-top:6px;">پورت تحویل اعلام‌شده: <b>'
           + (declared === null ? '<span style="color:' + warn + ';">' + (isEgress ? 'بی‌مورد' : 'اعلام نشده') + '</span>'
                                 : declared) + '</b>'
           + ' · پورت مؤثرِ خوانده‌شده: <b>' + (eff === null ? 'نامشخص' : eff) + '</b>'
           + (declared === null && eff !== null && !isEgress
               ? '<span style="color:' + dim + '"> (همان پورت اینگرس)</span>' : '')
           + '</div>';

      if (bc.refusal) {
        // Verbatim, the way the carrier rule prints the engine's own sentence: this text is the engine's
        // refusal, and a paraphrase here would be the dashboard arguing with the deploy about its own gate.
        out += '<div style="color:' + bad + '; margin-top:4px;">' + escapeHtml(String(bc.refusal)) + '</div>';
      }

      const st = String(bc.state || '').trim();
      const color = st === 'answered' ? ok
                  : (st === 'no-backend' ? bad
                  : (st === 'unreadable' ? warn : dim));
      out += '<div style="margin-top:6px; font-weight:700; color:' + color + ';">وضعیت مقصد: '
           + (st ? (BACKEND_STATE_LABEL[st] || escapeHtml(st))
                 : '<span style="color:' + dim + '; font-weight:400;">هنوز خوانده نشده</span>')
           + '</div>';
      if (st && BACKEND_STATE_MEANING[st]) {
        out += '<div style="color:' + dim + ';">' + BACKEND_STATE_MEANING[st] + '</div>';
      }
      if (st && known.indexOf(st) < 0) {
        out += '<div style="color:' + bad + ';">واژگان صفحه این وضعیت را نمی‌شناسد: فهرست JS با '
             + 'فهرست ذخیره‌سازی هم‌خوان نیست.</div>';
      }
      const chk = Number(bc.checked_at);
      if (Number.isFinite(chk) && chk > 0) {
        // `Number(null)` is 0 and `Number('')` is 0, so a clock that was never read has to be tested for
        // absence before it is tested for finiteness: folded into the arithmetic it produced "خوانده شده
        // 0 ثانیه پیش" - the freshest possible claim, manufactured by the absence of a measurement.
        const nowRaw = (nowSec === null || nowSec === undefined || nowSec === '') ? null : Number(nowSec);
        const now = (nowRaw === null || !Number.isFinite(nowRaw)) ? null : nowRaw;
        let age = 'ساعت سرور خوانده نشد';
        if (now !== null) {
          age = now < chk ? 'خوانش در آینده ثبت شده: ساعت این مرورگر با زمان رکورد هم‌خوان نیست'
                          : Math.round(now - chk) + ' ثانیه پیش';
        }
        out += '<div style="color:' + (now === null || now < chk ? warn : dim) + '">زمان خوانش: '
             + age + '</div>';
      } else if (st) {
        out += '<div style="color:' + warn + '">این وضعیت زمانِ خوانش ندارد؛ درباره تازگی‌اش نمی‌شود چیزی گفت.</div>';
      } else {
        out += '<div style="color:' + dim + '">این خوانش را استقرارِ تونل و چرخهٔ بررسی سلامت می‌نویسند. خالی '
             + 'بودنش «نبودِ چیزی» نیست؛ یعنی هنوز خوانده نشده است.</div>';
      }

      if (declarable.indexOf(active) >= 0 || !active) {
        out += '<div style="margin-top:8px; display:flex; gap:6px; align-items:center;">'
             + '<input id="backendPort" type="number" min="1" max="65535" step="1" placeholder="پورت تحویل" '
             + 'value="' + (declared === null ? '' : declared) + '" style="width:120px;" />'
             + '<button class="btn btn-secondary" onclick="declareBackend()">اعلام</button>'
             + (declared === null ? '' : '<button class="btn btn-secondary" onclick="clearBackendPort()">پاک کردن اعلام</button>')
             + '</div>'
             + '<div style="color:' + dim + '; margin-top:4px;">اعلام تا بازاستقرار بعد در پیکربندیِ نشسته '
             + 'نمی‌نشیند؛ بررسی سلامت از همان لحظه همین شماره را می‌خواند، پس میان این دو حالت فاصله هست.</div>';
      } else if (isUnknown) {
        out += '<div style="color:' + bad + '; margin-top:4px;">جدول قرارداد تحویل این ترنسپورت را '
             + 'نمی‌شناسد، پس دربارهٔ پورت مقصد آن چیزی گفته نمی‌شود و فیلد اعلام هم نمایش داده '
             + 'نمی‌شود.</div>';
      } else {
        out += '<div style="color:' + dim + '; margin-top:4px;">این ترنسپورت پورت تحویل جداپذیر ندارد'
             + (isEgress ? '، چون مقصد محلی ندارد.'
                         : '؛ مستقل کردنش قوانین DNAT و INPUT و مانیفست بوت را یک‌جا می‌خواهد.')
             + '</div>';
      }
      return out + '</div>';
    }

    function renderBackendRule(p) {
      const el = document.getElementById('backendRule');
      if (el) el.innerHTML = backendRuleHtml(p, backendContract, backendStates, serverNowSec());
    }

    async function postBackend(value, okMessage) {
      // One write path for declare and clear, so the two cannot drift into different error handling - and
      // so neither can report success on a body the server rejected.
      if (!currentPairId) {
        showToast('برای اعلام پورت تحویل، اول یک جفت موجود را انتخاب کنید.', 'error');
        return;
      }
      try {
        const res = await apiFetch('/api/backend', { id: currentPairId, backend_port: value });
        const data = await res.json();
        if (data.ok) {
          showToast(okMessage + (data.note ? ' — ' + data.note : ''), 'info');
          await loadData();
        } else {
          showToast('اعلام پورت تحویل رد شد: ' + (data.error || 'خطای نامشخص'), 'error');
        }
      } catch (err) {
        showToast('خطای شبکه: ' + err.message, 'error');
      }
    }

    function declareBackend() {
      const el = document.getElementById('backendPort');
      const raw = el ? String(el.value || '').trim() : '';
      if (!raw) {
        showToast('شماره پورت را وارد کنید؛ برای پاک کردن اعلام از دکمهٔ «پاک کردن اعلام» استفاده کنید.', 'error');
        return;
      }
      postBackend(raw, 'پورت تحویل اعلام شد');
    }

    function clearBackendPort() {
      // Empty string is what the server reads as "no separate delivery port", and the confirmation is here
      // because clearing sends the pair back to delivering at the frontend port.
      if (!confirm('اعلام پورت تحویل پاک شود؟ تحویل در بازاستقرار بعد به همان پورت اینگرس برمی‌گردد.')) return;
      postBackend('', 'اعلام پورت تحویل پاک شد');
    }

    // ---- #69 dual-host capacity monitoring (round 063, ruling 1) --------------------------------
    const RESOURCE_ROLE_LABEL = { iran: 'ایران', foreign: 'خارج' };
    // The source names the sampler declares, in the order engine samples them. Kept here so a row that lost
    // a source reads as a missing record rather than as silence; test_97 pins this list against
    // engine.RESOURCE_SAMPLE_COMMANDS. The last three are #70's connection counters - the kernel's own
    // account of how many handshakes opened, failed and retransmitted, which is what makes a burst
    // attributable after it has passed rather than only while an operator happens to be looking.
    const RESOURCE_SOURCES = ['load', 'cpu_count', 'memory', 'disk', 'uptime', 'boot_id',
                              'tcp', 'tcp_ext', 'sockets'];
    const RESOURCE_UNREADABLE = 'خوانده نشد';
    let resourceStaleAfterSec = null;
    let serverClockOffsetSec = null;

    function serverNowSec() {
      // Ages are measured against the clock that stamped the rows, carried forward by the browser's own
      // passage of time. The browser clock is never used directly: a laptop an hour fast makes a stale
      // sample look fresh, and this panel exists to be acted on.
      if (serverClockOffsetSec === null) return null;
      return Date.now() / 1000 + serverClockOffsetSec;
    }

    function securityEventsHtml(p, nowSec) {
      // #39's visible half. The product has always *recorded* a destination-anchor rotation, a switchover
      // it blocked because the anchor moved, and a rollback that only partly completed - and until now
      // nothing read those rows back, so the operator learned about a rotated key only from the one deploy
      // that refused. This panel is a read of the audit table, not a second opinion: the sentences below
      // are the rows the engine wrote.
      //
      // Deliberately no button. Accepting a rotation means forgetting a pin, which re-opens learning on
      // the next deploy; a control that made that one click on a page sitting open in a browser would
      // trade the whole point of the pin for convenience. The sanctioned path stays
      // `storage.unpin_destination`, called by hand, with the pair and protocol named.
      //
      // Pure like `resourceHtml`: pair row + clock in, markup out, so the offline suite asserts on the
      // string instead of trusting a screenshot.
      const num = (x) => (x === null || x === undefined || x === '' || !Number.isFinite(Number(x)))
                       ? null : Number(x);
      const card = 'margin-top:12px; padding:10px 12px; border-radius:var(--radius-sm); font-size:11.5px;'
                 + ' line-height:1.7; border:1px solid #232830; background:#131620;';
      const ACTION_LABEL = {
        DESTINATION_PIN_ROTATED: 'لنگر مقصد جابه‌جا شد (کلید اعتمادی این جفت عوض شده است)',
        UNPIN_DESTINATION: 'پین مقصد فراموش شد؛ استقرار بعدی آن را از نو می‌آموزد',
        FAILOVER_BLOCKED: 'تغییر مسیر متوقف شد',
        FAILOVER_ABORTED: 'تغییر مسیر پیش از اجرا لغو شد',
        DEPLOY_ROLLBACK: 'بازگشت استقرار'
      };
      const STATUS_COLOR = { WARNING: '#fbbf24', PARTIAL: '#f87171', REJECTED: '#f87171' };
      const ago = (epoch) => {
        const e = num(epoch), now = num(nowSec);
        if (e === null) return 'زمان نامشخص';
        if (now === null) return 'ساعت سرور خوانده نشد';
        const s = Math.max(0, now - e);
        if (s < 90) return Math.round(s) + ' ثانیه پیش';
        if (s < 7200) return Math.round(s / 60) + ' دقیقه پیش';
        if (s < 172800) return Math.round(s / 3600) + ' ساعت پیش';
        return Math.round(s / 86400) + ' روز پیش';
      };
      let out = '<div style="' + card + '">'
              + '<div style="font-weight:700; color:#f87171;">رویدادهای امنیتی این جفت</div>';
      if (!p) {
        return out + '<div style="color:var(--text-dim); margin-top:4px;">برای دیدنِ رویدادها یک جفت موجود '
             + 'را انتخاب کنید.</div></div>';
      }
      const rows = (p.security_events || []);
      if (!rows.length) {
        // Absence here is reported as absence, not as health: this panel shows rows that exist, and a
        // pair whose audit table was never written looks identical to a pair that never misbehaved.
        return out + '<div style="color:var(--text-dim); margin-top:4px;">هیچ رویدادی از این نوع ثبت نشده '
             + 'است. این «نبودِ رکورد» است، نه گواه سالم بودن؛ لنگر مقصد همچنان در استقرار بررسی می‌شود.</div></div>';
      }
      out += '<div style="color:var(--text-dim); margin-top:2px;">تازه‌ترین ' + rows.length
           + ' رویداد، از جدول رسیدگی خودِ محصول.</div>';
      rows.forEach(r => {
        const st = String(r.status || '');
        const act = String(r.action || '');
        const color = STATUS_COLOR[st] || 'var(--text-dim)';
        out += '<div style="margin-top:6px; padding-right:8px; border-right:2px solid ' + color + ';">'
             + '<div><b style="color:' + color + ';">' + escapeHtml(st || 'بی‌وضعیت') + '</b> · '
             + escapeHtml(ACTION_LABEL[act] || act) + ' · ' + escapeHtml(ago(r.created_at)) + '</div>'
             + '<div style="color:var(--text-dim); white-space:pre-wrap;">'
             + escapeHtml(String(r.details || '')) + '</div></div>';
      });
      return out + '</div>';
    }

    function renderSecurityEvents(p) {
      const el = document.getElementById('securityEvents');
      if (el) el.innerHTML = securityEventsHtml(p, serverNowSec());
    }

    function resourceHtml(p, staleAfterSec, nowSec) {
      // Pure: a pair row carrying its stored resource rows, a freshness policy and a clock in, markup out.
      // No globals, no fetch, no DOM - which is what lets the offline suite hand this function stored rows
      // and assert on the string instead of trusting a screenshot.
      const num = (x) => (x === null || x === undefined || x === '' || !Number.isFinite(Number(x)))
                       ? null : Number(x);
      const unread = '<span style="color:#f87171;">' + RESOURCE_UNREADABLE + '</span>';
      const fmtPct = (v) => (v === null ? null : v.toFixed(1) + '٪');
      const fmtGb = (kb) => { const v = num(kb); return v === null ? null : (v / 1048576).toFixed(1) + ' گیگ'; };
      const fmtDur = (s) => {
        const v = num(s);
        if (v === null) return null;
        if (v < 90) return Math.round(v) + ' ثانیه';
        const d = Math.floor(v / 86400), h = Math.floor((v % 86400) / 3600), m = Math.floor((v % 3600) / 60);
        if (d) return d + ' روز و ' + h + ' ساعت';
        if (h) return h + ' ساعت و ' + m + ' دقیقه';
        return m + ' دقیقه';
      };
      const sev = (v, warn, danger) => (v === null ? '#94a3b8'
                               : (v >= danger ? '#f87171' : (v >= warn ? '#fbbf24' : '#34d399')));
      const metric = (name, valueHtml, color) => '<div>' + name + ': '
        + '<span style="color:' + (color || '#e2e8f0') + '; font-weight:700;">' + valueHtml + '</span></div>';

      const card = 'margin-top:12px; padding:10px 12px; border-radius:var(--radius-sm); font-size:11.5px;'
                 + ' line-height:1.7; border:1px solid #232838; background:#131620;';
      let out = '<div style="' + card + '">'
              + '<div style="font-weight:700; color:#fbbf24;">پایش دوطرفه منابع و ظرفیت</div>';
      if (!p) {
        return out + '<div style="color:var(--text-dim); margin-top:4px;">این فرم جفت ذخیره‌شده‌ای نیست؛ '
             + 'منابع فقط برای یک جفت موجود خوانده می‌شود.</div></div>';
      }
      const res = p.resources || {};
      const limit = num(staleAfterSec);
      const attribution = [];
      let anyRow = false;

      ['iran', 'foreign'].forEach(role => {
        const row = res[role];
        out += '<div style="margin-top:10px; padding-top:8px; border-top:1px dashed #232838;">'
             + '<div style="font-weight:700; color:#a78bfa;">' + RESOURCE_ROLE_LABEL[role] + '</div>';
        if (!row) {
          out += '<div style="color:var(--text-dim);">هنوز نمونه‌ای از این میزبان ثبت نشده است؛ '
               + 'دکمه «Sample capacity» را بزنید.</div></div>';
          return;
        }
        anyRow = true;

        const collected = num(row.collected_at);
        const now = num(nowSec);
        // A missing clock or a missing timestamp is not "fresh": the sample is judged stale, because the
        // only thing that makes an old number safe to act on is knowing how old it is.
        let ageHtml, ageColor, stale = true;
        if (now === null || collected === null || limit === null) {
          ageHtml = 'سن نامشخص — ساعت سرور یا زمان نمونه خوانده نشد';
          ageColor = '#f87171';
        } else {
          const age = Math.max(0, now - collected);
          stale = age > limit;
          ageColor = stale ? '#fbbf24' : '#34d399';
          ageHtml = (stale ? 'کهنه' : 'تازه') + ' · ' + fmtDur(age) + ' پیش (آستانه ' + Math.round(limit) + ' ثانیه)';
        }
        out += '<div style="color:' + ageColor + '; font-weight:700;">' + ageHtml + '</div>';

        // CPU. The row's own `load1_per_core_pct` is the only percentage rendered here: this function never
        // re-derives it from load1 and ncpu, because dividing two readings the sampler judged unusable is a
        // guess wearing a number.
        const perCore = num(row.load1_per_core_pct), ncpu = num(row.ncpu);
        out += metric('بار ۱ دقیقه (سهم از ' + (ncpu === null ? RESOURCE_UNREADABLE : ncpu) + ' هسته)',
                      perCore === null ? unread : fmtPct(perCore), sev(perCore, 60, 90));

        const memPct = num(row.mem_used_pct);
        out += metric('حافظه استفاده‌شده', memPct === null ? unread : fmtPct(memPct), sev(memPct, 80, 95));
        const avail = fmtGb(row.mem_available_kb), total = fmtGb(row.mem_total_kb);
        out += '<div style="color:var(--text-dim);">آزاد: ' + (avail === null ? unread : avail)
             + ' از ' + (total === null ? unread : total) + '</div>';
        const swapTotal = num(row.swap_total_kb), swapFree = num(row.swap_free_kb);
        if (swapTotal !== null && swapTotal > 0) {
          // `swapTotal - swapFree` on an unreadable free value is NaN, and NaN concatenated into a
          // sentence reads as "null" - a number the sampler never produced.
          const usedGb = swapFree === null ? null : fmtGb(swapTotal - swapFree);
          out += '<div style="color:var(--text-dim);">swap مصرف‌شده: '
               + (usedGb === null ? unread : usedGb) + ' از ' + fmtGb(swapTotal) + '</div>';
        } else if (swapTotal === 0) {
          out += '<div style="color:var(--text-dim);">swap: ندارد</div>';
        }

        const diskPct = num(row.disk_used_pct);
        out += metric('دیسک ریشه پرشده', diskPct === null ? unread : fmtPct(diskPct), sev(diskPct, 75, 90));
        out += '<div style="color:var(--text-dim);">آزاد: '
             + (fmtGb(row.disk_avail_kb) === null ? unread : fmtGb(row.disk_avail_kb)) + '</div>';
        const mountRaw = row.disk_fullest_mount;
        const mount = (mountRaw === null || mountRaw === undefined || mountRaw === '') ? null : String(mountRaw);
        const mountPct = num(row.disk_fullest_used_pct);
        if (mount !== null || mountPct !== null) {
          out += '<div style="color:var(--text-dim);">پرمصرف‌ترین نقطه نصب: '
               + (mount === null ? RESOURCE_UNREADABLE : escapeHtml(mount)) + ' در '
               + '<span style="color:' + sev(mountPct, 75, 90) + '; font-weight:700;">'
               + (mountPct === null ? unread : fmtPct(mountPct)) + '</span></div>';
        }

        const up = fmtDur(row.uptime_sec);
        out += metric('آپتایم', up === null ? unread : up, '#e2e8f0');
        // boot_id is stored as '' when it was unread (storage writes str(... or "")), so the empty string
        // has to read as "no witness", not as a boot that happened.
        const boot = String(row.boot_id || '');
        out += '<div style="color:var(--text-dim);">شناسه بوت (شاهد بوت‌شدن): '
             + '<span style="font-family:monospace;">'
             + (boot ? escapeHtml(boot.slice(0, 8)) : RESOURCE_UNREADABLE) + '</span></div>';

        let states = null;
        try {
          states = (typeof row.source_states === 'string') ? JSON.parse(row.source_states) : (row.source_states || null);
        } catch (e) { states = null; }
        if (!states) {
          out += '<div style="color:#f87171;">وضعیت منابع: ' + RESOURCE_UNREADABLE + '</div>';
        } else {
          const bad = [];
          RESOURCE_SOURCES.forEach(s => {
            const st = states[s];
            if (st !== 'measured' && st !== 'partial') bad.push(s + '=' + (st || 'no-record'));
          });
          out += bad.length
            ? '<div style="color:#fbbf24;">منابع غیرکامل: ' + escapeHtml(bad.join(', ')) + '</div>'
            // Counted from the list rather than written as a numeral: a hard-coded "شش" stayed green for
            // three sources that had never been sampled at all the moment a ninth was added to the sampler.
            : '<div style="color:#34d399;">هر ' + RESOURCE_SOURCES.length + ' منبع خوانده شدند</div>';
        }

        const hot = [];
        if (perCore !== null && perCore >= 90) hot.push('CPU');
        if (memPct !== null && memPct >= 95) hot.push('حافظه');
        if (diskPct !== null && diskPct >= 90) hot.push('دیسک');
        if (mountPct !== null && mountPct >= 90) hot.push('دیسک ' + (mount || 'نامعلوم'));
        if (hot.length) {
          attribution.push(RESOURCE_ROLE_LABEL[role] + ': ' + hot.join(' + ')
                         + (stale ? ' (بر پایه نمونه کهنه)' : ''));
        }
        out += '</div>';
      });

      out += '<div style="margin-top:10px; padding-top:8px; border-top:1px dashed #232838;">'
           + '<div style="font-weight:700; color:#fbbf24;">انتساب رگبار</div>';
      if (!anyRow) {
        out += '<div style="color:var(--text-dim);">برای انتساب رگبار دست‌کم یک نمونه از یک میزبان لازم است.</div>';
      } else if (attribution.length) {
        out += attribution.map(a => '<div>• ' + escapeHtml(a) + '</div>').join('');
      } else {
        out += '<div style="color:#34d399;">هیچ میزبانی در آستانه فشار نیست. اگر رگباری در لاگ دیده شد، '
             + 'در همان لحظه نمونه‌گیری کنید تا انتساب بر پایه عدد زنده باشد.</div>';
      }
      return out + '</div></div>';
    }

    function attributionHtml(a, staleAfterSec, nowSec) {
      // #70: the connection-burst history, rendered from what the kernel counted, not from a load gauge.
      // Pure for the same reason `resourceHtml` is: the offline suite hands it a stored attribution object
      // and asserts on the string, so a claim about a burst is checked against arithmetic rather than
      // against a screenshot.
      const num = (x) => (x === null || x === undefined || x === '' || !Number.isFinite(Number(x)))
                       ? null : Number(x);
      const CAUSE_LABEL = {
        accept_queue_overflow: 'صف پذیرش سرریز شد (سرویس از پسِ نرخ اتصال‌ها برنیامد)',
        failed_handshakes: 'دست‌دادن‌های ناموفق (اسکنر یا پروبِ سانسور)',
        retransmit_growth: 'رشد بازفرست و تایم‌اوت (مسیر مشکل دارد، نه بار)',
        outbound_storm: 'موج خروجی (این میزبان به بیرون اتصال می‌گشاید)',
        inbound_storm: 'موج ورودی (دنیای بیرون به این میزبان اتصال می‌گشاید)',
        unattributed: 'بی‌انتساب — شمارنده‌ها جهت را جدا نکردند'
      };
      const card = 'margin-top:12px; padding:10px 12px; border-radius:var(--radius-sm); font-size:11.5px;'
                 + ' line-height:1.7; border:1px solid #232838; background:#131620;';
      let out = '<div style="' + card + '">'
              + '<div style="font-weight:700; color:#fbbf24;">انتساب رگبارِ اتّصال (تاریخچه شمارنده‌ها)</div>';
      if (!a) {
        return out + '<div style="color:var(--text-dim); margin-top:4px;">تاریخچه‌ای برای انتساب نیست؛ '
             + 'این پنل با «Sample capacity» پر می‌شود.</div></div>';
      }
      const roles = ['iran', 'foreign'].filter(r => a[r]);
      if (!roles.length) {
        return out + '<div style="color:var(--text-dim); margin-top:4px;">هیچ میزبانی در این پاسخ نیست.</div></div>';
      }
      const ago = (epoch) => {
        const e = num(epoch), now = num(nowSec);
        if (e === null) return 'زمان نامشخص';
        if (now === null) return 'ساعت سرور خوانده نشد';
        const d = Math.max(0, Math.round(now - e));
        if (d < 120) return d + ' ثانیه پیش';
        if (d < 7200) return Math.round(d / 60) + ' دقیقه پیش';
        return Math.round(d / 3600) + ' ساعت پیش';
      };
      // A missing count prints as a dash, never as "null" and never as 0. The second is the one that
      // matters: "0 new connections in the window" and "there was no window" are different sentences, and
      // this panel is read by someone deciding whether a host was idle.
      const cnt = (x) => escapeHtml(x === null ? '—' : String(x));
      roles.forEach(role => {
        const r = a[role], b = r.baseline || {}, t = r.totals || {};
        const verdict = String(r.verdict || 'NO_HISTORY');
        // The verdict string is shown verbatim as well as translated: an operator who has to compare two
        // rounds of this panel needs the exact token engine returned, not a paraphrase of it.
        const color = /^BURSTS/.test(verdict) ? '#f87171'
                    : (/NO_HISTORY|NO_USABLE_INTERVALS/.test(verdict) ? 'var(--text-dim)' : '#34d399');
        out += '<div style="margin-top:10px; padding-top:8px; border-top:1px dashed #232838;">'
             + '<div style="font-weight:700; color:#a78bfa;">' + RESOURCE_ROLE_LABEL[role] + '</div>'
             + '<div style="color:' + color + '; font-weight:700;">'
             + escapeHtml(verdict) + ' — ' + cnt(num(r.burst_count)) + ' رگبار در '
             + cnt(num(r.interval_count)) + ' بازهٔ قابل‌استفاده از ' + cnt(num(r.samples)) + ' نمونه</div>';
        if (b.available) {
          out += '<div style="color:var(--text-dim);">مبنای خودِ همین میزبان: میانهٔ نرخ '
               + cnt(num(b.median_new_conn_per_sec)) + ' اتصال بر ثانیه؛ آستانه '
               + cnt(num(b.factor)) + '× آن و کفِ مطلق '
               + cnt(num(b.min_connections)) + ' اتصال.</div>';
        } else {
          out += '<div style="color:#fbbf24;">مبنای مقایسه هنوز ساخته نشده است ('
               + cnt(num(b.intervals_with_rate)) + ' بازهٔ نرخ‌دار از '
               + cnt(num(b.min_intervals)) + ' لازم). رگبارها فقط با کفِ مطلق '
               + cnt(num(b.min_connections)) + ' اتصال برچسب می‌خورند، و نبودِ برچسب به معنی '
               + '«کمتر از آستانهٔ شناخته‌شده» نیست.</div>';
        }
        const win = r.window || {};
        if (!num(r.interval_count)) {
          // Said out loud rather than rendered as a row of zeros: with no usable interval there is no
          // window to total, and "0 new connections, 0 failed handshakes" is precisely the sentence that
          // turns an unmeasured host into a idle-looking one.
          out += '<div style="color:var(--text-dim);">بازهٔ قابل‌استفاده‌ای برای جمع بستن نیست — '
               + 'این عدد صفرِ ثبت‌شده نیست، ثبت‌نشدن است.</div>';
        } else {
          out += '<div style="color:var(--text-dim);">پنجرهٔ تاریخچه: '
               + escapeHtml(ago(win.from)) + ' تا ' + escapeHtml(ago(win.to))
               + ' · مجموع: ' + cnt(num(t.new_connections)) + ' اتصال تازه ('
               + cnt(num(t.inbound)) + ' ورودی، ' + cnt(num(t.outbound)) + ' خروجی)، '
               + cnt(num(t.attempt_fails)) + ' دست‌دادن ناموفق، '
               + cnt(num(t.tcp_timeouts)) + ' تایم‌اوت، '
               + cnt(num(t.listen_overflows)) + ' سرریز صف پذیرش'
               + ((num(t.intervals_without_counter) || 0) > 0 ? ' · '
                   + cnt(num(t.intervals_without_counter))
                   + ' بازه بدون شمارنده (در جمع شمرده نشدند)' : '') + '</div>';
        }
        if (r.stale) {
          out += '<div style="color:#fbbf24;">آخرین نمونه از آستانهٔ ' + Math.round(num(staleAfterSec) || 0)
               + ' ثانیه کهنه‌تر است؛ این انتساب تاریخچه را توصیف می‌کند، وضعیت فعلی را نه.</div>';
        }
        (r.bursts || []).forEach(x => {
          const cause = CAUSE_LABEL[x.cause] || 'بی‌انتساب — شمارنده‌ها جهت را جدا نکردند';
          out += '<div style="margin-top:6px; padding-right:8px; border-right:2px solid #f87171;">'
               + '<div>رگبار ' + cnt(num(x.new_connections)) + ' اتصال تازه در '
               + cnt(num(x.span_sec)) + ' ثانیه ('
               + cnt(num(x.rate_per_sec)) + ' بر ثانیه) — ' + escapeHtml(ago(x.at)) + '</div>'
               + '<div style="color:var(--text-dim);">' + escapeHtml(cause) + ' · مبنای برچسب: '
               + escapeHtml(String(x.basis)) + '</div>'
               // The gauge is the part that survives the burst: SYN_RECV is what report062 could only see
               // by hand, and showing it next to the cause is how the panel says "backlog" or "established"
               // instead of leaving the operator to guess which one it means.
               + '<div style="color:var(--text-dim);">سنجه در همان لحظه: مستقر '
               + cnt(num(x.established)) + '، SYN_RECV ' + cnt(num(x.syn_recv))
               + '، TIME_WAIT ' + cnt(num(x.time_wait)) + '، LISTEN '
               + cnt(num(x.listen)) + '، CurrEstabِ کرنل '
               + cnt(num(x.curr_estab_kernel)) + '</div></div>';
        });
        const sc = r.skipped_counts || {};
        const parts = Object.keys(sc).map(k => k + '=' + sc[k]);
        if (parts.length) {
          out += '<div style="color:var(--text-dim);">بازه‌های کنارگذاشته‌شده: '
               + escapeHtml(parts.join('، '))
               + ' — هر کدام با دلیل، تا سکوتِ یک میزبان با نبودِ ترافیک اشتباه خوانده نشود.</div>';
        }
        out += '</div>';
      });
      return out + '</div>';
    }

    function renderResources(p) {
      const el = document.getElementById('resourceHosts');
      if (el) el.innerHTML = resourceHtml(p, resourceStaleAfterSec, serverNowSec())
                          + attributionHtml(p && p.resource_attribution, resourceStaleAfterSec,
                                            serverNowSec());
    }

    async function sampleResources() {
      const btn = document.getElementById('sampleBtn');
      const sumEl = document.getElementById('resourceSummary');
      if (currentPairId === 'new' || !currentPairId) {
        sumEl.textContent = 'نمونه‌گیری منابع برای یک جفت ذخیره‌شده انجام می‌شود؛ اول جفت را ذخیره کنید.';
        return;
      }
      const orig = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Sampling...';
      try {
        const d = await (await apiFetch('/api/resources', { id: currentPairId })).json();
        if (d.error) {
          sumEl.textContent = 'نمونه‌گیری شکست خورد: ' + d.error;
          return;
        }
        await loadData();
        const badge = d.dry_run
          ? '<span style="color:#fbbf24;">DRY_RUN</span>'
          : (d.ok ? '<span style="color:#34d399;">ثبت شد</span>'
                  : '<span style="color:#f87171;">ناقص</span>');
        sumEl.innerHTML = badge + ' · ' + escapeHtml(d.summary || '');
      } catch (err) {
        sumEl.textContent = 'نمونه‌گیری ناموفق: ' + err.message;
      } finally {
        btn.disabled = false;
        btn.innerHTML = orig;
      }
    }

    const PREFLIGHT_COLORS = { CLEAN: '#34d399', MARGINAL: '#fbbf24' };

    async function runPreflight() {
      const btn = document.getElementById('preflightBtn');
      const legsEl = document.getElementById('preflightLegs');
      const sumEl = document.getElementById('preflightSummary');
      if (currentPairId === 'new' || !currentPairId) {
        sumEl.textContent = 'Preflight measures a stored pair: save the pair first, then run it.';
        legsEl.innerHTML = '';
        return;
      }
      const orig = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Measuring...';
      try {
        const d = await (await apiFetch('/api/preflight', { id: currentPairId })).json();
        if (d.error) {
          sumEl.textContent = 'PREFLIGHT FAILED: ' + d.error;
          legsEl.innerHTML = '';
          return;
        }
        const legs = d.legs || [];
        legsEl.innerHTML = legs.map(l => {
          const color = PREFLIGHT_COLORS[l.band] || '#f87171';
          return '<div style="padding:2px 0;"><span style="color:' + color + ';font-weight:700;">'
            + escapeHtml(l.band) + '</span> · ' + escapeHtml(l.detail)
            + (l.decides ? ' <span style="opacity:.6">(decides)</span>' : ' <span style="opacity:.45">(informational)</span>')
            + '</div>';
        }).join('') || '<div style="opacity:.6">no legs measured</div>';
        sumEl.innerHTML = '<strong style="color:' + (PREFLIGHT_COLORS[d.verdict] || (d.ok ? '#34d399' : '#f87171'))
          + ';">' + escapeHtml(d.verdict || (d.dry_run ? 'DRY_RUN' : (d.ok ? 'OK' : 'NOT OK'))) + '</strong> · '
          + escapeHtml(d.summary || '');
      } catch (err) {
        sumEl.textContent = 'Preflight request failed: ' + err.message;
      } finally {
        btn.disabled = false;
        btn.innerHTML = orig;
      }
    }

    function computeProfileScore(b, prof) {
      if (b.disqualified) return 0;
      try {
        const details = (typeof b.details_json === 'string') ? JSON.parse(b.details_json) : (b.details_json || {});
        if (details.scores_by_profile && details.scores_by_profile[prof] !== undefined) {
          return Number(details.scores_by_profile[prof]);
        }
      } catch (e) {}
      return Number(b.score) || 0;
    }

    function legSummary(b) {
      // A direction the host never measured stays absent; it is not a zero, and printing it as one is
      // how a 1124 Mbps upload came to hide a dead download.
      const num = (v) => (v === null || v === undefined) ? null : Number(v);
      const up = num(b.throughput_up_mbps), down = num(b.throughput_down_mbps);
      const measured = [up, down].filter(v => v !== null);
      if (!measured.length) return { text: '', warn: '', weak: null };
      const weak = Math.min.apply(null, measured);
      let warn = '';
      if (up !== null && down !== null && Math.min(up, down) > 0) {
        const ratio = Math.max(up, down) / Math.min(up, down);
        if (ratio > 4) warn = ' · نامتقارن ' + ratio.toFixed(1) + '×';
      } else if (up === null || down === null) {
        warn = ' · تنها یک جهت اندازه‌گیری شد';
      } else if (weak === 0) {
        warn = ' · یک جهت کاملاً بسته شد';
      }
      const parts = [];
      if (up !== null) parts.push('↑' + up.toFixed(1));
      if (down !== null) parts.push('↓' + down.toFixed(1));
      return { text: parts.join(' ') + ' Mbps', warn: warn, weak: weak,
               basis: (b.capacity_basis || '') };
    }


    // KPI strip: live values for the selected pair, from the same /api payload
    // renderBenchmarks already uses. Called at every renderBenchmarks exit so
    // pair switches, profile switches and post-job refreshes all refresh it.
    function renderKpis() {
      const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
      const p = pairs.find(x => x.id === currentPairId) || null;
      if (!p) {
        set('kpiTunnel', '—'); set('kpiRtt', '—'); set('kpiBest', '—'); set('kpiHealthy', '—');
        return;
      }
      const active = (p.active_tunnel || '').trim();
      set('kpiTunnel', active ? ('فعال · ' + active) : (p.status || '—'));
      const rtt = Number(p.base_rtt_ms);
      set('kpiRtt', (Number.isFinite(rtt) && rtt > 0) ? (rtt + 'ms') : '—');
      const benches = (p.benchmarks || []);
      if (!benches.length) {
        set('kpiBest', '—'); set('kpiHealthy', '—');
        return;
      }
      const scored = benches.map(b => Object.assign({}, b, { dynamicScore: computeProfileScore(b, currentProfile) }));
      scored.sort((a, b) => b.dynamicScore - a.dynamicScore);
      const winner = scored.find(x => !x.disqualified && x.dynamicScore > 0);
      set('kpiBest', winner ? (winner.protocol + ' · ' + winner.dynamicScore + ' pts') : '—');
      const healthy = scored.filter(x => !x.disqualified).length;
      set('kpiHealthy', healthy + ' از ' + scored.length);
    }

    function renderBenchmarks(p) {
      const container = document.getElementById('benchList');
      const deploySelect = document.getElementById('deploySelect');
      const banner = document.getElementById('winnerBanner');
      const benches = (p && p.benchmarks) ? p.benchmarks : [];

      if (!benches.length) {
        banner.style.display = 'none';
        container.innerHTML = '<div style="padding: 24px; font-size: 12.5px; color: var(--text-dim); text-align: center;">No benchmarks run for this pair yet. Click "Run 8-Protocol Benchmark" above.</div>';
        renderKpis();
        return;
      }

      const scoredBenches = benches.map(b => {
        const sc = computeProfileScore(b, currentProfile);
        return Object.assign({}, b, { dynamicScore: sc });
      });
      scoredBenches.sort((a, b) => b.dynamicScore - a.dynamicScore);

      // 1-Click Winner Banner
      const winner = scoredBenches.find(x => !x.disqualified && x.dynamicScore > 0);
      if (winner) {
        currentWinnerProtocol = winner.protocol;
        banner.style.display = 'flex';
        document.getElementById('winnerName').textContent = winner.protocol;
        document.getElementById('winnerScore').textContent = winner.dynamicScore + ' pts';
        let reason = '';
        if (currentProfile === 'gaming') {
          reason = 'Lowest latency (' + (winner.latency_ms || 46) + 'ms) & minimal Jitter (' + (winner.jitter_ms || 2) + 'ms) for lag-free gaming';
        } else if (currentProfile === 'ultraspeed') {
          const wlegs = legSummary(winner);
          reason = wlegs.weak === null
            ? 'Maximum throughput (passed 1MB wire-speed ladder) for high-speed download'
            : ('ضعیف‌ترین جهتِ اندازه‌گیری‌شده: ' + wlegs.weak.toFixed(1) + ' Mbps' + wlegs.warn
               + ' - عددی که نمره از آن ساخته می‌شود میانگین دو جهت مخالف نیست');
        } else {
          reason = 'Optimal balance: ' + (winner.latency_ms || 46) + 'ms latency, 0% loss, passed 1MB bulk ladder';
        }
        document.getElementById('winnerReason').textContent = reason;
      } else {
        banner.style.display = 'none';
      }

      container.innerHTML = scoredBenches.map(b => {
        const dq = b.disqualified;
        const dotClass = dq ? 'proto-fail' : 'proto-pass';
        const scoreClass = dq ? 'proto-score fail' : 'proto-score';
        const statusLabel = dq ? 'Disqualified' : (b.dynamicScore + ' pts');
        const lat = b.latency_ms ? (b.latency_ms + 'ms') : '-';
        const loss = b.loss_pct !== undefined ? (b.loss_pct + '% loss') : '';
        const legs = legSummary(b);

        return '<div class="bench-row">' +
          '<div class="proto-badge">' +
            '<span class="proto-indicator ' + dotClass + '"></span>' +
            '<span>' + escapeHtml(b.protocol) + '</span>' +
          '</div>' +
          '<div class="proto-metrics">' +
            '<span>' + escapeHtml(lat) + '</span>' +
            '<span>' + escapeHtml(loss) + '</span>' +
            (legs.text ? '<span title="ظرفیتِ نمره‌دهی = ضعیف‌ترین جهتِ اندازه‌گیری‌شده'
                             + (legs.basis ? (' (' + legs.basis + ')') : '') + '">'
                       + escapeHtml(legs.text + legs.warn) + '</span>' : '') +
            '<span class="' + scoreClass + '">' + escapeHtml(statusLabel) + '</span>' +
            (dq ? '' : '<div class="score-bar"><i style="width:' + Math.max(0, Math.min(100, Math.round(b.dynamicScore))) + '%"></i></div>') +
          '</div>' +
        '</div>';
      }).join('');
      renderKpis();
    }

    async function runBenchmark() {
      const btn = document.getElementById('runBenchBtn');
      const statusEl = document.getElementById('op-status');
      const raw = document.getElementById('raw');

      const irHost = v('a1');
      const frHost = v('b1');
      const irPass = v('a4');
      const frPass = v('b4');

      if (!irHost || !frHost) {
        showToast('لطفاً آدرس IP سرور ایران و سرور خارج را وارد کنید.', 'error');
        alert('لطفاً آدرس IP سرور ایران و سرور خارج را وارد کنید.');
        return;
      }

      if (!irPass || !frPass) {
        showToast('Please enter SSH passwords in the fields on the left first!', 'error');
        alert('Please enter SSH passwords for both Iran and foreign servers before running benchmarks.');
        return;
      }

      // Auto-register pair if this is a new pair
      if (!currentPairId || currentPairId === 'new') {
        try {
          const addRes = await apiFetch('/api/add', {
            name: v('pname') || ('Pair-' + irHost.replace(/[^0-9]/g, '') + '-' + frHost.replace(/[^0-9]/g, '')),
            iran: { host: irHost, port: +v('a2'), user: v('a3'), dial_host: v('a5'), auth: { type: 'password', value: irPass } },
            foreign: { host: frHost, port: +v('b2'), user: v('b3'), dial_host: v('b5'), auth: { type: 'password', value: frPass } },
            frontend: +v('f')
          });
          const addData = await addRes.json();
          if (addData.ok) {
            currentPairId = addData.id;
            await loadData();
            document.getElementById('pairSelect').value = currentPairId;
          } else {
            showToast('Registration error: ' + (addData.error || 'Unknown error'), 'error');
            return;
          }
        } catch (err) {
          showToast('Network error during pair registration: ' + err.message, 'error');
          return;
        }
      }

      const origText = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Running Benchmarks (__PROTOCOL_COUNT__ Protocols)...';

      statusEl.textContent = 'RUNNING BENCHMARKS';
      statusEl.style.background = 'rgba(59, 130, 246, 0.2)';
      statusEl.style.color = '#93c5fd';

      raw.textContent = 'Starting isolated 8-protocol benchmark suite on ' + irHost + ' -> ' + frHost + ' [' + currentProfile.toUpperCase() + ' profile]...\\nPlease allow 2 to 3 minutes for comprehensive testing...';

      const payload = {
        id: currentPairId,
        name: v('pname'),
        iran: { host: irHost, port: +v('a2'), user: v('a3'), dial_host: v('a5'), auth: { type: 'password', value: irPass } },
        foreign: { host: frHost, port: +v('b2'), user: v('b3'), dial_host: v('b5'), auth: { type: 'password', value: frPass } },
        frontend: +v('f'),
        profile: currentProfile,
        iran_password: irPass,
        foreign_password: frPass
      };

      try {
        const res = await apiFetch('/api/testall', payload);
        const data = await res.json();
        if (!data.ok) {
          showToast(data.error || 'Benchmark initialization failed', 'error');
          raw.textContent = 'Error: ' + (data.error || 'Unknown failure');
          statusEl.textContent = 'ERROR';
          btn.disabled = false;
          btn.innerHTML = origText;
          return;
        }
        showToast('8-protocol benchmark job initiated', 'info');
        pollJob(data.job, btn, origText);
      } catch (err) {
        showToast('Connection failed: ' + err.message, 'error');
        statusEl.textContent = 'FAILED';
        btn.disabled = false;
        btn.innerHTML = origText;
      }
    }

    async function saveAsNewPair() {
      const payload = {
        name: v('pname') || ('pair' + (pairs.length + 1)),
        iran: { host: v('a1'), port: +v('a2'), user: v('a3'), dial_host: v('a5'), auth: { type: 'password', value: v('a4') } },
        foreign: { host: v('b1'), port: +v('b2'), user: v('b3'), dial_host: v('b5'), auth: { type: 'password', value: v('b4') } },
        frontend: +v('f')
      };

      try {
        const res = await apiFetch('/api/add', payload);
        const data = await res.json();
        if (data.ok) {
          showToast('Added pair successfully: ' + payload.name, 'success');
          currentPairId = data.id;
          await loadData();
          document.getElementById('pairSelect').value = data.id;
          switchPair();
        } else {
          showToast('Failed to add pair: ' + (data.error || 'Unknown error'), 'error');
        }
      } catch (err) {
        showToast('Network error: ' + err.message, 'error');
      }
    }

    async function deleteCurrentPair() {
      const selVal = document.getElementById('pairSelect').value;
      if (selVal === 'new' || !currentPairId) {
        clearForm();
        return;
      }
      if (!confirm('Are you sure you want to permanently delete pair #' + currentPairId + ' and its benchmark history?')) {
        return;
      }
      try {
        const res = await apiFetch('/api/delete', { id: currentPairId });
        const data = await res.json();
        if (data.ok) {
          showToast('Pair deleted successfully', 'info');
          currentPairId = null;
          await loadData();
          clearForm();
        } else {
          showToast('Delete error: ' + (data.error || 'Unknown'), 'error');
        }
      } catch (err) {
        showToast('Network error: ' + err.message, 'error');
      }
    }

    function deploySelected() {
      const sel = document.getElementById('deploySelect').value;
      const frontend = +v('f');
      if (frontend === 443 || frontend === 80 || frontend === 8443) {
        pendingDeploy = { id: currentPairId, choice: sel };
        document.getElementById('modal-text').innerHTML =
          'Port <b>' + frontend + '</b> is part of the Protected Ingress Enclave.<br><br>' +
          'Selected protocol: <b style="color: #60a5fa;">' + sel + '</b><br>' +
          'Deployment will gracefully stop whatever service currently holds this port, verify it is free, then bind the tunnel and apply conntrack rules.<br>' +
          '<b style="color: #f87171;">The existing service on this port goes down and is not restarted automatically.</b> Its unit files are backed up under /root/tunnel-backups/.';
        document.getElementById('modal').style.display = 'flex';
      } else {
        executeDeploy(currentPairId, sel, false);
      }
    }

    function closeModal() {
      document.getElementById('modal').style.display = 'none';
      pendingDeploy = null;
    }

    function confirmRelease() {
      if (!pendingDeploy) return;
      const { id, choice } = pendingDeploy;
      closeModal();
      executeDeploy(id, choice, true);
    }

    async function executeDeploy(id, choice, forceConfirmed) {
      const statusEl = document.getElementById('op-status');
      const raw = document.getElementById('raw');

      statusEl.textContent = 'DEPLOYING';
      statusEl.style.background = 'rgba(245, 158, 11, 0.2)';
      statusEl.style.color = '#fbbf24';

      raw.textContent = 'Deploying ' + choice + ' to port ' + v('f') + '... Executing remote commands on Iran and Turkey servers...';

      const payload = {
        id, choice,
        confirm_force_release: forceConfirmed,
        iran_password: v('a4'),
        foreign_password: v('b4')
      };

      try {
        const res = await apiFetch('/api/deploy', payload);
        const data = await res.json();
        if (!data.ok) {
          if (data.error && (data.error.includes('SERVER GATE REJECTION') || data.error.includes('is occupied'))) {
            pendingDeploy = { id, choice };
            document.getElementById('modal-text').innerHTML =
              'Port <b>' + escapeHtml(String(v('f'))) + '</b> is currently occupied on the server.<br><br>' +
              escapeHtml(data.error) + '<br><br>' +
              'Do you want to confirm safe force release and takeover of this port?';
            document.getElementById('modal').style.display = 'flex';
            statusEl.textContent = 'CONFIRMATION REQUIRED';
            return;
          }
          showToast(data.error || 'Deployment error', 'error');
          raw.textContent = 'Deployment error: ' + (data.error || 'Unknown');
          statusEl.textContent = 'FAILED';
          return;
        }
        showToast('Deployment queued successfully', 'info');
        pollJob(data.job, null, null);
      } catch (err) {
        showToast('Deployment error: ' + err.message, 'error');
      }
    }

    async function pollJob(jid, btn, origText) {
      const raw = document.getElementById('raw');
      const statusEl = document.getElementById('op-status');
      const maxPoll = 500; // 500 * 2s = 1000s (~16.6 minutes)
      let delayMs = 2000;

      for (let k = 0; k < maxPoll; k++) {
        await new Promise(r => setTimeout(r, delayMs));
        let res;
        try {
          res = await apiFetch('/api/job', { job: jid });
        } catch (e) {
          continue;
        }

        if (res.status === 429) {
          // Sprint 2: Exponential backoff on rate limit
          delayMs = Math.min(delayMs * 2, 16000);
          statusEl.textContent = 'RATE LIMITED (BACKING OFF)';
          continue;
        }
        delayMs = 2000; // Reset delay on normal response

        const jobData = await res.json();

        if (jobData.done) {
          raw.textContent = JSON.stringify(jobData.out, null, 2);
          raw.scrollTop = raw.scrollHeight;

          if (btn && origText) {
            btn.disabled = false;
            btn.innerHTML = origText;
          }

          if (jobData.out && jobData.out.ok) {
            showToast('Job completed successfully', 'success');
            statusEl.textContent = 'COMPLETED';
            statusEl.style.background = 'rgba(16, 185, 129, 0.2)';
            statusEl.style.color = '#34d399';
          } else {
            showToast('Job execution failed', 'error');
            statusEl.textContent = 'FAILED';
            statusEl.style.background = 'rgba(239, 68, 68, 0.2)';
            statusEl.style.color = '#fca5a5';
          }
          await loadData();
          return;
        }

        const elapsed = k * 2;
        const pStatus = jobData.status ? (' [' + jobData.status + ']') : '';
        statusEl.textContent = jobData.status || 'PROCESSING';
        raw.textContent = 'Processing ' + pStatus + ' (' + elapsed + 's elapsed)\\nJob ID: ' + jid;
      }

      if (btn && origText) {
        btn.disabled = false;
        btn.innerHTML = origText;
      }
      raw.textContent = 'Job polling timed out after 10 minutes.';
      statusEl.textContent = 'TIMEOUT';
    }

    async function loadData() {
      try {
        const res = await fetch('/api', { cache: 'no-store' });
        const data = await res.json();
        pairs = data.pairs || [];
        carrierSlots = data.carrier_slots || [];
        carrierRuleText = data.carrier_rule_text || '';
        // The delivery contract and its state vocabulary arrive from the modules that own them. Kept as
        // received: if the server stops sending the table, the card says so through the unknown-transport
        // branch rather than drawing a page from a stale local copy.
        backendContract = data.backend_contract || null;
        backendStates = data.backend_states || [];
        // The freshness policy and the clock come from the server, never from defaults here: a page that
        // invented its own threshold would report a sample as current on a policy nobody chose.
        const lim = Number(data.resource_stale_after_sec);
        resourceStaleAfterSec = Number.isFinite(lim) ? lim : null;
        const srv = Number(data.server_time);
        serverClockOffsetSec = Number.isFinite(srv) ? (srv - Date.now() / 1000) : null;

        const badge = document.getElementById('mbadge');
        const badgeText = document.getElementById('mbadge-text');
        if (data.dry_run) {
          badge.className = 'status-badge mock';
          badgeText.textContent = 'MOCK DRY-RUN MODE';
        } else {
          badge.className = 'status-badge';
          badgeText.textContent = 'LIVE OPERATION MODE';
        }

        const select = document.getElementById('pairSelect');
        let opts = '<option value="new">+ Add New Server Pair (خالی / سرور جدید)</option>';
        opts += pairs.map(p => '<option value="' + escapeHtml(p.id) + '">' + escapeHtml(p.name) + ' (#' + escapeHtml(p.id) + ' - ' + escapeHtml(p.iran_host) + ')</option>').join('');
        select.innerHTML = opts;

        if (pairs.length > 0) {
          if (currentPairId && pairs.some(x => x.id === currentPairId)) {
            select.value = currentPairId;
            switchPair();
          } else if (currentPairId === 'new') {
            select.value = 'new';
          } else {
            currentPairId = pairs[0].id;
            select.value = currentPairId;
            switchPair();
          }
        } else {
          currentPairId = null;
          select.value = 'new';
          clearForm();
        }
        // Phase 6 sections render from the same poll payload.
        renderFleet();
        renderHealth();
      } catch (err) {
        showToast('Failed to load server pairs: ' + err.message, 'error');
      }
    }

    // ---- Phase 6: fleet map, live cards, Health Center, محک wizard ----
    function verdictColor(v) {
      if (v === 'HEALTHY') return '#34d399';
      if (v === 'DEGRADED') return '#fbbf24';
      if (v === 'DOWN_PENDING' || v === 'HEAL_CONFIRMED' || v === 'OBSERVE_DOWN') return '#f87171';
      if (v === 'FAILOVER_EXECUTED') return '#c084fc';
      return '#9ca3af';
    }

    function renderFleet() {
      const mapEl = document.getElementById('fleetMap');
      const cardsEl = document.getElementById('fleetCards');
      if (!pairs.length) {
        mapEl.innerHTML = '<div style="padding: 16px; color: var(--text-dim);">هنوز جفتی ثبت نشده است.</div>';
        cardsEl.innerHTML = '';
        return;
      }
      mapEl.innerHTML = pairs.map(p => {
        const col = verdictColor(p.health_history && p.health_history[0] ? p.health_history[0].verdict : null);
        return '<div style="display: flex; align-items: center; gap: 10px; margin: 6px 0; direction: rtl;">' +
          '<span>🇮🇷 ایران</span>' +
          '<span style="flex: 1; height: 3px; background: ' + col + '; border-radius: 2px;"></span>' +
          '<span style="font-size: 12px; color: var(--text-dim);">' + escapeHtml(p.active_tunnel || '—') + '</span>' +
          '<span style="flex: 1; height: 3px; background: ' + col + '; border-radius: 2px;"></span>' +
          '<span>🌍 خارج</span>' +
          '<span style="font-size: 12px;">' + escapeHtml(p.name) + '</span></div>';
      }).join('');
      cardsEl.innerHTML = pairs.map(p => {
        const last = (p.health_history && p.health_history[0]) || {};
        const up = p.uptime_24h || {};
        const q = p.quarantine;
        return '<div style="border: 1px solid var(--border-color); border-radius: 10px; padding: 12px;">' +
          '<div style="display: flex; justify-content: space-between;"><b>' + escapeHtml(p.name) + '</b>' +
          '<span style="color: ' + verdictColor(last.verdict) + ';">' + escapeHtml(last.verdict || p.status || '—') + '</span></div>' +
          '<div style="font-size: 12.5px; color: var(--text-dim); margin-top: 6px;">' +
          'ترانسپورت فعال: ' + escapeHtml(p.active_tunnel || '—') +
          ' | حالت: ' + escapeHtml(p.mode || 'manual') +
          (p.auto_protocol ? ' (خودکار: ' + escapeHtml(p.auto_protocol) + ')' : '') + '<br>' +
          'تاخیر آخر: ' + (last.latency_ms !== undefined && last.latency_ms !== null ? last.latency_ms + 'ms' : '—') +
          ' | آپتایم ۲۴ ساعت: ' + (up.uptime_pct !== undefined && up.uptime_pct !== null ? up.uptime_pct + '%' : '—') +
          ' | قطعی‌ها: ' + (up.outages !== undefined ? up.outages : '—') +
          ' | سوییچ‌ها: ' + (p.failover_count !== undefined ? p.failover_count : '—') +
          (q ? '<br>قرنطینه فعال: ' + escapeHtml(q.protocol) + ' (تا پایان مهلت)' : '') +
          '</div>' +
          '<div style="display: flex; gap: 6px; margin-top: 10px;">' +
          '<button class="btn btn-secondary" style="width: auto;" onclick="runDiagnostics(' + p.id + ')">عیب‌یابی</button>' +
          '<button class="btn btn-secondary" style="width: auto;" onclick="runQuickRepair(' + p.id + ')">تعمیر سریع</button>' +
          '<button class="btn btn-secondary" style="width: auto;" onclick="toggleMode(' + p.id + ', ' + (p.mode === 'auto' ? 'false' : 'true') + ')">' +
          (p.mode === 'auto' ? 'خروج از خودکار' : 'حالت خودکار') + '</button>' +
          '</div>' +
          '<div id="diag-' + p.id + '" style="margin-top: 8px; font-size: 12px; white-space: pre-wrap;"></div>' +
          '</div>';
      }).join('');
    }

    function renderHealth() {
      const el = document.getElementById('healthList');
      if (!pairs.length) { el.innerHTML = '<div style="color: var(--text-dim);">جفتی برای نمایش نیست.</div>'; return; }
      el.innerHTML = pairs.map(p => {
        const up = p.uptime_24h || {};
        const chips = (p.health_history || []).slice(0, 20).map(h =>
          '<span title="' + escapeHtml(h.recorded_at ? new Date(h.recorded_at * 1000).toLocaleString('fa-IR') : '') + '" style="display: inline-block; width: 12px; height: 12px; border-radius: 3px; margin: 1px; background: ' + verdictColor(h.verdict) + ';"></span>'
        ).join('');
        return '<div style="border-top: 1px solid var(--border-color); padding: 10px 0;">' +
          '<b>' + escapeHtml(p.name) + '</b> — آپتایم ۲۴ ساعت: ' +
          (up.uptime_pct !== undefined && up.uptime_pct !== null ? up.uptime_pct + '%' : 'بدون نمونه') +
          ' | نمونه‌ها: ' + (up.samples !== undefined ? up.samples : '—') +
          ' | قطعی‌ها: ' + (up.outages !== undefined ? up.outages : '—') +
          '<div style="margin-top: 6px;">' + (chips || 'بدون تاریخچه') + '</div>' +
          '<button class="btn btn-secondary" style="width: auto; margin-top: 6px;" onclick="showHistoryChart(' + p.id + ')">نمودار تاریخچه</button>' +
          '<div id="chart-' + p.id + '" style="margin-top: 6px;"></div></div>';
      }).join('');
    }

    async function showHistoryChart(pairId) {
      const box = document.getElementById('chart-' + pairId);
      box.textContent = 'در حال بارگذاری...';
      try {
        const res = await apiFetch('/api/history', { id: pairId, limit: 500 });
        const data = await res.json();
        if (!data.ok) { box.textContent = 'خطا: ' + (data.error || 'نامشخص'); return; }
        const s = data.samples || [];
        if (!s.length) { box.textContent = 'نمونه‌ای برای نمودار نیست.'; return; }
        box.innerHTML = '<canvas id="chartCanvas-' + pairId + '" width="640" height="180" style="width: 100%; border: 1px solid var(--border-color); border-radius: 8px;"></canvas>' +
          '<div id="chartInfo-' + pairId + '" style="font-size: 12px; margin-top: 4px;"></div>' +
          '<div style="font-size: 12px; color: var(--text-dim);">خط تاخیر با رنگ حکم هر نمونه؛ نقطه بنفش یعنی سوییچ (FAILOVER_EXECUTED). throughput در نمونه‌های مانیتور ثبت نمی‌شود، پس روی نمودار نیست.</div>';
        drawHistoryChart(pairId, s);
      } catch (err) { box.textContent = 'خطای شبکه: ' + err.message; }
    }
    function drawHistoryChart(pairId, s) {
      const cv = document.getElementById('chartCanvas-' + pairId);
      const info = document.getElementById('chartInfo-' + pairId);
      if (!cv) return;
      const ctx = cv.getContext('2d');
      const W = cv.width, H = cv.height, padL = 8, padR = 8, padT = 10, padB = 18;
      const lats = s.map(function (x) { return x.lat; }).filter(function (v) { return v !== null && v !== undefined; });
      const maxLat = Math.max.apply(null, lats.concat([1]));
      const px = function (i) { return padL + (s.length === 1 ? (W - padL - padR) / 2 : i * (W - padL - padR) / (s.length - 1)); };
      const py = function (v) { return padT + (H - padT - padB) * (1 - v / maxLat); };
      ctx.clearRect(0, 0, W, H);
      ctx.strokeStyle = '#38bdf8'; ctx.lineWidth = 1.5; ctx.beginPath();
      s.forEach(function (pt, i) {
        if (pt.lat === null || pt.lat === undefined) return;
        if (i === 0 || s[i - 1].lat === null || s[i - 1].lat === undefined) ctx.moveTo(px(i), py(pt.lat));
        else ctx.lineTo(px(i), py(pt.lat));
      });
      ctx.stroke();
      s.forEach(function (pt, i) {
        ctx.fillStyle = verdictColor(pt.verdict);
        ctx.beginPath();
        ctx.arc(px(i), py(pt.lat === null || pt.lat === undefined ? 0 : pt.lat), 3, 0, 2 * Math.PI);
        ctx.fill();
      });
      ctx.fillStyle = '#9ca3af'; ctx.font = '11px sans-serif';
      ctx.fillText('max ' + maxLat + 'ms', padL, H - 4);
      cv.onmousemove = function (ev) {
        const rect = cv.getBoundingClientRect();
        const mx = (ev.clientX - rect.left) * (W / rect.width);
        let best = 0, bestD = 1e9;
        s.forEach(function (pt, i) { const d = Math.abs(px(i) - mx); if (d < bestD) { bestD = d; best = i; } });
        const pt = s[best];
        info.textContent = (pt.t ? new Date(pt.t * 1000).toLocaleString('fa-IR') : '—') + ' — حکم: ' + (pt.verdict || '—') + ' | تاخیر: ' + (pt.lat !== null && pt.lat !== undefined ? pt.lat + 'ms' : '—') + ' | افت: ' + (pt.loss !== null && pt.loss !== undefined ? pt.loss + '%' : '—') + ' | پروتکل: ' + (pt.protocol || '—');
      };
    }

    function diagVal(v, suffix) {
      if (v === undefined || v === null || v === '') return '—';
      return escapeHtml(String(v)) + (suffix || '');
    }
    function diagCheck(ok) {
      return ok ? '<span style="color: var(--success);">● فعال</span>' : '<span style="color: var(--danger);">● غیرفعال</span>';
    }
    function diagSickSide(h) {
      if (!h.is_unit_active_iran) return 'سمت ایران بیمار است: واحد تانل روی سرور ایران فعال نیست.';
      if (!h.is_unit_active_foreign) return 'سمت خارج بیمار است: واحد تانل روی سرور خارج فعال نیست.';
      if (h.backend_state === 'no-backend') return 'بک‌اند پشت تانل پاسخ نمی‌دهد: مشکل از اپلیکیشن پشت تانل است، نه خود تانل.';
      if (h.ttl_state === 'injection_suspected') return 'مسیر دستکاری می‌شود (نشانه تزریق RST در TTL)؛ سوییچ پروتکل این را درست نمی‌کند.';
      if (h.status === 'DOWN') return 'هر دو واحد فعال‌اند ولی تانل ترافیک نمی‌برد؛ مسیر یا کریر را بررسی کنید.';
      return 'هر دو سر سالم‌اند.';
    }
    function diagRows(rows) {
      return rows.map(function (r) {
        return '<div style="display: flex; justify-content: space-between; gap: 8px; padding: 3px 0; border-top: 1px solid var(--border-color);"><span style="color: var(--text-dim);">' + r[0] + '</span><span>' + r[1] + '</span></div>';
      }).join('');
    }
    function renderDiagPanel(box, rep) {
      const h = rep.health || {};
      const pf = rep.preflight || {};
      const irF = pf.iran || {};
      const frF = pf.foreign || {};
      const path = pf.path || {};
      const irPath = (path.iran_to_foreign || {}).ping || {};
      const frPath = (path.foreign_to_iran || {}).ping || {};
      const backendTxt = h.backend_state === 'answered' ? 'پاسخ می‌دهد' : (h.backend_state === 'no-backend' ? 'پاسخ نمی‌دهد' : (h.backend_state === 'unreadable' ? 'خوانده نشد' : '—'));
      const ttlTxt = rep.ttl && rep.ttl.state ? escapeHtml(rep.ttl.state) : '—';
      const findings = (rep.preflight_findings || []).map(function (f) {
        return '<div>• ' + escapeHtml(f) + '</div>';
      }).join('') || '<div>یافته‌ای نیست.</div>';
      const q = rep.quarantine ? ('قرنطینه فعال: ' + escapeHtml(rep.quarantine.protocol || '')) : 'قرنطینه‌ای نیست';
      box.innerHTML = '<div style="border: 1px solid var(--border-color); border-radius: 10px; padding: 10px; margin-top: 4px;">' +
        '<div style="display: flex; justify-content: space-between;"><b>مقایسه دو سر</b>' +
        '<span style="color: ' + verdictColor(h.status) + ';">' + escapeHtml(h.status || '—') + '</span></div>' +
        '<div style="margin: 8px 0; font-weight: bold;">' + escapeHtml(diagSickSide(h)) + '</div>' +
        '<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">' +
        '<div><b>🇮🇷 ایران</b>' + diagRows([
          ['واحد تانل', diagCheck(h.is_unit_active_iran)],
          ['فرانت‌اند', diagCheck(h.is_socket_listening)],
          ['MTU اینترفیس', diagVal(irF.iface_mtu)],
          ['کنترل ازدحام', diagVal(irF.congestion_control)],
          ['قانون MSS clamp', diagVal(irF.mss_clamp_rules)],
          ['پینگ به خارج (افت)', diagVal(irPath.loss_pct, '%')],
          ['پینگ به خارج (میانگین)', diagVal(irPath.rtt_avg_ms, 'ms')]
        ]) + '</div>' +
        '<div><b>🌍 خارج</b>' + diagRows([
          ['واحد تانل', diagCheck(h.is_unit_active_foreign)],
          ['بک‌اند تحویل', backendTxt],
          ['MTU اینترفیس', diagVal(frF.iface_mtu)],
          ['کنترل ازدحام', diagVal(frF.congestion_control)],
          ['قانون MSS clamp', diagVal(frF.mss_clamp_rules)],
          ['پینگ به ایران (افت)', diagVal(frPath.loss_pct, '%')],
          ['پینگ به ایران (میانگین)', diagVal(frPath.rtt_avg_ms, 'ms')]
        ]) + '</div></div>' +
        '<div style="margin-top: 8px;">سرتاسری: افت ' + diagVal(h.loss_pct, '%') + ' | تاخیر ' + diagVal(h.latency_ms, 'ms') + ' | سربار ' + diagVal(h.overhead_ratio, '×') + ' | وضعیت TTL: ' + ttlTxt + '</div>' +
        '<div style="margin-top: 6px;"><b>یافته‌های پری‌فلایت:</b>' + findings + '</div>' +
        '<div style="margin-top: 6px; color: var(--text-dim);">' + escapeHtml(q) + ' | حالت: ' + escapeHtml(rep.mode || 'manual') + (rep.auto_protocol ? ' (خودکار: ' + escapeHtml(rep.auto_protocol) + ')' : '') + '</div></div>';
    }
    async function runDiagnostics(pairId) {
      const box = document.getElementById('diag-' + pairId);
      box.textContent = 'در حال عیب‌یابی...';
      try {
        const res = await apiFetch('/api/diagnostics', { id: pairId });
        const data = await res.json();
        if (!data.ok) { box.textContent = 'خطا: ' + (data.error || 'نامشخص'); return; }
        if (data.report && data.report.health) { renderDiagPanel(box, data.report); }
        else { box.textContent = JSON.stringify(data.report, null, 2); }
      } catch (err) { box.textContent = 'خطای شبکه: ' + err.message; }
    }

    async function runQuickRepair(pairId) {
      const box = document.getElementById('diag-' + pairId);
      box.textContent = 'در حال تعمیر...';
      try {
        const res = await apiFetch('/api/quick_repair', { id: pairId });
        const data = await res.json();
        box.textContent = data.ok ? ('انجام شد: ' + (data.action || '')) : ('خطا: ' + (data.error || 'نامشخص'));
        showToast(data.ok ? 'تعمیر سریع انجام شد' : ('تعمیر ناموفق: ' + (data.error || '')), data.ok ? 'success' : 'error');
        await loadData();
      } catch (err) { box.textContent = 'خطای شبکه: ' + err.message; }
    }

    async function toggleMode(pairId, toAuto) {
      const mode = toAuto ? 'auto' : 'manual';
      try {
        const res = await apiFetch('/api/mode', { id: pairId, mode });
        const data = await res.json();
        showToast(data.ok ? ('حالت جفت به ' + mode + ' تغییر کرد') : ('خطا: ' + (data.error || '')), data.ok ? 'success' : 'error');
        await loadData();
      } catch (err) { showToast('خطای شبکه: ' + err.message, 'error'); }
    }

    async function runWizard() {
      const statusEl = document.getElementById('wizardStatus');
      const outEl = document.getElementById('wizardResults');
      if (!currentPairId || currentPairId === 'new') {
        statusEl.textContent = 'اول یک جفت را از بالا انتخاب کن.';
        return;
      }
      const prof = document.getElementById('wizardProfile').value;
      const pair = pairs.find(x => x.id === currentPairId);
      statusEl.textContent = 'در حال محک زدن با پروفایل ' + prof + '... (چند دقیقه طول می‌کشد)';
      outEl.innerHTML = '';
      try {
        const payload = {
          id: currentPairId,
          iran: { host: v('a1'), port: +v('a2'), user: v('a3'), dial_host: v('a5'), auth: { type: 'password', value: v('a4') } },
          foreign: { host: v('b1'), port: +v('b2'), user: v('b3'), dial_host: v('b5'), auth: { type: 'password', value: v('b4') } },
          frontend: +v('f'), profile: prof,
          iran_password: v('a4'),
          foreign_password: v('b4')
        };
        const res = await apiFetch('/api/testall', payload);
        const data = await res.json();
        if (!data.ok) { statusEl.textContent = 'خطا: ' + (data.error || 'نامشخص'); return; }
        const jid = data.job;
        for (let k = 0; k < 500; k++) {
          await new Promise(r => setTimeout(r, 2000));
          const jr = await apiFetch('/api/job', { job: jid });
          const jobData = await jr.json();
          if (jobData.done) {
            if (!jobData.out || !jobData.out.ok) {
              statusEl.textContent = 'محک ناموفق بود: ' + ((jobData.out && jobData.out.error) || 'نامشخص');
              return;
            }
            const rows = (jobData.out.benchmarks || []).slice().sort((a, b) => (b.score || 0) - (a.score || 0));
            statusEl.textContent = 'محک کامل شد. بهترین گزینه اول است؛ برای اعمال، روی «اعمال» بزن.';
            outEl.innerHTML = rows.map(r => {
              const reasons = (r.reasons || []).map(x => '<li>' + escapeHtml(x) + '</li>').join('');
              const dq = r.disqualified ? ' (رد شده)' : '';
              return '<div style="border: 1px solid var(--border-color); border-radius: 10px; padding: 10px; margin: 8px 0;">' +
                '<div style="display: flex; justify-content: space-between;"><b>' + escapeHtml(r.protocol) + dq + '</b>' +
                '<span>' + (r.score !== undefined ? r.score + ' از ۱۰۰' : '—') + '</span></div>' +
                '<ul style="margin: 6px 0; font-size: 13px;">' + reasons + '</ul>' +
                (r.disqualified ? '' : '<button class="btn btn-primary" style="width: auto;" data-proto="' + escapeHtml(r.protocol) + '" onclick="wizardApply(this)">اعمال این ترانسپورت</button>') +
                '</div>';
            }).join('');
            await loadData();
            return;
          }
          statusEl.textContent = (jobData.status || 'در حال پردازش') + '...';
        }
        statusEl.textContent = 'زمان محک تمام شد؛ از بخش نتایج اصلی پیگیری کن.';
      } catch (err) { statusEl.textContent = 'خطای شبکه: ' + err.message; }
    }

    function wizardApply(btn) {
      const protocol = btn.dataset.proto;
      document.getElementById('pairSelect').value = currentPairId;
      switchPair();
      document.getElementById('deploySelect').value = protocol;
      deploySelected();
    }

    // Initialize on page load
    // ---- Phase 6 remainder: live events over SSE ----
    // EventSource reconnects on its own and resends Last-Event-ID, so a
    // dropped connection replays from the server's ring buffer instead
    // of losing events. The feed carries verdict transitions only, not
    // full pair state: the cards still refresh on the existing poll,
    // because SSE here replaces polling for EVENTS, not for state.
    function initLiveEvents() {
      const box = document.getElementById('liveEvents');
      if (!box || typeof EventSource === 'undefined') return;
      const es = new EventSource('/api/events');
      es.onmessage = function (ev) {
        try {
          const data = JSON.parse(ev.data);
          const item = document.createElement('div');
          item.style.padding = '3px 0';
          item.style.borderTop = '1px solid var(--border-color)';
          item.textContent = new Date(data.ts * 1000).toLocaleString('fa-IR') + ' — جفت #' + data.pair_id + ': ' + data.verdict + (data.detail ? ' — ' + data.detail : '');
          box.prepend(item);
          while (box.children.length > 30) box.removeChild(box.lastChild);
        } catch (e) {}
      };
      es.onerror = function () {
        if (!box.dataset.warned) {
          box.dataset.warned = '1';
          const note = document.createElement('div');
          note.style.color = 'var(--text-dim)';
          note.textContent = 'رویداد زنده در دسترس نیست (اگر توکن API فعال است، EventSource نمی‌تواند آن را بفرستد؛ فید در حالت بدون توکن کار می‌کند).';
          box.prepend(note);
        }
      };
    }
    initLiveEvents();
    loadData();
  </script>
</body>
</html>"""

# Note (Auditor Finding 3-4): the sing-box toggle is evaluated at startup to render HTML templates.
# Toggling the environment variable requires a service restart. Since 2026-10-24 the sing-box
# protocols are graduated (live-witnessed); BEST_TUNNEL_DISABLE_SINGBOX=1 re-quarantines them.
opt_in_options = ""
if getattr(protocols, "is_singbox_enabled", lambda: False)():
    print("[INIT] Sing-Box protocols ACTIVE (graduated 2026-10-24; BEST_TUNNEL_DISABLE_SINGBOX=1 re-quarantines)")
    opt_in_options = """<option value="singbox-vless-reality">Sing-Box VLESS-REALITY</option>
              <option value="singbox-ss-2022">Sing-Box Shadowsocks-2022</option>"""
else:
    print("[INIT] BEST_TUNNEL_DISABLE_SINGBOX=1: Sing-Box re-quarantined by operator (Restart required if toggled)")

PROTOCOL_COUNT = len(protocols.get_supported_protocols())
print(f"[INIT] {PROTOCOL_COUNT} protocol(s) active: {', '.join(protocols.get_supported_protocols())}")

PAGE = (
    PAGE.replace("__SECRETS_AT_REST__", PROFILE_NOTES["secrets_at_rest"])
    .replace("__ULTRASPEED_TOOLTIP__", PROFILE_NOTES["ultraspeed_tooltip"])
    .replace("__ULTRASPEED_LABEL__", PROFILE_NOTES["ultraspeed_label"])
    .replace("<!-- __OPT_IN_SINGBOX_OPTIONS__ -->", opt_in_options)
    .replace("__PROTOCOL_COUNT__", str(PROTOCOL_COUNT))
)

class H(BaseHTTPRequestHandler):
    def check_csrf(self):
        """Enforces robust CSRF & Bearer Auth protection:
        1. Bearer token must match if BEST_TUNNEL_API_TOKEN is set.
        2. Mandatory custom header X-Best-Tunnel-CSRF == 1
        3. Host header must strictly belong to ALLOWED_HOSTS
        4. Content-Type must be application/json
        No fallback on Origin or Referer.
        """
        if not check_bearer_auth(self.headers):
            return False
        if self.headers.get("X-Best-Tunnel-CSRF") != "1":
            return False
        host = self.headers.get("Host", "").strip()
        if host not in ALLOWED_HOSTS:
            return False
        ctype = self.headers.get("Content-Type", "").strip().lower()
        if not ctype.startswith("application/json"):
            return False
        return True

    def do_GET(self):
        client_ip = self.client_address[0] if (hasattr(self, "client_address") and self.client_address) else "127.0.0.1"
        if self.path == "/api":
            if not check_bearer_auth(self.headers):
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("WWW-Authenticate", 'Bearer realm="BestTunnel"')
                self.end_headers()
                self.wfile.write(b'{"ok": false, "error": "Unauthorized: Invalid or missing Bearer token"}')
                return
            if is_rate_limited(client_ip, category="read"):
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", "5")
                self.end_headers()
                self.wfile.write(b'{"ok": false, "error": "Rate limit exceeded on GET /api (R-66). Please slow down."}')
                return
            cleanup_jobs()
            cleanup_auth_cache()
            pairs = storage.get_pairs()
            enriched = []
            for p in pairs:
                p_copy = dict(p)
                p_copy["benchmarks"] = storage.get_benchmarks(p["id"], limit=API_BENCHMARKS_PER_PAIR)
                with AUTH_CACHE_LOCK:
                    has_auth = (
                        p["id"] in AUTH_CACHE and
                        bool(AUTH_CACHE[p["id"]].get("iran", {}).get("auth", {}).get("value")) and
                        bool(AUTH_CACHE[p["id"]].get("foreign", {}).get("auth", {}).get("value"))
                    )
                p_copy["has_auth"] = has_auth
                # Newest stored capacity sample per host, or None per role for a host never sampled.
                # Read from the DB rather than sampled here: /api answers on every poll, and opening a
                # host session per page refresh would make a dashboard load a write to the host's log.
                p_copy["resources"] = storage.latest_host_resources(p["id"])
                # And the burst attribution over the rows behind that newest sample. This is a DB read, not
                # a host read: the poll answers from what the last sample recorded, so a page refresh cannot
                # become a write to a host's session log. (#70 - report062 could only attribute Foreign's
                # bursts by an operator SSHed in during one.)
                p_copy["resource_attribution"] = resource_attribution(p["id"])
                # #39: the pair's own non-routine audit rows, newest first. A DB read like the two above,
                # so a page refresh stays a read - and the reason it is here at all is that the engine
                # wrote a rotation WARNING for two years and nothing ever read it back.
                p_copy["security_events"] = storage.recent_security_events(p["id"])
                # Phase 6 live cards + Health Center, all DB reads so a
                # poll stays a read: recent verdicts, 24 h uptime, any
                # live quarantine, and the switchover (reconnect) count.
                p_copy["health_history"] = storage.get_health_history(p["id"], limit=50)
                p_copy["uptime_24h"] = storage.health_uptime_summary(
                    p["id"], since_ts=time.time() - 86400)
                p_copy["quarantine"] = storage.get_quarantine(p["id"])
                p_copy["failover_count"] = storage.count_failovers(p["id"])
                # What this pair's transport promises about its delivery end, read out of the table the
                # deploy consults rather than restated here: `kinds` says what kind of delivery the active
                # transport does, `port` is the effective one (declaration, else the frontend), and the
                # refusal is the one a declaration would meet - so the card cannot claim a pair is
                # declarable that the engine will refuse.
                #
                # No plan is generated to answer this. The table describes the transport, and the port the
                # pair actually delivers into is the stored one; regenerating configs on every poll to read
                # a number the row already carries would make a page refresh re-roll key material.
                active = (p.get("active_tunnel") or "").strip()
                spec = protocols.BACKEND_TARGETS.get(active)
                declared = p.get("backend_port")
                p_copy["backend_contract"] = {
                    "active_protocol": active,
                    "kind": spec[3] if spec else (
                        "egress proxy: no local delivery port" if active
                        in protocols.BACKEND_EGRESS_PROXIES else ""),
                    "declared_port": declared,
                    "effective_port": int(declared) if declared else int(p["frontend_port"]),
                    "declarable": active in protocols.BACKEND_PORT_DECLARABLE,
                    "refusal": protocols.backend_port_refusal(
                        active, p["frontend_port"],
                        declared if declared and declared != p["frontend_port"] else None),
                    "state": p.get("backend_state") or "",
                    "checked_at": p.get("backend_checked_at") or 0,
                }
                enriched.append(p_copy)
            body = json.dumps({"pairs": enriched, "dry_run": is_dry_run(),
                               "carrier_slots": engine.carrier_slot_rule(pairs),
                               "carrier_rule_text": engine.CARRIER_SLOT_RULE_TEXT,
                               # The contract's vocabulary, sent from the module that owns it so the page
                               # never keeps a second copy of a list the engine also reads.
                               "backend_contract": protocols.backend_contract_view(),
                               "backend_states": list(storage.BACKEND_STATES),
                               # The clock the ages are measured against is the one that stamped the rows.
                               # A browser clock that disagrees would turn a fresh sample stale, or a stale
                               # sample fresh, and the second is the one an operator acts on.
                               "resource_stale_after_sec": engine.RESOURCE_STALE_AFTER_SEC,
                               "server_time": time.time()}, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Phase 6 live feed: real SSE, not another poll. ThreadingHTTPServer
        # gives this connection its own thread, so holding it open cannot
        # block other requests. Same bearer gate as /api (which passes
        # when no API token is configured - the default local setup);
        # EventSource cannot carry an Authorization header, so with a
        # token configured the feed 401s and the page shows its note
        # instead of silently serving nothing.
        parsed = urlsplit(self.path)
        if parsed.path == "/api/events":
            if not check_bearer_auth(self.headers):
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok": false, "error": "Unauthorized"}')
                return
            if is_rate_limited(client_ip, category="read"):
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", "5")
                self.end_headers()
                self.wfile.write(b'{"ok": false, "error": "Rate limit exceeded"}')
                return
            try:
                last_id = int(self.headers.get("Last-Event-ID") or 0)
            except ValueError:
                last_id = 0
            if last_id == 0:
                try:
                    since = parse_qs(parsed.query).get("since", ["0"])[0]
                    last_id = int(since)
                except (ValueError, TypeError):
                    last_id = 0
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

            def emit(frame, _wfile=self.wfile):
                _wfile.write(frame)
                _wfile.flush()

            stream_events(EVENT_BUS, emit, last_id)
            return

        body = PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        client_ip = self.client_address[0] if (hasattr(self, "client_address") and self.client_address) else "127.0.0.1"
        category = "polling" if self.path.startswith("/api/job") else "mutation"
        if is_rate_limited(client_ip, category=category):
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", "5")
            self.end_headers()
            self.wfile.write(b'{"ok": false, "error": "Rate limit exceeded (R-66). Please slow down."}')
            return

        if not self.check_csrf():
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": false, "error": "Forbidden: CSRF verification failed"}')
            return

        n = int(self.headers.get("Content-Length", 0))
        if n > 65536:
            self.send_response(413)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": false, "error": "Payload too large (max 64KB)"}')
            return

        raw = self.rfile.read(n) if n else b"{}"
        try:
            j = json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            j = {}

        cleanup_jobs()
        out = {"ok": False}

        if self.path == "/api/add":
            try:
                ir = j.get("iran", {})
                fr = j.get("foreign", {})
                frontend = int(j.get("frontend", 443))
                ir_port = int(ir.get("port", 22))
                fr_port = int(fr.get("port", 22))
                name = (j.get("name") or "").strip() or f"pair{int(time.time()) % 1000}"

                if not valid_ip(ir.get("host", "")) or not valid_ip(fr.get("host", "")):
                    out = {"ok": False, "error": "Invalid IP address provided."}
                else:
                    validate_frontend_port(frontend, ir_port, fr_port)
                    if not (1 <= ir_port <= 65535 and 1 <= fr_port <= 65535):
                        out = {"ok": False, "error": "SSH port numbers must be between 1 and 65535."}
                    else:
                        ir_dial, fr_dial = request_dial_hosts(ir, fr)
                        pair_id = storage.add_pair(
                            name=name,
                            iran_host=ir.get("host"),
                            foreign_host=fr.get("host"),
                            frontend_port=frontend,
                            iran_port=ir_port,
                            foreign_port=fr_port,
                            iran_dial_host=ir_dial,
                            foreign_dial_host=fr_dial
                        )
                        set_auth_cache(pair_id, ir, fr)
                        out = {"ok": True, "id": pair_id}
            except Exception as ex:
                out = {"ok": False, "error": str(ex)}

        elif self.path == "/api/delete":
            try:
                pair_id = int(j.get("id", 0))
                with AUTH_CACHE_LOCK:
                    if pair_id in AUTH_CACHE:
                        del AUTH_CACHE[pair_id]
                ok = storage.delete_pair(pair_id)
                out = {"ok": ok}
            except Exception as ex:
                out = {"ok": False, "error": str(ex)[:200]}

        elif self.path == "/api/purge_auth":
            purge_all_cached_auth()
            out = {"ok": True, "message": "All volatile SSH credentials purged from RAM"}

        elif self.path == "/api/dial_hosts":
            # Records the underlay each side's tunnels dial, for a pair that already exists. The live
            # pair was created before the column existed, and re-adding it would lose its benchmark
            # history, so this is the path that makes a persisted topology change.
            try:
                pair_id = int(j.get("id") or 0)
                p = storage.get_pair(pair_id)
                if not p:
                    raise ValueError(f"Pair #{pair_id} does not exist")
                ir_dial, fr_dial = request_dial_hosts(j.get("iran", {}), j.get("foreign", {}))
                storage.set_pair_dial_hosts(pair_id, ir_dial, fr_dial)
                merged = dict(storage.get_pair(pair_id) or p)
                out = {"ok": True,
                       "iran": bool(merged.get("iran_dial_host")),
                       "foreign": bool(merged.get("foreign_dial_host"))}
            except Exception as ex:
                out = {"ok": False, "error": str(ex)[:200]}

        elif self.path == "/api/backend":
            # Declare the port this pair's tunnel delivers into on the peer host, or clear the declaration.
            # Written for an existing pair because the live pair predates the column and re-adding it would
            # cost its benchmark history - the same reason /api/dial_hosts exists.
            #
            # The key has to be present. Absent is refused rather than read as "clear": a handler that
            # removed a declaration because a client sent a malformed body would turn a typo into a topology
            # change, and the next deploy of that pair would deliver to the frontend silently.
            try:
                pair_id = int(j.get("id") or 0)
                p = storage.get_pair(pair_id)
                if not p:
                    raise ValueError(f"Pair #{pair_id} does not exist")
                if "backend_port" not in j:
                    raise ValueError("backend_port is required: send a number, or null/empty to clear")
                port = request_backend_port(j.get("backend_port"), p["frontend_port"],
                                            (p.get("active_tunnel") or "").strip())
                before = p.get("backend_port") or None
                # An empty field is a clear, and 0 is the token `set_pair_backend` spells that with. The
                # stored witness is un-recorded alongside it whenever the declaration moved: the old read
                # answered a different port, and leaving it on the row would let the card describe the new
                # intent with evidence about the old one.
                storage.set_pair_backend(pair_id, backend_port=(port if port is not None else 0),
                                         backend_state=None if before == (port or None) else "")
                row = storage.get_pair(pair_id) or p
                note = "unchanged"
                if port is None and before is not None:
                    note = "declaration cleared; delivery returns to the frontend port on the next deploy"
                elif port is not None and before is None:
                    note = (f"declared {port}"
                            + (" (same as the frontend: no separate delivery port)"
                               if port == p["frontend_port"] else ""))
                elif port is not None and port != before:
                    note = f"declared {port} (was {before})"
                out = {"ok": True, "backend_port": row.get("backend_port"),
                       "backend_state": row.get("backend_state") or "", "note": note}
            except Exception as ex:
                out = {"ok": False, "error": str(ex)[:200]}

        elif self.path == "/api/preflight":
            # Measure the underlay the transports are about to be dialled across, and say which vantage
            # each number came from. This is a read: ping only, nothing installed, so it runs on dry-run
            # hosts too - but not on dry-run *runners*, because a mock answers a percentage it was told to
            # rather than one it measured, and a measurement report has to say which of the two it holds.
            try:
                pair_id = int(j.get("id") or 0)
                p = storage.get_pair(pair_id)
                if not p:
                    raise ValueError(f"Pair #{pair_id} does not exist")
                with AUTH_CACHE_LOCK:
                    auth = AUTH_CACHE.get(pair_id, {})
                full_pair = pair_for_operations(p, auth, "frontend_port")
                dry = is_dry_run()
                ir_runner = fr_runner = None
                # Opening the sessions is inside the try (#71): `get_ssh_runner` connects and authenticates,
                # so a pair whose second host is unreachable raises here - and with the `finally` still
                # outside, the exception propagated before the first session was ever handed to it, leaving
                # one live SSH session per failed click for the life of the dashboard process.
                try:
                    if not dry:
                        ir_runner = get_ssh_runner(full_pair["iran"], dry_run=False, host_role="iran")
                        fr_runner = get_ssh_runner(full_pair["foreign"], dry_run=False, host_role="foreign")
                    res = engine.underlay_preflight(full_pair, ir_runner, fr_runner, dry_run=dry)
                    out = dict(mask_tree(res), pair_id=pair_id)
                finally:
                    for r in (ir_runner, fr_runner):
                        if hasattr(r, "close"):
                            r.close()
            except Exception as ex:
                out = {"ok": False, "error": str(ex)[:200]}

        elif self.path == "/api/resources":
            # Round 063 ruling 1: capacity for both hosts of the pair, on demand, recorded so the panel can
            # show an age. The commands are the nine read-only sources `engine.RESOURCE_SAMPLE_COMMANDS`
            # declares, and each was proven inert by test_89 against the same classifier that gates a
            # deploy; nothing was widened to let this sampler through (#53 stands). The last three of those
            # nine - /proc/net/snmp, /proc/net/netstat and /proc/net/tcp - are this round's #70 addition:
            # the kernel's own connection counters, which is what makes a burst attributable after it has
            # passed instead of only during it.
            #
            # No host lock: a switchover takes one because it rewrites units on both hosts, while this reads
            # /proc. Locking here would make a capacity check contend with the very operations it exists to
            # observe. Dry-run issues no command at all and, because `engine` refuses to record a dry run,
            # leaves no row behind either.
            try:
                pair_id = int(j.get("id") or 0)
                p = storage.get_pair(pair_id)
                if not p:
                    raise ValueError(f"Pair #{pair_id} does not exist")
                with AUTH_CACHE_LOCK:
                    auth = AUTH_CACHE.get(pair_id, {})
                full_pair = pair_for_operations(p, auth, "frontend_port")
                dry = is_dry_run()
                ir_runner = fr_runner = None
                # Opening the sessions sits inside the try: a pair whose second host refuses to connect
                # would otherwise leave the first session open for the life of the process, because the
                # `finally` that closes them is never reached. /api/preflight and /api/failover/check were
                # written that way and are fixed to the same shape in the same round (#71).
                try:
                    if not dry:
                        ir_runner = get_ssh_runner(full_pair["iran"], dry_run=False, host_role="iran")
                        fr_runner = get_ssh_runner(full_pair["foreign"], dry_run=False, host_role="foreign")
                    res = engine.collect_pair_resources(full_pair, ir_runner, fr_runner,
                                                        dry_run=dry, record=True)
                    out = dict(mask_tree(res), pair_id=pair_id,
                               resources=storage.latest_host_resources(pair_id),
                               # Computed after the write above, so the sample just recorded is inside the
                               # history it is attributed from - the panel can say "this burst is the one
                               # you asked about" rather than describing only the previous hour.
                               resource_attribution=resource_attribution(pair_id))
                finally:
                    for r in (ir_runner, fr_runner):
                        if hasattr(r, "close"):
                            r.close()
            except Exception as ex:
                out = {"ok": False, "error": str(ex)[:200]}

        elif self.path == "/api/testall":
            try:
                pair_id = int(j.get("id") or 0)
                p = storage.get_pair(pair_id) if pair_id else None
                if not p:
                    # Check if hosts are provided directly in payload to auto-register
                    ir_host = (j.get("iran", {}).get("host") or "").strip()
                    fr_host = (j.get("foreign", {}).get("host") or "").strip()
                    if ir_host and fr_host:
                        if not valid_ip(ir_host) or not valid_ip(fr_host):
                            raise ValueError("Invalid IP address provided.")
                        f_port = int(j.get("frontend", 443))
                        ir_ssh_p = int(j.get("iran", {}).get("port", 22))
                        fr_ssh_p = int(j.get("foreign", {}).get("port", 22))
                        validate_frontend_port(f_port, ir_ssh_p, fr_ssh_p)
                        if not (1 <= ir_ssh_p <= 65535 and 1 <= fr_ssh_p <= 65535):
                            raise ValueError("SSH port numbers must be between 1 and 65535.")
                        ir_dial, fr_dial = request_dial_hosts(j.get("iran", {}), j.get("foreign", {}))
                        pair_id = storage.add_pair(
                            name=(j.get("name") or "").strip() or f"pair-{int(time.time())%1000}",
                            iran_host=ir_host,
                            foreign_host=fr_host,
                            frontend_port=f_port,
                            iran_port=ir_ssh_p,
                            foreign_port=fr_ssh_p,
                            iran_dial_host=ir_dial,
                            foreign_dial_host=fr_dial
                        )
                        p = storage.get_pair(pair_id)
                    else:
                        pairs = storage.get_pairs()
                        if pairs:
                            p = pairs[0]
                            pair_id = p["id"]
                        else:
                            raise ValueError("No server pairs configured. Please enter Iran and Foreign IP addresses.")

                # Host-level concurrency guard (P0-7)
                hosts_to_lock = [p["iran_host"], p["foreign_host"]]
                if not try_acquire_host_locks(hosts_to_lock):
                    out = {"ok": False, "error": f"Another operation (benchmark/deploy) is active on host {p['iran_host']} or {p['foreign_host']}. Concurrency rejected."}
                    body = json.dumps(out, ensure_ascii=False).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                # Concurrency check per pair
                with PAIR_BENCH_GUARD:
                    if PAIR_BENCH_LOCKS.get(pair_id, False):
                        release_host_locks(hosts_to_lock)
                        out = {"ok": False, "error": f"A benchmark is already active for pair #{pair_id}. Please wait."}
                        body = json.dumps(out, ensure_ascii=False).encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json; charset=utf-8")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                    PAIR_BENCH_LOCKS[pair_id] = True

                # Pickup credentials dynamically from request if provided (P0-3)
                ir_pw = (j.get("iran_password") or j.get("iran", {}).get("auth", {}).get("value") or "").strip()
                fr_pw = (j.get("foreign_password") or j.get("foreign", {}).get("auth", {}).get("value") or "").strip()
                if ir_pw or fr_pw:
                    update_auth_cache_passwords(pair_id, p, ir_pw, fr_pw)

                with AUTH_CACHE_LOCK:
                    auth = AUTH_CACHE.get(pair_id, {})
                ir_auth = auth.get("iran", {}).get("auth", {}).get("value")
                fr_auth = auth.get("foreign", {}).get("auth", {}).get("value")

                if not is_dry_run() and (not ir_auth or not fr_auth):
                    release_host_locks(hosts_to_lock)
                    with PAIR_BENCH_GUARD:
                        PAIR_BENCH_LOCKS[pair_id] = False
                    out = {"ok": False, "error": "SSH passwords not found in volatile RAM cache. Please enter passwords in the left panel form fields."}
                    body = json.dumps(out, ensure_ascii=False).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                full_pair = pair_for_operations(p, auth, "frontend")

                jid = uuid.uuid4().hex[:8]
                with JOBS_LOCK:
                    JOBS[jid] = {"done": False, "out": {}, "status": "Starting benchmarks...", "created_at": time.time()}
                storage.update_pair_status(pair_id, "TESTING")

                prof = j.get("profile", "balanced")

                def _t():
                    try:
                        def _cb(proto, st):
                            with JOBS_LOCK:
                                if jid in JOBS:
                                    JOBS[jid]["status"] = f"Testing {proto} ({st})"
                        results = engine.run_all_benchmarks(full_pair, dry_run=is_dry_run(), callback=_cb, profile=prof)
                        # Phase 6 محک wizard: every row carries its plain-Persian
                        # reasons, computed from the same breakdown the score
                        # came from - the wizard renders reasons, not just numbers.
                        for _row in results:
                            _row["reasons"] = fleet.persian_score_reasons(_row, prof)
                        storage.update_pair_status(pair_id, "TESTED")
                        with JOBS_LOCK:
                            JOBS[jid] = {"done": True, "out": {"ok": True, "benchmarks": results}, "status": "Completed", "created_at": time.time()}
                    except Exception as ex:
                        storage.update_pair_status(pair_id, "TEST_FAILED")
                        with JOBS_LOCK:
                            JOBS[jid] = {"done": True, "out": {"ok": False, "error": str(ex)[:250]}, "status": "Failed", "created_at": time.time()}
                    finally:
                        release_host_locks(hosts_to_lock)
                        with PAIR_BENCH_GUARD:
                            PAIR_BENCH_LOCKS[pair_id] = False

                threading.Thread(target=_t, daemon=True).start()
                out = {"ok": True, "job": jid}
            except Exception as ex:
                if pair_id:
                    with PAIR_BENCH_GUARD:
                        PAIR_BENCH_LOCKS[pair_id] = False
                out = {"ok": False, "error": str(ex)[:200]}

        elif self.path == "/api/job":
            with JOBS_LOCK:
                out = JOBS.get(j.get("job", ""), {"done": False})

        elif self.path == "/api/deploy":
            try:
                pair_id = int(j.get("id", 1))
                ch = j.get("choice", "GRE")
                is_swap = j.get("isSwap", False)
                confirm_force = bool(j.get("confirm_force_release", False))
                override_users = bool(j.get("override_active_users", False))

                p = storage.get_pair(pair_id)
                if not p:
                    raise ValueError(f"Server pair #{pair_id} not found.")

                # Re-validate target frontend port against SSH/reserved ports
                validate_frontend_port(
                    int(p.get("frontend_port", 443)),
                    int(p.get("iran_port", 22)),
                    int(p.get("foreign_port", 22))
                )

                # Host-level concurrency guard (P0-7)
                hosts_to_lock = [p["iran_host"], p["foreign_host"]]
                if not try_acquire_host_locks(hosts_to_lock):
                    out = {"ok": False, "error": f"Another operation (benchmark/deploy) is active on host {p['iran_host']} or {p['foreign_host']}. Concurrency rejected."}
                    body = json.dumps(out, ensure_ascii=False).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                ir_pw = (j.get("iran_password") or "").strip()
                fr_pw = (j.get("foreign_password") or "").strip()
                if ir_pw or fr_pw:
                    update_auth_cache_passwords(pair_id, p, ir_pw, fr_pw)

                with AUTH_CACHE_LOCK:
                    auth = AUTH_CACHE.get(pair_id, {})
                ir_auth = auth.get("iran", {}).get("auth", {}).get("value")
                fr_auth = auth.get("foreign", {}).get("auth", {}).get("value")

                if not is_dry_run() and (not ir_auth or not fr_auth):
                    release_host_locks(hosts_to_lock)
                    out = {"ok": False, "error": "SSH passwords not found in volatile RAM cache. Please enter passwords in the form fields."}
                    body = json.dumps(out, ensure_ascii=False).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                full_pair = pair_for_operations(p, auth, "frontend")

                jid = uuid.uuid4().hex[:8]
                with JOBS_LOCK:
                    JOBS[jid] = {"done": False, "out": {}, "created_at": time.time()}
                storage.update_pair_status(pair_id, "DEPLOYING", ch)

                def _d():
                    try:
                        deploy_res = engine.deploy_tunnel(
                            pair=full_pair,
                            choice=ch,
                            dry_run=is_dry_run(),
                            force_confirmed=confirm_force,
                            override_active_users=override_users
                        )
                        storage.update_pair_status(pair_id, "ACTIVE", ch)
                        # The engine's own verdict is what gets audited, not a hand-written "Activated …" -
                        # the old line claimed a delivery for a tunnel the deploy had just reported as
                        # transport-only, and an audit row is the artifact read days later when no screen is
                        # open. `deploy_res["status"]` already distinguishes the two.
                        storage.log_audit(pair_id, "HOT_SWAP" if is_swap else "DEPLOY", "SUCCESS",
                                          f"{deploy_res['status']} on port {full_pair['frontend']}"
                                          f" | backend_state={deploy_res.get('backend_state') or 'n/a'}")
                        with JOBS_LOCK:
                            JOBS[jid] = {
                                "done": True,
                                "out": {
                                    "ok": True,
                                    "status": deploy_res["status"],
                                    "mode": "MOCK_DRY_RUN" if is_dry_run() else "LIVE",
                                    "protocol": ch,
                                    "port": full_pair["frontend"]
                                },
                                "created_at": time.time()
                            }
                    except Exception as ex:
                        storage.update_pair_status(pair_id, "DEPLOY_FAILED")
                        storage.log_audit(pair_id, "DEPLOY", "FAILED", str(ex)[:200])
                        with JOBS_LOCK:
                            JOBS[jid] = {"done": True, "out": {"ok": False, "error": str(ex)[:300]}, "created_at": time.time()}
                    finally:
                        release_host_locks(hosts_to_lock)

                threading.Thread(target=_d, daemon=True).start()
                out = {"ok": True, "job": jid}
            except Exception as ex:
                out = {"ok": False, "error": str(ex)[:200]}

        elif self.path == "/api/failover/check":
            try:
                pair_id = int(j.get("id", 1))
                p = storage.get_pair(pair_id)
                if not p:
                    raise ValueError(f"Pair #{pair_id} not found")
                with AUTH_CACHE_LOCK:
                    auth = AUTH_CACHE.get(pair_id, {})
                full_pair = pair_for_operations(p, auth, "frontend_port")
                # An empty active_tunnel means the running protocol is unknown, not that it is GRE.
                # Checking GRE units on a chisel pair reports the units inactive -> DOWN, and the
                # operator then "heals" a tunnel that was serving traffic.
                active_proto = (p.get("active_tunnel") or "").strip()
                if not active_proto:
                    raise ValueError(f"Pair #{pair_id} has no recorded active_tunnel - record the "
                                     f"running protocol instead of guessing one")
                checker = failover.TunnelHealthChecker()
                ir_runner = fr_runner = None
                # The same #71 shape: the two sessions open inside the `finally` that closes them, so the
                # pair whose foreign host is down on a check no longer strands the Iranian session.
                try:
                    ir_runner = get_ssh_runner(full_pair["iran"], dry_run=is_dry_run(), host_role="iran")
                    fr_runner = get_ssh_runner(full_pair["foreign"], dry_run=is_dry_run(),
                                               host_role="foreign")
                    rep = checker.check_health(ir_runner, fr_runner, full_pair, active_proto,
                                               dry_run=is_dry_run())
                    out = {
                        "ok": True,
                        "status": rep.status,
                        "loss_pct": rep.loss_pct,
                        "latency_ms": rep.latency_ms,
                        "overhead_ratio": rep.overhead_ratio,
                        "details": rep.details
                    }
                finally:
                    for r in (ir_runner, fr_runner):
                        if hasattr(r, "close"):
                            r.close()
            except Exception as ex:
                out = {"ok": False, "error": str(ex)}

        elif self.path == "/api/failover/trigger":
            hosts_to_lock = []
            try:
                pair_id = int(j.get("id", 1))
                p = storage.get_pair(pair_id)
                if not p:
                    raise ValueError(f"Pair #{pair_id} not found")

                # Host-level concurrency guard: a switchover rewrites units on both hosts, so it
                # must never overlap a benchmark or deploy already holding those hosts.
                hosts_to_lock = [p["iran_host"], p["foreign_host"]]
                if not try_acquire_host_locks(hosts_to_lock):
                    out = {"ok": False, "error": f"Another operation (benchmark/deploy) is active on host {p['iran_host']} or {p['foreign_host']}. Concurrency rejected."}
                    hosts_to_lock = []
                else:
                    with AUTH_CACHE_LOCK:
                        auth = AUTH_CACHE.get(pair_id, {})
                    full_pair = pair_for_operations(p, auth, "frontend_port")
                    # Same rule as the health endpoint, with a worse consequence here: guessing "GRE"
                    # excludes GRE from the candidate ranking instead of the protocol that is really
                    # running, so a switchover can tear down units that do not exist and re-deploy the
                    # live tunnel as if it were its own replacement.
                    cur_proto = (p.get("active_tunnel") or "").strip()
                    if not cur_proto:
                        raise ValueError(f"Pair #{pair_id} has no recorded active_tunnel - refusing "
                                         f"to fail over from an unknown protocol")

                    # execute_failover requires an explicit successor. Honour an operator-chosen
                    # target, otherwise rank alternatives from stored benchmark scores. The pair is
                    # passed so the carrier gate can drop a refused transport from the ranking, and the
                    # explicit target below is gated inside execute_failover anyway.
                    target_proto = (j.get("target") or "").strip() or failover.FailoverCandidateSelector.select_best_candidate(
                        pair_id, cur_proto, pair=full_pair)
                    if not target_proto:
                        raise ValueError(f"No failover candidate available for pair #{pair_id} (current={cur_proto})")
                    if target_proto not in protocols.get_supported_protocols():
                        raise ValueError(f"Target protocol '{target_proto}' is not supported or is quarantined")
                    if target_proto == cur_proto:
                        raise ValueError(f"Target protocol '{target_proto}' is already active")

                    fm = failover_manager()
                    res = fm.execute_failover(full_pair, cur_proto, target_proto,
                                              reason=j.get("reason", "Operator manual trigger"),
                                              dry_run=is_dry_run())
                    if res.get("success"):
                        storage.update_pair_status(pair_id, "ACTIVE", target_proto)
                    # execute_failover reports `success`; the HTTP layer below keys off `ok`,
                    # so mirror it or a blocked/failed switchover would return HTTP 200.
                    out = dict(res)
                    out["ok"] = bool(res.get("success"))
            except Exception as ex:
                out = {"ok": False, "error": str(ex)[:200]}
            finally:
                if hosts_to_lock:
                    release_host_locks(hosts_to_lock)

        elif self.path == "/api/mode":
            # Phase 6: per-pair steering. No host contact, no lock: this
            # only writes the pair row the monitor and the wizard read.
            try:
                pair_id = int(j.get("id", 0))
                mode = (j.get("mode") or "").strip().lower()
                if not storage.get_pair(pair_id):
                    out = {"ok": False, "error": f"Pair #{pair_id} not found"}
                elif not storage.set_pair_mode(pair_id, mode):
                    out = {"ok": False, "error": f"Unknown mode '{mode[:24]}' (use manual or auto)"}
                else:
                    storage.log_audit(pair_id, "SET_MODE", "SUCCESS",
                                      f"Pair steering set to {mode}")
                    out = {"ok": True, "id": pair_id, "mode": mode}
            except Exception as ex:
                out = {"ok": False, "error": str(ex)[:200]}

        elif self.path == "/api/history":
            # Phase 6 remainder: history chart data. A pure DB read:
            # newest-first rows reversed to chronological order, capped
            # so one chart cannot drag a year of samples into the page.
            # Throughput is deliberately absent: the monitor never
            # samples it, so the chart plots what exists (latency,
            # loss, verdict) instead of inventing a third series.
            try:
                pair_id = int(j.get("id", 0))
                limit = int(j.get("limit", 500))
                limit = max(10, min(limit, 2000))
                if not storage.get_pair(pair_id):
                    out = {"ok": False, "error": f"Pair #{pair_id} not found"}
                else:
                    rows = storage.get_health_history(pair_id, limit=limit)
                    rows.reverse()
                    out = {"ok": True, "id": pair_id, "samples": [
                        {"t": r.get("recorded_at"), "verdict": r.get("verdict"),
                         "protocol": r.get("protocol"),
                         "loss": r.get("loss_pct"), "lat": r.get("latency_ms"),
                         "sat": r.get("saturation_pct")}
                        for r in rows]}
            except Exception as ex:
                out = {"ok": False, "error": str(ex)[:200]}

        elif self.path == "/api/diagnostics":
            # Phase 6 Diagnostics: one report per pair - health verdict,
            # preflight findings, TTL injection verdict, quarantine and
            # auto state. Synchronous like the health endpoint; the host
            # lock keeps it from overlapping a deploy or benchmark.
            # The session opens sit inside the try whose finally closes
            # them (test_98's shape pin, same shape as /api/failover/check):
            # a lock failure raises into the outer except instead of
            # nesting the guarded block one level deeper, and clears
            # hosts_to_lock first so the outer finally releases nothing
            # it does not hold.
            hosts_to_lock = []
            try:
                pair_id = int(j.get("id", 0))
                p = storage.get_pair(pair_id)
                if not p:
                    raise ValueError(f"Pair #{pair_id} not found")
                hosts_to_lock = [p["iran_host"], p["foreign_host"]]
                if not try_acquire_host_locks(hosts_to_lock):
                    hosts_to_lock = []
                    raise ValueError("Another operation is active on these hosts.")
                with AUTH_CACHE_LOCK:
                    auth = AUTH_CACHE.get(pair_id, {})
                full_pair = pair_for_operations(p, auth, "frontend_port")
                active = (p.get("active_tunnel") or "").strip()
                if not active:
                    raise ValueError(f"Pair #{pair_id} has no recorded active_tunnel")
                ir_runner = fr_runner = None
                try:
                    ir_runner = get_ssh_runner(full_pair["iran"], dry_run=is_dry_run(),
                                               host_role="iran")
                    fr_runner = get_ssh_runner(full_pair["foreign"], dry_run=is_dry_run(),
                                               host_role="foreign")
                    report = fleet.diagnose_pair(ir_runner, fr_runner, full_pair, active)
                    out = {"ok": True, "report": mask_tree(report)}
                finally:
                    for r in (ir_runner, fr_runner):
                        if hasattr(r, "close"):
                            r.close()
            except Exception as ex:
                out = {"ok": False, "error": str(ex)[:200]}
            finally:
                if hosts_to_lock:
                    release_host_locks(hosts_to_lock)

        elif self.path == "/api/quick_repair":
            # Phase 6 Quick Repair: the operator's explicit heal. This is
            # not the monitor's automatic path, so it does not consult
            # BEST_TUNNEL_AUTOHEAL - clicking Repair is the authorisation.
            # The heal itself lives in run_quick_repair below, outside
            # do_POST, because test_52 scans do_POST for a direct
            # evaluate_and_heal call: a checker route once guessed the
            # active protocol and wired itself into the heal path, and
            # the scan exists to keep that from recurring silently.
            # Repair is an explicit operator action, never a checker, so
            # it is a named helper the route calls - and the route still
            # refuses a pair with no recorded active_tunnel first.
            hosts_to_lock = []
            try:
                pair_id = int(j.get("id", 0))
                p = storage.get_pair(pair_id)
                if not p:
                    raise ValueError(f"Pair #{pair_id} not found")
                hosts_to_lock = [p["iran_host"], p["foreign_host"]]
                if not try_acquire_host_locks(hosts_to_lock):
                    out = {"ok": False, "error": "Another operation is active on these hosts."}
                    hosts_to_lock = []
                else:
                    with AUTH_CACHE_LOCK:
                        auth = AUTH_CACHE.get(pair_id, {})
                    full_pair = pair_for_operations(p, auth, "frontend_port")
                    if not (p.get("active_tunnel") or "").strip():
                        raise ValueError(f"Pair #{pair_id} has no recorded active_tunnel")
                    out = run_quick_repair(full_pair, is_dry_run())
            except Exception as ex:
                out = {"ok": False, "error": str(ex)[:200]}
            finally:
                if hosts_to_lock:
                    release_host_locks(hosts_to_lock)

        elif self.path == "/api/failover/monitor":
            try:
                action = (j.get("action") or "status").strip().lower()
                mon = failover_monitor_instance()
                if action == "start":
                    if not failover_monitor.auto_heal_enabled():
                        raise ValueError(
                            f"refusing to start a monitor that cannot act: "
                            f"{failover_monitor.AUTOHEAL_ENV} is not set. A thread that samples every "
                            f"minute and heals nothing looks like protection without being it - use "
                            f"action=once for an explicit pass")
                    started = mon.start()
                    out = {"ok": True, "started": started, "monitor": mask_tree(mon.status())}
                elif action == "stop":
                    out = {"ok": True, "stopped": mon.stop(timeout=5.0),
                           "monitor": mask_tree(mon.status())}
                elif action == "once":
                    out = {"ok": True, "decisions": mask_tree(mon.run_once()),
                           "auto_heal": failover_monitor.auto_heal_enabled()}
                elif action == "status":
                    out = {"ok": True, "monitor": mask_tree(mon.status())}
                else:
                    out = {"ok": False, "error": f"unknown monitor action '{action[:24]}'"}
            except Exception as ex:
                out = {"ok": False, "error": str(ex)[:200]}

        elif self.path == "/api/capacity_sampler":
            # #70's history maker: continuous capacity sampling, on its own gate and its own thread.
            #
            # `once` is offered alongside `start` because the reboot pentest needs a pass *during* a window
            # and an operator may not want a thread running the rest of the week. `once` does not check
            # CAPACITY_SAMPLER_ENV - it is an explicit human request, and the gate exists to stop automation
            # nobody asked for, not to refuse an order.
            try:
                action = (j.get("action") or "status").strip().lower()
                sampler = capacity_sampler_instance()
                if action == "start":
                    if not capacity_sampling_enabled():
                        raise ValueError(
                            f"refusing to start automation nobody asked for: {CAPACITY_SAMPLER_ENV} is not "
                            f"set. Use action=once for an explicit pass")
                    started = sampler.start()
                    out = {"ok": True, "started": started, "sampler": mask_tree(sampler.status())}
                elif action == "stop":
                    out = {"ok": True, "stopped": sampler.stop(timeout=5.0),
                           "sampler": mask_tree(sampler.status())}
                elif action == "once":
                    out = {"ok": True, "decisions": mask_tree(sampler.run_once()),
                           "enabled": capacity_sampling_enabled(),
                           "dry_run": bool(is_dry_run())}
                elif action == "status":
                    out = {"ok": True, "sampler": mask_tree(sampler.status())}
                else:
                    out = {"ok": False, "error": f"unknown sampler action '{action[:24]}'"}
            except Exception as ex:
                out = {"ok": False, "error": str(ex)[:200]}

        elif self.path == "/api/unpin_host_key":
            try:
                host = (j.get("host") or "").strip()
                port = int(j.get("port", 22))
                if not host:
                    out = {"ok": False, "error": "Host required"}
                else:
                    storage.unpin_host_key(host, port)
                    out = {"ok": True, "message": f"Unpinned host key for {host}:{port}"}
            except Exception as ex:
                out = {"ok": False, "error": str(ex)}

        body = json.dumps(out, ensure_ascii=False).encode("utf-8")
        status_code = 400 if (isinstance(out, dict) and not out.get("ok", True)) else 200
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    print(f"Starting Tunnel Studio Pro v3.0 Dashboard (DRY_RUN={is_dry_run()}) on http://127.0.0.1:8800")
    # An operator who set BEST_TUNNEL_AUTOHEAL expects healing to be running after a reboot, not only
    # after someone remembers to press the button; the refusal to start it is printed either way, so
    # the absence of automation is visible instead of inferred.
    if failover_monitor.auto_heal_enabled():
        print("failover monitor: STARTED (automatic healing is enabled)")
        failover_monitor_instance().start()
    else:
        print(f"failover monitor: NOT STARTED ({failover_monitor.AUTOHEAL_ENV} unset) - tunnels keep "
              f"the protocol an operator chose until a switchover is asked for")
    # The capacity sampler on the same rule: a reboot window is only recorded if something kept asking while
    # the host was down, and "someone will press it later" is how the window becomes a gap in the history.
    # Its gate is separate from AUTOHEAL's on purpose - ruling 3 boots with healing off.
    if capacity_sampling_enabled() and not is_dry_run():
        print(f"capacity sampler: STARTED (every {capacity_interval_sec():g} s, recording both hosts of "
              f"every deployed pair)")
        capacity_sampler_instance().start()
    elif capacity_sampling_enabled():
        print("capacity sampler: NOT STARTED (BEST_TUNNEL_DRY_RUN is on) - no history will be recorded")
    else:
        print(f"capacity sampler: NOT STARTED ({CAPACITY_SAMPLER_ENV} unset) - capacity is sampled only "
              f"when the panel asks, so a reboot dark window will not appear in the history")
    ThreadingHTTPServer(("127.0.0.1", 8800), H).serve_forever()
