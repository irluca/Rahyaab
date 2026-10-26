"""HTTP JSON API for the Rahyaab hub (stdlib http.server only).

Routes (all under /api, all require a session except health/login/
first-time setup):
    GET  /api/health
    POST /api/setup            {username, password} — only when no user exists
    POST /api/login            {username, password} -> session cookie
    POST /api/logout
    GET  /api/servers          POST /api/servers
    GET  /api/servers/{id}     DELETE /api/servers/{id}
    GET  /api/pairs            POST /api/pairs
    GET  /api/pairs/{id}       DELETE /api/pairs/{id}
    GET  /api/pairs/{id}/healer
    POST /api/pairs/{id}/healer/{start,stop,restart}
    GET  /api/jobs             POST /api/jobs
    GET  /api/jobs/{id}
    GET  /api/events

The dashboard (Phase 3) is a separate static frontend served from
dashboard/; this module serves API only. The hub binds localhost by
default — remote access is via SSH forwarding until TLS lands.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import auth, healerctl, metrics
from .jobs import HANDLERS, Worker
from .ssh import executor_for_server
from .store import Store

SESSION_COOKIE = "rahyaab_session"
_MAX_LOGIN_FAILURES = 10
_LOGIN_WINDOW_SECONDS = 300


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _public_server(row: dict) -> dict:
    return {k: row[k] for k in
            ("id", "name", "host", "port", "username", "key_path", "notes", "created_at")}


def _public_pair(row: dict) -> dict:
    return row  # pairs carry no secrets


class Collector(threading.Thread):
    """Samples real metrics every minute: per-server load/memory/disk/
    uptime and per-pair tunnel latency + carrier byte counters.

    Failures are swallowed per item: a dead server must not stop the
    collector, and a missing sample is simply a gap in the chart.
    """

    def __init__(self, store: Store, make_executor=None,
                 interval: float = 60.0, first_delay: float = 5.0):
        super().__init__(daemon=True, name="rahyaab-collector")
        self.store = store
        self.make_executor = make_executor
        self.interval = interval
        self.first_delay = first_delay
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def _executor(self, server: dict):
        fake = self.make_executor(server) if self.make_executor else None
        return executor_for_server(server, fake=fake)

    def run(self) -> None:
        if self._stop.wait(self.first_delay):
            return
        while not self._stop.is_set():
            try:
                self.collect_once()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def collect_once(self) -> None:
        seen_servers: set[int] = set()
        for pair in self.store.list_pairs():
            healer_server = self.store.get_server(pair["healer_server_id"])
            if healer_server is None:
                continue
            for server_id in (pair["iran_server_id"], pair["foreign_server_id"]):
                if server_id in seen_servers:
                    continue
                seen_servers.add(server_id)
                server = self.store.get_server(server_id)
                if server is None:
                    continue
                try:
                    self.store.add_server_metric(
                        server_id, metrics.collect_server(self._executor(server)))
                except Exception:
                    pass
            try:
                self.store.add_pair_metric(
                    pair["id"], metrics.collect_pair(self._executor(healer_server), pair))
            except Exception:
                pass


class Hub:
    def __init__(self, store: Store, make_executor=None, enable_collector: bool = False):
        self.store = store
        self.make_executor = make_executor
        # Set by serve() when TLS is on. The session cookie is then
        # Secure-only, and HSTS is advertised: once the panel is
        # public, browsers must never send the cookie over plain HTTP.
        self.tls_enabled = False
        self.collector = None
        if enable_collector:
            self.collector = Collector(store, make_executor=make_executor)
            self.collector.start()
        self._login_failures: dict[str, list[float]] = {}
        self._failures_lock = threading.Lock()
        self.worker = Worker(store, make_executor=make_executor)
        self.worker.start()

    # -- auth helpers ------------------------------------------------------
    def _check_login_rate(self, ip: str) -> None:
        now = time.time()
        with self._failures_lock:
            attempts = [t for t in self._login_failures.get(ip, [])
                        if now - t < _LOGIN_WINDOW_SECONDS]
            self._login_failures[ip] = attempts
            if len(attempts) >= _MAX_LOGIN_FAILURES:
                raise ApiError(429, "too many failed logins, try again later")

    def _record_login_failure(self, ip: str) -> None:
        with self._failures_lock:
            self._login_failures.setdefault(ip, []).append(time.time())

    def setup(self, body: dict) -> dict:
        if self.store.user_count() > 0:
            raise ApiError(403, "hub already has an operator account")
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        if len(username) < 3 or len(password) < 8:
            raise ApiError(400, "username needs 3+ chars, password 8+ chars")
        user = self.store.create_user(username, auth.hash_password(password))
        self.store.log_event("setup", "First operator account created")
        return {"id": user["id"], "username": user["username"]}

    def login(self, body: dict, ip: str) -> str:
        self._check_login_rate(ip)
        user = self.store.get_user((body.get("username") or "").strip())
        if user is None or not auth.verify_password(body.get("password") or "",
                                                    user["password_hash"]):
            self._record_login_failure(ip)
            raise ApiError(401, "invalid username or password")
        token = auth.new_session_token()
        self.store.create_session(
            auth.hash_token(token), user["id"],
            time.time() + auth.SESSION_TTL_SECONDS)
        return token

    def authenticate(self, token: str | None) -> dict:
        if not token:
            raise ApiError(401, "login required")
        session = self.store.get_session(auth.hash_token(token))
        if session is None:
            raise ApiError(401, "session expired or invalid")
        return session

    def logout(self, token: str | None) -> None:
        if token:
            self.store.delete_session(auth.hash_token(token))

    # -- servers -----------------------------------------------------------
    def create_server(self, body: dict) -> dict:
        name = (body.get("name") or "").strip()
        host = (body.get("host") or "").strip()
        port = body.get("port") or 22
        if not name or not host:
            raise ApiError(400, "name and host are required")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ApiError(400, "port must be 1-65535")
        try:
            server = self.store.create_server({
                "name": name, "host": host, "port": port,
                "username": (body.get("username") or "root").strip() or "root",
                "key_path": body.get("key_path"),
                "notes": body.get("notes") or "",
            })
        except sqlite3.IntegrityError:
            raise ApiError(409, "a server with that name already exists")
        self.store.log_event("server_added", "Server %s added (%s)" % (name, host),
                             server_id=server["id"])
        return _public_server(server)

    def delete_server(self, server_id: int) -> None:
        pairs = [p for p in self.store.list_pairs()
                 if server_id in (p["iran_server_id"], p["foreign_server_id"],
                                  p["healer_server_id"])]
        if pairs:
            raise ApiError(409, "server is still used by a pair")
        if not self.store.delete_server(server_id):
            raise ApiError(404, "server not found")

    # -- pairs ---------------------------------------------------------------
    def create_pair(self, body: dict) -> dict:
        name = (body.get("name") or "").strip()
        iran_id = body.get("iran_server_id")
        foreign_id = body.get("foreign_server_id")
        if not name or not iran_id or not foreign_id:
            raise ApiError(400, "name, iran_server_id and foreign_server_id are required")
        if iran_id == foreign_id:
            raise ApiError(400, "a pair needs two different servers")
        if self.store.get_server(iran_id) is None \
                or self.store.get_server(foreign_id) is None:
            raise ApiError(400, "unknown server id")
        healer_id = body.get("healer_server_id") or iran_id
        if self.store.get_server(healer_id) is None:
            raise ApiError(400, "unknown healer server id")
        scores = body.get("candidate_scores") or {}
        if not isinstance(scores, dict):
            raise ApiError(400, "candidate_scores must be an object")
        try:
            pair = self.store.create_pair({
                "name": name, "iran_server_id": iran_id,
                "foreign_server_id": foreign_id, "healer_server_id": healer_id,
                "frontend_port": body.get("frontend_port") or 443,
                "current_protocol": body.get("current_protocol"),
                "inner_iran": body.get("inner_iran"),
                "inner_foreign": body.get("inner_foreign"),
                "candidate_scores": scores,
            })
        except sqlite3.IntegrityError:
            raise ApiError(409, "a pair with that name already exists")
        self.store.log_event("pair_created", "Pair %s created" % name, pair_id=pair["id"])
        return _public_pair(pair)

    def delete_pair(self, pair_id: int) -> None:
        if not self.store.delete_pair(pair_id):
            raise ApiError(404, "pair not found")

    # -- healer --------------------------------------------------------------
    def _healer_executor(self, pair: dict):
        server = self.store.get_server(pair["healer_server_id"])
        if server is None:
            raise ApiError(409, "pair has no healer server")
        fake = self.make_executor(server) if self.make_executor else None
        return pair, executor_for_server(server, fake=fake)

    def healer_status(self, pair_id: int) -> dict:
        pair = self.store.get_pair(pair_id)
        if pair is None:
            raise ApiError(404, "pair not found")
        _, executor = self._healer_executor(pair)
        try:
            result = healerctl.status(executor)
        except Exception as exc:
            result = {"reachable": False, "error": str(exc)}
        self.store.update_pair_healer(pair_id, result)
        return result

    def healer_action(self, pair_id: int, action: str) -> dict:
        pair = self.store.get_pair(pair_id)
        if pair is None:
            raise ApiError(404, "pair not found")
        _, executor = self._healer_executor(pair)
        fn = {"start": healerctl.start, "stop": healerctl.stop,
              "restart": healerctl.restart}[action]
        try:
            result = fn(executor)
        except Exception as exc:
            raise ApiError(502, "healer host unreachable: %s" % exc)
        self.store.log_event("healer_%s" % action,
                             "Healer %s for pair %s" % (action, pair["name"]),
                             pair_id=pair_id, data=result)
        return result

    # -- jobs ------------------------------------------------------------------
    def create_job(self, body: dict) -> dict:
        job_type = body.get("type") or ""
        if job_type not in HANDLERS:
            raise ApiError(400, "unknown job type: %s" % job_type)
        pair_id = body.get("pair_id")
        if pair_id is not None and self.store.get_pair(pair_id) is None:
            raise ApiError(400, "unknown pair id")
        if job_type in ("healer_status", "connectivity") and pair_id is None:
            raise ApiError(400, "this job type needs a pair_id")
        return self.store.create_job(job_type, pair_id, body.get("input") or {})


_STATIC_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                 ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}


def make_handler(hub: Hub, static_dir=None):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep stdout clean
            pass

        def _send_static(self, path: str) -> bool:
            """Serve the Phase 3 dashboard. Returns False when not a static path."""
            if static_dir is None:
                return False
            if path == "/":
                rel = "index.html"
            elif path.startswith("/static/"):
                rel = path[len("/static/"):]
            else:
                return False
            if not rel or ".." in rel.split("/"):
                self._send(404, {"error": "not found"})
                return True
            from pathlib import Path
            target = (Path(static_dir) / rel).resolve()
            base = Path(static_dir).resolve()
            if not str(target).startswith(str(base) + "/") and target != base:
                self._send(404, {"error": "not found"})
                return True
            if target.suffix not in _STATIC_TYPES or not target.is_file():
                self._send(404, {"error": "not found"})
                return True
            body = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", _STATIC_TYPES[target.suffix])
            self.send_header("Content-Length", str(len(body)))
            if hub.tls_enabled:
                self.send_header("Strict-Transport-Security",
                                 "max-age=31536000")
            self.end_headers()
            self.wfile.write(body)
            return True

        # -- plumbing ------------------------------------------------------
        def _send(self, status: int, payload: dict, set_cookie: str | None = None,
                  clear_cookie: bool = False) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if hub.tls_enabled:
                self.send_header("Strict-Transport-Security",
                                 "max-age=31536000")
            secure = "; Secure" if hub.tls_enabled else ""
            if set_cookie:
                self.send_header("Set-Cookie",
                                 "%s=%s; HttpOnly; SameSite=Lax; Path=/api/%s" % (
                                     SESSION_COOKIE, set_cookie, secure))
            if clear_cookie:
                self.send_header("Set-Cookie",
                                 "%s=; HttpOnly; SameSite=Lax; Path=/api/; Max-Age=0%s"
                                 % (SESSION_COOKIE, secure))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                raise ApiError(400, "body must be JSON")
            if not isinstance(data, dict):
                raise ApiError(400, "body must be a JSON object")
            return data

        def _session_token(self) -> str | None:
            cookie = SimpleCookie(self.headers.get("Cookie") or "")
            morsel = cookie.get(SESSION_COOKIE)
            return morsel.value if morsel else None

        def _route(self, method: str, path: str):
            """Returns (status, payload, set_cookie, clear_cookie)."""
            body = self._read_body() if method in ("POST", "PUT") else {}
            if path == "/api/health" and method == "GET":
                return 200, {"ok": True, "users": hub.store.user_count() > 0}, None, False
            if path == "/api/setup" and method == "POST":
                return 201, hub.setup(body), None, False
            if path == "/api/login" and method == "POST":
                token = hub.login(body, self.client_address[0])
                return 200, {"ok": True}, token, False
            # Everything below needs a session.
            hub.authenticate(self._session_token())
            if path == "/api/logout" and method == "POST":
                hub.logout(self._session_token())
                return 200, {"ok": True}, None, True
            if path == "/api/servers" and method == "GET":
                return 200, {"servers": [_public_server(s) for s in hub.store.list_servers()]}, None, False
            if path == "/api/servers" and method == "POST":
                return 201, hub.create_server(body), None, False
            m = re.fullmatch(r"/api/servers/(\d+)", path)
            if m and method == "GET":
                server = hub.store.get_server(int(m.group(1)))
                if server is None:
                    raise ApiError(404, "server not found")
                return 200, _public_server(server), None, False
            if m and method == "DELETE":
                hub.delete_server(int(m.group(1)))
                return 200, {"ok": True}, None, False
            if path == "/api/pairs" and method == "GET":
                return 200, {"pairs": [_public_pair(p) for p in hub.store.list_pairs()]}, None, False
            if path == "/api/pairs" and method == "POST":
                return 201, hub.create_pair(body), None, False
            m = re.fullmatch(r"/api/pairs/(\d+)", path)
            if m and method == "GET":
                pair = hub.store.get_pair(int(m.group(1)))
                if pair is None:
                    raise ApiError(404, "pair not found")
                return 200, _public_pair(pair), None, False
            if m and method == "DELETE":
                hub.delete_pair(int(m.group(1)))
                return 200, {"ok": True}, None, False
            m = re.fullmatch(r"/api/pairs/(\d+)/healer", path)
            if m and method == "GET":
                return 200, hub.healer_status(int(m.group(1))), None, False
            m = re.fullmatch(r"/api/pairs/(\d+)/healer/(start|stop|restart)", path)
            if m and method == "POST":
                return 200, hub.healer_action(int(m.group(1)), m.group(2)), None, False
            m = re.fullmatch(r"/api/pairs/(\d+)/history", path)
            if m and method == "GET":
                pair = hub.store.get_pair(int(m.group(1)))
                if pair is None:
                    raise ApiError(404, "pair not found")
                return 200, {"history": hub.store.list_healer_history(
                    int(m.group(1)))}, None, False
            m = re.fullmatch(r"/api/servers/(\d+)/metrics", path)
            if m and method == "GET":
                if hub.store.get_server(int(m.group(1))) is None:
                    raise ApiError(404, "server not found")
                return 200, {"metrics": hub.store.list_server_metrics(
                    int(m.group(1)))}, None, False
            m = re.fullmatch(r"/api/pairs/(\d+)/metrics", path)
            if m and method == "GET":
                if hub.store.get_pair(int(m.group(1))) is None:
                    raise ApiError(404, "pair not found")
                return 200, {"metrics": hub.store.list_pair_metrics(
                    int(m.group(1)))}, None, False
            if path == "/api/jobs" and method == "GET":
                return 200, {"jobs": hub.store.list_jobs()}, None, False
            if path == "/api/jobs" and method == "POST":
                return 201, hub.create_job(body), None, False
            m = re.fullmatch(r"/api/jobs/(\d+)", path)
            if m and method == "GET":
                job = hub.store.get_job(int(m.group(1)))
                if job is None:
                    raise ApiError(404, "job not found")
                return 200, job, None, False
            if path == "/api/events" and method == "GET":
                return 200, {"events": hub.store.list_events()}, None, False
            raise ApiError(404, "unknown route")

        def _handle(self, method: str) -> None:
            if method == "GET":
                try:
                    if self._send_static(urlparse(self.path).path):
                        return
                except BrokenPipeError:
                    return
                except Exception:
                    pass  # fall through to the API router's error handling
            try:
                status, payload, cookie, clear = self._route(
                    method, urlparse(self.path).path)
                self._send(status, payload, set_cookie=cookie, clear_cookie=clear)
            except ApiError as exc:
                self._send(exc.status, {"error": exc.message})
            except BrokenPipeError:
                pass
            except Exception as exc:  # never leak a stack trace to a client
                self._send(500, {"error": "internal error: %s" % exc})

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_DELETE(self):
            self._handle("DELETE")

    return Handler


def serve(store: Store, host: str = "127.0.0.1", port: int = 8890,
          make_executor=None, static_dir=None,
          tls_cert: str | None = None, tls_key: str | None = None,
          enable_collector: bool = False) -> ThreadingHTTPServer:
    hub = Hub(store, make_executor=make_executor, enable_collector=enable_collector)
    if static_dir is None:
        from pathlib import Path
        candidate = Path(__file__).resolve().parent.parent / "dashboard"
        static_dir = str(candidate) if candidate.is_dir() else None
    server = ThreadingHTTPServer((host, port), make_handler(hub, static_dir))
    if tls_cert and tls_key:
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls_cert, tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        hub.tls_enabled = True
    server.hub = hub  # type: ignore[attr-defined]
    return server
