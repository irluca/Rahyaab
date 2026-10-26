#!/usr/bin/env python3
"""SSH Transport & Simulation Layer for Tunnel Studio Pro v2.0.
Provides:
1. MockSSHClient with distinct host identity modeling (iran vs foreign states separated).
2. SafeSSHRunner wrapping live Paramiko SSHClient enforcing command safety, TOFU, and structured run().
3. Zero-Disk credential isolation (passwords/keys never leaked to disk or diffs).
4. Session recovery: re-open a dropped SSH session with exponential backoff, and re-issue a command
   only when safety can prove the command has no side effects.
"""
import os
import re
import io
import shlex
import random
import time
import json
import safety
from safety import check_command_safe


class TransientTransportError(RuntimeError):
    """The SSH session itself failed, so the command did not complete.

    Distinct from a non-zero exit: a non-zero exit is the *host* answering, this is the answer never
    arriving. Consumers that score tunnels must be able to tell the two apart, because treating an
    unreachable host as an unhealthy tunnel turns a network flap into a protocol switchover.
    """


class HostKeyMismatchError(RuntimeError):
    """A pinned host key changed. Never a network hiccup, and never worth retrying."""


class DeadSessionError(ConnectionError):
    """The session was already down when a command was about to be sent on it.

    It needs its own type for two reasons. First, paramiko does not report this cleanly: on a client
    whose transport has gone, exec_command fails as
    `AttributeError: 'NoneType' object has no attribute 'open_session'`, which names no network error
    at all - witnessed live on 2026-10-10, and the reason the first live run of this recovery layer
    refused to recover. Second, a command that was never sent has no unknown outcome, and the message
    an operator reads should say which of the two they are looking at.

    Inheriting ConnectionError is what makes it transient: the classifier matches names along the MRO.

    `may_have_been_sent` separates the shapes this is raised for, and the separation decides what an
    operator is told. A transport found dead *before* anything was written means the command provably
    never left; a transport that died while the write was in progress, or that died under the read of
    the answer, means nobody can prove what reached the far side - and in the read case the bytes that
    did arrive may stop mid-stream. "The deploy never started" and "the deploy may have half-run" need
    different fixes, so they must not arrive under the same words.
    """

    def __init__(self, message, may_have_been_sent: bool = False):
        super().__init__(message)
        self.may_have_been_sent = may_have_been_sent


# Reconnection parameters. Exponential with a cap, plus jitter: without the jitter, a sweep that
# drops both hosts' sessions at the same instant re-opens them in lockstep and collides again.
RECONNECT_ATTEMPTS = 3
RECONNECT_BASE_SECONDS = 1.0
RECONNECT_CAP_SECONDS = 15.0

# Matched by exception *class name* along the MRO, so a dry-run process classifies failures without
# importing paramiko. These are the names a dropped TCP session actually arrives under.
_TRANSIENT_TYPE_NAMES = frozenset({
    "SSHException", "SSHErrorClass", "NoValidConnectionsError", "ProxyCommandFailure",
    "ChannelException", "SocketTimeout", "ConnectionResetError", "ConnectionAbortedError",
    "BrokenPipeError", "ConnectionError", "NewConnectionError", "gaierror", "herror", "OSError",
    "EOFError",
})
# Names that mean "the far side answered and refused", or "we are not allowed to do this": a fresh
# session changes nothing about those. TransientTransportError belongs here too - it is what this
# module raises once the attempts are already spent, so re-entering the loop would just spin.
_PERMANENT_TYPE_NAMES = frozenset({"HostKeyMismatchError", "PermissionError", "ValueError",
                                   "TimeoutError", "RuntimeError", "TransientTransportError"})


def is_transient_transport_failure(exc: BaseException) -> bool:
    """Would opening another TCP session plausibly fix this?

    Type names are checked on the whole MRO because paramiko's classes inherit from OSError, and an
    exact type check would miss `NoValidConnectionsError` (a subclass of socket.error) while a bare
    `except OSError` would also swallow a permission failure raised inside the safety layer.
    """
    names = {klass.__name__ for klass in type(exc).__mro__}
    if names & _PERMANENT_TYPE_NAMES:
        return False
    return bool(names & _TRANSIENT_TYPE_NAMES)


def backoff_delay(attempt: int) -> float:
    """Seconds to wait before re-attempt number `attempt` (0-based): 1, 2, 4, capped, plus jitter."""
    return min(RECONNECT_CAP_SECONDS, RECONNECT_BASE_SECONDS * (2 ** attempt)) + \
        random.uniform(0, RECONNECT_BASE_SECONDS)


def transport_flaps(*runners) -> dict:
    """What the SSH layer had to recover to produce one pass, or {} when it did not have to.

    Read with getattr rather than assumed: a mock transport, or any runner that never dropped a
    session, reports nothing, so a quiet pass keeps looking quiet.
    """
    live = [r for r in runners if r is not None]
    reconnects = sum(getattr(r, "reconnects", 0) for r in live)
    reissued = sum(getattr(r, "reissued", 0) for r in live)
    return {"reconnects": reconnects, "reissued": reissued} if (reconnects or reissued) else {}


def open_session(connector, sleep=None, attempt=0, attempts=RECONNECT_ATTEMPTS):
    """Establish one live session, retrying a transient failure with growing waits.

    The first try is immediate and only the retries wait: a sweep opens a dozen sessions, and paying a
    backoff before a connect that has not failed yet buys nothing. `attempt` offsets the waits so a
    caller that is already re-opening mid-run continues the sequence instead of starting it again.
    `attempts` counts tries, not waits - so a caller asking for 3 gets 3 connects and 2 sleeps.

    Only transient failures loop, plus a timeout: reaching this function means no command was ever
    sent, so a timeout here describes the path. An auth rejection or a changed host key is a fact about
    the far side, and hammering it faster is both useless and, in the host-key case, the behaviour of a
    client that has stopped verifying.
    """
    waiter = sleep if sleep is not None else time.sleep
    tries = max(1, int(attempts))
    last = None
    for i in range(tries):
        if i:
            waiter(backoff_delay(attempt + i - 1))
        try:
            return connector()
        except Exception as exc:
            # A timeout *while establishing* a session is a fact about the path, so it is retried -
            # this is how the banner failure arrives. A timeout inside run() is not, and is not
            # retried there: the command is already running on a socket that is still open.
            if not is_transient_transport_failure(exc) and not isinstance(exc, TimeoutError):
                raise
            last = exc
    raise TransientTransportError(
        f"SSH session could not be established after {tries} attempt(s): "
        f"{type(last).__name__}: {str(last)[:160] or 'no message'}")

class MockChannel:
    def __init__(self, exit_status=0):
        self._status = exit_status

    def recv_exit_status(self):
        return self._status

class MockChannelFile:
    def __init__(self, data: str, exit_status=0):
        self._data = data.encode("utf-8")
        self._stream = io.BytesIO(self._data)
        self.channel = MockChannel(exit_status)

    def read(self, n=-1):
        return self._stream.read(n)

    def decode(self, *args, **kwargs):
        return self._data.decode(*args, **kwargs)

def file_write_command(path: str) -> str:
    """The one command shape both transports use to put a plan file on a host.

    A function rather than an inline f-string so the safety allowlist can be asserted against the exact
    text that gets issued: `safety.check_command_safe` has blocked a heredoc shape before, and a writer
    whose command nobody checked is a writer that fails on the first live deploy.
    """
    parent = path.rsplit("/", 1)[0] or "/"
    return (f"umask 077; mkdir -p {shlex.quote(parent)}; cat > {shlex.quote(path)}; "
            f"chmod 600 {shlex.quote(path)}")


class MockSSHClient:
    """Mock SSH Client that models specific host identity (iran vs foreign)."""

    def __init__(self, simulated_state=None, host_role="unknown"):
        self.host_role = host_role
        self.hostname = "127.0.0.1"
        self.port = 22
        self.username = "root"
        if simulated_state is not None:
            self.state = simulated_state
        else:
            self.state = {
                "role": host_role,
                "listeners": {22: "sshd"},
                "services": {},
                "files": {},
                "sysctl": {"net.netfilter.nf_conntrack_max": "131072"},
                "interfaces": ["lo", "eth0"],
                "packet_loss": 0.0,
                "latency": 55.0
            }
        self.connected = True
        # Present on both transports so any reporter can ask the same question of a mocked run and a
        # live one; a session that never drops simply never increments them.
        self.reconnects = 0
        self.reissued = 0

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, hostname, port=22, username="root", password=None, key_filename=None, **kwargs):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.connected = True

    def close(self):
        self.connected = False

    def exec_command(self, cmd: str, timeout=30):
        if not self.connected:
            raise ConnectionError(f"MockSSHClient [{self.host_role}] is not connected")

        # 1. Enforce safety checks
        if not check_command_safe(cmd):
            err_msg = f"SECURITY VIOLATION: Forbidden command blocked by safety policy: {cmd}\n"
            return None, MockChannelFile("", exit_status=1), MockChannelFile(err_msg, exit_status=1)

        out = ""
        err = ""
        exit_code = 0

        # 2. Handle configuration file generation (cat > /etc/... <<EOF ... EOF)
        m1 = re.search(r"cat\s+>\s+([^\s<]+)\s+<<\s*['\"]?([A-Za-z0-9_]+)['\"]?\n(.*?)\n\2", cmd, re.DOTALL)
        m2 = re.search(r"cat\s+<<\s*['\"]?([A-Za-z0-9_]+)['\"]?\s+>\s*([^\s<]+)\n(.*?)\n\1", cmd, re.DOTALL)
        if m1:
            filepath = m1.group(1).strip()
            content = m1.group(3)
            self.state["files"][filepath] = content
        elif m2:
            filepath = m2.group(2).strip()
            content = m2.group(3)
            self.state["files"][filepath] = content

        # 3. Handle systemctl service status / reload / start / restart / stop
        if "systemctl daemon-reload" in cmd:
            out += "Daemon reloaded.\n"
        if "systemctl enable" in cmd or "systemctl start" in cmd or "systemctl restart" in cmd:
            svc_m = re.search(r'systemctl (?:enable --now|enable|start|restart) ([a-zA-Z0-9_.-]+)', cmd)
            if svc_m:
                svc = svc_m.group(1)
                unit_f1 = f"/etc/systemd/system/{svc}.service"
                unit_f2 = f"/etc/systemd/system/{svc}"
                if unit_f1 in self.state["files"] or unit_f2 in self.state["files"]:
                    # `state["units_die_after_start"]` models the shape the verification window exists
                    # for: the unit file was found, `enable --now` returned success, and the process
                    # exited afterwards. Without the flag this mock marks every started unit active, so
                    # no offline test could ever reach a branch that asks whether a dead unit blocks a
                    # keep - and a branch nothing can fail is not a branch.
                    if not self.state.get("units_die_after_start"):
                        self.state["services"][svc] = "active"
                    out += f"Started {svc}\n"
                else:
                    exit_code = 1
                    err += f"Failed to enable unit: Unit {svc}.service not found on [{self.host_role}].\n"
        if "systemctl show -p ActiveEnterTimestamp" in cmd:
            out += "ActiveEnterTimestamp=Tue 2026-10-06 16:35:00 UTC\n"
        if "systemctl is-active" in cmd:
            svc_m = re.search(r'systemctl is-active ([a-zA-Z0-9_.-]+)', cmd)
            svc = svc_m.group(1) if svc_m else ""
            if self.state.get("services", {}).get(svc) == "active":
                out += "active\n"
            else:
                out += "inactive\n"
                exit_code = 3
        if "systemctl stop" in cmd:
            svc_m = re.search(r'systemctl stop ([a-zA-Z0-9_.-]+)', cmd)
            if svc_m:
                svc = svc_m.group(1)
                self.state["services"][svc] = "inactive"
                out += f"Stopped {svc}\n"

        # 4. Handle date -u
        if "date -u" in cmd:
            out += time.strftime("%Y-%m-%d %H:%M:%S\n", time.gmtime())

        # 5. Handle test -f
        if cmd.startswith("test -f ") or " test -f " in cmd:
            fpath_m = re.search(r'test -f ([^\s;&|]+)', cmd)
            if fpath_m:
                fpath = fpath_m.group(1)
                if fpath not in self.state.get("files", {}):
                    exit_code = 1

        # 6. Handle reading OS / system info
        if "uname -a" in cmd:
            out += "Linux debian13 6.1.0-28-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22) x86_64 GNU/Linux\n"
        if "cat /etc/os-release" in cmd:
            out += 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nNAME="Debian GNU/Linux"\nVERSION_ID="13"\nVERSION="13 (trixie)"\nID=debian\n'

        # 6b. Handle host resource telemetry reads (round 063, ruling 1).
        # Each source is overridable on its own through `state["resources"]`, and a source named in
        # `state["resources"]["absent"]` answers the way a missing procfs file does: non-zero exit and
        # "No such file or directory" on stderr. Both halves matter to the sampler - its whole contract is
        # a *per-source* verdict, so a test that blanks every reading at once proves nothing about the one
        # shape it was written for (a kernel without MemAvailable, a df that lost one of its two mounts).
        res = self.state.get("resources") or {}
        absent = res.get("absent") or []

        if "/proc/loadavg" in cmd:
            if "load" in absent:
                exit_code = 1
                err += "cat: /proc/loadavg: No such file or directory\n"
            else:
                out += res.get("load", "0.42 0.31 0.20 2/123 4567\n")
        if cmd.strip() == "nproc":
            if "cpu_count" in absent:
                exit_code = 1
                err += "nproc: command not found\n"
            else:
                out += res.get("cpu_count", "4\n")
        if "/proc/meminfo" in cmd:
            if "memory" in absent:
                exit_code = 1
                err += "cat: /proc/meminfo: No such file or directory\n"
            else:
                out += res.get("memory", "MemTotal:        3883264 kB\nMemFree:          210432 kB\n"
                                         "MemAvailable:    1043264 kB\nSwapTotal:             0 kB\n"
                                         "SwapFree:              0 kB\n")
        if cmd.startswith("df -P"):
            if "disk" in absent:
                exit_code = 1
                err += "df: cannot access: No such file or directory\n"
            else:
                out += res.get("disk", "Filesystem     1024-blocks    Used Available Capacity Mounted on\n"
                                       "/dev/sda1         41052824 7410280  31522076      20% /\n"
                                       "/dev/sdb1          9845632 1234560   8100000      14% /var\n")
                if res.get("disk_partial"):
                    # The real shape of one of two arguments failing: the other row still prints, and the
                    # exit status is non-zero.
                    exit_code = 1
                    err += "df: /var: can't access existence\n"
        if "/proc/uptime" in cmd:
            if "uptime" in absent:
                exit_code = 1
                err += "cat: /proc/uptime: No such file or directory\n"
            else:
                out += res.get("uptime", "123456.78 456789.01\n")
        if "random/boot_id" in cmd:
            if "boot_id" in absent:
                exit_code = 1
                err += "cat: /proc/sys/kernel/random/boot_id: No such file or directory\n"
            else:
                out += res.get("boot_id", "3f2a1b4c-5d6e-7f80-91a2-b3c4d5e6f708\n")

        # 6c. The connection counters (#70, closing open finding #64).
        #
        # The blocks below are labelled with the kernel's own names in a plausible order and carry counters
        # this product does not ask for, because that is the shape the parser has to survive: it zips the
        # header line onto the value line positionally, so a mock that only printed the four names we read
        # would pass even if the pairing were broken. `Tcp:` appears only in /proc/net/snmp and `TcpExt:`
        # only in /proc/net/netstat, which is what makes the exact-label match testable - ask the `Tcp:`
        # parser for netstat text and it must find no block rather than borrow the listen queue's numbers.
        if "/proc/net/snmp" in cmd:
            if "tcp" in absent:
                exit_code = 1
                err += "cat: /proc/net/snmp: No such file or directory\n"
            else:
                out += res.get("tcp", "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors "
                                      "ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests "
                                      "OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails "
                                      "FragOKs FragFails FragCreates\n"
                                      "Ip: 1 64 9123450 0 12 0 0 0 9123401 8990123 0 44 0 0 0 0 0 0 0\n"
                                      "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens "
                                      "AttemptFails EstabReseds CurrEstab InSegs OutSegs RetransSegs "
                                      "OutRsts InCsumErrors\n"
                                      "Tcp: 1 200 120000 -1 187432 93021 4102 3155 47 8123456 7990123 "
                                      "4211 887 0\n")
        if "/proc/net/netstat" in cmd:
            if "tcp_ext" in absent:
                exit_code = 1
                err += "cat: /proc/net/netstat: No such file or directory\n"
            else:
                out += res.get("tcp_ext", "TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed "
                                          "EmbRSTs OMTPacketsUsed UseVCs TCPTimeouts TCPHybridACKPredup "
                                          "TCPSlowStartRetrans TCPSynRetrans ListenOverflows ListenDrops "
                                          "TCPMemoryPressures TCPAbortOnData TCPAbortOnTimeout "
                                          "TCPBacklogCoalesce TCPSACKReneged TCPDSACKRecv TCPDSACKOfoRecv "
                                          "PAWPassiveEstReset PAWActiveEstReset TCPAbortFailed\n"
                                          "TcpExt: 0 0 12 44 0 0 4643 0 318 612 0 0 0 27 19 9021 34 11 "
                                          "0 0 0 3\n")
        if "/proc/net/tcp" in cmd:
            if "sockets" in absent:
                exit_code = 1
                err += "cat: /proc/net/tcp: No such file or directory\n"
            else:
                # Hex-encoded addresses, one LISTEN, four ESTABLISHED, two TIME_WAIT and the SYN_RECV
                # backlog report062 saw by hand. The engine counts the third column and discards these
                # rows, so the only thing that outlives this read is a histogram.
                out += res.get("sockets", "  sl  local_address rem_address   st tx_queue rx_queue "
                                          "tr tm->when retrnsmt   uid  timeout inode\n"
                                          "   0: 00000000:1F90 00000000:0000 0A 0:00000000 00:00000000 "
                                          "00000000     0        0 40211 1 0\n"
                                          "   1: 0100007F:1F90 0100007F:D4A2 01 0:00000000 00:00000000 "
                                          "00:00000000  40100     0        0 48122 1 0\n"
                                          "   2: 0100007F:1F90 0100007F:D4A3 01 0:00000000 00:00000000 "
                                          "00:00000000  40100     0        0 48123 1 0\n"
                                          "   3: 0100007F:1F90 0100007F:D4A4 01 0:00000000 00:00000000 "
                                          "00:00000000  40100     0        0 48124 1 0\n"
                                          "   4: 00000000:1F91 00000000:0000 0A 0:00000000 00:00000000 "
                                          "00000000     0        0 40212 1 0\n"
                                          "   5: 0100007F:D4A2 0100007F:1F90 06 0:00000000 00:0000000E "
                                          "01:000002D1 00000000     0        0 0 1 0\n"
                                          "   6: 0100007F:D4A3 0100007F:1F90 06 0:00000000 00:0000000E "
                                          "01:000002D1 00000000     0        0 0 1 0\n")
                if res.get("sockets_syn_recv"):
                    for i in range(int(res["sockets_syn_recv"])):
                        out += (f"  {7 + i:3d}: 00000000:1F90 01007F01:C000 03 0:00000000 00:00000000 "
                                f"00:00000000 00000000     0        0 0 1 0\n")
                if res.get("sockets_partial"):
                    # One of the two files the command asks for is gone: the header and the first table
                    # still print, the second path errors, and the exit is non-zero - the `df -P / /var`
                    # shape, which is why `sockets` is parsed as a multi-source read.
                    exit_code = 1
                    err += "cat: /proc/net/tcp6: No such file or directory\n"

        # 6c. Handle fuser -k: killing a port's listener frees the port. The mock
        # renders every listener with pid 1234, so a bare `kill -15 <pid>` cannot
        # be attributed to one port and is left unmodeled; fuser names the port,
        # and it is the step the port-release path relies on for listeners no
        # systemd unit owns. Without this the mock would report a killed
        # listener as still listening, which no real host does.
        if "fuser -k" in cmd:
            fuser_m = re.search(r"fuser -k (?:-15 )?(\d+)/tcp", cmd)
            if fuser_m:
                self.state.get("listeners", {}).pop(int(fuser_m.group(1)), None)

        # 7. Handle ss -tlnp / socket inspection
        if "ss -tlnp" in cmd or "ss -tln" in cmd:
            # A piped grep for one port is a filter, not decoration: on a real
            # host `ss ... | grep -E ':443 '` prints nothing at all when
            # nothing listens on 443 - no header, no other ports. The old
            # unfiltered rendering (header plus every listener) made
            # check_port_status report "listening" for a port that was free
            # merely because something else (sshd on 22) listened somewhere,
            # which only stayed invisible while the deploy ignored the
            # release result. Plain ss without a grep keeps the old shape.
            grep_m = re.search(r"grep -E ':(\d+) '", cmd)
            if grep_m:
                want = int(grep_m.group(1))
                for p, proc in self.state.get("listeners", {}).items():
                    if p == want:
                        out += f"LISTEN 0 65536 0.0.0.0:{p} 0.0.0.0:* users:((\"{proc}\",pid=1234,fd=3))\n"
            else:
                out += "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
                for p, proc in self.state.get("listeners", {}).items():
                    out += f"LISTEN 0 65536 0.0.0.0:{p} 0.0.0.0:* users:((\"{proc}\",pid=1234,fd=3))\n"

        # 7b. Handle `ss -H -tln` - the two reads engine.backend_listener_state makes of this host's kernel
        # socket table. Answered separately from the branch above because the shapes differ on purpose:
        # `-H` means NO header line, so a mock that printed one would hide the bug the state-column filter
        # in that function exists to stop, and a `sport` filter means only the matching port prints, which
        # is what makes the two reads independent rather than two spellings of one answer.
        if "ss -H -tln" in cmd:
            want = None
            m_sport = re.search(r"sport\s*=\s*:(\d+)", cmd)
            if m_sport:
                want = m_sport.group(1)
            for p in sorted(self.state.get("listeners", {}), key=str):
                if want is not None and str(p) != want:
                    continue
                # No `users:(...)` column: `-p` was not asked for, and a mock that added one would make the
                # field count this instrument relies on differ between the two transports it is read over.
                out += f"LISTEN 0 65536 0.0.0.0:{p} 0.0.0.0:*\n"

        # 8. Handle iptables-save / nft
        if "iptables-save" in cmd:
            out += "# Generated by iptables-save v1.8.9\n*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
        elif "iptables -S" in cmd:
            out += "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
        if "iptables -t nat -S PREROUTING" in cmd:
            # The chain a carrier's frontend lives in. `state["prerouting"]` is a list of rule lines the
            # way `state["listeners"]` and `state["services"]` are, so a test can put a *different*
            # carrier's DNAT in force and drive the whole deploy path against it - which is the only way
            # the shadowing refusal is ever exercised offline, since the verification loop short-circuits
            # for mocks. Unarmed, this stays the empty chain the simulator has always returned, so a mock
            # cannot invent a conflict that would make an unrelated test refuse.
            rules = self.state.get("prerouting") or []
            out += "".join(f"{r}\n" for r in rules)

        # 9. Handle ping probes
        if "ping -c" in cmd:
            loss = self.state.get("packet_loss", 0.0)
            lat = self.state.get("latency", 46.2 if "grep" in cmd else 55.0)
            jit = self.state.get("jitter", 2.1 if "grep" in cmd else 4.0)
            # Read the count out of the command the caller actually issued. It used to be a three-way
            # match on "-c 10"/"-c 30"/else 2, so a probe that asked for 50 samples was answered with a
            # two-packet transcript - and any threshold expressed as a percentage of the sample size was
            # then tested against a model that could not represent it.
            m_cnt = re.search(r"ping -c (\d+)", cmd)
            cnt = int(m_cnt.group(1)) if m_cnt else 1
            recv = int(cnt * (1.0 - (loss / 100.0)))
            # Per-reply lines exist in real ping output and the TTL analyser
            # reads them; a state that carries ttl_samples models a host whose
            # replies arrive with those TTLs (two families = injection).
            ttl_samples = self.state.get("ttl_samples")
            if ttl_samples:
                target = cmd.split()[-1]
                for i, ttl in enumerate(list(ttl_samples)[:cnt]):
                    out += f"64 bytes from {target}: icmp_seq={i + 1} ttl={ttl} time={lat:.1f} ms\n"
            out += (
                f"--- {self.hostname} ping statistics ---\n"
                f"{cnt} packets transmitted, {recv} received, {int(loss)}% packet loss, time 2002ms\n"
                f"rtt min/avg/max/mdev = {lat-jit:.3f}/{lat:.3f}/{lat+jit:.3f}/{jit:.3f} ms\n"
            )

        # 10. Handle which command
        if cmd.startswith("which ") or " which " in cmd:
            bin_name = cmd.split()[-1]
            out += f"/usr/local/bin/{bin_name}\n"

        # 11. Handle starting test HTTP backend
        if "best_test_backend.py" in cmd:
            m_port = re.search(r"\(('0.0.0.0'|\"0.0.0.0\"),\s*(\d+)\)", cmd)
            if m_port:
                p_val = int(m_port.group(2))
                self.state["listeners"][p_val] = "http_backend"

        # 12. Handle iperf3 server start and fuser / process termination
        if "iperf3 -s -p" in cmd:
            m_ip = re.search(r"iperf3 -s -p\s*(\d+)", cmd)
            if m_ip:
                p_val = int(m_ip.group(1))
                self.state["listeners"][p_val] = "iperf3"

        if "fuser -k" in cmd:
            m_fus = re.search(r"fuser -k\s*(\d+)/tcp", cmd)
            if m_fus:
                p_val = int(m_fus.group(1))
                self.state["listeners"].pop(p_val, None)

        # Handle tunnel unit lifecycle for port listeners
        if ("systemctl enable" in cmd or "systemctl start" in cmd or "systemctl restart" in cmd) and self.host_role == "iran":
            if "best-tunnel-" in cmd:
                # Tunnel client active on Iran frontend port 8898 (or 443)
                self.state["listeners"][8898] = "tunnel_client"

        if "systemctl stop" in cmd and self.host_role == "iran":
            if "best-tunnel-" in cmd:
                self.state["listeners"].pop(8898, None)

        # 13. Handle live probe script (best_probe.py)
        if "best_probe.py lat" in cmd:
            if self.state.get("lat_no_sample"):
                # Zero completed samples is a failed measurement, not a 999 ms latency.
                out += "AVG:NOSAMPLE MDEV:NOSAMPLE OK:0/10\n"
            else:
                lat = self.state.get("latency", 52.4)
                jit = self.state.get("jitter", 3.8)
                out += f"AVG:{lat:.2f} MDEV:{jit:.2f} OK:10/10\n"

        if "best_probe.py loss" in cmd:
            loss = self.state.get("packet_loss", 0.0)
            ok = int(30 * (1.0 - (loss / 100.0)))
            out += f"LOSS:{loss:.1f} OK:{ok}\n"

        if "best_probe.py stability" in cmd:
            m_st = re.search(r'best_probe\.py stability\s+\S+\s+\S+\s+(\d+)\s+([0-9.]+)', cmd)
            total = int(m_st.group(1)) if m_st else 30
            interval = float(m_st.group(2)) if m_st else 1.0
            window = round(total * interval, 1)
            # A tunnel that stalls on the bulk ladder is simulated as dropping out early.
            # Stability is deliberately NOT derived from packet_loss: scoring.py already
            # penalises loss quadratically, so folding it in here would double-count it.
            survived = 3.2 if self.state.get("fail_ladder_at_step") else self.state.get("stability_survived", window)
            ok_count = int(total * (survived / window)) if window > 0 else 0
            out += f"STAB_OK:{ok_count} STAB_TOTAL:{total} STAB_SURVIVED:{survived:.1f}\n"

        if "best_probe.py ladder" in cmd or "curl" in cmd:
            fail_step = self.state.get("fail_ladder_at_step", None)
            step_match = re.search(r'/test_([0-9]+[km])', cmd)
            step_name = step_match.group(1) if step_match else ""
            if fail_step and fail_step in step_name:
                out += "LADDER_ERR:Connection reset by peer\n"
            else:
                out += "LADDER_STEP_OK in 0.082s\n"

        # 14. Handle iperf3 client (-c target_ip -p port)
        if "iperf3 -c " in cmd:
            m_cl = re.search(r"iperf3 -c\s+([^\s]+)\s+-p\s*(\d+)", cmd)
            if m_cl:
                t_host = m_cl.group(1)
                t_port = int(m_cl.group(2))
                # For tunnel mode (127.0.0.1), verify tunnel port is actually forwarded on Iran
                if t_host in ("127.0.0.1", "localhost") and t_port not in self.state.get("listeners", {}):
                    exit_code = 1
                    err += f"iperf3: error - unable to connect to server: Connection refused on port {t_port}\n"
                    out = ""
                else:
                    exit_code = 0
                    is_rev = "-R" in cmd
                    # Output realistic structured iperf3 JSON
                    rate_bps = 82500000.0 if is_rev else 78400000.0
                    res_json = {
                        "start": {"test_start": {"protocol": "TCP", "num_streams": 4}},
                        "end": {
                            "sum_sent": {"bits_per_second": rate_bps, "retransmits": 1},
                            "sum_received": {"bits_per_second": rate_bps}
                        }
                    }
                    out += json.dumps(res_json) + "\n"

        # 14b. The deploy's own data probe (engine.deploy_tunnel, verification stage 7).
        # The probe is a loopback connect *through the tunnel*, and what comes back is decided by an
        # application on the peer host that this runner cannot see - so a mock that answered from its own
        # listener table would certify a delivery it has no evidence for. The test declares the far end's
        # answer with `state["probe_data"]`. Unarmed it stays the silent shape pair 2 measured on hardware:
        # the transport accepts at the frontend, and nothing replies.
        if "PROBE_DATA_EXCHANGED" in cmd:
            out += ("PROBE_DATA_EXCHANGED\n" if self.state.get("probe_data") else "NO_DATA\n")

        if "READY" in cmd:
            out += "READY\n"

        return None, MockChannelFile(out, exit_status=exit_code), MockChannelFile(err, exit_status=exit_code)

    def write_file(self, path: str, content: str, timeout: int = 30) -> None:
        """Stage a plan file, mirroring SafeSSHRunner.write_file so both transports answer the same call.

        The content lands in `state["files"]` exactly as the shell-heredoc shape used to, because every
        assertion in this suite reads that dict; what changed is that it no longer travels as an
        argument. `state["fail_cmd"]` is honoured against the path as well as against a command, so a
        failure that happens while a config is being written - the most likely place for a deploy to
        die on a live host - is still injectable.
        """
        if not self.connected:
            raise ConnectionError(f"MockSSHClient [{self.host_role}] is not connected")
        if not check_command_safe(file_write_command(path)):
            raise PermissionError(f"SECURITY VIOLATION: Command blocked by safety policy: {path[:100]}")
        fail_on = self.state.get("fail_cmd")
        if fail_on and fail_on in path:
            raise RuntimeError(f"Mock file write failed on [{self.host_role}]: {path}\n"
                               f"Stderr: {self.state.get('fail_stderr', 'injected failure')[:200]}")
        self.state.setdefault("files", {})[path] = content

    def run(self, cmd: str, check=True, best_effort=False, timeout=30, retryable=False):
        # `retryable` is accepted so both transports present one signature - callers pass it
        # uniformly, and a mock session never drops, so there is nothing to re-issue. A mock that
        # silently ignored an unknown kwarg would let the live path be the only one ever tested.
        # Failure injection for one command, so an error path that only real hardware reaches can be
        # tested: state["fail_cmd"] is a substring to match, state["fail_stderr"] what the host printed.
        fail_on = self.state.get("fail_cmd")
        if fail_on and fail_on in cmd:
            err_str = self.state.get("fail_stderr", "injected failure")
            if check and not best_effort:
                raise RuntimeError(f"Mock command failed (exit 1) on [{self.host_role}]: {cmd[:100]}\n"
                                   f"Stderr: {err_str[:200]}")
            return 1, "", err_str
        _, stdout, stderr = self.exec_command(cmd, timeout=timeout)
        out_str = stdout.read().decode("utf-8", errors="replace")
        err_str = stderr.read().decode("utf-8", errors="replace")
        status = stdout.channel.recv_exit_status()
        if check and not best_effort and status != 0:
            raise RuntimeError(f"Mock command failed (exit {status}) on [{self.host_role}]: {cmd[:100]}\nStderr: {err_str[:200]}")
        return status, out_str, err_str

# Only these tokens ever arm live mode. Everything else - unset, empty, or unrecognised - stays
# dry-run, so a typo in the value cannot silently put root commands on a real server.
_LIVE_TOKENS = ("0", "false", "no", "off")

def is_dry_run_enabled() -> bool:
    """Single source of truth for BEST_TUNNEL_DRY_RUN across the whole package.

    Unset means dry-run. The orchestrator executes destructive commands (systemctl, iptables,
    fuser -k, unit teardowns) as root over SSH, so live operation has to be opted into
    explicitly rather than inherited from a missing environment variable.

    The value is matched as an allowlist of *live* tokens, not as a blocklist of dry-run ones.
    Reading "yes"/"true"/"1" as dry-run and anything unrecognised as dry-run too means the three
    ways this variable gets written wrong by hand (empty value, misspelled value, forgotten
    comment) all fail toward the safe mode instead of arming it.
    """
    return os.getenv("BEST_TUNNEL_DRY_RUN", "").strip().lower() not in _LIVE_TOKENS

class TOFUHostKeyPolicy:
    """Trust-On-First-Use (TOFU) host key policy with persistent pinning in SQLite."""
    def missing_host_key(self, client, hostname, key):
        import storage
        port = getattr(client, "_port", 22)
        pinned = storage.get_pinned_host_key(hostname, port)
        key_b64 = key.get_base64()
        key_type = key.get_name()

        if pinned is None:
            storage.pin_host_key(hostname, port, key_type, key_b64)
            storage.log_audit(None, "SSH_TOFU", "PINNED", f"Pinned host key for {hostname}:{port} ({key_type})")
            return
        elif pinned["key_base64"] == key_b64:
            return
        else:
            err = f"HOST KEY VERIFICATION FAILED for {hostname}:{port}! Potential MITM attack detected."
            storage.log_audit(None, "SSH_TOFU", "REJECTED", err)
            raise HostKeyMismatchError(err)

class SafeSSHRunner:
    """Production SSH Runner wrapping Paramiko with safety policy and structured run().

    A live session is a TCP connection to a host that is, in this project, behind a censor, so it
    does fail: the first live sweep died on `No existing session` and the failover monitor's live
    pass on `Error reading SSH protocol banner`, each after the session had already been open. This
    class owns the recovery, and splits it in two, because the two halves have different costs:

    * the **session** may always be re-opened (with backoff) - that touches nothing but this socket;
    * a **command** may be issued again only if re-running it is harmless, and after a drop we cannot
      know whether it already ran, so the text decides, not the caller's recollection.
    """

    def __init__(self, raw_client, hostname="", connector=None, sleep=None,
                 attempts=RECONNECT_ATTEMPTS):
        self._client = raw_client
        self.hostname = hostname
        self._connector = connector
        self._sleep = sleep if sleep is not None else time.sleep
        self._attempts = attempts
        # Counted, not logged: a sweep report that says "the link flapped three times and every
        # measurement still completed" is a different document from one that says "no errors".
        self.reconnects = 0
        self.reissued = 0
        self.last_reopen_error = None

    def exec_command(self, cmd: str, timeout=30):
        if not check_command_safe(cmd):
            raise PermissionError(f"SECURITY VIOLATION: Command blocked by safety policy: {cmd[:100]}")
        return self._client.exec_command(cmd, timeout=timeout)

    def _session_gone(self) -> bool:
        """Is this session demonstrably unable to carry traffic right now?

        Asked of the transport rather than inferred from a failure, because the failure paramiko gives
        back for a dead session is an AttributeError - indistinguishable from a bug in our own code.
        """
        probe = getattr(self._client, "get_transport", None)
        if probe is None:
            return False
        try:
            transport = probe()
        except Exception:
            return True
        return transport is None or not transport.is_active()

    def _exec_once(self, cmd: str, timeout):
        # Checked before anything is sent, and again if exec_command raises an AttributeError: a session
        # that is already down cannot have run the command, so the honest report is "never sent" and
        # the honest recovery is to re-open - not an unclassified crash.
        if self._session_gone():
            raise DeadSessionError(f"SSH session to {self.hostname} is not active, nothing was sent")
        try:
            stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        except AttributeError as exc:
            if not self._session_gone():
                raise
            raise DeadSessionError(f"SSH session to {self.hostname} died while {cmd[:60]} was being "
                                   f"sent: {exc}", may_have_been_sent=True) from exc
        out_bytes = stdout.read()
        err_bytes = stderr.read()
        status = stdout.channel.recv_exit_status()
        # The third shape, and the one paramiko does not report as a failure: when its reader thread
        # dies it force-closes every channel (`Transport.run` -> `chan._unlink()` -> `_set_closed()`),
        # which wakes the exit-status wait with the *initial* -1 and leaves the stream short. Witnessed
        # live on 2026-10-11: `touch /tmp/x && ping -c 2` returned `(exit -1, 106 bytes, '')` to the
        # caller with the file already written on the far side. -1 is not an exit code, it is the host
        # never saying how the command ended, and returning it lets a health checker read a short
        # `systemctl is-active` answer as a dead unit - the hazard report052's AMBIGUOUS_DOWN exists for.
        if status == -1 or self._session_gone():
            raise DeadSessionError(f"SSH session to {self.hostname} died while reading the answer "
                                   f"to {cmd[:60]}: exit status "
                                   f"{'never arrived' if status == -1 else status}, output may be "
                                   f"truncated", may_have_been_sent=True)
        return status, out_bytes.decode("utf-8", errors="replace"), err_bytes.decode("utf-8", errors="replace")

    def reopen(self) -> bool:
        """Replace a session that stopped carrying traffic. True when a new session is live.

        A host-key refusal during the retry is raised, not swallowed: three attempts to reconnect
        into a MITM is the behaviour this class must never have. Everything else that exhausts the
        backoff comes back as False, because the caller still has to report the command it could not
        finish - a re-open failure and a command failure are two different facts.
        """
        if self._connector is None:
            return False
        try:
            self._client.close()
        except Exception:
            pass
        try:
            client = open_session(self._connector, sleep=self._sleep, attempts=self._attempts)
        except HostKeyMismatchError:
            raise
        except Exception as exc:
            if not isinstance(exc, TransientTransportError) and not is_transient_transport_failure(exc):
                raise
            self.last_reopen_error = exc
            return False
        self._client = client
        self.last_reopen_error = None
        self.reconnects += 1
        return True

    def write_file(self, path: str, content: str, timeout: int = 30) -> None:
        """Put `content` at `path`, mode 0600, without the bytes ever entering a remote command line.

        This exists because `exec_command` runs its string through a remote shell, so a heredoc makes
        the entire file an argument of that shell: readable in `/proc/<pid>/cmdline` by any local user
        for the life of the command, and captured by anything that logs argv. The files staged here are
        a REALITY private key, a chisel TLS key, a wstunnel CA key and an ESP SA key - the argument is
        exactly what this product refuses to put in a systemd unit for the same reason (report041 B1).
        So the payload is written to the child's stdin, which no other process can read, and only the
        path appears in the command.

        `umask 077` covers a new file; the explicit `chmod 600` covers a redeploy onto a path that
        already exists, whose mode umask does not change. Never re-issued after a drop: a partial write
        is a broken tunnel, and re-writing over one on a re-opened session would report success for a
        file whose earlier half may have come from a different plan.
        """
        cmd = file_write_command(path)
        if not check_command_safe(cmd):
            raise PermissionError(f"SECURITY VIOLATION: Command blocked by safety policy: {cmd[:100]}")
        if self._session_gone():
            raise DeadSessionError(f"SSH session to {self.hostname} is not active, nothing was sent")
        try:
            stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
            stdin.write(content)
            stdin.flush()
            stdin.channel.shutdown_write()
            status = stdout.channel.recv_exit_status()
            err_str = stderr.read().decode("utf-8", errors="replace")
        except Exception as exc:
            if is_transient_transport_failure(exc) or isinstance(exc, AttributeError):
                raise TransientTransportError(
                    f"file write to {path} on {self.hostname} did not complete: {type(exc).__name__}: "
                    f"{str(exc)[:180] or 'no message'} - the session is not re-opened and the file is "
                    f"not re-written, because a half-written config cannot be told apart from a whole "
                    f"one", exc)
            raise
        if status != 0:
            raise RuntimeError(f"Remote file write failed (exit {status}) on {self.hostname}: "
                               f"{path}\nStderr: {err_str[:300]}")

    def run(self, cmd: str, check=True, best_effort=False, timeout=30, retryable=False):
        """Run one command, re-opening the session if it dropped.

        `retryable` states the caller's intent; `safety.is_read_only_command(cmd)` is the machine's
        own check of the text, and both must agree before a command is issued a second time. A
        mutating command handed retryable=True is therefore still never re-run - which direction this
        fails in matters, because re-running `systemctl enable --now` or a teardown mid-failover
        restarts or destroys a live tunnel.

        A transport failure is raised even under `best_effort`, and that is load-bearing: best_effort
        means "a non-zero exit is expected", not "the host was unreachable". Swallowing the drop would
        hand the health checker empty output for `systemctl is-active`, which reads as a dead unit, and
        the monitor would then switch protocols to heal an outage that was only its own SSH session.
        """
        if not check_command_safe(cmd):
            raise PermissionError(f"SECURITY VIOLATION: Command blocked by safety policy: {cmd[:100]}")
        may_reissue = bool(retryable) and safety.is_read_only_command(cmd)
        attempts = 1 + self._attempts if may_reissue else 1
        failure = None
        restored = False
        for attempt in range(attempts):
            try:
                status, out_str, err_str = self._exec_once(cmd, timeout)
            except TimeoutError as exc:
                # Paramiko's channel timeout arrives as a TimeoutError with an empty message, and that
                # message is what the benchmark records: "Execution error: " alone tells the operator
                # nothing about which command to fix, so name it and the budget it ran out of. A
                # timeout is not a dropped session - the socket is still up, so no re-open is attempted.
                raise TimeoutError(f"remote command timed out after {timeout}s: {cmd[:120]}") from exc
            except Exception as exc:
                if not is_transient_transport_failure(exc):
                    raise
                failure = (exc, attempt)
                restored = self.reopen()
                if attempt + 1 >= attempts or not restored:
                    break
                self.reissued += 1
                continue
            if check and not best_effort and status != 0:
                raise RuntimeError(f"Remote command failed (exit {status}) on {self.hostname}: "
                                   f"{cmd[:100]}\nStderr: {err_str[:300]}")
            return status, out_str, err_str
        exc, attempt = failure
        # What the recovery did has to be in the message, or "failed after 1 attempt(s)" reads like a
        # surrender when in fact three sessions were opened and none of them carried traffic.
        never_sent = isinstance(exc, DeadSessionError) and not getattr(exc, "may_have_been_sent", False)
        why = (f"SSH transport to {self.hostname} failed after {attempt + 1} attempt(s) on "
               f"{type(exc).__name__}: {str(exc)[:180] or 'no message'} - "
               + ("command not completed, outcome of any already-sent side effect is unknown: "
                  if not never_sent else "the session was already down, so this was never sent: "))
        if not restored:
            why += f"; the session was not re-opened: " \
                   f"{str(self.last_reopen_error or 'this transport has no connector')[:160]}"
        elif not may_reissue:
            why += "; the session came back, but the command is not classified read-only, so it was " \
                   f"not issued a second time"
        raise TransientTransportError(why, exc)

    def close(self):
        self._client.close()

def get_ssh_runner(spec, dry_run=None, simulated_state=None, host_role="unknown"):
    """Factory returning either Mock client with host identity or Paramiko client with SafeSSHRunner."""
    if dry_run is None:
        dry_run = is_dry_run_enabled()

    if dry_run:
        c = MockSSHClient(simulated_state, host_role=host_role)
        c.connect(spec.get("host", "127.0.0.1"), port=spec.get("port", 22), username=spec.get("user", "root"))
        return c
    else:
        import paramiko
        import storage
        if storage.db_is_inside_repo():
            # Opening a live session makes this the first writer of the host addresses: TOFU pins the
            # hostname verbatim, so a live run that left the database in the working tree would leave
            # the servers' routable addresses in the repository for any search, index or report to pick
            # up. Refuse before connecting rather than clean up afterwards.
            raise RuntimeError(
                f"Refusing a live SSH session while the database is inside the repository "
                f"({storage.DB_PATH}). Set BEST_TUNNEL_DB_PATH to a path outside the working tree, "
                f"as the live harnesses do.")
        auth = spec.get("auth", {})

        def connector():
            raw = paramiko.SSHClient()
            raw._port = spec.get("port", 22)
            raw.set_missing_host_key_policy(TOFUHostKeyPolicy())
            if auth.get("type") == "key":
                raw.connect(spec["host"], port=spec.get("port", 22), username=spec.get("user", "root"),
                            key_filename=auth.get("value"), timeout=15, banner_timeout=20,
                            auth_timeout=20, allow_agent=False, look_for_keys=False)
            else:
                raw.connect(spec["host"], port=spec.get("port", 22), username=spec.get("user", "root"),
                            password=auth.get("value", ""), timeout=15, banner_timeout=20,
                            auth_timeout=20, allow_agent=False, look_for_keys=False)
            return raw

        # The first session gets the same backoff as a reconnect, because that is where a sweep dies
        # today: the base-RTT probe opens a session before the protocol loop, and one flapped banner
        # there used to end the whole run rather than one row of it.
        return SafeSSHRunner(open_session(connector), hostname=spec.get("host", "unknown"),
                             connector=connector)
