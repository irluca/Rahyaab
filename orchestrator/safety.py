#!/usr/bin/env python3
"""Safety guard and port policy module for Tunnel Studio Pro v2.0.
Strictly enforces:
1. Hard Blacklist for SSH ports & internal system listeners.
2. Protected Ports Enclave for 443/80/8443 & active listeners (requires confirmation + safe release).
3. Prohibition of known destructive commands via regex blocklist.
4. Sanitization and quoting of process names and PIDs (prevents command injection).
5. Scoped firewall tagging with unique rule comments.

Item 3 is a blocklist, not an allowlist: it stops the destructive commands we have thought of
and cannot stop ones we have not. Obfuscation (indirection through variables, $(...) nesting,
hex/octal escapes, or uploading a script and running it) bypasses it entirely. Treat it as a
guard against operator error, not as a defence against a hostile caller - the caller already
holds root SSH credentials, so nothing here can be a security boundary against them.

`is_read_only_command()` is the one place that does use an allowlist, and it answers a different
question: not "is this dangerous" but "is re-running this after a dropped SSH session harmless".
For that question an allowlist is the only safe shape, because the cost of a wrong answer is
asymmetric: refusing a retry costs one slower measurement, granting one can restart or tear down
a live tunnel.
"""
import re
import shlex

# Precise regex patterns targeting destructive commands without false positives
DESTRUCTIVE_PATTERNS = [
    # 1. Root or critical system directory recursive deletion (e.g. rm -rf /, rm -fr /, rm -r -f /etc, /root, /boot, /home)
    re.compile(r'\brm\s+.*?(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|-r\s+-f|-f\s+-r)\s+(?:/\s*$|/\*|/etc(?:/|\s|$)|/var(?:/|\s|$)|/usr(?:/|\s|$)|/bin(?:/|\s|$)|/sbin(?:/|\s|$)|/boot(?:/|\s|$)|/home(?:/|\s|$)|/root/?\s*$|/root/\*)'),

    # 2. Blanket firewall flushes (catches iptables -F, iptables --flush, iptables -t nat -F, iptables -t mangle --flush, ip6tables, etc.)
    re.compile(r'\b(?:iptables|ip6tables)\b.*?(?:\s|^)(?:-[a-zA-Z]*F|--flush)(?:\s|$)'),

    # 3. nftables blanket flush (nft flush ruleset, nft flush table, etc.)
    re.compile(r'\bnft\b.*?\bflush\b'),

    # 4. Blanket process kill commands that could destroy all system services
    re.compile(r'\bpkill\s+-f\b'),
    re.compile(r'\bkillall\b'),

    # 5. Disk wipe / formatting
    re.compile(r'\b(?:mkfs(?:\.[a-z0-9]+)?|dd\s+if=.*?\s+of=/dev/)'),

    # 6. Destructive find with -delete on root
    re.compile(r'\bfind\s+/\s+.*?-delete\b'),

    # 7. Truncation or overwrite of core system files
    re.compile(r'\btruncate\s+.*?-s\s*0\s+/(?:etc|root|boot)'),
    re.compile(r'>\s*/(?:etc/passwd|etc/shadow|etc/sudoers)'),

    # 8. Subshell-nested destructive execution
    re.compile(r'\b(?:bash|sh)\s+-c\s+[\'\"].*?(?:rm\s+-[a-zA-Z]*[rf]{2}\s+/|mkfs|iptables\s+-[a-zA-Z]*F)'),

    # 9. Host power-state changes. This orchestrator drives hosts over SSH, so any of these
    #    severs its own control channel and can leave a tunnel half-configured.
    re.compile(r'\b(?:reboot|shutdown|poweroff|halt)\b'),
    re.compile(r'\binit\s+[06]\b'),
    re.compile(r'\bsystemctl\s+(?:stop|disable|mask|kill)\s+(?:ssh|sshd)(?:\.service)?\b'),

    # 10. Piping a remote or decoded payload straight into a shell: unverifiable code execution
    #     that also defeats the SHA-256 pinning enforced by binary_manager.
    re.compile(r'\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b'),
    re.compile(r'\bbase64\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b'),

    # 11. Fork bomb
    re.compile(r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:'),

    # 12. Netcat-style reverse shell handing /bin/sh to a socket
    re.compile(r'\b(?:nc|ncat|netcat)\b[^|]*\s-e\s+/(?:usr/)?bin/(?:ba)?sh\b'),

    # 13. Raw write to a block device (the dd-specific rule in group 5 does not cover redirection)
    re.compile(r'>\s*/dev/(?:sd|hd|vd|xvd|nvme|mmcblk|disk)'),

    # 14. Unconditional recursive deletion that ignores the root-filesystem guard
    re.compile(r'--no-preserve-root\b'),

    # 15. Destroying scheduled jobs or hardening attributes the operator depends on
    re.compile(r'\bcrontab\s+-[a-zA-Z]*r'),
    re.compile(r'\bchattr\b'),

    # 16. A default DROP policy locks out the SSH session that is driving this tool
    re.compile(r'\bip6?tables\s+-P\s+\S+\s+DROP\b'),

    # 17. Account removal or lockout
    re.compile(r'\buserdel\b'),
    re.compile(r'\busermod\s+(?:-[a-zA-Z]*L|--lock)\b'),
    re.compile(r'\bpasswd\s+-l\b'),

    # 18. Overwriting or deleting SSH daemon configuration and host keys
    re.compile(r'>\s*/etc/ssh/'),
    re.compile(r'\brm\s+[^|\n]*?/etc/ssh/')
]

# Standard test ports used during isolated benchmarks
TEST_PORTS = [445, 446, 447, 8898, 8899]

# System internal ports that are strictly non-routable as frontends
SYSTEM_RESERVED_PORTS = {22, 53, 68, 123}

def is_hard_blacklisted(port: int, ssh_port: int = 22) -> bool:
    """SSH port and core system ports can never be used as tunnel frontends."""
    return port == ssh_port or port in SYSTEM_RESERVED_PORTS

def validate_frontend_port(port: int, ir_ssh_port: int = 22, fr_ssh_port: int = 22) -> None:
    """Enforces strict safety gating on target frontend port across all endpoints:
    1. Range check: 1 <= port <= 65535
    2. Hard blacklist: cannot be SSH port on Iran, SSH port on Foreign, or system reserved ports.
    Raises ValueError or PermissionError on violation.
    """
    try:
        p = int(port)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid port: {port}. Must be an integer between 1 and 65535.")

    if p < 1 or p > 65535:
        raise ValueError(f"Port {p} is out of valid range (1-65535).")

    if is_hard_blacklisted(p, ir_ssh_port) or is_hard_blacklisted(p, fr_ssh_port):
        raise PermissionError(
            f"CRITICAL SAFETY VIOLATION: Port {p} is hard-blacklisted (SSH / system management port). "
            "Tunnel frontend binding is strictly forbidden to prevent server lockout."
        )

def is_protected_port(port: int, ss_out: str = "") -> bool:
    """Port 443, 80, 8443 or any port currently in use is a protected port."""
    try:
        p = int(port)
    except Exception:
        return False
    if p in {80, 443, 8443}:
        return True
    if ss_out and (f":{p} " in ss_out or f":{p}\t" in ss_out):
        return True
    return False

def check_command_safe(cmd: str) -> bool:
    """Returns False if command matches any destructive regex pattern."""
    for pattern in DESTRUCTIVE_PATTERNS:
        if pattern.search(cmd):
            return False
    return True


# A dropped SSH session makes the caller face one question: may this command be issued again? Re-running
# a measurement costs a second of latency; re-running `systemctl enable --now` restarts a tunnel the
# operator did not ask to restart, and re-running a teardown can delete the successor that was just
# started. So the retry decision is made here, from the text of the command, and never from a caller's
# claim about it - a caller that is wrong about its own side effects is exactly the failure this gate
# exists to catch. Unknown means not read-only: forgetting to annotate a new probe loses a retry, which
# is a slower measurement, not a corrupted deployment.
_READ_ONLY_PLAIN = frozenset("""
cat cut date df du free grep egrep fgrep hostname head id jq journalctl ls nproc pidof ping ping6 ps
readlink realpath sort stat tail tr type uname uptime wc which whereis ss
""".split())

# `systemctl stop` shares a verb with `systemctl is-active`, so the subcommand decides.
_SYSTEMCTL_READ_ONLY = frozenset({
    "is-active", "is-enabled", "is-failed", "is-system-running", "status", "show", "cat",
    "list-units", "list-sockets", "list-timers", "list-dependencies", "get-default",
})

# `ip link` shows an interface, `ip link set` rewrites one.
_IP_READ_ONLY_HEADS = frozenset({"a", "addr", "address", "r", "route", "l", "link", "n", "neigh",
                                 "rule", "s", "sr", "mroute", "maddr", "ntable", "fou", "xfrm"})
_IP_MUTATING_ACTIONS = frozenset({"add", "del", "delete", "change", "replace", "set", "flush",
                                  "modify", "new"})

# Listing is inert; `-A/-I/-D/-F/-P/-N/-X` rewrite the ruleset a tunnel depends on.
_IPTABLES_READ_ONLY_FLAGS = frozenset({"-S", "-L", "-n", "-v", "-x", "-t", "-s", "-w",
                                       "--line-numbers", "--numeric"})
_IPTABLES_FORBIDDEN_FLAGS = frozenset({"-A", "-I", "-D", "-F", "-P", "-R", "-N", "-X", "-E", "-Z",
                                       "--append", "--insert", "--delete", "--flush", "--policy",
                                       "--new-chain", "--delete-chain"})

# Anything with these tokens is not a read-only command, whatever its verbs look like: a redirect,
# a heredoc, a substitution, or a pipe into a program that writes.
_WRITE_TOKENS = re.compile(r"(?:>>?|<<|[<>]|\$\(|`|\btee\b|\bxargs\b|\bsed\s+(?:-[^\s]*i|--in-place))")

_SEG_SEPARATORS = frozenset({";", "&&", "||", "|", "&"})
# A shell control character that is not its own token means two commands were written without a space
# (`… ping -c 1 198.51.100.10; rm …`), and shlex hands that to us as one argument. A plain verb ignores its trailing
# arguments, so the second command would ride along inside a segment that already passed. Rather than
# re-implement a shell parser, such a command is simply not classified as read-only.
_CONTROL_CHARS = ";|&<>$\n\r\t`"


def _read_only_segment(tokens: list[str]) -> bool:
    """True when one `;`/`|`-delimited segment is a call to an inert program."""
    if not tokens:
        return True
    head, args = tokens[0], tokens[1:]
    if head == "systemctl":
        return bool(args) and args[0] in _SYSTEMCTL_READ_ONLY
    if head == "ip":
        if not args or args[0] not in _IP_READ_ONLY_HEADS:
            return False
        return not any(a in _IP_MUTATING_ACTIONS for a in args[1:])
    if head in ("iptables", "ip6tables"):
        flags = [a for a in args if a.startswith("-")]
        if not flags:
            return False
        if any(f in _IPTABLES_FORBIDDEN_FLAGS for f in flags):
            return False
        return all(f in _IPTABLES_READ_ONLY_FLAGS for f in flags)
    if head in ("python", "python3"):
        # Only the measurement agent: it opens sockets and prints, it does not configure.
        return bool(args) and args[0].endswith("best_probe.py")
    if "/" in head:
        # An absolute path is still the same program: `/usr/sbin/ss -tlnp` is as inert as `ss`.
        head = head.rsplit("/", 1)[-1]
        if not head:
            return False
    return head in _READ_ONLY_PLAIN


def _read_only_line(line: str) -> bool:
    """Every `;`/`|`-separated segment of one shell line must be inert."""
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        return False
    segments, current = [], []
    for tok in tokens:
        if tok in _SEG_SEPARATORS:
            segments.append(current)
            current = []
        elif any(c in tok for c in _CONTROL_CHARS):
            return False
        else:
            current.append(tok)
    segments.append(current)
    return all(_read_only_segment(seg) for seg in segments)


def is_read_only_command(cmd: str) -> bool:
    """Conservative answer to "is re-running this command harmless?".

    Every segment of every line must lead with an allowlisted inert program - subcommand checked for
    `systemctl`/`ip`/`iptables`/`python` - and the string must carry no redirect, heredoc,
    substitution or pipe into a writer. Lines are judged separately because a plain verb ignores its
    own trailing tokens, so a second command hidden behind a newline would otherwise ride along
    inside a segment that passed. A parse failure answers False: this gates retries, so being wrong
    one way costs a slower measurement and the other way a half-configured tunnel.
    """
    if not cmd or not cmd.strip() or _WRITE_TOKENS.search(cmd):
        return False
    return all(_read_only_line(line) for line in cmd.splitlines() if line.strip())

def sanitize_proc_name(proc: str) -> str:
    """Validates and quotes process name extracted from ss to prevent command injection."""
    clean = re.sub(r'[^a-zA-Z0-9_.-]', '', proc)
    if not clean:
        raise ValueError(f"Invalid process name: {proc}")
    return shlex.quote(clean)

def sanitize_pid(pid: int | str) -> int:
    """Validates PID integer range to prevent injection."""
    val = int(pid)
    if val <= 0 or val > 4194304:
        raise ValueError(f"Invalid pid: {pid}")
    return val

def parse_active_connections_count(ss_tinp_out: str, port: int) -> int:
    """Parses ss -tinp output to count live active non-LISTEN sockets on port."""
    lines = [l for l in ss_tinp_out.splitlines() if l.strip() and not l.startswith("State")]
    count = 0
    for line in lines:
        if f":{port} " in line or f":{port}\t" in line:
            if "ESTAB" in line or "SYN-SENT" in line or "SYN-RECV" in line:
                count += 1
    return count

def generate_firewall_comment(pair_id: str, proto: str) -> str:
    """Builds a scoped iptables comment so teardown can delete exactly this pair's rules.

    Inputs are stripped to [A-Za-z0-9_-] so the comment cannot break out of the -m comment
    quoting and so one pair's teardown can never match another pair's rules.
    """
    safe_pair = re.sub(r'[^a-zA-Z0-9_-]', '', str(pair_id))
    safe_proto = re.sub(r'[^a-zA-Z0-9_-]', '', str(proto))
    return f"best-tunnel-{safe_pair}-{safe_proto}"
