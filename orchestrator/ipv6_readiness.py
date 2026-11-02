"""IPv6 readiness probe for Rahyaab pairs: is the reverse direction
usable, and is the forward direction?

Measured live on 2026-11-02, and the reason this module exists: the
Iran->foreign IPv6 direction was fully blocked on the test master
(both ICMPv6 and TCP), while foreign->Iran IPv6 passed cleanly. A
plain "has IPv6" check would have certified pairs whose tunnels could
never come up, so the probe tests each direction separately, with a
real TCP connect, and reports each direction as ok / blocked /
unknown instead of collapsing them into one boolean.

Verdict rules (mirroring the spoof probe's open/closed/unknown):
  reverse_ready - Iran has a global IPv6 address AND a TCP connect
    from the foreign host to Iran's IPv6 :22 succeeds. This is the
    only direction a reverse-mode tunnel needs: the foreign side
    initiates, and return traffic on an established connection passes
    even though new outbound connections from Iran do not.
  outbound_ok   - the foreign host has a global IPv6 address AND a
    TCP connect from Iran to it succeeds. Informational for now: no
    shipped protocol dials IPv6 from the Iran side.
  unknown       - a direction whose test could not run (no address on
    one side, the target does not listen on IPv6 :22, SSH failed).
    Unknown is never reported as blocked: the probe simply does not
    know, and the dashboard says so.

The runners here follow the engine's run() contract (run(cmd, check,
best_effort, timeout, retryable) -> (rc, out, err)); the detached
runner script reuses the spoof probe's SSHRunner. Nothing in this
module writes to either host: every command is a read, and the TCP
connect targets the SSH port that already listens.
"""

import ipaddress
import subprocess
import time

DOC_PLACEHOLDER = "2001:db8::1"


def parse_global_v6(text: str) -> list[str]:
    """Global-unicast IPv6 addresses found in `ip -6 addr` output.

    The range check is 2000::/3 by hand rather than ipaddress'
    is_global, so documentation addresses (2001:db8::/32) also parse:
    tests and fixtures need them, and the TCP direction test below is
    the real gate anyway — an address nobody can connect to never
    reports ready. Link-local, ULA, loopback and multicast are
    excluded: none of them is reachable from the peer host.
    """
    found = []
    for token in (text or "").replace("/", " ").split():
        try:
            addr = ipaddress.IPv6Address(token)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_link_local or addr.is_multicast:
            continue
        # 2000::/3 is the global-unicast range. It admits documentation
        # addresses (2001:db8::/32) — which tests need — and excludes
        # ULA (fc00::/7) on its own, so no flag juggling is needed.
        if not (0x2000 <= (int(addr) >> 112) <= 0x3FFF):
            continue
        text_addr = str(addr)
        if text_addr not in found:
            found.append(text_addr)
    return found


def detect_v6(runner) -> list[str]:
    """Global IPv6 addresses on the host behind `runner`, or []."""
    try:
        _rc, out, _err = runner.run("ip -6 addr show scope global",
                                     best_effort=True, timeout=20)
    except Exception:
        return []
    return parse_global_v6(out)


def local_global_v6() -> str | None:
    """First global IPv6 address of THIS host, or None.

    For code running on the Iran host itself (the healer): no SSH
    round-trip, no dependency on the peer being reachable.
    """
    try:
        out = subprocess.run(["ip", "-6", "addr", "show", "scope", "global"],
                             capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return None
    addrs = parse_global_v6(out)
    return addrs[0] if addrs else None


def _listens_on_v6(runner, port: int = 22) -> bool | None:
    """Does the host behind `runner` listen on IPv6 :port?

    True when `ss -tln` shows a [::]:port bind (dual-stack binds
    print exactly that); False when ss answers but shows no such
    bind; None when ss is missing or unreadable, which makes the
    direction unknown rather than blocked.
    """
    try:
        rc, out, _err = runner.run("ss -tln", best_effort=True, timeout=20)
    except Exception:
        return None
    if rc != 0:
        return None
    return ("[::]:%d" % port) in out


def tcp_probe(from_runner, to_runner, host_v6: str, port: int = 22) -> tuple[str, str]:
    """One direction: can `from_runner`'s host TCP-connect to host_v6:port?

    The address is validated before it is embedded in the command, so
    the command text carries only hex digits and colons. The target's
    listen state is checked first: a host that does not listen on IPv6
    :22 is "unknown" (nothing to connect to), not "blocked".
    """
    try:
        ipaddress.IPv6Address(host_v6)
    except ValueError:
        return "unknown", "not an IPv6 address"
    listens = _listens_on_v6(to_runner, port)
    if listens is False:
        return "unknown", "target does not listen on IPv6 :%d" % port
    if listens is None:
        return "unknown", "could not read target listen state"
    probe = ("python3 -c \"import socket; s=socket.socket(socket.AF_INET6, "
             "socket.SOCK_STREAM); s.settimeout(5); s.connect(('%s', %d)); "
             "print('TCP-OK'); s.close()\"" % (host_v6, port))
    try:
        _rc, out, _err = from_runner.run(probe, best_effort=True, timeout=20)
    except Exception as exc:
        return "unknown", "probe command failed: %s" % type(exc).__name__
    if "TCP-OK" in out:
        return "ok", ""
    return "blocked", "TCP connect timed out or was refused"


def probe_pair(ir_runner, fr_runner) -> dict:
    """Full per-pair verdict. Pure reads; writes nothing anywhere."""
    iran_addrs = detect_v6(ir_runner)
    foreign_addrs = detect_v6(fr_runner)
    iran_to_foreign = {"status": "unknown", "detail": "no foreign IPv6 address"}
    foreign_to_iran = {"status": "unknown", "detail": "no Iran IPv6 address"}
    if foreign_addrs:
        status, detail = tcp_probe(ir_runner, fr_runner, foreign_addrs[0])
        iran_to_foreign = {"status": status, "detail": detail}
    if iran_addrs:
        status, detail = tcp_probe(fr_runner, ir_runner, iran_addrs[0])
        foreign_to_iran = {"status": status, "detail": detail}
    reverse_ready = bool(iran_addrs) and foreign_to_iran["status"] == "ok"
    outbound_ok = bool(foreign_addrs) and iran_to_foreign["status"] == "ok"
    return {
        "iran_v6": iran_addrs,
        "foreign_v6": foreign_addrs,
        "iran_to_foreign": iran_to_foreign,
        "foreign_to_iran": foreign_to_iran,
        "reverse_ready": reverse_ready,
        "outbound_ok": outbound_ok,
        "checked_at": time.time(),
    }
