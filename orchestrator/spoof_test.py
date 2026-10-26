"""Spoof capability tester (Phase 3) - the paired sender/receiver probe.

Whether a datacenter lets a forged-source packet leave (no egress source
validation) decides if the spoof emergency mode can exist for a pair at
all, and it cannot be inferred from the host: the kernel happily sends,
the provider silently drops. Hashem's panel ships the same idea as a
standalone tester for exactly this reason; this is an independent
implementation of that measurement, designed to run inside the benchmark
pipeline as one more probe.

Method: the receiver host listens on a raw ICMP socket for echo requests
carrying a magic marker. The sender host crafts echo requests whose
source address is forged - set to the *receiver's own* address, so any
packet that arrives is unambiguously forged (the receiver never sends
itself ICMP echo requests with this marker). Arrival therefore proves
both halves of the pre-condition: the sender's provider passed a forged
source out, and the path delivered it. Sending is one-way and needs no
reply, which keeps the test usable on the one-way-filtered pairs this
project exists for.

Safety: the forger runs only between the two hosts of the pair being
tested, with the pair's own address as the forged source, for a few
seconds, at a trickle rate. It spoofs nobody else, at nobody else.
"""

from __future__ import annotations

import re
import socket
import struct

MARKER = b"BTS-SPOOF-PROBE-v1"
PACKETS = 20
SEND_INTERVAL_S = 0.05
LISTEN_WINDOW_S = 8
RECEIVER_PATH = "/usr/local/bin/best_spoof_receiver.py"
SENDER_PATH = "/usr/local/bin/best_spoof_sender.py"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def build_icmp_echo(src_ip: str, dst_ip: str, ident: int, seq: int,
                    marker: bytes = MARKER) -> bytes:
    """A complete IPv4 packet carrying one ICMP echo request with a forged
    source. Pure bytes-in/bytes-out, so the wire format is pinned offline -
    a wrong checksum here would make a capable path look incapable."""
    payload = marker + struct.pack("!HH", ident, seq)
    icmp = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
    icmp = struct.pack("!BBHHH", 8, 0, _checksum(icmp), ident, seq) + payload
    total_len = 20 + len(icmp)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0, 64, 1, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0, 64, 1,
                         _checksum(header), socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip))
    return header + icmp


RECEIVER_SOURCE = r'''
import socket, sys, time

marker = sys.argv[1].encode()
window = float(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock.settimeout(0.5)
seen = set()
deadline = time.time() + window
while time.time() < deadline:
    try:
        packet, _addr = sock.recvfrom(65535)
    except socket.timeout:
        continue
    except OSError:
        break
    ihl = (packet[0] & 0x0F) * 4
    body = packet[ihl:]
    if len(body) > 8 and body[0] == 8 and marker in body:
        ident, seq = __import__("struct").unpack("!HH", body[-4:])
        seen.add((ident, seq))
print("RECEIVED:{}".format(len(seen)))
'''

SENDER_SOURCE = r'''
import socket, sys, time

sys.path.insert(0, "/usr/local/bin")
# The packet builder ships inside this file at install time (see
# install_spoof_tools): one source of truth for the wire format.
exec(open("/usr/local/bin/best_spoof_common.py").read())

dst = sys.argv[1]
forged_src = sys.argv[2]
ident = int(sys.argv[3])
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sent = 0
for seq in range(PACKETS):
    sock.sendto(build_icmp_echo(forged_src, dst, ident, seq), (dst, 0))
    sent += 1
    time.sleep(SEND_INTERVAL)
print("SENT:{}".format(sent))
'''


def common_source() -> str:
    """The shared wire-format code both tools run on the hosts, generated from
    this module's own functions so the offline-pinned builder is byte-for-byte
    the code that runs live (no second implementation to drift)."""
    import inspect

    parts = ["import socket, struct\n",
             f"MARKER = {MARKER!r}\nPACKETS = {PACKETS}\nSEND_INTERVAL = {SEND_INTERVAL_S}\n"]
    for fn in (_checksum, build_icmp_echo):
        parts.append(inspect.getsource(fn) + "\n")
    return "".join(parts)


_RECEIVED = re.compile(r"RECEIVED:(\d+)")
_SENT = re.compile(r"SENT:(\d+)")


def parse_count(pattern: re.Pattern, text: str):
    match = pattern.search(text or "")
    return int(match.group(1)) if match else None


def verdict(sent, received) -> dict:
    """Judge one direction. Capable only on positive arrival evidence: a
    sender that failed to run (sent None) is 'unknown', never 'incapable' -
    the same honesty rule as preflight's unmeasured facts."""
    if sent is None or received is None:
        return {"capable": None, "loss_pct": None,
                "note": "the probe did not complete; capability is unknown, not disproven"}
    if received > 0:
        return {"capable": True, "loss_pct": round(100.0 * (sent - received) / sent, 1),
                "note": f"forged-source packets arrived ({received}/{sent}); this egress "
                        "passes spoofed sources"}
    return {"capable": False, "loss_pct": 100.0,
            "note": "no forged-source packet arrived; this egress drops spoofed "
                    "sources (or the path does) - spoof mode cannot be offered here"}


def run_direction(sender_runner, receiver_runner, sender_ip: str,
                  receiver_ip: str, ident: int = 0xB7) -> dict:
    """Run one direction of the test. The receiver starts first and listens
    for a fixed window; the sender fires its trickle at the receiver with
    the receiver's own address forged as the source."""
    install = (
        "cat > /usr/local/bin/best_spoof_common.py <<'EOF'\n" + common_source() + "EOF\n"
        f"cat > {RECEIVER_PATH} <<'EOF'\n{RECEIVER_SOURCE}EOF\n"
        f"cat > {SENDER_PATH} <<'EOF'\n{SENDER_SOURCE}EOF\n")
    receiver_runner.run(install, check=False, best_effort=True, timeout=30)
    sender_runner.run(install, check=False, best_effort=True, timeout=30)
    _rc, out, _ = receiver_runner.run(
        f"nohup python3 {RECEIVER_PATH} {MARKER.decode()} {LISTEN_WINDOW_S} "
        f"> /tmp/best_spoof_rx.txt 2>&1 & echo started",
        check=False, best_effort=True, timeout=20)
    sender_runner.run("sleep 1", check=False, best_effort=True, timeout=10)
    _rc, sent_out, _ = sender_runner.run(
        f"python3 {SENDER_PATH} {receiver_ip} {receiver_ip} {ident}",
        check=False, best_effort=True, timeout=30)
    _rc, rx_out, _ = receiver_runner.run(
        f"sleep {LISTEN_WINDOW_S}; cat /tmp/best_spoof_rx.txt",
        check=False, best_effort=True, timeout=LISTEN_WINDOW_S + 20)
    result = verdict(parse_count(_SENT, sent_out), parse_count(_RECEIVED, rx_out))
    result.update({"from": sender_ip, "to": receiver_ip})
    return result
