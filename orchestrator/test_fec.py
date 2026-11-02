"""UDP FEC relay (wireguard-fec): 2 data packets + 1 XOR parity packet.

The relay is a generated script, so these tests exec the template the
generator ships and drive it over real loopback UDP sockets, with a
lossy middle that drops one data packet on purpose: the payload must
still arrive, rebuilt from its sibling and the parity packet.
"""
import shlex

import struct


import unittest

import protocols
import wizard_setup

_NS = {"__name__": "fec_proxy_test"}
exec(protocols._FEC_PROXY_TEMPLATE, _NS)
Relay = _NS["Relay"]
xor_bytes = _NS["xor_bytes"]
encode_parity = _NS["encode_parity"]
decode_missing = _NS["decode_missing"]
HDR = _NS["HDR"]


def _canon(cmd):
    cmd = cmd.replace("2>/dev/null || true", "").replace(" || true", "").strip()
    toks = shlex.split(cmd)[1:]
    table, out, i = "filter", [], 0
    while i < len(toks):
        t = toks[i]
        if t == "-t":
            table = toks[i + 1]; i += 2; continue
        if t == "-m" and toks[i + 1] == "comment":
            i += 3; continue
        if t == "--comment":
            i += 2; continue
        if t in ("-A", "-I", "-D"):
            chain = toks[i + 1]; i += 2
            if t == "-I" and i < len(toks) and toks[i].isdigit():
                i += 1
            out += [table, "-", chain]
            continue
        out.append(t); i += 1
    return " ".join(out)


class TestFecCodec(unittest.TestCase):
    def test_parity_rebuilds_either_packet(self):
        p0, p1 = b"hello fec world", b"second packet, longer than the first"
        parity, len0, len1 = encode_parity(p0, p1)
        self.assertEqual(decode_missing(parity, p1, 1, len0), p0)
        self.assertEqual(decode_missing(parity, p0, 0, len1), p1)

    def test_parity_of_unequal_lengths_pads_with_zeros(self):
        p0, p1 = b"a", b"xyz"
        parity, _, _ = encode_parity(p0, p1)
        self.assertEqual(len(parity), 3)
        self.assertEqual(decode_missing(parity, p1, 1, 1), p0)

    def test_xor_is_its_own_inverse(self):
        data = bytes(range(256))
        self.assertEqual(xor_bytes(xor_bytes(data, b"key"), b"key")[:len(data)], data)


class FakeSock:
    """A stand-in for Relay.send_sock: records deliveries, or forwards
    packets to a function. The VM blocks real UDP sends, so the relay
    state machine is driven directly; the select loop that dispatches
    to on_local/on_peer is ten symmetric lines."""

    def __init__(self, deliver=None):
        self.sent = []
        self.deliver = deliver

    def sendto(self, data, addr):
        self.sent.append((data, addr))
        if self.deliver is not None:
            self.deliver(data)


class TestFecRelayLogic(unittest.TestCase):
    def _pair(self, drop_first_data):
        """Two relays wired through fakes: A encodes, an optional
        lossy middle drops group 0's first data packet, B decodes."""
        a = Relay(("127.0.0.1", 0), ("127.0.0.1", 0),
                  ("127.0.0.1", 0), ("127.0.0.1", 0))
        b = Relay(("127.0.0.1", 0), ("127.0.0.1", 0),
                  ("127.0.0.1", 0), ("127.0.0.1", 0))
        delivered = []
        b.send_sock = FakeSock(deliver=lambda data: delivered.append(data))
        dropped = {"done": False}

        def _middle(packet):
            if drop_first_data and not dropped["done"] and len(packet) >= HDR.size:
                gid, index, _, _ = HDR.unpack(packet[:HDR.size])
                if gid == 0 and index == 0:
                    dropped["done"] = True
                    return
            b.on_peer(packet)

        a.send_sock = FakeSock(deliver=_middle)
        return a, b, delivered

    def test_loss_of_first_data_packet_is_rebuilt(self):
        a, b, delivered = self._pair(drop_first_data=True)
        payloads = [b"p0-first", b"p1-second-longer-payload", b"p2", b"p3" * 100,
                    b"p4", b"p5-last"]
        for p in payloads:
            a.on_local(p)
        self.assertEqual(len(delivered), len(payloads),
                         f"lost payloads despite FEC: got {len(delivered)} of {len(payloads)}")
        self.assertEqual(set(delivered), set(payloads))
        # p0 only reaches the receiver rebuilt: the middle dropped it.
        self.assertIn(b"p0-first", delivered)

    def test_no_loss_passes_through_untouched_and_in_order(self):
        a, b, delivered = self._pair(drop_first_data=False)
        payloads = [b"one", b"two", b"three", b"four"]
        for p in payloads:
            a.on_local(p)
        self.assertEqual(delivered, payloads)

    def test_parity_arriving_first_still_rebuilds(self):
        a, b, delivered = self._pair(drop_first_data=False)
        p0, p1 = b"aaa", b"bbbbb"
        parity, len0, len1 = encode_parity(p0, p1)
        # Parity first, then the surviving sibling; the lost packet is
        # rebuilt the moment the sibling lands.
        b.on_peer(HDR.pack(9, 2, len0, len1) + parity)
        self.assertEqual(delivered, [])
        b.on_peer(HDR.pack(9, 0, len0, len1) + p0)
        self.assertEqual(delivered, [p0, p1])

    def test_duplicate_data_is_delivered_once(self):
        a, b, delivered = self._pair(drop_first_data=False)
        packet = HDR.pack(3, 0, 5, 0) + b"dup!"
        b.on_peer(packet)
        b.on_peer(packet)
        self.assertEqual(delivered, [b"dup!"])

    def test_stale_groups_are_dropped(self):
        a, b, delivered = self._pair(drop_first_data=False)
        b.on_peer(HDR.pack(4, 0, 2, 0) + b"hi")
        self.assertEqual(len(b.groups), 1)
        for state in b.groups.values():
            state["expiry"] = 0.0  # long past
        b.on_peer(HDR.pack(5, 0, 2, 0) + b"yo")
        self.assertEqual(list(b.groups), [5])


class TestWireguardFecGenerator(unittest.TestCase):
    IR, FR, PID, FRONT = "198.51.100.10", "203.0.113.20", 7, 8443

    def test_registered_but_not_a_first_tunnel_pick(self):
        self.assertIn("wireguard-fec", protocols.GENERATORS)
        self.assertIn("wireguard-fec", protocols.BASE_PROTOCOLS)
        self.assertIn("wireguard-fec", protocols.INNER_PROBED)
        self.assertEqual(len(protocols.BASE_PROTOCOLS), 16)
        # FEC costs a parity packet per two data packets: the sweep
        # scores it and the healer switches to it, but the wizard's
        # first tunnel is a plain carrier or overlay.
        self.assertNotIn("wireguard-fec", wizard_setup.FALLBACK_ORDER)

    def test_plan_shape_ports_and_endpoints(self):
        plan = protocols.generate_deployment("wireguard-fec", self.PID, self.IR, self.FR, self.FRONT)
        bench = protocols.generate_benchmark_plan("wireguard-fec", self.PID, self.IR, self.FR)
        for p, wg_port, fec_local, fec_peer, iface, inners in (
                (plan, 51827, 25007, 26007, "wgf7",
                 ("10.24.17.1", "10.24.17.2")),
                (bench, 8897, 27007, 28007, "wgf7b",
                 ("10.25.67.1", "10.25.67.2"))):
            self.assertEqual(protocols.carrier_iface("wireguard-fec", self.PID,
                                                     "prod" if p is plan else "bench"), iface)
            self.assertEqual(protocols.carrier_inner_pair("wireguard-fec", self.PID,
                                                          "prod" if p is plan else "bench"), inners)
            units = {}
            for side in ("iran", "foreign"):
                for path, text in p[f"{side}_files"].items():
                    if path.endswith(".service"):
                        units.setdefault(side, []).append(text)
                self.assertEqual(len(units[side]), 2, f"{side}: WG unit + proxy unit expected")
            wg_unit = [t for t in units["iran"] if "type wireguard" in t][0]
            proxy_unit = [t for t in units["iran"] if "Type=simple" in t][0]
            self.assertIn(f"endpoint 127.0.0.1:{fec_local}", wg_unit)
            self.assertIn(f"listen-port {wg_port}", wg_unit)
            self.assertIn(f"--local 127.0.0.1:{fec_local}", proxy_unit)
            self.assertIn(f"--peer-listen 0.0.0.0:{fec_peer}", proxy_unit)
            self.assertIn(f"--peer {self.FR}:{fec_peer}", proxy_unit)
            self.assertIn(f"--deliver 127.0.0.1:{wg_port}", proxy_unit)
            # The tunnel never receives from the public internet: only
            # the relay's public port is opened, for the peer relay.
            self.assertIn(f"-p udp --dport {fec_peer} -s {self.FR}/32",
                          "\n".join(p["iran_cmds"]))
            self.assertNotIn(f"--dport {wg_port} -s {self.FR}/32",
                             "\n".join(p["iran_cmds"]))
            # Every installed rule has its delete, on both hosts.
            for side in ("iran", "foreign"):
                installed = {}
                for cmd in p[f"{side}_cmds"]:
                    if cmd.startswith("iptables ") and (" -A " in cmd or " -I " in cmd):
                        installed.setdefault(_canon(cmd), []).append(cmd)
                deleted = {_canon(cmd) for cmd in p[f"teardown_{side}"]
                           if cmd.startswith("iptables ") and " -D " in cmd}
                orphans = [s[0] for s in installed.values() if _canon(s[0]) not in deleted]
                self.assertEqual(orphans, [], f"{side}: orphan rule - {orphans}")
            # The relay script ships on both sides, identical, and parses.
            proxy_path = [k for k in p["iran_files"] if k.endswith(".py")][0]
            self.assertEqual(p["iran_files"][proxy_path], p["foreign_files"][proxy_path])
            compile(p["iran_files"][proxy_path], proxy_path, "exec")
            # No private key reaches any unit.
            keyfile = [k for k in p["iran_files"] if k.endswith("-iran.key")][0]
            priv = p["iran_files"][keyfile].strip()
            for side_units in units.values():
                for text in side_units:
                    self.assertNotIn(priv, text)
            # The backend-target pattern finds the delivery port on the
            # prod plan (the deploy gate only ever sees prod plans;
            # bench interfaces carry the 'b' suffix, like GRE's).
            if p is plan:
                import re
                side, pattern, _, _ = protocols.BACKEND_TARGETS["wireguard-fec"]
                blob = "\n".join(p[f"{side}"].values())
                m = re.search(pattern, blob)
                self.assertIsNotNone(m, "backend-target pattern finds nothing")
                self.assertEqual(int(m.group("backend")), self.FRONT)


if __name__ == "__main__":
    unittest.main()
