"""IPv6 reverse mode: tcp-lanes-v6 generator, readiness probe, hub
plumbing, and the failover guard.

The template is a generated file, so its address parsing and
dual-stack listener are tested by exec'ing it, like test_tcp_lanes
does. The probe logic runs against fake runners (no SSH, no hosts);
the store tests use a throwaway hub DB; the failover guard test uses
the same dry-run shape as the quarantine tests.
"""
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import protocols

_NS = {"__name__": "tcp_lanes_v6_test"}
exec(protocols._TCP_LANES_TEMPLATE, _NS)
serve = _NS["serve"]
run_client = _NS["run_client"]
make_listener = _NS["make_listener"]

import ipv6_readiness


class FakeRunner:
    """Runner duck-type: canned (rc, out, err) per command substring."""

    def __init__(self, canned=None):
        self.canned = canned or {}
        self.commands = []

    def run(self, cmd, check=True, best_effort=False, timeout=30, retryable=False):
        self.commands.append(cmd)
        for needle, answer in self.canned.items():
            if needle in cmd:
                return answer
        return (0, "", "")

    def close(self):
        pass


class TestTemplateAddresses(unittest.TestCase):
    def test_make_listener_dual_stack_accepts_v4_and_v6(self):
        if not socket.has_ipv6:
            self.skipTest("no IPv6 in this VM")
        srv = make_listener(("::", 0))
        port = srv.getsockname()[1]
        srv.settimeout(5.0)
        accepted = []

        def accept_one():
            try:
                conn, _ = srv.accept()
                accepted.append(conn)
            except OSError:
                pass

        t = threading.Thread(target=accept_one, daemon=True)
        t.start()
        v4 = socket.create_connection(("127.0.0.1", port), timeout=5)
        t.join(timeout=5)
        self.assertTrue(accepted, "dual-stack listener must accept IPv4-mapped clients")
        v4.close()
        accepted[0].close()
        srv.close()

    def test_make_listener_v4_shape_unchanged(self):
        srv = make_listener(("127.0.0.1", 0))
        self.assertEqual(srv.family, socket.AF_INET)
        srv.close()

    def test_v6_end_to_end_through_dual_stack_server(self):
        if not socket.has_ipv6:
            self.skipTest("no IPv6 in this VM")
        # Echo backend on loopback v4, lanes server dual-stack, client
        # dialing ::1: the v6 dial path must carry bytes like v4 does.
        backend = socket.socket()
        backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        backend.bind(("127.0.0.1", 0))
        backend.listen(1)
        backend_port = backend.getsockname()[1]

        def echo_loop():
            try:
                conn, _ = backend.accept()
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)
            except OSError:
                pass

        threading.Thread(target=echo_loop, daemon=True).start()
        ready = {}
        stop = threading.Event()
        srv_thread = threading.Thread(
            target=serve, args=(("::", 0), ("::", 0), b"tok-v6"),
            kwargs={"ready": ready, "stop": stop}, daemon=True)
        srv_thread.start()
        for _ in range(50):
            if "lanes" in ready and "frontend" in ready:
                break
            time.sleep(0.1)
        self.assertIn("lanes", ready)
        lanes_port = ready["lanes"][1]
        front_port = ready["frontend"][1]
        client_stop = threading.Event()

        def run_v6_client():
            run_client(("::1", lanes_port), ("127.0.0.1", backend_port),
                       b"tok-v6", streams=1, stop=client_stop)

        threading.Thread(target=run_v6_client, daemon=True).start()
        time.sleep(1.0)
        probe = socket.create_connection(("127.0.0.1", front_port), timeout=5)
        probe.sendall(b"ping-v6")
        self.assertEqual(probe.recv(4096), b"ping-v6")
        probe.close()
        client_stop.set()
        stop.set()


class TestV6Generator(unittest.TestCase):
    V6 = "2001:db8::1"

    def test_v6_units_bind_dual_stack_and_dial_bracketed(self):
        plan = protocols.generate_deployment(
            "tcp-lanes-v6", 7, "198.51.100.10", "203.0.113.20", 45984,
            iran_v6=self.V6)
        self.assertEqual(plan["protocol"], "tcp-lanes-v6")
        ir_unit = next(c for p, c in plan["iran_files"].items()
                       if p.endswith("tcp-lanes-server.service"))
        fr_unit = next(c for p, c in plan["foreign_files"].items()
                       if p.endswith("tcp-lanes-client.service"))
        self.assertIn("--listen [::]:", ir_unit)
        self.assertIn("--frontend [::]:45984", ir_unit)
        self.assertIn("--remote [%s]:" % self.V6, fr_unit)
        self.assertIn("--backend 127.0.0.1:45984", fr_unit)

    def test_v4_generator_unchanged_without_iran_v6(self):
        plan = protocols.generate_deployment(
            "tcp-lanes", 7, "198.51.100.10", "203.0.113.20", 45984)
        ir_unit = next(c for p, c in plan["iran_files"].items()
                       if p.endswith("tcp-lanes-server.service"))
        self.assertIn("--listen 0.0.0.0:", ir_unit)
        self.assertNotIn("[::]", ir_unit)

    def test_v6_without_address_refuses(self):
        with self.assertRaises(ValueError):
            protocols.generate_deployment(
                "tcp-lanes-v6", 7, "198.51.100.10", "203.0.113.20", 45984)
        with self.assertRaises(ValueError):
            protocols.generate_tcp_lanes_v6(
                7, "198.51.100.10", "203.0.113.20", 45984)

    def test_v6_with_garbage_address_refuses(self):
        with self.assertRaises(ValueError):
            protocols.generate_deployment(
                "tcp-lanes-v6", 7, "198.51.100.10", "203.0.113.20", 45984,
                iran_v6="not-an-address")

    def test_iran_v6_for_other_protocols_refuses(self):
        with self.assertRaises(ValueError):
            protocols.generate_deployment(
                "tcp-lanes", 7, "198.51.100.10", "203.0.113.20", 45984,
                iran_v6=self.V6)

    def test_bench_plan_uses_env_fallback(self):
        os.environ["BEST_TUNNEL_IPV6_REVERSE"] = self.V6
        try:
            plan = protocols.generate_benchmark_plan(
                "tcp-lanes-v6", 7, "198.51.100.10", "203.0.113.20")
            fr_unit = next(c for p, c in plan["foreign_files"].items()
                           if p.endswith("tcp-lanes-client.service"))
            self.assertIn("--remote [%s]:8897" % self.V6, fr_unit)
        finally:
            os.environ.pop("BEST_TUNNEL_IPV6_REVERSE", None)

    def test_bench_plan_without_address_refuses(self):
        os.environ.pop("BEST_TUNNEL_IPV6_REVERSE", None)
        with self.assertRaises(ValueError):
            protocols.generate_benchmark_plan(
                "tcp-lanes-v6", 7, "198.51.100.10", "203.0.113.20")


class TestSupportedGating(unittest.TestCase):
    def test_v6_appended_only_with_valid_env(self):
        os.environ.pop("BEST_TUNNEL_IPV6_REVERSE", None)
        self.assertNotIn("tcp-lanes-v6", protocols.get_supported_protocols())
        os.environ["BEST_TUNNEL_IPV6_REVERSE"] = "2001:db8::5"
        try:
            self.assertIn("tcp-lanes-v6", protocols.get_supported_protocols())
        finally:
            os.environ.pop("BEST_TUNNEL_IPV6_REVERSE", None)
        os.environ["BEST_TUNNEL_IPV6_REVERSE"] = "garbage"
        try:
            self.assertNotIn("tcp-lanes-v6", protocols.get_supported_protocols())
        finally:
            os.environ.pop("BEST_TUNNEL_IPV6_REVERSE", None)

    def test_default_count_unchanged(self):
        os.environ.pop("BEST_TUNNEL_IPV6_REVERSE", None)
        os.environ.pop("BEST_TUNNEL_SKIP_SPOOF", None)
        self.assertEqual(len(protocols.get_supported_protocols()), 18)


class TestReadiness(unittest.TestCase):
    def test_parse_global_v6(self):
        out = ("    inet6 2a03:9381:b::62/64 scope global\n"
               "    inet6 fe80::1/64 scope link\n"
               "    inet6 fd00::5/64 scope global\n"
               "    inet6 2001:db8::1/64 scope global\n"
               "    inet6 ::1/128 scope host\n")
        self.assertEqual(ipv6_readiness.parse_global_v6(out),
                         ["2a03:9381:b::62", "2001:db8::1"])

    def test_probe_pair_reverse_ready(self):
        ir = FakeRunner({
            "ip -6 addr": (0, "inet6 2a03:9381:b::62/64 scope global\n", ""),
            "ss -tln": (0, "LISTEN 0 4096 [::]:22 [::]:*\n", ""),
        })
        fr = FakeRunner({
            "ip -6 addr": (0, "inet6 2a01:f900:10:101::1/64 scope global\n", ""),
            "ss -tln": (0, "LISTEN 0 4096 [::]:22 [::]:*\n", ""),
        })
        # TCP connects run on the dialing host: foreign->Iran must print
        # TCP-OK, Iran->foreign must not. The probe command itself
        # contains the text "TCP-OK" (its print), so the needle must be
        # "python3 -c", matched after the ip/ss needles, not "TCP-OK".
        fr.canned["python3 -c"] = (0, "TCP-OK\n", "")
        ir.canned["python3 -c"] = (0, "", "")
        payload = ipv6_readiness.probe_pair(ir, fr)
        self.assertTrue(payload["reverse_ready"])
        self.assertFalse(payload["outbound_ok"])
        self.assertEqual(payload["foreign_to_iran"]["status"], "ok")
        self.assertEqual(payload["iran_to_foreign"]["status"], "blocked")

    def test_probe_pair_unknown_when_not_listening(self):
        ir = FakeRunner({
            "ip -6 addr": (0, "inet6 2a03:9381:b::62/64 scope global\n", ""),
            "ss -tln": (0, "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n", ""),
        })
        fr = FakeRunner({
            "ip -6 addr": (0, "inet6 2a01:f900:10:101::1/64 scope global\n", ""),
            "ss -tln": (0, "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n", ""),
        })
        payload = ipv6_readiness.probe_pair(ir, fr)
        self.assertFalse(payload["reverse_ready"])
        self.assertEqual(payload["foreign_to_iran"]["status"], "unknown")

    def test_probe_pair_no_addresses(self):
        payload = ipv6_readiness.probe_pair(FakeRunner(), FakeRunner())
        self.assertFalse(payload["reverse_ready"])
        self.assertFalse(payload["outbound_ok"])
        self.assertEqual(payload["iran_v6"], [])
        self.assertEqual(payload["foreign_v6"], [])


class TestHubStore(unittest.TestCase):
    def setUp(self):
        import hub.store as hub_store
        self.tmp = tempfile.mkdtemp(prefix="ipv6_hub_")
        self.store = hub_store.Store(os.path.join(self.tmp, "hub.db"))
        iran = self.store.create_server({"name": "iran", "host": "198.51.100.10"})
        foreign = self.store.create_server({"name": "foreign", "host": "203.0.113.20"})
        pair = self.store.create_pair({
            "name": "p1", "iran_server_id": iran["id"],
            "foreign_server_id": foreign["id"],
            "healer_server_id": iran["id"], "frontend_port": 45984})
        self.pair_id = pair["id"]

    def test_save_get_and_attach(self):
        payload = {"iran_v6": ["2001:db8::1"], "foreign_v6": [],
                   "reverse_ready": True, "outbound_ok": False}
        self.assertIsNone(self.store.get_ipv6_status(self.pair_id))
        self.store.save_ipv6_status(self.pair_id, payload)
        self.assertEqual(self.store.get_ipv6_status(self.pair_id), payload)
        pairs = self.store.list_pairs()
        self.assertEqual(pairs[0]["ipv6_status"], payload)
        self.assertEqual(self.store.get_pair(self.pair_id)["ipv6_status"],
                         payload)


class TestSweepGate(unittest.TestCase):
    def setUp(self):
        import hub.store as hub_store
        self.tmp = tempfile.mkdtemp(prefix="ipv6_sweep_")
        self.store = hub_store.Store(os.path.join(self.tmp, "hub.db"))
        iran = self.store.create_server({"name": "iran", "host": "198.51.100.10"})
        foreign = self.store.create_server({"name": "foreign", "host": "203.0.113.20"})
        pair = self.store.create_pair({
            "name": "p1", "iran_server_id": iran["id"],
            "foreign_server_id": foreign["id"],
            "healer_server_id": iran["id"], "frontend_port": 45984})
        self.pair_id = pair["id"]

    def test_ipv6_reverse_address(self):
        import run_sweep
        self.assertIsNone(run_sweep.ipv6_reverse_address(self.store, self.pair_id))
        self.store.save_ipv6_status(self.pair_id, {
            "iran_v6": ["2001:db8::9"], "reverse_ready": False})
        self.assertIsNone(run_sweep.ipv6_reverse_address(self.store, self.pair_id))
        self.store.save_ipv6_status(self.pair_id, {
            "iran_v6": ["2001:db8::9"], "reverse_ready": True})
        self.assertEqual(run_sweep.ipv6_reverse_address(self.store, self.pair_id),
                         "2001:db8::9")


class TestFailoverGuard(unittest.TestCase):
    def setUp(self):
        import storage
        self.orig_db = storage.DB_PATH
        self.tmp = tempfile.mkdtemp(prefix="ipv6_failover_")
        storage.DB_PATH = os.path.join(self.tmp, "wizard.db")
        storage.init_db()
        self.pid = storage.add_pair(name="v6guard",
                                    iran_host="198.51.100.10",
                                    foreign_host="203.0.113.20",
                                    frontend_port=45984)
        self.addCleanup(storage.delete_pair, self.pid)
        self.addCleanup(setattr, storage, "DB_PATH", self.orig_db)

    def test_v6_target_without_detected_address_is_blocked(self):
        import failover
        pair = {"id": self.pid, "frontend": 45984,
                "iran": {"host": "198.51.100.10", "port": 22},
                "foreign": {"host": "203.0.113.20", "port": 22}}
        mgr = failover.FailoverManager(min_interval_seconds=0,
                                       max_failovers_per_window=99)
        res = mgr.execute_failover(pair, "tcp-lanes", "tcp-lanes-v6",
                                   reason="test", dry_run=True,
                                   ir_runner=FakeRunner(), fr_runner=FakeRunner())
        self.assertFalse(res["success"])
        self.assertTrue(res.get("blocked"))
        self.assertIn("IPv6", res.get("reason", ""))

    def test_resolve_iran_v6(self):
        import failover
        runner = FakeRunner({
            "ip -6 addr": (0, "inet6 2a03:9381:b::62/64 scope global\n", ""),
        })
        self.assertEqual(failover.resolve_iran_v6(runner), "2a03:9381:b::62")
        self.assertIsNone(failover.resolve_iran_v6(FakeRunner()))
        self.assertIsNone(failover.resolve_iran_v6(None))


if __name__ == "__main__":
    unittest.main()
