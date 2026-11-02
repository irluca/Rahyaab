"""Parallel-TCP reverse carrier (tcp-lanes): 8 TLS-record-shaped
streams, token-authenticated lanes, per-connection stickiness.

The script is a generated file, so tests exec the template and drive
it over real loopback TCP (which this VM permits, unlike UDP): an
echo backend behind the client, a frontend in front of the server,
and data must come back through the lanes.
"""
import re
import socket
import threading
import time
import unittest

import protocols
import wizard_setup

_NS = {"__name__": "tcp_lanes_test"}
exec(protocols._TCP_LANES_TEMPLATE, _NS)
frame_bytes = _NS["frame_bytes"]
read_frame = _NS["read_frame"]
serve = _NS["serve"]
run_client = _NS["run_client"]
FTYPE_AUTH = _NS["FTYPE_AUTH"]
FTYPE_OPEN = _NS["FTYPE_OPEN"]
FTYPE_DATA = _NS["FTYPE_DATA"]


class TestLanesFraming(unittest.TestCase):
    def test_wire_shape_is_a_tls_application_data_record(self):
        raw = frame_bytes(7, FTYPE_DATA, b"hello")
        self.assertEqual(raw[:3], bytes([0x17, 0x03, 0x03]))
        length = int.from_bytes(raw[3:5], "big")
        self.assertEqual(length, len(raw) - 5)

    def test_frame_round_trips_over_a_socketpair(self):
        a, b = socket.socketpair()
        try:
            a.sendall(frame_bytes(42, FTYPE_DATA, b"payload-123"))
            self.assertEqual(read_frame(b), (42, FTYPE_DATA, b"payload-123"))
        finally:
            a.close()
            b.close()


class TestLanesLive(unittest.TestCase):
    def _echo_server(self, stop):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(16)
        srv.settimeout(0.5)
        addr = srv.getsockname()

        def _pump(conn):
            try:
                while True:
                    data = conn.recv(16384)
                    if not data:
                        break
                    conn.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

        def _loop():
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                threading.Thread(target=_pump, args=(conn,), daemon=True).start()

        threading.Thread(target=_loop, daemon=True).start()
        return addr

    def _wait_ready(self, ready, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if "lanes" in ready and "frontend" in ready:
                return ready
            time.sleep(0.05)
        raise AssertionError(f"server did not bind in time: {ready}")

    def _roundtrip(self, frontend_addr, payload, timeout=5.0):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            try:
                sock = socket.create_connection(frontend_addr, timeout=2)
                sock.sendall(payload)
                got = sock.recv(len(payload) + 64)
                sock.close()
                if got == payload:
                    return got
                last = got
            except OSError as exc:
                last = exc
            time.sleep(0.2)
        raise AssertionError(f"no echo through the lanes for {payload!r}: last={last!r}")

    def test_end_to_end_through_two_lanes(self):
        stop = threading.Event()
        echo_addr = self._echo_server(stop)
        ready = {}
        server_thread = threading.Thread(
            target=serve, args=(("127.0.0.1", 0), ("127.0.0.1", 0), b"test-token"),
            kwargs={"ready": ready, "stop": stop}, daemon=True)
        server_thread.start()
        try:
            self._wait_ready(ready)
            client_thread = threading.Thread(
                target=run_client,
                args=(ready["lanes"], echo_addr, b"test-token"),
                kwargs={"streams": 2, "stop": stop}, daemon=True)
            client_thread.start()
            self.assertEqual(self._roundtrip(ready["frontend"], b"hello-lanes"), b"hello-lanes")
            self.assertEqual(self._roundtrip(ready["frontend"], b"second-connection"),
                             b"second-connection")
        finally:
            stop.set()
            server_thread.join(timeout=5)
            client_thread.join(timeout=5)

    def test_wrong_token_lane_is_closed_before_traffic(self):
        stop = threading.Event()
        ready = {}
        server_thread = threading.Thread(
            target=serve, args=(("127.0.0.1", 0), ("127.0.0.1", 0), b"real-token"),
            kwargs={"ready": ready, "stop": stop}, daemon=True)
        server_thread.start()
        try:
            self._wait_ready(ready)
            sock = socket.create_connection(ready["lanes"], timeout=2)
            sock.sendall(frame_bytes(0, FTYPE_AUTH, b"wrong-token"))
            sock.settimeout(2.0)
            self.assertEqual(sock.recv(100), b"")
            sock.close()
        finally:
            stop.set()
            server_thread.join(timeout=5)


class TestTcpLanesGenerator(unittest.TestCase):
    IR, FR, PID, FRONT = "198.51.100.10", "203.0.113.20", 7, 8443

    def test_registered_and_last_in_the_fallback_chain(self):
        self.assertIn("tcp-lanes", protocols.GENERATORS)
        self.assertIn("tcp-lanes", protocols.BASE_PROTOCOLS)
        self.assertEqual(len(protocols.BASE_PROTOCOLS), 16)
        self.assertEqual(wizard_setup.FALLBACK_ORDER[-1], "tcp-lanes")

    def test_plan_shape_ports_and_token_handling(self):
        plan = protocols.generate_deployment("tcp-lanes", self.PID, self.IR, self.FR, self.FRONT)
        bench = protocols.generate_benchmark_plan("tcp-lanes", self.PID, self.IR, self.FR)
        for p, transport, frontend in ((plan, 29007, self.FRONT), (bench, 8897, 8898)):
            ir_unit = [t for t in p["iran_files"].values() if "tcp-lanes-server" in t or "TCP Lanes Server" in t][0]
            fr_unit = [t for t in p["foreign_files"].values() if "TCP Lanes Client" in t][0]
            self.assertIn(f"--listen 0.0.0.0:{transport}", ir_unit)
            self.assertIn(f"--frontend 0.0.0.0:{frontend}", ir_unit)
            self.assertIn(f"--remote {self.IR}:{transport}", fr_unit)
            self.assertIn(f"--backend 127.0.0.1:{frontend}", fr_unit)
            self.assertIn("--streams 8", fr_unit)
            # The token lives in files only: never in any unit argv.
            token = [v.strip() for k, v in p["iran_files"].items() if "token" in k][0]
            for text in list(p["iran_files"].values()) + list(p["foreign_files"].values()):
                if text.startswith("[Unit]"):
                    self.assertNotIn(token, text)
            # The script ships identical on both sides and parses.
            script = [v for k, v in p["iran_files"].items() if k.endswith(".py")][0]
            self.assertEqual(script, [v for k, v in p["foreign_files"].items() if k.endswith(".py")][0])
            compile(script, "tcp-lanes", "exec")
            # Backend-target pattern finds the delivery port.
            side, pattern, _, _ = protocols.BACKEND_TARGETS["tcp-lanes"]
            blob = "\n".join(p[f"{side}"].values())
            m = re.search(pattern, blob)
            self.assertIsNotNone(m, "backend-target pattern finds nothing")
            self.assertEqual(int(m.group("backend")), frontend)
            # Teardown removes units, token, env and script.
            self.assertIn("tcp-lanes", "\n".join(p["teardown_iran"]))
            self.assertIn("tcp-lanes", "\n".join(p["teardown_foreign"]))


if __name__ == "__main__":
    unittest.main()
