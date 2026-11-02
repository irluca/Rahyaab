"""Kernel carriers added from C-Tunnel's list (2026-11-02): fou-gre,
ipip and wireguard. They are first-class tunnels measured like GRE/ESP
(bench inners, DNAT, inner probe) but not underlay carriers for
overlays, and 6to4 is deliberately absent: SIT carries IPv6 only, and
Rahyaab's bench/probe/DNAT path is IPv4-only, so 6to4 would need IPv6
inners - a separate project, not a generator."""
import base64
import re
import shlex
import unittest

import protocols
import wizard_setup


IR, FR, PID, FRONT = "198.51.100.10", "203.0.113.20", 7, 8443
NEW = ("fou-gre", "ipip", "wireguard")


def _canon(cmd):
    """test_71's pairing normalisation, reused: -A/-I/-D collapse, the
    insert position and the comment module drop out, so an installed
    rule and its delete compare equal."""
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


class TestKernelCarrierRegistry(unittest.TestCase):
    def test_new_protocols_registered_and_supported(self):
        for proto in NEW:
            self.assertIn(proto, protocols.GENERATORS)
            self.assertIn(proto, protocols.BASE_PROTOCOLS)
            self.assertIn(proto, protocols.get_supported_protocols())
        self.assertEqual(len(protocols.BASE_PROTOCOLS), 16)
        self.assertIn("GRE", protocols.BASE_PROTOCOLS)
        self.assertIn("ESP", protocols.BASE_PROTOCOLS)

    def test_inner_probed_covers_the_new_carriers(self):
        for proto in NEW:
            self.assertIn(proto, protocols.INNER_PROBED)

    def test_fallback_chain_tries_kernel_before_overlays(self):
        order = wizard_setup.FALLBACK_ORDER
        self.assertLess(order.index("ESP"), order.index("fou-gre"))
        self.assertLess(order.index("fou-gre"), order.index("ipip"))
        self.assertLess(order.index("ipip"), order.index("wireguard"))
        self.assertLess(order.index("wireguard"), order.index("backhaul-wss"))
        self.assertEqual(len(order), len(set(order)))

    def test_6to4_is_not_a_protocol(self):
        # SIT encapsulates IPv6 in IPv4; Rahyaab's inners are IPv4.
        self.assertNotIn("6to4", protocols.GENERATORS)
        self.assertNotIn("6to4", protocols.BASE_PROTOCOLS)


class TestKernelCarrierNaming(unittest.TestCase):
    def test_iface_names_are_short_tagged_and_bench_suffixed(self):
        self.assertEqual(protocols.carrier_iface("fou-gre", PID, "prod"), "foug7")
        self.assertEqual(protocols.carrier_iface("fou-gre", PID, "bench"), "foug7b")
        self.assertEqual(protocols.carrier_iface("ipip", PID, "prod"), "ipip7")
        self.assertEqual(protocols.carrier_iface("wireguard", PID, "prod", "a1b2"), "wg7a1b2")
        self.assertEqual(protocols.carrier_iface("wireguard", PID, "bench", "a1b2"), "wg7a1b2b")
        for proto in NEW:
            # The kernel caps interface names at 15 characters.
            self.assertLessEqual(len(protocols.carrier_iface(proto, 199, "bench", "abcd")), 15)

    def test_inner_octets_do_not_collide_with_gre_esp_or_spoof(self):
        seen = {}
        for proto in ("GRE", "ESP") + NEW:
            for ns in ("prod", "bench"):
                pair = protocols.carrier_inner_pair(proto, PID, ns)
                octet = pair[0].rsplit(".", 2)[0]
                self.assertNotIn(octet, seen,
                                 f"{proto}/{ns} shares its /24 with {seen.get(octet)}")
                seen[octet] = f"{proto}/{ns}"
        # Legacy base 10 output is untouched.
        self.assertEqual(protocols.carrier_inner_pair("GRE", PID, "prod"),
                         ("10.10.17.1", "10.10.17.2"))
        self.assertEqual(protocols.carrier_inner_pair("ESP", PID, "prod"),
                         ("10.12.17.1", "10.12.17.2"))
        # A second hub's base 20 shifts every carrier, prod and bench.
        self.assertEqual(protocols.carrier_inner_pair("fou-gre", PID, "prod", 20),
                         ("10.26.17.1", "10.26.17.2"))
        self.assertEqual(protocols.carrier_inner_pair("wireguard", PID, "bench", 20),
                         ("10.33.67.1", "10.33.67.2"))

    def test_unknown_protocol_has_no_carrier_shape(self):
        with self.assertRaises(ValueError):
            protocols.carrier_iface("backhaul-wss", PID, "prod")
        with self.assertRaises(ValueError):
            protocols.carrier_inner_pair("backhaul-wss", PID, "prod")


class TestKernelCarrierPlans(unittest.TestCase):
    def _units(self, plan):
        out = {}
        for side in ("iran", "foreign"):
            for path, text in plan[f"{side}_files"].items():
                if path.endswith(".service"):
                    out[side] = text
        return out

    def test_every_new_carrier_builds_both_sides_and_benches(self):
        for proto in NEW:
            plan = protocols.generate_deployment(proto, PID, IR, FR, FRONT)
            bench = protocols.generate_benchmark_plan(proto, PID, IR, FR)
            for p in (plan, bench):
                units = self._units(p)
                self.assertEqual(set(units), {"iran", "foreign"})
                for side, text in units.items():
                    self.assertNotIn("$", "\n".join(
                        ln for ln in text.splitlines() if ln.startswith("ExecStart")),
                        f"{proto}/{side}: a $ in ExecStart breaks under systemd")
                    self.assertIn("ExecStop=", text)
            # Bench inners differ from prod inners: no bench/prod clash.
            self.assertNotEqual(
                protocols.carrier_inner_pair(proto, PID, "prod"),
                protocols.carrier_inner_pair(proto, PID, "bench"))

    def test_every_installed_rule_has_its_delete(self):
        """test_71's invariant, for the new carriers: no orphan ACCEPT
        may survive a teardown on either host."""
        for proto in NEW:
            plan = protocols.generate_deployment(proto, PID, IR, FR, FRONT)
            for side in ("iran", "foreign"):
                installed = {}
                for cmd in plan[f"{side}_cmds"]:
                    if cmd.startswith("iptables ") and (" -A " in cmd or " -I " in cmd):
                        installed.setdefault(_canon(cmd), []).append(cmd)
                deleted = {_canon(cmd) for cmd in plan[f"teardown_{side}"]
                           if cmd.startswith("iptables ") and " -D " in cmd}
                orphans = [sample[0] for sample in installed.values()
                           if _canon(sample[0]) not in deleted]
                self.assertEqual(orphans, [],
                                 f"{proto}/{side}: orphan rule survives teardown - {orphans}")
            iface = protocols.carrier_iface(proto, PID, "prod")
            joined = "\n".join(plan["teardown_foreign"])
            for verb in ("tcp", "udp"):
                self.assertIn(f"-D INPUT -i {iface} -p {verb} --dport {FRONT}", joined,
                              f"{proto}: Foreign's inner-frontend {verb} ACCEPT is not deleted")


class TestFouGre(unittest.TestCase):
    def test_ports_and_keys(self):
        plan = protocols.generate_deployment("fou-gre", PID, IR, FR, FRONT)
        bench = protocols.generate_benchmark_plan("fou-gre", PID, IR, FR)
        fou_port = 24000 + (PID % 1000)
        self.assertIn(f"ip fou add port {fou_port} ipproto 47",
                      "\n".join(plan["iran_files"].values()))
        self.assertIn("ip fou add port 8897 ipproto 47",
                      "\n".join(bench["iran_files"].values()))
        # The bench GRE key separates bench from prod on the shared
        # encap path; prod carries no key.
        bench_key = 9000 + (PID % 1000)
        self.assertIn(f"ikey {bench_key} okey {bench_key}",
                      "\n".join(bench["iran_files"].values()))
        self.assertNotIn("ikey ", "\n".join(plan["iran_files"].values()))
        # FOU traffic is UDP, not protocol 47, at the firewall.
        self.assertIn(f"-p udp --dport {fou_port} -s {FR}/32",
                      "\n".join(plan["iran_cmds"]))
        self.assertNotIn("-p 47", "\n".join(plan["iran_cmds"]))
        self.assertIn(f"ip fou del port {fou_port}",
                      "\n".join(plan["teardown_iran"]))


class TestIpip(unittest.TestCase):
    def test_bench_guard_only_in_bench_and_proto_4_at_the_firewall(self):
        plan = protocols.generate_deployment("ipip", PID, IR, FR, FRONT)
        bench = protocols.generate_benchmark_plan("ipip", PID, IR, FR)
        self.assertNotIn("BENCH_TUPLE_BUSY", "\n".join(plan["iran_cmds"]))
        self.assertIn("BENCH_TUPLE_BUSY", "\n".join(bench["iran_cmds"]))
        self.assertIn("BENCH_TUPLE_BUSY", "\n".join(bench["foreign_cmds"]))
        self.assertIn(f"mode ipip remote {FR} local {IR}",
                      "\n".join(plan["iran_files"].values()))
        self.assertIn(f"-p 4 -s {FR}/32", "\n".join(plan["iran_cmds"]))


class TestWireguard(unittest.TestCase):
    def _derive_pub(self, priv_b64):
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives import serialization
        priv = x25519.X25519PrivateKey.from_private_bytes(
            base64.b64decode(priv_b64))
        return base64.b64encode(priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    def test_keys_never_reach_units_and_ports_follow_convention(self):
        plan = protocols.generate_deployment("wireguard", PID, IR, FR, FRONT)
        bench = protocols.generate_benchmark_plan("wireguard", PID, IR, FR)
        wg_port = 51820 + (PID % 1000)
        ir_keyfile = f"/etc/best-tunnel/wireguard/prod-p{PID}-iran.key"
        fr_keyfile = f"/etc/best-tunnel/wireguard/prod-p{PID}-foreign.key"
        ir_priv = plan["iran_files"][ir_keyfile].strip()
        fr_priv = plan["foreign_files"][fr_keyfile].strip()
        self.assertEqual(len(base64.b64decode(ir_priv)), 32)
        self.assertEqual(len(base64.b64decode(fr_priv)), 32)
        units = {}
        for side in ("iran", "foreign"):
            for path, text in plan[f"{side}_files"].items():
                if path.endswith(".service"):
                    units[side] = text
        # Each unit carries the peer's PUBLIC key and its own key FILE
        # path - never either private key.
        self.assertNotIn(ir_priv, units["iran"])
        self.assertNotIn(fr_priv, units["foreign"])
        self.assertIn(self._derive_pub(fr_priv), units["iran"])
        self.assertIn(self._derive_pub(ir_priv), units["foreign"])
        self.assertIn(f"private-key {ir_keyfile}", units["iran"])
        self.assertIn(f"listen-port {wg_port}", units["iran"])
        self.assertIn(f"endpoint {FR}:{wg_port}", units["iran"])
        self.assertIn("listen-port 8897", "\n".join(bench["iran_files"].values()))
        # Teardown removes the key files.
        self.assertIn(f"rm -f ", "\n".join(plan["teardown_iran"]))
        self.assertIn(ir_keyfile, "\n".join(plan["teardown_iran"]))
        self.assertIn(fr_keyfile, "\n".join(plan["teardown_foreign"]))
        self.assertIn(f"-p udp --dport {wg_port} -s {FR}/32",
                      "\n".join(plan["iran_cmds"]))


if __name__ == "__main__":
    unittest.main()
