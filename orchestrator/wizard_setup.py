"""Full-setup wizard, steps 5-7: measure, deploy the first tunnel, install the healer.

Runs on the hub server, after install.sh did hub install + push-key +
remote node install, and after hub/wizard.py registered the pair.

Trust bridge: push-key verified both host keys and pinned them in
/root/.ssh/known_hosts. The engine's own host-key store (SQLite, TOFU)
is a different store, so before any sweep or deploy connection this
module seeds it from known_hosts — a first connection that presents a
different key is then REJECTED, never blindly pinned.

Measurement is honest or it refuses: candidates are tried in order
(first the requested protocol, default GRE, then the fallback order)
with the engine's own single-benchmark path (temporary test tunnel on
ports 8897/8898, never the production frontend), and the first
protocol with a positive score is deployed. A disqualified or
zero-score row only rejects that candidate; only when every
candidate fails does the setup abort, with every candidate's reason
in the error. The first production tunnel is then deployed with the
engine's deploy_tunnel (verified + rollback), and only then is the
healer installed on top of it — the monitor never has to conjure a
tunnel from nothing, because a pair with no deployed tunnel produces
no sample and the monitor does not act on it.

The engine evidence database lives outside the repository
(/var/lib/rahyaab/wizard.db); a live run refuses to start while its
database is inside the working tree.
"""

import os
import sys

os.environ.setdefault("BEST_TUNNEL_DB_PATH", "/var/lib/rahyaab/wizard.db")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DEFAULT_PROTOCOL = "GRE"

# First-tunnel fallback order (bug 15, 2026-11-01): a new node used to
# end up connected to NOTHING when its first protocol (GRE) failed —
# the setup job failed and a human had to requeue ESP, then an
# overlay, by hand (pair 4, jobs 19/20/21). The wizard now tries
# candidates in order and deploys the first one that measures clean,
# exactly that manual chain, on its own. Carriers first (best when
# they work), then the TCP overlays by robustness, UDP last (UDP may
# be filtered where TCP passes). singbox-vless-reality is NOT in the
# chain: the carrier gate refuses it on GRE pairs and it needs its
# own evaluation; the sweep still ranks it afterwards. Spoof and Bale
# are excluded for the same reason as everywhere else (probe-gated
# and parked).
FALLBACK_ORDER = ["GRE", "ESP", "fou-gre", "ipip", "wireguard",
                  "backhaul-wss", "rathole-noise",
                  "frp-TLS", "chisel-wss", "xray-reverse", "wstunnel-v10",
                  "singbox-ss-2022", "kcptun", "hysteria2", "tcp-lanes"]


def parse_known_hosts(path: str) -> dict:
    """Parse unhashed known_hosts lines into {(host, port): (type, b64)}.

    Hashed entries (|1|...) cannot be mapped to a host and are skipped;
    push-key writes plain lines, so the wizard's hosts are always here.
    """
    pins = {}
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return pins
    for line in lines:
        parts = line.split()
        if len(parts) < 3 or parts[0].startswith("|") or parts[0].startswith("#"):
            continue
        hostfield, key_type, b64 = parts[0], parts[1], parts[2]
        for host in hostfield.split(","):
            if host.startswith("[") and "]:" in host:
                name, port = host[1:].split("]:", 1)
                try:
                    pins[(name, int(port))] = (key_type, b64)
                except ValueError:
                    continue
            else:
                pins[(host, 22)] = (key_type, b64)
    return pins


def seed_host_pins(known_hosts_path: str, hosts: list, pin_fn=None) -> list:
    """Seed the engine's pinned-key store from verified known_hosts.

    pin_fn defaults to storage.pin_host_key at call time (so tests can
    inject a fake). Returns the (host, port) pairs actually seeded.
    """
    if pin_fn is None:
        import storage
        pin_fn = storage.pin_host_key
    pins = parse_known_hosts(known_hosts_path)
    seeded = []
    for host, port in hosts:
        if (host, port) in pins:
            key_type, b64 = pins[(host, port)]
            pin_fn(host, port, key_type, b64)
            seeded.append((host, port))
    return seeded


def pair_spec(iran_host: str, foreign_host: str, hub_key_path: str,
              pair_id: int, frontend_port: int = 443, hub_tag: str = "",
              inner_base: int = 10) -> dict:
    """Engine pair dict with key auth on both legs.

    hub_tag/inner_base travel with the pair from here on: every unit,
    config, interface and inner address the deploy, the healer and the
    sweep generate for this pair derives from them, so a pair deployed
    by a second hub can never overwrite or misroute the first hub's.
    """
    auth = {"type": "key", "value": hub_key_path}
    return {
        "id": pair_id,
        "iran": {"host": iran_host, "port": 22, "user": "root", "auth": auth},
        "foreign": {"host": foreign_host, "port": 22, "user": "root", "auth": auth},
        "frontend": frontend_port,
        "base_rtt_ms": 0.0,
        "hub_tag": hub_tag or "",
        "inner_base": int(inner_base or 10),
    }


def preflight_collision_check(pair: dict, ir_runner, fr_runner) -> None:
    """Refuse a setup whose carrier inners or node-side names already exist.

    A second hub's pair 1 would otherwise deploy grep1/espp1 and
    10.10.11.x onto a node where the first hub's pair 1 already lives,
    and the second deploy would either fail or break the first tunnel.
    This check reads both hosts (read-only) before any measure runs and
    raises ValueError naming the offending object and host, so the
    failure is a refused join — never a broken tunnel. It also catches
    the single-hub case the scheme itself cannot: pair ids wrap at 200,
    so pair 201 would otherwise silently reuse pair 1's inners.
    """
    import re
    tag = pair.get("hub_tag") or ""
    base = int(pair.get("inner_base") or 10)
    pid = int(pair.get("id") or 1)
    idx = (pid % 200) + 10
    planned_ifaces = {"grep%d%s" % (pid, tag), "espp%d%s" % (pid, tag)}
    planned_unit_prefix = "best-tunnel-prod-p%d-%s-" % (pid, tag) if tag else "best-tunnel-prod-p%d-" % pid
    for role, runner in (("iran", ir_runner), ("foreign", fr_runner)):
        _, out_addr, _ = runner.run("ip -o addr show", best_effort=True)
        _, out_link, _ = runner.run("ip -o link show", best_effort=True)
        _, out_units, _ = runner.run(
            "systemctl list-units 'best-tunnel-prod-*' --all --no-legend",
            best_effort=True)
        for line in (out_addr or "").splitlines():
            m = re.search(r"inet (\d+)\.(\d+)\.(\d+)\.(\d+)/", line)
            if not m:
                continue
            o1, o2, o3, o4 = (int(x) for x in m.groups())
            if o1 == 10 and o2 in (base, base + 2) and o3 == idx and o4 <= 3:
                raise ValueError(
                    "preflight: %s already has address %d.%d.%d.%d on a carrier "
                    "interface — this pair's inner /30 (base %d, pair %d) is "
                    "already in use there, most likely by another hub's pair. "
                    "Install this hub with a different inner base."
                    % (role, o1, o2, o3, o4, base, pid))
        for line in (out_link or "").splitlines():
            m = re.match(r"\d+: ([^:]+):", line)
            if m and m.group(1) in planned_ifaces:
                raise ValueError(
                    "preflight: %s already has carrier interface %s — a "
                    "carrier for this pair id and hub tag is already deployed "
                    "there; remove it before joining again."
                    % (role, m.group(1)))
        for line in (out_units or "").splitlines():
            unit = line.split()[0] if line.split() else ""
            if unit.startswith(planned_unit_prefix):
                raise ValueError(
                    "preflight: %s already has unit %s — a production unit "
                    "for this pair id and hub tag is already deployed there; "
                    "remove it before joining again." % (role, unit))


def measure_single_protocol(pair: dict, protocol: str) -> dict:
    """Real measurement: base RTT + one engine single-benchmark row.

    Raises on a disqualified or zero-score row — the setup must not
    continue on an invented score.
    """
    import engine
    import protocols
    from mock_ssh import get_ssh_runner
    ir_runner = get_ssh_runner(pair["iran"], dry_run=False, host_role="iran")
    try:
        fr_runner = get_ssh_runner(pair["foreign"], dry_run=False, host_role="foreign")
        try:
            base = engine.measure_direct_base_rtt(
                ir_runner, protocols.dial_address(pair["foreign"], protocol),
                dry_run=False)
            row = engine.run_single_benchmark(
                pair, protocol, dry_run=False, ir_runner=ir_runner,
                fr_runner=fr_runner, base_rtt=base.base_rtt_ms)
        finally:
            fr_runner.close()
    finally:
        ir_runner.close()
    if row.get("disqualified") or not (row.get("score") or 0) > 0:
        reasons = row.get("dq_reasons") or ["unmeasured"]
        raise RuntimeError(
            f"Protocol {protocol} did not measure cleanly: {reasons}")
    return row


def measure_first_working_protocol(pair: dict, protocol: str,
                                   measure_fn) -> tuple:
    """Try candidates in order; return (protocol, row, tried, errors).

    The first candidate is the requested protocol, then FALLBACK_ORDER
    (deduped). A candidate fails as a *verdict* when measuring raises
    the "did not measure cleanly" RuntimeError or returns a
    non-positive score — the bench ran and the protocol failed, so the
    chain continues. Any other exception (SSH/connectivity, teardown)
    is infrastructure, not a protocol verdict: it would fail every
    candidate the same way, so it aborts immediately instead of
    burning one measure per candidate. When every candidate fails as
    a verdict, raises a RuntimeError listing every candidate and its
    reason, so the job error is a full diagnosis, not one protocol.
    """
    candidates = []
    for cand in [protocol] + FALLBACK_ORDER:
        if cand not in candidates:
            candidates.append(cand)
    tried = []
    errors = {}
    for cand in candidates:
        tried.append(cand)
        try:
            row = measure_fn(pair, cand)
        except RuntimeError as exc:
            if "did not measure cleanly" in str(exc):
                errors[cand] = str(exc)
                continue
            raise
        score = float(row.get("score") or 0)
        if score > 0:
            return cand, row, tried, errors
        errors[cand] = "non-positive score %s" % row.get("score")
    detail = "; ".join("%s: %s" % (c, errors[c]) for c in candidates)
    raise RuntimeError(
        "No protocol measured cleanly for this pair: %s" % detail)
    """Real production deploy; raises on failure, returns status dict."""
    import engine
    result = engine.deploy_tunnel(pair, protocol, dry_run=False)
    if not str(result.get("status", "")).startswith("ACTIVE"):
        raise RuntimeError(f"Deploy of {protocol} did not verify: {result}")
    return result


def record_measurement(hub_db_path: str, pair_id: int, scores: dict,
                       protocol: str) -> None:
    from hub.store import Store
    Store(hub_db_path).update_pair_measurement(pair_id, scores, protocol)


def run_setup(iran_host: str, foreign_host: str, pair_id: int,
              pair_name: str, hub_db_path: str, hub_key_path: str,
              frontend_port: int = 443, protocol: str = DEFAULT_PROTOCOL,
              known_hosts_path: str = "/root/.ssh/known_hosts",
              pin_fn=None, measure_fn=None, deploy_fn=None,
              install_fn=None, record_fn=None, ensure_fn=None,
              hub_tag: str = "", inner_base: int = 10,
              preflight_fn=None, preflight: bool = True) -> dict:
    """Measure, deploy, install the healer, record. Returns a summary.

    The *_fn arguments default to the real implementations; tests
    inject fakes. Any step raising aborts the setup — a half-built
    pair is reported, never papered over with a fake score or a
    claimed tunnel.
    """
    import install_healer_wizard
    if pin_fn is None:
        import storage
        pin_fn = storage.pin_host_key
    if ensure_fn is None:
        import storage
        ensure_fn = storage.ensure_pair_row
    measure_fn = measure_fn or measure_single_protocol
    deploy_fn = deploy_fn or deploy_first_tunnel
    install_fn = install_fn or install_healer_wizard.wizard_install
    record_fn = record_fn or record_measurement

    seeded = seed_host_pins(known_hosts_path,
                            [(iran_host, 22), (foreign_host, 22)],
                            pin_fn=pin_fn)
    pair = pair_spec(iran_host, foreign_host, hub_key_path, pair_id,
                     frontend_port, hub_tag=hub_tag, inner_base=inner_base)
    # Multi-master pre-flight: refuse before any measure creates state
    # when this pair's inners or names already exist on either host.
    # Skipped only by tests, which cover the check itself directly;
    # a skipped pre-flight creates no runners at all, so no SSH happens.
    if preflight:
        if preflight_fn is None:
            preflight_fn = preflight_collision_check
        from mock_ssh import get_ssh_runner
        _ir_pre = get_ssh_runner(pair["iran"], dry_run=False, host_role="iran")
        try:
            _fr_pre = get_ssh_runner(pair["foreign"], dry_run=False, host_role="foreign")
            try:
                preflight_fn(pair, _ir_pre, _fr_pre)
            finally:
                _fr_pre.close()
        finally:
            _ir_pre.close()
    # Bug 15: try candidates in order and deploy the first one that
    # measures clean, instead of failing the whole setup on the first
    # protocol. A pair that ends up connected to nothing is the
    # failure this exists to prevent.
    protocol, row, tried, _errors = measure_first_working_protocol(
        pair, protocol, measure_fn)
    score = float(row["score"])
    # The deploy's carrier declaration is UPDATE-only by design, so the
    # pair row must exist before deploy runs — no wizard caller ever
    # created it, and every deploy's declaration was silently dropped
    # (bug 12, 2026-11-01). Ensuring it here costs nothing on re-runs.
    ensure_fn(pair_id, pair_name, iran_host, foreign_host, frontend_port,
              hub_tag=hub_tag, inner_base=inner_base)
    deploy = deploy_fn(pair, protocol)
    install = install_fn(iran_host, foreign_host, pair_id, pair_name,
                         frontend_port, protocol, {protocol: score},
                         hub_key_path, hub_tag=hub_tag, inner_base=inner_base)
    record_fn(hub_db_path, pair_id, {protocol: score}, protocol)
    return {
        "protocol": protocol,
        "score": score,
        "tried": tried,
        "hub_tag": hub_tag or "",
        "inner_base": int(inner_base or 10),
        "base_rtt_ms": row.get("base_rtt_ms"),
        "seeded_host_pins": seeded,
        "deploy_status": deploy.get("status"),
        "healer_active": install.get("active"),
        "healer_heartbeat": install.get("heartbeat"),
    }


def main(argv=None) -> int:
    """CLI for install.sh's full-setup: prints the summary as JSON."""
    import argparse
    import json
    parser = argparse.ArgumentParser(description="Rahyaab setup wizard: measure, deploy, install healer")
    parser.add_argument("--iran-host", required=True)
    parser.add_argument("--foreign-host", required=True)
    parser.add_argument("--pair-id", type=int, required=True)
    parser.add_argument("--pair-name", default="جفت اصلی")
    parser.add_argument("--hub-db", default="/var/lib/rahyaab/hub.db")
    parser.add_argument("--hub-key", default="/etc/rahyaab/hub_key")
    parser.add_argument("--frontend-port", type=int, default=443)
    parser.add_argument("--protocol", default=DEFAULT_PROTOCOL)
    parser.add_argument("--hub-tag", default="")
    parser.add_argument("--inner-base", type=int, default=10)
    args = parser.parse_args(argv)
    summary = run_setup(
        args.iran_host, args.foreign_host, args.pair_id, args.pair_name,
        args.hub_db, args.hub_key, frontend_port=args.frontend_port,
        protocol=args.protocol, hub_tag=args.hub_tag,
        inner_base=args.inner_base)
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
