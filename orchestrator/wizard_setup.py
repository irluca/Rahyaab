"""Full-setup wizard, steps 5-7: measure, deploy the first tunnel, install the healer.

Runs on the hub server, after install.sh did hub install + push-key +
remote node install, and after hub/wizard.py registered the pair.

Trust bridge: push-key verified both host keys and pinned them in
/root/.ssh/known_hosts. The engine's own host-key store (SQLite, TOFU)
is a different store, so before any sweep or deploy connection this
module seeds it from known_hosts — a first connection that presents a
different key is then REJECTED, never blindly pinned.

Measurement is honest or it refuses: one protocol (default GRE, the
carrier that has measured best on this route) is measured with the
engine's own single-benchmark path (temporary test tunnel on ports
8897/8898, never the production frontend), and a disqualified or
zero-score row aborts the setup instead of inventing a score. The
first production tunnel is then deployed with the engine's
deploy_tunnel (verified + rollback), and only then is the healer
installed on top of it — the monitor never has to conjure a tunnel
from nothing, because a pair with no deployed tunnel produces no
sample and the monitor does not act on it.

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
              pair_id: int, frontend_port: int = 443) -> dict:
    """Engine pair dict with key auth on both legs."""
    auth = {"type": "key", "value": hub_key_path}
    return {
        "id": pair_id,
        "iran": {"host": iran_host, "port": 22, "user": "root", "auth": auth},
        "foreign": {"host": foreign_host, "port": 22, "user": "root", "auth": auth},
        "frontend": frontend_port,
        "base_rtt_ms": 0.0,
    }


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


def deploy_first_tunnel(pair: dict, protocol: str) -> dict:
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
              install_fn=None, record_fn=None) -> dict:
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
    measure_fn = measure_fn or measure_single_protocol
    deploy_fn = deploy_fn or deploy_first_tunnel
    install_fn = install_fn or install_healer_wizard.wizard_install
    record_fn = record_fn or record_measurement

    seeded = seed_host_pins(known_hosts_path,
                            [(iran_host, 22), (foreign_host, 22)],
                            pin_fn=pin_fn)
    pair = pair_spec(iran_host, foreign_host, hub_key_path, pair_id,
                     frontend_port)
    row = measure_fn(pair, protocol)
    score = float(row["score"])
    if not score > 0:
        raise RuntimeError(
            f"Protocol {protocol} measured a non-positive score; refusing to continue")
    deploy = deploy_fn(pair, protocol)
    install = install_fn(iran_host, foreign_host, pair_id, pair_name,
                         frontend_port, protocol, {protocol: score},
                         hub_key_path)
    record_fn(hub_db_path, pair_id, {protocol: score}, protocol)
    return {
        "protocol": protocol,
        "score": score,
        "base_rtt_ms": row.get("base_rtt_ms"),
        "seeded_host_pins": seeded,
        "deploy_status": deploy.get("status"),
        "healer_active": install.get("active"),
        "healer_heartbeat": install.get("heartbeat"),
    }
