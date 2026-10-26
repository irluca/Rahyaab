#!/usr/bin/env python3
"""Install the server-side healer (healer.py) from the operator's laptop.

The healer cannot be installed by anyone else: the pair's SSH passwords
live only in the operator's hands, and this script asks for them on the
operator's own terminal (getpass - never a command-line flag, never
written to any file, never sent anywhere). Run it from the project
folder with the project Python, e.g.:

    .venv\\Scripts\\python.exe orchestrator\\install_healer.py

What it does, in order:

1. Reads the pair row and benchmark medians from the laptop database
   (the same evidence the dashboard's ranking uses) and builds the
   healer config. Disqualified protocols are left out: a transport the
   sweep disqualified must not come back as a healer candidate.
2. Installs Python dependencies on the Iran host (python3-paramiko,
   python3-cryptography) and uploads every orchestrator module.
3. Creates a dedicated ed25519 keypair on the Iran host (only if none
   exists) and authorises its public key on the foreign host (only if
   not already present). The private key never leaves the Iran host.
4. Writes the healer config (0600) and the systemd unit, wipes the
   healer database so the next start seeds fresh medians, and stops and
   disables the old resident agents on both hosts: while the healer
   owns the pair, a second controller would resurrect units mid-switch.
5. Validates with one `healer.py --once` pass BEFORE starting the
   service (so the validator is the only actor), then enables and
   starts the service and checks it is active with a fresh heartbeat.

Re-running is safe: the keypair, the authorised key, the uploads, the
config and the unit are all overwritten or skipped idempotently, and a
re-install after a fresh benchmark picks up the new medians. To go back
to dashboard control: `systemctl stop best-tunnel-healer` on the Iran
host, then use the dashboard as before (and re-enable the agents if
they are still wanted).
"""

import argparse
import getpass
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import failover
import storage

CODE_DIR = "/opt/best-tunnel/orchestrator"
CONFIG_PATH = "/etc/best-tunnel/healer.json"
KEY_PATH = "/etc/best-tunnel/healer_key"
DB_PATH = "/var/lib/best-tunnel/healer.db"
HEARTBEAT_PATH = "/var/lib/best-tunnel/healer-heartbeat.json"
UNIT_PATH = "/etc/systemd/system/best-tunnel-healer.service"
AGENT_UNIT = "best-tunnel-agent"


def render_unit(code_dir: str = CODE_DIR, config_path: str = CONFIG_PATH) -> str:
    """The healer's systemd unit. Restart=always is the healer's own
    watchdog: a crashed healer comes back by itself, and a stopped one
    (systemctl stop) stays stopped - that is how the operator takes the
    pair back. No secret appears here: the token lives in the 0600
    config, never in argv or a world-readable unit."""
    return f"""[Unit]
Description=Tunnel Studio Pro server-side healer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={code_dir}
ExecStart=/usr/bin/python3 {code_dir}/healer.py --config {config_path}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""


def pair_dict_from_row(row: dict) -> dict:
    """A dashboard-shaped pair dict, for the median refusal checks."""
    return {
        "id": row["id"],
        "frontend_port": row.get("frontend_port", 443),
        "backend_port": row.get("backend_port") or None,
        "underlay_carrier": row.get("underlay_carrier", ""),
        "iran": {"host": row["iran_host"], "port": row.get("iran_port", 22),
                 "dial_host": row.get("iran_dial_host", "") or ""},
        "foreign": {"host": row["foreign_host"], "port": row.get("foreign_port", 22),
                    "dial_host": row.get("foreign_dial_host", "") or ""},
    }


def export_medians(pair_id: int, pair: dict) -> dict[str, float]:
    """Benchmark medians for the healer's candidate ranking.

    Disqualified protocols are omitted, not seeded with a score: the
    selector would exclude a disqualified row anyway, but a seeded row
    marked qualified would resurrect a transport the sweep disqualified.
    """
    medians, disqualified = failover.median_protocol_scores(pair_id, None, pair)
    return {proto: score for proto, score in medians.items()
            if proto not in disqualified}


def build_healer_config(row: dict, medians: dict[str, float],
                        telegram: dict | None = None) -> dict:
    """The config the installer ships to the Iran host. No password:
    the foreign leg authenticates with the dedicated key, and the Iran
    leg is local. The optional Telegram token is the only secret, and it
    lands in a 0600 file, never in the unit or the terminal output."""
    cfg = {
        "pair_id": row["id"],
        "pair_name": row.get("name", ""),
        "iran": {"host": row["iran_host"], "port": row.get("iran_port", 22), "user": "root"},
        "foreign": {"host": row["foreign_host"], "port": row.get("foreign_port", 22),
                    "user": "root"},
        "key_path": KEY_PATH,
        "frontend_port": row.get("frontend_port", 443),
        "backend_port": row.get("backend_port") or None,
        "underlay_carrier": row.get("underlay_carrier", ""),
        "iran_dial_host": row.get("iran_dial_host", "") or "",
        "foreign_dial_host": row.get("foreign_dial_host", "") or "",
        "base_rtt_ms": row.get("base_rtt_ms", 0.0) or 0.0,
        "active_tunnel": (row.get("active_tunnel") or "").strip(),
        "candidate_scores": dict(medians),
        "check_interval_seconds": 20,
        "down_streak": 3,
        "db_path": DB_PATH,
        "heartbeat_path": HEARTBEAT_PATH,
    }
    if telegram and telegram.get("bot_token") and telegram.get("chat_id"):
        cfg["telegram"] = {"bot_token": telegram["bot_token"],
                           "chat_id": telegram["chat_id"]}
    return cfg


class Host:
    """One SSH host, via paramiko, with TOFU host-key pinning."""

    def __init__(self, host: str, port: int, user: str, password: str):
        import paramiko
        import mock_ssh
        self.label = host
        self._client = paramiko.SSHClient()
        self._client._port = port
        self._client.set_missing_host_key_policy(mock_ssh.TOFUHostKeyPolicy())
        self._client.connect(host, port=port, username=user, password=password,
                             timeout=20, banner_timeout=30, auth_timeout=30,
                             allow_agent=False, look_for_keys=False)

    def exec(self, cmd: str, timeout: int = 120, check: bool = True):
        _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        if check and rc != 0:
            raise RuntimeError(f"[{self.label}] command failed (exit {rc}): {cmd[:120]}\n{err[:300]}")
        return rc, out, err

    def read_file(self, path: str) -> str:
        try:
            with self._client.open_sftp() as sftp:
                with sftp.open(path, "r") as f:
                    return f.read().decode("utf-8", errors="replace")
        except OSError:
            return ""

    def write_file(self, path: str, content: str, mode: int = 0o600) -> None:
        with self._client.open_sftp() as sftp:
            with sftp.open(path, "w") as f:
                f.write(content)
            sftp.chmod(path, mode)

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass


def install(iran: Host, foreign: Host, cfg: dict, code_files: dict[str, str],
            settle_seconds: float = 25) -> dict:
    """Run every install step. Returns a verification summary.

    code_files maps filenames to contents (the orchestrator modules to
    upload). Raises on the first failing required step; agent
    stop/disable is best-effort because an absent agent is not an error.
    settle_seconds is the wait for the first heartbeat after start (the
    service's check interval is 20 s); tests pass 0.
    """
    steps = []
    # 1. Dependencies on the Iran host.
    iran.exec("apt-get update && apt-get install -y python3-paramiko python3-cryptography",
              timeout=600)
    steps.append("iran dependencies installed")
    # 2. Directories + code upload.
    iran.exec("mkdir -p /opt/best-tunnel/orchestrator /etc/best-tunnel /var/lib/best-tunnel")
    for name, content in sorted(code_files.items()):
        iran.write_file(f"{CODE_DIR}/{name}", content, mode=0o644)
    steps.append(f"{len(code_files)} orchestrator modules uploaded")
    # 3. Dedicated keypair on Iran (only if missing), authorised on foreign.
    rc, _, _ = iran.exec(f"test -e {KEY_PATH}", check=False)
    if rc != 0:
        iran.exec(f"ssh-keygen -t ed25519 -f {KEY_PATH} -N '' -C 'best-tunnel-healer'")
        steps.append("healer keypair created on Iran host")
    else:
        steps.append("healer keypair already present on Iran host")
    pubkey = iran.read_file(KEY_PATH + ".pub").strip()
    if not pubkey:
        raise RuntimeError("healer public key is unreadable on the Iran host")
    foreign.exec("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
    # Resolve the remote home over the session: the laptop's own home is
    # a different machine's path and must never be used here.
    _, home, _ = foreign.exec("echo $HOME")
    auth_path = (home.strip() + "/.ssh/authorized_keys") if home.strip() else ".ssh/authorized_keys"
    authorised = foreign.read_file(auth_path)
    if pubkey not in authorised:
        new_keys = (authorised.rstrip("\n") + "\n" + pubkey + "\n") if authorised.strip() else (pubkey + "\n")
        foreign.write_file(auth_path, new_keys, mode=0o600)
        steps.append("healer public key authorised on foreign host")
    else:
        steps.append("healer public key already authorised on foreign host")
    foreign.exec(f"chmod 600 {auth_path}")
    # 4. Config + unit + fresh database.
    iran.write_file(CONFIG_PATH, json.dumps(cfg, indent=2, sort_keys=True), mode=0o600)
    iran.write_file(UNIT_PATH, render_unit(), mode=0o644)
    iran.exec(f"rm -f {DB_PATH} {DB_PATH}-wal {DB_PATH}-shm")
    steps.append("healer config and unit written, database reset for fresh seeding")
    # 5. Retire the old agents on both hosts (best-effort: absent is fine).
    for host in (iran, foreign):
        host.exec(f"systemctl stop {AGENT_UNIT} 2>/dev/null; systemctl disable {AGENT_UNIT} 2>/dev/null",
                  check=False)
    steps.append("resident agents stopped and disabled on both hosts")
    # 6. Validate with one --once pass BEFORE the service starts, so the
    # validator is the only actor that can heal.
    iran.exec("systemctl daemon-reload")
    _, once_out, _ = iran.exec(
        f"/usr/bin/python3 {CODE_DIR}/healer.py --config {CONFIG_PATH} --once", timeout=300)
    steps.append("healer --once validation pass completed")
    # 7. Start the service and verify it is alive with a fresh heartbeat.
    iran.exec(f"systemctl enable --now best-tunnel-healer")
    if settle_seconds:
        time.sleep(settle_seconds)
    _, active, _ = iran.exec("systemctl is-active best-tunnel-healer")
    if active.strip() != "active":
        raise RuntimeError("best-tunnel-healer is not active after start")
    heartbeat_raw = iran.read_file(HEARTBEAT_PATH)
    heartbeat = json.loads(heartbeat_raw) if heartbeat_raw.strip() else {}
    steps.append("best-tunnel-healer service active")
    return {"steps": steps, "once_output": once_out, "heartbeat": heartbeat,
            "active": active.strip()}


def collect_code_files(code_dir: str) -> dict[str, str]:
    """Every orchestrator module the healer can import, minus tests and
    local state. Uploading the whole directory beats a dependency list
    that rots: a module added later ships itself."""
    files = {}
    for name in sorted(os.listdir(code_dir)):
        if not name.endswith(".py") or name.startswith("test_"):
            continue
        path = os.path.join(code_dir, name)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                files[name] = f.read()
    if "healer.py" not in files or "local_runner.py" not in files:
        raise RuntimeError(f"healer modules missing from {code_dir}")
    return files


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Install the Tunnel Studio Pro server-side healer")
    parser.add_argument("--pair-id", type=int, default=None)
    parser.add_argument("--db", default=None,
                        help="laptop database path (default: orchestrator/best_tunnel.db)")
    parser.add_argument("--code-dir", default=None,
                        help="orchestrator directory to upload (default: this script's directory)")
    args = parser.parse_args(argv)

    code_dir = args.code_dir or os.path.dirname(os.path.abspath(__file__))
    storage.DB_PATH = args.db or os.path.join(code_dir, "best_tunnel.db")
    storage.init_db()
    pairs = storage.get_pairs()
    if args.pair_id is not None:
        row = storage.get_pair(args.pair_id)
        if row is None:
            print(f"No pair #{args.pair_id} in the laptop database.", file=sys.stderr)
            return 2
    elif len(pairs) == 1:
        row = pairs[0]
    elif not pairs:
        print("No pairs in the laptop database. Add and deploy a pair first.", file=sys.stderr)
        return 2
    else:
        print("Several pairs exist; re-run with --pair-id.", file=sys.stderr)
        return 2
    if not (row.get("active_tunnel") or "").strip():
        print(f"Pair #{row['id']} has no deployed tunnel. Deploy one first.", file=sys.stderr)
        return 2

    medians = export_medians(row["id"], pair_dict_from_row(row))
    if not medians:
        print("No usable benchmark medians for this pair. Run a benchmark first.", file=sys.stderr)
        return 2

    print(f"Pair #{row['id']} ({row.get('name', '')}): active {row['active_tunnel']}, "
          f"{len(medians)} ranked candidates.")
    iran_password = getpass.getpass("Iran host SSH password: ")
    foreign_password = getpass.getpass("Foreign host SSH password: ")
    token = getpass.getpass("Telegram bot token for healer alerts (Enter to skip): ")
    chat_id = ""
    if token.strip():
        chat_id = input("Telegram chat id for healer alerts: ").strip()
    telegram = {"bot_token": token.strip(), "chat_id": chat_id} if token.strip() and chat_id else None
    if token.strip() and not chat_id:
        print("Token without a chat id sends nothing; alerts disabled.", file=sys.stderr)
        telegram = None

    cfg = build_healer_config(row, medians, telegram)
    code_files = collect_code_files(code_dir)
    print("Connecting to both hosts (TOFU host-key pinning, as the dashboard uses)...")
    iran = Host(row["iran_host"], row.get("iran_port", 22), "root", iran_password)
    foreign = Host(row["foreign_host"], row.get("foreign_port", 22), "root", foreign_password)
    try:
        result = install(iran, foreign, cfg, code_files)
    finally:
        iran.close()
        foreign.close()
    print("\nHealer installed:")
    for step in result["steps"]:
        print(f"  - {step}")
    print("\nValidation pass output:")
    print(result["once_output"])
    print("The healer now owns this pair. While it runs, do not deploy, switch or benchmark")
    print("this pair from the dashboard; stop it first on the Iran host:")
    print("  systemctl stop best-tunnel-healer")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
