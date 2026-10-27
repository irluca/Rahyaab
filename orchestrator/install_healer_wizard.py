"""Wizard-side healer install: the laptop installer's install(), key auth.

The laptop installer (install_healer.py) authenticates to both hosts
with root passwords typed into the laptop. The wizard runs on the hub
server and authenticates with the hub key, which push-key already
installed on both servers — so no password is ever needed here.

This module adapts only the transport: KeyHost implements install()'s
Host interface (exec / read_file / write_file / close) over key auth
with pinned host keys (unknown hosts are rejected, exactly like the
dashboard's executor). Everything else — healer keypair creation on
Iran, authorisation on foreign, config + unit, the --once validation
pass, service start and heartbeat check — is install() itself, so the
wizard and the laptop install the same healer the same way.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import install_healer  # noqa: E402


class KeyHost:
    """One SSH host, via the hub key, with pinned host keys."""

    def __init__(self, host: str, port: int, user: str, key_path: str,
                 known_hosts: str = "/root/.ssh/known_hosts"):
        import paramiko
        self.label = host
        self._client = paramiko.SSHClient()
        self._client.load_system_host_keys()
        if os.path.exists(known_hosts):
            self._client.load_host_keys(known_hosts)
        self._client.set_missing_host_key_policy(paramiko.RejectPolicy())
        self._client.connect(host, port=port, username=user,
                             key_filename=key_path, timeout=20,
                             banner_timeout=30, auth_timeout=30,
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


def wizard_install(iran_host: str, foreign_host: str, pair_id: int,
                   pair_name: str, frontend_port: int, active_tunnel: str,
                   candidate_scores: dict, hub_key_path: str,
                   code_dir: str | None = None,
                   settle_seconds: float = 25) -> dict:
    """Install + start the healer for a wizard pair. Returns install()'s
    verification summary (steps, once output, heartbeat, active)."""
    code_dir = code_dir or os.path.dirname(os.path.abspath(__file__))
    row = {
        "id": pair_id, "name": pair_name,
        "iran_host": iran_host, "iran_port": 22,
        "foreign_host": foreign_host, "foreign_port": 22,
        "frontend_port": frontend_port,
        "active_tunnel": active_tunnel,
    }
    cfg = install_healer.build_healer_config(row, dict(candidate_scores),
                                             telegram=None)
    code_files = install_healer.collect_code_files(code_dir)
    iran = KeyHost(iran_host, 22, "root", hub_key_path)
    foreign = KeyHost(foreign_host, 22, "root", hub_key_path)
    try:
        return install_healer.install(iran, foreign, cfg, code_files,
                                      settle_seconds=settle_seconds)
    finally:
        iran.close()
        foreign.close()
