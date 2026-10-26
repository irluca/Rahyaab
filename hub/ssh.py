"""SSH execution for the hub.

An Executor runs one command on one managed server and returns
(rc, stdout, stderr). The hub only ever runs a small fixed set of
commands (see healerctl); nothing from a request body is interpolated
into a command string.

Real executor: paramiko, key-based only, host keys must already be
known — unknown hosts are rejected rather than silently trusted.
The Phase 4 installer pins each fleet server's host key before the
hub is pointed at it. FakeExecutor exists for the offline tests only.
"""

from __future__ import annotations

import os
from typing import Protocol


class Executor(Protocol):
    def run(self, command: str, timeout: int = 60) -> tuple[int, str, str]:
        ...


class ParamikoExecutor:
    def __init__(self, host: str, port: int = 22, username: str = "root",
                 key_path: str | None = None,
                 known_hosts: str | None = None):
        self.host = host
        self.port = port
        self.username = username
        self.key_path = key_path
        self.known_hosts = known_hosts or os.path.expanduser("~/.ssh/known_hosts")

    def run(self, command: str, timeout: int = 60) -> tuple[int, str, str]:
        import paramiko

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if os.path.exists(self.known_hosts):
            client.load_host_keys(self.known_hosts)
        # Reject unknown hosts: a new fleet server must have its host
        # key pinned first (Phase 4 installer does this explicitly).
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(
                self.host, port=self.port, username=self.username,
                key_filename=self.key_path, timeout=20, banner_timeout=30,
                auth_timeout=30, allow_agent=False, look_for_keys=False,
                password=None)
            _, stdout, stderr = client.exec_command(command, timeout=timeout)
            rc = stdout.channel.recv_exit_status()
            return rc, stdout.read().decode("utf-8", errors="replace"), \
                stderr.read().decode("utf-8", errors="replace")
        finally:
            client.close()


class FakeExecutor:
    """Test-only executor: canned (rc, stdout, stderr) per command prefix."""

    def __init__(self, responses: dict[str, tuple[int, str, str]] | None = None):
        self.responses = responses or {}
        self.commands: list[str] = []

    def run(self, command: str, timeout: int = 60) -> tuple[int, str, str]:
        self.commands.append(command)
        for prefix, result in self.responses.items():
            if command.startswith(prefix):
                return result
        return 0, "", ""


def executor_for_server(server: dict, fake: Executor | None = None) -> Executor:
    if fake is not None:
        return fake
    return ParamikoExecutor(
        host=server["host"], port=server.get("port") or 22,
        username=server.get("username") or "root",
        key_path=server.get("key_path"))
