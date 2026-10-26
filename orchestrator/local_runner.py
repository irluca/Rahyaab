#!/usr/bin/env python3
"""A Runner that executes on the local host instead of over SSH.

The server-side healer (healer.py) runs ON the Iran host, so its Iran leg
needs no network at all: the same Runner interface the engine, the health
checker and the failover manager already consume, backed by subprocess.

Semantics mirror SafeSSHRunner on purpose, so a caller cannot tell which
leg it holds:

* `run(cmd, check=True, best_effort=False, timeout=30, retryable=False)`
  returns (rc, stdout, stderr). A command the safety policy blocks raises
  PermissionError before anything runs, exactly like the SSH runner. A
  non-zero exit raises RuntimeError unless check is False or best_effort
  is True. A timeout raises TimeoutError naming the budget. There is no
  session to drop, so `retryable` changes nothing here: a local exec
  failure is a real failure, not a transport flap, and re-issuing a
  mutating command (a restart, a teardown) would be the bug the SSH
  runner's re-issue rule exists to prevent.
* `write_file(path, content)` writes mode 0600, for the same reason the
  SSH runner's does: the files staged here are REALITY private keys and
  tunnel configs, and a world-readable copy on the Iran host would hand
  them to every local user.
* `close()` is a no-op: there is nothing to disconnect, and the monitor
  closes its runners after every pass.

Only the healer uses this runner, and only for the Iran leg. The foreign
leg still goes over SSH with the healer's dedicated key, through the
normal get_ssh_runner factory.
"""

import os
import subprocess

from safety import check_command_safe


class LocalRunner:
    """Subprocess-backed Runner for the host the healer itself runs on."""

    def __init__(self, hostname: str = "localhost"):
        self.hostname = hostname
        self.closed = False

    def run(self, cmd: str, check=True, best_effort=False, timeout=30,
            retryable=False):
        if not check_command_safe(cmd):
            raise PermissionError(
                f"SECURITY VIOLATION: Command blocked by safety policy: {cmd[:100]}")
        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(
                f"local command timed out after {timeout}s: {cmd[:120]}") from exc
        out_str = proc.stdout.decode("utf-8", errors="replace")
        err_str = proc.stderr.decode("utf-8", errors="replace")
        if check and not best_effort and proc.returncode != 0:
            raise RuntimeError(
                f"Local command failed (exit {proc.returncode}): {cmd[:100]}\n"
                f"Stderr: {err_str[:300]}")
        return proc.returncode, out_str, err_str

    def write_file(self, path: str, content: str, timeout: int = 30) -> None:
        # umask 077 covers a new file; the explicit chmod covers a redeploy
        # onto a path that already exists, whose mode umask does not change.
        old_umask = os.umask(0o077)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
        finally:
            os.umask(old_umask)
        os.chmod(path, 0o600)

    def close(self):
        self.closed = True
