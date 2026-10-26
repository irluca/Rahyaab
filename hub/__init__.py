"""Rahyaab hub: server-side control plane for tunnel pairs.

Pure Python standard library, plus paramiko only for the real SSH
executor (hub/ssh.py). The hub never stores passwords for managed
servers: SSH is key-based only. Its own database lives outside the
repo by default (see hub/main.py), never next to the code.
"""

__version__ = "0.2.0"
