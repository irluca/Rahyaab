#!/usr/bin/env bash
# Installs a best-tunnel-agent binary, verifying its checksum first.
# This is the agent's half of the product's binary rule: no binary runs
# on a server unless its SHA-256 matches the pinned value the operator
# recorded at build time. The agent itself never self-updates; a new
# version arrives only through this script, with a new pinned hash.
#
# Usage: install_agent.sh <binary-path> <expected-sha256>
set -euo pipefail

BIN="${1:?usage: install_agent.sh <binary-path> <expected-sha256>}"
WANT="${2:?usage: install_agent.sh <binary-path> <expected-sha256>}"

if [ ! -f "$BIN" ]; then
    echo "[ERROR] binary not found: $BIN" >&2
    exit 1
fi

GOT="$(sha256sum "$BIN" | awk '{print $1}')"
if [ "$GOT" != "$WANT" ]; then
    echo "[SECURITY ERROR] SHA-256 mismatch for best-tunnel-agent" >&2
    echo "Expected: $WANT" >&2
    echo "Actual:   $GOT" >&2
    exit 1
fi

echo "[INFO] checksum verified: $GOT"
install -m 755 "$BIN" /usr/local/bin/best-tunnel-agent
echo "[SUCCESS] installed /usr/local/bin/best-tunnel-agent"
echo "[NOTE] write /etc/best-tunnel/agent.toml, then:"
echo "  cp agent/best-tunnel-agent.service /etc/systemd/system/"
echo "  systemctl daemon-reload && systemctl enable --now best-tunnel-agent"
