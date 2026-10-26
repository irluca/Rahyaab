#!/bin/bash
# REVERSE MODE - Foreign side (for foreign servers that CANNOT reach Iran directly)
# Model: chisel CLIENT dials OUT to Iran server, user ports on Iran forward back here.
# Usage: sudo bash foreign-reverse-client.sh
# Only edit vars below (must match iran-reverse-server.sh).
set -e
IR_IP="198.51.100.10"      # Iran public IP (must equal PUB_IP on the Iran host)
IR_CERT="/etc/chisel/iran-cert.pem"   # the Iran host's /etc/chisel/cert.pem, copied over
TRANSPORT_PORT="2096"     # same as iran side
USERPORTS="2087 2082"      # backend ports on THIS server (127.0.0.1), space-separated (frontend=backend same port)
CH_USER="tun"
CH_PASS="CHANGE-ME-24CHARS"   # <-- same password as iran side
URL="https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz"
# Pin mirrored from orchestrator/binary_manager.py (single source of truth).
SHA256="0525aa3c5d457f2a4075e66221d5125d434bedf15006d3271c213f5cd6ff2230"
command -v /usr/local/bin/chisel >/dev/null 2>&1 || {
  cd /tmp; rm -f chisel.gz chisel
  for u in "$URL" "https://ghproxy.net/$URL" "https://mirror.ghproxy.com/$URL" "https://gh.ddlc.top/$URL"; do
    curl -fsSL --max-time 60 -o chisel.gz "$u" && break || sleep 2
  done
  # The pinned hash covers the compressed artifact, so verify before decompressing.
  echo "$SHA256  chisel.gz" | sha256sum -c - || { rm -f chisel.gz; echo "[SECURITY] chisel SHA-256 mismatch - refusing to install" >&2; exit 1; }
  gunzip -f chisel.gz
  cp -f /tmp/chisel /usr/local/bin/chisel; chmod +x /usr/local/bin/chisel
}
REMOTES=""
for p in $USERPORTS; do REMOTES="$REMOTES R:$p:127.0.0.1:$p"; done
# The credential must NOT appear on ExecStart: the command line is world-readable through
# /proc/<pid>/cmdline and is captured by journald. chisel falls back to the AUTH environment
# variable when --auth is absent, so the secret lives in a 0600 EnvironmentFile instead.
umask 077
mkdir -p /etc/chisel
cat > /etc/chisel/auth.env <<EOF
AUTH=$CH_USER:$CH_PASS
EOF
chmod 600 /etc/chisel/auth.env
# Fail closed rather than silently disabling verification. --tls-skip-verify lets anything that can
# intercept the transport pose as the Iran host, which defeats the point of tunnelling at all.
if [ ! -f "$IR_CERT" ]; then
  echo "[ERROR] Iran certificate not found at $IR_CERT" >&2
  echo "        copy it from the Iran host: scp root@<iran>:/etc/chisel/cert.pem $IR_CERT" >&2
  exit 1
fi
cat > /etc/systemd/system/chisel-client.service <<EOF
[Unit]
Description=Chisel Client (reverse forwards to Iran)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
EnvironmentFile=/etc/chisel/auth.env
ExecStart=/usr/local/bin/chisel client --tls-ca $IR_CERT --keepalive 25s https://$IR_IP:$TRANSPORT_PORT$REMOTES
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now chisel-client
sleep 8; systemctl is-active chisel-client
journalctl -u chisel-client --no-pager -n 4 2>&1 | tail -4
echo "=== FOREIGN REVERSE CLIENT OK: dials https://$IR_IP:$TRANSPORT_PORT, forwards:$REMOTES ==="
