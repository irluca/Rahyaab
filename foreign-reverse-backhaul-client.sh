#!/bin/bash
# REVERSE MODE (Backhaul wss) - Foreign side. Dials OUT to Iran server.
# Usage: sudo bash foreign-reverse-backhaul-client.sh
set -e
IR_IP="198.51.100.10"      # Iran public IP (must equal PUB_IP on the Iran host)
IR_CERT="/etc/backhaul/iran-cert.pem"   # the Iran host's /etc/backhaul/cert.pem, copied over
TRANSPORT_PORT="3080"     # same as iran side
BH_TOKEN="CHANGE-ME-32CHARS"  # <-- same token as iran side
URL="https://github.com/musixal/backhaul/releases/download/v0.7.2/backhaul_linux_amd64.tar.gz"
# Pin mirrored from orchestrator/binary_manager.py (single source of truth).
SHA256="57bf95c2eabeddb1152d2e94ac42f4310883ce0fb909ee2a57bd53503b2dabbc"
command -v /usr/local/bin/backhaul >/dev/null 2>&1 || {
  cd /tmp; rm -f backhaul.tgz
  for u in "$URL" "https://ghproxy.net/$URL" "https://mirror.ghproxy.com/$URL" "https://gh.ddlc.top/$URL"; do
    curl -fsSL --max-time 90 -o backhaul.tgz "$u" && break || sleep 2
  done
  echo "$SHA256  backhaul.tgz" | sha256sum -c - || { rm -f backhaul.tgz; echo "[SECURITY] backhaul SHA-256 mismatch - refusing to install" >&2; exit 1; }
  tar xzf backhaul.tgz; cp -f backhaul /usr/local/bin/backhaul; chmod +x /usr/local/bin/backhaul
}
mkdir -p /etc/backhaul
# Fail closed rather than dial a wss endpoint with no trust anchor. Without tls_cert the client
# has nothing to verify the server against, which lets anything that can intercept FOREIGN->IRAN
# pose as the Iran host and read the tunneled traffic. Field name mirrors the orchestrator's
# backhaul adapter (protocols.py:249); confirm backhaul accepts it on the first live run with
# scratch/check_backhaul_opts.py before trusting the tunnel.
if [ ! -f "$IR_CERT" ]; then
  echo "[ERROR] Iran certificate not found at $IR_CERT" >&2
  echo "        copy it from the Iran host: scp root@<iran>:/etc/backhaul/cert.pem $IR_CERT" >&2
  exit 1
fi
umask 077   # the config below carries a tunnel credential
cat > /etc/backhaul/client.toml <<EOF
[client]
remote_addr = "$IR_IP:$TRANSPORT_PORT"
transport = "wss"
token = "$BH_TOKEN"
tls_cert = "$IR_CERT"
keepalive_period = 75
nodelay = true
heartbeat = 40
retry_interval = 3
EOF
chmod 600 /etc/backhaul/client.toml
cat > /etc/systemd/system/backhaul-client.service <<'EOF'
[Unit]
Description=Backhaul Client wss
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/backhaul -c /etc/backhaul/client.toml
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now backhaul-client
sleep 10; systemctl is-active backhaul-client
journalctl -u backhaul-client --no-pager -n 4 2>&1 | tail -4
echo "=== FOREIGN BACKHAUL CLIENT OK: dials wss://$IR_IP:$TRANSPORT_PORT ==="
