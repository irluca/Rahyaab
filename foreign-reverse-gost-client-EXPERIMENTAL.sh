#!/bin/bash
# EXPERIMENTAL - GOST client (pairs with iran-reverse-gost-server-EXPERIMENTAL.sh)
# LIVE TEST 2026-10-24: this client started but its reverse tunnel to the Iran
# server never established (three structured attempts, incl. CA:TRUE cert and
# an explicit chain reference in the service). See the server script's header
# for the full verdict. Stays EXPERIMENTAL.
# PREREQ: copy Iran's /etc/gost/cert.pem here as /etc/gost/iran-cert.pem first!
# The dialer pins that certificate (caFile + secure below), so a peer that cannot
# present it is refused - verification is never skipped (F4).
# Usage: sudo bash foreign-reverse-gost-client-EXPERIMENTAL.sh
set -e
IR_IP="198.51.100.10"
IR_CERT="/etc/gost/iran-cert.pem"   # the Iran host's /etc/gost/cert.pem, copied over
TRANSPORT_PORT="7443"
TUN_UUID="CHANGE-ME-UUID"     # <-- same as iran side
BACKEND="127.0.0.1:2087"      # local xray backend
SNI_RULE="app-measurement.com" # <-- same as iran side
URL="https://github.com/go-gost/gost/releases/download/v3.3.0/gost_3.3.0_linux_amd64.tar.gz"
# Pin mirrored from orchestrator/binary_manager.py (single source of truth).
SHA256="676fb7f78d267b6ae73df719c0c7f2b565dde7147da935cfafbc1e1da558b6d5"
command -v /usr/local/bin/gost >/dev/null 2>&1 || {
  cd /tmp; rm -f gost.tgz gost
  for u in "$URL" "https://ghproxy.net/$URL" "https://mirror.ghproxy.com/$URL" "https://gh.ddlc.top/$URL"; do
    curl -fsSL --max-time 120 -o gost.tgz "$u" && break || sleep 2
  done
  echo "$SHA256  gost.tgz" | sha256sum -c - || { rm -f gost.tgz; echo "[SECURITY] gost SHA-256 mismatch - refusing to install" >&2; exit 1; }
  tar xzf gost.tgz
  cp -f gost /usr/local/bin/gost; chmod +x /usr/local/bin/gost
}
mkdir -p /etc/gost
if [ ! -f "$IR_CERT" ]; then
  echo "[ERROR] $IR_CERT not found; copy the Iran host's /etc/gost/cert.pem here first (see header)" >&2
  exit 1
fi
umask 077   # the config below carries a tunnel credential
cat > /etc/gost/client.yml <<EOF
services:
- name: service-0
  addr: :0
  handler:
    type: rtcp
  listener:
    type: rtcp
  forwarder:
    nodes:
    - name: backend
      addr: $BACKEND
      matcher:
        rule: Host(\`$SNI_RULE\`)
chains:
- name: chain-0
  hops:
  - name: hop-0
    nodes:
    - name: node-0
      addr: $IR_IP:$TRANSPORT_PORT
      connector:
        type: tunnel
        metadata:
          tunnel.id: $TUN_UUID
      dialer:
        type: tls
        tls:
          caFile: $IR_CERT
          secure: true
EOF
chmod 600 /etc/gost/client.yml
cat > /etc/systemd/system/gost-client.service <<'EOF'
[Unit]
Description=GOST tunnel client
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/gost -C /etc/gost/client.yml
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now gost-client
sleep 8; systemctl is-active gost-client
journalctl -u gost-client --no-pager -n 5 2>&1 | tail -5
echo "=== FOREIGN GOST CLIENT OK ==="
