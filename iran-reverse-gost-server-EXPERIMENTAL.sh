#!/bin/bash
# EXPERIMENTAL - GOST Reverse Proxy Tunnel (SNI-routed, NOT a transparent pipe!)
# LIVE TEST 2026-10-24 (Iran/Turkey test pair, tunnel run over the GRE carrier
# because inbound TCP to Iran is dropped there): pinned install OK, this server
# starts and listens (entrypoint + tunnel), SAN certificate generation OK - but
# the client's reverse tunnel never established (no socket to :7443) and the
# end-to-end fetch died at the entrypoint handshake. Root cause not isolated.
# Verdict: stays EXPERIMENTAL; not a product protocol. Do not rely on this pair
# of scripts for a working tunnel - prefer the product's own protocols.
# Only use if you understand GOST ingress/hostname routing. For normal VPN use,
# prefer chisel/frp/backhaul scripts (transparent byte pipes).
# Model: tunnel server here (TLS :7443), entrypoint :2086 routes by TLS SNI to client.
# Usage: sudo bash iran-reverse-gost-server.sh
set -e
TRANSPORT_PORT="7443"
ENTRY_PORT="2086"
# This host's public address (override with PUB_IP=...). The serving certificate below is
# issued for it and the client pins that certificate, so a mismatch aborts the tunnel -
# the same arrangement as the backhaul and chisel installers.
PUB_IP="${PUB_IP:-$(hostname -I | awk '{print $1}')}"
TUN_UUID="CHANGE-ME-UUID"     # <-- generate: cat /proc/sys/kernel/random/uuid
SNI_RULE="app-measurement.com" # <-- MUST equal the Reality SNI clients send!
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
# Go rejects certificates that carry only a Common Name, so the address must appear as a
# subjectAltName - a CN-only certificate cannot be verified at all, which is how clients
# end up shipped with verification disabled instead of the certificate being fixed (F4).
if ! printf '%s' "$PUB_IP" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
  echo "[ERROR] PUB_IP='$PUB_IP' is not an IPv4 address; export PUB_IP=<public ip> and rerun" >&2
  exit 1
fi
[ -f /etc/gost/cert.pem ] || openssl req -x509 -newkey rsa:2048 -keyout /etc/gost/key.pem -out /etc/gost/cert.pem -days 3650 -nodes -subj "/CN=$PUB_IP" -addext "subjectAltName=IP:$PUB_IP"
chmod 644 /etc/gost/cert.pem
chmod 600 /etc/gost/key.pem
umask 077   # the config below carries a tunnel credential
cat > /etc/gost/server.yml <<EOF
services:
- name: service-0
  addr: :$TRANSPORT_PORT
  handler:
    type: tunnel
    metadata:
      entrypoint: ":$ENTRY_PORT"
      ingress: ingress-0
  listener:
    type: tls
    tls:
      certFile: "/etc/gost/cert.pem"
      keyFile: "/etc/gost/key.pem"
ingresses:
- name: ingress-0
  rules:
  - hostname: "$SNI_RULE"
    endpoint: $TUN_UUID
EOF
chmod 600 /etc/gost/server.yml
cat > /etc/systemd/system/gost-server.service <<'EOF'
[Unit]
Description=GOST tunnel server
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/gost -C /etc/gost/server.yml
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now gost-server
sleep 4; systemctl is-active gost-server
echo "[INFO] copy this certificate to the foreign host, then run foreign-reverse-gost-client-EXPERIMENTAL.sh there:"
echo "       scp /etc/gost/cert.pem root@<foreign>:/etc/gost/iran-cert.pem"
echo "=== IRAN GOST SERVER OK: tunnel :$TRANSPORT_PORT entrypoint :$ENTRY_PORT SNI=$SNI_RULE ==="
