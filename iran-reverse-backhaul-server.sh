#!/bin/bash
# REVERSE MODE (Backhaul wss) - Iran side. Lower overhead than chisel (~0.10s vs ~0.19s in our test).
# Model: backhaul SERVER here (wss transport), foreign dials IN, user ports open HERE.
# Usage: sudo bash iran-reverse-backhaul-server.sh
set -e
TRANSPORT_PORT="3080"     # backhaul wss transport (must be reachable FOREIGN->IRAN)
USERMAP="8443=2087"       # space-separated LOCAL=REMOTE (Iran frontend=foreign backend port)
BH_TOKEN="CHANGE-ME-32CHARS"  # <-- same token on both sides
# Public address this host is reached on. It MUST equal IR_IP in foreign-reverse-backhaul-client.sh:
# the certificate below is issued for it and the client verifies it, so a mismatch aborts the
# handshake instead of silently degrading. Auto-detection is unreliable behind NAT.
PUB_IP="${PUB_IP:-$(hostname -I | awk '{print $1}')}"
URL="https://github.com/musixal/backhaul/releases/download/v0.7.2/backhaul_linux_amd64.tar.gz"
# Pin mirrored from orchestrator/binary_manager.py (single source of truth). The proxy mirrors
# below are not trusted, so the hash is what makes them usable: any mismatch aborts the install.
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
# Go rejects certificates that carry only a Common Name, so the address must appear as a
# subjectAltName or the client cannot verify the server. This also moves the material out of
# /etc/chisel, which was a copy-paste leftover: backhaul was sharing a certificate file with the
# chisel installer, so whichever ran first silently fixed the other's TLS identity.
if ! printf '%s' "$PUB_IP" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
  echo "[ERROR] PUB_IP='$PUB_IP' is not an IPv4 address; export PUB_IP=<public ip> and rerun" >&2
  exit 1
fi
[ -f /etc/backhaul/cert.pem ] || openssl req -x509 -newkey rsa:2048 -keyout /etc/backhaul/key.pem -out /etc/backhaul/cert.pem -days 3650 -nodes -subj "/CN=$PUB_IP" -addext "subjectAltName=IP:$PUB_IP"
chmod 600 /etc/backhaul/key.pem
chmod 644 /etc/backhaul/cert.pem
PORTS=$(for m in $USERMAP; do printf '"%s",' "$m"; done | sed 's/,$//')
umask 077   # the config below carries a tunnel credential
cat > /etc/backhaul/server.toml <<EOF
[server]
bind_addr = "0.0.0.0:$TRANSPORT_PORT"
transport = "wss"
token = "$BH_TOKEN"
keepalive_period = 75
nodelay = true
heartbeat = 40
channel_size = 2048
tls_cert = "/etc/backhaul/cert.pem"
tls_key = "/etc/backhaul/key.pem"
ports = [$PORTS]
log_level = "info"
EOF
chmod 600 /etc/backhaul/server.toml
echo "[INFO] copy this certificate to the foreign host, then run foreign-reverse-backhaul-client.sh there:"
echo "       scp /etc/backhaul/cert.pem root@<foreign>:/etc/backhaul/iran-cert.pem"
cat > /etc/systemd/system/backhaul-server.service <<'EOF'
[Unit]
Description=Backhaul Server wss (reverse transport)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/backhaul -c /etc/backhaul/server.toml
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now backhaul-server
sleep 3; systemctl is-active backhaul-server
echo "=== IRAN BACKHAUL SERVER OK: wss transport $TRANSPORT_PORT, maps: $USERMAP ==="
