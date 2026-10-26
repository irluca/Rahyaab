#!/bin/bash
# REVERSE MODE (FRP+TLS) - Foreign side. Dials OUT to Iran server.
# PREREQ: copy Iran's /etc/frp/frp-cert.pem here as /etc/frp/ca.pem first!
# Usage: sudo bash foreign-reverse-frp-client.sh
set -e
IR_IP="198.51.100.10"      # Iran public IP
TRANSPORT_PORT="7000"     # same as iran side
USERMAP="8444=2087"       # space-separated FRONTEND:BACKEND (Iran frontend=here backend 127.0.0.1)
F_TOKEN="CHANGE-ME-32CHARS"   # <-- same token as iran side
URL="https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_linux_amd64.tar.gz"
# Pin mirrored from orchestrator/binary_manager.py (single source of truth).
SHA256="84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716"
command -v /usr/local/bin/frpc >/dev/null 2>&1 || {
  cd /tmp; rm -rf frp.tgz frp_0.71.0_linux_amd64
  for u in "$URL" "https://ghproxy.net/$URL" "https://mirror.ghproxy.com/$URL" "https://gh.ddlc.top/$URL"; do
    curl -fsSL --max-time 120 -o frp.tgz "$u" && break || sleep 2
  done
  echo "$SHA256  frp.tgz" | sha256sum -c - || { rm -f frp.tgz; echo "[SECURITY] frp SHA-256 mismatch - refusing to install" >&2; exit 1; }
  tar xzf frp.tgz; cp -f frp_0.71.0_linux_amd64/frpc /usr/local/bin/frpc; chmod +x /usr/local/bin/frpc
}
mkdir -p /etc/frp
[ -f /etc/frp/ca.pem ] || { echo "!!! Missing /etc/frp/ca.pem - copy Iran /etc/frp/frp-cert.pem here first !!!"; exit 1; }
umask 077   # the config below carries a tunnel credential
{
echo "serverAddr = \"$IR_IP\""
echo "serverPort = $TRANSPORT_PORT"
echo 'auth.method = "token"'
echo "auth.token = \"$F_TOKEN\""
echo 'transport.tcpMux = true'
echo 'transport.tls.enable = true'
echo 'transport.tls.disableCustomTLSFirstByte = true'
echo 'transport.tls.trustedCaFile = "/etc/frp/ca.pem"'
echo ''
i=0
for m in $USERMAP; do
  f="${m%%:*}"; b="${m##*:}"; i=$((i+1))
echo "[[proxies]]"
echo "name = \"t$f\""
echo 'type = "tcp"'
echo 'localIP = "127.0.0.1"'
echo "localPort = $b"
echo "remotePort = $f"
echo ''
done
} > /etc/frp/frpc.toml
chmod 600 /etc/frp/frpc.toml
cat > /etc/systemd/system/frpc.service <<'EOF'
[Unit]
Description=FRP Client TLS
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/frpc -c /etc/frp/frpc.toml
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now frpc
sleep 10; systemctl is-active frpc
journalctl -u frpc --no-pager -n 4 2>&1 | tail -4
echo "=== FOREIGN FRP CLIENT OK: dials $IR_IP:$TRANSPORT_PORT, maps: $USERMAP ==="
