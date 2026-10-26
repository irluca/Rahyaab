#!/bin/bash
# REVERSE MODE (FRP+TLS) - Iran side. Fastest TLS option in our test (~0.17s vs chisel ~0.27s).
# Model: frps here (TLS transport), foreign dials IN, user ports open HERE.
# Usage: sudo bash iran-reverse-frp-server.sh
set -e
TRANSPORT_PORT="7000"     # frp transport (must be reachable FOREIGN->IRAN)
USERMAP="8444=2087"       # space-separated LOCAL=REMOTE (Iran frontend=foreign backend port)
F_TOKEN="CHANGE-ME-32CHARS"   # <-- same token on both sides
URL="https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_linux_amd64.tar.gz"
# Pin mirrored from orchestrator/binary_manager.py (single source of truth). The proxy mirrors
# below are not trusted, so the hash is what makes them usable: any mismatch aborts the install.
SHA256="84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716"
command -v /usr/local/bin/frps >/dev/null 2>&1 || {
  cd /tmp; rm -rf frp.tgz frp_0.71.0_linux_amd64
  for u in "$URL" "https://ghproxy.net/$URL" "https://mirror.ghproxy.com/$URL" "https://gh.ddlc.top/$URL"; do
    curl -fsSL --max-time 120 -o frp.tgz "$u" && break || sleep 2
  done
  echo "$SHA256  frp.tgz" | sha256sum -c - || { rm -f frp.tgz; echo "[SECURITY] frp SHA-256 mismatch - refusing to install" >&2; exit 1; }
  tar xzf frp.tgz; cp -f frp_0.71.0_linux_amd64/frps /usr/local/bin/frps; chmod +x /usr/local/bin/frps
}
mkdir -p /etc/frp
[ -f /etc/frp/frp-cert.pem ] || openssl req -x509 -newkey rsa:2048 -keyout /etc/frp/frp-key.pem -out /etc/frp/frp-cert.pem -days 3650 -nodes -subj "/CN=$(hostname -I | awk '{print $1}')" -addext "subjectAltName=IP:$(hostname -I | awk '{print $1}')"
chmod 600 /etc/frp/frp-key.pem 2>/dev/null || true
umask 077   # the config below carries a tunnel credential
cat > /etc/frp/frps.toml <<EOF
bindPort = $TRANSPORT_PORT
auth.method = "token"
auth.token = "$F_TOKEN"
transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 15
transport.tls.force = true
transport.tls.certFile = "/etc/frp/frp-cert.pem"
transport.tls.keyFile = "/etc/frp/frp-key.pem"
EOF
chmod 600 /etc/frp/frps.toml
cat > /etc/systemd/system/frps.service <<'EOF'
[Unit]
Description=FRP Server TLS (reverse transport)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/frps -c /etc/frp/frps.toml
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now frps
sleep 3; systemctl is-active frps
echo "=== IRAN FRP SERVER OK: TLS transport $TRANSPORT_PORT, maps: $USERMAP ==="
echo "!!! Copy /etc/frp/frp-cert.pem to the foreign server as /etc/frp/ca.pem !!!"
