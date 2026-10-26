#!/bin/bash
# REVERSE MODE (Rathole + Noise/Stealth) - Foreign side. Dials OUT to Iran server.
# NOTE: plain TCP transport STALLS on hard paths - always use noise here.
# Usage: sudo bash foreign-reverse-rathole-client.sh
set -e
IR_IP="198.51.100.10"      # Iran public IP
TRANSPORT_PORT="2443"     # same as iran side
# "frontend-port:backend-port" pairs: Iran frontend -> this server backend (127.0.0.1)
MAPS="2089:2087"          # space-separated FRONTEND:BACKEND, e.g. "2089:2087 2082:2082"
R_TOKEN="CHANGE-ME-32CHARS"   # <-- same token as iran side
NOISE_PUB="CHANGE-ME-SERVER-PUBLIC-KEY"  # <-- server pubkey from iran side genkey
URL="https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-gnu.zip"
# Pin mirrored from orchestrator/binary_manager.py (single source of truth).
SHA256="3e7d0d0f365120cd3cd351d147d1a12ee960c8068b464d4dd533a3821873b80e"
command -v /usr/local/bin/rathole >/dev/null 2>&1 || {
  cd /tmp; rm -f rathole.zip rathole
  for u in "$URL" "https://ghproxy.net/$URL" "https://mirror.ghproxy.com/$URL" "https://gh.ddlc.top/$URL"; do
    curl -fsSL --max-time 90 -o rathole.zip "$u" && break || sleep 2
  done
  echo "$SHA256  rathole.zip" | sha256sum -c - || { rm -f rathole.zip; echo "[SECURITY] rathole SHA-256 mismatch - refusing to install" >&2; exit 1; }
  (unzip -o -q rathole.zip 2>/dev/null || python3 -c "import zipfile; zipfile.ZipFile('/tmp/rathole.zip').extract('rathole','/tmp/')")
  cp -f /tmp/rathole /usr/local/bin/rathole; chmod +x /usr/local/bin/rathole
}
mkdir -p /etc/rathole
umask 077   # the config below carries a tunnel credential
{
echo '[client]'
echo "remote_addr = \"$IR_IP:$TRANSPORT_PORT\""
echo ''
echo '[client.transport]'
echo 'type = "noise"'
echo ''
echo '[client.transport.noise]'
echo 'pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"'
echo "remote_public_key = \"$NOISE_PUB\""
echo ''
for m in $MAPS; do
  f="${m%%:*}"; b="${m##*:}"
echo "[client.services.t$f]"
echo "token = \"$R_TOKEN\""
echo "local_addr = \"127.0.0.1:$b\""
echo ''
done
} > /etc/rathole/client.toml
chmod 600 /etc/rathole/client.toml
cat > /etc/systemd/system/rathole-client.service <<'EOF'
[Unit]
Description=Rathole Client (forward to Iran)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/rathole /etc/rathole/client.toml
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now rathole-client
sleep 8; systemctl is-active rathole-client
journalctl -u rathole-client --no-pager -n 4 2>&1 | tail -4
echo "=== FOREIGN RATHOLE CLIENT OK: dials $IR_IP:$TRANSPORT_PORT, maps: $MAPS ==="
