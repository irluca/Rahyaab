#!/bin/bash
# REVERSE MODE (Rathole + Noise/Stealth) - Iran side.
# Noise transport = random-looking bytes, no fingerprint (like BackPack Stealth).
# NOTE: plain TCP transport STALLS on hard paths - always use noise here.
# Model: rathole SERVER here (transport), foreign dials IN, user ports open HERE.
# Usage: sudo bash iran-reverse-rathole-server.sh
set -e
TRANSPORT_PORT="2443"     # rathole transport (must be reachable FOREIGN->IRAN)
USERPORTS="2089"          # user frontend ports on THIS server (space-separated; use free ports, NOT xray ports)
R_TOKEN="CHANGE-ME-32CHARS"   # <-- same token on both sides
NOISE_PRIV="CHANGE-ME-SERVER-PRIVATE-KEY"  # <-- from: rathole --genkey (run once, keep!)
URL="https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-gnu.zip"
# Pin mirrored from orchestrator/binary_manager.py (single source of truth). The proxy mirrors
# below are not trusted, so the hash is what makes them usable: any mismatch aborts the install.
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
echo '[server]'
echo "bind_addr = \"0.0.0.0:$TRANSPORT_PORT\""
echo ''
echo '[server.transport]'
echo 'type = "noise"'
echo ''
echo '[server.transport.noise]'
echo 'pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"'
echo "local_private_key = \"$NOISE_PRIV\""
echo ''
for p in $USERPORTS; do
echo "[server.services.t$p]"
echo "token = \"$R_TOKEN\""
echo "bind_addr = \"0.0.0.0:$p\""
echo ''
done
} > /etc/rathole/server.toml
chmod 600 /etc/rathole/server.toml
cat > /etc/systemd/system/rathole-server.service <<'EOF'
[Unit]
Description=Rathole Server (reverse transport)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/rathole /etc/rathole/server.toml
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now rathole-server
sleep 3; systemctl is-active rathole-server
echo "=== IRAN RATHOLE SERVER OK: transport $TRANSPORT_PORT, frontends: $USERPORTS ==="
ss -tlnp 2>/dev/null | grep -E ":($TRANSPORT_PORT|$(echo $USERPORTS | tr ' ' '|')) " | head -5
