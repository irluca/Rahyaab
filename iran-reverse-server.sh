#!/bin/bash
# REVERSE MODE - Iran side (for foreign servers that CANNOT reach Iran directly)
# Model: chisel SERVER listens here (transport), foreign dials IN, user ports open HERE.
# Usage: sudo bash iran-reverse-server.sh
# Only edit vars below.
set -e
TRANSPORT_PORT="2096"     # chisel transport (must be reachable NEW->IR; NOT 22, NOT xray ports)
USERPORTS="2087"          # user ports to expose on THIS server (space-separated)
CH_USER="tun"
CH_PASS="CHANGE-ME-24CHARS"   # <-- set a strong password, same on both sides
# Public address this host is reached on. It MUST equal IR_IP in foreign-reverse-client.sh: the
# TLS certificate below is issued for this address and the client verifies it, so a mismatch fails
# the handshake instead of quietly degrading. Auto-detection is unreliable behind NAT, hence the
# PUB_IP override and the explicit format check.
PUB_IP="${PUB_IP:-$(curl -s --max-time 10 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')}"
URL="https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz"
# Pin mirrored from orchestrator/binary_manager.py (single source of truth). The proxy mirrors
# below are not trusted, so the hash is what makes them usable: any mismatch aborts the install.
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
mkdir -p /etc/chisel
# Go's x509 verifier (chisel is a Go binary) rejects certificates that carry only a Common Name, so
# the address has to be present as a subjectAltName or --tls-ca on the client cannot ever succeed.
# The previous version emitted a CN-only cert, which is why the client was shipped with
# --tls-skip-verify: verification had been disabled instead of the certificate being fixed.
if ! printf '%s' "$PUB_IP" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
  echo "[ERROR] PUB_IP='$PUB_IP' is not an IPv4 address; export PUB_IP=<public ip> and rerun" >&2
  exit 1
fi
[ -f /etc/chisel/cert.pem ] || openssl req -x509 -newkey rsa:2048 -keyout /etc/chisel/key.pem -out /etc/chisel/cert.pem -days 3650 -nodes -subj "/CN=$PUB_IP" -addext "subjectAltName=IP:$PUB_IP"
chmod 600 /etc/chisel/key.pem
chmod 644 /etc/chisel/cert.pem
echo "[INFO] copy this certificate to the foreign host and verify the client can reach $PUB_IP:$TRANSPORT_PORT:"
echo "       scp /etc/chisel/cert.pem root@<foreign>:/etc/chisel/iran-cert.pem"
# The credential must NOT appear on ExecStart. Anything on the command line is world-readable via
# /proc/<pid>/cmdline for as long as the service runs, and it also lands in journald. chisel reads
# its user table from --authfile instead, so the secret stays in a 0600 root-owned file.
case "$CH_PASS" in
  *'"'*|*'\'*) echo "[ERROR] CH_PASS must not contain a double quote or backslash (it is embedded in JSON)" >&2; exit 1 ;;
esac
umask 077
# chisel reads this file as {"<user:pass>": ["<remote-addr-regex>", ...]}; [""] is its documented
# equivalent of a full-access --auth entry. The users-keyed array of username/password objects
# written here before was rejected by chisel 1.10.1 itself - the server exits 1 on "Invalid JSON",
# so the transport never comes up and every downstream check fails. Shape confirmed on the binary.
cat > /etc/chisel/authfile <<EOF
{"$CH_USER:$CH_PASS":[""]}
EOF
chmod 600 /etc/chisel/authfile
cat > /etc/systemd/system/chisel-server.service <<EOF
[Unit]
Description=Chisel Server (reverse tunnel transport)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/chisel server --port $TRANSPORT_PORT --reverse --authfile /etc/chisel/authfile --tls-cert /etc/chisel/cert.pem --tls-key /etc/chisel/key.pem
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now chisel-server
sleep 2; systemctl is-active chisel-server
echo "=== IRAN REVERSE SERVER OK: transport port $TRANSPORT_PORT (wss), user ports will open here: $USERPORTS ==="
ss -tlnp 2>/dev/null | grep ":$TRANSPORT_PORT " | head -2
