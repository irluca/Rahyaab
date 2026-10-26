#!/bin/bash
# GRE Tunnel - Kharej side (FINAL - parameterized + persistent)
# Usage: sudo bash kharej-gre.sh
# Addresses come from the environment; the defaults below are RFC 5737 documentation space, which
# is unreachable on purpose so an unconfigured run fails visibly instead of pointing a production
# tunnel at a third party's host. Export the four vars (or edit them) before running on real
# servers - a committed real address is how this file used to leak one into every clone.
set -e
IR_PUB="${IR_PUB:-198.51.100.10}"   # public IP of peer (iran)
KH_PUB="${KH_PUB:-203.0.113.20}"    # public IP of THIS server (kharej)
KH_TUN="${KH_TUN:-10.10.10.2}"      # tunnel IP of THIS side
IR_TUN="${IR_TUN:-10.10.10.1}"      # tunnel IP of peer
for _v in IR_PUB KH_PUB IR_TUN KH_TUN; do
  if ! printf '%s' "${!_v}" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    echo "[ERROR] $_v='${!_v}' is not an IPv4 address; export it and rerun" >&2
    exit 1
  fi
done
modprobe ip_gre || true
grep -q ip_gre /etc/modules-load.d/gre.conf 2>/dev/null || echo ip_gre > /etc/modules-load.d/gre.conf
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=0\nnet.ipv4.conf.default.rp_filter=0\n' > /etc/sysctl.d/99-gre.conf
ip tunnel del gre1 2>/dev/null || true
ip tunnel add gre1 mode gre remote $IR_PUB local $KH_PUB ttl 255
ip addr add $KH_TUN/30 dev gre1 2>/dev/null || true
ip link set gre1 up mtu 1376
sysctl -w net.ipv4.conf.gre1.rp_filter=0 || true
iptables -C FORWARD -i gre1 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i gre1 -j ACCEPT
iptables -C FORWARD -o gre1 -j ACCEPT 2>/dev/null || iptables -I FORWARD 2 -o gre1 -j ACCEPT
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
# --- persistence ---
cp "$0" /usr/local/bin/gre-setup.sh; chmod +x /usr/local/bin/gre-setup.sh
cat > /usr/local/bin/gre-watchdog.sh <<EOF
#!/bin/bash
PEER="$IR_TUN"
LOG="/var/log/gre-watchdog.log"
if ! ping -c3 -W3 \$PEER >/dev/null 2>&1; then
  echo "\$(date) GRE down, restarting" >> \$LOG
  ip link set gre1 down 2>/dev/null || true
  ip link set gre1 up mtu 1376 2>/dev/null || /usr/local/bin/gre-setup.sh >> \$LOG 2>&1
  sleep 3
  ping -c2 -W3 \$PEER >/dev/null 2>&1 && echo "\$(date) GRE recovered" >> \$LOG || /usr/local/bin/gre-setup.sh >> \$LOG 2>&1 || true
fi
EOF
chmod +x /usr/local/bin/gre-watchdog.sh
cat > /etc/systemd/system/gre-tunnel.service <<'UNIT'
[Unit]
Description=GRE Tunnel Persistent
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/gre-setup.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/gre-watchdog.service <<'UNIT'
[Unit]
Description=GRE Watchdog
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/gre-watchdog.sh
UNIT
cat > /etc/systemd/system/gre-watchdog.timer <<'UNIT'
[Unit]
Description=Run GRE watchdog every 2 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
Unit=gre-watchdog.service
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now gre-tunnel.service >/dev/null 2>&1 || true
systemctl enable --now gre-watchdog.timer >/dev/null 2>&1 || true
# --- fou ready (fallback carrier for paths where proto47 is blocked; NOT active) ---
modprobe fou 2>/dev/null || true
grep -q '^fou$' /etc/modules-load.d/fou.conf 2>/dev/null || echo fou >> /etc/modules-load.d/fou.conf
ip fou add port 55555 ipproto 47 2>/dev/null || true
# --- BBR + buffers ---
modprobe tcp_bbr 2>/dev/null || true
sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.tcp_max_syn_backlog=8192 >/dev/null 2>&1 || true
sysctl -w net.core.rmem_max=33554432 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_max=33554432 >/dev/null 2>&1 || true
printf 'net.ipv4.tcp_congestion_control=bbr\nnet.core.default_qdisc=fq\nnet.ipv4.tcp_syncookies=1\nnet.ipv4.tcp_max_syn_backlog=8192\nnet.core.rmem_max=33554432\nnet.core.wmem_max=33554432\nnet.ipv4.tcp_rmem=4096 87380 16777216\nnet.ipv4.tcp_wmem=4096 65536 16777216\n' > /etc/sysctl.d/99-tunnel-perf.conf
echo "=== KHAREJ GRE OK ==="
ip addr show gre1 | head -8
ping -c2 -W3 $IR_TUN | tail -3
ss -tlnp | grep -E '443|8443' | head -5
