#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
#  Rahyaab — tunnel dashboard installer for your servers
#
#  Run on the server itself (as root):
#      bash <(curl -fsSL https://raw.githubusercontent.com/irluca/Rahyaab/main/install.sh)
#  or from a local file:
#      bash install.sh
#
#  Ideas borrowed from the BackPack and Kariz installers (interactive
#  menu, one-line install, no Docker) — but the code, engine, and
#  dashboard are entirely Rahyaab's own.
#
#  This script only prepares the host: dependencies, Rahyaab code,
#  hub/node, BBR, firewall, and the panel certificate — plus the hub
#  key: when the hub is installed and no key exists, one is generated
#  on this very server, and with --push-key it can be installed on a
#  node using that node's one-time root password (the password is
#  never stored). Creating the operator account, adding servers,
#  benchmarking, and configuring the healer all happen after install,
#  inside the dashboard itself (like the Nexora setup wizard) — the
#  script creates no passwords or accounts and fakes nothing.
#
#  Permanent red line: this script never accesses or changes any
#  PasarGuard panel, its configs, or its users, and it never touches
#  running tunnels or the healer. Re-running is safe: the code is
#  refreshed, but the hub database and existing certificates are
#  never touched.
#
#  Certificates and IPs — honestly: Let's Encrypt does not issue
#  certificates for a bare IP (domains only). So there are two
#  separate paths:
#    • Domain → a real Let's Encrypt certificate + auto-renewal (certbot)
#    • IP     → a self-signed certificate with an IP SAN + an
#      auto-renewal timer that rebuilds it before expiry and
#      restarts the hub. The browser warns the first time; the
#      certificate fingerprint is printed in the final summary so
#      you can compare it with what the browser shows.
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="1.5.1"
# Default repository; override with --repo or --local.
REPO="${RAHYAAB_REPO:-irluca/Rahyaab}"
BRANCH="${RAHYAAB_BRANCH:-main}"
INSTALL_DIR="/opt/rahyaab"
DATA_DIR="/var/lib/rahyaab"
CONF_DIR="/etc/rahyaab"
HUB_PORT="8890"
HUB_DB="$DATA_DIR/hub.db"
UNIT="rahyaab-hub"

ROLE=""
DOMAIN=""
EMAIL=""
CERT_PATH=""
KEY_PATH=""
HUB_KEY="$CONF_DIR/hub_key"
HUB_PUB="$CONF_DIR/hub_key.pub"
LOCAL_SRC=""
NODE_HOST=""
REMOTE_NODE=""
FULL_SETUP_NODE=""
JOIN_HOST=""
JOIN_TOKEN=""
JOIN_FP=""
PRINT_JOIN=0
IRAN_HOST=""
PAIR_NAME="جفت اصلی"
PROTOCOL="GRE"
NODE_USER="root"
NODE_PORT="22"
BBR=0
IP_CERT=0
YES=0
FORCE=0
CHECK_ONLY=0

# ── Colors and messages ──────────────────────────────────────────────────
if [ -t 1 ]; then
    C_CYAN='\033[1;36m'; C_GREEN='\033[1;32m'; C_YELLOW='\033[1;33m'
    C_RED='\033[1;31m'; C_DIM='\033[2m'; C_RESET='\033[0m'
else
    C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_DIM=''; C_RESET=''
fi

info()  { echo -e "${C_CYAN}[*]${C_RESET} $*"; }
ok()    { echo -e "${C_GREEN}[✓]${C_RESET} $*"; }
warn()  { echo -e "${C_YELLOW}[!]${C_RESET} $*"; }
die()   { echo -e "${C_RED}[✗]${C_RESET} $*" >&2; exit 1; }
step()  { echo; echo -e "${C_CYAN}── $* ──${C_RESET}"; }

banner() {
    echo -e "${C_CYAN}"
    echo '█████    ██   ██  ██ ██  ██   ██     ██   █████'
    echo '██  ██  ██ ██ ██  ██ ██  ██  ██ ██  ██ ██ ██  ██'
    echo '█████  ██████ ██████   ██   ██████ ██████ █████'
    echo '██ ██  ██  ██ ██  ██   ██   ██  ██ ██  ██ ██  ██'
    echo '██  ██ ██  ██ ██  ██   ██   ██  ██ ██  ██ █████'
    echo -e "${C_RESET}"
    echo "Rahyaab v$VERSION — tunnel dashboard between your servers"
    echo -e "${C_DIM}──────────────────────────────────────────────────────────────${C_RESET}"
}

confirm() {
    if [ "$YES" -eq 1 ]; then return 0; fi
    local ans
    read -r -p "Continue? [y/N] " ans
    case "$ans" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

ask() { # ask VAR PROMPT [DEFAULT]
    local var="$1" prompt="$2" def="${3:-}" val
    if [ -n "$def" ]; then
        read -r -p "$prompt [$def]: " val
        val="${val:-$def}"
    else
        read -r -p "$prompt: " val
    fi
    printf -v "$var" '%s' "$val"
}

public_ip() {
    local ip
    ip="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    if [ -z "$ip" ]; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    fi
    echo "${ip:-unknown}"
}

usage() {
    cat <<EOF
Usage:
  bash install.sh                     Interactive menu (Master setup, Node setup, Manage, Backup, Web Panel, Optimize, Update, Uninstall)
  bash install.sh --role master       Non-interactive master install (hub + master registration + join command)
  bash install.sh --role hub          Non-interactive hub install (no master registration)
  bash install.sh --role node         Non-interactive node install (no join)
  bash install.sh --join HOST TOKEN FINGERPRINT   Join a node to the master with the join command (paste one line from the master)
  bash install.sh --print-join        Show the node join command (on the master; generates a fresh single-use code)
  bash install.sh --role hub --bbr --domain panel.example.com --email you@example.com
  bash install.sh --role hub --bbr --ip-cert
  bash install.sh --local /path/to/rahyaab --role hub
  bash install.sh --push-key 203.0.113.20   Install the hub key on a node (the node root password is asked once and never stored)
  bash install.sh --remote-node 203.0.113.20   Install a node on another server from this hub server (with the hub key; requires push-key first)
  bash install.sh --full-setup 203.0.113.20 --bbr --ip-cert   Full setup: hub + node + pair + first tunnel + healer (the node root password is asked once)
  bash install.sh --check-only        Check prerequisites only, no changes

Hub key: when the hub is installed and no key exists, one is generated
on this server (/etc/rahyaab/hub_key) and an existing key is never
overwritten. The hub reaches nodes with this key; for first trust,
either copy the printed public key to the node by hand, or install
it with --push-key and the node's one-time root password. The
password is used for that one connection only and then discarded.

Options:
  --role hub|node|master   Role of this server (hub = dashboard, node = no dashboard,
                           master = hub + automatic master registration + print the node join command)
  --join HOST TOKEN FINGERPRINT   Join this node to the master (three parts of the join command)
  --print-join        Show the node join command (master only)
  --push-key HOST     Install the hub key on a node with its one-time root password
  --remote-node HOST  Install a node on another server from this hub server (requires push-key first)
  --full-setup HOST   Full setup of both servers (hub + node + pair + first tunnel + healer)
  --iran-host IP      Hub server IP for full-setup (default: auto-detected)
  --pair-name NAME    Pair name for full-setup (default: $PAIR_NAME)
  --protocol PROTO    First-tunnel protocol for full-setup (default: GRE)
  --node-user USER    Node user for push-key (default: root)
  --node-port PORT    Node SSH port for push-key (default: 22)
  --bbr               Enable BBR
  --domain DOMAIN     Let's Encrypt certificate for a domain
  --email EMAIL       certbot email (required with --domain)
  --ip-cert           Self-signed IP certificate + auto-renewal
  --cert FILE --key FILE   Your own ready certificate
  --local DIR         Install code from local files (instead of downloading)
  --repo OWNER/REPO   GitHub repository (default: $REPO)
  --branch BRANCH     Branch (default: $BRANCH)
  --yes               No confirmation prompts
  --force             Skip the OS check
  --check-only        Check only, no install
  --help              This help text
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --role)     ROLE="$2"; shift 2 ;;
            --join)     JOIN_HOST="$2"; JOIN_TOKEN="$3"; JOIN_FP="$4"; shift 4 ;;
            --print-join) PRINT_JOIN=1; shift ;;
            --push-key) NODE_HOST="$2"; shift 2 ;;
            --remote-node) REMOTE_NODE="$2"; shift 2 ;;
            --full-setup) FULL_SETUP_NODE="$2"; shift 2 ;;
            --iran-host) IRAN_HOST="$2"; shift 2 ;;
            --pair-name) PAIR_NAME="$2"; shift 2 ;;
            --protocol) PROTOCOL="$2"; shift 2 ;;
            --node-user) NODE_USER="$2"; shift 2 ;;
            --node-port) NODE_PORT="$2"; shift 2 ;;
            --domain)   DOMAIN="$2"; shift 2 ;;
            --email)    EMAIL="$2"; shift 2 ;;
            --cert)     CERT_PATH="$2"; shift 2 ;;
            --key)      KEY_PATH="$2"; shift 2 ;;
            --local)    LOCAL_SRC="$2"; shift 2 ;;
            --repo)     REPO="$2"; shift 2 ;;
            --branch)   BRANCH="$2"; shift 2 ;;
            --bbr)      BBR=1; shift ;;
            --ip-cert)  IP_CERT=1; shift ;;
            --yes)      YES=1; shift ;;
            --force)    FORCE=1; shift ;;
            --check-only) CHECK_ONLY=1; shift ;;
            --help)     usage; exit 0 ;;
            --version)  echo "rahyaab-installer $VERSION"; exit 0 ;;
            *)          die "Unknown option: $1 (see --help)" ;;
        esac
    done
    case "$ROLE" in ""|hub|node|master) ;; *) die "Invalid role: $ROLE (hub, node, or master)" ;; esac
    if [ -n "$DOMAIN" ] && [ -z "$EMAIL" ]; then
        die "--email is also required for a domain certificate"
    fi
    if { [ -n "$CERT_PATH" ] || [ -n "$KEY_PATH" ]; } && { [ -z "$CERT_PATH" ] || [ -z "$KEY_PATH" ]; }; then
        die "--cert and --key must be given together"
    fi
}

need_root() {
    [ "$(id -u)" -eq 0 ] || die "This script must run as root (sudo bash install.sh)"
}

detect_os() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        info "OS: ${NAME:-unknown} ${VERSION_ID:-}"
        case "${ID:-}" in
            debian|ubuntu) return 0 ;;
            *)
                if [ "$FORCE" -eq 1 ]; then
                    warn "OS is not Debian/Ubuntu; continuing with --force"
                    return 0
                fi
                die "Only Debian and Ubuntu are supported (use --force to skip this check)"
                ;;
        esac
    else
        die "/etc/os-release not found; cannot detect the OS"
    fi
}

check_only() {
    step "Checking prerequisites (no changes)"
    need_root
    detect_os
    echo "python3: $(python3 --version 2>/dev/null || echo 'not installed')"
    echo "openssl: $(openssl version 2>/dev/null || echo 'not installed')"
    echo "curl:    $(curl --version 2>/dev/null | head -1 || echo 'not installed')"
    echo "Public IP: $(public_ip)"
    echo "Hub installed: $(systemctl is-active "$UNIT" 2>/dev/null || echo 'no')"
    echo "BBR: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'unknown')"
    ok "Check complete; nothing was changed"
}

# ── Dependencies and code ─────────────────────────────────────────────
install_deps() { # $1 = hub|node
    step "Installing system dependencies"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    local pkgs="python3 curl openssl iproute2 iptables unzip tar ca-certificates"
    if [ "$1" = "hub" ]; then
        pkgs="$pkgs python3-paramiko"
    fi
    apt-get install -y -qq $pkgs
    ok "Dependencies installed"
}

fetch_code() {
    step "Fetching Rahyaab code"
    mkdir -p "$INSTALL_DIR"
    if [ -n "$LOCAL_SRC" ]; then
        [ -d "$LOCAL_SRC" ] || die "Local directory not found: $LOCAL_SRC"
        [ -f "$LOCAL_SRC/hub/main.py" ] || die "hub/main.py is not in the local directory; pass the repository root"
        (cd "$LOCAL_SRC" && tar --exclude=.git --exclude=__pycache__ --exclude='*.pyc' -cf - .) \
            | (cd "$INSTALL_DIR" && tar -xf -)
        ok "Code copied from local files"
    else
        local url="https://codeload.github.com/${REPO}/tar.gz/refs/heads/${BRANCH}"
        local auth_args=()
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            auth_args=(-H "Authorization: Bearer $GITHUB_TOKEN")
        fi
        info "Downloading from $url"
        if ! curl -fsSL "${auth_args[@]}" -o /tmp/rahyaab.tgz "$url"; then
            die "Download failed (GitHub returns 404 for a private repo without a token). Two options: (1) copy the code to the server with SCP and install with --local <dir>; (2) create a read-only token (fine-grained PAT, only this repo) and rerun with GITHUB_TOKEN=<token>. Do not store the token in a file or shell history."
        fi
        tar -xzf /tmp/rahyaab.tgz --strip-components=1 -C "$INSTALL_DIR"
        rm -f /tmp/rahyaab.tgz
        ok "Code downloaded and extracted"
    fi
    [ -f "$INSTALL_DIR/hub/main.py" ] || die "hub/main.py is not in the downloaded code"
    [ -d "$INSTALL_DIR/dashboard" ] || warn "dashboard directory is not in the code; the dashboard will not be served"
    mkdir -p "$DATA_DIR" "$CONF_DIR"
}

# ── Hub key ────────────────────────────────────────────────────
# The hub key is generated and kept on this very server; it is
# never pushed to GitHub and never held by Muse. The hub reaches
# nodes with this key (a server record in the dashboard without a
# key_path defaults to this path).
ensure_hub_key() {
    mkdir -p "$CONF_DIR"
    if [ -f "$HUB_KEY" ]; then
        # An existing private key is never overwritten — even if its
        # public file is missing (old deployments shipped private only).
        # In that case the public key is rebuilt from the private one.
        if [ ! -f "$HUB_PUB" ]; then
            ssh-keygen -y -f "$HUB_KEY" > "$HUB_PUB" \
                || die "Rebuilding the hub public key from the private key failed"
            chmod 644 "$HUB_PUB"
            info "Hub public key rebuilt from the existing private key"
        else
            info "Hub key already exists and will not be touched: $HUB_KEY"
        fi
    else
        step "Generating the hub key"
        rm -f "$HUB_KEY" "$HUB_PUB"
        ssh-keygen -t ed25519 -f "$HUB_KEY" -N "" -C "rahyaab-hub" >/dev/null \
            || die "Generating the hub key failed"
        chmod 600 "$HUB_KEY"
        chmod 644 "$HUB_PUB"
        ok "Hub key generated: $HUB_KEY"
    fi
    info "Hub public key (copy it manually to a node if you do not want to give a password):"
    cat "$HUB_PUB"
    info "Fingerprint: $(ssh-keygen -lf "$HUB_PUB" | awk '{print $2}')"
    # The hub SSHes to BOTH pair servers with this key — including to
    # itself, because the master is the Iran side of its own pairs.
    # Without this self-authorisation the background full_setup job
    # dies on authentication the moment it connects to the master.
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
    if grep -qF "$(cat "$HUB_PUB")" /root/.ssh/authorized_keys; then
        info "Hub key already authorised on this server"
    else
        cat "$HUB_PUB" >> /root/.ssh/authorized_keys
        ok "Hub key authorised on this server (the hub can SSH to itself)"
    fi
}

# Install the hub public key on a node with that node's one-time
# root password. The password is used for this one connection only;
# it is never stored, logged, or printed, and is wiped from memory
# right after the connection. After this, the node opens only with
# the hub key and no password is needed anymore. The node host key
# is pinned right there in /root/.ssh/known_hosts (a stale entry
# for the same host, e.g. after a rebuild, is removed first).
push_key() { # $1 = node host
    local node="${1:-$NODE_HOST}"
    [ -n "$node" ] || die "Node host is required (--push-key <host>)"
    ensure_hub_key
    if ! python3 -c "import paramiko" 2>/dev/null; then
        step "Installing python3-paramiko for the one-time connection"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq python3-paramiko \
            || die "Installing paramiko failed"
    fi
    local pass
    echo "The node root password for $node is asked only this once and is never stored."
    read -r -s -p "Root password for $node: " pass
    echo
    [ -n "$pass" ] || die "Empty password given"
    step "Installing the hub key on $node"
    RAHYAAB_NODE_PASSWORD="$pass" HUB_KEY="$HUB_KEY" HUB_PUB="$HUB_PUB" \
        NODE_HOST="$node" NODE_USER="$NODE_USER" NODE_PORT="$NODE_PORT" \
        python3 - "$HUB_KEY" "$HUB_PUB" <<'PYEOF'
import os, sys
import paramiko
key_path, pub_path = sys.argv[1], sys.argv[2]
host = os.environ["NODE_HOST"]
user = os.environ.get("NODE_USER") or "root"
port = int(os.environ.get("NODE_PORT") or 22)
pw = os.environ["RAHYAAB_NODE_PASSWORD"]
pub = open(pub_path).read().strip()
kh_path = "/root/.ssh/known_hosts"
os.makedirs("/root/.ssh", exist_ok=True)
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(host, port, user, password=pw, timeout=20, banner_timeout=30,
          auth_timeout=30, allow_agent=False, look_for_keys=False)
# Pin the host key (drop a stale entry for the same host first, so a rebuild does not break it)
rk = c.get_transport().get_remote_server_key()
line = "%s %s %s" % (host, rk.get_name(), rk.get_base64())
old = open(kh_path).read() if os.path.exists(kh_path) else ""
kept = [l for l in old.splitlines() if not l.startswith(host + " ")]
if line not in kept:
    kept.append(line)
open(kh_path, "w").write("\n".join(kept) + "\n")
os.chmod(kh_path, 0o600)
# Add the hub public key (only if missing)
sftp = c.open_sftp()
try:
    sftp.stat("/root/.ssh")
except IOError:
    sftp.mkdir("/root/.ssh")
    sftp.chmod("/root/.ssh", 0o700)
try:
    cur = sftp.open("/root/.ssh/authorized_keys").read().decode()
except IOError:
    cur = ""
if pub not in cur:
    f = sftp.open("/root/.ssh/authorized_keys", "a")
    f.write(pub + "\n")
    f.close()
    sftp.chmod("/root/.ssh/authorized_keys", 0o600)
    print("hub key added to node")
else:
    print("hub key already present on node")
c.close()
# Verify: key-only login, rejecting unknown hosts
c2 = paramiko.SSHClient()
c2.load_system_host_keys()
c2.load_host_keys(kh_path)
c2.set_missing_host_key_policy(paramiko.RejectPolicy())
c2.connect(host, port, user, key_filename=key_path, timeout=20,
           banner_timeout=30, auth_timeout=30, allow_agent=False, look_for_keys=False)
_, out, _ = c2.exec_command("echo rahyaab-key-ok")
assert out.read().decode().strip() == "rahyaab-key-ok", "key-only login failed"
c2.close()
print("push-key-ok")
PYEOF
    local rc=$?
    pass=""
    unset RAHYAAB_NODE_PASSWORD
    [ "$rc" -eq 0 ] || die "Installing the key on the node failed"
    ok "Hub key installed on $node and key-only login verified; password discarded"
}

# Install a node on another server, from this hub server, with
# the hub key. Prerequisite: push-key must already have run for
# that node (host key pinned and hub key installed on the node);
# otherwise it fails cleanly instead of hanging on a question.
# The code is tarballed from this very /opt/rahyaab, so no second
# download from GitHub is needed.
install_node_remote() { # $1 = node host
    local node="${1:-$REMOTE_NODE}"
    [ -n "$node" ] || die "Node host is required (--remote-node <host>)"
    ensure_hub_key
    [ -d "$INSTALL_DIR" ] || die "Rahyaab code is not on this server; install the hub first"
    [ -f "$INSTALL_DIR/hub/main.py" ] || die "hub/main.py is not in $INSTALL_DIR"
    [ -f "$INSTALL_DIR/install.sh" ] || die "install.sh is not in $INSTALL_DIR"
    step "Installing a node on $node remotely"
    local tgz="/tmp/rahyaab-node.tgz"
    (cd "$INSTALL_DIR" && tar --exclude=.git --exclude=__pycache__ --exclude='*.pyc' --exclude='*.bak-*' -czf "$tgz" .) \
        || die "Creating the code tarball failed"
    scp -i "$HUB_KEY" -o BatchMode=yes -o StrictHostKeyChecking=yes \
        -o ConnectTimeout=20 -P "$NODE_PORT" "$tgz" "$INSTALL_DIR/install.sh" \
        "$NODE_USER@$node:/tmp/" \
        || die "Sending to the node failed; run push-key for $node first"
    ssh -i "$HUB_KEY" -o BatchMode=yes -o StrictHostKeyChecking=yes \
        -o ConnectTimeout=20 -p "$NODE_PORT" "$NODE_USER@$node" \
        "rm -rf /tmp/rahyaab-src && mkdir -p /tmp/rahyaab-src && tar -xzf /tmp/rahyaab-node.tgz -C /tmp/rahyaab-src && bash /tmp/install.sh --role node --bbr --local /tmp/rahyaab-src --yes" \
        || die "Installing the node on $node failed"
    step "Verifying the node"
    ssh -i "$HUB_KEY" -o BatchMode=yes -o StrictHostKeyChecking=yes \
        -o ConnectTimeout=20 -p "$NODE_PORT" "$NODE_USER@$node" \
        "test -f /opt/rahyaab/hub/main.py && sysctl -n net.ipv4.tcp_congestion_control" \
        || die "Node verification failed"
    rm -f "$tgz"
    ok "Node on $node installed and verified"
}

# Full setup of both servers from this hub server: hub install +
# BBR + certificate + push-key + remote node install + pair
# registration in the hub database + the measure/deploy/install-
# healer chain (wizard_setup.run_setup). The node root password
# is asked only at the push-key step and never stored. The chain
# step takes a few minutes (benchmark + deploy + healer install).
# Guard: if a pair with the same name is already set up (it has a
# current protocol), it stops before any destructive change; a
# previous incomplete setup (no current protocol) can be resumed
# by running again.
full_setup() { # $1 = node host
    local node="${1:-$FULL_SETUP_NODE}"
    [ -n "$node" ] || die "Node host is required (--full-setup <host>)"
    local iran_ip="$IRAN_HOST"
    if [ -z "$iran_ip" ]; then
        iran_ip="$(public_ip)"
    fi
    [ -n "$iran_ip" ] && [ "$iran_ip" != "unknown" ] \
        || die "Could not find this server's IP; pass it with --iran-host"
    if [ "$YES" -eq 0 ]; then
        ask IRAN_HOST "IP of this server (hub/Iran)" "$iran_ip"
        iran_ip="$IRAN_HOST"
    fi
    step "1) Installing the hub on this server"
    install_hub
    if [ "$BBR" -eq 1 ]; then enable_bbr; fi
    if [ -n "$DOMAIN" ]; then cert_domain; fi
    if [ "$IP_CERT" -eq 1 ]; then cert_ip; fi
    if [ -n "$CERT_PATH" ]; then cert_custom; fi
    step "2) Installing the hub key on the node (one-time password will be asked)"
    push_key "$node"
    step "3) Installing the node on $node remotely"
    install_node_remote "$node"
    step "4) Registering the servers and pair in the hub database"
    local pair_json pair_id pair_protocol
    pair_json="$(cd "$INSTALL_DIR" && python3 -m hub.wizard --db "$HUB_DB" --iran-host "$iran_ip" --foreign-host "$node" --pair-name "$PAIR_NAME")" \
        || die "Registering the pair in the hub database failed"
    pair_id="$(echo "$pair_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')" \
        || die "Reading the pair ID failed"
    pair_protocol="$(echo "$pair_json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("current_protocol") or "")')"
    if [ -n "$pair_protocol" ]; then
        die "Pair "$PAIR_NAME" is already set up (current protocol: $pair_protocol); give a new pair another name"
    fi
    info "Pair registered (ID $pair_id)"
    step "5) Measuring, deploying the first tunnel, and installing the healer"
    local setup_json setup_score setup_status panel_url
    setup_json="$(python3 "$INSTALL_DIR/orchestrator/wizard_setup.py" --iran-host "$iran_ip" --foreign-host "$node" --pair-id "$pair_id" --pair-name "$PAIR_NAME" --hub-db "$HUB_DB" --hub-key "$HUB_KEY" --frontend-port 443 --protocol "$PROTOCOL")" \
        || die "Setup chain failed; see the output above"
    setup_score="$(echo "$setup_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["score"])')"
    setup_status="$(echo "$setup_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["deploy_status"])')"
    if [ -n "$DOMAIN" ]; then panel_url="https://$DOMAIN:$HUB_PORT"; else panel_url="https://$iran_ip:$HUB_PORT"; fi
    echo
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  Full setup complete                                 ║"
    echo "║  Pair: $PAIR_NAME                                    ║"
    echo "║  First tunnel: $PROTOCOL (score $setup_score, status $setup_status)║"
    echo "║  Dashboard: $panel_url                               ║"
    echo "║  Next: create the operator account on the            ║"
    echo "║  dashboard setup page. This script never touches PasarGuard.║"
    echo "╚══════════════════════════════════════════════════════╝"
}

# ── Hub unit ───────────────────────────────────────────────────
write_hub_unit() { # $1=host $2=cert $3=key
    local host="$1" cert="$2" key="$3" tls_args=""
    if [ -n "$cert" ] && [ -n "$key" ]; then
        tls_args=" --tls-cert $cert --tls-key $key"
    fi
    cat > "/etc/systemd/system/$UNIT.service" <<EOF
[Unit]
Description=Rahyaab hub control plane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 -m hub.main --host $host --port $HUB_PORT --db $HUB_DB$tls_args
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "/etc/systemd/system/$UNIT.service"
    systemctl daemon-reload
}

hub_health() { # $1 = http|https
    local scheme="$1" out="" i=0
    systemctl is-active "$UNIT" | grep -qx "active" \
        || die "Service $UNIT did not come up; check 'journalctl -u $UNIT -n 50'"
    # On a slow VPS the hub may take a few seconds to listen; retry for up to 30s
    while [ "$i" -lt 15 ]; do
        if [ "$scheme" = "https" ]; then
            out="$(curl -kfsS "https://127.0.0.1:$HUB_PORT/api/health" 2>/dev/null || true)"
        else
            out="$(curl -fsS "http://127.0.0.1:$HUB_PORT/api/health" 2>/dev/null || true)"
        fi
        [ -n "$out" ] && break
        sleep 2
        i=$((i + 1))
    done
    [ -n "$out" ] || die "Hub is up but /api/health did not answer"
    info "Hub health: $out"
}

firewall_open_8890() {
    step "Firewall for port $HUB_PORT"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$HUB_PORT/tcp" >/dev/null
        ok "ufw: port $HUB_PORT opened"
        return 0
    fi
    if command -v iptables >/dev/null 2>&1; then
        local rules policy
        rules="$(iptables -S INPUT 2>/dev/null || true)"
        if [ -n "$rules" ] && ! echo "$rules" | grep -q "$HUB_PORT"; then
            policy="$(echo "$rules" | head -1)"
            case "$policy" in
                *DROP*|*REJECT*)
                    iptables -A INPUT -p tcp --dport "$HUB_PORT" -j ACCEPT
                    ok "iptables: port $HUB_PORT opened (input policy was closed)"
                    if command -v netfilter-persistent >/dev/null 2>&1; then
                        netfilter-persistent save >/dev/null 2>&1 || true
                    else
                        warn "netfilter-persistent is missing; the iptables rule will not survive a reboot unless saved manually"
                    fi
                    ;;
                *) info "Firewall policy is open; no rule was needed" ;;
            esac
        else
            info "Firewall is not closed or the rule already exists; nothing was needed"
        fi
    else
        info "No firewall tool found; assuming open"
    fi
}

install_hub() {
    step "Installing the hub (dashboard)"
    install_deps hub
    fetch_code
    ensure_hub_key
    write_hub_unit "127.0.0.1" "" ""
    systemctl enable "$UNIT" >/dev/null 2>&1
    # Note: enable --now does not restart a running unit; a reinstall
    # needs an explicit restart so the fresh code and settings actually come up
    systemctl restart "$UNIT"
    hub_health http
    firewall_open_8890
    ok "Hub installed; for now it is only reachable on this server (127.0.0.1)"
    warn "To open it to the internet, choose 'Web Panel' from the menu and set a certificate (domain or IP)"
}

install_node() {
    step "Installing the node (no dashboard)"
    install_deps node
    fetch_code
    ok "Node installed: engine and protocol scripts in $INSTALL_DIR"
    info "From now on this server is managed from the hub dashboard over SSH keys;"
    info "it listens on no service itself, and no operator account is created here."
}

# ── Node join flow ─────────────────────────────────────
# Kariz/Smite-style: the master gives a one-line command, the
# node pastes it. No IP is typed: the node address is read from
# the request origin and the master address comes from its own
# certificate. Trust in the channel is not blind either: the
# master certificate fingerprint is inside the join command itself,
# and the node checks the received certificate against that
# fingerprint before sending the code, then uses that verified
# certificate as the CA for the join request.
norm_fp() { # $1=fingerprint -> 64 uppercase hex chars, no separators
    echo "$1" | tr -d ' :\t' | sed 's/^SHA256Fingerprint=//I' | tr 'a-f' 'A-F'
}

active_hub_cert() { # Current hub certificate path from the unit, or empty
    systemctl cat "$UNIT" 2>/dev/null | grep -o -- '--tls-cert [^ ]*' | awk '{print $2}' | head -1
}

print_join_command() {
    [ -f "$INSTALL_DIR/hub/main.py" ] || die "Hub is not installed on this server"
    [ -f "$HUB_PUB" ] || die "No hub key; install the hub first"
    local cert host token fp
    cert="$(active_hub_cert)"
    [ -n "$cert" ] || die "Hub has no certificate yet (local only); set a certificate from 'Web Panel' in the menu first, then get the join command again"
    case "$cert" in
        /etc/letsencrypt/live/*/fullchain.pem)
            host="$(echo "$cert" | cut -d/ -f5)" ;;
        *) host="$(public_ip)" ;;
    esac
    [ -n "$host" ] && [ "$host" != "unknown" ] || die "Master address not found"
    token="$(cd "$INSTALL_DIR" && python3 -m hub.join generate)" || die "Generating the join code failed"
    fp="$(norm_fp "$(cert_fingerprint "$cert")")"
    JOIN_CMD_LINE="curl -fsSL -o /tmp/install-rahyaab.sh https://raw.githubusercontent.com/irluca/Rahyaab/main/install.sh && bash /tmp/install-rahyaab.sh --join $host $token $fp"
    echo
    echo -e "${C_CYAN}──────────────────────────────────────────────────────────────${C_RESET}"
    echo -e "${C_CYAN}Node join command — paste this one line on the node server:${C_RESET}"
    echo "$JOIN_CMD_LINE"
    echo -e "${C_CYAN}──────────────────────────────────────────────────────────────${C_RESET}"
    warn "This code is single-use; printing a new one invalidates the old one"
}

verify_master_cert() { # $1=host $2=expected-fp (normalized)
    local host="$1" expected="$2" cert_pem="/tmp/rahyaab-master-cert.pem" actual
    echo | openssl s_client -connect "$host:$HUB_PORT" -servername "$host" 2>/dev/null \
        | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > "$cert_pem"
    [ -s "$cert_pem" ] || die "Secure connection to the master failed ($host:$HUB_PORT)"
    actual="$(norm_fp "$(cert_fingerprint "$cert_pem")")"
    [ "$actual" = "$expected" ] || die "Master certificate fingerprint does not match the join command; get a fresh command from the master (the certificate may have changed, or someone may be in the middle)"
    ok "Master certificate verified"
}

node_join() { # $1=host $2=token $3=fingerprint
    local host="$1" token="$2" fp
    fp="$(norm_fp "$3")"
    [ -n "$host" ] || die "Master address is required"
    [[ "$token" =~ ^[0-9a-f]{32}$ ]] || die "Invalid join code (must be 32 hex characters)"
    [[ "$fp" =~ ^[0-9A-F]{64}$ ]] || die "Invalid fingerprint (must be 64 hex characters)"
    step "Installing the node and joining master $host"
    install_deps node
    fetch_code
    enable_bbr
    verify_master_cert "$host" "$fp"
    local key_file ktype kb64
    key_file=""
    for k in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_rsa_key.pub; do
        if [ -f "$k" ]; then key_file="$k"; break; fi
    done
    [ -n "$key_file" ] || die "No SSH host key on this server (is sshd installed?); install openssh-server first"
    read -r ktype kb64 _ < "$key_file"
    # The node name travels with the join so the master can tell nodes
    # apart: same hostname on a different host becomes name-2, name-3
    # on the master instead of hijacking the first node's record.
    local node_name
    node_name="$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9_.-')"
    [ -n "$node_name" ] || node_name="node"
    local json resp code body err hub_pub
    json="$(TOKEN="$token" KTYPE="$ktype" KB64="$kb64" NNAME="$node_name" python3 -c 'import json,os; print(json.dumps({"token": os.environ["TOKEN"], "host_key_type": os.environ["KTYPE"], "host_key_b64": os.environ["KB64"], "name": os.environ["NNAME"]}))')"
    resp="$(curl -sS --max-time 30 --cacert /tmp/rahyaab-master-cert.pem -X POST "https://$host:$HUB_PORT/api/join" -H 'Content-Type: application/json' --data "$json" -w $'\n%{http_code}')" \
        || die "Connection to the master failed ($host:$HUB_PORT)"
    code="${resp##*$'\n'}"
    body="${resp%$'\n'*}"
    if [ "$code" != "201" ]; then
        err="$(echo "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("error",""))' 2>/dev/null || echo "$body")"
        die "Master rejected the join (code $code): $err"
    fi
    hub_pub="$(echo "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin)["hub_pubkey"])')" \
        || die "Master response was unreadable"
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
    grep -qF "$hub_pub" /root/.ssh/authorized_keys || echo "$hub_pub" >> /root/.ssh/authorized_keys
    ok "Node joined the master; pair and tunnel creation started in the background on the master; check the master dashboard in a few minutes"
}

parse_join_input() { # $1=pasted command -> JOIN_HOST/JOIN_TOKEN/JOIN_FP
    local rest
    if [[ "$1" == *"--join"* ]]; then
        rest="${1##*--join }"
    else
        rest="$1"
    fi
    read -r JOIN_HOST JOIN_TOKEN JOIN_FP _ <<< "$rest"
    [ -n "$JOIN_HOST" ] && [ -n "$JOIN_TOKEN" ] && [ -n "$JOIN_FP" ] \
        || die "Join command is incomplete; it must have the master address, code, and fingerprint"
}

node_join_flow() {
    echo "Paste the master join command printed on the master here"
    echo "(or just its three parts: master address, code, fingerprint)"
    local pasted
    read -r -p "Join command: " pasted
    parse_join_input "$pasted"
    node_join "$JOIN_HOST" "$JOIN_TOKEN" "$JOIN_FP"
}

master_setup_flow() {
    step "Installing the master (hub)"
    install_hub
    enable_bbr
    if [ -z "$DOMAIN" ] && [ "$IP_CERT" -eq 0 ] && [ -z "$CERT_PATH" ]; then
        if [ "$YES" -eq 0 ]; then
            echo
            echo "Create the panel certificate now too?"
            echo "  1) Domain   2) IP   3) Later (local only)"
            local g
            read -r -p "Select: " g
            case "$g" in
                1) cert_domain ;;
                2) cert_ip ;;
                *) warn "Hub is local-only; get a certificate before opening it to the internet" ;;
            esac
        else
            warn "No certificate selected; hub is local-only"
        fi
    else
        if [ -n "$DOMAIN" ]; then cert_domain; fi
        if [ "$IP_CERT" -eq 1 ]; then cert_ip; fi
        if [ -n "$CERT_PATH" ]; then cert_custom; fi
    fi
    local iran_ip="$IRAN_HOST"
    [ -z "$iran_ip" ] && iran_ip="$(public_ip)"
    [ -n "$iran_ip" ] && [ "$iran_ip" != "unknown" ] || die "Could not find this server's IP; pass it with --iran-host"
    if [ "$YES" -eq 0 ]; then
        ask IRAN_HOST "IP of this server (master)" "$iran_ip"
        iran_ip="$IRAN_HOST"
    fi
    step "Registering the master in the hub database"
    (cd "$INSTALL_DIR" && python3 -m hub.wizard --db "$HUB_DB" --self-host "$iran_ip") \
        || die "Registering the master failed"
    if [ -n "$(active_hub_cert)" ]; then
        print_join_command
    else
        warn "No certificate, so no join command was printed; after getting a certificate, run 'Print join command' under 'Manage' in the menu"
    fi
    summary
}

# ── BBR ─────────────────────────────────────────────────────────
enable_bbr() {
    step "Enabling BBR"
    if ! modprobe tcp_bbr 2>/dev/null; then
        warn "tcp_bbr module did not load (some VPS kernels forbid it); trying anyway"
    fi
    cat > /etc/sysctl.d/99-rahyaab-bbr.conf <<EOF
# Rahyaab: BBR congestion control + fq queueing
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-rahyaab-bbr.conf
    local cur
    cur="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'unknown')"
    if [ "$cur" = "bbr" ]; then
        ok "BBR enabled (tcp_congestion_control=bbr)"
    else
        warn "BBR is set but the current value is '$cur'; check again after reboot"
    fi
}

# ── Certificates ────────────────────────────────────────────────────────
hub_installed() {
    [ -f "/etc/systemd/system/$UNIT.service" ]
}

apply_tls_to_hub() { # $1=cert $2=key
    write_hub_unit "0.0.0.0" "$1" "$2"
    systemctl restart "$UNIT"
    hub_health https
    firewall_open_8890
}

cert_expiry() { # $1=cert
    openssl x509 -in "$1" -noout -enddate 2>/dev/null | cut -d= -f2
}

cert_fingerprint() { # $1=cert
    openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null
}

cert_domain() {
    step "Let's Encrypt certificate for a domain"
    hub_installed || die "Install the hub first, then get a certificate"
    if [ -z "$DOMAIN" ]; then
        ask DOMAIN "Panel domain (e.g. panel.example.com)"
    fi
    if [ -z "$EMAIL" ]; then
        ask EMAIL "Email for certbot"
    fi
    [ -n "$DOMAIN" ] && [ -n "$EMAIL" ] || die "Domain and email are required"
    if ss -ltn 2>/dev/null | grep -q ':80 '; then
        die "Port 80 is busy; certbot standalone mode needs a free port 80"
    fi
    info "The domain must reach this server from the internet, or validation will fail"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq certbot
    certbot certonly --standalone --non-interactive --agree-tos \
        --email "$EMAIL" -d "$DOMAIN" \
        || die "Issuing the certificate failed; check the domain DNS and that port 80 is open"
    local cert="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    local key="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/rahyaab-hub.sh <<EOF
#!/bin/sh
# After each successful renewal, restart the hub so it picks up the new certificate.
if systemctl is-active -q $UNIT; then
    systemctl restart $UNIT
fi
EOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/rahyaab-hub.sh
    apply_tls_to_hub "$cert" "$key"
    ok "Domain certificate activated; auto-renewal runs on the certbot timer"
    info "Expiry: $(cert_expiry "$cert")"
    info "Panel address: https://$DOMAIN:$HUB_PORT"
}

cert_ip() {
    step "IP certificate (self-signed + auto-renewal)"
    hub_installed || die "Install the hub first, then get a certificate"
    local ip cert key
    ip="$(public_ip)"
    if [ "$ip" = "unknown" ]; then
        ask ip "Server public IP"
    fi
    cert="$CONF_DIR/tls/cert.pem"
    key="$CONF_DIR/tls/key.pem"
    mkdir -p "$CONF_DIR/tls"
    if [ -f "$cert" ] && [ -f "$key" ]; then
        if openssl x509 -in "$cert" -noout -checkend 2592000 >/dev/null 2>&1; then
            info "Existing certificate is still valid for more than 30 days; keeping it"
        else
            info "Existing certificate is close to expiry; generating a fresh one"
            rm -f "$cert" "$key"
        fi
    fi
    if [ ! -f "$cert" ]; then
        openssl req -x509 -newkey rsa:2048 -keyout "$key" -out "$cert" -days 825 -nodes -subj "/CN=$ip" -addext "subjectAltName=IP:$ip" || die "Generating the certificate failed"
        chmod 600 "$key"; chmod 644 "$cert"
        ok "Self-signed certificate for IP $ip created (825 days)"
    fi
    cat > /usr/local/bin/rahyaab-renew-ip-cert.sh <<EOF
#!/bin/sh
# If the IP certificate has less than 30 days left, regenerate it and restart the hub.
CERT="$cert"
KEY="$key"
IP="$ip"
if [ -f "\$CERT" ] && openssl x509 -in "\$CERT" -noout -checkend 2592000 >/dev/null 2>&1; then
    exit 0
fi
openssl req -x509 -newkey rsa:2048 -keyout "\$KEY" -out "\$CERT" -days 825 -nodes -subj "/CN=\$IP" -addext "subjectAltName=IP:\$IP" || exit 1
chmod 600 "\$KEY"; chmod 644 "\$CERT"
if systemctl is-active -q $UNIT; then
    systemctl restart $UNIT
fi
EOF
    chmod +x /usr/local/bin/rahyaab-renew-ip-cert.sh
    cat > /etc/systemd/system/rahyaab-cert-renew.service <<EOF
[Unit]
Description=Renew Rahyaab IP certificate if close to expiry

[Service]
Type=oneshot
ExecStart=/usr/local/bin/rahyaab-renew-ip-cert.sh
EOF
    cat > /etc/systemd/system/rahyaab-cert-renew.timer <<EOF
[Unit]
Description=Daily check for Rahyaab IP certificate renewal

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now rahyaab-cert-renew.timer
    apply_tls_to_hub "$cert" "$key"
    ok "IP certificate activated; the daily timer renews it before expiry"
    info "Fingerprint (compare with the browser): $(cert_fingerprint "$cert")"
    info "Expiry: $(cert_expiry "$cert")"
    info "Panel address: https://$ip:$HUB_PORT"
    warn "Certificate is self-signed; the browser will warn once until you approve it"
}

cert_custom() {
    step "Your own ready certificate"
    hub_installed || die "Install the hub first, then set a certificate"
    if [ -z "$CERT_PATH" ]; then ask CERT_PATH "Certificate file path (fullchain.pem)"; fi
    if [ -z "$KEY_PATH" ]; then ask KEY_PATH "Key file path (privkey.pem)"; fi
    [ -f "$CERT_PATH" ] || die "Certificate file not found: $CERT_PATH"
    [ -f "$KEY_PATH" ] || die "Key file not found: $KEY_PATH"
    apply_tls_to_hub "$CERT_PATH" "$KEY_PATH"
    ok "Your certificate is activated"
    info "Expiry: $(cert_expiry "$CERT_PATH")"
}

cert_menu() {
    echo
    echo "Panel certificate:"
    echo "  1) Domain — real Let's Encrypt + auto-renewal"
    echo "  2) IP — self-signed + auto-renewal (browser warns once)"
    echo "  3) My own ready certificate (I will give the file paths)"
    echo "  0) Back"
    local c
    read -r -p "Select: " c
    case "$c" in
        1) cert_domain ;;
        2) cert_ip ;;
        3) cert_custom ;;
        0) return 0 ;;
        *) warn "Invalid selection" ;;
    esac
}

# ── Status, update, uninstall ─────────────────────────────────────
show_status() {
    step "Rahyaab status on this server"
    echo "Hub:       $(systemctl is-active "$UNIT" 2>/dev/null || echo 'not installed')"
    if hub_installed; then
        grep -o 'ExecStart=.*' "/etc/systemd/system/$UNIT.service" | cut -c1-160
    fi
    echo "BBR:       $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'unknown')"
    if [ -f "$CONF_DIR/tls/cert.pem" ]; then
        echo "IP certificate: expires $(cert_expiry "$CONF_DIR/tls/cert.pem")"
    fi
    local d
    for d in /etc/letsencrypt/live/*/; do
        [ -d "$d" ] || continue
        echo "Domain certificate: ${d} expires $(cert_expiry "${d}fullchain.pem" 2>/dev/null || echo '?')"
    done
    echo "Public IP: $(public_ip)"
    echo "Code:      $INSTALL_DIR"
    echo "Data:      $DATA_DIR"
}

update_code() {
    step "Updating Rahyaab code"
    [ -d "$INSTALL_DIR" ] || die "Rahyaab is not installed; pick an install option first"
    fetch_code
    if hub_installed && systemctl is-active -q "$UNIT"; then
        systemctl restart "$UNIT"
        if grep -q 'tls-cert' "/etc/systemd/system/$UNIT.service"; then
            hub_health https
        else
            hub_health http
        fi
    fi
    ok "Code updated; database and certificates untouched"
}

uninstall() {
    step "Uninstalling Rahyaab"
    warn "Rahyaab services will stop and the code will be removed"
    confirm || { info "Cancelled"; return 0; }
    systemctl stop "$UNIT" 2>/dev/null || true
    systemctl disable "$UNIT" 2>/dev/null || true
    systemctl stop rahyaab-cert-renew.timer 2>/dev/null || true
    systemctl disable rahyaab-cert-renew.timer 2>/dev/null || true
    rm -f "/etc/systemd/system/$UNIT.service" \
        /etc/systemd/system/rahyaab-cert-renew.service \
        /etc/systemd/system/rahyaab-cert-renew.timer \
        /usr/local/bin/rahyaab-renew-ip-cert.sh
    systemctl daemon-reload
    rm -rf "$INSTALL_DIR"
    local ans
    read -r -p "Also remove data and certificates? (hub database, accounts, pairs) [y/N] " ans
    case "$ans" in
        [yY]|[yY][eE][sS])
            rm -rf "$DATA_DIR" "$CONF_DIR"
            ok "Everything removed"
            ;;
        *) info "Data kept: $DATA_DIR and $CONF_DIR" ;;
    esac
    ok "Uninstall complete"
}

summary() {
    # Final tidy summary. The panel address and certificate fingerprint
    # are repeated here (not buried in the scrollback), and the
    # operator account is explained honestly: it does not exist yet,
    # so no username/password can be printed; the operator creates it
    # on the panel's first-open setup page.
    local cert host users
    if hub_installed; then
        cert="$(active_hub_cert)"
        if [ -n "$cert" ]; then
            case "$cert" in
                /etc/letsencrypt/live/*/fullchain.pem)
                    host="$(echo "$cert" | cut -d/ -f5)" ;;
                *) host="$(public_ip)" ;;
            esac
            echo
            info "Certificate:   $(cert_fingerprint "$cert")"
            info "The browser warns once about the self-signed cert;"
            info "compare its fingerprint with the one above first."
        else
            echo
            warn "Panel is local only (no certificate yet)"
        fi
    fi
    echo
    echo -e "${C_GREEN}╔══════════════════════════════════════════════════════╗${C_RESET}"
    box() { printf "${C_GREEN}║${C_RESET}  %-52s${C_GREEN}║${C_RESET}\n" "$1"; }
    box "Install complete."
    box ""
    if hub_installed; then
        if [ -z "$cert" ]; then
            box "Panel: local only (127.0.0.1:8890 on this server)"
        else
            box "Panel: https://$host:$HUB_PORT"
        fi
        users=""
        if [ -f "$HUB_DB" ]; then
            users="$(python3 -c 'import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute("SELECT COUNT(*) FROM users").fetchone()[0])' "$HUB_DB" 2>/dev/null || true)"
        fi
        if [ -n "$users" ] && [ "$users" != "0" ]; then
            box "Operator account: already exists."
        else
            box "Operator account: not created yet."
            box "Open the panel address and create it on the"
            box "first-open setup page. No password exists"
            box "yet, so none is printed here."
        fi
        box ""
        if [ -n "${JOIN_CMD_LINE:-}" ]; then
            box "Node: paste the join command printed above"
            box "on the node server (it downloads this same"
            box "installer in node mode)."
        else
            box "Node: print its join command from the Manage"
            box "menu (it is single-use)."
        fi
    else
        box "This server is a node; it is managed from"
        box "the master dashboard."
    fi
    box ""
    box "Note: this script never touches PasarGuard."
    echo -e "${C_GREEN}╚══════════════════════════════════════════════════════╝${C_RESET}"
}

# ── Backup & Restore, Web Panel, Optimize ──────────────────────────────
create_backup() {
    step "Creating a backup"
    hub_installed || { warn "Hub is not installed; nothing to back up"; return 0; }
    [ -f "$HUB_DB" ] || { warn "Hub database not found ($HUB_DB); nothing to back up"; return 0; }
    local tmp backup stamp
    tmp="$(mktemp -d)"
    python3 - "$HUB_DB" "$tmp/hub.db" <<'PYBACKUP' || { warn "Database backup failed; nothing was changed"; rm -rf "$tmp"; return 0; }
import sqlite3
import sys
src = sqlite3.connect(sys.argv[1])
dst = sqlite3.connect(sys.argv[2])
src.backup(dst)
dst.close()
src.close()
PYBACKUP
    mkdir -p "$tmp/data" "$tmp/conf"
    cp -a "$DATA_DIR/." "$tmp/data/" 2>/dev/null || { warn "Could not read hub data ($DATA_DIR)"; rm -rf "$tmp"; return 0; }
    cp -f "$tmp/hub.db" "$tmp/data/hub.db"
    cp -a "$CONF_DIR/." "$tmp/conf/" 2>/dev/null || { warn "Could not read hub configuration ($CONF_DIR)"; rm -rf "$tmp"; return 0; }
    stamp="$(date +%Y%m%d-%H%M%S)"
    backup="/root/rahyaab-backup-$stamp.tar.gz"
    tar -czf "$backup" -C "$tmp" data conf || { warn "Could not write $backup"; rm -rf "$tmp"; return 0; }
    rm -rf "$tmp"
    ok "Backup created: $backup"
    info "Keep this file private: it contains the hub key and certificates"
}

restore_backup() {
    step "Restoring a backup"
    local file ans tmp health_scheme
    read -r -p "Backup file path: " file
    [ -f "$file" ] || { warn "Backup file not found: $file"; return 0; }
    warn "This overwrites the current hub data and certificates."
    read -r -p "Restore this backup? [y/N] " ans
    case "$ans" in
        [yY]|[yY][eE][sS]) ;;
        *) info "Cancelled"; return 0 ;;
    esac
    tmp="$(mktemp -d)"
    tar -xzf "$file" -C "$tmp" || { warn "Could not read $file"; rm -rf "$tmp"; return 0; }
    [ -d "$tmp/data" ] && [ -d "$tmp/conf" ] || { warn "Not a Rahyaab backup (no data/conf inside): $file"; rm -rf "$tmp"; return 0; }
    systemctl stop "$UNIT" 2>/dev/null || true
    mkdir -p "$DATA_DIR" "$CONF_DIR"
    cp -a "$tmp/data/." "$DATA_DIR/"
    cp -a "$tmp/conf/." "$CONF_DIR/"
    rm -rf "$tmp"
    if hub_installed; then
        if systemctl restart "$UNIT"; then
            if grep -q 'tls-cert' "/etc/systemd/system/$UNIT.service"; then
                health_scheme=https
            else
                health_scheme=http
            fi
            if (hub_health "$health_scheme"); then
                ok "Restore complete; hub health verified"
            else
                warn "Restore extracted but the hub health check failed"
            fi
        else
            warn "Restore extracted but the hub failed to restart"
        fi
    else
        warn "Hub service is not installed; data restored but nothing was restarted"
    fi
}

backup_menu() {
    while true; do
        echo
        echo "Backup & Restore:"
        echo -e "  ${C_YELLOW}1)${C_RESET} Create backup   Back up hub data and certificates"
        echo -e "  ${C_YELLOW}2)${C_RESET} Restore backup  Restore hub data and certificates from a backup file"
        echo -e "  ${C_YELLOW}0)${C_RESET} Back"
        local c
        read -r -p "Select an option: " c
        case "$c" in
            1) create_backup ;;
            2) restore_backup ;;
            0) return 0 ;;
            *) warn "Invalid selection" ;;
        esac
    done
}

web_panel_info() {
    step "Web Panel"
    if hub_installed; then
        echo "Hub:       $(systemctl is-active "$UNIT" 2>/dev/null || true)"
    else
        echo "Hub:       not installed"
    fi
    local cert host
    cert=""
    if hub_installed; then
        cert="$(active_hub_cert)"
    fi
    if [ -n "$cert" ]; then
        case "$cert" in
            /etc/letsencrypt/live/*/fullchain.pem)
                host="$(echo "$cert" | cut -d/ -f5)" ;;
            *) host="$(public_ip)" ;;
        esac
        echo "Panel address: https://$host:$HUB_PORT"
        echo "Certificate:   $(cert_fingerprint "$cert")"
        echo "Expiry:        $(cert_expiry "$cert")"
    else
        echo "Panel: local only (no certificate yet)"
    fi
    cert_menu
}

optimize() {
    step "Optimize"
    local before after
    before="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'unknown')"
    echo "Congestion control before: $before"
    enable_bbr
    cat > /etc/sysctl.d/99-rahyaab.conf <<EOF
# Rahyaab: TCP buffer tuning (persistent)
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.core.netdev_max_backlog=5000
EOF
    sysctl -p /etc/sysctl.d/99-rahyaab.conf || warn "Some TCP settings were not applied; check them after a reboot"
    after="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'unknown')"
    echo "Congestion control after: $after"
    ok "Optimization applied (BBR + TCP buffers; settings persist across reboots)"
}

# ── Menus and entry ───────────────────────────────────────────────────
management_menu() {
    while true; do
        echo
        echo "Manage:"
    echo -e "  ${C_YELLOW}1)${C_RESET} Install hub         Dashboard on this server"
    echo -e "  ${C_YELLOW}2)${C_RESET} Install node        Engine only, no dashboard"
    echo -e "  ${C_YELLOW}3)${C_RESET} Show status         Hub, BBR, certificates, paths"
    echo -e "  ${C_YELLOW}4)${C_RESET} Push hub key        Install the hub key on a node (one-time root password)"
    echo -e "  ${C_YELLOW}5)${C_RESET} Install remote node Install a node from here over the hub key"
    echo -e "  ${C_YELLOW}6)${C_RESET} Full setup          Hub + node + pair + first tunnel + healer, one command"
    echo -e "  ${C_YELLOW}7)${C_RESET} Print join command  Fresh single-use node join command (master only)"
    echo -e "  ${C_YELLOW}0)${C_RESET} Back"
        local c
        read -r -p "Select an option: " c
        case "$c" in
            1)
                install_hub
                echo
                echo "Create the panel certificate now too?"
                echo "  1) Domain   2) IP   3) Later (local only)"
                local g
                read -r -p "Select: " g
                case "$g" in
                    1) cert_domain ;;
                    2) cert_ip ;;
                    *) warn "Hub is local-only; get a certificate before opening it to the internet" ;;
                esac
                summary
                ;;
            2) install_node ;;
            3) show_status ;;
            4)
                local node
                read -r -p "Node host (IP or domain): " node
                push_key "$node"
                ;;
            5)
                local node
                read -r -p "Node host (IP or domain): " node
                install_node_remote "$node"
                ;;
            6)
                local node pair
                read -r -p "Node host (IP or domain): " node
                read -r -p "Pair name [$PAIR_NAME]: " pair
                FULL_SETUP_NODE="$node"
                PAIR_NAME="${pair:-جفت اصلی}"
                BBR=1
                IP_CERT=1
                full_setup "$node"
                ;;
            7) print_join_command ;;
            0) return 0 ;;
            *) warn "Invalid selection" ;;
        esac
    done
}

menu() {
    while true; do
        echo
        echo -e "  ${C_YELLOW}1)${C_RESET} Master setup      Install hub + certificate + register master + print join command"
        echo -e "  ${C_YELLOW}2)${C_RESET} Node setup        Paste join command, install node, join master"
        echo -e "  ${C_YELLOW}3)${C_RESET} Manage            Install hub/node, status, push key, remote node, full setup, join command"
        echo -e "  ${C_YELLOW}4)${C_RESET} Backup & Restore  Create or restore a backup of hub data and certificates"
        echo -e "  ${C_YELLOW}5)${C_RESET} Web Panel         Panel address, certificate, status, and certificate setup"
        echo -e "  ${C_YELLOW}6)${C_RESET} Optimize          BBR + TCP buffer tuning"
        echo -e "  ${C_YELLOW}7)${C_RESET} Update            Refresh Rahyaab, keep database and certificates"
        echo -e "  ${C_YELLOW}8)${C_RESET} Uninstall         Remove Rahyaab from this server"
        echo -e "  ${C_YELLOW}9)${C_RESET} Exit"
        local c
        read -r -p "Select an option: " c
        case "$c" in
            1) master_setup_flow; return 0 ;;
            2) node_join_flow; return 0 ;;
            3) management_menu ;;
            4) backup_menu ;;
            5) web_panel_info ;;
            6) optimize ;;
            7) update_code; return 0 ;;
            8) uninstall; return 0 ;;
            9) info "Goodbye"; return 0 ;;
            *) warn "Invalid selection" ;;
        esac
    done
}

main() {
    parse_args "$@"
    banner
    need_root
    detect_os
    if [ "$CHECK_ONLY" -eq 1 ]; then
        check_only
        return 0
    fi
    if [ -n "$NODE_HOST" ]; then
        push_key "$NODE_HOST"
        return 0
    fi
    if [ -n "$REMOTE_NODE" ]; then
        install_node_remote "$REMOTE_NODE"
        return 0
    fi
    if [ -n "$FULL_SETUP_NODE" ]; then
        full_setup "$FULL_SETUP_NODE"
        return 0
    fi
    if [ -n "$JOIN_HOST" ]; then
        node_join "$JOIN_HOST" "$JOIN_TOKEN" "$JOIN_FP"
        return 0
    fi
    if [ "$PRINT_JOIN" -eq 1 ]; then
        print_join_command
        return 0
    fi
    if [ -n "$ROLE" ]; then
        # Non-interactive path
        if [ "$ROLE" = "master" ]; then
            master_setup_flow
            return 0
        fi
        if [ "$ROLE" = "hub" ]; then
            install_hub
        else
            install_node
        fi
        if [ "$BBR" -eq 1 ]; then enable_bbr; fi
        if [ -n "$DOMAIN" ]; then cert_domain; fi
        if [ "$IP_CERT" -eq 1 ]; then cert_ip; fi
        if [ -n "$CERT_PATH" ]; then cert_custom; fi
        summary
        return 0
    fi
    menu
}

main "$@"
