#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
#  رهیاب | RAHYAAB — نصب‌کننده کنترل‌صفحه تانل بین سرورها
#
#  اجرا روی خود سرور (با دسترسی root):
#      bash <(curl -fsSL https://raw.githubusercontent.com/irluca/Rahyaab/main/install.sh)
#  یا از روی فایل محلی:
#      bash install.sh
#
#  ایده‌ها از نصب‌کننده‌های BackPack و Kariz گرفته شده (منوی تعاملی،
#  نصب یک‌خطی، بدون داکر) — ولی کد، موتور و داشبورد کاملاً خود رهیاب است.
#
#  این اسکریپت فقط «میزبان» را آماده می‌کند: وابستگی‌ها، کد رهیاب،
#  هاب/نود، BBR، فایروال و گواهی پنل — به‌علاوه کلید هاب: موقع نصب
#  هاب، اگر کلیدی نباشد روی همین سرور ساخته می‌شود و با ‎--push-key
#  می‌شود با پسورد یک‌باره روت نود، روی آن نود نصبش کرد (پسورد هیچ‌جا
#  ذخیره نمی‌شود). ساخت حساب اپراتور، افزودن سرورها،
#  بنچمارک و پیکربندی نگهبان بعد از نصب، از داخل خود داشبورد انجام
#  می‌شود (مثل ویزارد راه‌اندازی Nexora) — اسکریپت هیچ رمز و حسابی
#  نمی‌سازد و چیزی را جعل نمی‌کند.
#
#  خط قرمز همیشگی: این اسکریپت به پنل PasarGuard، کانفیگ‌ها و
#  یوزرهایش هیچ دسترسی و تغییری ندارد، و به تانل‌ها و نگهبانِ در حال
#  اجرا دست نمی‌زند. اجرای دوباره امن است: کد تازه می‌شود، ولی
#  دیتابیس هاب و گواهی‌های موجود دست نمی‌خورند.
#
#  گواهی و آی‌پی — صادقانه: Let's Encrypt برای آی‌پیِ خالی گواهی
#  نمی‌دهد (فقط دامنه). پس دو مسیر جدا داریم:
#    • دامنه → گواهی واقعی Let's Encrypt + تمدید خودکار (certbot)
#    • آی‌پی  → گواهی self-signed با SAN آی‌پی + تایمر تمدید خودکار
#      که پیش از انقضا خودش گواهی تازه می‌سازد و هاب را ری‌استارت
#      می‌کند. مرورگر بار اول هشدار می‌دهد؛ اثر انگشت گواهی در
#      خلاصه پایانی چاپ می‌شود تا با خروجی مرورگر مقایسه شود.
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="1.1.0"
# پیش‌فرض مخزن؛ تا وقتی فاز ۵ پوش نشده، با --repo یا --local عوضش کنید.
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
NODE_USER="root"
NODE_PORT="22"
BBR=0
IP_CERT=0
YES=0
FORCE=0
CHECK_ONLY=0

# ── رنگ و پیام ──────────────────────────────────────────────────
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
    echo '  ╔══════════════════════════════════════════════════════╗'
    echo '  ║                                                      ║'
    echo '  ║     رهیاب  ·  R A H Y A A B                           ║'
    echo '  ║     کنترل‌صفحه تانل بین سرورها                        ║'
    echo "  ║     نصب‌کننده نسخه $VERSION                             ║"
    echo '  ║                                                      ║'
    echo '  ╚══════════════════════════════════════════════════════╝'
    echo -e "${C_RESET}"
}

confirm() {
    if [ "$YES" -eq 1 ]; then return 0; fi
    local ans
    read -r -p "ادامه می‌دهیم؟ [y/N] " ans
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
    echo "${ip:-نامشخص}"
}

usage() {
    cat <<EOF
استفاده:
  bash install.sh                     منوی تعاملی
  bash install.sh --role hub          نصب غیرتعاملی هاب
  bash install.sh --role node         نصب غیرتعاملی نود
  bash install.sh --role hub --bbr --domain panel.example.com --email you@example.com
  bash install.sh --role hub --bbr --ip-cert
  bash install.sh --local /path/to/rahyaab --role hub
  bash install.sh --push-key 203.0.113.20   نصب کلید هاب روی نود (پسورد روت نود یک بار پرسیده می‌شود، هیچ‌جا ذخیره نمی‌شود)
  bash install.sh --check-only        فقط بررسی پیش‌نیازها، بدون تغییر

کلید هاب: موقع نصب هاب، اگر کلیدی نباشد روی همین سرور ساخته می‌شود
(/etc/rahyaab/hub_key) و کلید موجود هیچ‌وقت بازنویسی نمی‌شود. هاب با
همین کلید به نودها وصل می‌شود؛ برای اعتماد اول، یا کلید عمومی چاپ‌شده
را دستی روی نود بگذارید، یا با --push-key و پسورد یک‌باره روت نود،
نصبش کنید. پسورد فقط برای همان یک اتصال است و بعد دور انداخته می‌شود.

گزینه‌ها:
  --role hub|node     نقش این سرور (هاب = داشبورد، نود = بدون داشبورد)
  --push-key HOST     نصب کلید هاب روی نود با پسورد یک‌باره روت آن
  --node-user USER    یوزر نود برای push-key (پیش‌فرض: root)
  --node-port PORT    پورت SSH نود برای push-key (پیش‌فرض: 22)
  --bbr               فعال‌سازی BBR
  --domain DOMAIN     گواهی Let's Encrypt برای دامنه
  --email EMAIL       ایمیل certbot (برای --domain لازم است)
  --ip-cert           گواهی self-signed برای آی‌پی + تمدید خودکار
  --cert FILE --key FILE   گواهی آماده خودتان
  --local DIR         نصب کد از روی فایل‌های محلی (به‌جای دانلود)
  --repo OWNER/REPO   مخزن گیت‌هاب (پیش‌فرض: $REPO)
  --branch BRANCH     شاخه (پیش‌فرض: $BRANCH)
  --yes               بدون پرسش تایید
  --force             رد شدن از بررسی سیستم‌عامل
  --check-only        فقط بررسی، بدون نصب
  --help              همین راهنما
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --role)     ROLE="$2"; shift 2 ;;
            --push-key) NODE_HOST="$2"; shift 2 ;;
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
            *)          die "گزینه ناشناخته: $1 (با --help راهنما را ببینید)" ;;
        esac
    done
    case "$ROLE" in ""|hub|node) ;; *) die "نقش نامعتبر: $ROLE (hub یا node)" ;; esac
    if [ -n "$DOMAIN" ] && [ -z "$EMAIL" ]; then
        die "برای گواهی دامنه، --email هم لازم است"
    fi
    if { [ -n "$CERT_PATH" ] || [ -n "$KEY_PATH" ]; } && { [ -z "$CERT_PATH" ] || [ -z "$KEY_PATH" ]; }; then
        die "--cert و --key باید با هم داده شوند"
    fi
}

need_root() {
    [ "$(id -u)" -eq 0 ] || die "این اسکریپت باید با دسترسی root اجرا شود (sudo bash install.sh)"
}

detect_os() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        info "سیستم‌عامل: ${NAME:-نامشخص} ${VERSION_ID:-}"
        case "${ID:-}" in
            debian|ubuntu) return 0 ;;
            *)
                if [ "$FORCE" -eq 1 ]; then
                    warn "سیستم‌عامل غیر از Debian/Ubuntu است؛ با --force ادامه می‌دهیم"
                    return 0
                fi
                die "فقط Debian و Ubuntu پشتیبانی می‌شوند (با --force می‌شود رد شد)"
                ;;
        esac
    else
        die "فایل /etc/os-release پیدا نشد؛ سیستم‌عامل قابل تشخیص نیست"
    fi
}

check_only() {
    step "بررسی پیش‌نیازها (بدون تغییر)"
    need_root
    detect_os
    echo "python3: $(python3 --version 2>/dev/null || echo 'نصب نیست')"
    echo "openssl: $(openssl version 2>/dev/null || echo 'نصب نیست')"
    echo "curl:    $(curl --version 2>/dev/null | head -1 || echo 'نصب نیست')"
    echo "آی‌پی عمومی: $(public_ip)"
    echo "هاب نصب‌شده: $(systemctl is-active "$UNIT" 2>/dev/null || echo 'no')"
    echo "BBR: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'نامشخص')"
    ok "بررسی تمام شد؛ تغییری انجام نشد"
}

# ── وابستگی‌ها و کد ─────────────────────────────────────────────
install_deps() { # $1 = hub|node
    step "نصب وابستگی‌های سیستم"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    local pkgs="python3 curl openssl iproute2 iptables unzip tar ca-certificates"
    if [ "$1" = "hub" ]; then
        pkgs="$pkgs python3-paramiko"
    fi
    apt-get install -y -qq $pkgs
    ok "وابستگی‌ها نصب شد"
}

fetch_code() {
    step "دریافت کد رهیاب"
    mkdir -p "$INSTALL_DIR"
    if [ -n "$LOCAL_SRC" ]; then
        [ -d "$LOCAL_SRC" ] || die "پوشه محلی پیدا نشد: $LOCAL_SRC"
        [ -f "$LOCAL_SRC/hub/main.py" ] || die "در پوشه محلی hub/main.py نیست؛ مسیر ریشه ریپو را بدهید"
        (cd "$LOCAL_SRC" && tar --exclude=.git --exclude=__pycache__ --exclude='*.pyc' -cf - .) \
            | (cd "$INSTALL_DIR" && tar -xf -)
        ok "کد از روی فایل‌های محلی کپی شد"
    else
        local url="https://codeload.github.com/${REPO}/tar.gz/refs/heads/${BRANCH}"
        local auth_args=()
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            auth_args=(-H "Authorization: Bearer $GITHUB_TOKEN")
        fi
        info "دانلود از $url"
        if ! curl -fsSL "${auth_args[@]}" -o /tmp/rahyaab.tgz "$url"; then
            die "دانلود ناموفق بود (گیت‌هاب برای ریپوی خصوصی بدون توکن ۴۰۴ می‌دهد). دو راه دارید: (۱) یک کپی از کد را با SCP روی سرور بگذارید و با --local <پوشه> نصب کنید؛ (۲) یک توکن خواندنی (fine-grained PAT، فقط همان ریپو) بسازید و با GITHUB_TOKEN=<توکن> همین دستور را دوباره بزنید. توکن را در فایل یا تاریخچه شل ذخیره نکنید."
        fi
        tar -xzf /tmp/rahyaab.tgz --strip-components=1 -C "$INSTALL_DIR"
        rm -f /tmp/rahyaab.tgz
        ok "کد دانلود و باز شد"
    fi
    [ -f "$INSTALL_DIR/hub/main.py" ] || die "hub/main.py در کد دریافتی نیست"
    [ -d "$INSTALL_DIR/dashboard" ] || warn "پوشه dashboard در کد نیست؛ داشبورد سرو نمی‌شود"
    mkdir -p "$DATA_DIR" "$CONF_DIR"
}

# ── کلید هاب ────────────────────────────────────────────────────
# کلید هاب روی همین سرور ساخته و نگه داشته می‌شود؛ هیچ‌وقت به
# گیت‌هاب پوش نمی‌شود و هیچ‌وقت پیش متا نیست. هاب با همین کلید به
# نودها وصل می‌شود (رکورد هر سرور در داشبورد، اگر key_path نداشته
# باشد، همین مسیر را پیش‌فرض می‌گیرد).
ensure_hub_key() {
    mkdir -p "$CONF_DIR"
    if [ -f "$HUB_KEY" ] && [ -f "$HUB_PUB" ]; then
        info "کلید هاب از قبل هست و دست نمی‌خورد: $HUB_KEY"
    else
        step "ساخت کلید هاب"
        rm -f "$HUB_KEY" "$HUB_PUB"
        ssh-keygen -t ed25519 -f "$HUB_KEY" -N "" -C "rahyaab-hub" >/dev/null \
            || die "ساخت کلید هاب ناموفق بود"
        chmod 600 "$HUB_KEY"
        chmod 644 "$HUB_PUB"
        ok "کلید هاب ساخته شد: $HUB_KEY"
    fi
    info "کلید عمومی هاب (برای کپی دستی روی نود، اگر نخواستی پسورد بدهی):"
    cat "$HUB_PUB"
    info "اثر انگشت: $(ssh-keygen -lf "$HUB_PUB" | awk '{print $2}')"
}

# نصب کلید عمومی هاب روی یک نود با پسورد یک‌باره روت آن نود.
# پسورد فقط برای همین یک اتصال استفاده می‌شود؛ هیچ‌جا ذخیره، لاگ
# یا چاپ نمی‌شود و بلافاصله بعد از اتصال از حافظه پاک می‌شود.
# بعد از این، نود فقط با کلید هاب باز می‌شود و پسورد دیگر لازم نیست.
# کلید هاست نود هم همان‌جا در /root/.ssh/known_hosts پین می‌شود
# (ورودی کهنه همان هاست، مثل بعد از ریبیلد، اول پاک می‌شود).
push_key() { # $1 = node host
    local node="${1:-$NODE_HOST}"
    [ -n "$node" ] || die "هاست نود لازم است (‎--push-key <host>‎)"
    ensure_hub_key
    if ! python3 -c "import paramiko" 2>/dev/null; then
        step "نصب python3-paramiko برای اتصال یک‌باره"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq python3-paramiko \
            || die "نصب paramiko ناموفق بود"
    fi
    local pass
    echo "پسورد روت نود $node فقط همین یک بار پرسیده می‌شود و هیچ‌جا ذخیره نمی‌شود."
    read -r -s -p "پسورد روت $node: " pass
    echo
    [ -n "$pass" ] || die "پسورد خالی داده شد"
    step "نصب کلید هاب روی $node"
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
# پین کلید هاست (ورودی کهنه همان هاست را اول دور بریز تا بعد از ریبیلد گیر نکند)
rk = c.get_transport().get_remote_server_key()
line = "%s %s %s" % (host, rk.get_name(), rk.get_base64())
old = open(kh_path).read() if os.path.exists(kh_path) else ""
kept = [l for l in old.splitlines() if not l.startswith(host + " ")]
if line not in kept:
    kept.append(line)
open(kh_path, "w").write("\n".join(kept) + "\n")
os.chmod(kh_path, 0o600)
# افزودن کلید عمومی هاب (فقط اگر نباشد)
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
# راستی‌آزمایی: ورود فقط با کلید، با سیاست رد هاست ناشناس
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
    [ "$rc" -eq 0 ] || die "نصب کلید روی نود ناموفق بود"
    ok "کلید هاب روی $node نصب و ورود فقط با کلید راستی‌آزمایی شد؛ پسورد دور انداخته شد"
}

# ── یونیت هاب ───────────────────────────────────────────────────
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
        || die "سرویس $UNIT بالا نیامد؛ با 'journalctl -u $UNIT -n 50' لاگ را ببینید"
    # هاب روی VPS کند ممکن است چند ثانیه دیرتر گوش بدهد؛ تا ۳۰ ثانیه تلاش کن
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
    [ -n "$out" ] || die "هاب بالا آمده ولی /api/health جواب نداد"
    info "سلامت هاب: $out"
}

firewall_open_8890() {
    step "فایروال برای پورت $HUB_PORT"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$HUB_PORT/tcp" >/dev/null
        ok "ufw: پورت $HUB_PORT باز شد"
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
                    ok "iptables: پورت $HUB_PORT باز شد (سیاست ورودی بسته بود)"
                    if command -v netfilter-persistent >/dev/null 2>&1; then
                        netfilter-persistent save >/dev/null 2>&1 || true
                    else
                        warn "netfilter-persistent نیست؛ قانون iptables بعد از ریبوت نمی‌ماند مگر دستی ذخیره شود"
                    fi
                    ;;
                *) info "سیاست فایروال باز است؛ قانونی لازم نبود" ;;
            esac
        else
            info "فایروال بسته نیست یا قانون از قبل هست؛ کاری لازم نبود"
        fi
    else
        info "ابزار فایروال پیدا نشد؛ فرض بر باز بودن است"
    fi
}

install_hub() {
    step "نصب هاب (داشبورد)"
    install_deps hub
    fetch_code
    ensure_hub_key
    write_hub_unit "127.0.0.1" "" ""
    systemctl enable "$UNIT" >/dev/null 2>&1
    # نکته: enable --now یونیتِ در حال اجرا را ری‌استارت نمی‌کند؛ برای نصب دوباره
    # حتماً restart لازم است تا کد و تنظیمات تازه واقعاً بالا بیایند
    systemctl restart "$UNIT"
    hub_health http
    firewall_open_8890
    ok "هاب نصب شد؛ فعلاً فقط روی خود سرور (127.0.0.1) در دسترس است"
    warn "برای باز شدن روی اینترنت، از منو «گواهی پنل» را اجرا کنید (دامنه یا آی‌پی)"
}

install_node() {
    step "نصب نود (بدون داشبورد)"
    install_deps node
    fetch_code
    ok "نود نصب شد: موتور و اسکریپت‌های پروتکل در $INSTALL_DIR"
    info "این سرور از این به بعد از روی داشبوردِ هاب، با کلید SSH مدیریت می‌شود؛"
    info "خودش هیچ سرویسی گوش نمی‌دهد و حساب اپراتوری هم اینجا ساخته نمی‌شود."
}

# ── BBR ─────────────────────────────────────────────────────────
enable_bbr() {
    step "فعال‌سازی BBR"
    if ! modprobe tcp_bbr 2>/dev/null; then
        warn "ماژول tcp_bbr بار نشد (روی بعضی VPSها کرنل اجازه نمی‌دهد)؛ باز هم تلاش می‌کنیم"
    fi
    cat > /etc/sysctl.d/99-rahyaab-bbr.conf <<EOF
# Rahyaab: BBR congestion control + fq queueing
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-rahyaab-bbr.conf
    local cur
    cur="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'نامشخص')"
    if [ "$cur" = "bbr" ]; then
        ok "BBR فعال شد (tcp_congestion_control=bbr)"
    else
        warn "BBR تنظیم شد ولی مقدار فعلی '$cur' است؛ بعد از ریبوت دوباره چک کنید"
    fi
}

# ── گواهی ────────────────────────────────────────────────────────
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
    step "گواهی Let's Encrypt برای دامنه"
    hub_installed || die "اول هاب را نصب کنید (گزینه ۱)، بعد گواهی بگیرید"
    if [ -z "$DOMAIN" ]; then
        ask DOMAIN "دامنه پنل (مثل panel.example.com)"
    fi
    if [ -z "$EMAIL" ]; then
        ask EMAIL "ایمیل برای certbot"
    fi
    [ -n "$DOMAIN" ] && [ -n "$EMAIL" ] || die "دامنه و ایمیل لازم است"
    if ss -ltn 2>/dev/null | grep -q ':80 '; then
        die "پورت ۸۰ اشغال است؛ certbot حالت standalone به پورت ۸۰ خالی نیاز دارد"
    fi
    info "دامنه باید از اینترنت به همین سرور برسد، وگرنه اعتبارسنجی رد می‌شود"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq certbot
    certbot certonly --standalone --non-interactive --agree-tos \
        --email "$EMAIL" -d "$DOMAIN" \
        || die "صدور گواهی ناموفق بود؛ DNS دامنه و باز بودن پورت ۸۰ را چک کنید"
    local cert="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    local key="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/rahyaab-hub.sh <<EOF
#!/bin/sh
# پس از هر تمدید موفق، هاب را ری‌استارت کن تا گواهی تازه را بگیرد.
if systemctl is-active -q $UNIT; then
    systemctl restart $UNIT
fi
EOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/rahyaab-hub.sh
    apply_tls_to_hub "$cert" "$key"
    ok "گواهی دامنه فعال شد؛ تمدید خودکار با تایمر certbot انجام می‌شود"
    info "انقضا: $(cert_expiry "$cert")"
    info "آدرس پنل: https://$DOMAIN:$HUB_PORT"
}

cert_ip() {
    step "گواهی آی‌پی (self-signed + تمدید خودکار)"
    hub_installed || die "اول هاب را نصب کنید (گزینه ۱)، بعد گواهی بگیرید"
    local ip cert key
    ip="$(public_ip)"
    if [ "$ip" = "نامشخص" ]; then
        ask ip "آی‌پی عمومی سرور"
    fi
    cert="$CONF_DIR/tls/cert.pem"
    key="$CONF_DIR/tls/key.pem"
    mkdir -p "$CONF_DIR/tls"
    if [ -f "$cert" ] && [ -f "$key" ]; then
        if openssl x509 -in "$cert" -noout -checkend 2592000 >/dev/null 2>&1; then
            info "گواهی موجود هنوز بیش از ۳۰ روز اعتبار دارد؛ همان می‌ماند"
        else
            info "گواهی موجود رو به انقضاست؛ تازه ساخته می‌شود"
            rm -f "$cert" "$key"
        fi
    fi
    if [ ! -f "$cert" ]; then
        openssl req -x509 -newkey rsa:2048 -keyout "$key" -out "$cert" -days 825 -nodes -subj "/CN=$ip" -addext "subjectAltName=IP:$ip" || die "ساخت گواهی ناموفق بود"
        chmod 600 "$key"; chmod 644 "$cert"
        ok "گواهی self-signed برای آی‌پی $ip ساخته شد (۸۲۵ روز)"
    fi
    cat > /usr/local/bin/rahyaab-renew-ip-cert.sh <<EOF
#!/bin/sh
# اگر گواهی آی‌پی کمتر از ۳۰ روز اعتبار داشت، تازه بساز و هاب را ری‌استارت کن.
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
    ok "گواهی آی‌پی فعال شد؛ تایمر روزانه پیش از انقضا خودش تمدید می‌کند"
    info "اثر انگشت (با مرورگر مقایسه کنید): $(cert_fingerprint "$cert")"
    info "انقضا: $(cert_expiry "$cert")"
    info "آدرس پنل: https://$ip:$HUB_PORT"
    warn "گواهی self-signed است؛ مرورگر بار اول هشدار می‌دهد تا تاییدش کنید"
}

cert_custom() {
    step "گواهی آماده خودتان"
    hub_installed || die "اول هاب را نصب کنید (گزینه ۱)، بعد گواهی بدهید"
    if [ -z "$CERT_PATH" ]; then ask CERT_PATH "مسیر فایل گواهی (fullchain.pem)"; fi
    if [ -z "$KEY_PATH" ]; then ask KEY_PATH "مسیر فایل کلید (privkey.pem)"; fi
    [ -f "$CERT_PATH" ] || die "فایل گواهی پیدا نشد: $CERT_PATH"
    [ -f "$KEY_PATH" ] || die "فایل کلید پیدا نشد: $KEY_PATH"
    apply_tls_to_hub "$CERT_PATH" "$KEY_PATH"
    ok "گواهی خودتان فعال شد"
    info "انقضا: $(cert_expiry "$CERT_PATH")"
}

cert_menu() {
    echo
    echo "گواهی پنل:"
    echo "  1) دامنه — Let's Encrypt واقعی + تمدید خودکار"
    echo "  2) آی‌پی — self-signed + تمدید خودکار (مرورگر بار اول هشدار می‌دهد)"
    echo "  3) گواهی آماده خودم (مسیر فایل‌ها را می‌دهم)"
    echo "  0) برگشت"
    local c
    read -r -p "انتخاب: " c
    case "$c" in
        1) cert_domain ;;
        2) cert_ip ;;
        3) cert_custom ;;
        0) return 0 ;;
        *) warn "انتخاب نامعتبر" ;;
    esac
}

# ── وضعیت، به‌روزرسانی، حذف ─────────────────────────────────────
show_status() {
    step "وضعیت رهیاب روی این سرور"
    echo "هاب:       $(systemctl is-active "$UNIT" 2>/dev/null || echo 'نصب نیست')"
    if hub_installed; then
        grep -o 'ExecStart=.*' "/etc/systemd/system/$UNIT.service" | cut -c1-160
    fi
    echo "BBR:       $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'نامشخص')"
    if [ -f "$CONF_DIR/tls/cert.pem" ]; then
        echo "گواهی آی‌پی: انقضا $(cert_expiry "$CONF_DIR/tls/cert.pem")"
    fi
    local d
    for d in /etc/letsencrypt/live/*/; do
        [ -d "$d" ] || continue
        echo "گواهی دامنه: ${d} انقضا $(cert_expiry "${d}fullchain.pem" 2>/dev/null || echo '?')"
    done
    echo "آی‌پی عمومی: $(public_ip)"
    echo "کد:        $INSTALL_DIR"
    echo "داده:      $DATA_DIR"
}

update_code() {
    step "به‌روزرسانی کد رهیاب"
    [ -d "$INSTALL_DIR" ] || die "رهیاب نصب نیست؛ اول گزینه نصب را بزنید"
    fetch_code
    if hub_installed && systemctl is-active -q "$UNIT"; then
        systemctl restart "$UNIT"
        if grep -q 'tls-cert' "/etc/systemd/system/$UNIT.service"; then
            hub_health https
        else
            hub_health http
        fi
    fi
    ok "کد به‌روز شد؛ دیتابیس و گواهی‌ها دست نخوردند"
}

uninstall() {
    step "حذف رهیاب"
    warn "سرویس‌های رهیاب متوقف و کد پاک می‌شود"
    confirm || { info "لغو شد"; return 0; }
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
    read -r -p "داده‌ها و گواهی‌ها هم پاک شود؟ (دیتابیس هاب، حساب‌ها، جفت‌ها) [y/N] " ans
    case "$ans" in
        [yY]|[yY][eE][sS])
            rm -rf "$DATA_DIR" "$CONF_DIR"
            ok "همه‌چیز پاک شد"
            ;;
        *) info "داده‌ها نگه داشته شد: $DATA_DIR و $CONF_DIR" ;;
    esac
    ok "حذف انجام شد"
}

summary() {
    echo
    echo -e "${C_GREEN}╔══════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_GREEN}║${C_RESET}  نصب تمام شد — قدم‌های بعدی:                            ${C_GREEN}║${C_RESET}"
    echo -e "${C_GREEN}║${C_RESET}  ۱) داشبورد را باز کنید و حساب اپراتور را بسازید         ${C_GREEN}║${C_RESET}"
    echo -e "${C_GREEN}║${C_RESET}  ۲) سرورها را اضافه کنید، بنچمارک بگیرید، جفت بسازید      ${C_GREEN}║${C_RESET}"
    echo -e "${C_GREEN}║${C_RESET}  ۳) نگهبان را از داخل داشبورد فعال کنید                   ${C_GREEN}║${C_RESET}"
    echo -e "${C_GREEN}║${C_RESET}  توجه: این اسکریپت به PasarGuard دست نمی‌زند.             ${C_GREEN}║${C_RESET}"
    echo -e "${C_GREEN}╚══════════════════════════════════════════════════════╝${C_RESET}"
}

# ── منو و اجرا ───────────────────────────────────────────────────
menu() {
    while true; do
        echo
        echo "رهیاب — چه کاری انجام شود؟"
        echo "  1) نصب هاب (داشبورد) روی این سرور"
        echo "  2) نصب نود (بدون داشبورد)"
        echo "  3) فعال‌سازی BBR"
        echo "  4) گواهی پنل (دامنه / آی‌پی / آماده)"
        echo "  5) به‌روزرسانی کد رهیاب"
        echo "  6) نمایش وضعیت"
        echo "  7) حذف رهیاب"
        echo "  8) نصب کلید هاب روی نود (با پسورد یک‌باره)"
        echo "  0) خروج"
        local c
        read -r -p "انتخاب: " c
        case "$c" in
            1)
                install_hub
                echo
                echo "گواهی پنل را هم همین حالا بسازم؟"
                echo "  1) دامنه   2) آی‌پی   3) بعداً (فقط لوکال می‌ماند)"
                local g
                read -r -p "انتخاب: " g
                case "$g" in
                    1) cert_domain ;;
                    2) cert_ip ;;
                    *) warn "هاب فقط روی لوکال است؛ پیش از باز کردن روی اینترنت، گواهی بگیرید" ;;
                esac
                summary
                ;;
            2) install_node ;;
            3) enable_bbr ;;
            4) cert_menu ;;
            5) update_code ;;
            6) show_status ;;
            7) uninstall ;;
            8)
                local node
                read -r -p "هاست نود (آی‌پی یا دامنه): " node
                push_key "$node"
                ;;
            0) info "خدانگهدار"; return 0 ;;
            *) warn "انتخاب نامعتبر" ;;
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
    if [ -n "$ROLE" ]; then
        # مسیر غیرتعاملی
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
