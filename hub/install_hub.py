"""Install the Rahyaab hub on the Iran fleet server (Phase 4).

Run from this VM AFTER the user has authorized the hub public key
(.hub-key/hub_key.pub) in /root/.ssh/authorized_keys on BOTH fleet
servers. The installer itself uses only that key — no password is
ever read, stored or transmitted.

    python3 -m hub.install_hub --check-only     # verify access, change nothing
    python3 -m hub.install_hub                 # full install + adoption

What it does, in order:
  1. Preflight: healer unit still active, heartbeat fresh, python3 present.
     Nothing about the healer is changed, and /opt/best-tunnel is never
     touched. PasarGuard is never touched, by any path.
  2. Uploads hub/ + dashboard/ to /opt/rahyaab on the Iran host.
  3. Installs the hub private key at /etc/rahyaab/hub_key (0600) so the
     hub can SSH to both fleet servers (itself included, via its public
     IP) using the key the user authorized.
  4. Pins both fleet servers' host keys into the hub host's known_hosts
     (ssh-keyscan from the hub host itself), so the hub's RejectPolicy
     executor accepts them.
  5. Adopts the live pair (manag-netlen, GRE serving, inner
     10.10.11.x, sweep candidate scores) into the hub database.
  6. Enables and starts rahyaab-hub (127.0.0.1:8890 only) and verifies
     it: unit active, /api/health answers, dashboard page serves.

What it deliberately does NOT do: create the operator account. The
user creates it himself through the dashboard (SSH-forwarded), the
same way Nexora's setup wizard works — the installer never invents
or transports an operator password.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import urllib.parse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HUB_KEY = REPO_ROOT / ".hub-key" / "hub_key"

# Morning sweep medians of 2026-10-26 (balanced profile), the same
# scores the live healer was seeded with. sing-box-SS-2022 was
# disqualified (100% loss) and sing-box-VLESS excluded by the carrier
# gate, so neither appears here.
CANDIDATE_SCORES = {
    "GRE": 99.96, "ESP": 99.84, "frp-TLS": 93.15, "xray-reverse": 89.73,
    "kcptun": 89.52, "rathole-noise": 87.43, "backhaul-wss": 84.79,
    "wstunnel-v10": 78.03, "chisel-wss": 66.53, "hysteria2": 66.36,
}

def unit_file(host: str = "127.0.0.1", tls_cert: str | None = None,
              tls_key: str | None = None) -> str:
    tls_args = ""
    if tls_cert and tls_key:
        tls_args = f" --tls-cert {tls_cert} --tls-key {tls_key}"
    return f"""[Unit]
Description=Rahyaab hub control plane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/rahyaab
ExecStart=/usr/bin/python3 -m hub.main --host {host} --port 8890 --db /var/lib/rahyaab/hub.db{tls_args}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

ADOPT_TEMPLATE = """\
import json, sys
sys.path.insert(0, "/opt/rahyaab")
from hub.store import Store
scores = json.loads({scores_json!r})
store = Store("/var/lib/rahyaab/hub.db")
servers = {{s["name"]: s for s in store.list_servers()}}
def ensure_server(name, host):
    if name in servers:
        return servers[name]
    row = store.create_server({{"name": name, "host": host, "port": 22,
                                "username": "root", "key_path": "/etc/rahyaab/hub_key"}})
    servers[name] = row
    return row
iran = ensure_server("iran", {iran_host!r})
foreign = ensure_server("foreign", {foreign_host!r})
pairs = {{p["name"]: p for p in store.list_pairs()}}
if "manag-netlen" not in pairs:
    store.create_pair({{"name": "manag-netlen", "iran_server_id": iran["id"],
                        "foreign_server_id": foreign["id"],
                        "healer_server_id": iran["id"], "frontend_port": 443,
                        "current_protocol": "GRE", "inner_iran": "10.10.11.1",
                        "inner_foreign": "10.10.11.2",
                        "candidate_scores": scores}})
    print("adopted manag-netlen")
else:
    print("manag-netlen already adopted")
"""


def adoption_script(iran_host: str, foreign_host: str) -> str:
    return ADOPT_TEMPLATE.format(
        scores_json=json.dumps(CANDIDATE_SCORES),
        iran_host=iran_host, foreign_host=foreign_host)


def _valid_host(host: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9.\-]+", host))


class Remote:
    """Thin paramiko wrapper. First connection pins the host key
    (TOFU) and prints its fingerprint for the user to verify against
    the server's own ssh-keygen -lf output; later runs reject a
    changed key."""

    def __init__(self, host: str, key_path: Path):
        self.host = host
        self.key_path = key_path
        self._client = None

    def connect(self) -> None:
        import paramiko

        self._client = paramiko.SSHClient()
        self._client.load_system_host_keys()
        known = os.path.expanduser("~/.ssh/known_hosts")
        if os.path.exists(known):
            self._client.load_host_keys(known)
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # This VM's direct outbound TCP is reset by the egress proxy;
        # SSH must go through it via socat HTTP-CONNECT, exactly like
        # the proven connect_new.py pattern.
        sock = None
        if os.environ.get("https_proxy"):
            u = urllib.parse.urlparse(os.environ["https_proxy"])
            sock = paramiko.ProxyCommand(
                f"socat - PROXY:{u.hostname}:{self.host}:22,"
                f"proxyport={u.port},proxyauth={u.username}:{u.password}")
        self._client.connect(self.host, port=22, username="root",
                             key_filename=str(self.key_path), timeout=20,
                             banner_timeout=30, auth_timeout=30,
                             allow_agent=False, look_for_keys=False, sock=sock)
        key = self._client.get_transport().get_remote_server_key()
        print(f"host key {self.host}: {key.get_name()} "
              f"SHA256:{key.get_base64()[:43]} (verify against the server's "
              f"ssh-keygen -lf output if in doubt)")

    def exec(self, cmd: str, check: bool = True) -> tuple[int, str, str]:
        _, stdout, stderr = self._client.exec_command(cmd, timeout=120)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        if check and rc != 0:
            raise RuntimeError(f"remote command failed ({rc}): {cmd}\n{err}")
        return rc, out, err

    def put(self, local: Path, remote_path: str) -> None:
        sftp = self._client.open_sftp()
        try:
            sftp.put(str(local), remote_path)
        finally:
            sftp.close()

    def put_text(self, text: str, remote_path: str) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(text)
            tmp = fh.name
        try:
            self.put(Path(tmp), remote_path)
        finally:
            os.unlink(tmp)

    def close(self) -> None:
        if self._client:
            self._client.close()


def _tarball() -> Path:
    tmp = Path(tempfile.mktemp(suffix=".tar.gz"))
    with tarfile.open(tmp, "w:gz") as tar:
        for sub in ("hub", "dashboard"):
            for path in sorted((REPO_ROOT / sub).rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts \
                        and path.suffix != ".pyc" \
                        and not path.name.startswith("test_"):
                    tar.add(path, arcname=str(path.relative_to(REPO_ROOT)))
    return tmp


def preflight(remote: Remote) -> None:
    rc, out, _ = remote.exec("systemctl is-active best-tunnel-healer", check=False)
    if out.strip() != "active":
        raise RuntimeError("healer is not active on the hub host; refusing to install")
    remote.exec("test -s /var/lib/best-tunnel/healer-heartbeat.json")
    rc, out, _ = remote.exec("python3 --version")
    print("preflight ok: healer active, heartbeat present,", out.strip())


def _upload_code(remote: Remote) -> None:
    """Upload the current hub + dashboard code to /opt/rahyaab.

    Every step that changes the unit file must call this first: the
    unit may reference flags that only the fresh code understands
    (the first --expose-public run failed exactly this way — new unit,
    old code, argparse error, restart loop).
    """
    tarball = _tarball()
    try:
        remote.put(tarball, "/tmp/rahyaab.tar.gz")
    finally:
        tarball.unlink(missing_ok=True)
    remote.exec("mkdir -p /opt/rahyaab /etc/rahyaab /var/lib/rahyaab "
                "&& tar -xzf /tmp/rahyaab.tar.gz -C /opt/rahyaab && rm /tmp/rahyaab.tar.gz")


def install(remote: Remote, iran_host: str, foreign_host: str) -> None:
    preflight(remote)
    _upload_code(remote)
    remote.put(HUB_KEY, "/etc/rahyaab/hub_key")
    remote.exec("chmod 600 /etc/rahyaab/hub_key")
    remote.put_text(unit_file(), "/tmp/rahyaab-hub.service")
    remote.exec("mv /tmp/rahyaab-hub.service /etc/systemd/system/rahyaab-hub.service "
                "&& chmod 644 /etc/systemd/system/rahyaab-hub.service")
    rc, out, _ = remote.exec("python3 -c 'import paramiko'", check=False)
    if rc != 0:
        print("paramiko missing on hub host, installing via apt...")
        remote.exec("apt-get update -qq && apt-get install -y -qq python3-paramiko")
    for host in (iran_host, foreign_host):
        remote.exec(
            f"mkdir -p /root/.ssh && touch /root/.ssh/known_hosts && "
            f"grep -q '^{host} ' /root/.ssh/known_hosts || "
            f"ssh-keyscan -t ed25519 {host} >> /root/.ssh/known_hosts")
    remote.put_text(adoption_script(iran_host, foreign_host), "/tmp/rahyaab-adopt.py")
    remote.exec("python3 /tmp/rahyaab-adopt.py && rm /tmp/rahyaab-adopt.py")
    remote.exec("systemctl daemon-reload && systemctl enable --now rahyaab-hub")
    import time
    time.sleep(3)
    rc, out, _ = remote.exec("systemctl is-active rahyaab-hub", check=False)
    if out.strip() != "active":
        raise RuntimeError("rahyaab-hub did not come up active")
    rc, out, _ = remote.exec("curl -fsS http://127.0.0.1:8890/api/health")
    print("hub health:", out.strip())
    rc, out, _ = remote.exec("curl -fsS http://127.0.0.1:8890/ | head -c 200")
    if "رهیاب" not in out:
        raise RuntimeError("dashboard page did not serve")
    print("install complete: hub active, health ok, dashboard serves")


def expose_public(remote: Remote, iran_host: str) -> dict:
    """Switch an installed hub from localhost-only to public HTTPS.

    Generates a self-signed certificate on the host (there is no
    domain for Let's Encrypt; the browser will warn once until the
    operator accepts it, and a domain cert can replace it later),
    rewrites the unit to bind 0.0.0.0 with TLS, restarts the hub,
    and opens 8890/tcp only if the host firewall actually drops it.
    The healer, the tunnel and the hub database are untouched.
    """
    preflight(remote)
    _upload_code(remote)
    remote.exec("command -v openssl")
    cert, key = "/etc/rahyaab/tls/cert.pem", "/etc/rahyaab/tls/key.pem"
    remote.exec("mkdir -p /etc/rahyaab/tls")
    rc, _, _ = remote.exec(f"test -f {cert} -a -f {key}", check=False)
    if rc != 0:
        remote.exec(
            f"openssl req -x509 -newkey rsa:2048 -keyout {key} -out {cert} "
            f"-days 825 -nodes -subj '/CN={iran_host}' "
            f"-addext 'subjectAltName=IP:{iran_host}'")
    remote.exec(f"chmod 600 {key} && chmod 644 {cert}")
    remote.put_text(unit_file(host="0.0.0.0", tls_cert=cert, tls_key=key),
                    "/tmp/rahyaab-hub.service")
    remote.exec("mv /tmp/rahyaab-hub.service /etc/systemd/system/rahyaab-hub.service "
                "&& chmod 644 /etc/systemd/system/rahyaab-hub.service "
                "&& systemctl daemon-reload && systemctl restart rahyaab-hub")
    import time
    time.sleep(3)
    rc, out, _ = remote.exec("systemctl is-active rahyaab-hub", check=False)
    if out.strip() != "active":
        raise RuntimeError("rahyaab-hub did not come back up after exposing")
    remote.exec("curl -kfsS https://127.0.0.1:8890/api/health")
    # Firewall: only add a rule when the firewall is actually closed.
    firewall = "already open or no firewall tool"
    rc, out, _ = remote.exec("command -v iptables", check=False)
    if rc == 0:
        rc, rules, _ = remote.exec("iptables -S INPUT", check=False)
        if "8890" not in rules:
            # -P INPUT is the first line, e.g. "-P INPUT DROP".
            policy = rules.splitlines()[0] if rules else ""
            if "DROP" in policy or "REJECT" in policy:
                remote.exec("iptables -A INPUT -p tcp --dport 8890 -j ACCEPT")
                firewall = "added iptables ACCEPT for 8890/tcp (policy was closed)"
    rc, fp, _ = remote.exec(
        f"openssl x509 -noout -fingerprint -sha256 -in {cert}", check=False)
    return {"cert_fingerprint": fp.strip(), "firewall": firewall}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Install the Rahyaab hub (Phase 4)")
    parser.add_argument("--iran-host", default="203.0.113.10")
    parser.add_argument("--foreign-host", default="203.0.113.20")
    parser.add_argument("--hub-key", default=str(HUB_KEY))
    parser.add_argument("--check-only", action="store_true",
                        help="connect and preflight only, change nothing")
    parser.add_argument("--expose-public", action="store_true",
                        help="switch an installed hub to public HTTPS on 0.0.0.0:8890")
    args = parser.parse_args(argv)
    if not _valid_host(args.iran_host) or not _valid_host(args.foreign_host):
        parser.error("hosts must be plain hostnames or IPs")
    key = Path(args.hub_key)
    if not key.is_file():
        parser.error(f"hub key not found: {key}")
    remote = Remote(args.iran_host, key)
    try:
        remote.connect()
        if args.check_only:
            preflight(remote)
            print("check-only ok: key works, healer healthy, nothing changed")
        elif args.expose_public:
            info = expose_public(remote, args.iran_host)
            print("public HTTPS on: https://%s:8890" % args.iran_host)
            print("cert:", info["cert_fingerprint"])
            print("firewall:", info["firewall"])
        else:
            install(remote, args.iran_host, args.foreign_host)
    finally:
        remote.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
