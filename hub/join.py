"""Node join: one command + panel code (Kariz-style), Smite-style auto-detected IP.

Master install generates a single-use join token and prints the join
command. The node pastes that command; its installer phones home to
POST /api/join with the token + its own SSH host key + its hostname.
The hub:

- validates the token (one successful use, then it is deleted),
- creates the node server record with the request's source IP
  (auto-detected, never typed by the operator); a node name that
  already belongs to a different host is suffixed (name-2, name-3)
  instead of hijacking that node's record,
- pins the node's host key into the hub's known_hosts (stale lines
  for that host removed first, so a rebuilt node re-joins cleanly),
- returns the hub public key for the node to authorise,
- creates a pair for THIS node (master = iran, node = foreign) if
  the master has no pair with this node yet, and enqueues a
  full_setup job that measures, deploys the first tunnel and installs
  that pair's own healer instance. The very first pair keeps the
  historic name; later pairs are named after their node. The pair's
  frontend port — the listener on the master that user traffic dials,
  one port per pair — is either the port the join request asked for
  or, when the request asks for none, a random five-digit port. A
  requested port is refused when it is reserved, already used by
  another pair, or already bound on the master; the random pick
  skips all three as well, checked against the master's own socket
  table (the hub runs on the master, so a local `ss` read is the
  authoritative check). A re-join never changes an existing pair's
  port: changing a live pair's port is the dashboard's change_port
  job, never a side effect of joining again.

No login is needed for /api/join: the token is the credential. A
pair that already has a current protocol gets no new job — joining
never redeploys a live pair on its own.
"""

import hmac
import os
import random
import re
import secrets
import subprocess

DEFAULT_TOKEN_PATH = "/etc/rahyaab/join.token"
DEFAULT_PUBKEY_PATH = "/etc/rahyaab/hub_key.pub"
DEFAULT_KNOWN_HOSTS = "/root/.ssh/known_hosts"
DEFAULT_HUB_KEY = "/etc/rahyaab/hub_key"
DEFAULT_PAIR_NAME = "جفت اصلی"
DEFAULT_MASTER_NAME = "ایران"
DEFAULT_NODE_NAME = "خارج"


class JoinError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def token_path() -> str:
    return os.environ.get("RAHYAAB_JOIN_TOKEN_PATH", DEFAULT_TOKEN_PATH)


def pubkey_path() -> str:
    return os.environ.get("RAHYAAB_HUB_PUBKEY_PATH", DEFAULT_PUBKEY_PATH)


def known_hosts_path() -> str:
    return os.environ.get("RAHYAAB_KNOWN_HOSTS_PATH", DEFAULT_KNOWN_HOSTS)


def hub_key_path() -> str:
    return os.environ.get("RAHYAAB_HUB_KEY_PATH", DEFAULT_HUB_KEY)


def generate_token(path: str | None = None) -> str:
    """Create a fresh single-use token (32 hex chars), mode 0600."""
    path = path or token_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    token = secrets.token_hex(16)
    with open(path, "w", encoding="utf-8") as f:
        f.write(token + "\n")
    os.chmod(path, 0o600)
    return token


def read_token(path: str | None = None) -> str | None:
    path = path or token_path()
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip() or None
    except OSError:
        return None


def _line_hosts(line: str) -> list[str]:
    """Hosts a known_hosts line covers: plain, comma list, [host]:port."""
    parts = line.split()
    if not parts:
        return []
    hosts = []
    for item in parts[0].split(","):
        if item.startswith("[") and "]:" in item:
            hosts.append(item[1:].split("]:", 1)[0])
        else:
            hosts.append(item)
    return hosts


def pin_host_key(known_hosts: str, host: str, port: int,
                 key_type: str, key_b64: str) -> None:
    """Pin one host key, dropping stale lines for that host first.

    A rebuilt node presents a new host key; keeping the old line
    would make every later connection fail closed.
    """
    parent = os.path.dirname(known_hosts)
    if parent:
        os.makedirs(parent, exist_ok=True)
    try:
        with open(known_hosts, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []
    kept = [ln for ln in lines if host not in _line_hosts(ln)]
    line = "%s %s %s" % (host, key_type, key_b64)
    if line not in kept:
        kept.append(line)
    with open(known_hosts, "w", encoding="utf-8") as f:
        f.write("\n".join(kept) + "\n")
    os.chmod(known_hosts, 0o600)


def sanitize_node_name(raw) -> str:
    """A node name safe to show and to derive a pair name from."""
    cleaned = re.sub(r"[^A-Za-z0-9_.\-]", "", (raw or "").strip())[:64]
    return cleaned or DEFAULT_NODE_NAME


def _free_name(store, wanted: str) -> str:
    """`wanted`, or the first suffixed variant no server uses."""
    taken = {s["name"] for s in store.list_servers()}
    if wanted not in taken:
        return wanted
    i = 2
    while "%s-%d" % (wanted, i) in taken:
        i += 1
    return "%s-%d" % (wanted, i)


def _free_pair_name(store, wanted: str) -> str:
    taken = {p["name"] for p in store.list_pairs()}
    if wanted not in taken:
        return wanted
    i = 2
    while "%s-%d" % (wanted, i) in taken:
        i += 1
    return "%s-%d" % (wanted, i)


# Ports a tunnel frontend may never take on the master: SSH (the
# master's own SSH port is checked separately), the system ports the
# orchestrator blacklists, and the hub panel's own port — the panel
# binds 8890 on the same host, so a frontend there would collide
# with the dashboard itself.
RESERVED_FRONTEND_PORTS = frozenset({22, 53, 68, 123, 8890})

# Random frontend ports live here: five digits, clear of the
# well-known range where other services normally listen.
RANDOM_PORT_LOW = 10000
RANDOM_PORT_HIGH = 60000


def validate_frontend_port(port, ssh_port: int = 22) -> int:
    """Validate a requested tunnel frontend port. Returns the int.

    Mirrors the orchestrator's safety gate (range + SSH/system
    blacklist) plus the hub panel port, which also binds on the
    master. Raises JoinError(400) on anything unusable.
    """
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise JoinError(400, "frontend_port must be a number")
    if not 1 <= p <= 65535:
        raise JoinError(400, "frontend_port %d is out of range" % p)
    if p == int(ssh_port or 22) or p in RESERVED_FRONTEND_PORTS:
        raise JoinError(400, "frontend_port %d is reserved" % p)
    return p


def _ss_port_free(port: int) -> bool | None:
    """True when `port` has no listener on this host (the master).

    Reads the local socket table: the hub runs on the master, so this
    is authoritative for the frontend's bind host. None when the
    table cannot be read — the caller then accepts the port on the
    strength of the other checks, and the deploy stays the backstop.
    """
    try:
        out = subprocess.run(["ss", "-tln"], capture_output=True,
                             text=True, timeout=10).stdout
    except Exception:
        return None
    marker = ":%d " % port
    tab_marker = ":%d\t" % port
    return marker not in out and tab_marker not in out


def _pair_frontend_ports(store, master_id: int) -> set[int]:
    return {int(p.get("frontend_port") or 0)
            for p in store.list_pairs()
            if p.get("iran_server_id") == master_id}


def pick_frontend_port(store, master_id: int, ssh_port: int = 22,
                       free_checker=None) -> int:
    """Pick a random free frontend port for a new pair on `master_id`.

    Skips reserved ports, ports other pairs on this master already
    use, and ports with a live listener. `free_checker` is a callable
    taking a port and returning True (free), False (bound) or None
    (unknown); it defaults to the local socket table. An unknown
    verdict is accepted — the deploy is the backstop — but a bound
    verdict always re-rolls. Raises JoinError(500) when no port is
    found after bounded tries.
    """
    used = _pair_frontend_ports(store, master_id)
    check = free_checker or _ss_port_free
    for _ in range(200):
        port = random.randint(RANDOM_PORT_LOW, RANDOM_PORT_HIGH)
        if port in used or port == int(ssh_port or 22):
            continue
        if port in RESERVED_FRONTEND_PORTS:
            continue
        if check(port) is False:
            continue
        return port
    raise JoinError(500, "could not find a free tunnel port")


def resolve_join_frontend_port(store, master: dict, body: dict,
                               free_checker=None) -> int:
    """Resolve the frontend port for a pair the join is about to create.

    An explicitly requested port is validated and refused when it is
    taken by another pair or bound on the master; an absent request
    draws a random port. Raises JoinError on a refused request.
    """
    ssh_port = int(master.get("port") or 22)
    used = _pair_frontend_ports(store, master["id"])
    requested = body.get("frontend_port")
    if requested is None or str(requested).strip() == "":
        return pick_frontend_port(store, master["id"], ssh_port, free_checker)
    port = validate_frontend_port(requested, ssh_port)
    if port in used:
        raise JoinError(400, "frontend_port %d is already used by another pair"
                        % port)
    check = free_checker or _ss_port_free
    if check(port) is False:
        raise JoinError(400, "frontend_port %d is already in use on the master"
                        % port)
    return port


def join_node(store, body: dict, source_ip: str,
              token_file: str | None = None,
              pubkey_file: str | None = None,
              known_hosts: str | None = None,
              hub_key: str | None = None,
              free_checker=None) -> dict:
    """Process one /api/join request. Returns server, pair, job, pubkey."""
    token_file = token_file or token_path()
    pubkey_file = pubkey_file or pubkey_path()
    known_hosts = known_hosts or known_hosts_path()
    hub_key = hub_key or hub_key_path()

    presented = (body.get("token") or "").strip()
    saved = read_token(token_file)
    if not presented or saved is None or not hmac.compare_digest(presented, saved):
        raise JoinError(403, "invalid join token")
    name = sanitize_node_name(body.get("name"))
    try:
        ssh_port = int(body.get("ssh_port") or 22)
    except (TypeError, ValueError):
        raise JoinError(400, "ssh_port must be a number")
    key_type = (body.get("host_key_type") or "").strip()
    key_b64 = (body.get("host_key_b64") or "").strip()
    if not key_type or not key_b64:
        raise JoinError(400, "host_key_type and host_key_b64 are required")
    if not source_ip:
        raise JoinError(400, "source address is missing")
    try:
        with open(pubkey_file, encoding="utf-8") as f:
            hub_pubkey = f.read().strip()
    except OSError:
        raise JoinError(500, "hub public key missing; run master install first")
    if not hub_pubkey:
        raise JoinError(500, "hub public key missing; run master install first")

    master = None
    node = None
    for server in store.list_servers():
        if server["name"] == DEFAULT_MASTER_NAME:
            master = server
        if (server["name"] == name and server["host"] == source_ip
                and (server.get("port") or 22) == ssh_port):
            node = server
    if master is None:
        raise JoinError(400, "master server record missing; register the master first")
    if node is None:
        # Same name but a different host is a second node, not a re-join:
        # suffix it instead of repointing the first node's record (and
        # its live pair) at a different machine. A rebuilt node keeps
        # its address in practice, so the exact match above covers it.
        name = _free_name(store, name)
        node = store.create_server({
            "name": name, "host": source_ip, "port": ssh_port,
            "username": "root", "key_path": None, "notes": "join",
        })
    pin_host_key(known_hosts, source_ip, ssh_port, key_type, key_b64)

    pair = None
    for existing in store.list_pairs():
        if (existing["iran_server_id"] == master["id"]
                and existing["foreign_server_id"] == node["id"]):
            pair = existing
            break
    if pair is None:
        from hub.wizard import next_inner_pair
        inner_iran, inner_foreign = next_inner_pair(store)
        if not store.list_pairs():
            pair_name = DEFAULT_PAIR_NAME
        else:
            pair_name = _free_pair_name(store, "جفت %s" % name)
        # A requested port applies only to a pair created here. A
        # re-join keeps the existing pair's port untouched: changing a
        # live pair's port is the change_port job, never a join side
        # effect, so a re-join body carrying a port is ignored.
        frontend_port = resolve_join_frontend_port(
            store, master, body, free_checker)
        pair = store.create_pair({
            "name": pair_name,
            "iran_server_id": master["id"],
            "foreign_server_id": node["id"],
            "healer_server_id": master["id"],
            "frontend_port": frontend_port,
            "current_protocol": None,
            "inner_iran": inner_iran,
            "inner_foreign": inner_foreign,
            "candidate_scores": {},
        })
    job = None
    if not (pair.get("current_protocol") or "").strip():
        job = store.create_job("full_setup", pair["id"], {
            "iran_host": master["host"],
            "foreign_host": node["host"],
            "pair_name": pair["name"],
            "hub_key_path": hub_key,
            "frontend_port": pair.get("frontend_port") or 443,
            "protocol": "GRE",
        })
    store.log_event("node_join", "Node %s joined from %s" % (name, source_ip),
                    pair_id=pair["id"], server_id=node["id"])
    try:
        os.remove(token_file)
    except OSError:
        pass
    return {"server": node, "pair": pair, "job": job, "hub_pubkey": hub_pubkey}


def main(argv=None) -> int:
    """CLI for install.sh: `python3 -m hub.join generate` prints a token."""
    import argparse
    parser = argparse.ArgumentParser(description="Rahyaab node join token")
    parser.add_argument("command", choices=["generate"])
    parser.add_argument("--path", default=None)
    args = parser.parse_args(argv)
    if args.command == "generate":
        print(generate_token(args.path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
