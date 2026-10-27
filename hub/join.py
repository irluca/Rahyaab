"""Node join: one command + panel code (Kariz-style), Smite-style auto-detected IP.

Master install generates a single-use join token and prints the join
command. The node pastes that command; its installer phones home to
POST /api/join with the token + its own SSH host key. The hub:

- validates the token (one successful use, then it is deleted),
- creates the node server record with the request's source IP
  (auto-detected, never typed by the operator),
- pins the node's host key into the hub's known_hosts (stale lines
  for that host removed first, so a rebuilt node re-joins cleanly),
- returns the hub public key for the node to authorise,
- creates the first pair (master = iran, node = foreign) if none
  exists, and enqueues a full_setup job that measures, deploys the
  first tunnel and installs the healer.

No login is needed for /api/join: the token is the credential. A
pair that already has a current protocol gets no new job — joining
never redeploys a live pair on its own.
"""

import hmac
import os
import secrets

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


def join_node(store, body: dict, source_ip: str,
              token_file: str | None = None,
              pubkey_file: str | None = None,
              known_hosts: str | None = None,
              hub_key: str | None = None) -> dict:
    """Process one /api/join request. Returns server, pair, job, pubkey."""
    token_file = token_file or token_path()
    pubkey_file = pubkey_file or pubkey_path()
    known_hosts = known_hosts or known_hosts_path()
    hub_key = hub_key or hub_key_path()

    presented = (body.get("token") or "").strip()
    saved = read_token(token_file)
    if not presented or saved is None or not hmac.compare_digest(presented, saved):
        raise JoinError(403, "invalid join token")
    name = (body.get("name") or DEFAULT_NODE_NAME).strip() or DEFAULT_NODE_NAME
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
        if server["name"] == name:
            node = server
    if master is None:
        raise JoinError(400, "master server record missing; register the master first")
    if node is not None:
        if node["host"] != source_ip or (node.get("port") or 22) != ssh_port:
            store.update_server_host(node["id"], source_ip, ssh_port)
            node = store.get_server(node["id"])
    else:
        node = store.create_server({
            "name": name, "host": source_ip, "port": ssh_port,
            "username": "root", "key_path": None, "notes": "join",
        })
    pin_host_key(known_hosts, source_ip, ssh_port, key_type, key_b64)

    pair = None
    for existing in store.list_pairs():
        if existing["name"] == DEFAULT_PAIR_NAME:
            pair = existing
            break
    if pair is None:
        from hub.wizard import next_inner_pair
        inner_iran, inner_foreign = next_inner_pair(store)
        pair = store.create_pair({
            "name": DEFAULT_PAIR_NAME,
            "iran_server_id": master["id"],
            "foreign_server_id": node["id"],
            "healer_server_id": master["id"],
            "frontend_port": 443,
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
