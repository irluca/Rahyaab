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
  historic name; later pairs are named after their node, and each
  gets the next free frontend port on the master (443, then 444, ...),
  because two pairs on one master cannot share one frontend port.

No login is needed for /api/join: the token is the credential. A
pair that already has a current protocol gets no new job — joining
never redeploys a live pair on its own.
"""

import hmac
import os
import re
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


def _free_frontend_port(store, master_id: int) -> int:
    """First free frontend port on this master, starting at 443."""
    used = {int(p.get("frontend_port") or 0)
            for p in store.list_pairs() if p["iran_server_id"] == master_id}
    port = 443
    while port in used:
        port += 1
    return port


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
        pair = store.create_pair({
            "name": pair_name,
            "iran_server_id": master["id"],
            "foreign_server_id": node["id"],
            "healer_server_id": master["id"],
            "frontend_port": _free_frontend_port(store, master["id"]),
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
