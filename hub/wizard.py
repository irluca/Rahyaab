"""Full-setup wizard, step 4: register servers and pair in the hub DB.

Runs on the hub server (the same host that serves the dashboard), so
it writes the hub database directly through hub.store — no operator
account or login needed, because this runs before any account exists.

Idempotent by name: re-running with the same names returns the
existing rows instead of duplicating them. Server records carry no
key_path, so the hub executor uses its default: the hub key at
/etc/rahyaab/hub_key (see hub/ssh.py).

Inner addresses default to 10.10.11.1 (Iran) / 10.10.11.2 (foreign);
later pairs take the next free /24 (10.10.12.x, ...), so two pairs
never share an inner subnet.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hub.store import Store  # noqa: E402

DEFAULT_INNER_BASE = 11


def next_inner_pair(store: Store) -> tuple[str, str]:
    """First free 10.10.N.1 / 10.10.N.2 pair, N starting at 11."""
    used = set()
    for pair in store.list_pairs():
        inner = pair.get("inner_iran") or ""
        parts = inner.split(".")
        if len(parts) == 4 and parts[0] == "10" and parts[1] == "10":
            try:
                used.add(int(parts[2]))
            except ValueError:
                continue
    n = DEFAULT_INNER_BASE
    while n in used:
        n += 1
    return f"10.10.{n}.1", f"10.10.{n}.2"


def _find_or_create_server(store: Store, name: str, host: str) -> dict:
    for server in store.list_servers():
        if server["name"] == name:
            return server
    return store.create_server({
        "name": name, "host": host, "port": 22,
        "username": "root", "key_path": None,
        "notes": "wizard",
    })


def register_pair(db_path: str, iran_host: str, foreign_host: str,
                  pair_name: str = "جفت اصلی",
                  iran_name: str = "ایران", foreign_name: str = "خارج",
                  inner_iran: str | None = None,
                  inner_foreign: str | None = None,
                  frontend_port: int = 443) -> dict:
    """Register servers + pair; returns the pair row (decoded)."""
    store = Store(db_path)
    for pair in store.list_pairs():
        if pair["name"] == pair_name:
            return pair
    if inner_iran is None or inner_foreign is None:
        auto_iran, auto_foreign = next_inner_pair(store)
        inner_iran = inner_iran or auto_iran
        inner_foreign = inner_foreign or auto_foreign
    iran = _find_or_create_server(store, iran_name, iran_host)
    foreign = _find_or_create_server(store, foreign_name, foreign_host)
    return store.create_pair({
        "name": pair_name,
        "iran_server_id": iran["id"],
        "foreign_server_id": foreign["id"],
        "healer_server_id": iran["id"],
        "frontend_port": frontend_port,
        "current_protocol": None,
        "inner_iran": inner_iran,
        "inner_foreign": inner_foreign,
        "candidate_scores": {},
    })


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Rahyaab setup wizard: register pair")
    parser.add_argument("--db", default="/var/lib/rahyaab/hub.db")
    parser.add_argument("--iran-host", required=True)
    parser.add_argument("--foreign-host", required=True)
    parser.add_argument("--pair-name", default="جفت اصلی")
    parser.add_argument("--iran-name", default="ایران")
    parser.add_argument("--foreign-name", default="خارج")
    parser.add_argument("--inner-iran", default=None)
    parser.add_argument("--inner-foreign", default=None)
    parser.add_argument("--frontend-port", type=int, default=443)
    args = parser.parse_args(argv)
    pair = register_pair(
        args.db, args.iran_host, args.foreign_host,
        pair_name=args.pair_name, iran_name=args.iran_name,
        foreign_name=args.foreign_name, inner_iran=args.inner_iran,
        inner_foreign=args.inner_foreign, frontend_port=args.frontend_port)
    print(json.dumps(pair, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
