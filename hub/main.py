"""Rahyaab hub entry point.

    python3 -m hub.main [--host 127.0.0.1] [--port 8890] [--db PATH]

The database defaults to ~/.local/share/rahyaab/hub.db — outside the
repo, so a checkout never carries operator accounts or job history.
First run: POST /api/setup once to create the operator account; the
endpoint refuses once any user exists.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Allow `python3 -m hub.main` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hub.server import serve  # noqa: E402
from hub.store import Store  # noqa: E402


def default_db_path() -> Path:
    return Path(os.environ.get(
        "RAHYAAB_HUB_DB",
        Path.home() / ".local" / "share" / "rahyaab" / "hub.db"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Rahyaab hub control plane")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8890)
    parser.add_argument("--db", default=str(default_db_path()))
    parser.add_argument("--tls-cert", default=None,
                        help="PEM certificate for public HTTPS mode")
    parser.add_argument("--tls-key", default=None,
                        help="PEM private key for public HTTPS mode")
    args = parser.parse_args(argv)
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert and --tls-key must be given together")
    store = Store(args.db)
    server = serve(store, host=args.host, port=args.port,
                   tls_cert=args.tls_cert, tls_key=args.tls_key,
                   enable_collector=True)
    scheme = "https" if args.tls_cert else "http"
    print(f"rahyaab hub listening on {scheme}://{args.host}:{args.port} "
          f"(db: {args.db})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.hub.worker.stop()
        if server.hub.collector is not None:
            server.hub.collector.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
