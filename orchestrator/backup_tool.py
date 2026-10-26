"""Backup and restore for the operator's own data (Phase 2).

A backup is a timestamped folder under ``~/.best_tunnel/backups/`` holding:

* ``pairs.json`` - every server pair's configuration, exactly as stored.
  Credentials are never part of it: they are never written to the database
  in the first place (they live in memory, or in the operator's separate
  ``~/.best_tunnel/live.env.txt``, which this tool deliberately never reads).
* ``database.db`` - a consistent copy of the live database, taken through
  SQLite's backup API so it is safe even while the dashboard is running.
* ``manifest.json`` - what the backup contains and when it was taken.

Restoring pairs never overwrites: a pair whose name already exists is
skipped and reported. Restoring the database file itself is a separate,
explicit step (``--with-db``) that asks for typed confirmation, because it
replaces history (benchmarks, audit trail) as well as configuration.

Usage:
    python backup_tool.py backup
    python backup_tool.py list
    python backup_tool.py restore <backup-folder> [--with-db]
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

import storage

BACKUP_ROOT = Path(os.path.expanduser("~")) / ".best_tunnel" / "backups"


def _export_pairs() -> list[dict]:
    pairs = storage.get_pairs()
    for pair in pairs:
        pair.pop("id", None)  # ids are local history, not configuration
    return pairs


def create_backup(out_dir: str | Path | None = None) -> Path:
    """Write one backup folder and return its path."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = Path(out_dir) if out_dir else BACKUP_ROOT / f"backup-{stamp}"
    target.mkdir(parents=True, exist_ok=True)

    pairs = _export_pairs()
    (target / "pairs.json").write_text(
        json.dumps(pairs, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

    db_included = False
    db_source = Path(storage.DB_PATH)
    if db_source.exists():
        src = sqlite3.connect(str(db_source))
        try:
            dst = sqlite3.connect(str(target / "database.db"))
            try:
                src.backup(dst)
                db_included = True
            finally:
                dst.close()
        finally:
            src.close()

    manifest = {
        "app": "Tunnel Studio Pro",
        "created_at": time.time(),
        "created_at_text": time.strftime("%Y-%m-%d %H:%M:%S"),
        "pairs": len(pairs),
        "db_included": db_included,
        "contains_credentials": False,
    }
    (target / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


def restore_pairs(backup_dir: str | Path) -> dict:
    """Insert the backup's pairs that do not already exist (matched by name).

    Returns {"inserted": n, "skipped": [names]}. Existing pairs are never
    modified - a restore brings back what was lost, it does not roll back
    edits made since the backup.
    """
    backup_dir = Path(backup_dir)
    exported = json.loads((backup_dir / "pairs.json").read_text(encoding="utf-8"))
    existing_names = {p["name"] for p in storage.get_pairs()}
    with storage.db_session() as conn:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(pairs)")]
    insertable = [c for c in columns if c != "id"]
    inserted, skipped = 0, []
    for pair in exported:
        if pair.get("name") in existing_names:
            skipped.append(pair.get("name"))
            continue
        data = {k: v for k, v in pair.items() if k in insertable}
        if not data:
            continue
        marks = ", ".join("?" for _ in data)
        with storage.db_session() as conn:
            conn.execute(f"INSERT INTO pairs ({', '.join(data)}) VALUES ({marks})",
                         tuple(data.values()))
        inserted += 1
    return {"inserted": inserted, "skipped": skipped}


def restore_database(backup_dir: str | Path) -> bool:
    """Replace the live database file with the backup's copy.

    The caller is responsible for the confirmation and for the dashboard
    being stopped; a database swapped under a running process is neither
    seen by it nor safe.
    """
    source = Path(backup_dir) / "database.db"
    if not source.exists():
        return False
    target = Path(storage.DB_PATH)
    target.parent.mkdir(parents=True, exist_ok=True)
    dst = sqlite3.connect(str(target))
    try:
        src = sqlite3.connect(str(source))
        try:
            src.backup(dst)
        finally:
            src.close()
    finally:
        dst.close()
    return True


def list_backups() -> list[Path]:
    if not BACKUP_ROOT.exists():
        return []
    return sorted(p for p in BACKUP_ROOT.glob("backup-*") if p.is_dir())


def main(argv: list[str]) -> int:
    if not argv or argv[0] == "backup":
        target = create_backup()
        manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
        print(f"Backup written to: {target}")
        print(f"  pairs: {manifest['pairs']}  database included: {manifest['db_included']}")
        print("  (no credentials are ever part of a backup)")
        return 0
    if argv[0] == "list":
        backups = list_backups()
        if not backups:
            print(f"No backups yet under {BACKUP_ROOT}")
            return 0
        for path in backups:
            manifest = path / "manifest.json"
            when = ""
            if manifest.exists():
                when = json.loads(manifest.read_text(encoding="utf-8")).get("created_at_text", "")
            print(f"  {path.name}   {when}")
        return 0
    if argv[0] == "restore" and len(argv) >= 2:
        folder = Path(argv[1])
        if not folder.is_dir():
            folder = BACKUP_ROOT / argv[1]
        if not folder.is_dir():
            print(f"Backup folder not found: {argv[1]}")
            return 1
        result = restore_pairs(folder)
        print(f"Pairs restored: {result['inserted']}  skipped (already exist): "
              f"{len(result['skipped'])}")
        if "--with-db" in argv:
            answer = input("This also REPLACES the current database (benchmarks and "
                           "audit history included). Type YES to continue: ")
            if answer.strip() != "YES":
                print("Database restore cancelled; pairs were still restored.")
                return 0
            if restore_database(folder):
                print("Database restored. Restart the dashboard to use it.")
            else:
                print("That backup has no database copy; nothing was replaced.")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
