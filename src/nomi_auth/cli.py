"""Local maintenance commands. Run with the service's environment and filesystem access."""

import argparse
import time
from pathlib import Path

from .config import Settings
from .db import Database
from .maintenance import backup_data, cleanup_textures, restore_data


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    backup = sub.add_parser("backup")
    backup.add_argument("destination", type=Path)
    restore = sub.add_parser("restore")
    restore.add_argument("archive", type=Path)
    restore.add_argument("destination", type=Path)
    disable = sub.add_parser("disable")
    disable.add_argument("login_name")
    enable = sub.add_parser("enable")
    enable.add_argument("login_name")
    sub.add_parser("cleanup")
    args = parser.parse_args()
    if args.command == "restore":
        restore_data(args.archive, args.destination)
        print(f"Restored data directory: {args.destination}")
        return
    cfg = Settings()
    db = Database(cfg.data_dir / "nomi-auth.sqlite3")
    if args.command == "backup":
        backup_data(db, args.destination)
        print(f"Complete data snapshot: {args.destination}")
        return
    timestamp = int(time.time())
    if args.command == "cleanup":
        db.cleanup(timestamp)
        cleanup_textures(db, timestamp)
        print("Expired transient data deleted; receipts and audit retained for one day.")
        return
    with db.write() as conn:
        row = conn.execute(
            "SELECT id FROM accounts WHERE login_normalized=?", (args.login_name.lower(),)
        ).fetchone()
        if not row:
            parser.error("Account not found")
        status = "disabled" if args.command == "disable" else "active"
        conn.execute("UPDATE accounts SET status=? WHERE id=?", (status, row["id"]))
        conn.execute("DELETE FROM tokens WHERE account_id=?", (row["id"],))
        conn.execute(
            "DELETE FROM joins WHERE profile_id IN (SELECT uuid FROM profiles WHERE account_id=?)",
            (row["id"],),
        )
        conn.execute(
            "INSERT INTO audit(action,account_id,created_at) VALUES(?,?,?)",
            (args.command, row["id"], timestamp),
        )
        print(f"Account {args.login_name}: {status}")


if __name__ == "__main__":
    main()
