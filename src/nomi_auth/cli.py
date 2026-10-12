"""Local maintenance commands. Run with the service's environment and filesystem access."""

import argparse
import sqlite3
import time
from pathlib import Path

from .config import Settings
from .db import Database


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    backup = sub.add_parser("backup")
    backup.add_argument("destination", type=Path)
    disable = sub.add_parser("disable")
    disable.add_argument("login_name")
    enable = sub.add_parser("enable")
    enable.add_argument("login_name")
    sub.add_parser("cleanup")
    args = parser.parse_args()
    cfg = Settings()
    db = Database(cfg.data_dir / "nomi-auth.sqlite3")
    if args.command == "backup":
        if args.destination.exists():
            parser.error("Destination already exists; select a new backup filename")
        args.destination.parent.mkdir(parents=True, exist_ok=True)
        with db.read() as source, sqlite3.connect(args.destination) as target:
            source.backup(target)
        print(f"Database snapshot: {args.destination}")
        return
    timestamp = int(time.time())
    with db.write() as conn:
        if args.command == "cleanup":
            conn.execute(
                "UPDATE registrations SET status='EXPIRED',password_hash=NULL WHERE status='PENDING' AND expires_at<=?",
                (timestamp,),
            )
            conn.execute("DELETE FROM tokens WHERE expires_at<=?", (timestamp,))
            conn.execute("DELETE FROM joins WHERE expires_at<=?", (timestamp,))
            conn.execute("DELETE FROM registrations WHERE expires_at<?", (timestamp - 86400,))
            conn.execute("DELETE FROM recoveries WHERE expires_at<?", (timestamp - 86400,))
            # Receipts retained for 24 hours past their application cleanup boundary.
            print("Expired applications and sessions cleaned; idempotency receipts retained.")
        else:
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
