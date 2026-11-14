"""
Local maintenance commands. Run with the service's environment and filesystem access.
"""

import argparse
import time
from pathlib import Path

from src.core.config import Settings
from src.storage.database import Database
from src.storage.maintenance import backup_data, cleanup_textures, restore_data


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
    migrate = sub.add_parser("migrate-database")
    migrate.add_argument(
        "source", type=Path, help="Schema-5 SQLite database (source is read-only)"
    )
    args = parser.parse_args()
    if args.command == "restore":
        restore_data(args.archive, args.destination)
        print(f"Restored data directory: {args.destination}")
        return
    settings = Settings()
    database = Database.from_settings(settings)
    if args.command == "migrate-database":
        from src.storage.transfer import import_sqlite

        counts = import_sqlite(args.source, database)
        print(f"Migration verified: {sum(counts.values())} rows; source unchanged.")
        return
    if args.command == "backup":
        backup_data(database, args.destination)
        print(f"Complete data snapshot: {args.destination}")
        return
    timestamp = int(time.time())
    if args.command == "cleanup":
        database.cleanup(timestamp)
        cleanup_textures(database, timestamp)
        print(
            "Expired transient data deleted; receipts and audit retained for one day."
        )
        return
    with database.write() as connection:
        row = connection.execute(
            "SELECT id FROM accounts WHERE login_normalized=?",
            (args.login_name.lower(),),
        ).fetchone()
        if not row:
            parser.error("Account not found")
        status = "disabled" if args.command == "disable" else "active"
        connection.execute(
            "UPDATE accounts SET status=? WHERE id=?", (status, row["id"])
        )
        connection.execute("DELETE FROM tokens WHERE account_id=?", (row["id"],))
        connection.execute(
            "DELETE FROM joins WHERE profile_id IN (SELECT uuid FROM profiles WHERE account_id=?)",
            (row["id"],),
        )
        connection.execute(
            "INSERT INTO audit(action,account_id,created_at) VALUES(?,?,?)",
            (args.command, row["id"], timestamp),
        )
        print(f"Account {args.login_name}: {status}")


if __name__ == "__main__":
    main()
