"""Lossless, transactional data transfer through a portable SQLite snapshot."""

import sqlite3
from contextlib import closing
from pathlib import Path

from .db import Database

TABLES = (
    "schema_versions", "accounts", "profiles", "identities", "registrations", "receipts",
    "tokens", "joins", "login_requests", "audit", "refresh_retries", "login_retries",
)


def readonly_snapshot(path: Path):
    if not path.is_file():
        raise FileNotFoundError(path)
    conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def copy_rows(source, target):
    """Explicit columns preserve every field, even when backend column order differs."""
    counts = {}
    for table in TABLES:
        rows = source.execute(f"SELECT * FROM {table}").fetchall()
        for row in rows:
            names = list(row.keys())
            target.execute(
                f"INSERT INTO {table} ({','.join(names)}) VALUES({','.join('?' for _ in names)})",
                tuple(row[name] for name in names),
            )
        counts[table] = len(rows)
    return counts


def export_sqlite(source, destination: Path):
    """Export an already locked SQL connection; used by MySQL complete backups."""
    snapshot = Database(destination)
    with snapshot.write() as target:
        target.execute("DELETE FROM schema_versions")
        return copy_rows(source, target)


def import_sqlite(source_path: Path, target: Database):
    """Import only into an empty database, without changing a byte of the source."""
    if target.backend != "mysql":
        raise ValueError("Migration destination must use mysql or mariadb")
    with closing(readonly_snapshot(source_path)) as source:
        source.execute("BEGIN")
        if source.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("Source database is corrupt")
        if source.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("Source database has invalid references")
        versions = {r[0] for r in source.execute("SELECT version FROM schema_versions")}
        if max(versions, default=0) != 5 or 2 not in versions:
            raise ValueError("Upgrade source SQLite to schema 5 before migration")
        # No DDL inside this transaction: failures roll back every imported row.
        with target.write() as destination:
            for table in TABLES:
                if table != "schema_versions" and destination.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                    raise ValueError("Destination database is not empty; refusing to overwrite")
            destination.execute("DELETE FROM schema_versions")
            counts = copy_rows(source, destination)
            for table, count in counts.items():
                if destination.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] != count:
                    raise ValueError("Imported row counts do not match")
                # Compare every field as well as counts, including credentials and UUIDs.
                columns = [r[1] for r in source.execute(f"PRAGMA table_info({table})")]
                expected = sorted(tuple(r[name] for name in columns) for r in source.execute(f"SELECT * FROM {table}"))
                actual = sorted(tuple(r[name] for name in columns) for r in destination.execute(f"SELECT * FROM {table}"))
                if expected != actual:
                    raise ValueError("Imported data differs from source")
        return counts
