"""
Lossless, transactional data transfer through a portable SQLite snapshot.
"""

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from .database_types import Connection
from .db import Database

TABLES = (
    "schema_versions",
    "accounts",
    "profiles",
    "identities",
    "registrations",
    "receipts",
    "tokens",
    "joins",
    "login_requests",
    "audit",
    "refresh_retries",
    "login_retries",
)


def readonly_snapshot(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise FileNotFoundError(path)
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def copy_rows(source: Connection, target: Connection) -> dict[str, int]:
    """
    Copy explicit columns, since backend column order is not part of the data contract.
    """
    counts = {}
    for table in TABLES:
        records = source.execute(f"SELECT * FROM {table}").fetchall()
        for record in records:
            columns = list(record.keys())
            column_list = ",".join(columns)
            placeholders = ",".join("?" for _ in columns)
            values = tuple(record[column] for column in columns)
            target.execute(
                f"INSERT INTO {table} ({column_list}) VALUES({placeholders})", values
            )
        counts[table] = len(records)
    return counts


def export_sqlite(source: Connection, destination: Path) -> dict[str, int]:
    """
    Export an already locked connection into a portable SQLite snapshot.
    """
    snapshot = Database(destination)
    with snapshot.write() as target:
        target.execute("DELETE FROM schema_versions")
        return copy_rows(source, target)


def import_sqlite(source_path: Path, target: Database) -> dict[str, int]:
    """
    Import into an empty database without changing the source file.
    The target transaction contains all data changes and their verification.
    """
    if target.backend != "mysql":
        raise ValueError("Migration destination must use mysql or mariadb")

    with closing(readonly_snapshot(source_path)) as source:
        source.execute("BEGIN")
        _check_source(source)
        # No DDL here: a failed insert or comparison rolls back every table.
        with target.write() as destination:
            _check_empty(destination)
            destination.execute("DELETE FROM schema_versions")
            counts = copy_rows(source, destination)
            _verify_import(source, destination, counts)
    return counts


def _check_source(source: sqlite3.Connection) -> None:
    if source.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ValueError("Source database is corrupt")
    if source.execute("PRAGMA foreign_key_check").fetchone():
        raise ValueError("Source database has invalid references")
    versions = {
        record[0] for record in source.execute("SELECT version FROM schema_versions")
    }
    if max(versions, default=0) != 5 or 2 not in versions:
        raise ValueError("Upgrade source SQLite to schema 5 before migration")


def _check_empty(destination: Connection) -> None:
    for table in TABLES:
        if table == "schema_versions":
            continue
        record = destination.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
        if record is not None:
            raise ValueError("Destination database is not empty; refusing to overwrite")


def _verify_import(
    source: sqlite3.Connection, destination: Connection, counts: dict[str, int]
) -> None:
    for table, count in counts.items():
        actual_count = destination.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[
            0
        ]
        if actual_count != count:
            raise ValueError("Imported row counts do not match")

        # Compare all values, not just row counts: credentials and UUIDs must match.
        columns = [
            record[1] for record in source.execute(f"PRAGMA table_info({table})")
        ]
        expected = _table_values(source, table, columns)
        actual = _table_values(destination, table, columns)
        if expected != actual:
            raise ValueError("Imported data differs from source")


def _table_values(
    connection: Connection, table: str, columns: list[str]
) -> list[tuple[Any, ...]]:
    records = connection.execute(f"SELECT * FROM {table}")
    values = [tuple(record[column] for column in columns) for record in records]
    return sorted(values)
