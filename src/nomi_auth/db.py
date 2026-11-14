import sqlite3
import threading
from collections.abc import Generator
from contextlib import closing, contextmanager
from pathlib import Path

from .config import Settings
from .database_types import Connection

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_versions(version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS accounts(
 id TEXT PRIMARY KEY, login_name TEXT NOT NULL, login_normalized TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL DEFAULT 'active', created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS profiles(
 uuid TEXT PRIMARY KEY, account_id TEXT NOT NULL UNIQUE REFERENCES accounts(id),
 name TEXT NOT NULL, name_normalized TEXT NOT NULL UNIQUE, skin_hash TEXT,
 skin_model TEXT NOT NULL DEFAULT 'default', last_renamed_at INTEGER);
CREATE TABLE IF NOT EXISTS identities(
 account_id TEXT NOT NULL UNIQUE REFERENCES accounts(id), app_id TEXT NOT NULL,
 group_id TEXT NOT NULL, member_id TEXT NOT NULL, UNIQUE(app_id,group_id,member_id));
CREATE TABLE IF NOT EXISTS registrations(
 id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, poll_hash TEXT NOT NULL,
 name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING',
 expires_at INTEGER NOT NULL, account_id TEXT REFERENCES accounts(id), error TEXT,
 session_issued INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS receipts(
 app_id TEXT NOT NULL, event_id TEXT NOT NULL, operation TEXT NOT NULL,
 payload_hash TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(app_id,event_id,operation));
CREATE TABLE IF NOT EXISTS tokens(
 hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), kind TEXT NOT NULL,
 client_token TEXT, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS joins(
 profile_id TEXT NOT NULL REFERENCES profiles(uuid), server_id TEXT NOT NULL,
 expires_at INTEGER NOT NULL, PRIMARY KEY(profile_id,server_id));
CREATE TABLE IF NOT EXISTS login_requests(
 id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, poll_hash TEXT NOT NULL,
 account_id TEXT REFERENCES accounts(id), status TEXT NOT NULL DEFAULT 'PENDING', expires_at INTEGER NOT NULL,
 session_issued INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY, action TEXT NOT NULL, account_id TEXT, detail TEXT, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS token_expiry ON tokens(expires_at);
CREATE INDEX IF NOT EXISTS registration_expiry ON registrations(expires_at);
CREATE TABLE IF NOT EXISTS refresh_retries(
 old_hash TEXT PRIMARY KEY, request_hash TEXT NOT NULL, nonce TEXT NOT NULL,
 game_hash TEXT NOT NULL REFERENCES tokens(hash) ON DELETE CASCADE,
 refresh_hash TEXT NOT NULL REFERENCES tokens(hash) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS login_retries(
 request_id TEXT PRIMARY KEY, poll_hash TEXT NOT NULL, request_hash TEXT NOT NULL, nonce TEXT NOT NULL,
 game_hash TEXT NOT NULL REFERENCES tokens(hash) ON DELETE CASCADE,
 refresh_hash TEXT NOT NULL REFERENCES tokens(hash) ON DELETE CASCADE,
 management_hash TEXT NOT NULL REFERENCES tokens(hash) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL);
"""


class Database:
    backend = "sqlite"

    @classmethod
    def from_settings(cls, settings: Settings) -> "Database":
        if settings.database_backend == "sqlite":
            return cls(settings.data_dir / "nomi-auth.sqlite3")
        from .mysql import MySQLDatabase

        return MySQLDatabase(settings)

    def __init__(self, path: Path) -> None:
        self.path = path
        self._cleanup_lock = threading.Lock()
        self._last_cleanup: int | None = None
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect_sqlite()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(SCHEMA)
        with self.write() as connection:
            self._upgrade_sqlite(connection)

    def _upgrade_sqlite(self, connection: Connection) -> None:
        versions = [
            record[0]
            for record in connection.execute("SELECT version FROM schema_versions")
        ]
        if versions and max(versions) > 5:
            raise RuntimeError("Database schema is newer than this application")

        self._remove_password_columns(connection)
        connection.execute("DROP TABLE IF EXISTS recoveries")
        if 2 not in versions:
            # Passwordless authentication cannot reuse sessions from the old mechanism.
            connection.execute("DELETE FROM tokens")
            connection.execute("DELETE FROM joins")
        connection.execute("INSERT OR IGNORE INTO schema_versions VALUES(2)")

        self._upgrade_login_requests(connection)
        connection.execute("INSERT OR IGNORE INTO schema_versions VALUES(3)")
        self._upgrade_receipts(connection)
        connection.execute("INSERT OR IGNORE INTO schema_versions VALUES(4)")
        connection.execute("INSERT OR IGNORE INTO schema_versions VALUES(5)")

    def _remove_password_columns(self, connection: Connection) -> None:
        for table in ("accounts", "registrations"):
            columns = self._sqlite_columns(connection, table)
            if "password_hash" in columns:
                connection.execute(f"ALTER TABLE {table} DROP COLUMN password_hash")
            if table == "registrations" and "session_issued" not in columns:
                connection.execute(
                    "ALTER TABLE registrations ADD COLUMN session_issued INTEGER NOT NULL DEFAULT 0"
                )

    def _upgrade_login_requests(self, connection: Connection) -> None:
        columns = self._sqlite_columns(connection, "login_requests")
        for column in ("app_id", "group_id", "member_id", "error"):
            if column not in columns:
                connection.execute(
                    f"ALTER TABLE login_requests ADD COLUMN {column} TEXT"
                )

    def _upgrade_receipts(self, connection: Connection) -> None:
        if "created_at" not in self._sqlite_columns(connection, "receipts"):
            connection.execute(
                "ALTER TABLE receipts ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0"
            )
            connection.execute(
                "UPDATE receipts SET created_at=unixepoch() WHERE created_at=0"
            )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS receipt_created ON receipts(created_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS audit_created ON audit(created_at)"
        )

    def _sqlite_columns(self, connection: Connection, table: str) -> set[str]:
        return {
            record[1] for record in connection.execute(f"PRAGMA table_info({table})")
        }

    def cleanup_if_due(self, timestamp: int) -> None:
        """
        Coalesce concurrent maintenance requests; failures remain eligible for retry.
        """
        with self._cleanup_lock:
            if (
                self._last_cleanup is not None
                and 0 <= timestamp - self._last_cleanup < 30
            ):
                return
            self.cleanup(timestamp)
            self._last_cleanup = timestamp

    def cleanup(self, timestamp: int) -> None:
        """
        Delete expired transient data without touching accounts, identities or UUIDs.
        """
        with self.write() as connection:
            for table in (
                "refresh_retries",
                "login_retries",
                "tokens",
                "joins",
                "registrations",
                "login_requests",
            ):
                connection.execute(
                    f"DELETE FROM {table} WHERE expires_at<=?", (timestamp,)
                )
            for table in ("registrations", "login_requests"):
                connection.execute(
                    f"DELETE FROM {table} WHERE status='CANCELLED' OR session_issued=1"
                )
            for table in ("receipts", "audit"):
                connection.execute(
                    f"DELETE FROM {table} WHERE created_at<=?", (timestamp - 86400,)
                )

    def connect(self) -> Connection:
        return self._connect_sqlite()

    def _connect_sqlite(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @contextmanager
    def read(self) -> Generator[Connection, None, None]:
        connection = self.connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def write(self) -> Generator[Connection, None, None]:
        with self.read() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
