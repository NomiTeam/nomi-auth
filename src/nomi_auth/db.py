import sqlite3
from contextlib import contextmanager
from pathlib import Path

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
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.read() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
        # v2 removes password storage while preserving accounts, identities and UUIDs.
        with self.write() as conn:
            versions = [r[0] for r in conn.execute("SELECT version FROM schema_versions")]
            if versions and max(versions) > 3:
                raise RuntimeError("Database schema is newer than this application")
            for table in ("accounts", "registrations"):
                columns = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
                if "password_hash" in columns:
                    conn.execute(f"ALTER TABLE {table} DROP COLUMN password_hash")
                if table == "registrations" and "session_issued" not in columns:
                    conn.execute(
                        "ALTER TABLE registrations ADD COLUMN session_issued INTEGER NOT NULL DEFAULT 0"
                    )
            conn.execute("DROP TABLE IF EXISTS recoveries")
            if 2 not in versions:
                # Revoke old sessions at the authentication-mechanism boundary.
                conn.execute("DELETE FROM tokens")
                conn.execute("DELETE FROM joins")
            conn.execute("INSERT OR IGNORE INTO schema_versions VALUES(2)")
            # A claimed login may wait for a name supplied by the same group member.
            columns = {r[1] for r in conn.execute("PRAGMA table_info(login_requests)")}
            for column in ("app_id", "group_id", "member_id", "error"):
                if column not in columns:
                    conn.execute(f"ALTER TABLE login_requests ADD COLUMN {column} TEXT")
            conn.execute("INSERT OR IGNORE INTO schema_versions VALUES(3)")

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    @contextmanager
    def read(self):
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def write(self):
        with self.read() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
