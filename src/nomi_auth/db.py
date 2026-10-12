import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_versions(version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS accounts(
 id TEXT PRIMARY KEY, login_name TEXT NOT NULL, login_normalized TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS profiles(
 uuid TEXT PRIMARY KEY, account_id TEXT NOT NULL UNIQUE REFERENCES accounts(id),
 name TEXT NOT NULL, name_normalized TEXT NOT NULL UNIQUE, skin_hash TEXT,
 skin_model TEXT NOT NULL DEFAULT 'default', last_renamed_at INTEGER);
CREATE TABLE IF NOT EXISTS identities(
 account_id TEXT NOT NULL UNIQUE REFERENCES accounts(id), app_id TEXT NOT NULL,
 group_id TEXT NOT NULL, member_id TEXT NOT NULL, UNIQUE(app_id,group_id,member_id));
CREATE TABLE IF NOT EXISTS registrations(
 id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, poll_hash TEXT NOT NULL,
 name TEXT NOT NULL, password_hash TEXT, status TEXT NOT NULL DEFAULT 'PENDING',
 expires_at INTEGER NOT NULL, account_id TEXT REFERENCES accounts(id), error TEXT);
CREATE TABLE IF NOT EXISTS receipts(
 app_id TEXT NOT NULL, event_id TEXT NOT NULL, operation TEXT NOT NULL,
 payload_hash TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(app_id,event_id,operation));
CREATE TABLE IF NOT EXISTS tokens(
 hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), kind TEXT NOT NULL,
 client_token TEXT, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS joins(
 profile_id TEXT NOT NULL REFERENCES profiles(uuid), server_id TEXT NOT NULL,
 expires_at INTEGER NOT NULL, PRIMARY KEY(profile_id,server_id));
CREATE TABLE IF NOT EXISTS recoveries(
 id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, poll_hash TEXT NOT NULL,
 account_id TEXT REFERENCES accounts(id), status TEXT NOT NULL DEFAULT 'PENDING', expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY, action TEXT NOT NULL, account_id TEXT, detail TEXT, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS token_expiry ON tokens(expires_at);
CREATE INDEX IF NOT EXISTS registration_expiry ON registrations(expires_at);
INSERT OR IGNORE INTO schema_versions VALUES(1);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)

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
