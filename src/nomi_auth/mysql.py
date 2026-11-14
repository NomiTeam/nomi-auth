"""MySQL/MariaDB storage; preserve SQLite's serialized writer semantics."""

import hashlib
import threading
from collections.abc import Mapping
from contextlib import contextmanager

import pymysql

from .db import Database

# Keep column order compatible with SQLite and existing positional inserts.
# Indexed identifiers have explicit bounds; other payloads remain unrestricted TEXT.
MYSQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_versions(version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS accounts(
 id VARCHAR(64) PRIMARY KEY, login_name VARCHAR(128) NOT NULL,
 login_normalized VARCHAR(128) NOT NULL UNIQUE,
 status VARCHAR(32) NOT NULL DEFAULT 'active', created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS profiles(
 uuid VARCHAR(64) PRIMARY KEY, account_id VARCHAR(64) NOT NULL UNIQUE,
 name VARCHAR(128) NOT NULL, name_normalized VARCHAR(128) NOT NULL UNIQUE, skin_hash VARCHAR(64),
 skin_model VARCHAR(32) NOT NULL DEFAULT 'default', last_renamed_at BIGINT,
 FOREIGN KEY(account_id) REFERENCES accounts(id));
CREATE TABLE IF NOT EXISTS identities(
 account_id VARCHAR(64) NOT NULL UNIQUE, app_id VARCHAR(128) NOT NULL,
 group_id VARCHAR(128) NOT NULL, member_id VARCHAR(128) NOT NULL,
 UNIQUE(app_id,group_id,member_id), FOREIGN KEY(account_id) REFERENCES accounts(id));
CREATE TABLE IF NOT EXISTS registrations(
 id VARCHAR(64) PRIMARY KEY, code_hash VARCHAR(64) NOT NULL UNIQUE, poll_hash VARCHAR(64) NOT NULL,
 name VARCHAR(128) NOT NULL, status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
 expires_at BIGINT NOT NULL, account_id VARCHAR(64), error TEXT,
 session_issued INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(account_id) REFERENCES accounts(id),
 INDEX registration_expiry(expires_at));
CREATE TABLE IF NOT EXISTS receipts(
 app_id VARCHAR(128) NOT NULL, event_id VARCHAR(256) NOT NULL, operation VARCHAR(32) NOT NULL,
 payload_hash VARCHAR(64) NOT NULL, result TEXT NOT NULL, created_at BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(app_id,event_id,operation), INDEX receipt_created(created_at));
CREATE TABLE IF NOT EXISTS tokens(
 hash VARCHAR(64) PRIMARY KEY, account_id VARCHAR(64) NOT NULL, kind VARCHAR(32) NOT NULL,
 client_token TEXT, expires_at BIGINT NOT NULL, FOREIGN KEY(account_id) REFERENCES accounts(id),
 INDEX token_expiry(expires_at));
CREATE TABLE IF NOT EXISTS joins(
 profile_id VARCHAR(64) NOT NULL, server_id VARCHAR(256) NOT NULL,
 expires_at BIGINT NOT NULL, PRIMARY KEY(profile_id,server_id),
 FOREIGN KEY(profile_id) REFERENCES profiles(uuid));
CREATE TABLE IF NOT EXISTS login_requests(
 id VARCHAR(64) PRIMARY KEY, code_hash VARCHAR(64) NOT NULL UNIQUE, poll_hash VARCHAR(64) NOT NULL,
 account_id VARCHAR(64), status VARCHAR(32) NOT NULL DEFAULT 'PENDING', expires_at BIGINT NOT NULL,
 session_issued INTEGER NOT NULL DEFAULT 0, app_id VARCHAR(128), group_id VARCHAR(128),
 member_id VARCHAR(128), error TEXT, FOREIGN KEY(account_id) REFERENCES accounts(id));
CREATE TABLE IF NOT EXISTS audit(
 id BIGINT AUTO_INCREMENT PRIMARY KEY, action TEXT NOT NULL, account_id VARCHAR(64),
 detail TEXT, created_at BIGINT NOT NULL, INDEX audit_created(created_at));
CREATE TABLE IF NOT EXISTS refresh_retries(
 old_hash VARCHAR(64) PRIMARY KEY, request_hash VARCHAR(64) NOT NULL, nonce TEXT NOT NULL,
 game_hash VARCHAR(64) NOT NULL, refresh_hash VARCHAR(64) NOT NULL, expires_at BIGINT NOT NULL,
 FOREIGN KEY(game_hash) REFERENCES tokens(hash) ON DELETE CASCADE,
 FOREIGN KEY(refresh_hash) REFERENCES tokens(hash) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS login_retries(
 request_id VARCHAR(64) PRIMARY KEY, poll_hash VARCHAR(64) NOT NULL, request_hash VARCHAR(64) NOT NULL,
 nonce TEXT NOT NULL, game_hash VARCHAR(64) NOT NULL, refresh_hash VARCHAR(64) NOT NULL,
 management_hash VARCHAR(64) NOT NULL, expires_at BIGINT NOT NULL,
 FOREIGN KEY(game_hash) REFERENCES tokens(hash) ON DELETE CASCADE,
 FOREIGN KEY(refresh_hash) REFERENCES tokens(hash) ON DELETE CASCADE,
 FOREIGN KEY(management_hash) REFERENCES tokens(hash) ON DELETE CASCADE);
"""


class Row(Mapping):
    def __init__(self, names, values):
        self._values = values
        self._mapping = dict(zip(names, values))

    def __getitem__(self, key):
        return self._values[key] if isinstance(key, int) else self._mapping[key]

    def __iter__(self):
        return iter(self._mapping)

    def __len__(self):
        return len(self._mapping)


class Result:
    def __init__(self, rows):
        self.rows = iter(rows)

    def fetchone(self):
        return next(self.rows, None)

    def fetchall(self):
        return list(self.rows)

    def __iter__(self):
        return self.rows


class Connection:
    def __init__(self, raw):
        self.raw = raw

    def execute(self, sql, parameters=()):
        # Queries are application constants; user values always go through driver binding.
        sql = sql.replace("%", "%%").replace("?", "%s")
        with self.raw.cursor() as cursor:
            cursor.execute(sql, parameters)
            names = [c[0] for c in cursor.description] if cursor.description else []
            rows = [Row(names, values) for values in cursor.fetchall()] if names else []
        return Result(rows)

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()


class MySQLDatabase(Database):
    backend = "mysql"

    def __init__(self, settings):
        self.settings = settings
        # Files remain in data_dir independently of the selected SQL backend.
        self.path = settings.data_dir / "nomi-auth.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._cleanup_lock = threading.Lock()
        self._last_cleanup = None
        self.lock_name = "nomi-auth:" + hashlib.sha256(settings.mysql_database.encode()).hexdigest()[:48]
        with self.write() as conn:
            tables = {row[0] for row in conn.execute("SHOW TABLES")}
            if "schema_versions" in tables:
                versions = [row[0] for row in conn.execute("SELECT version FROM schema_versions")]
                if versions and max(versions) != 5:
                    raise RuntimeError("Unsupported MySQL database schema")
            elif tables:
                raise RuntimeError("MySQL destination must be a dedicated empty database")
            # DDL implicitly commits on MySQL; the connection-scoped lock still holds.
            for statement in MYSQL_SCHEMA.split(";"):
                if statement.strip():
                    conn.execute(statement + " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin")
            versions = [row[0] for row in conn.execute("SELECT version FROM schema_versions")]
            if versions and max(versions) != 5:
                raise RuntimeError("Unsupported MySQL database schema")
            if not versions:
                for version in (2, 3, 4, 5):
                    conn.execute("INSERT INTO schema_versions VALUES(?)", (version,))

    def connect(self):
        cfg = self.settings
        raw = pymysql.connect(
            host=cfg.mysql_host,
            port=cfg.mysql_port,
            user=cfg.mysql_user,
            password=cfg.mysql_password.get_secret_value(),
            database=cfg.mysql_database,
            unix_socket=cfg.mysql_unix_socket,
            charset="utf8mb4",
            autocommit=True,
            connect_timeout=cfg.database_timeout,
            read_timeout=cfg.database_timeout,
            write_timeout=cfg.database_timeout,
            sql_mode="STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION",
            ssl_ca=str(cfg.mysql_ssl_ca) if cfg.mysql_ssl_ca else None,
            ssl_verify_cert=bool(cfg.mysql_ssl_ca),
            ssl_verify_identity=bool(cfg.mysql_ssl_ca),
        )
        return Connection(raw)

    @contextmanager
    def write(self):
        with self.read() as conn:
            locked = conn.execute(
                "SELECT GET_LOCK(?, ?)", (self.lock_name, self.settings.database_timeout)
            ).fetchone()[0]
            if locked != 1:
                raise pymysql.OperationalError(1205, "Timed out waiting for Nomi database writer")
            # The read context closes this connection, releasing the advisory lock on every exit.
            conn.raw.begin()
            try:
                yield conn
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
