import hashlib
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pymysql
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_service import create_account, login, request_account, verify

from src.app import create_app
from src.core.config import Settings
from src.storage.database import Database
from src.storage.maintenance import backup_data, restore_data
from src.storage.transfer import TABLES, import_sqlite


@pytest.fixture
def mysql_settings(database_settings):
    if database_settings.database_backend == "sqlite":
        pytest.skip("MySQL-specific test")
    return database_settings


def test_backend_configuration_is_explicit_and_password_is_redacted(tmp_path):
    values = {
        "data_dir": tmp_path,
        "bot_token": "x" * 32,
        "bot_app_id": "app",
        "group_openid": "group",
    }
    assert Settings(**values).database_backend == "sqlite"
    assert Settings(**values, database_backend="mariadb").database_backend == "mariadb"
    assert "very-private-password" not in repr(
        Settings(**values, mysql_password="very-private-password")
    )
    with pytest.raises(ValidationError):
        Settings(**values, database_backend="other")
    with pytest.raises(ValidationError):
        Settings(**values, database_backend="mysql", mysql_database="")


def test_cross_instance_first_claimant_wins(mysql_settings):
    first = TestClient(create_app(mysql_settings))
    second = TestClient(create_app(mysql_settings))
    request = request_account(first)
    with ThreadPoolExecutor(2) as executor:
        futures = [
            executor.submit(verify, client, request, member=str(i), event=str(i))
            for i, client in enumerate((first, second))
        ]
        assert sorted(f.result().status_code for f in futures) == [200, 409]
    with first.app.state.db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1


def test_writer_lock_and_rollback_across_instances(mysql_settings):
    first = Database.from_settings(mysql_settings)
    second = Database.from_settings(mysql_settings)
    entered = Event()

    def writer():
        entered.set()
        with second.write() as conn:
            conn.execute("INSERT INTO accounts VALUES('second','Bob','bob','active',1)")

    with ThreadPoolExecutor(1) as executor:
        with pytest.raises(RuntimeError, match="rollback"), first.write() as conn:
            conn.execute(
                "INSERT INTO accounts VALUES('first','Alice','alice','active',1)"
            )
            future = executor.submit(writer)
            assert entered.wait(2)
            assert not future.done()
            with second.read() as reader:
                assert (
                    reader.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0
                )
            raise RuntimeError("rollback")
        future.result(timeout=5)
    with first.read() as conn:
        assert conn.execute("SELECT id FROM accounts").fetchone()[0] == "second"


def test_sqlite_migration_preserves_sessions_key_and_every_row(
    mysql_settings, tmp_path
):
    source_cfg = mysql_settings.model_copy(
        update={"database_backend": "sqlite", "data_dir": tmp_path / "original"}
    )
    source_app = create_app(source_cfg)
    source_client = TestClient(source_app)
    create_account(source_client)
    session = login(source_client)
    archive = tmp_path / "snapshot.tar.gz"
    backup_data(source_app.state.db, archive)
    restored = tmp_path / "restored"
    restore_data(archive, restored)
    source_file = restored / "nomi-auth.sqlite3"
    before = hashlib.sha256(source_file.read_bytes()).digest()
    target_cfg = mysql_settings.model_copy(update={"data_dir": restored})
    target = Database.from_settings(target_cfg)
    counts = import_sqlite(source_file, target)
    assert counts["accounts"] == counts["profiles"] == counts["identities"] == 1
    assert counts["tokens"] >= 3
    assert hashlib.sha256(source_file.read_bytes()).digest() == before
    with pytest.raises(ValueError, match="not empty"):
        import_sqlite(source_file, target)
    migrated = TestClient(create_app(target_cfg))
    assert (
        migrated.post(
            "/api/yggdrasil/authserver/validate", json=session["game"]
        ).status_code
        == 204
    )
    assert (
        login(migrated, event="after-migration")["game"]["selectedProfile"]
        == session["game"]["selectedProfile"]
    )
    assert (restored / "texture-signing.pem").read_bytes() == (
        source_cfg.data_dir / "texture-signing.pem"
    ).read_bytes()
    mysql_backup = tmp_path / "mysql-backup.tar.gz"
    backup_data(target, mysql_backup)
    restore_data(mysql_backup, tmp_path / "back-to-sqlite")
    sqlite_cfg = source_cfg.model_copy(update={"data_dir": tmp_path / "back-to-sqlite"})
    assert (
        TestClient(create_app(sqlite_cfg))
        .post("/api/yggdrasil/authserver/validate", json=session["game"])
        .status_code
        == 204
    )


def test_import_failure_rolls_back_all_tables(mysql_settings, tmp_path):
    source = Database(tmp_path / "source.sqlite3")
    with source.write() as conn:
        conn.execute(
            "INSERT INTO accounts VALUES('account','Alice','alice','active',1)"
        )
        # Deliberately exceed MySQL's supported identifier size after an account was copied.
        conn.execute(
            "INSERT INTO profiles(uuid,account_id,name,name_normalized) VALUES(?,?,?,?)",
            ("z" * 65, "account", "Alice", "alice"),
        )
    target = Database.from_settings(mysql_settings)
    with pytest.raises(pymysql.DataError):
        import_sqlite(source.path, target)
    with target.read() as conn:
        for table in TABLES:
            if table != "schema_versions":
                assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
        assert (
            conn.execute("SELECT MAX(version) FROM schema_versions").fetchone()[0] == 5
        )


def test_connection_failure_returns_503_without_credentials(
    mysql_settings, monkeypatch
):
    app = create_app(mysql_settings)

    def unavailable():
        raise pymysql.OperationalError(2003, "private-connection-detail")

    monkeypatch.setattr(app.state.db, "connect", unavailable)
    response = TestClient(app).get("/health")
    assert response.status_code == 503
    assert response.json()["code"] == "DATABASE_UNAVAILABLE"
    assert "private-connection-detail" not in response.text


def test_mariadb_alias_and_writer_timeout_release(mysql_settings):
    cfg = mysql_settings.model_copy(
        update={"database_backend": "mariadb", "database_timeout": 1}
    )
    first = Database.from_settings(mysql_settings)
    second = Database.from_settings(cfg)
    with (
        first.write(),
        pytest.raises(pymysql.OperationalError, match="writer"),
        second.write(),
    ):
        pytest.fail("Concurrent writer acquired the lock")
    with second.write() as conn:
        conn.execute(
            "INSERT INTO accounts VALUES('after-timeout','Bob','bob','active',1)"
        )
    assert TestClient(create_app(cfg)).get("/health").status_code == 200


def test_newer_schema_is_rejected_without_changing_it(mysql_settings):
    db = Database.from_settings(mysql_settings)
    with db.write() as conn:
        conn.execute("INSERT INTO schema_versions VALUES(6)")
    try:
        with pytest.raises(RuntimeError, match="Unsupported"):
            Database.from_settings(mysql_settings)
        with db.read() as conn:
            assert (
                conn.execute("SELECT MAX(version) FROM schema_versions").fetchone()[0]
                == 6
            )
    finally:
        with db.write() as conn:
            conn.execute("DELETE FROM schema_versions WHERE version=6")


def test_database_selection_from_env_file(tmp_path):
    env_file = tmp_path / "settings.env"
    env_file.write_text(
        "NOMI_DATABASE_BACKEND=mariadb\nNOMI_MYSQL_PORT=13306\n"
        "NOMI_MYSQL_DATABASE=example\nNOMI_MYSQL_USER=example\n"
        "NOMI_MYSQL_PASSWORD=file-secret\nNOMI_BOT_TOKEN="
        + "x" * 32
        + "\nNOMI_BOT_APP_ID=app\nNOMI_GROUP_OPENID=group\n"
    )
    cfg = Settings(_env_file=env_file)
    assert cfg.database_backend == "mariadb"
    assert cfg.mysql_port == 13306
    assert cfg.mysql_password.get_secret_value() == "file-secret"


def test_mysql_does_not_create_or_replace_sqlite_file(mysql_settings):
    source = mysql_settings.data_dir / "nomi-auth.sqlite3"
    source.write_bytes(b"existing sqlite must remain untouched")
    db = Database.from_settings(mysql_settings)
    with db.write() as conn:
        conn.execute("INSERT INTO accounts VALUES('case','Alice','alice','active',1)")
    assert source.read_bytes() == b"existing sqlite must remain untouched"


def test_query_failure_uses_database_error_handler(mysql_settings, monkeypatch):
    app = create_app(mysql_settings)
    monkeypatch.setattr(app.state.db, "cleanup_if_due", lambda timestamp: None)

    def unavailable():
        raise pymysql.OperationalError(2013, "private-database-detail")

    monkeypatch.setattr(app.state.db, "connect", unavailable)
    response = TestClient(app).get("/health")
    assert response.status_code == 503
    assert "private-database-detail" not in response.text


def test_cli_migration_backup_disable_and_cleanup(mysql_settings, tmp_path):
    source_cfg = mysql_settings.model_copy(
        update={"database_backend": "sqlite", "data_dir": tmp_path / "cli-source"}
    )
    source_client = TestClient(create_app(source_cfg))
    create_account(source_client)
    session = login(source_client)
    env = os.environ.copy()
    env.update(
        {
            "NOMI_DATABASE_BACKEND": "mysql",
            "NOMI_DATA_DIR": str(source_cfg.data_dir),
            "NOMI_MYSQL_HOST": mysql_settings.mysql_host,
            "NOMI_MYSQL_PORT": str(mysql_settings.mysql_port),
            "NOMI_MYSQL_DATABASE": mysql_settings.mysql_database,
            "NOMI_MYSQL_USER": mysql_settings.mysql_user,
            "NOMI_MYSQL_PASSWORD": mysql_settings.mysql_password.get_secret_value(),
            "NOMI_BOT_TOKEN": "x" * 32,
            "NOMI_BOT_APP_ID": "app",
            "NOMI_GROUP_OPENID": "group",
        }
    )

    def command(*args):
        result = subprocess.run(
            [sys.executable, "-m", "src.cli", *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    assert "Migration verified" in command(
        "migrate-database", str(source_cfg.data_dir / "nomi-auth.sqlite3")
    )
    archive = tmp_path / "cli-backup.tar.gz"
    assert "snapshot" in command("backup", str(archive))
    assert "Restored" in command(
        "restore", str(archive), str(tmp_path / "cli-restored")
    )
    assert "disabled" in command("disable", "Alice")
    target = TestClient(
        create_app(mysql_settings.model_copy(update={"data_dir": source_cfg.data_dir}))
    )
    assert (
        target.post(
            "/api/yggdrasil/authserver/validate", json=session["game"]
        ).status_code
        == 403
    )
    assert "active" in command("enable", "Alice")
    assert "Expired" in command("cleanup")
