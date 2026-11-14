import os

import pytest

from nomi_auth.config import Settings
from nomi_auth.db import Database
from nomi_auth.transfer import TABLES


@pytest.fixture(params=["sqlite", "mysql"])
def database_settings(request, tmp_path):
    options = {"data_dir": tmp_path, "bot_token": "x" * 32, "bot_app_id": "app", "group_openid": "group"}
    if request.param == "sqlite":
        return Settings(**options, database_backend="sqlite")
    name = os.environ.get("NOMI_TEST_MYSQL_DATABASE")
    if not name:
        pytest.skip("Set NOMI_TEST_MYSQL_DATABASE to run real MySQL/MariaDB integration tests")
    if not name.startswith("nomi_auth_test_"):
        pytest.fail("Refusing to run destructive tests outside an isolated nomi_auth_test_* database")
    cfg = Settings(**options, database_backend="mysql", mysql_database=name,
                   mysql_user=os.environ["NOMI_TEST_MYSQL_USER"],
                   mysql_password=os.environ["NOMI_TEST_MYSQL_PASSWORD"],
                   mysql_host=os.environ.get("NOMI_TEST_MYSQL_HOST", "127.0.0.1"),
                   mysql_port=int(os.environ.get("NOMI_TEST_MYSQL_PORT", "3306")))
    db = Database.from_settings(cfg)
    with db.write() as conn:
        for table in reversed(TABLES):
            if table != "schema_versions":
                conn.execute(f"DELETE FROM {table}")
    return cfg
