from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NOMI_", env_file=".env", extra="ignore")
    public_url: str = "http://127.0.0.1:8000"
    data_dir: Path = Path("data")
    database_backend: Literal["sqlite", "mysql", "mariadb"] = "sqlite"
    mysql_host: str = "127.0.0.1"
    mysql_port: int = Field(default=3306, ge=1, le=65535)
    mysql_database: str = "nomi_auth"
    mysql_user: str = "nomi_auth"
    mysql_password: SecretStr = SecretStr("")
    mysql_unix_socket: str | None = None
    mysql_ssl_ca: Path | None = None
    database_timeout: int = Field(default=10, ge=1, le=120)
    bot_token: str = Field(min_length=32)
    bot_app_id: str = Field(min_length=1)
    group_openid: str = Field(min_length=1)
    group_label: str = "服务器指定群"
    registration_ttl: int = Field(default=300, ge=30, le=1800)
    rename_cooldown: int = Field(default=604800, ge=0)
    game_token_ttl: int = Field(default=86400, ge=60)
    refresh_token_ttl: int = Field(default=2592000, ge=60)
    management_token_ttl: int = Field(default=3600, ge=60)

    @model_validator(mode="after")
    def validate_database(self):
        if self.database_backend != "sqlite" and (not self.mysql_database or not self.mysql_user):
            raise ValueError("MySQL database and user must not be empty")
        return self
