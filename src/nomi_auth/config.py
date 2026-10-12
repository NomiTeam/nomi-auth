from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NOMI_", env_file=".env", extra="ignore")
    public_url: str = "http://127.0.0.1:8000"
    data_dir: Path = Path("data")
    bot_token: str = Field(min_length=32)
    bot_app_id: str = Field(min_length=1)
    group_openid: str = Field(min_length=1)
    group_label: str = "服务器指定群"
    registration_ttl: int = Field(default=300, ge=30, le=1800)
    rename_cooldown: int = Field(default=604800, ge=0)
    game_token_ttl: int = Field(default=86400, ge=60)
    management_token_ttl: int = Field(default=3600, ge=60)
