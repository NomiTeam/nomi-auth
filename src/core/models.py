"""
Request models shared by the public API and the trusted bot interface.
"""

from pydantic import BaseModel, ConfigDict, Field


class Registration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z0-9_]{3,16}$")


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Redemption(BaseModel):
    code: str = Field(min_length=1, max_length=64)
    bot_app_id: str = Field(min_length=1, max_length=128)
    group_openid: str = Field(min_length=1, max_length=128)
    member_openid: str = Field(min_length=1, max_length=128)
    event_id: str = Field(min_length=1, max_length=256)


class Rename(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z0-9_]{3,16}$")


class MemberOperation(BaseModel):
    bot_app_id: str = Field(min_length=1, max_length=128)
    group_openid: str = Field(min_length=1, max_length=128)
    member_openid: str = Field(min_length=1, max_length=128)
    event_id: str = Field(min_length=1, max_length=256)
    name: str = Field(max_length=64)


class GameRequest(BaseModel):
    username: str = Field(default="", max_length=128)
    accessToken: str = Field(default="", max_length=256)
    clientToken: str | None = Field(default=None, max_length=256)
    selectedProfile: str | dict[str, str] | None = None
    serverId: str | None = Field(default=None, max_length=256)
    requestUser: bool = False
