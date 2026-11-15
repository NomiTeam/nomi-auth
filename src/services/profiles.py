import json
import re
import uuid
from typing import Any

from fastapi import FastAPI, File, Form, Header, UploadFile
from fastapi.responses import FileResponse, Response

from src.core.config import Settings
from src.core.errors import Problem
from src.core.models import MemberOperation, Rename
from src.core.security import current_timestamp, digest
from src.services.accounts import AccountManager
from src.services.receipts import ReceiptManager
from src.storage.database import Database
from src.storage.skins import SkinStore
from src.storage.types import Connection


class ProfileManager:
    """
    Manage profile names and skin files without replacing identities.
    """

    def __init__(
        self,
        settings: Settings,
        database: Database,
        accounts: AccountManager,
        receipts: ReceiptManager,
    ) -> None:
        self.settings = settings
        self.database = database
        self.accounts = accounts
        self.receipts = receipts
        self.skins = SkinStore(settings.data_dir / "textures")

    def rename(
        self, request_data: Rename, authorization: str | None = Header(None)
    ) -> dict[str, Any]:
        """
        Rename the profile owned by a management token.
        """
        with self.database.write() as connection:
            account = self.accounts.find_token_account(
                connection, self.accounts.read_bearer(authorization), "management"
            )
            return self.rename_profile(connection, account["id"], request_data.name)

    def rename_profile(
        self, connection: Connection, account_id: str | None, name: str
    ) -> dict[str, Any]:
        """
        Validate and change a name while preserving the registered UUID.
        """
        if not re.fullmatch("[A-Za-z0-9_]{3,16}", name):
            raise Problem("INVALID_NAME", "名称须为 3 至 16 位字母、数字或下划线")
        profile = connection.execute(
            "SELECT * FROM profiles WHERE account_id=?", (account_id,)
        ).fetchone()
        if connection.execute(
            "SELECT 1 FROM profiles WHERE name_normalized=? AND uuid<>?",
            (name.lower(), profile["uuid"]),
        ).fetchone():
            raise Problem("NAME_TAKEN", "游戏名已被使用", 409)
        if profile["name"] == name:
            return {"uuid": profile["uuid"], "name": name}
        if (
            profile["last_renamed_at"]
            and profile["last_renamed_at"] + self.settings.rename_cooldown
            > current_timestamp()
        ):
            raise Problem("RENAME_COOLDOWN", "尚在改名冷却期", 409)
        # Only the name changes; the original UUID remains the profile identity.
        connection.execute(
            "UPDATE profiles SET name=?,name_normalized=?,last_renamed_at=? WHERE uuid=?",
            (name, name.lower(), current_timestamp(), profile["uuid"]),
        )
        self.accounts.record_audit(
            connection,
            "rename",
            account_id,
            json.dumps({"old": profile["name"], "new": name}),
        )
        return {"uuid": profile["uuid"], "name": name}

    def rename_game(
        self,
        profile_id: str,
        request_data: Rename,
        authorization: str | None = Header(None),
    ) -> dict[str, Any]:
        """
        Rename a game profile and return its updated launcher session.
        """
        token = self.accounts.read_bearer(authorization)
        with self.database.write() as connection:
            account = self.accounts.find_token_account(connection, token, "game")
            profile = connection.execute(
                "SELECT * FROM profiles WHERE account_id=?", (account["id"],)
            ).fetchone()
            if profile["uuid"] != profile_id.replace("-", ""):
                raise Problem("PROFILE_MISMATCH", "只能修改自己的角色", 403)
            self.rename_profile(connection, account["id"], request_data.name)
            client_token = connection.execute(
                "SELECT client_token FROM tokens WHERE hash=?", (digest(token),)
            ).fetchone()[0]
            selected_profile = {"id": profile["uuid"], "name": request_data.name}
            return {
                "login_name": account["login_name"],
                "game": {
                    "accessToken": token,
                    "clientToken": client_token,
                    "selectedProfile": selected_profile,
                    "availableProfiles": [selected_profile],
                },
            }

    def rename_member(
        self, request_data: MemberOperation, authorization: str | None = Header(None)
    ) -> dict[str, Any]:
        """
        Apply a group rename once and save both success and failure results.
        """
        self.accounts.check_bot(authorization, request_data)
        with self.database.write() as connection:
            cached = self.receipts.find(connection, request_data, "rename")
            if cached is not None:
                return cached
            account = connection.execute(
                """
                SELECT a.* FROM identities i JOIN accounts a ON a.id=i.account_id
                WHERE i.app_id=? AND i.group_id=? AND i.member_id=?
                """,
                (
                    request_data.bot_app_id,
                    request_data.group_openid,
                    request_data.member_openid,
                ),
            ).fetchone()
            try:
                if not account:
                    raise Problem("ACCOUNT_NOT_FOUND", "尚未注册账号", 404)
                if account["status"] != "active":
                    raise Problem("ACCOUNT_UNAVAILABLE", "账号已停用", 403)
                result = {
                    "status": "RENAMED",
                    **self.rename_profile(connection, account["id"], request_data.name),
                }
            except Problem as error:
                result = {"status": "FAILED", "code": error.code}
            self.receipts.save(connection, request_data, "rename", result)
        return result

    def upload_skin(
        self,
        authorization: str | None = Header(None),
        image: UploadFile = File(...),
        model: str = Form("default"),
    ) -> dict[str, Any]:
        """
        Upload a skin using the management session.
        """
        return self.save_skin(authorization, image, model, "management")

    def save_skin(
        self,
        authorization: str | None,
        image: UploadFile,
        model: str,
        kind: str,
        expected_profile: str | None = None,
    ) -> dict[str, Any]:
        """
        Validate a skin and publish it under the shared database writer lock.
        """
        with self.database.read() as connection:
            self._skin_account(connection, authorization, kind, expected_profile)

        model = model or "default"
        if model not in ("default", "slim"):
            raise Problem("INVALID_MODEL", "不支持的手臂模型")
        content, texture_hash = self.skins.read_image(image.file)

        # Recheck account access after image decoding and before changing any files.
        with self.database.write() as connection:
            account = self._skin_account(
                connection, authorization, kind, expected_profile
            )
            self.skins.publish(content, texture_hash)
            previous_skin = connection.execute(
                "SELECT skin_hash FROM profiles WHERE account_id=?", (account["id"],)
            ).fetchone()[0]
            if previous_skin != texture_hash:
                self.skins.retire(previous_skin)
            connection.execute(
                "UPDATE profiles SET skin_hash=?,skin_model=? WHERE account_id=?",
                (texture_hash, model, account["id"]),
            )
            self.accounts.record_audit(
                connection, "skin_upload", account["id"], texture_hash
            )

        texture_url = f"{self.settings.public_url.rstrip('/')}/textures/{texture_hash}"
        return {"hash": texture_hash, "url": texture_url}

    def _skin_account(
        self,
        connection: Connection,
        authorization: str | None,
        kind: str,
        expected_profile: str | None,
    ) -> Any:
        token = self.accounts.read_bearer(authorization)
        account = self.accounts.find_token_account(connection, token, kind)
        if expected_profile is None:
            return account

        profile = connection.execute(
            "SELECT 1 FROM profiles WHERE uuid=? AND account_id=?",
            (expected_profile, account["id"]),
        ).fetchone()
        if profile is None:
            raise Problem("INVALID_PROFILE", "无法修改此角色的皮肤", 403)
        return account

    def upload_game_skin(
        self,
        profile_id: str,
        authorization: str | None = Header(None),
        skin_file: UploadFile = File(..., alias="file"),
        model: str = Form(""),
    ) -> Response:
        """
        Upload a skin using the native launcher protocol.
        """
        try:
            normalized = uuid.UUID(profile_id).hex
        except ValueError:
            raise Problem("INVALID_PROFILE", "角色 UUID 无效", 400)
        self.save_skin(authorization, skin_file, model, "game", normalized)
        return Response(status_code=204)

    def clear_skin(self, authorization: str | None = Header(None)) -> None:
        """
        Remove the skin reference while retaining the old file for recovery.
        """
        with self.database.write() as connection:
            account = self.accounts.find_token_account(
                connection, self.accounts.read_bearer(authorization), "management"
            )
            old = connection.execute(
                "SELECT skin_hash FROM profiles WHERE account_id=?", (account["id"],)
            ).fetchone()[0]
            self.skins.retire(old)
            connection.execute(
                "UPDATE profiles SET skin_hash=NULL WHERE account_id=?",
                (account["id"],),
            )

    def texture(self, texture_hash: str) -> Response:
        """
        Serve an existing content-addressed PNG with immutable caching.
        """
        path = self.skins.find(texture_hash)
        return FileResponse(
            path,
            media_type="image/png",
            headers={
                "Cache-Control": "public,max-age=31536000,immutable",
                "X-Content-Type-Options": "nosniff",
            },
        )

    def add_routes(self, app: FastAPI) -> None:
        """
        Register the HTTP endpoints handled by this manager.
        """
        app.patch("/api/v1/me/profile/name", response_model=None)(self.rename)
        app.patch("/api/v1/game/profiles/{profile_id}/name", response_model=None)(
            self.rename_game
        )
        app.post("/internal/v1/profiles/rename", response_model=None)(
            self.rename_member
        )
        app.put("/api/v1/me/profile/skin", response_model=None)(self.upload_skin)
        app.put(
            "/api/yggdrasil/api/user/profile/{profile_id}/skin",
            status_code=204,
            response_model=None,
        )(self.upload_game_skin)
        app.delete("/api/v1/me/profile/skin", status_code=204, response_model=None)(
            self.clear_skin
        )
        app.get("/textures/{texture_hash}", response_model=None)(self.texture)
