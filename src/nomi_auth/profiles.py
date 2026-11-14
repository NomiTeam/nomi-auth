import io
import json
import re
import uuid
from typing import Any

from fastapi import File, Form, Header, UploadFile
from fastapi.responses import FileResponse, Response
from PIL import Image, UnidentifiedImageError

from .accounts import AccountManager
from .config import Settings
from .db import Database
from .errors import Problem
from .models import MemberOperation, Rename
from .receipts import ReceiptManager
from .security import current_timestamp, digest


class ProfileManager:
    """
    Manage profile names and skin files without replacing identities.
    """

    def __init__(
        self, settings: Settings, database: Database, accounts: AccountManager, receipts: ReceiptManager
    ) -> None:
        self.settings = settings
        self.database = database
        self.accounts = accounts
        self.receipts = receipts
        self.texture_dir = settings.data_dir / "textures"
        self.texture_dir.mkdir(exist_ok=True)

    def rename(self, request_data: Rename, authorization: str | None = Header(None)) -> dict[str, Any]:
        """
        Rename the profile owned by a management token.
        """
        with self.database.write() as connection:
            account = self.accounts.find_token_account(
                connection, self.accounts.read_bearer(authorization), "management"
            )
            return self.rename_profile(connection, account["id"], request_data.name)

    def rename_profile(self, connection: Any, account_id: str | None, name: str) -> dict[str, Any]:
        """
        Validate and change a name while preserving the registered UUID.
        """
        if not re.fullmatch("[A-Za-z0-9_]{3,16}", name):
            raise Problem("INVALID_NAME", "名称须为 3 至 16 位字母、数字或下划线")
        profile = connection.execute("SELECT * FROM profiles WHERE account_id=?", (account_id,)).fetchone()
        if connection.execute(
            "SELECT 1 FROM profiles WHERE name_normalized=? AND uuid<>?", (name.lower(), profile["uuid"])
        ).fetchone():
            raise Problem("NAME_TAKEN", "游戏名已被使用", 409)
        if profile["name"] == name:
            return {"uuid": profile["uuid"], "name": name}
        if (
            profile["last_renamed_at"]
            and profile["last_renamed_at"] + self.settings.rename_cooldown > current_timestamp()
        ):
            raise Problem("RENAME_COOLDOWN", "尚在改名冷却期", 409)
        # Only the name changes; the original UUID remains the profile identity.
        connection.execute(
            "UPDATE profiles SET name=?,name_normalized=?,last_renamed_at=? WHERE uuid=?",
            (name, name.lower(), current_timestamp(), profile["uuid"]),
        )
        self.accounts.record_audit(
            connection, "rename", account_id, json.dumps({"old": profile["name"], "new": name})
        )
        return {"uuid": profile["uuid"], "name": name}

    def rename_game(
        self, profile_id: str, request_data: Rename, authorization: str | None = Header(None)
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
                "SELECT a.* FROM identities i JOIN accounts a ON a.id=i.account_id\n                WHERE i.app_id=? AND i.group_id=? AND i.member_id=?",
                (request_data.bot_app_id, request_data.group_openid, request_data.member_openid),
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
        authorization: Any,
        image: UploadFile,
        model: str,
        kind: str,
        expected_profile: str | None = None,
    ) -> dict[str, Any]:
        """
        Validate and publish a skin while sharing the backup and cleanup write lock.
        """
        model = model or "default"

        def checked_account(connection):
            account = self.accounts.find_token_account(
                connection, self.accounts.read_bearer(authorization), kind
            )
            if expected_profile is not None:
                owned = connection.execute(
                    "SELECT 1 FROM profiles WHERE uuid=? AND account_id=?", (expected_profile, account["id"])
                ).fetchone()
                if not owned:
                    raise Problem("INVALID_PROFILE", "无法修改此角色的皮肤", 403)
            return account

        with self.database.read() as connection:
            checked_account(connection)
        if model not in ("default", "slim"):
            raise Problem("INVALID_MODEL", "不支持的手臂模型")
        raw = image.file.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise Problem("INVALID_IMAGE", "图片不能超过 1 MiB", 413)
        try:
            with Image.open(io.BytesIO(raw)) as source:
                if source.format != "PNG" or source.size not in ((64, 64), (64, 32)):
                    raise Problem("INVALID_IMAGE", "只接受 64x64 或 64x32 PNG")
                clean = source.convert("RGBA")
                output = io.BytesIO()
                clean.save(output, format="PNG")
        except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
            raise Problem("INVALID_IMAGE", "PNG 图片损坏")
        import hashlib

        content = output.getvalue()
        texture_hash = hashlib.sha256(content).hexdigest()
        target = self.texture_dir / texture_hash
        # Publish files and update their references under the same writer lock.
        with self.database.write() as connection:
            account = checked_account(connection)
            if not target.exists():
                temporary = self.texture_dir / ("." + uuid.uuid4().hex)
                try:
                    temporary.write_bytes(content)
                    temporary.replace(target)
                finally:
                    temporary.unlink(missing_ok=True)
            old = connection.execute(
                "SELECT skin_hash FROM profiles WHERE account_id=?", (account["id"],)
            ).fetchone()[0]
            if old and old != texture_hash and (self.texture_dir / old).is_file():
                (self.texture_dir / old).touch()
            connection.execute(
                "UPDATE profiles SET skin_hash=?,skin_model=? WHERE account_id=?",
                (texture_hash, model, account["id"]),
            )
            self.accounts.record_audit(connection, "skin_upload", account["id"], texture_hash)
        return {
            "hash": texture_hash,
            "url": f"{self.settings.public_url.rstrip('/')}/textures/{texture_hash}",
        }

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
            if old and (self.texture_dir / old).is_file():
                (self.texture_dir / old).touch()
            connection.execute("UPDATE profiles SET skin_hash=NULL WHERE account_id=?", (account["id"],))

    def texture(self, texture_hash: str) -> Response:
        """
        Serve an existing content-addressed PNG with immutable caching.
        """
        import re

        if not re.fullmatch("[0-9a-f]{64}", texture_hash) or not (self.texture_dir / texture_hash).is_file():
            raise Problem("NOT_FOUND", "材质不存在", 404)
        return FileResponse(
            self.texture_dir / texture_hash,
            media_type="image/png",
            headers={
                "Cache-Control": "public,max-age=31536000,immutable",
                "X-Content-Type-Options": "nosniff",
            },
        )
