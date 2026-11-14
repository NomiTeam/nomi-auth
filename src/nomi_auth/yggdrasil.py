import base64
import json
import uuid
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI
from fastapi.responses import Response

from .accounts import AccountManager
from .config import Settings
from .db import Database
from .errors import Problem
from .models import GameRequest
from .security import current_timestamp, digest


class Yggdrasil:
    """
    Implement game authentication using the same account and token rules.
    """

    def __init__(self, settings: Settings, database: Database, accounts: AccountManager) -> None:
        self.settings = settings
        self.database = database
        self.accounts = accounts
        self.root = "/api/yggdrasil"
        key_path = self.settings.data_dir / "texture-signing.pem"
        if not key_path.exists():
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            try:
                with key_path.open("xb") as output:
                    output.write(
                        self.key.private_bytes(
                            serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption(),
                        )
                    )
                key_path.chmod(384)
            except FileExistsError:
                pass
        self.key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    def profile_response(self, record: Any, properties: bool = False, signed: bool = False) -> dict[str, Any]:
        """
        Build a game profile and optionally include signed texture properties.
        """
        result = {"id": record["uuid"], "name": record["name"]}
        if properties:
            textures = {}
            if record["skin_hash"]:
                textures["SKIN"] = {
                    "url": f"{self.settings.public_url.rstrip('/')}/textures/{record['skin_hash']}",
                    "metadata": {"model": record["skin_model"]},
                }
            value = base64.b64encode(
                json.dumps(
                    {
                        "timestamp": current_timestamp() * 1000,
                        "profileId": record["uuid"],
                        "profileName": record["name"],
                        "textures": textures,
                    },
                    separators=(",", ":"),
                ).encode()
            ).decode()
            texture_property = {"name": "textures", "value": value}
            if signed:
                texture_property["signature"] = base64.b64encode(
                    self.key.sign(value.encode(), padding.PKCS1v15(), hashes.SHA1())
                ).decode()
            result["properties"] = [texture_property, {"name": "uploadableTextures", "value": "skin"}]
        return result

    def token_and_profile(self, connection: Any, request_data: Any) -> tuple[Any, Any, Any]:
        """
        Validate game credentials and resolve the owning profile.
        """
        token = request_data.get("accessToken", "")
        account = self.accounts.find_token_account(connection, token, "game")
        stored_token = connection.execute("SELECT * FROM tokens WHERE hash=?", (digest(token),)).fetchone()
        if "clientToken" in request_data and request_data["clientToken"] != stored_token["client_token"]:
            raise Problem("INVALID_TOKEN", "Invalid token.", 403)
        profile = connection.execute("SELECT * FROM profiles WHERE account_id=?", (account["id"],)).fetchone()
        return (account, stored_token, profile)

    def metadata(self) -> dict[str, Any]:
        """
        Return authentication metadata and the persistent texture signing public key.
        """
        from urllib.parse import urlparse

        public = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {
            "meta": {
                "serverName": "Nomi",
                "implementationName": "Nomi Auth",
                "implementationVersion": "0.1.0",
                "feature.non_email_login": True,
            },
            "skinDomains": [urlparse(self.settings.public_url).hostname],
            "signaturePublickey": public.decode(),
        }

    def legacy_auth_disabled(self) -> None:
        """
        Reject password authentication in favor of group verification.
        """
        raise Problem("QQ_LOGIN_REQUIRED", "Use Nomi QQ verification login.", 403)

    def game_refresh(self, request_data: GameRequest) -> dict[str, Any]:
        """
        Rotate a game token while retaining its client token.
        """
        request_data = request_data.model_dump(exclude_none=True)
        with self.database.write() as connection:
            account, stored_token, profile = self.token_and_profile(connection, request_data)
            selected_profile = request_data.get("selectedProfile")
            if selected_profile and (
                not isinstance(selected_profile, dict) or selected_profile.get("id") != profile["uuid"]
            ):
                raise Problem("INVALID_PROFILE", "Invalid profile.", 403)
            connection.execute("DELETE FROM tokens WHERE hash=?", (stored_token["hash"],))
            token = self.accounts.issue_token(connection, account["id"], "game", stored_token["client_token"])
        result = {
            "accessToken": token,
            "clientToken": stored_token["client_token"],
            "selectedProfile": self.profile_response(profile),
        }
        if request_data.get("requestUser"):
            result["user"] = {"id": account["id"], "properties": []}
        return result

    def game_validate(self, request_data: GameRequest) -> None:
        """
        Check that the game token belongs to an active account.
        """
        request_data = request_data.model_dump(exclude_none=True)
        with self.database.read() as connection:
            self.token_and_profile(connection, request_data)

    def game_invalidate(self, request_data: GameRequest) -> None:
        """
        Revoke a matching game token without revealing whether it existed.
        """
        request_data = request_data.model_dump(exclude_none=True)
        with self.database.write() as connection:
            record = connection.execute(
                "SELECT * FROM tokens WHERE hash=? AND kind='game'",
                (digest(request_data.get("accessToken", "")),),
            ).fetchone()
            if record and (
                "clientToken" not in request_data or record["client_token"] == request_data["clientToken"]
            ):
                connection.execute("DELETE FROM tokens WHERE hash=?", (record["hash"],))

    def join(self, request_data: GameRequest) -> None:
        """
        Authorize a matching profile to join one server for thirty seconds.
        """
        request_data = request_data.model_dump(exclude_none=True)
        server_id = request_data.get("serverId")
        if not isinstance(server_id, str) or not 1 <= len(server_id) <= 256:
            raise Problem("INVALID_SESSION", "Invalid server ID.")
        with self.database.write() as connection:
            _, _, profile = self.token_and_profile(connection, request_data)
            if request_data.get("selectedProfile") != profile["uuid"]:
                raise Problem("INVALID_PROFILE", "Invalid token.", 403)
            connection.execute(
                "DELETE FROM joins WHERE profile_id=? AND server_id=?", (profile["uuid"], server_id)
            )
            connection.execute(
                "INSERT INTO joins VALUES(?,?,?)", (profile["uuid"], server_id, current_timestamp() + 30)
            )

    def has_joined(self, username: str, serverId: str) -> Any:
        """
        Return a signed profile only after a matching join authorization.
        """
        with self.database.read() as connection:
            record = connection.execute(
                "SELECT p.* FROM profiles p JOIN joins j ON p.uuid=j.profile_id\n                JOIN accounts a ON a.id=p.account_id WHERE p.name_normalized=? AND j.server_id=?\n                AND j.expires_at>? AND a.status='active'",
                (username.lower(), serverId, current_timestamp()),
            ).fetchone()
        return self.profile_response(record, True, True) if record else Response(status_code=204)

    def get_profile(self, profile_id: str, unsigned: bool = True) -> Any:
        """
        Find an active profile and optionally sign its textures.
        """
        try:
            profile_id = uuid.UUID(profile_id).hex
        except ValueError:
            return Response(status_code=204)
        with self.database.read() as connection:
            record = connection.execute(
                "SELECT p.* FROM profiles p JOIN accounts a ON a.id=p.account_id WHERE uuid=? AND a.status='active'",
                (profile_id,),
            ).fetchone()
        return self.profile_response(record, True, not unsigned) if record else Response(status_code=204)

    def profiles(self, names: list[str]) -> list[dict[str, Any]]:
        """
        Resolve up to one hundred distinct names to active game profiles.
        """
        if len(names) > 100:
            raise Problem("TOO_MANY_NAMES", "Too many names.")
        results = []
        with self.database.read() as connection:
            for name in dict.fromkeys(n.lower() for n in names):
                record = connection.execute(
                    "SELECT p.* FROM profiles p JOIN accounts a ON a.id=p.account_id WHERE name_normalized=? AND a.status='active'",
                    (name,),
                ).fetchone()
                if record:
                    results.append(self.profile_response(record))
        return results

    def add_routes(self, app: FastAPI) -> None:
        """
        Register the HTTP endpoints handled by this manager.
        """
        app.get(self.root + "/", response_model=None)(self.metadata)
        app.get("/api/yggdrasil", response_model=None)(self.metadata)
        app.post(self.root + "/authserver/authenticate", response_model=None)(self.legacy_auth_disabled)
        app.post(self.root + "/authserver/signout", response_model=None)(self.legacy_auth_disabled)
        app.post(self.root + "/authserver/refresh", response_model=None)(self.game_refresh)
        app.post(self.root + "/authserver/validate", status_code=204, response_model=None)(self.game_validate)
        app.post(self.root + "/authserver/invalidate", status_code=204, response_model=None)(
            self.game_invalidate
        )
        app.post(self.root + "/sessionserver/session/minecraft/join", status_code=204, response_model=None)(
            self.join
        )
        app.get(self.root + "/sessionserver/session/minecraft/hasJoined", response_model=None)(
            self.has_joined
        )
        app.get(self.root + "/sessionserver/session/minecraft/profile/{profile_id}", response_model=None)(
            self.get_profile
        )
        app.post(self.root + "/api/profiles/minecraft", response_model=None)(self.profiles)
