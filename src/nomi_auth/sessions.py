import hmac
import re
import secrets
from typing import Any

from fastapi import FastAPI, Header

from .accounts import AccountManager
from .config import Settings
from .db import Database
from .errors import Problem
from .security import current_timestamp, digest, secret


class SessionManager:
    """
    Issue rotate and revoke launcher and management sessions.
    """

    def __init__(self, settings: Settings, database: Database, accounts: AccountManager) -> None:
        self.settings = settings
        self.database = database
        self.accounts = accounts

    def issue_session(
        self,
        connection: Any,
        record: Any,
        table: str,
        required_status: str,
        retry_key: str | None = None,
        poll_token: str | None = None,
    ) -> dict[str, Any]:
        """
        Issue one session and remove the completed request atomically.
        """
        if record["status"] != required_status:
            raise Problem("NOT_VERIFIED", "申请尚未验证或已经结束", 403)
        if record["expires_at"] <= current_timestamp():
            raise Problem("REQUEST_EXPIRED", "申请已过期，请重新申请")
        if record["session_issued"]:
            raise Problem("SESSION_ALREADY_ISSUED", "登录凭据已领取，请重新发起群验证", 409)
        account = connection.execute(
            "SELECT * FROM accounts WHERE id=? AND status='active'", (record["account_id"],)
        ).fetchone()
        if not account:
            raise Problem("ACCOUNT_UNAVAILABLE", "账号不可用", 403)
        client_token = secret()
        nonce = secret()

        def value(kind):
            return (
                hmac.digest(poll_token.encode(), f"{retry_key}:{nonce}:{kind}".encode(), "sha256").hex()
                if retry_key
                else None
            )

        game_token = self.accounts.issue_token(connection, account["id"], "game", client_token, value("game"))
        management_token = self.accounts.issue_token(
            connection, account["id"], "management", token=value("management")
        )
        refresh_token = self.accounts.issue_token(
            connection, account["id"], "refresh", client_token, value("refresh")
        )
        if retry_key:
            connection.execute(
                "INSERT INTO login_retries VALUES(?,?,?,?,?,?,?,?)",
                (
                    record["id"],
                    digest(poll_token),
                    digest(retry_key),
                    nonce,
                    digest(game_token),
                    digest(refresh_token),
                    digest(management_token),
                    current_timestamp() + 120,
                ),
            )
        # A completed request cannot issue another independent session.
        connection.execute(f"DELETE FROM {table} WHERE id=?", (record["id"],))
        self.accounts.record_audit(connection, "qq_session_issued", account["id"])
        result = self.format_session(connection, account, client_token, game_token, refresh_token)
        result["management_token"] = management_token
        return result

    def current_profile(self, authorization: str | None = Header(None)) -> dict[str, Any]:
        """
        Return the current name and UUID for a game token.
        """
        with self.database.read() as connection:
            account = self.accounts.find_token_account(
                connection, self.accounts.read_bearer(authorization), "game"
            )
            profile = connection.execute(
                "SELECT * FROM profiles WHERE account_id=?", (account["id"],)
            ).fetchone()
            return {"id": profile["uuid"], "name": profile["name"]}

    def refresh(
        self, authorization: str | None = Header(None), x_request_id: str | None = Header(None)
    ) -> dict[str, Any]:
        """
        Rotate device credentials, preserving bounded retries after response loss.
        """
        token = self.accounts.read_bearer(authorization)
        if x_request_id is not None and (not re.fullmatch("[a-f0-9]{64}", x_request_id)):
            raise Problem("INVALID_REQUEST", "无效的续期请求标识", 422)

        def derived(nonce, kind):
            return hmac.digest(token.encode(), f"{x_request_id}:{nonce}:{kind}".encode(), "sha256").hex()

        with self.database.write() as connection:
            retry = connection.execute(
                "SELECT * FROM refresh_retries WHERE old_hash=? AND expires_at>?",
                (digest(token), current_timestamp()),
            ).fetchone()
            if retry and x_request_id and secrets.compare_digest(retry["request_hash"], digest(x_request_id)):
                account = self.accounts.find_token_account(
                    connection, derived(retry["nonce"], "refresh"), "refresh"
                )
                stored_token = connection.execute(
                    "SELECT * FROM tokens WHERE hash=?", (retry["refresh_hash"],)
                ).fetchone()
                access = derived(retry["nonce"], "game")
                refresh = derived(retry["nonce"], "refresh")
                return self.format_session(connection, account, stored_token["client_token"], access, refresh)
            account = self.accounts.find_token_account(connection, token, "refresh")
            stored_token = connection.execute(
                "SELECT * FROM tokens WHERE hash=?", (digest(token),)
            ).fetchone()
            connection.execute(
                "DELETE FROM tokens WHERE hash=? OR (account_id=? AND kind='game' AND client_token=?)",
                (digest(token), account["id"], stored_token["client_token"]),
            )
            if x_request_id:
                nonce = secret()
                access, refresh = (derived(nonce, "game"), derived(nonce, "refresh"))
                for value, kind, ttl in (
                    (access, "game", self.settings.game_token_ttl),
                    (refresh, "refresh", self.settings.refresh_token_ttl),
                ):
                    connection.execute(
                        "INSERT INTO tokens VALUES(?,?,?,?,?)",
                        (
                            digest(value),
                            account["id"],
                            kind,
                            stored_token["client_token"],
                            current_timestamp() + ttl,
                        ),
                    )
                connection.execute(
                    "INSERT INTO refresh_retries VALUES(?,?,?,?,?,?)",
                    (
                        digest(token),
                        digest(x_request_id),
                        nonce,
                        digest(access),
                        digest(refresh),
                        current_timestamp() + 120,
                    ),
                )
            else:
                access = self.accounts.issue_token(
                    connection, account["id"], "game", stored_token["client_token"]
                )
                refresh = self.accounts.issue_token(
                    connection, account["id"], "refresh", stored_token["client_token"]
                )
            return self.format_session(connection, account, stored_token["client_token"], access, refresh)

    def format_session(
        self, connection: Any, account: Any, client_token: str | None, access: str, refresh: str
    ) -> dict[str, Any]:
        """
        Build the launcher response using the stored token expiry times.
        """
        profile = connection.execute("SELECT * FROM profiles WHERE account_id=?", (account["id"],)).fetchone()
        expiries = {
            r["kind"]: r["expires_at"]
            for r in connection.execute(
                "SELECT kind,expires_at FROM tokens WHERE hash IN (?,?)", (digest(access), digest(refresh))
            )
        }
        selected_profile = {"id": profile["uuid"], "name": profile["name"]}
        return {
            "login_name": account["login_name"],
            "refresh_token": refresh,
            "refresh_expires_at": expiries["refresh"],
            "game_expires_at": expiries["game"],
            "game": {
                "accessToken": access,
                "clientToken": client_token,
                "selectedProfile": selected_profile,
                "availableProfiles": [selected_profile],
            },
        }

    def revoke(self, authorization: str | None = Header(None)) -> None:
        """
        Revoke one device without invalidating other device sessions.
        """
        token = self.accounts.read_bearer(authorization)
        with self.database.write() as connection:
            record = connection.execute(
                "SELECT * FROM tokens WHERE hash=? AND kind='refresh'", (digest(token),)
            ).fetchone()
            if record:
                connection.execute(
                    "DELETE FROM tokens WHERE account_id=? AND client_token=? AND kind IN ('game','refresh')",
                    (record["account_id"], record["client_token"]),
                )

    def logout(self, authorization: str | None = Header(None)) -> None:
        """
        Remove only the supplied management token.
        """
        with self.database.write() as connection:
            connection.execute(
                "DELETE FROM tokens WHERE hash=? AND kind='management'",
                (digest(self.accounts.read_bearer(authorization)),),
            )

    def me(self, authorization: str | None = Header(None)) -> dict[str, Any]:
        """
        Read account and profile details for a management session.
        """
        with self.database.read() as connection:
            account = self.accounts.find_token_account(
                connection, self.accounts.read_bearer(authorization), "management"
            )
            profile = dict(
                connection.execute("SELECT * FROM profiles WHERE account_id=?", (account["id"],)).fetchone()
            )
        return {"login_name": account["login_name"], "profile": profile}

    def add_routes(self, app: FastAPI) -> None:
        """
        Register the HTTP endpoints handled by this manager.
        """
        app.get("/api/v1/game/profile", response_model=None)(self.current_profile)
        app.post("/api/v1/sessions/refresh", response_model=None)(self.refresh)
        app.delete("/api/v1/sessions/refresh", status_code=204, response_model=None)(self.revoke)
        app.delete("/api/v1/sessions/current", status_code=204, response_model=None)(self.logout)
        app.get("/api/v1/me", response_model=None)(self.me)
