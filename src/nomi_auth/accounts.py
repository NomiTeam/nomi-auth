import re
import secrets
from typing import Any

from .config import Settings
from .db import Database
from .errors import Problem
from .security import current_timestamp, digest, secret


class AccountManager:
    """
    Validate account access and record account operations.
    """

    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.database = database

    def read_bearer(self, header: str | None) -> str:
        """
        Read the bearer token without accepting missing credentials.
        """
        if not header or not header.startswith("Bearer "):
            raise Problem("UNAUTHORIZED", "缺少有效凭证", 401)
        return header[7:]

    def check_bot(self, header: str | None, request_data: Any) -> None:
        """
        Accept events only from the configured bot and group.
        """
        if not secrets.compare_digest(self.read_bearer(header).encode(), self.settings.bot_token.encode()):
            raise Problem("UNAUTHORIZED", "机器人凭证无效", 401)
        if (
            request_data.bot_app_id != self.settings.bot_app_id
            or request_data.group_openid != self.settings.group_openid
        ):
            raise Problem("WRONG_GROUP", "仅允许指定机器人与群")

    def find_token_account(self, connection: Any, token: str, kind: str) -> Any:
        """
        Resolve an active account using an unexpired token of the required kind.
        """
        record = connection.execute(
            "SELECT a.* FROM tokens t JOIN accounts a ON a.id=t.account_id\n            WHERE t.hash=? AND t.kind=? AND t.expires_at>? AND a.status='active'",
            (digest(token), kind, current_timestamp()),
        ).fetchone()
        if not record:
            raise Problem("INVALID_TOKEN", "令牌无效或已过期", 403)
        return record

    def issue_token(
        self,
        connection: Any,
        account_id: str | None,
        kind: str,
        client_token: str | None = None,
        token: str | None = None,
    ) -> str:
        """
        Store a token hash and return the raw token to the caller once.
        """
        token = token or secret()
        ttl = {
            "game": self.settings.game_token_ttl,
            "refresh": self.settings.refresh_token_ttl,
            "management": self.settings.management_token_ttl,
        }[kind]
        connection.execute(
            "INSERT INTO tokens VALUES(?,?,?,?,?)",
            (digest(token), account_id, kind, client_token, current_timestamp() + ttl),
        )
        return token

    def record_audit(
        self, connection: Any, action: str, account_id: str | None = None, detail: str | None = None
    ) -> None:
        """
        Record an account operation without including secret credentials.
        """
        connection.execute(
            "INSERT INTO audit(action,account_id,detail,created_at) VALUES(?,?,?,?)",
            (action, account_id, detail, current_timestamp()),
        )

    def health(self) -> dict[str, Any]:
        """
        Check that the database accepts a simple query.
        """
        with self.database.read() as connection:
            connection.execute("SELECT 1").fetchone()
        return {"status": "ok"}

    def availability(self, name: str) -> dict[str, Any]:
        """
        Check the name format and current account and profile names.
        """
        if not re.fullmatch("[A-Za-z0-9_]{3,16}", name):
            raise Problem("INVALID_NAME", "用户名须为 3 至 16 位字母、数字或下划线")
        with self.database.read() as connection:
            occupied = connection.execute(
                "SELECT 1 FROM accounts WHERE login_normalized=? UNION ALL SELECT 1 FROM profiles WHERE name_normalized=?",
                (name.lower(), name.lower()),
            ).fetchone()
        return {"available": occupied is None}
