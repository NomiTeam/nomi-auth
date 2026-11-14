import hmac
import json
import re
import secrets
import uuid
from typing import Any

from fastapi import Header

from .accounts import AccountManager
from .config import Settings
from .db import Database
from .errors import Problem
from .models import LoginRequest, MemberOperation, Redemption
from .receipts import ReceiptManager
from .security import code, code_hash, current_timestamp, digest, secret
from .sessions import SessionManager


class LoginManager:
    """
    Claim group login codes and register members without existing accounts.
    """

    def __init__(
        self,
        settings: Settings,
        database: Database,
        accounts: AccountManager,
        receipts: ReceiptManager,
        sessions: SessionManager,
    ) -> None:
        self.settings = settings
        self.database = database
        self.accounts = accounts
        self.receipts = receipts
        self.sessions = sessions

    def start(self, request_data: LoginRequest = LoginRequest()) -> dict[str, Any]:
        """
        Create a login code without requiring a name or password.
        """
        request_id, verification_code, poll_token = (uuid.uuid4().hex, code(), secret())
        expires_at = current_timestamp() + self.settings.registration_ttl
        with self.database.write() as connection:
            connection.execute(
                "INSERT INTO login_requests(id,code_hash,poll_hash,account_id,expires_at) VALUES(?,?,?,?,?)",
                (request_id, code_hash(verification_code), digest(poll_token), None, expires_at),
            )
        return {
            "request_id": request_id,
            "code": verification_code,
            "poll_token": poll_token,
            "expires_at": expires_at,
            "group_label": self.settings.group_label,
        }

    def find_request(self, connection: Any, request_id: str, authorization: Any) -> Any:
        """
        Find a login request using its private polling token.
        """
        record = connection.execute("SELECT * FROM login_requests WHERE id=?", (request_id,)).fetchone()
        if not record or not secrets.compare_digest(
            record["poll_hash"], digest(self.accounts.read_bearer(authorization))
        ):
            raise Problem("NOT_FOUND", "登录申请不存在或凭证无效", 404)
        return record

    def status(self, request_id: str, authorization: str | None = Header(None)) -> dict[str, Any]:
        """
        Read the login state and consume a previously failed result.
        """
        with self.database.write() as connection:
            record = self.find_request(connection, request_id, authorization)
            if record["status"] == "FAILED":
                connection.execute("DELETE FROM login_requests WHERE id=?", (request_id,))
        status = (
            "EXPIRED"
            if record["status"] in ("PENDING", "AWAITING_NAME", "VERIFIED")
            and record["expires_at"] <= current_timestamp()
            else record["status"]
        )
        return {"status": status, "expires_at": record["expires_at"], "error": record["error"]}

    def cancel(self, request_id: str, authorization: str | None = Header(None)) -> dict[str, Any]:
        """
        Cancel a login or claimed registration before issuing credentials.
        """
        with self.database.write() as connection:
            record = self.find_request(connection, request_id, authorization)
            if record["status"] not in ("PENDING", "AWAITING_NAME", "VERIFIED"):
                raise Problem("ALREADY_FINISHED", "申请已结束", 409)
            connection.execute("DELETE FROM login_requests WHERE id=?", (request_id,))
        return {"status": "CANCELLED"}

    def verify(self, request_data: Redemption, authorization: str | None = Header(None)) -> dict[str, Any]:
        """
        Claim a code and resolve the sending member in one transaction.
        """
        self.accounts.check_bot(authorization, request_data)
        payload_hash = digest(request_data.model_dump_json())
        with self.database.write() as connection:
            receipt = connection.execute(
                "SELECT * FROM receipts WHERE app_id=? AND event_id=? AND operation='login'",
                (request_data.bot_app_id, request_data.event_id),
            ).fetchone()
            if receipt:
                if receipt["payload_hash"] != payload_hash:
                    raise Problem("EVENT_CONFLICT", "事件参数与原请求不一致", 409)
                return json.loads(receipt["result"])
            record = connection.execute(
                "SELECT * FROM login_requests WHERE code_hash=?", (code_hash(request_data.code),)
            ).fetchone()
            if not record or record["expires_at"] <= current_timestamp():
                raise Problem("INVALID_CODE", "登录验证码无效或过期")
            same_member = (record["app_id"], record["group_id"], record["member_id"]) == (
                request_data.bot_app_id,
                request_data.group_openid,
                request_data.member_openid,
            )
            if record["status"] == "AWAITING_NAME" and same_member:
                return {"status": "AWAITING_NAME"}
            if record["status"] != "PENDING":
                raise Problem("CODE_USED", "登录验证码已使用或申请已结束", 409)
            identity = connection.execute(
                "SELECT a.id,a.status FROM identities i JOIN accounts a ON a.id=i.account_id\n                WHERE i.app_id=? AND i.group_id=? AND i.member_id=?",
                (request_data.bot_app_id, request_data.group_openid, request_data.member_openid),
            ).fetchone()
            if not identity:
                pending = connection.execute(
                    "SELECT 1 FROM login_requests WHERE app_id=? AND group_id=? AND member_id=?\n                    AND status='AWAITING_NAME' AND expires_at>?",
                    (
                        request_data.bot_app_id,
                        request_data.group_openid,
                        request_data.member_openid,
                        current_timestamp(),
                    ),
                ).fetchone()
                if pending:
                    raise Problem("REQUEST_IN_PROGRESS", "你已有待注册申请，请先完成或关闭它", 409)
                connection.execute(
                    "UPDATE login_requests SET status='AWAITING_NAME',app_id=?,group_id=?,member_id=?\n                    WHERE id=?",
                    (
                        request_data.bot_app_id,
                        request_data.group_openid,
                        request_data.member_openid,
                        record["id"],
                    ),
                )
                result = {"status": "AWAITING_NAME"}
            elif identity["status"] != "active":
                raise Problem("ACCOUNT_UNAVAILABLE", "账号已停用", 403)
            else:
                connection.execute(
                    "UPDATE login_requests SET status='VERIFIED',account_id=? WHERE id=?",
                    (identity["id"], record["id"]),
                )
                profile = connection.execute(
                    "SELECT name,uuid FROM profiles WHERE account_id=?", (identity["id"],)
                ).fetchone()
                result = {"status": "VERIFIED", "name": profile["name"], "uuid": profile["uuid"]}
                self.accounts.record_audit(connection, "qq_login_verified", identity["id"])
            connection.execute(
                "INSERT INTO receipts VALUES(?,?,'login',?,?,?)",
                (
                    request_data.bot_app_id,
                    request_data.event_id,
                    payload_hash,
                    json.dumps(result),
                    current_timestamp(),
                ),
            )
        return result

    def register(
        self, request_data: MemberOperation, authorization: str | None = Header(None)
    ) -> dict[str, Any]:
        """
        Create an account for the member who claimed the pending login.
        """
        self.accounts.check_bot(authorization, request_data)
        with self.database.write() as connection:
            cached = self.receipts.find(connection, request_data, "login_register")
            if cached is not None:
                return cached
            record = connection.execute(
                "SELECT * FROM login_requests WHERE app_id=? AND group_id=? AND member_id=?\n                AND status='AWAITING_NAME' ORDER BY expires_at DESC LIMIT 1",
                (request_data.bot_app_id, request_data.group_openid, request_data.member_openid),
            ).fetchone()
            if not record:
                raise Problem("NO_PENDING_REGISTRATION", "没有待注册申请，请先发送启动器的登录码", 409)
            error = None
            if record["expires_at"] <= current_timestamp():
                error = "REQUEST_EXPIRED"
            elif not re.fullmatch("[A-Za-z0-9_]{3,16}", request_data.name):
                error = "INVALID_NAME"
            elif connection.execute(
                "SELECT 1 FROM identities WHERE app_id=? AND group_id=? AND member_id=?",
                (request_data.bot_app_id, request_data.group_openid, request_data.member_openid),
            ).fetchone():
                error = "IDENTITY_ALREADY_BOUND"
            elif connection.execute(
                "SELECT 1 FROM accounts WHERE login_normalized=? UNION ALL SELECT 1 FROM profiles WHERE name_normalized=?",
                (request_data.name.lower(), request_data.name.lower()),
            ).fetchone():
                error = "NAME_TAKEN"
            if error:
                connection.execute(
                    "UPDATE login_requests SET status='FAILED',error=? WHERE id=?", (error, record["id"])
                )
                result = {"status": "FAILED", "code": error}
            else:
                account_id, profile_id = (uuid.uuid4().hex, uuid.uuid4().hex)
                connection.execute(
                    "INSERT INTO accounts(id,login_name,login_normalized,created_at) VALUES(?,?,?,?)",
                    (account_id, request_data.name, request_data.name.lower(), current_timestamp()),
                )
                connection.execute(
                    "INSERT INTO profiles(uuid,account_id,name,name_normalized) VALUES(?,?,?,?)",
                    (profile_id, account_id, request_data.name, request_data.name.lower()),
                )
                connection.execute(
                    "INSERT INTO identities VALUES(?,?,?,?)",
                    (
                        account_id,
                        request_data.bot_app_id,
                        request_data.group_openid,
                        request_data.member_openid,
                    ),
                )
                connection.execute(
                    "UPDATE login_requests SET status='VERIFIED',account_id=? WHERE id=?",
                    (account_id, record["id"]),
                )
                self.accounts.record_audit(connection, "qq_register", account_id)
                result = {"status": "REGISTERED", "name": request_data.name, "uuid": profile_id}
            self.receipts.save(connection, request_data, "login_register", result)
        return result

    def exchange(
        self,
        request_id: str,
        authorization: str | None = Header(None),
        x_request_id: str | None = Header(None),
    ) -> dict[str, Any]:
        """
        Exchange a verified login, or replay its original grant for the same retry.
        """
        poll_token = self.accounts.read_bearer(authorization)
        if x_request_id is not None and (not re.fullmatch("[a-f0-9]{64}", x_request_id)):
            raise Problem("INVALID_REQUEST", "无效的登录请求标识", 422)
        with self.database.write() as connection:
            retry = connection.execute(
                "SELECT * FROM login_retries WHERE request_id=? AND expires_at>?",
                (request_id, current_timestamp()),
            ).fetchone()
            if (
                retry
                and x_request_id
                and secrets.compare_digest(retry["poll_hash"], digest(poll_token))
                and secrets.compare_digest(retry["request_hash"], digest(x_request_id))
            ):

                def value(kind):
                    return hmac.digest(
                        poll_token.encode(), f"{x_request_id}:{retry['nonce']}:{kind}".encode(), "sha256"
                    ).hex()

                account = self.accounts.find_token_account(connection, value("refresh"), "refresh")
                stored_token = connection.execute(
                    "SELECT * FROM tokens WHERE hash=?", (retry["refresh_hash"],)
                ).fetchone()
                result = self.sessions.format_session(
                    connection, account, stored_token["client_token"], value("game"), value("refresh")
                )
                result["management_token"] = value("management")
                return result
            record = self.find_request(connection, request_id, authorization)
            return self.sessions.issue_session(
                connection, record, "login_requests", "VERIFIED", x_request_id, poll_token
            )
