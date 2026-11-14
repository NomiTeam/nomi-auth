import hmac
import re
import secrets
import uuid
from typing import Any

from fastapi import FastAPI, Header

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
        with self.database.write() as connection:
            cached = self.receipts.find(connection, request_data, "login")
            if cached is not None:
                return cached

            request = self._find_code(connection, request_data.code)
            member_identity = (request_data.bot_app_id, request_data.group_openid, request_data.member_openid)
            claimed_identity = (request["app_id"], request["group_id"], request["member_id"])
            if request["status"] == "AWAITING_NAME" and member_identity == claimed_identity:
                return {"status": "AWAITING_NAME"}
            if request["status"] != "PENDING":
                raise Problem("CODE_USED", "登录验证码已使用或申请已结束", 409)

            account = self.accounts.find_member(connection, request_data)
            if account is None:
                result = self._claim_registration(connection, request, request_data)
            else:
                result = self._confirm_login(connection, request, account)
            self.receipts.save(connection, request_data, "login", result)
        return result

    def _find_code(self, connection: Any, verification_code: str) -> Any:
        request = connection.execute(
            "SELECT * FROM login_requests WHERE code_hash=?", (code_hash(verification_code),)
        ).fetchone()
        if request is None or request["expires_at"] <= current_timestamp():
            raise Problem("INVALID_CODE", "登录验证码无效或过期")
        return request

    def _claim_registration(self, connection: Any, request: Any, member: Redemption) -> dict[str, Any]:
        """
        Reserve a registration for the first member, allowing only one pending name.
        """
        pending = connection.execute(
            "SELECT 1 FROM login_requests WHERE app_id=? AND group_id=? AND member_id=? "
            "AND status='AWAITING_NAME' AND expires_at>?",
            (member.bot_app_id, member.group_openid, member.member_openid, current_timestamp()),
        ).fetchone()
        if pending:
            raise Problem("REQUEST_IN_PROGRESS", "你已有待注册申请，请先完成或关闭它", 409)

        connection.execute(
            "UPDATE login_requests SET status='AWAITING_NAME',app_id=?,group_id=?,member_id=? WHERE id=?",
            (member.bot_app_id, member.group_openid, member.member_openid, request["id"]),
        )
        return {"status": "AWAITING_NAME"}

    def _confirm_login(self, connection: Any, request: Any, account: Any) -> dict[str, Any]:
        if account["status"] != "active":
            raise Problem("ACCOUNT_UNAVAILABLE", "账号已停用", 403)
        connection.execute(
            "UPDATE login_requests SET status='VERIFIED',account_id=? WHERE id=?",
            (account["id"], request["id"]),
        )
        profile = connection.execute(
            "SELECT name,uuid FROM profiles WHERE account_id=?", (account["id"],)
        ).fetchone()
        self.accounts.record_audit(connection, "qq_login_verified", account["id"])
        return {"status": "VERIFIED", "name": profile["name"], "uuid": profile["uuid"]}

    def register(
        self, request_data: MemberOperation, authorization: str | None = Header(None)
    ) -> dict[str, Any]:
        """
        Complete or close the requesting member's pending registration.
        """
        self.accounts.check_bot(authorization, request_data)
        with self.database.write() as connection:
            cached = self.receipts.find(connection, request_data, "login_register")
            if cached is not None:
                return cached

            request = connection.execute(
                "SELECT * FROM login_requests WHERE app_id=? AND group_id=? AND member_id=? "
                "AND status='AWAITING_NAME' ORDER BY expires_at DESC LIMIT 1",
                (request_data.bot_app_id, request_data.group_openid, request_data.member_openid),
            ).fetchone()
            if request is None:
                raise Problem("NO_PENDING_REGISTRATION", "没有待注册申请，请先发送启动器的登录码", 409)

            error = self._registration_error(connection, request, request_data)
            if error is not None:
                connection.execute(
                    "UPDATE login_requests SET status='FAILED',error=? WHERE id=?", (error, request["id"])
                )
                result = {"status": "FAILED", "code": error}
            else:
                result = self._complete_registration(connection, request, request_data)
            self.receipts.save(connection, request_data, "login_register", result)
        return result

    def _registration_error(self, connection: Any, request: Any, member: MemberOperation) -> str | None:
        if request["expires_at"] <= current_timestamp():
            return "REQUEST_EXPIRED"
        if not re.fullmatch(r"[A-Za-z0-9_]{3,16}", member.name):
            return "INVALID_NAME"
        if self.accounts.find_member(connection, member) is not None:
            return "IDENTITY_ALREADY_BOUND"
        if self.accounts.name_taken(connection, member.name):
            return "NAME_TAKEN"
        return None

    def _complete_registration(
        self, connection: Any, request: Any, member: MemberOperation
    ) -> dict[str, Any]:
        account_id, profile_id = self.accounts.create(connection, member.name, member)
        connection.execute(
            "UPDATE login_requests SET status='VERIFIED',account_id=? WHERE id=?",
            (account_id, request["id"]),
        )
        self.accounts.record_audit(connection, "qq_register", account_id)
        return {"status": "REGISTERED", "name": member.name, "uuid": profile_id}

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

    def add_routes(self, app: FastAPI) -> None:
        """
        Register the HTTP endpoints handled by this manager.
        """
        app.post("/api/v1/logins", status_code=201, response_model=None)(self.start)
        app.get("/api/v1/logins/{request_id}", response_model=None)(self.status)
        app.delete("/api/v1/logins/{request_id}", response_model=None)(self.cancel)
        app.post("/internal/v1/logins/verify", response_model=None)(self.verify)
        app.post("/internal/v1/logins/register", response_model=None)(self.register)
        app.post("/api/v1/logins/{request_id}/session", response_model=None)(self.exchange)
