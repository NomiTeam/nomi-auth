import json
import secrets
import uuid
from typing import Any

from fastapi import FastAPI, Header

from .accounts import AccountManager
from .config import Settings
from .db import Database
from .errors import Problem
from .models import Redemption, Registration
from .security import code, code_hash, current_timestamp, digest, secret
from .sessions import SessionManager


class RegistrationManager:
    """
    Handle legacy name-specific registration requests.
    """

    def __init__(
        self, settings: Settings, database: Database, accounts: AccountManager, sessions: SessionManager
    ) -> None:
        self.settings = settings
        self.database = database
        self.accounts = accounts
        self.sessions = sessions

    def start(self, request_data: Registration) -> dict[str, Any]:
        """
        Create a name-specific registration request for older clients.
        """
        with self.database.read() as connection:
            if self.accounts.name_taken(connection, request_data.name):
                raise Problem("NAME_TAKEN", "用户名已被使用", 409)
        request_id, verification_code, poll_token = (uuid.uuid4().hex, code(), secret())
        expires_at = current_timestamp() + self.settings.registration_ttl
        with self.database.write() as connection:
            connection.execute(
                "INSERT INTO registrations(id,code_hash,poll_hash,name,expires_at) VALUES(?,?,?,?,?)",
                (request_id, code_hash(verification_code), digest(poll_token), request_data.name, expires_at),
            )
        return {
            "request_id": request_id,
            "code": verification_code,
            "poll_token": poll_token,
            "expires_at": expires_at,
            "group_label": self.settings.group_label,
        }

    def find_request(self, connection: Any, request_id: str, authorization: str | None) -> Any:
        """
        Find a registration only when its private polling token matches.
        """
        record = connection.execute("SELECT * FROM registrations WHERE id=?", (request_id,)).fetchone()
        if not record or not secrets.compare_digest(
            record["poll_hash"], digest(self.accounts.read_bearer(authorization))
        ):
            raise Problem("NOT_FOUND", "申请不存在或凭证无效", 404)
        return record

    def status(self, request_id: str, authorization: str | None = Header(None)) -> dict[str, Any]:
        """
        Read the request result and consume a previously failed result.
        """
        with self.database.write() as connection:
            record = self.find_request(connection, request_id, authorization)
            if record["status"] == "FAILED":
                connection.execute("DELETE FROM registrations WHERE id=?", (request_id,))
        state = (
            "EXPIRED"
            if record["status"] == "PENDING" and record["expires_at"] <= current_timestamp()
            else record["status"]
        )
        return {"status": state, "expires_at": record["expires_at"], "error": record["error"]}

    def cancel(self, request_id: str, authorization: str | None = Header(None)) -> dict[str, Any]:
        """
        Cancel a pending registration before it can issue a session.
        """
        with self.database.write() as connection:
            record = self.find_request(connection, request_id, authorization)
            if record["status"] != "PENDING":
                raise Problem("ALREADY_FINISHED", "申请已结束", 409)
            connection.execute("DELETE FROM registrations WHERE id=?", (request_id,))
        return {"status": "CANCELLED"}

    def redeem(self, request_data: Redemption, authorization: str | None = Header(None)) -> dict[str, Any]:
        """
        Verify a legacy registration and bind its first successful group member.
        """
        self.accounts.check_bot(authorization, request_data)
        payload_hash = digest(request_data.model_dump_json())
        with self.database.write() as connection:
            receipt = connection.execute(
                "SELECT * FROM receipts WHERE app_id=? AND event_id=? AND operation='register'",
                (request_data.bot_app_id, request_data.event_id),
            ).fetchone()
            if receipt:
                if receipt["payload_hash"] != payload_hash:
                    raise Problem("EVENT_CONFLICT", "事件参数与原请求不一致", 409)
                return json.loads(receipt["result"])
            record = connection.execute(
                "SELECT * FROM registrations WHERE code_hash=?", (code_hash(request_data.code),)
            ).fetchone()
            if not record:
                raise Problem("INVALID_CODE", "验证码无效")
            if record["status"] != "PENDING":
                raise Problem("CODE_USED", "申请已结束，验证码不可再使用", 409)
            if record["expires_at"] <= current_timestamp():
                raise Problem("REQUEST_EXPIRED", "验证码已过期")
            if connection.execute(
                "SELECT 1 FROM identities WHERE app_id=? AND group_id=? AND member_id=?",
                (request_data.bot_app_id, request_data.group_openid, request_data.member_openid),
            ).fetchone():
                raise Problem("IDENTITY_ALREADY_BOUND", "该群成员已有账号", 409)
            name = record["name"]
            if connection.execute(
                "SELECT 1 FROM accounts WHERE login_normalized=? UNION ALL SELECT 1 FROM profiles WHERE name_normalized=?",
                (name.lower(), name.lower()),
            ).fetchone():
                connection.execute(
                    "UPDATE registrations SET status='FAILED',error='NAME_TAKEN' WHERE id=?", (record["id"],)
                )
                result = {"status": "FAILED", "code": "NAME_TAKEN"}
            else:
                account_id, _profile_id = self.accounts.create(connection, name, request_data)
                connection.execute(
                    "UPDATE registrations SET status='COMPLETED',account_id=? WHERE id=?",
                    (account_id, record["id"]),
                )
                self.accounts.record_audit(connection, "register", account_id)
                result = {"status": "COMPLETED"}
            connection.execute(
                "INSERT INTO receipts VALUES(?,?,'register',?,?,?)",
                (
                    request_data.bot_app_id,
                    request_data.event_id,
                    payload_hash,
                    json.dumps(result),
                    current_timestamp(),
                ),
            )
        return result

    def exchange(self, request_id: str, authorization: str | None = Header(None)) -> dict[str, Any]:
        """
        Exchange a completed legacy registration exactly once.
        """
        with self.database.write() as connection:
            record = self.find_request(connection, request_id, authorization)
            return self.sessions.issue_session(connection, record, "registrations", "COMPLETED")

    def add_routes(self, app: FastAPI) -> None:
        """
        Register the HTTP endpoints handled by this manager.
        """
        app.post("/api/v1/registrations", status_code=201, response_model=None)(self.start)
        app.get("/api/v1/registrations/{request_id}", response_model=None)(self.status)
        app.delete("/api/v1/registrations/{request_id}", response_model=None)(self.cancel)
        app.post("/internal/v1/registrations/redeem", response_model=None)(self.redeem)
        app.post("/api/v1/registrations/{request_id}/session", response_model=None)(self.exchange)
