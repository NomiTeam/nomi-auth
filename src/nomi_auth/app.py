import asyncio
import base64
import hmac
import io
import json
import logging
import re
import secrets
import sqlite3
import threading
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI, File, Form, Header, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, ConfigDict, Field

from .config import Settings
from .db import Database
from .security import code, code_hash, digest, secret


class Problem(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        self.code, self.message, self.status = code, message, status


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


def now():
    return int(time.time())


def create_app(settings: Settings | None = None):
    cfg = settings or Settings()
    db = Database(cfg.data_dir / "nomi-auth.sqlite3")

    @asynccontextmanager
    async def lifespan(app):
        async def sweep():
            while True:
                try:
                    await asyncio.to_thread(db.cleanup, now())
                except sqlite3.Error:
                    logging.getLogger(__name__).exception("Transient data cleanup failed")
                await asyncio.sleep(30)

        task = asyncio.create_task(sweep())
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="Nomi Auth", version="0.1.0", lifespan=lifespan)
    app.state.db = db
    app.state.settings = cfg
    limiter = defaultdict(deque)
    limiter_lock = threading.Lock()

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # Single-instance rate limiter. Never trust arbitrary X-Forwarded-For values.
        sensitive = request.method == "POST" and (
            request.url.path.startswith("/api/v1/")
            or request.url.path.endswith(("/authenticate", "/signout"))
        )
        key = (request.client.host if request.client else "unknown", "sensitive" if sensitive else "general")
        limit = 20 if sensitive else 300
        with limiter_lock:
            bucket = limiter[key]
            timestamp = time.monotonic()
            while bucket and bucket[0] < timestamp - 60:
                bucket.popleft()
            blocked = len(bucket) >= limit
            if not blocked:
                bucket.append(timestamp)
            if len(limiter) > 10000:
                stale = [k for k, v in limiter.items() if not v or v[-1] < timestamp - 60]
                for k in stale:
                    del limiter[k]
        if blocked:
            return JSONResponse({"code": "RATE_LIMITED", "message": "请求过于频繁"}, 429)
        # Access-time cleanup also covers expired records when the service was stopped.
        try:
            await asyncio.to_thread(db.cleanup, now())
        except sqlite3.Error:
            return JSONResponse({"code": "DATABASE_UNAVAILABLE", "message": "数据库暂时不可用，请重试"}, 503)
        response = await call_next(request)
        if not request.url.path.startswith("/textures/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(Problem)
    async def problem_handler(request, exc):
        if request.url.path.startswith("/api/yggdrasil"):
            return JSONResponse(
                {"error": "ForbiddenOperationException", "errorMessage": exc.message}, exc.status
            )
        return JSONResponse(
            {"code": exc.code, "message": exc.message, "request_id": uuid.uuid4().hex}, exc.status
        )

    @app.exception_handler(sqlite3.OperationalError)
    async def database_error(request, exc):
        return JSONResponse({"code": "DATABASE_UNAVAILABLE", "message": "数据库暂时不可用，请重试"}, 503)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        if request.url.path.startswith("/api/yggdrasil"):
            return JSONResponse(
                {"error": "IllegalArgumentException", "errorMessage": "Invalid request."}, 400
            )
        # Never echo validation inputs: they may contain a submitted password.
        return JSONResponse({"code": "INVALID_REQUEST", "message": "请求格式或参数不符合要求"}, 422)

    def bearer(header):
        if not header or not header.startswith("Bearer "):
            raise Problem("UNAUTHORIZED", "缺少有效凭证", 401)
        return header[7:]

    def bot_auth(header, body):
        if not secrets.compare_digest(bearer(header), cfg.bot_token):
            raise Problem("UNAUTHORIZED", "机器人凭证无效", 401)
        if body.bot_app_id != cfg.bot_app_id or body.group_openid != cfg.group_openid:
            raise Problem("WRONG_GROUP", "仅允许指定机器人与群")

    def account_for_token(conn, token, kind):
        row = conn.execute(
            """SELECT a.* FROM tokens t JOIN accounts a ON a.id=t.account_id
            WHERE t.hash=? AND t.kind=? AND t.expires_at>? AND a.status='active'""",
            (digest(token), kind, now()),
        ).fetchone()
        if not row:
            raise Problem("INVALID_TOKEN", "令牌无效或已过期", 403)
        return row

    def issue(conn, account_id, kind, client_token=None, token=None):
        token = token or secret()
        ttl = {
            "game": cfg.game_token_ttl,
            "refresh": cfg.refresh_token_ttl,
            "management": cfg.management_token_ttl,
        }[kind]
        conn.execute(
            "INSERT INTO tokens VALUES(?,?,?,?,?)",
            (digest(token), account_id, kind, client_token, now() + ttl),
        )
        return token

    def audit(conn, action, account_id=None, detail=None):
        conn.execute(
            "INSERT INTO audit(action,account_id,detail,created_at) VALUES(?,?,?,?)",
            (action, account_id, detail, now()),
        )

    @app.get("/health")
    def health():
        with db.read() as conn:
            conn.execute("SELECT 1").fetchone()
        return {"status": "ok"}

    @app.get("/api/v1/names/availability")
    def availability(name: str):
        import re

        if not re.fullmatch(r"[A-Za-z0-9_]{3,16}", name):
            raise Problem("INVALID_NAME", "用户名须为 3 至 16 位字母、数字或下划线")
        with db.read() as conn:
            occupied = conn.execute(
                "SELECT 1 FROM accounts WHERE login_normalized=? UNION ALL "
                "SELECT 1 FROM profiles WHERE name_normalized=?",
                (name.lower(), name.lower()),
            ).fetchone()
        return {"available": occupied is None}

    @app.post("/api/v1/registrations", status_code=201)
    def register(body: Registration):
        if not availability(body.name)["available"]:
            raise Problem("NAME_TAKEN", "用户名已被使用", 409)
        request_id, verification, poll = uuid.uuid4().hex, code(), secret()
        expires = now() + cfg.registration_ttl
        with db.write() as conn:
            conn.execute(
                "INSERT INTO registrations(id,code_hash,poll_hash,name,expires_at) VALUES(?,?,?,?,?)",
                (request_id, code_hash(verification), digest(poll), body.name, expires),
            )
        return {
            "request_id": request_id,
            "code": verification,
            "poll_token": poll,
            "expires_at": expires,
            "group_label": cfg.group_label,
        }

    def registration_record(conn, request_id, auth):
        row = conn.execute("SELECT * FROM registrations WHERE id=?", (request_id,)).fetchone()
        if not row or not secrets.compare_digest(row["poll_hash"], digest(bearer(auth))):
            raise Problem("NOT_FOUND", "申请不存在或凭证无效", 404)
        return row

    @app.get("/api/v1/registrations/{request_id}")
    def registration_status(request_id: str, authorization: str | None = Header(None)):
        with db.write() as conn:
            row = registration_record(conn, request_id, authorization)
            if row["status"] == "FAILED":
                conn.execute("DELETE FROM registrations WHERE id=?", (request_id,))
        state = "EXPIRED" if row["status"] == "PENDING" and row["expires_at"] <= now() else row["status"]
        return {"status": state, "expires_at": row["expires_at"], "error": row["error"]}

    @app.delete("/api/v1/registrations/{request_id}")
    def cancel_registration(request_id: str, authorization: str | None = Header(None)):
        with db.write() as conn:
            row = registration_record(conn, request_id, authorization)
            if row["status"] != "PENDING":
                raise Problem("ALREADY_FINISHED", "申请已结束", 409)
            conn.execute("DELETE FROM registrations WHERE id=?", (request_id,))
        return {"status": "CANCELLED"}

    @app.post("/internal/v1/registrations/redeem")
    def redeem(body: Redemption, authorization: str | None = Header(None)):
        bot_auth(authorization, body)
        payload_hash = digest(body.model_dump_json())
        with db.write() as conn:
            receipt = conn.execute(
                "SELECT * FROM receipts WHERE app_id=? AND event_id=? AND operation='register'",
                (body.bot_app_id, body.event_id),
            ).fetchone()
            if receipt:
                if receipt["payload_hash"] != payload_hash:
                    raise Problem("EVENT_CONFLICT", "事件参数与原请求不一致", 409)
                return json.loads(receipt["result"])
            row = conn.execute(
                "SELECT * FROM registrations WHERE code_hash=?", (code_hash(body.code),)
            ).fetchone()
            if not row:
                raise Problem("INVALID_CODE", "验证码无效")
            if row["status"] != "PENDING":
                raise Problem("CODE_USED", "申请已结束，验证码不可再使用", 409)
            if row["expires_at"] <= now():
                raise Problem("REQUEST_EXPIRED", "验证码已过期")
            if conn.execute(
                "SELECT 1 FROM identities WHERE app_id=? AND group_id=? AND member_id=?",
                (body.bot_app_id, body.group_openid, body.member_openid),
            ).fetchone():
                raise Problem("IDENTITY_ALREADY_BOUND", "该群成员已有账号", 409)
            name = row["name"]
            if conn.execute(
                "SELECT 1 FROM accounts WHERE login_normalized=? UNION ALL "
                "SELECT 1 FROM profiles WHERE name_normalized=?",
                (name.lower(), name.lower()),
            ).fetchone():
                conn.execute(
                    "UPDATE registrations SET status='FAILED',error='NAME_TAKEN' WHERE id=?",
                    (row["id"],),
                )
                result = {"status": "FAILED", "code": "NAME_TAKEN"}
            else:
                account_id, profile_id = uuid.uuid4().hex, uuid.uuid4().hex
                conn.execute(
                    "INSERT INTO accounts(id,login_name,login_normalized,created_at) VALUES(?,?,?,?)",
                    (account_id, name, name.lower(), now()),
                )
                conn.execute(
                    "INSERT INTO profiles(uuid,account_id,name,name_normalized) VALUES(?,?,?,?)",
                    (profile_id, account_id, name, name.lower()),
                )
                conn.execute(
                    "INSERT INTO identities VALUES(?,?,?,?)",
                    (account_id, body.bot_app_id, body.group_openid, body.member_openid),
                )
                conn.execute(
                    "UPDATE registrations SET status='COMPLETED',account_id=? WHERE id=?",
                    (account_id, row["id"]),
                )
                audit(conn, "register", account_id)
                result = {"status": "COMPLETED"}
            conn.execute(
                "INSERT INTO receipts VALUES(?,?,'register',?,?,?)",
                (body.bot_app_id, body.event_id, payload_hash, json.dumps(result), now()),
            )
        return result

    @app.post("/api/v1/logins", status_code=201)
    def login_start(body: LoginRequest = LoginRequest()):
        request_id, verification, poll = uuid.uuid4().hex, code(), secret()
        expires = now() + cfg.registration_ttl
        with db.write() as conn:
            conn.execute(
                "INSERT INTO login_requests(id,code_hash,poll_hash,account_id,expires_at) VALUES(?,?,?,?,?)",
                (
                    request_id,
                    code_hash(verification),
                    digest(poll),
                    None,
                    expires,
                ),
            )
        return {
            "request_id": request_id,
            "code": verification,
            "poll_token": poll,
            "expires_at": expires,
            "group_label": cfg.group_label,
        }

    def login_record(conn, request_id, authorization):
        row = conn.execute("SELECT * FROM login_requests WHERE id=?", (request_id,)).fetchone()
        if not row or not secrets.compare_digest(row["poll_hash"], digest(bearer(authorization))):
            raise Problem("NOT_FOUND", "登录申请不存在或凭证无效", 404)
        return row

    @app.get("/api/v1/logins/{request_id}")
    def login_status(request_id: str, authorization: str | None = Header(None)):
        with db.write() as conn:
            row = login_record(conn, request_id, authorization)
            if row["status"] == "FAILED":
                conn.execute("DELETE FROM login_requests WHERE id=?", (request_id,))
        status = (
            "EXPIRED"
            if row["status"] in ("PENDING", "AWAITING_NAME", "VERIFIED") and row["expires_at"] <= now()
            else row["status"]
        )
        return {"status": status, "expires_at": row["expires_at"], "error": row["error"]}

    @app.delete("/api/v1/logins/{request_id}")
    def login_cancel(request_id: str, authorization: str | None = Header(None)):
        with db.write() as conn:
            row = login_record(conn, request_id, authorization)
            if row["status"] not in ("PENDING", "AWAITING_NAME", "VERIFIED"):
                raise Problem("ALREADY_FINISHED", "申请已结束", 409)
            conn.execute("DELETE FROM login_requests WHERE id=?", (request_id,))
        return {"status": "CANCELLED"}

    @app.post("/internal/v1/logins/verify")
    def login_verify(body: Redemption, authorization: str | None = Header(None)):
        bot_auth(authorization, body)
        payload_hash = digest(body.model_dump_json())
        with db.write() as conn:
            receipt = conn.execute(
                "SELECT * FROM receipts WHERE app_id=? AND event_id=? AND operation='login'",
                (body.bot_app_id, body.event_id),
            ).fetchone()
            if receipt:
                if receipt["payload_hash"] != payload_hash:
                    raise Problem("EVENT_CONFLICT", "事件参数与原请求不一致", 409)
                return json.loads(receipt["result"])
            row = conn.execute(
                "SELECT * FROM login_requests WHERE code_hash=?", (code_hash(body.code),)
            ).fetchone()
            if not row or row["expires_at"] <= now():
                raise Problem("INVALID_CODE", "登录验证码无效或过期")
            same_member = (row["app_id"], row["group_id"], row["member_id"]) == (
                body.bot_app_id,
                body.group_openid,
                body.member_openid,
            )
            if row["status"] == "AWAITING_NAME" and same_member:
                return {"status": "AWAITING_NAME"}
            if row["status"] != "PENDING":
                raise Problem("CODE_USED", "登录验证码已使用或申请已结束", 409)
            identity = conn.execute(
                """SELECT a.id,a.status FROM identities i JOIN accounts a ON a.id=i.account_id
                WHERE i.app_id=? AND i.group_id=? AND i.member_id=?""",
                (body.bot_app_id, body.group_openid, body.member_openid),
            ).fetchone()
            if not identity:
                pending = conn.execute(
                    """SELECT 1 FROM login_requests WHERE app_id=? AND group_id=? AND member_id=?
                    AND status='AWAITING_NAME' AND expires_at>?""",
                    (body.bot_app_id, body.group_openid, body.member_openid, now()),
                ).fetchone()
                if pending:
                    raise Problem("REQUEST_IN_PROGRESS", "你已有待注册申请，请先完成或关闭它", 409)
                conn.execute(
                    """UPDATE login_requests SET status='AWAITING_NAME',app_id=?,group_id=?,member_id=?
                    WHERE id=?""",
                    (body.bot_app_id, body.group_openid, body.member_openid, row["id"]),
                )
                result = {"status": "AWAITING_NAME"}
            elif identity["status"] != "active":
                raise Problem("ACCOUNT_UNAVAILABLE", "账号已停用", 403)
            else:
                conn.execute(
                    "UPDATE login_requests SET status='VERIFIED',account_id=? WHERE id=?",
                    (identity["id"], row["id"]),
                )
                profile = conn.execute(
                    "SELECT name,uuid FROM profiles WHERE account_id=?", (identity["id"],)
                ).fetchone()
                result = {"status": "VERIFIED", "name": profile["name"], "uuid": profile["uuid"]}
                audit(conn, "qq_login_verified", identity["id"])
            conn.execute(
                "INSERT INTO receipts VALUES(?,?,'login',?,?,?)",
                (body.bot_app_id, body.event_id, payload_hash, json.dumps(result), now()),
            )
        return result

    def member_receipt(conn, body, operation):
        receipt = conn.execute(
            "SELECT * FROM receipts WHERE app_id=? AND event_id=? AND operation=?",
            (body.bot_app_id, body.event_id, operation),
        ).fetchone()
        if receipt:
            if receipt["payload_hash"] != digest(body.model_dump_json()):
                raise Problem("EVENT_CONFLICT", "事件参数与原请求不一致", 409)
            return json.loads(receipt["result"])
        return None

    def save_member_receipt(conn, body, operation, result):
        conn.execute(
            "INSERT INTO receipts VALUES(?,?,?,?,?,?)",
            (
                body.bot_app_id,
                body.event_id,
                operation,
                digest(body.model_dump_json()),
                json.dumps(result),
                now(),
            ),
        )

    @app.post("/internal/v1/logins/register")
    def register_claimed_login(body: MemberOperation, authorization: str | None = Header(None)):
        bot_auth(authorization, body)
        with db.write() as conn:
            cached = member_receipt(conn, body, "login_register")
            if cached is not None:
                return cached
            row = conn.execute(
                """SELECT * FROM login_requests WHERE app_id=? AND group_id=? AND member_id=?
                AND status='AWAITING_NAME' ORDER BY expires_at DESC LIMIT 1""",
                (body.bot_app_id, body.group_openid, body.member_openid),
            ).fetchone()
            if not row:
                raise Problem("NO_PENDING_REGISTRATION", "没有待注册申请，请先发送启动器的登录码", 409)
            error = None
            if row["expires_at"] <= now():
                error = "REQUEST_EXPIRED"
            elif not re.fullmatch(r"[A-Za-z0-9_]{3,16}", body.name):
                error = "INVALID_NAME"
            elif conn.execute(
                "SELECT 1 FROM identities WHERE app_id=? AND group_id=? AND member_id=?",
                (body.bot_app_id, body.group_openid, body.member_openid),
            ).fetchone():
                error = "IDENTITY_ALREADY_BOUND"
            elif conn.execute(
                "SELECT 1 FROM accounts WHERE login_normalized=? UNION ALL SELECT 1 FROM profiles WHERE name_normalized=?",
                (body.name.lower(), body.name.lower()),
            ).fetchone():
                error = "NAME_TAKEN"
            if error:
                conn.execute(
                    "UPDATE login_requests SET status='FAILED',error=? WHERE id=?", (error, row["id"])
                )
                result = {"status": "FAILED", "code": error}
            else:
                account_id, profile_id = uuid.uuid4().hex, uuid.uuid4().hex
                conn.execute(
                    "INSERT INTO accounts(id,login_name,login_normalized,created_at) VALUES(?,?,?,?)",
                    (account_id, body.name, body.name.lower(), now()),
                )
                conn.execute(
                    "INSERT INTO profiles(uuid,account_id,name,name_normalized) VALUES(?,?,?,?)",
                    (profile_id, account_id, body.name, body.name.lower()),
                )
                conn.execute(
                    "INSERT INTO identities VALUES(?,?,?,?)",
                    (account_id, body.bot_app_id, body.group_openid, body.member_openid),
                )
                conn.execute(
                    "UPDATE login_requests SET status='VERIFIED',account_id=? WHERE id=?",
                    (account_id, row["id"]),
                )
                audit(conn, "qq_register", account_id)
                result = {"status": "REGISTERED", "name": body.name, "uuid": profile_id}
            save_member_receipt(conn, body, "login_register", result)
        return result

    def exchange_session(conn, row, table, required_status, retry_key=None, poll=None):
        if row["status"] != required_status:
            raise Problem("NOT_VERIFIED", "申请尚未验证或已经结束", 403)
        if row["expires_at"] <= now():
            raise Problem("REQUEST_EXPIRED", "申请已过期，请重新申请")
        if row["session_issued"]:
            raise Problem("SESSION_ALREADY_ISSUED", "登录凭据已领取，请重新发起群验证", 409)
        account = conn.execute(
            "SELECT * FROM accounts WHERE id=? AND status='active'", (row["account_id"],)
        ).fetchone()
        if not account:
            raise Problem("ACCOUNT_UNAVAILABLE", "账号不可用", 403)
        client_token = secret()
        nonce = secret()

        def value(kind):
            return (
                hmac.digest(poll.encode(), f"{retry_key}:{nonce}:{kind}".encode(), "sha256").hex()
                if retry_key
                else None
            )

        game_token = issue(conn, account["id"], "game", client_token, value("game"))
        management_token = issue(conn, account["id"], "management", token=value("management"))
        refresh_token = issue(conn, account["id"], "refresh", client_token, value("refresh"))
        if retry_key:
            conn.execute(
                "INSERT INTO login_retries VALUES(?,?,?,?,?,?,?,?)",
                (
                    row["id"],
                    digest(poll),
                    digest(retry_key),
                    nonce,
                    digest(game_token),
                    digest(refresh_token),
                    digest(management_token),
                    now() + 120,
                ),
            )
        conn.execute(f"DELETE FROM {table} WHERE id=?", (row["id"],))
        audit(conn, "qq_session_issued", account["id"])
        result = launcher_refresh_result(conn, account, client_token, game_token, refresh_token)
        result["management_token"] = management_token
        return result

    @app.get("/api/v1/game/profile")
    def current_game_profile(authorization: str | None = Header(None)):
        with db.read() as conn:
            account = account_for_token(conn, bearer(authorization), "game")
            profile = conn.execute("SELECT * FROM profiles WHERE account_id=?", (account["id"],)).fetchone()
            return {"id": profile["uuid"], "name": profile["name"]}

    @app.post("/api/v1/sessions/refresh")
    def refresh_launcher_session(
        authorization: str | None = Header(None), x_request_id: str | None = Header(None)
    ):
        token = bearer(authorization)
        if x_request_id is not None and not re.fullmatch(r"[a-f0-9]{64}", x_request_id):
            raise Problem("INVALID_REQUEST", "无效的续期请求标识", 422)

        def derived(nonce, kind):
            # Reconstruct the exact response using the caller's secret; never store plaintext tokens.
            return hmac.digest(token.encode(), f"{x_request_id}:{nonce}:{kind}".encode(), "sha256").hex()

        with db.write() as conn:
            retry = conn.execute(
                "SELECT * FROM refresh_retries WHERE old_hash=? AND expires_at>?",
                (digest(token), now()),
            ).fetchone()
            if retry and x_request_id and secrets.compare_digest(retry["request_hash"], digest(x_request_id)):
                account = account_for_token(conn, derived(retry["nonce"], "refresh"), "refresh")
                stored = conn.execute(
                    "SELECT * FROM tokens WHERE hash=?", (retry["refresh_hash"],)
                ).fetchone()
                access = derived(retry["nonce"], "game")
                refresh = derived(retry["nonce"], "refresh")
                return launcher_refresh_result(conn, account, stored["client_token"], access, refresh)
            account = account_for_token(conn, token, "refresh")
            stored = conn.execute("SELECT * FROM tokens WHERE hash=?", (digest(token),)).fetchone()
            # Atomic single-use rotation. Other devices have independent client tokens.
            conn.execute(
                "DELETE FROM tokens WHERE hash=? OR (account_id=? AND kind='game' AND client_token=?)",
                (digest(token), account["id"], stored["client_token"]),
            )
            if x_request_id:
                nonce = secret()
                access, refresh = derived(nonce, "game"), derived(nonce, "refresh")
                for value, kind, ttl in (
                    (access, "game", cfg.game_token_ttl),
                    (refresh, "refresh", cfg.refresh_token_ttl),
                ):
                    conn.execute(
                        "INSERT INTO tokens VALUES(?,?,?,?,?)",
                        (digest(value), account["id"], kind, stored["client_token"], now() + ttl),
                    )
                conn.execute(
                    "INSERT INTO refresh_retries VALUES(?,?,?,?,?,?)",
                    (
                        digest(token),
                        digest(x_request_id),
                        nonce,
                        digest(access),
                        digest(refresh),
                        now() + 120,
                    ),
                )
            else:
                access = issue(conn, account["id"], "game", stored["client_token"])
                refresh = issue(conn, account["id"], "refresh", stored["client_token"])
            return launcher_refresh_result(conn, account, stored["client_token"], access, refresh)

    def launcher_refresh_result(conn, account, client_token, access, refresh):
        profile = conn.execute("SELECT * FROM profiles WHERE account_id=?", (account["id"],)).fetchone()
        expiries = {
            r["kind"]: r["expires_at"]
            for r in conn.execute(
                "SELECT kind,expires_at FROM tokens WHERE hash IN (?,?)", (digest(access), digest(refresh))
            )
        }
        selected = {"id": profile["uuid"], "name": profile["name"]}
        return {
            "login_name": account["login_name"],
            "refresh_token": refresh,
            "refresh_expires_at": expiries["refresh"],
            "game_expires_at": expiries["game"],
            "game": {
                "accessToken": access,
                "clientToken": client_token,
                "selectedProfile": selected,
                "availableProfiles": [selected],
            },
        }

    @app.delete("/api/v1/sessions/refresh", status_code=204)
    def revoke_launcher_session(authorization: str | None = Header(None)):
        token = bearer(authorization)
        with db.write() as conn:
            row = conn.execute(
                "SELECT * FROM tokens WHERE hash=? AND kind='refresh'", (digest(token),)
            ).fetchone()
            if row:
                conn.execute(
                    "DELETE FROM tokens WHERE account_id=? AND client_token=? AND kind IN ('game','refresh')",
                    (row["account_id"], row["client_token"]),
                )

    @app.post("/api/v1/logins/{request_id}/session")
    def login_exchange(
        request_id: str, authorization: str | None = Header(None), x_request_id: str | None = Header(None)
    ):
        poll = bearer(authorization)
        if x_request_id is not None and not re.fullmatch(r"[a-f0-9]{64}", x_request_id):
            raise Problem("INVALID_REQUEST", "无效的登录请求标识", 422)
        with db.write() as conn:
            retry = conn.execute(
                "SELECT * FROM login_retries WHERE request_id=? AND expires_at>?", (request_id, now())
            ).fetchone()
            if (
                retry
                and x_request_id
                and secrets.compare_digest(retry["poll_hash"], digest(poll))
                and secrets.compare_digest(retry["request_hash"], digest(x_request_id))
            ):

                def value(kind):
                    return hmac.digest(
                        poll.encode(), f"{x_request_id}:{retry['nonce']}:{kind}".encode(), "sha256"
                    ).hex()

                account = account_for_token(conn, value("refresh"), "refresh")
                stored = conn.execute(
                    "SELECT * FROM tokens WHERE hash=?", (retry["refresh_hash"],)
                ).fetchone()
                result = launcher_refresh_result(
                    conn, account, stored["client_token"], value("game"), value("refresh")
                )
                result["management_token"] = value("management")
                return result
            row = login_record(conn, request_id, authorization)
            return exchange_session(conn, row, "login_requests", "VERIFIED", x_request_id, poll)

    @app.post("/api/v1/registrations/{request_id}/session")
    def registration_exchange(request_id: str, authorization: str | None = Header(None)):
        with db.write() as conn:
            row = registration_record(conn, request_id, authorization)
            return exchange_session(conn, row, "registrations", "COMPLETED")

    @app.delete("/api/v1/sessions/current", status_code=204)
    def logout(authorization: str | None = Header(None)):
        with db.write() as conn:
            conn.execute(
                "DELETE FROM tokens WHERE hash=? AND kind='management'", (digest(bearer(authorization)),)
            )

    @app.get("/api/v1/me")
    def me(authorization: str | None = Header(None)):
        with db.read() as conn:
            account = account_for_token(conn, bearer(authorization), "management")
            profile = dict(
                conn.execute("SELECT * FROM profiles WHERE account_id=?", (account["id"],)).fetchone()
            )
        return {"login_name": account["login_name"], "profile": profile}

    @app.patch("/api/v1/me/profile/name")
    def rename(body: Rename, authorization: str | None = Header(None)):
        with db.write() as conn:
            account = account_for_token(conn, bearer(authorization), "management")
            return rename_profile(conn, account["id"], body.name)

    def rename_profile(conn, account_id, name):
        if not re.fullmatch(r"[A-Za-z0-9_]{3,16}", name):
            raise Problem("INVALID_NAME", "名称须为 3 至 16 位字母、数字或下划线")
        profile = conn.execute("SELECT * FROM profiles WHERE account_id=?", (account_id,)).fetchone()
        if conn.execute(
            "SELECT 1 FROM profiles WHERE name_normalized=? AND uuid<>?", (name.lower(), profile["uuid"])
        ).fetchone():
            raise Problem("NAME_TAKEN", "游戏名已被使用", 409)
        if profile["name"] == name:
            return {"uuid": profile["uuid"], "name": name}
        if profile["last_renamed_at"] and profile["last_renamed_at"] + cfg.rename_cooldown > now():
            raise Problem("RENAME_COOLDOWN", "尚在改名冷却期", 409)
        # UUID is assigned only at registration. Renaming never replaces a profile.
        conn.execute(
            "UPDATE profiles SET name=?,name_normalized=?,last_renamed_at=? WHERE uuid=?",
            (name, name.lower(), now(), profile["uuid"]),
        )
        audit(conn, "rename", account_id, json.dumps({"old": profile["name"], "new": name}))
        return {"uuid": profile["uuid"], "name": name}

    @app.patch("/api/v1/game/profiles/{profile_id}/name")
    def rename_game_profile(profile_id: str, body: Rename, authorization: str | None = Header(None)):
        token = bearer(authorization)
        with db.write() as conn:
            account = account_for_token(conn, token, "game")
            profile = conn.execute("SELECT * FROM profiles WHERE account_id=?", (account["id"],)).fetchone()
            if profile["uuid"] != profile_id.replace("-", ""):
                raise Problem("PROFILE_MISMATCH", "只能修改自己的角色", 403)
            rename_profile(conn, account["id"], body.name)
            client_token = conn.execute(
                "SELECT client_token FROM tokens WHERE hash=?", (digest(token),)
            ).fetchone()[0]
            selected = {"id": profile["uuid"], "name": body.name}
            return {
                "login_name": account["login_name"],
                "game": {
                    "accessToken": token,
                    "clientToken": client_token,
                    "selectedProfile": selected,
                    "availableProfiles": [selected],
                },
            }

    @app.post("/internal/v1/profiles/rename")
    def rename_member(body: MemberOperation, authorization: str | None = Header(None)):
        bot_auth(authorization, body)
        with db.write() as conn:
            cached = member_receipt(conn, body, "rename")
            if cached is not None:
                return cached
            account = conn.execute(
                """SELECT a.* FROM identities i JOIN accounts a ON a.id=i.account_id
                WHERE i.app_id=? AND i.group_id=? AND i.member_id=?""",
                (body.bot_app_id, body.group_openid, body.member_openid),
            ).fetchone()
            try:
                if not account:
                    raise Problem("ACCOUNT_NOT_FOUND", "尚未注册账号", 404)
                if account["status"] != "active":
                    raise Problem("ACCOUNT_UNAVAILABLE", "账号已停用", 403)
                result = {"status": "RENAMED", **rename_profile(conn, account["id"], body.name)}
            except Problem as error:
                # End this operation and remember failures so replay cannot later rename it.
                result = {"status": "FAILED", "code": error.code}
            save_member_receipt(conn, body, "rename", result)
        return result

    texture_dir = cfg.data_dir / "textures"
    texture_dir.mkdir(exist_ok=True)

    @app.put("/api/v1/me/profile/skin")
    def upload_skin(
        authorization: str | None = Header(None), image: UploadFile = File(...), model: str = Form("default")
    ):
        return perform_skin_upload(authorization, image, model, "management")

    def perform_skin_upload(authorization, image, model, kind, expected_profile=None):
        model = model or "default"

        def checked_account(conn):
            account = account_for_token(conn, bearer(authorization), kind)
            if expected_profile is not None:
                owned = conn.execute(
                    "SELECT 1 FROM profiles WHERE uuid=? AND account_id=?", (expected_profile, account["id"])
                ).fetchone()
                if not owned:
                    raise Problem("INVALID_PROFILE", "无法修改此角色的皮肤", 403)
            return account

        with db.read() as conn:
            checked_account(conn)
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
        target = texture_dir / texture_hash
        if not target.exists():
            temporary = texture_dir / ("." + uuid.uuid4().hex)
            temporary.write_bytes(content)
            temporary.replace(target)
        with db.write() as conn:
            account = checked_account(conn)
            conn.execute(
                "UPDATE profiles SET skin_hash=?,skin_model=? WHERE account_id=?",
                (texture_hash, model, account["id"]),
            )
            audit(conn, "skin_upload", account["id"], texture_hash)
        return {"hash": texture_hash, "url": f"{cfg.public_url.rstrip('/')}/textures/{texture_hash}"}

    @app.put("/api/yggdrasil/api/user/profile/{profile_id}/skin", status_code=204)
    def hmcl_upload_skin(
        profile_id: str,
        authorization: str | None = Header(None),
        skin_file: UploadFile = File(..., alias="file"),
        model: str = Form(""),
    ):
        try:
            normalized = uuid.UUID(profile_id).hex
        except ValueError:
            raise Problem("INVALID_PROFILE", "角色 UUID 无效", 400)
        perform_skin_upload(authorization, skin_file, model, "game", normalized)
        return Response(status_code=204)

    @app.delete("/api/v1/me/profile/skin", status_code=204)
    def clear_skin(authorization: str | None = Header(None)):
        with db.write() as conn:
            account = account_for_token(conn, bearer(authorization), "management")
            conn.execute("UPDATE profiles SET skin_hash=NULL WHERE account_id=?", (account["id"],))

    @app.get("/textures/{texture_hash}")
    def texture(texture_hash: str):
        import re

        if not re.fullmatch(r"[0-9a-f]{64}", texture_hash) or not (texture_dir / texture_hash).is_file():
            raise Problem("NOT_FOUND", "材质不存在", 404)
        return FileResponse(
            texture_dir / texture_hash,
            media_type="image/png",
            headers={
                "Cache-Control": "public,max-age=31536000,immutable",
                "X-Content-Type-Options": "nosniff",
            },
        )

    install_yggdrasil(app, cfg, db, account_for_token, issue)
    return app


def install_yggdrasil(app, cfg, db, account_for_token, issue):
    root = "/api/yggdrasil"
    key_path = cfg.data_dir / "texture-signing.pem"
    if not key_path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # Exclusive creation prevents accidentally overwriting a persisted key.
        try:
            with key_path.open("xb") as output:
                output.write(
                    key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                )
            key_path.chmod(0o600)
        except FileExistsError:
            pass
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    def profile_response(row, properties=False, signed=False):
        result = {"id": row["uuid"], "name": row["name"]}
        if properties:
            textures = {}
            if row["skin_hash"]:
                textures["SKIN"] = {
                    "url": f"{cfg.public_url.rstrip('/')}/textures/{row['skin_hash']}",
                    "metadata": {"model": row["skin_model"]},
                }
            value = base64.b64encode(
                json.dumps(
                    {
                        "timestamp": now() * 1000,
                        "profileId": row["uuid"],
                        "profileName": row["name"],
                        "textures": textures,
                    },
                    separators=(",", ":"),
                ).encode()
            ).decode()
            prop = {"name": "textures", "value": value}
            if signed:
                prop["signature"] = base64.b64encode(
                    key.sign(value.encode(), padding.PKCS1v15(), hashes.SHA1())
                ).decode()
            result["properties"] = [prop, {"name": "uploadableTextures", "value": "skin"}]
        return result

    def token_and_profile(conn, body):
        token = body.get("accessToken", "")
        account = account_for_token(conn, token, "game")
        stored = conn.execute("SELECT * FROM tokens WHERE hash=?", (digest(token),)).fetchone()
        if "clientToken" in body and body["clientToken"] != stored["client_token"]:
            raise Problem("INVALID_TOKEN", "Invalid token.", 403)
        profile = conn.execute("SELECT * FROM profiles WHERE account_id=?", (account["id"],)).fetchone()
        return account, stored, profile

    @app.get(root + "/")
    @app.get(root)
    def metadata():
        from urllib.parse import urlparse

        public = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {
            "meta": {
                "serverName": "Nomi",
                "implementationName": "Nomi Auth",
                "implementationVersion": "0.1.0",
                "feature.non_email_login": True,
            },
            "skinDomains": [urlparse(cfg.public_url).hostname],
            "signaturePublickey": public.decode(),
        }

    @app.post(root + "/authserver/authenticate")
    @app.post(root + "/authserver/signout")
    def legacy_auth_disabled():
        raise Problem("QQ_LOGIN_REQUIRED", "Use Nomi QQ verification login.", 403)

    @app.post(root + "/authserver/refresh")
    def game_refresh(body: GameRequest):
        body = body.model_dump(exclude_none=True)
        with db.write() as conn:
            account, stored, profile = token_and_profile(conn, body)
            selected = body.get("selectedProfile")
            if selected and (not isinstance(selected, dict) or selected.get("id") != profile["uuid"]):
                raise Problem("INVALID_PROFILE", "Invalid profile.", 403)
            conn.execute("DELETE FROM tokens WHERE hash=?", (stored["hash"],))
            token = issue(conn, account["id"], "game", stored["client_token"])
        result = {
            "accessToken": token,
            "clientToken": stored["client_token"],
            "selectedProfile": profile_response(profile),
        }
        if body.get("requestUser"):
            result["user"] = {"id": account["id"], "properties": []}
        return result

    @app.post(root + "/authserver/validate", status_code=204)
    def game_validate(body: GameRequest):
        body = body.model_dump(exclude_none=True)
        with db.read() as conn:
            token_and_profile(conn, body)

    @app.post(root + "/authserver/invalidate", status_code=204)
    def game_invalidate(body: GameRequest):
        body = body.model_dump(exclude_none=True)
        with db.write() as conn:
            row = conn.execute(
                "SELECT * FROM tokens WHERE hash=? AND kind='game'", (digest(body.get("accessToken", "")),)
            ).fetchone()
            if row and ("clientToken" not in body or row["client_token"] == body["clientToken"]):
                conn.execute("DELETE FROM tokens WHERE hash=?", (row["hash"],))

    @app.post(root + "/sessionserver/session/minecraft/join", status_code=204)
    def join(body: GameRequest):
        body = body.model_dump(exclude_none=True)
        server_id = body.get("serverId")
        if not isinstance(server_id, str) or not 1 <= len(server_id) <= 256:
            raise Problem("INVALID_SESSION", "Invalid server ID.")
        with db.write() as conn:
            _, _, profile = token_and_profile(conn, body)
            if body.get("selectedProfile") != profile["uuid"]:
                raise Problem("INVALID_PROFILE", "Invalid token.", 403)
            conn.execute(
                "INSERT OR REPLACE INTO joins VALUES(?,?,?)", (profile["uuid"], server_id, now() + 30)
            )

    @app.get(root + "/sessionserver/session/minecraft/hasJoined")
    def has_joined(username: str, serverId: str):
        with db.read() as conn:
            row = conn.execute(
                """SELECT p.* FROM profiles p JOIN joins j ON p.uuid=j.profile_id
                JOIN accounts a ON a.id=p.account_id WHERE p.name_normalized=? AND j.server_id=?
                AND j.expires_at>? AND a.status='active'""",
                (username.lower(), serverId, now()),
            ).fetchone()
        return profile_response(row, True, True) if row else Response(status_code=204)

    @app.get(root + "/sessionserver/session/minecraft/profile/{profile_id}")
    def get_profile(profile_id: str, unsigned: bool = True):
        with db.read() as conn:
            row = conn.execute(
                "SELECT p.* FROM profiles p JOIN accounts a ON a.id=p.account_id WHERE uuid=? AND a.status='active'",
                (profile_id,),
            ).fetchone()
        return profile_response(row, True, not unsigned) if row else Response(status_code=204)

    @app.post(root + "/api/profiles/minecraft")
    def profiles(names: list[str]):
        if len(names) > 100:
            raise Problem("TOO_MANY_NAMES", "Too many names.")
        results = []
        with db.read() as conn:
            for name in dict.fromkeys(n.lower() for n in names):
                row = conn.execute(
                    "SELECT p.* FROM profiles p JOIN accounts a ON a.id=p.account_id WHERE name_normalized=? AND a.status='active'",
                    (name,),
                ).fetchone()
                if row:
                    results.append(profile_response(row))
        return results
