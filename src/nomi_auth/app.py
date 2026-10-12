import base64
import io
import json
import secrets
import sqlite3
import threading
import time
import uuid
from collections import defaultdict, deque

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI, File, Form, Header, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, Field

from .config import Settings
from .db import Database
from .security import code, code_hash, digest, password_hasher, secret, verify_password


class Problem(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        self.code, self.message, self.status = code, message, status


class Registration(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_]{3,16}$")
    password: str = Field(min_length=10, max_length=128)


class Credentials(BaseModel):
    username: str = Field(max_length=128)
    password: str = Field(max_length=128)


class Redemption(BaseModel):
    code: str = Field(min_length=1, max_length=64)
    bot_app_id: str = Field(min_length=1, max_length=128)
    group_openid: str = Field(min_length=1, max_length=128)
    member_openid: str = Field(min_length=1, max_length=128)
    event_id: str = Field(min_length=1, max_length=256)


class Rename(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_]{3,16}$")
    password: str = Field(max_length=128)


class PasswordChange(BaseModel):
    old_password: str = Field(max_length=128)
    new_password: str = Field(min_length=10, max_length=128)


class Recovery(BaseModel):
    username: str = Field(max_length=128)


class NewPassword(BaseModel):
    password: str = Field(min_length=10, max_length=128)


def now():
    return int(time.time())


def create_app(settings: Settings | None = None):
    cfg = settings or Settings()
    db = Database(cfg.data_dir / "nomi-auth.sqlite3")
    app = FastAPI(title="Nomi Auth", version="0.1.0")
    app.state.db = db
    app.state.settings = cfg
    limiter = defaultdict(deque)
    limiter_lock = threading.Lock()

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # Single-instance rate limiter. Never trust arbitrary X-Forwarded-For values.
        key = (request.client.host if request.client else "unknown", request.url.path)
        limit = 20 if request.method == "POST" and request.url.path.startswith("/api/v1/") else 300
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

    def authenticate(username, password):
        with db.read() as conn:
            row = conn.execute(
                "SELECT * FROM accounts WHERE login_normalized=?", (username.lower(),)
            ).fetchone()
        if not row or not verify_password(row["password_hash"], password) or row["status"] != "active":
            raise Problem("INVALID_CREDENTIALS", "登录名或密码错误", 403)
        return row

    def issue(conn, account_id, kind, client_token=None):
        token = secret()
        ttl = cfg.game_token_ttl if kind == "game" else cfg.management_token_ttl
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
        hashed = password_hasher.hash(body.password)
        request_id, verification, poll = uuid.uuid4().hex, code(), secret()
        expires = now() + cfg.registration_ttl
        with db.write() as conn:
            conn.execute(
                "INSERT INTO registrations(id,code_hash,poll_hash,name,password_hash,expires_at) "
                "VALUES(?,?,?,?,?,?)",
                (request_id, code_hash(verification), digest(poll), body.name, hashed, expires),
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
        with db.read() as conn:
            row = registration_record(conn, request_id, authorization)
        state = "EXPIRED" if row["status"] == "PENDING" and row["expires_at"] <= now() else row["status"]
        return {"status": state, "expires_at": row["expires_at"], "error": row["error"]}

    @app.delete("/api/v1/registrations/{request_id}")
    def cancel_registration(request_id: str, authorization: str | None = Header(None)):
        with db.write() as conn:
            row = registration_record(conn, request_id, authorization)
            if row["status"] != "PENDING":
                raise Problem("ALREADY_FINISHED", "申请已结束", 409)
            conn.execute(
                "UPDATE registrations SET status='CANCELLED',password_hash=NULL WHERE id=?", (request_id,)
            )
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
                    "UPDATE registrations SET status='FAILED',error='NAME_TAKEN',password_hash=NULL WHERE id=?",
                    (row["id"],),
                )
                result = {"status": "FAILED", "code": "NAME_TAKEN"}
            else:
                account_id, profile_id = uuid.uuid4().hex, uuid.uuid4().hex
                conn.execute(
                    "INSERT INTO accounts(id,login_name,login_normalized,password_hash,created_at) VALUES(?,?,?,?,?)",
                    (account_id, name, name.lower(), row["password_hash"], now()),
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
                    "UPDATE registrations SET status='COMPLETED',account_id=?,password_hash=NULL WHERE id=?",
                    (account_id, row["id"]),
                )
                audit(conn, "register", account_id)
                result = {"status": "COMPLETED"}
            conn.execute(
                "INSERT INTO receipts VALUES(?,?,'register',?,?)",
                (body.bot_app_id, body.event_id, payload_hash, json.dumps(result)),
            )
        return result

    @app.post("/api/v1/sessions")
    def management_login(body: Credentials):
        account = authenticate(body.username, body.password)
        with db.write() as conn:
            token = issue(conn, account["id"], "management")
        return {"access_token": token, "expires_in": cfg.management_token_ttl}

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
        with db.read() as conn:
            account = account_for_token(conn, bearer(authorization), "management")
        if not verify_password(account["password_hash"], body.password):
            raise Problem("INVALID_CREDENTIALS", "密码错误", 403)
        with db.write() as conn:
            account_for_token(conn, bearer(authorization), "management")
            profile = conn.execute("SELECT * FROM profiles WHERE account_id=?", (account["id"],)).fetchone()
            if profile["last_renamed_at"] and profile["last_renamed_at"] + cfg.rename_cooldown > now():
                raise Problem("RENAME_COOLDOWN", "尚在改名冷却期", 409)
            if conn.execute(
                "SELECT 1 FROM profiles WHERE name_normalized=? AND uuid<>?",
                (body.name.lower(), profile["uuid"]),
            ).fetchone():
                raise Problem("NAME_TAKEN", "游戏名已被使用", 409)
            conn.execute(
                "UPDATE profiles SET name=?,name_normalized=?,last_renamed_at=? WHERE uuid=?",
                (body.name, body.name.lower(), now(), profile["uuid"]),
            )
            audit(conn, "rename", account["id"], json.dumps({"old": profile["name"], "new": body.name}))
        return {"uuid": profile["uuid"], "name": body.name}

    @app.put("/api/v1/me/password", status_code=204)
    def change_password(body: PasswordChange, authorization: str | None = Header(None)):
        with db.read() as conn:
            account = account_for_token(conn, bearer(authorization), "management")
        if not verify_password(account["password_hash"], body.old_password):
            raise Problem("INVALID_CREDENTIALS", "原密码错误", 403)
        hashed = password_hasher.hash(body.new_password)
        with db.write() as conn:
            current = account_for_token(conn, bearer(authorization), "management")
            if current["password_hash"] != account["password_hash"]:
                raise Problem("STALE_CREDENTIALS", "密码已更新，请重新登录", 409)
            conn.execute("UPDATE accounts SET password_hash=? WHERE id=?", (hashed, account["id"]))
            conn.execute("DELETE FROM tokens WHERE account_id=?", (account["id"],))
            conn.execute(
                "DELETE FROM joins WHERE profile_id IN (SELECT uuid FROM profiles WHERE account_id=?)",
                (account["id"],),
            )
            audit(conn, "password_change", account["id"])

    texture_dir = cfg.data_dir / "textures"
    texture_dir.mkdir(exist_ok=True)

    @app.put("/api/v1/me/profile/skin")
    def upload_skin(
        authorization: str | None = Header(None), image: UploadFile = File(...), model: str = Form("default")
    ):
        with db.read() as conn:
            account_for_token(conn, bearer(authorization), "management")
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
            account = account_for_token(conn, bearer(authorization), "management")
            conn.execute(
                "UPDATE profiles SET skin_hash=?,skin_model=? WHERE account_id=?",
                (texture_hash, model, account["id"]),
            )
            audit(conn, "skin_upload", account["id"], texture_hash)
        return {"hash": texture_hash, "url": f"{cfg.public_url.rstrip('/')}/textures/{texture_hash}"}

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

    @app.post("/api/v1/recoveries", status_code=201)
    def recovery_start(body: Recovery):
        request_id, verification, poll = uuid.uuid4().hex, code(), secret()
        expires = now() + cfg.registration_ttl
        with db.write() as conn:
            account = conn.execute(
                "SELECT id FROM accounts WHERE login_normalized=? AND status='active'",
                (body.username.lower(),),
            ).fetchone()
            conn.execute(
                "INSERT INTO recoveries(id,code_hash,poll_hash,account_id,expires_at) VALUES(?,?,?,?,?)",
                (
                    request_id,
                    code_hash(verification),
                    digest(poll),
                    account["id"] if account else None,
                    expires,
                ),
            )
        return {"request_id": request_id, "code": verification, "poll_token": poll, "expires_at": expires}

    def recovery_record(conn, request_id, auth):
        row = conn.execute("SELECT * FROM recoveries WHERE id=?", (request_id,)).fetchone()
        if not row or not secrets.compare_digest(row["poll_hash"], digest(bearer(auth))):
            raise Problem("NOT_FOUND", "找回申请不存在", 404)
        if row["expires_at"] <= now():
            raise Problem("REQUEST_EXPIRED", "找回申请过期")
        return row

    @app.post("/internal/v1/recoveries/verify")
    def recovery_verify(body: Redemption, authorization: str | None = Header(None)):
        bot_auth(authorization, body)
        with db.write() as conn:
            row = conn.execute(
                "SELECT * FROM recoveries WHERE code_hash=?", (code_hash(body.code),)
            ).fetchone()
            if not row or row["expires_at"] <= now() or row["status"] not in ("PENDING", "VERIFIED"):
                raise Problem("INVALID_CODE", "找回验证码无效")
            identity = conn.execute(
                "SELECT 1 FROM identities WHERE account_id=? AND app_id=? AND group_id=? AND member_id=?",
                (row["account_id"], body.bot_app_id, body.group_openid, body.member_openid),
            ).fetchone()
            if not identity:
                raise Problem("IDENTITY_MISMATCH", "该成员无法验证此找回申请", 403)
            conn.execute("UPDATE recoveries SET status='VERIFIED' WHERE id=?", (row["id"],))
        return {"status": "VERIFIED"}

    @app.get("/api/v1/recoveries/{request_id}")
    def recovery_status(request_id: str, authorization: str | None = Header(None)):
        with db.read() as conn:
            row = recovery_record(conn, request_id, authorization)
        return {"status": row["status"], "expires_at": row["expires_at"]}

    @app.post("/api/v1/recoveries/{request_id}/complete", status_code=204)
    def recovery_complete(request_id: str, body: NewPassword, authorization: str | None = Header(None)):
        hashed = password_hasher.hash(body.password)
        with db.write() as conn:
            row = recovery_record(conn, request_id, authorization)
            if row["status"] != "VERIFIED":
                raise Problem("NOT_VERIFIED", "找回尚未验证", 403)
            conn.execute("UPDATE accounts SET password_hash=? WHERE id=?", (hashed, row["account_id"]))
            conn.execute("DELETE FROM tokens WHERE account_id=?", (row["account_id"],))
            conn.execute(
                "DELETE FROM joins WHERE profile_id IN (SELECT uuid FROM profiles WHERE account_id=?)",
                (row["account_id"],),
            )
            conn.execute("UPDATE recoveries SET status='COMPLETED' WHERE id=?", (request_id,))
            conn.execute(
                "UPDATE recoveries SET status='CANCELLED' WHERE account_id=? AND id<>? AND status IN ('PENDING','VERIFIED')",
                (row["account_id"], request_id),
            )
            audit(conn, "password_recovery", row["account_id"])

    install_yggdrasil(app, cfg, db, account_for_token, authenticate, issue)
    return app


def install_yggdrasil(app, cfg, db, account_for_token, authenticate, issue):
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
            result["properties"] = [prop]
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
    def game_login(body: dict):
        account = authenticate(str(body.get("username", "")), str(body.get("password", "")))
        client_token = body.get("clientToken") or secret()
        if not isinstance(client_token, str) or len(client_token) > 256:
            raise Problem("INVALID_TOKEN", "Invalid client token.")
        with db.write() as conn:
            # Recheck credentials against concurrent reset or disable before issuing.
            current = conn.execute("SELECT * FROM accounts WHERE id=?", (account["id"],)).fetchone()
            if current["status"] != "active" or current["password_hash"] != account["password_hash"]:
                raise Problem("INVALID_CREDENTIALS", "Credentials changed.", 403)
            token = issue(conn, account["id"], "game", client_token)
            profile = profile_response(
                conn.execute("SELECT * FROM profiles WHERE account_id=?", (account["id"],)).fetchone()
            )
        response = {
            "accessToken": token,
            "clientToken": client_token,
            "availableProfiles": [profile],
            "selectedProfile": profile,
        }
        if body.get("requestUser"):
            response["user"] = {"id": account["id"], "properties": []}
        return response

    @app.post(root + "/authserver/refresh")
    def game_refresh(body: dict):
        with db.write() as conn:
            account, stored, profile = token_and_profile(conn, body)
            selected = body.get("selectedProfile")
            if selected and selected.get("id") != profile["uuid"]:
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
    def game_validate(body: dict):
        with db.read() as conn:
            token_and_profile(conn, body)

    @app.post(root + "/authserver/invalidate", status_code=204)
    def game_invalidate(body: dict):
        with db.write() as conn:
            row = conn.execute(
                "SELECT * FROM tokens WHERE hash=? AND kind='game'", (digest(body.get("accessToken", "")),)
            ).fetchone()
            if row and ("clientToken" not in body or row["client_token"] == body["clientToken"]):
                conn.execute("DELETE FROM tokens WHERE hash=?", (row["hash"],))

    @app.post(root + "/authserver/signout", status_code=204)
    def game_signout(body: Credentials):
        account = authenticate(body.username, body.password)
        with db.write() as conn:
            conn.execute("DELETE FROM tokens WHERE account_id=? AND kind='game'", (account["id"],))
            conn.execute(
                "DELETE FROM joins WHERE profile_id IN (SELECT uuid FROM profiles WHERE account_id=?)",
                (account["id"],),
            )

    @app.post(root + "/sessionserver/session/minecraft/join", status_code=204)
    def join(body: dict):
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
