import base64
import io
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi.testclient import TestClient
from PIL import Image

from nomi_auth.app import create_app
from nomi_auth.config import Settings


@pytest.fixture
def client(tmp_path):
    return TestClient(
        create_app(Settings(data_dir=tmp_path, bot_token="x" * 32, bot_app_id="app", group_openid="group"))
    )


def private(request):
    return {"Authorization": "Bearer " + request["poll_token"]}


def request_account(client, name="Alice"):
    result = client.post("/api/v1/registrations", json={"name": name})
    assert result.status_code == 201, result.text
    return result.json()


def verify(client, request, member="member", event="event", group="group", operation="register"):
    path = "/internal/v1/registrations/redeem" if operation == "register" else "/internal/v1/logins/verify"
    return client.post(
        path,
        headers={"Authorization": "Bearer " + "x" * 32},
        json={
            "code": request["code"],
            "bot_app_id": "app",
            "group_openid": group,
            "member_openid": member,
            "event_id": event,
        },
    )


def create_account(client, name="Alice", member="member", event="event"):
    request = request_account(client, name)
    assert verify(client, request, member, event).json()["status"] == "COMPLETED"
    return request


def exchange(client, request, operation="register"):
    kind = "registrations" if operation == "register" else "logins"
    return client.post(f"/api/v1/{kind}/{request['request_id']}/session", headers=private(request))


def login(client, name="Alice", member="member", event="login-event"):
    request = client.post("/api/v1/logins", json={"username": name}).json()
    assert verify(client, request, member=member, event=event, operation="login").status_code == 200
    response = exchange(client, request, "login")
    assert response.status_code == 200, response.text
    return response.json()


def test_register_and_private_poll(client):
    request = create_account(client)
    assert client.get("/api/v1/registrations/" + request["request_id"]).status_code == 401
    assert (
        client.get("/api/v1/registrations/" + request["request_id"], headers=private(request)).json()[
            "status"
        ]
        == "COMPLETED"
    )
    assert client.get("/api/v1/names/availability", params={"name": "alice"}).json() == {"available": False}
    assert verify(client, request).status_code == 200
    assert verify(client, request, event="later", member="other").status_code == 409
    assert exchange(client, request).status_code == 200
    assert exchange(client, request).status_code == 409


def test_bound_member_and_wrong_group_cannot_consume_registration(client):
    create_account(client)
    request = request_account(client, "Bob")
    assert verify(client, request, event="wrong", group="other").status_code == 400
    assert verify(client, request, event="bound").json()["code"] == "IDENTITY_ALREADY_BOUND"
    assert verify(client, request, member="new", event="new").json()["status"] == "COMPLETED"


def test_same_code_concurrent_members(client):
    request = request_account(client)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda i: verify(client, request, member=str(i), event=str(i)), range(2)))
    assert sorted(r.status_code for r in results) == [200, 409]
    with client.app.state.db.read() as conn:
        assert conn.execute("SELECT count(*) FROM accounts").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM identities").fetchone()[0] == 1


def test_name_race(client):
    first, second = request_account(client), request_account(client, "alice")
    assert verify(client, first).json()["status"] == "COMPLETED"
    assert verify(client, second, member="other", event="other").json() == {
        "status": "FAILED",
        "code": "NAME_TAKEN",
    }


def test_cancel_races_with_registration(client):
    request = request_account(client)
    with ThreadPoolExecutor(max_workers=2) as executor:
        cancel = executor.submit(
            client.delete, "/api/v1/registrations/" + request["request_id"], headers=private(request)
        )
        redeem = executor.submit(verify, client, request)
        assert sorted(r.status_code for r in [cancel.result(), redeem.result()]) == [200, 409]
    with client.app.state.db.read() as conn:
        status = conn.execute(
            "SELECT status FROM registrations WHERE id=?", (request["request_id"],)
        ).fetchone()[0]
        count = conn.execute("SELECT count(*) FROM accounts").fetchone()[0]
    assert (status, count) in (("CANCELLED", 0), ("COMPLETED", 1))


def test_reinstall_login_requires_bound_identity(client):
    create_account(client)
    request = client.post("/api/v1/logins", json={"username": "Alice"}).json()
    assert exchange(client, request, "login").status_code == 403
    assert verify(client, request, member="impostor", event="wrong", operation="login").status_code == 403
    assert verify(client, request, event="good", operation="login").status_code == 200
    assert verify(client, request, event="good", operation="login").status_code == 200
    assert verify(client, request, event="another", operation="login").status_code == 409
    assert client.post("/api/v1/logins/" + request["request_id"] + "/session").status_code == 401
    result = exchange(client, request, "login").json()
    assert result["login_name"] == "Alice"
    assert "accessToken" in result["game"]
    assert exchange(client, request, "login").status_code == 403


def test_concurrent_exchange_only_issues_once(client):
    request = create_account(client)
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: exchange(client, request), range(2)))
    assert sorted(r.status_code for r in responses) == [200, 409]
    with client.app.state.db.read() as conn:
        assert conn.execute("SELECT count(*) FROM tokens").fetchone()[0] == 2


def test_expired_and_cancelled_login(client):
    create_account(client)
    request = client.post("/api/v1/logins", json={"username": "Alice"}).json()
    assert (
        client.delete("/api/v1/logins/" + request["request_id"], headers=private(request)).status_code == 200
    )
    assert verify(client, request, operation="login").status_code == 409
    other = client.post("/api/v1/logins", json={"username": "Alice"}).json()
    assert verify(client, other, operation="login", event="verified").status_code == 200
    with client.app.state.db.write() as conn:
        conn.execute("UPDATE login_requests SET expires_at=0 WHERE id=?", (other["request_id"],))
    assert exchange(client, other, "login").status_code == 400


def test_unknown_name_generic_response_and_disabled_account(client):
    create_account(client)
    unknown = client.post("/api/v1/logins", json={"username": "Unknown"})
    assert unknown.status_code == 201
    assert verify(client, unknown.json(), operation="login").status_code == 403
    request = client.post("/api/v1/logins", json={"username": "Alice"}).json()
    assert verify(client, request, operation="login", event="ok").status_code == 200
    with client.app.state.db.write() as conn:
        conn.execute("UPDATE accounts SET status='disabled'")
    assert exchange(client, request, "login").status_code == 403


def test_game_sessions_signature_and_rename(client):
    create_account(client)
    session = login(client)
    game = session["game"]
    root = "/api/yggdrasil"
    token = {"accessToken": game["accessToken"], "clientToken": game["clientToken"]}
    profile_id = game["selectedProfile"]["id"]
    assert client.post(root + "/authserver/validate", json=token).status_code == 204
    assert (
        client.post(
            root + "/sessionserver/session/minecraft/join",
            json={**token, "selectedProfile": "0" * 32, "serverId": "server"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            root + "/sessionserver/session/minecraft/join",
            json={**token, "selectedProfile": profile_id, "serverId": "server"},
        ).status_code
        == 204
    )
    joined = client.get(
        root + "/sessionserver/session/minecraft/hasJoined",
        params={"username": "Alice", "serverId": "server"},
    ).json()
    prop = joined["properties"][0]
    public = serialization.load_pem_public_key(client.get(root).json()["signaturePublickey"].encode())
    public.verify(
        base64.b64decode(prop["signature"]), prop["value"].encode(), padding.PKCS1v15(), hashes.SHA1()
    )
    headers = {"Authorization": "Bearer " + session["management_token"]}
    assert (
        client.patch("/api/v1/me/profile/name", headers=headers, json={"name": "NewAlice"}).json()["uuid"]
        == profile_id
    )
    assert client.get("/api/v1/me", headers=headers).json()["login_name"] == "Alice"
    assert login(client, event="renamed")["game"]["selectedProfile"]["name"] == "NewAlice"
    assert client.post(root + "/authserver/refresh", json=token).status_code == 200
    assert client.post(root + "/authserver/validate", json=token).status_code == 403


def test_skin_reencoding_and_token_scope(client):
    from PIL.PngImagePlugin import PngInfo

    create_account(client)
    session = login(client)
    headers = {"Authorization": "Bearer " + session["management_token"]}
    game_headers = {"Authorization": "Bearer " + session["game"]["accessToken"]}
    assert client.get("/api/v1/me", headers=game_headers).status_code == 403
    buffer = io.BytesIO()
    metadata = PngInfo()
    metadata.add_text("unwanted", "strip-me")
    Image.new("RGBA", (64, 64), "red").save(buffer, format="PNG", pnginfo=metadata)
    response = client.put(
        "/api/v1/me/profile/skin",
        headers=headers,
        files={"image": ("skin.png", buffer.getvalue(), "image/png")},
        data={"model": "slim"},
    )
    assert response.status_code == 200
    downloaded = client.get("/textures/" + response.json()["hash"])
    with Image.open(io.BytesIO(downloaded.content)) as image:
        assert "unwanted" not in image.info
    profile_id = session["game"]["selectedProfile"]["id"]
    prop = client.get("/api/yggdrasil/sessionserver/session/minecraft/profile/" + profile_id).json()[
        "properties"
    ][0]
    assert json.loads(base64.b64decode(prop["value"]))["textures"]["SKIN"]["metadata"]["model"] == "slim"
    assert (
        client.put(
            "/api/v1/me/profile/skin", headers=headers, files={"image": ("bad.png", b"invalid", "image/png")}
        ).status_code
        == 400
    )


def test_password_routes_removed_and_legacy_auth_disabled(client):
    assert (
        client.post("/api/v1/registrations", json={"name": "Alice", "password": "anything"}).status_code
        == 422
    )
    assert (
        client.post("/api/v1/sessions", json={"username": "Alice", "password": "anything"}).status_code == 404
    )
    assert client.put("/api/v1/me/password", json={}).status_code == 404
    assert client.post("/api/v1/recoveries", json={}).status_code == 404
    assert (
        client.post(
            "/api/yggdrasil/authserver/authenticate", json={"username": "Alice", "password": "anything"}
        ).status_code
        == 403
    )
    with client.app.state.db.read() as conn:
        assert "password_hash" not in {r[1] for r in conn.execute("PRAGMA table_info(accounts)")}
        assert "password_hash" not in {r[1] for r in conn.execute("PRAGMA table_info(registrations)")}


def test_restart_keeps_verified_login_and_key(client):
    create_account(client)
    request = client.post("/api/v1/logins", json={"username": "Alice"}).json()
    assert verify(client, request, operation="login").status_code == 200
    public = client.get("/api/yggdrasil").json()["signaturePublickey"]
    restarted = TestClient(create_app(client.app.state.settings))
    assert restarted.get("/api/yggdrasil").json()["signaturePublickey"] == public
    assert exchange(restarted, request, "login").status_code == 200


def test_v1_migration_preserves_identity_and_uuid(tmp_path):
    path = tmp_path / "nomi-auth.sqlite3"
    with sqlite3.connect(path) as conn:
        conn.executescript("""
        CREATE TABLE schema_versions(version INTEGER PRIMARY KEY);
        INSERT INTO schema_versions VALUES(1);
        CREATE TABLE accounts(id TEXT PRIMARY KEY, login_name TEXT NOT NULL, login_normalized TEXT UNIQUE,
          password_hash TEXT NOT NULL, status TEXT DEFAULT 'active', created_at INTEGER);
        INSERT INTO accounts VALUES('account','Alice','alice','legacy-hash','active',0);
        CREATE TABLE profiles(uuid TEXT PRIMARY KEY,account_id TEXT UNIQUE,name TEXT,name_normalized TEXT UNIQUE,
          skin_hash TEXT,skin_model TEXT DEFAULT 'default',last_renamed_at INTEGER);
        INSERT INTO profiles(uuid,account_id,name,name_normalized) VALUES('12345678901234567890123456789012','account','Alice','alice');
        CREATE TABLE identities(account_id TEXT UNIQUE,app_id TEXT,group_id TEXT,member_id TEXT,UNIQUE(app_id,group_id,member_id));
        INSERT INTO identities VALUES('account','app','group','member');
        CREATE TABLE registrations(id TEXT PRIMARY KEY,code_hash TEXT UNIQUE,poll_hash TEXT,name TEXT,
          password_hash TEXT,status TEXT DEFAULT 'PENDING',expires_at INTEGER,account_id TEXT,error TEXT);
        """)
    migrated = TestClient(
        create_app(Settings(data_dir=tmp_path, bot_token="x" * 32, bot_app_id="app", group_openid="group"))
    )
    assert login(migrated)["game"]["selectedProfile"]["id"] == "12345678901234567890123456789012"
