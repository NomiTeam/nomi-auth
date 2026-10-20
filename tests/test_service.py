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
    request = client.post("/api/v1/logins", json={}).json()
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
    assert exchange(client, request).status_code == 404


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
        assert sorted(r.status_code for r in [cancel.result(), redeem.result()]) in ([200, 400], [200, 409])
    with client.app.state.db.read() as conn:
        status = conn.execute(
            "SELECT status FROM registrations WHERE id=?", (request["request_id"],)
        ).fetchone()
        count = conn.execute("SELECT count(*) FROM accounts").fetchone()[0]
    assert (None if status is None else status[0], count) in ((None, 0), ("COMPLETED", 1))


def test_reinstall_login_requires_bound_identity(client):
    create_account(client)
    request = client.post("/api/v1/logins", json={}).json()
    assert exchange(client, request, "login").status_code == 403
    assert verify(client, request, event="wrong", group="other", operation="login").status_code == 400
    assert verify(client, request, event="good", operation="login").status_code == 200
    assert verify(client, request, event="good", operation="login").status_code == 200
    assert verify(client, request, event="another", operation="login").status_code == 409
    assert client.post("/api/v1/logins/" + request["request_id"] + "/session").status_code == 401
    result = exchange(client, request, "login").json()
    assert result["login_name"] == "Alice"
    assert "accessToken" in result["game"]
    assert exchange(client, request, "login").status_code == 404


def test_concurrent_exchange_only_issues_once(client):
    request = create_account(client)
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: exchange(client, request), range(2)))
    assert sorted(r.status_code for r in responses) == [200, 404]
    with client.app.state.db.read() as conn:
        assert conn.execute("SELECT count(*) FROM tokens").fetchone()[0] == 3


def test_expired_and_cancelled_login(client):
    create_account(client)
    request = client.post("/api/v1/logins", json={}).json()
    assert (
        client.delete("/api/v1/logins/" + request["request_id"], headers=private(request)).status_code == 200
    )
    assert verify(client, request, operation="login").status_code == 400
    other = client.post("/api/v1/logins", json={}).json()
    assert verify(client, other, operation="login", event="verified").status_code == 200
    with client.app.state.db.write() as conn:
        conn.execute("UPDATE login_requests SET expires_at=0 WHERE id=?", (other["request_id"],))
    assert exchange(client, other, "login").status_code == 404


def test_unknown_name_generic_response_and_disabled_account(client):
    create_account(client)
    unknown = client.post("/api/v1/logins", json={})
    assert unknown.status_code == 201
    assert (
        verify(client, unknown.json(), member="unregistered", operation="login").json()["status"]
        == "AWAITING_NAME"
    )
    request = client.post("/api/v1/logins", json={}).json()
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
    request = client.post("/api/v1/logins", json={}).json()
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


def test_login_without_name_resolves_sending_members_account(client):
    create_account(client, "Alice", member="alice", event="register-alice")
    create_account(client, "Bob", member="bob", event="register-bob")
    request = client.post("/api/v1/logins").json()
    assert verify(client, request, member="bob", event="bob-login", operation="login").status_code == 200
    assert exchange(client, request, "login").json()["login_name"] == "Bob"


def test_hmcl_native_skin_upload_model_and_ownership(client):
    create_account(client)
    session = login(client)
    headers = {"Authorization": "Bearer " + session["game"]["accessToken"]}
    profile_id = session["game"]["selectedProfile"]["id"]
    output = io.BytesIO()
    Image.new("RGBA", (64, 64), "red").save(output, format="PNG")
    for model, expected in (("slim", "slim"), ("", "default")):
        response = client.put(
            "/api/yggdrasil/api/user/profile/" + profile_id + "/skin",
            headers=headers,
            files={"file": ("skin.png", output.getvalue(), "image/png")},
            data={"model": model},
        )
        assert response.status_code == 204 and not response.content
        profile = client.get("/api/yggdrasil/sessionserver/session/minecraft/profile/" + profile_id).json()
        props = {p["name"]: p["value"] for p in profile["properties"]}
        assert props["uploadableTextures"] == "skin"
        assert (
            json.loads(base64.b64decode(props["textures"]))["textures"]["SKIN"]["metadata"]["model"]
            == expected
        )
    assert (
        client.put(
            "/api/yggdrasil/api/user/profile/" + "0" * 32 + "/skin",
            headers=headers,
            files={"file": ("skin.png", output.getvalue(), "image/png")},
        ).status_code
        == 403
    )


def member_command(client, name, member="new", event="choose-name", operation="register"):
    return client.post(
        "/internal/v1/logins/register" if operation == "register" else "/internal/v1/profiles/rename",
        headers={"Authorization": "Bearer " + "x" * 32},
        json={
            "name": name,
            "bot_app_id": "app",
            "group_openid": "group",
            "member_openid": member,
            "event_id": event,
        },
    )


def test_unified_login_claim_register_and_restart(client):
    request = client.post("/api/v1/logins").json()
    assert verify(client, request, member="new", operation="login").json()["status"] == "AWAITING_NAME"
    assert verify(client, request, member="other", event="steal", operation="login").status_code == 409
    assert member_command(client, "Stolen", member="other").status_code == 409
    assert exchange(client, request, "login").status_code == 403
    restarted = TestClient(create_app(client.app.state.settings))
    result = member_command(restarted, "NewPlayer").json()
    assert result["status"] == "REGISTERED" and result["name"] == "NewPlayer"
    assert member_command(restarted, "NewPlayer").json() == result
    session = exchange(restarted, request, "login").json()
    assert session["game"]["selectedProfile"]["id"] == result["uuid"]
    second = restarted.post("/api/v1/logins").json()
    assert verify(restarted, second, member="new", event="second", operation="login").json() == {
        "status": "VERIFIED",
        "name": "NewPlayer",
        "uuid": result["uuid"],
    }


def test_unified_registration_conflict_closes_request(client):
    create_account(client)
    request = client.post("/api/v1/logins").json()
    verify(client, request, member="new", operation="login")
    result = member_command(client, "alice").json()
    assert result == {"status": "FAILED", "code": "NAME_TAKEN"}
    assert (
        client.get("/api/v1/logins/" + request["request_id"], headers=private(request)).json()["status"]
        == "FAILED"
    )
    assert member_command(client, "Available", event="again").status_code == 409
    assert exchange(client, request, "login").status_code == 404


def test_pending_member_only_one_request_expiry_and_cancellation(client):
    first = client.post("/api/v1/logins").json()
    verify(client, first, member="new", operation="login")
    second = client.post("/api/v1/logins").json()
    assert (
        verify(client, second, member="new", event="second", operation="login").json()["code"]
        == "REQUEST_IN_PROGRESS"
    )
    assert client.delete("/api/v1/logins/" + first["request_id"], headers=private(first)).status_code == 200
    assert member_command(client, "AfterClose").status_code == 409
    verify(client, second, member="new", event="retry", operation="login")
    with client.app.state.db.write() as conn:
        conn.execute("UPDATE login_requests SET expires_at=0 WHERE id=?", (second["request_id"],))
    assert member_command(client, "TooLate", event="late").json()["code"] == "NO_PENDING_REGISTRATION"


def test_register_cancel_race_in_unified_flow(client):
    request = client.post("/api/v1/logins").json()
    verify(client, request, member="new", operation="login")
    with ThreadPoolExecutor(max_workers=2) as executor:
        cancel = executor.submit(
            client.delete, "/api/v1/logins/" + request["request_id"], headers=private(request)
        )
        register = executor.submit(member_command, client, "RacePlayer")
        responses = [cancel.result(), register.result()]
    # A cancellation may also invalidate the verified but unclaimed session.
    with client.app.state.db.read() as conn:
        state = conn.execute(
            "SELECT status FROM login_requests WHERE id=?", (request["request_id"],)
        ).fetchone()
    assert state is None
    assert all(r.status_code in (200, 409) for r in responses)
    assert exchange(client, request, "login").status_code == 404


def test_bot_rename_preserves_uuid_and_ends_conflict(client):
    create_account(client, "Alice", event="alice")
    create_account(client, "Bob", member="bob", event="bob")
    before = login(client)["game"]["selectedProfile"]["id"]
    renamed = member_command(client, "NewAlice", member="member", event="rename", operation="rename").json()
    assert renamed == {"status": "RENAMED", "name": "NewAlice", "uuid": before}
    assert (
        member_command(client, "NewAlice", member="member", event="rename", operation="rename").json()
        == renamed
    )
    conflict = member_command(client, "bOB", member="member", event="conflict", operation="rename").json()
    assert conflict == {"status": "FAILED", "code": "NAME_TAKEN"}
    assert (
        member_command(client, "Another", member="member", event="cooldown", operation="rename").json()[
            "code"
        ]
        == "RENAME_COOLDOWN"
    )
    after = login(client, event="after-rename")["game"]["selectedProfile"]
    assert after == {"id": before, "name": "NewAlice"}
    assert (
        member_command(client, "Unknown", member="unknown", event="unknown", operation="rename").json()[
            "code"
        ]
        == "ACCOUNT_NOT_FOUND"
    )


def test_unified_code_concurrent_first_claimant_wins(client):
    request = client.post("/api/v1/logins").json()
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda i: verify(client, request, member=str(i), event=str(i), operation="login"), range(2)
            )
        )
    assert sorted(r.status_code for r in results) == [200, 409]
    winner = next(str(i) for i, result in enumerate(results) if result.status_code == 200)
    other = "1" if winner == "0" else "0"
    assert member_command(client, "OtherPlayer", member=other).status_code == 409
    assert member_command(client, "Winner", member=winner).json()["status"] == "REGISTERED"


def test_invalid_registration_ends_request(client):
    request = client.post("/api/v1/logins").json()
    verify(client, request, member="new", operation="login")
    assert member_command(client, "not valid").json()["code"] == "INVALID_NAME"
    assert member_command(client, "NowValid", event="retry").status_code == 409


def test_multiple_renames_keep_uuid_and_failed_replay_stays_failed(client):
    create_account(client)
    original = login(client)["game"]["selectedProfile"]["id"]
    for index, name in enumerate(("AliceTwo", "AliceThree", "ALICE")):
        with client.app.state.db.write() as conn:
            conn.execute("UPDATE profiles SET last_renamed_at=0")
        result = member_command(
            client, name, member="member", event=f"rename-{index}", operation="rename"
        ).json()
        assert result["uuid"] == original and result["name"] == name
    failed = member_command(
        client, "AfterCooldown", member="member", event="failed", operation="rename"
    ).json()
    assert failed["code"] == "RENAME_COOLDOWN"
    with client.app.state.db.write() as conn:
        conn.execute("UPDATE profiles SET last_renamed_at=0")
    assert (
        member_command(client, "AfterCooldown", member="member", event="failed", operation="rename").json()
        == failed
    )
    assert login(client, event="after-replay")["game"]["selectedProfile"] == {"id": original, "name": "ALICE"}


def test_launcher_rename_returns_updated_session_and_preserves_uuid(client):
    create_account(client)
    session = login(client)
    game = session["game"]
    profile_id = game["selectedProfile"]["id"]
    headers = {"Authorization": "Bearer " + game["accessToken"]}
    result = client.patch(
        "/api/v1/game/profiles/" + profile_id + "/name", headers=headers, json={"name": "NewAlice"}
    )
    assert result.status_code == 200
    updated = result.json()
    assert updated["game"]["selectedProfile"] == {"id": profile_id, "name": "NewAlice"}
    assert updated["game"]["accessToken"] == game["accessToken"]
    assert client.post("/api/yggdrasil/authserver/validate", json=game).status_code == 204
    assert (
        client.patch(
            "/api/v1/game/profiles/" + "0" * 32 + "/name", headers=headers, json={"name": "Other"}
        ).status_code
        == 403
    )
    assert (
        client.patch(
            "/api/v1/game/profiles/" + profile_id + "/name",
            headers={"Authorization": "Bearer " + session["management_token"]},
            json={"name": "WrongScope"},
        ).status_code
        == 403
    )
    assert (
        member_command(
            client, "Another", member="member", event="bot-after-launcher", operation="rename"
        ).json()["code"]
        == "RENAME_COOLDOWN"
    )


def test_launcher_rename_conflict_does_not_change_profile(client):
    create_account(client, "Alice", event="alice")
    create_account(client, "Bob", member="bob", event="bob")
    game = login(client)["game"]
    profile_id = game["selectedProfile"]["id"]
    result = client.patch(
        "/api/v1/game/profiles/" + profile_id + "/name",
        headers={"Authorization": "Bearer " + game["accessToken"]},
        json={"name": "bOB"},
    )
    assert result.status_code == 409 and result.json()["code"] == "NAME_TAKEN"
    assert login(client, event="still-alice")["game"]["selectedProfile"] == game["selectedProfile"]


def test_cleanup_deletes_transients_and_keeps_live_identity(client):
    import time

    create_account(client)
    request = client.post("/api/v1/logins").json()
    session = login(client)
    with client.app.state.db.write() as conn:
        conn.execute("UPDATE login_requests SET expires_at=0 WHERE id=?", (request["request_id"],))
        conn.execute("UPDATE tokens SET expires_at=0 WHERE kind='management'")
        conn.execute("UPDATE receipts SET created_at=0")
        conn.execute("UPDATE audit SET created_at=0")
    client.app.state.db.cleanup(int(time.time()))
    with client.app.state.db.read() as conn:
        for table in ("receipts", "audit"):
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
        for table in ("accounts", "profiles", "identities"):
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM login_requests").fetchone()[0] == 0
    assert client.post("/api/yggdrasil/authserver/validate", json=session["game"]).status_code == 204


def test_failed_result_deleted_after_private_read_only(client):
    create_account(client)
    request = client.post("/api/v1/logins").json()
    verify(client, request, member="new", operation="login")
    member_command(client, "Alice")
    path = "/api/v1/logins/" + request["request_id"]
    assert client.get(path).status_code == 401
    assert client.get(path, headers=private(request)).json()["error"] == "NAME_TAKEN"
    assert client.get(path, headers=private(request)).status_code == 404


def refresh_headers(session):
    return {"Authorization": "Bearer " + session["refresh_token"]}


def test_launcher_refresh_after_game_expiry_rotates_once(client):
    create_account(client)
    session = login(client)
    with client.app.state.db.write() as conn:
        conn.execute("UPDATE tokens SET expires_at=0 WHERE kind='game'")
    assert client.post("/api/yggdrasil/authserver/validate", json=session["game"]).status_code == 403
    refreshed = client.post("/api/v1/sessions/refresh", headers=refresh_headers(session))
    assert refreshed.status_code == 200
    renewed = refreshed.json()
    assert renewed["game"]["selectedProfile"] == session["game"]["selectedProfile"]
    assert renewed["refresh_token"] != session["refresh_token"]
    assert renewed["game"]["accessToken"] != session["game"]["accessToken"]
    assert renewed["refresh_expires_at"] - renewed["game_expires_at"] == 29 * 86400
    assert client.post("/api/v1/sessions/refresh", headers=refresh_headers(session)).status_code == 403
    assert client.post("/api/yggdrasil/authserver/validate", json=renewed["game"]).status_code == 204
    assert (
        client.post(
            "/api/yggdrasil/authserver/validate", json={"accessToken": renewed["refresh_token"]}
        ).status_code
        == 403
    )
    with client.app.state.db.read() as conn:
        from nomi_auth.security import digest

        assert (
            conn.execute(
                "SELECT kind FROM tokens WHERE hash=?", (digest(renewed["refresh_token"]),)
            ).fetchone()[0]
            == "refresh"
        )
        assert (
            conn.execute("SELECT count(*) FROM tokens WHERE hash=?", (renewed["refresh_token"],)).fetchone()[
                0
            ]
            == 0
        )


def test_concurrent_refresh_only_one_wins_and_other_device_survives(client):
    create_account(client)
    first = login(client, event="first")
    second = login(client, event="second")
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(
            executor.map(
                lambda _: client.post("/api/v1/sessions/refresh", headers=refresh_headers(first)), range(2)
            )
        )
    assert sorted(r.status_code for r in responses) == [200, 403]
    assert client.post("/api/yggdrasil/authserver/validate", json=first["game"]).status_code == 403
    assert client.post("/api/yggdrasil/authserver/validate", json=second["game"]).status_code == 204
    assert client.post("/api/v1/sessions/refresh", headers=refresh_headers(second)).status_code == 200


def test_refresh_expiry_scope_disable_and_revocation(client):
    create_account(client)
    session = login(client)
    assert (
        client.post(
            "/api/v1/sessions/refresh", headers={"Authorization": "Bearer " + session["game"]["accessToken"]}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/sessions/refresh", headers={"Authorization": "Bearer " + session["management_token"]}
        ).status_code
        == 403
    )
    assert client.delete("/api/v1/sessions/refresh", headers=refresh_headers(session)).status_code == 204
    assert client.post("/api/v1/sessions/refresh", headers=refresh_headers(session)).status_code == 403
    assert client.post("/api/yggdrasil/authserver/validate", json=session["game"]).status_code == 403
    expired = login(client, event="expired")
    with client.app.state.db.write() as conn:
        conn.execute("UPDATE tokens SET expires_at=0 WHERE kind='refresh'")
    assert client.post("/api/v1/sessions/refresh", headers=refresh_headers(expired)).status_code == 403
    disabled = login(client, event="disabled")
    with client.app.state.db.write() as conn:
        conn.execute("UPDATE accounts SET status='disabled'")
        conn.execute("DELETE FROM tokens")
    assert client.post("/api/v1/sessions/refresh", headers=refresh_headers(disabled)).status_code == 403


def test_refresh_retry_is_exact_bounded_and_revocable(client):
    import time

    create_account(client)
    original = login(client)
    headers = {**refresh_headers(original), "X-Request-ID": "a" * 64}
    first = client.post("/api/v1/sessions/refresh", headers=headers)
    assert first.status_code == 200
    assert client.post("/api/v1/sessions/refresh", headers=headers).json() == first.json()
    assert (
        client.post("/api/v1/sessions/refresh", headers={**headers, "X-Request-ID": "b" * 64}).status_code
        == 403
    )
    with client.app.state.db.read() as conn:
        row = dict(conn.execute("SELECT * FROM refresh_retries").fetchone())
        assert original["refresh_token"] not in str(row)
        assert first.json()["refresh_token"] not in str(row)
    client.delete("/api/v1/sessions/refresh", headers=refresh_headers(first.json()))
    assert client.post("/api/v1/sessions/refresh", headers=headers).status_code == 403
    second = login(client, event="second")
    headers = {**refresh_headers(second), "X-Request-ID": "c" * 64}
    assert client.post("/api/v1/sessions/refresh", headers=headers).status_code == 200
    with client.app.state.db.write() as conn:
        conn.execute("UPDATE refresh_retries SET expires_at=0")
    client.app.state.db.cleanup(int(time.time()))
    assert client.post("/api/v1/sessions/refresh", headers=headers).status_code == 403


def test_concurrent_same_refresh_request_returns_one_grant(client):
    create_account(client)
    session = login(client)
    headers = {**refresh_headers(session), "X-Request-ID": "d" * 64}
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(
            executor.map(lambda _: client.post("/api/v1/sessions/refresh", headers=headers), range(2))
        )
    assert all(r.status_code == 200 for r in responses)
    assert responses[0].json() == responses[1].json()
    with client.app.state.db.read() as conn:
        assert conn.execute("SELECT count(*) FROM tokens WHERE kind='refresh'").fetchone()[0] == 1
    with client.app.state.db.write() as conn:
        conn.execute("UPDATE accounts SET status='disabled'")
    assert client.post("/api/v1/sessions/refresh", headers=headers).status_code == 403


def test_login_exchange_response_loss_is_retryable_and_revocable(client):
    create_account(client)
    request = client.post("/api/v1/logins").json()
    verify(client, request, operation="login")
    path = f"/api/v1/logins/{request['request_id']}/session"
    headers = {**private(request), "X-Request-ID": "e" * 64}
    first = client.post(path, headers=headers)
    assert first.status_code == 200
    assert client.post(path, headers=headers).json() == first.json()
    assert client.post(path, headers={**headers, "Authorization": "Bearer other"}).status_code != 200
    assert client.post(path, headers={**headers, "X-Request-ID": "f" * 64}).status_code != 200
    client.delete("/api/v1/sessions/refresh", headers=refresh_headers(first.json()))
    assert client.post(path, headers=headers).status_code != 200
    with client.app.state.db.read() as conn:
        assert conn.execute("SELECT count(*) FROM login_retries").fetchone()[0] == 0


def test_authenticated_profile_syncs_bot_rename_without_changing_uuid(client):
    create_account(client)
    session = login(client)
    headers = {"Authorization": "Bearer " + session["game"]["accessToken"]}
    before = client.get("/api/v1/game/profile", headers=headers).json()
    assert (
        member_command(
            client, "RenamedAlice", member="member", event="rename-sync", operation="rename"
        ).json()["status"]
        == "RENAMED"
    )
    after = client.get("/api/v1/game/profile", headers=headers).json()
    assert after == {"id": before["id"], "name": "RenamedAlice"}
    assert client.get("/api/v1/game/profile", headers=refresh_headers(session)).status_code == 403


def test_schema_four_upgrade_keeps_existing_accounts_and_sessions(client):
    from nomi_auth.db import Database

    create_account(client)
    session = login(client)
    with client.app.state.db.write() as conn:
        conn.execute("DROP TABLE login_retries")
        conn.execute("DROP TABLE refresh_retries")
        conn.execute("DELETE FROM schema_versions WHERE version=5")
    upgraded = Database(client.app.state.db.path)
    with upgraded.read() as conn:
        assert conn.execute("SELECT max(version) FROM schema_versions").fetchone()[0] == 5
        assert (
            conn.execute("SELECT uuid FROM profiles").fetchone()[0]
            == session["game"]["selectedProfile"]["id"]
        )
    assert client.post("/api/yggdrasil/authserver/validate", json=session["game"]).status_code == 204
