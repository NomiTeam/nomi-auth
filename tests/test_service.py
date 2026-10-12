import base64
import io
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi.testclient import TestClient
from PIL import Image

from nomi_auth.app import create_app
from nomi_auth.config import Settings

PASSWORD = "a-long-test-password"


@pytest.fixture
def client(tmp_path):
    return TestClient(
        create_app(Settings(data_dir=tmp_path, bot_token="x" * 32, bot_app_id="app", group_openid="group"))
    )


def request_account(client, name="Alice"):
    response = client.post("/api/v1/registrations", json={"name": name, "password": PASSWORD})
    assert response.status_code == 201, response.text
    return response.json()


def redeem(client, request, member="member", event="event", group="group"):
    return client.post(
        "/internal/v1/registrations/redeem",
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
    assert redeem(client, request, member, event).json()["status"] == "COMPLETED"
    return request


def login(client, username="Alice"):
    result = client.post("/api/v1/sessions", json={"username": username, "password": PASSWORD})
    assert result.status_code == 200, result.text
    return {"Authorization": "Bearer " + result.json()["access_token"]}


def test_register_and_private_poll(client):
    request = create_account(client)
    assert client.get("/api/v1/registrations/" + request["request_id"]).status_code == 401
    result = client.get(
        "/api/v1/registrations/" + request["request_id"],
        headers={"Authorization": "Bearer " + request["poll_token"]},
    )
    assert result.json()["status"] == "COMPLETED"
    assert client.get("/api/v1/names/availability", params={"name": "alice"}).json() == {"available": False}
    assert redeem(client, request).status_code == 200  # same event is idempotent
    assert redeem(client, request, event="later", member="other").status_code == 409


def test_invalid_group_and_bound_member_do_not_consume(client):
    create_account(client)
    request = request_account(client, "Bob")
    assert redeem(client, request, event="wronggroup", group="other").status_code == 400
    assert redeem(client, request, event="bound").json()["code"] == "IDENTITY_ALREADY_BOUND"
    assert redeem(client, request, member="new", event="new").json()["status"] == "COMPLETED"


def test_same_code_concurrent_members(client):
    request = request_account(client)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda i: redeem(client, request, member=str(i), event=str(i)), range(2)))
    assert sorted(r.status_code for r in results) == [200, 409]
    with client.app.state.db.read() as conn:
        assert conn.execute("SELECT count(*) FROM accounts").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM identities").fetchone()[0] == 1


def test_name_race(client):
    first, second = request_account(client), request_account(client, "alice")
    assert redeem(client, first).json()["status"] == "COMPLETED"
    assert redeem(client, second, member="other", event="other").json() == {
        "status": "FAILED",
        "code": "NAME_TAKEN",
    }


def test_cancel_and_expire(client):
    request = request_account(client)
    headers = {"Authorization": "Bearer " + request["poll_token"]}
    assert client.delete("/api/v1/registrations/" + request["request_id"], headers=headers).status_code == 200
    assert redeem(client, request).status_code == 409
    other = request_account(client, "Bob")
    with client.app.state.db.write() as conn:
        conn.execute("UPDATE registrations SET expires_at=0 WHERE id=?", (other["request_id"],))
    assert redeem(client, other, event="expired").json()["code"] == "REQUEST_EXPIRED"


def test_game_sessions_signature_and_rename(client):
    create_account(client)
    root = "/api/yggdrasil"
    response = client.post(
        root + "/authserver/authenticate",
        json={"username": "Alice", "password": PASSWORD, "clientToken": "client", "requestUser": True},
    )
    game = response.json()
    assert response.status_code == 200, response.text
    profile_id = game["selectedProfile"]["id"]
    token = {"accessToken": game["accessToken"], "clientToken": "client"}
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
    headers = login(client)
    assert (
        client.patch(
            "/api/v1/me/profile/name", headers=headers, json={"name": "NewAlice", "password": PASSWORD}
        ).json()["uuid"]
        == profile_id
    )
    assert client.get("/api/v1/me", headers=headers).json()["login_name"] == "Alice"
    assert client.post(root + "/authserver/refresh", json=token).status_code == 200
    assert client.post(root + "/authserver/validate", json=token).status_code == 403


def test_skin_and_password_revocation(client):
    create_account(client)
    headers = login(client)
    buffer = io.BytesIO()
    Image.new("RGBA", (64, 64), "red").save(buffer, format="PNG")
    response = client.put(
        "/api/v1/me/profile/skin",
        headers=headers,
        files={"image": ("skin.png", buffer.getvalue(), "image/png")},
        data={"model": "slim"},
    )
    assert response.status_code == 200, response.text
    assert client.get("/textures/" + response.json()["hash"]).headers["content-type"] == "image/png"
    assert (
        client.put(
            "/api/v1/me/profile/skin", headers=headers, files={"image": ("bad.png", b"notpng", "image/png")}
        ).status_code
        == 400
    )
    assert (
        client.put(
            "/api/v1/me/password",
            headers=headers,
            json={"old_password": PASSWORD, "new_password": "new-long-password"},
        ).status_code
        == 204
    )
    assert client.get("/api/v1/me", headers=headers).status_code == 403


def test_recovery_requires_original_identity(client):
    create_account(client)
    request = client.post("/api/v1/recoveries", json={"username": "Alice"}).json()
    payload = {
        "code": request["code"],
        "bot_app_id": "app",
        "group_openid": "group",
        "member_openid": "wrong",
        "event_id": "recover",
    }
    headers = {"Authorization": "Bearer " + "x" * 32}
    assert client.post("/internal/v1/recoveries/verify", headers=headers, json=payload).status_code == 403
    payload["member_openid"] = "member"
    assert client.post("/internal/v1/recoveries/verify", headers=headers, json=payload).status_code == 200
    private = {"Authorization": "Bearer " + request["poll_token"]}
    path = "/api/v1/recoveries/" + request["request_id"] + "/complete"
    assert client.post(path, headers=private, json={"password": "recovered-password"}).status_code == 204
    assert client.post(path, headers=private, json={"password": "recovered-again"}).status_code == 403


def test_cancel_races_with_redemption(client):
    request = request_account(client)
    private = {"Authorization": "Bearer " + request["poll_token"]}
    with ThreadPoolExecutor(max_workers=2) as executor:
        cancel = executor.submit(
            client.delete, "/api/v1/registrations/" + request["request_id"], headers=private
        )
        exchange = executor.submit(redeem, client, request)
        results = [cancel.result(), exchange.result()]
    assert sorted(r.status_code for r in results) == [200, 409]
    with client.app.state.db.read() as conn:
        row = conn.execute("SELECT status FROM registrations WHERE id=?", (request["request_id"],)).fetchone()
        count = conn.execute("SELECT count(*) FROM accounts").fetchone()[0]
    assert (row["status"], count) in (("CANCELLED", 0), ("COMPLETED", 1))


def test_restart_keeps_pending_request_and_signing_key(client):
    request = request_account(client)
    public = client.get("/api/yggdrasil").json()["signaturePublickey"]
    restarted = TestClient(create_app(client.app.state.settings))
    assert restarted.get("/api/yggdrasil").json()["signaturePublickey"] == public
    assert redeem(restarted, request).status_code == 200


def test_game_bad_payload_is_not_server_error(client):
    for path in ("authenticate", "refresh", "validate", "invalidate"):
        response = client.post("/api/yggdrasil/authserver/" + path, json={"username": [], "accessToken": []})
        assert response.status_code == 400
        assert response.json()["error"] == "IllegalArgumentException"


def test_invalid_request_does_not_echo_password(client):
    response = client.post("/api/v1/registrations", json={"name": "Alice", "password": "short"})
    assert response.status_code == 422
    assert "short" not in response.text


def test_game_token_cannot_manage_account(client):
    create_account(client)
    token = client.post(
        "/api/yggdrasil/authserver/authenticate", json={"username": "Alice", "password": PASSWORD}
    ).json()["accessToken"]
    assert client.get("/api/v1/me", headers={"Authorization": "Bearer " + token}).status_code == 403


def test_skin_is_reencoded_and_has_signed_url(client):
    import json

    from PIL.PngImagePlugin import PngInfo

    create_account(client)
    headers = login(client)
    info = PngInfo()
    info.add_text("unwanted", "metadata-to-strip")
    output = io.BytesIO()
    Image.new("RGBA", (64, 64)).save(output, format="PNG", pnginfo=info)
    response = client.put(
        "/api/v1/me/profile/skin",
        headers=headers,
        files={"image": ("skin.png", output.getvalue(), "image/png")},
        data={"model": "slim"},
    )
    downloaded = client.get("/textures/" + response.json()["hash"])
    with Image.open(io.BytesIO(downloaded.content)) as image:
        assert "unwanted" not in image.info
    profile_id = client.get("/api/v1/me", headers=headers).json()["profile"]["uuid"]
    prop = client.get(
        "/api/yggdrasil/sessionserver/session/minecraft/profile/" + profile_id, params={"unsigned": "false"}
    ).json()["properties"][0]
    textures = json.loads(base64.b64decode(prop["value"]))["textures"]
    assert textures["SKIN"]["metadata"]["model"] == "slim"
    assert textures["SKIN"]["url"].endswith(response.json()["hash"])
