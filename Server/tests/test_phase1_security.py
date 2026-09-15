"""Behavioral regressions for the phase 1 security requirements."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select
from starlette.websockets import WebSocketDisconnect

from app.config import Settings
from app.database import check_db_connection
from app.main import create_app
from app.models import LoginSession, PasswordHistory, RefreshToken, User
from app.password_policy import (
    BreachCheckUnavailable,
    check_password_breach,
    validate_password,
)
from app.security import hash_secret
from app.session_management import SessionManager
from app.timeutils import naive_utc, utc_now
from tests.conftest import create_reset_token, register_device

PASSWORD = "Violet!Harbor7Lantern"
SECRET = "testing-only-secret-with-at-least-32-chars"


def register(client, username="alice"):
    response = client.post(
        "/api/auth/register", json={"username": username, "password": PASSWORD}
    )
    assert response.status_code == 200, response.text
    return response.json()["user"]


def login(client, username="alice"):
    response = client.post(
        "/api/auth/login", json={"username": username, "password": PASSWORD}
    )
    assert response.status_code == 200, response.text
    return response.json()


def headers(tokens):
    return {"Authorization": "Bearer " + tokens["access_token"]}


def test_environment_and_secret_file_loading(tmp_path, monkeypatch):
    monkeypatch.setenv("MYDESK_SECRET_KEY", "env-key")
    monkeypatch.setenv("MYDESK_DATABASE_POOL_SIZE", "17")
    (tmp_path / "MYDESK_SECRET_KEY").write_text(SECRET)
    settings = Settings(_env_file=None, _secrets_dir=tmp_path)
    assert settings.secret_key == SECRET
    assert settings.database_pool_size == 17
    assert SECRET not in repr(settings)


@pytest.mark.parametrize(
    "change",
    [
        {"secret_key": "short"},
        {"secret_key": "dev-secret-change-me-in-production"},
        {"database_url": "sqlite:///:memory:"},
        {"database_url": "postgresql+asyncpg://db/x"},
        {"debug": True},
        {"cors_allowed_origins": "*"},
        {"cors_allowed_origins": "http://desk.example.com"},
        {"cors_allowed_origins": "https://desk.example.com/path"},
        {"rate_limit_enabled": False},
        {"check_password_breaches": False},
        {"min_password_strength": 2},
    ],
)
def test_production_rejects_insecure_configuration(change):
    values = dict(
        environment="prod",
        secret_key=SECRET,
        database_url="postgresql+psycopg2://db/test",
        redis_url="redis://redis/0",
        cors_allowed_origins="https://desk.example.com",
        check_password_breaches=True,
        rate_limit_enabled=True,
    )
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **(values | change))


def test_cors_and_security_headers_follow_configuration(client):
    response = client.options(
        "/api/auth/login",
        headers={
            "Origin": "http://localhost:8000",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:8000"
    assert response.headers["access-control-max-age"] == "600"
    denied = client.options(
        "/api/auth/login",
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers
    assert "strict-transport-security" not in client.get("/").headers
    assert check_db_connection(client.app.state.db_engine)
    assert client.get("/api/health").status_code == 200


def test_limits_are_per_ip_with_headers_and_do_not_trust_client_forwarding(client):
    client.app.state.settings.rate_limit_enabled = True
    with TestClient(client.app, client=("192.0.2.1", 1000)) as first:
        for i in range(5):
            response = first.post(
                "/api/auth/login", json={"username": "absent", "password": PASSWORD}
            )
            assert response.status_code == 401
            assert response.headers["x-ratelimit-remaining"] == str(4 - i)
        response = first.post(
            "/api/auth/login",
            json={"username": "absent", "password": PASSWORD},
            headers={"X-Forwarded-For": "192.0.2.3"},
        )
        assert response.status_code == 429
        assert response.headers["x-ratelimit-remaining"] == "0"
        assert int(response.headers["retry-after"]) > 0
    with TestClient(client.app, client=("192.0.2.2", 1000)) as second:
        assert (
            second.post(
                "/api/auth/login", json={"username": "absent", "password": PASSWORD}
            ).status_code
            == 401
        )


def test_pairing_limits_are_per_user(client):
    register(client)
    register(client, "bob")
    first, second = login(client), login(client, "bob")
    client.app.state.settings.rate_limit_enabled = True
    for _ in range(10):
        response = client.post("/api/pairing-codes", headers=headers(first))
        assert response.status_code == 200
        assert "x-ratelimit-limit" in response.headers
    assert client.post("/api/pairing-codes", headers=headers(first)).status_code == 429
    assert client.post("/api/pairing-codes", headers=headers(second)).status_code == 200


@pytest.mark.parametrize("path", ["bootstrap", "register"])
def test_password_policy_applies_to_account_creation(client, path):
    response = client.post(
        f"/api/auth/{path}", json={"username": "alice", "password": "password123"}
    )
    assert response.status_code == 400
    assert "uppercase" in response.json()["detail"]
    with client.app.state.SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 0


@pytest.mark.parametrize(
    "payload",
    [
        {"username": "<script>"},
        {"username": "a" * 31},
        {"email": "not-an-email"},
        {"email": "x" * 300 + "@example.com"},
    ],
)
def test_registration_inputs_are_validated_without_echoing_passwords(client, payload):
    response = client.post(
        "/api/auth/register",
        json={"username": "alice", "password": PASSWORD, **payload},
    )
    assert response.status_code == 422
    assert PASSWORD not in response.text


def test_password_breach_range_protocol_and_fail_closed(monkeypatch):
    import hashlib

    digest = hashlib.sha1(PASSWORD.encode(), usedforsecurity=False).hexdigest().upper()

    def response(url, **kwargs):
        assert url.endswith(digest[:5]) and PASSWORD not in url
        assert kwargs["headers"]["Add-Padding"] == "true"
        return httpx.Response(
            200, text=digest[5:] + ":1\n", request=httpx.Request("GET", url)
        )

    monkeypatch.setattr(httpx, "get", response)
    assert check_password_breach(PASSWORD)

    def unavailable(*args, **kwargs):
        raise httpx.ConnectError("unavailable")

    monkeypatch.setattr(httpx, "get", unavailable)
    with pytest.raises(BreachCheckUnavailable):
        check_password_breach(PASSWORD)


def test_password_history_uses_argon2_and_reset_cannot_bypass_policy(client):
    user = register(client)
    token = create_reset_token(client, "alice")
    for bad in (PASSWORD, "password123"):
        response = client.post(
            "/api/auth/password-reset", json={"token": token, "new_password": bad}
        )
        assert response.status_code == 400
    assert login(client)
    for new in ("Copper!Meadow8Falcon", "Silver!Garden9Canyon", "Orchid!Valley6Moon"):
        token = create_reset_token(client, "alice")
        assert (
            client.post(
                "/api/auth/password-reset", json={"token": token, "new_password": new}
            ).status_code
            == 200
        )
    with client.app.state.SessionLocal() as db:
        history = db.scalars(
            select(PasswordHistory).where(PasswordHistory.user_id == user["id"])
        ).all()
        assert len(history) == 3
        assert all(row.password_hash.startswith("$argon2") for row in history)
        valid, _ = validate_password(
            "Copper!Meadow8Falcon",
            [h.password_hash for h in history],
            settings=client.app.state.settings,
        )
        assert not valid


def test_concurrent_limit_revokes_old_access_and_refresh_tokens(client):
    user = register(client)
    tokens = [login(client) for _ in range(4)]
    assert client.get("/api/auth/me", headers=headers(tokens[0])).status_code == 401
    assert (
        client.post(
            "/api/auth/refresh", json={"refresh_token": tokens[0]["refresh_token"]}
        ).status_code
        == 401
    )
    for current in tokens[1:]:
        assert client.get("/api/auth/me", headers=headers(current)).status_code == 200
    with client.app.state.SessionLocal() as db:
        assert (
            SessionManager(db, client.app.state.settings).get_active_session_count(
                user["id"]
            )
            == 3
        )


def test_concurrent_logins_cannot_exceed_limit(client):
    register(client)
    with ThreadPoolExecutor(max_workers=4) as pool:
        tokens = list(pool.map(lambda _: login(client), range(4)))
    assert (
        sum(
            client.get("/api/auth/me", headers=headers(t)).status_code == 200
            for t in tokens
        )
        == 3
    )


def test_logout_revokes_rotated_chain_only_and_closes_websocket(client, monkeypatch):
    import app.routes.websocket as ws_routes

    monkeypatch.setattr(ws_routes, "AUTH_RECHECK_SECONDS", 0.05)
    register(client)
    first, second = login(client), login(client)
    rotated = client.post(
        "/api/auth/refresh", json={"refresh_token": first["refresh_token"]}
    ).json()
    with client.websocket_connect(
        "/console/ws", subprotocols=["mydesk", "bearer." + first["access_token"]]
    ) as ws:
        assert ws.receive_json()["type"] == "console_registered"
        response = client.post(
            "/api/auth/logout",
            headers=headers(first),
            json={"refresh_token": first["refresh_token"]},
        )
        assert response.status_code == 200
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()
    for tokens in (first, rotated):
        assert client.get("/api/auth/me", headers=headers(tokens)).status_code == 401
        assert (
            client.post(
                "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
            ).status_code
            == 401
        )
    assert client.get("/api/auth/me", headers=headers(second)).status_code == 200


def test_sessions_survive_restart_and_refresh_does_not_extend_absolute_lifetime(client):
    register(client)
    tokens = login(client)
    app = create_app(client.app.state.settings)
    with TestClient(app) as restarted:
        assert restarted.get("/api/auth/me", headers=headers(tokens)).status_code == 200
        rotated = restarted.post(
            "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        ).json()
        sid = jwt.decode(tokens["access_token"], options={"verify_signature": False})[
            "sid"
        ]
        with app.state.SessionLocal() as db:
            session = db.get(LoginSession, sid)
            refresh = db.scalar(
                select(RefreshToken).where(
                    RefreshToken.token_hash == hash_secret(rotated["refresh_token"])
                )
            )
            assert naive_utc(refresh.expires_at) == naive_utc(session.expires_at)
            session.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()
        assert (
            restarted.get("/api/auth/me", headers=headers(rotated)).status_code == 401
        )
        assert (
            restarted.post(
                "/api/auth/refresh", json={"refresh_token": rotated["refresh_token"]}
            ).status_code
            == 401
        )


@pytest.mark.parametrize("session_id", [None, "missing-session"])
def test_jwt_requires_a_live_session(client, session_id):
    register(client)
    payload = jwt.decode(
        login(client)["access_token"], options={"verify_signature": False}
    )
    if session_id is None:
        del payload["sid"]
    else:
        payload["sid"] = session_id
    token = jwt.encode(payload, client.app.state.settings.secret_key, algorithm="HS256")
    assert (
        client.get(
            "/api/auth/me", headers={"Authorization": "Bearer " + token}
        ).status_code
        == 401
    )
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            "/console/ws", subprotocols=["mydesk", "bearer." + token]
        ):
            pytest.fail("Token without a live session accepted")


def test_failed_device_handshake_does_not_disconnect_real_device(client, auth_headers):
    device = register_device(client, auth_headers)
    url = f"/device/ws?device_id={device['device_id']}"
    with client.websocket_connect(
        url, headers={"Authorization": "Bearer " + device["device_token"]}
    ) as ws:
        ws.receive_json()
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                url, headers={"Authorization": "Bearer wrong"}
            ):
                pytest.fail("Bad token accepted")
        ws.send_json({"type": "heartbeat"})
        assert ws.receive_json()["type"] == "heartbeat_ack"
        assert client.app.state.ws_manager.is_device_online(device["device_id"])


def test_websocket_rejects_foreign_origin_and_malformed_messages(client, owner_token):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            "/console/ws",
            subprotocols=["mydesk", "bearer." + owner_token],
            headers={"Origin": "https://evil.example.com"},
        ):
            pytest.fail("Foreign origin accepted")
    with client.websocket_connect(
        "/console/ws", subprotocols=["mydesk", "bearer." + owner_token]
    ) as ws:
        ws.receive_json()
        for message in (
            [],
            {"type": "session_start_request", "deviceId": []},
            {"type": "input_text", "sessionId": "s", "text": "x" * 10001},
        ):
            ws.send_json(message)
            assert ws.receive_json()["code"] == "INVALID_MESSAGE"
        ws.send_json({"type": "heartbeat"})
        assert ws.receive_json()["type"] == "heartbeat_ack"


def test_bootstrap_is_atomic(client):
    barrier = Barrier(2)

    def bootstrap(i):
        barrier.wait()
        return client.post(
            "/api/auth/bootstrap", json={"username": f"owner{i}", "password": PASSWORD}
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(r.status_code for r in pool.map(bootstrap, range(2))) == [
            200,
            409,
        ]


def test_pairing_code_is_atomically_consumed(client, auth_headers):
    code = client.post("/api/pairing-codes", headers=auth_headers).json()["code"]
    barrier = Barrier(2)

    def pair(_):
        barrier.wait()
        return client.post(
            "/api/devices/pair",
            json={
                "pairing_code": code,
                "name": "Device",
                "device_password": "device-password",
            },
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(r.status_code for r in pool.map(pair, range(2))) == [200, 400]


def test_browser_websocket_protocol_auth_avoids_url_credentials(client, owner_token):
    with client.websocket_connect(
        "/console/ws", subprotocols=["mydesk", "bearer." + owner_token]
    ) as ws:
        assert ws.accepted_subprotocol == "mydesk"
        assert ws.receive_json()["type"] == "console_registered"


def test_websocket_query_credentials_are_not_accepted(
    client, owner_token, auth_headers
):
    device = register_device(client, auth_headers)
    for url in (
        "/console/ws?token=" + owner_token,
        f"/device/ws?device_id={device['device_id']}&token={device['device_token']}",
    ):
        with pytest.raises(WebSocketDisconnect) as error:
            with client.websocket_connect(url):
                pytest.fail("Query credential accepted")
        assert error.value.code == 4401


def test_breach_service_failure_does_not_create_an_account(client, monkeypatch):
    import app.password_policy as policy

    def unavailable(*args, **kwargs):
        raise BreachCheckUnavailable("Password breach check unavailable; retry later")

    monkeypatch.setattr(policy, "check_password_breach", unavailable)
    client.app.state.settings.check_password_breaches = True
    response = client.post(
        "/api/auth/bootstrap", json={"username": "alice", "password": PASSWORD}
    )
    assert response.status_code == 503
    with client.app.state.SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 0


def test_logout_cannot_revoke_another_user_session(client):
    register(client)
    register(client, "bob")
    alice, bob = login(client), login(client, "bob")
    response = client.post(
        "/api/auth/logout",
        headers=headers(bob),
        json={"refresh_token": alice["refresh_token"]},
    )
    assert response.status_code == 400
    assert client.get("/api/auth/me", headers=headers(alice)).status_code == 200


def test_device_cannot_end_another_device_session_and_revoke_notifies_console(
    client, auth_headers, owner_token
):
    first = register_device(client, auth_headers)
    second = register_device(client, auth_headers)

    with (
        client.websocket_connect(
            f"/device/ws?device_id={first['device_id']}",
            headers={"Authorization": "Bearer " + first["device_token"]},
        ) as active,
        client.websocket_connect(
            f"/device/ws?device_id={second['device_id']}",
            headers={"Authorization": "Bearer " + second["device_token"]},
        ) as other,
    ):
        active.receive_json()
        other.receive_json()
        with client.websocket_connect(
            "/console/ws", subprotocols=["mydesk", "bearer." + owner_token]
        ) as console:
            console.receive_json()
            console.send_json(
                {
                    "type": "session_start_request",
                    "deviceId": first["device_id"],
                    "devicePassword": "password-device",
                }
            )
            sid = active.receive_json()["sessionId"]
            assert console.receive_json()["type"] == "session_started"
            for message in (
                {"type": "session_end", "sessionId": sid},
                {"type": "heartbeat", "sessionId": sid},
                {"type": "session_error", "sessionId": sid, "code": "ERROR"},
            ):
                other.send_json(message)
                assert other.receive_json()["code"] == "SESSION_NOT_AUTHORIZED"
            console.send_json(
                {
                    "type": "input_swipe",
                    "sessionId": sid,
                    "from": {"x": 1, "y": 2},
                    "to": {"x": 3, "y": 4},
                    "durationMs": 450,
                }
            )
            swipe = active.receive_json()
            assert swipe["type"] == "input_swipe" and swipe["from"] == {"x": 1, "y": 2}
            response = client.post(
                f"/api/devices/{first['device_id']}/revoke", headers=auth_headers
            )
            assert response.status_code == 200
            assert console.receive_json()["reason"] == "device_revoked"
            with pytest.raises(WebSocketDisconnect):
                active.receive_json()


@pytest.mark.parametrize("revoke_during_handshake", [False, True])
def test_pending_device_handshake_cannot_replace_or_revive_connection(
    client, auth_headers, monkeypatch, revoke_during_handshake
):
    import asyncio
    from threading import Event
    from starlette.websockets import WebSocket

    device = register_device(client, auth_headers)
    entered, release = Event(), Event()
    original_accept = WebSocket.accept

    async def paused_accept(socket, *args, **kwargs):
        if socket.url.path == "/device/ws" and not entered.is_set():
            entered.set()
            assert await asyncio.to_thread(release.wait, 10)
        return await original_accept(socket, *args, **kwargs)

    monkeypatch.setattr(WebSocket, "accept", paused_accept)
    url = f"/device/ws?device_id={device['device_id']}"
    auth = {"Authorization": "Bearer " + device["device_token"]}

    def first_connection():
        with client.websocket_connect(url, headers=auth) as ws:
            if revoke_during_handshake:
                with pytest.raises(WebSocketDisconnect) as error:
                    ws.receive_json()
                assert error.value.code == 4401
                return
            assert ws.receive_json()["type"] == "device_registered"
            ws.send_json({"type": "heartbeat"})
            assert ws.receive_json()["type"] == "heartbeat_ack"
            assert client.app.state.ws_manager.is_device_online(device["device_id"])

    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(first_connection)
        try:
            assert entered.wait(10)
            assert not client.app.state.ws_manager.is_device_online(device["device_id"])
            with pytest.raises(WebSocketDisconnect) as error:
                with client.websocket_connect(url, headers=auth) as duplicate:
                    duplicate.receive_json()
            assert error.value.code == 4409
            if revoke_during_handshake:
                assert (
                    client.post(
                        f"/api/devices/{device['device_id']}/revoke",
                        headers=auth_headers,
                    ).status_code
                    == 200
                )
        finally:
            release.set()
        first.result(timeout=10)


def test_restart_releases_interrupted_remote_session(client, owner_token, auth_headers):
    from app.models import Device, RemoteSession

    device = register_device(client, auth_headers)
    with client.app.state.SessionLocal.begin() as db:
        stored = db.get(Device, device["device_id"])
        stored.status = "in_session"
        db.add(
            RemoteSession(
                id="interrupted",
                device_id=stored.id,
                owner_id=stored.owner_id,
                status="in_session",
            )
        )
    app = create_app(client.app.state.settings)
    with TestClient(app) as restarted:
        assert restarted.get("/api/auth/me", headers=auth_headers).status_code == 200
        assert (
            restarted.post(
                "/api/auth/bootstrap",
                json={
                    "username": "second_owner",
                    "password": PASSWORD,
                },
            ).status_code
            == 409
        )
        with app.state.SessionLocal() as db:
            old = db.get(RemoteSession, "interrupted")
            assert old.status == "ended" and old.end_reason == "server_restarted"
            assert old.ended_at is not None
            assert db.get(Device, device["device_id"]).status == "offline"
        with (
            restarted.websocket_connect(
                f"/device/ws?device_id={device['device_id']}",
                headers={"Authorization": "Bearer " + device["device_token"]},
            ) as android,
            restarted.websocket_connect(
                "/console/ws", subprotocols=["mydesk", "bearer." + owner_token]
            ) as console,
        ):
            android.receive_json()
            console.receive_json()
            console.send_json(
                {
                    "type": "session_start_request",
                    "deviceId": device["device_id"],
                    "devicePassword": "password-device",
                }
            )
            assert android.receive_json()["type"] == "session_start"
            assert console.receive_json()["type"] == "session_started"


def test_concurrent_failed_logins_preserve_lockout_count(client):
    user = register(client)
    barrier = Barrier(5)

    def wrong_password(_):
        barrier.wait(timeout=10)
        return client.post(
            "/api/auth/login",
            json={
                "username": "alice",
                "password": "wrong-password",
            },
        )

    with ThreadPoolExecutor(max_workers=5) as pool:
        assert all(r.status_code == 401 for r in pool.map(wrong_password, range(5)))
    with client.app.state.SessionLocal() as db:
        stored = db.get(User, user["id"])
        assert stored.failed_login_attempts == 5
        assert naive_utc(stored.locked_until) > utc_now()
    assert (
        "locked"
        in client.post(
            "/api/auth/login",
            json={
                "username": "alice",
                "password": PASSWORD,
            },
        ).json()["detail"]
    )
