"""Behavioral checks for HIGH-002 through HIGH-007 reported in September 2026."""

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import jwt
import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session
from starlette.websockets import WebSocketDisconnect

from app.models import AuditLog, LoginSession, PairingCode, PasswordResetToken, User
from app.security import hash_secret, verify_password
from tests.conftest import create_reset_token, register_device, request_session


def test_websocket_text_is_relayed_literally_and_invalid_payloads_are_rejected(
    client, owner_token, auth_headers
):
    device = register_device(client, auth_headers)
    with (
        client.websocket_connect(
            "/device/ws?device_id=" + device["device_id"],
            headers={"Authorization": "Bearer " + device["device_token"]},
        ) as peer,
        client.websocket_connect(
            "/console/ws", subprotocols=["mydesk", "bearer." + owner_token]
        ) as console,
    ):
        peer.receive_json()
        console.receive_json()
        request_session(console, device["device_id"])
        session_id = console.receive_json()["sessionId"]
        peer.receive_json()
        message = {"type": "input_text", "sessionId": session_id}
        for value in (
            '<script>alert("example")</script>',
            "O'Reilly; DROP TABLE users; --",
            "Città 🌍\n日本語 <test> & parole",
        ):
            payload = message | {"text": value}
            console.send_json(payload)
            assert peer.receive_json() == payload

        for extra in (
            {"text": "a" * 10001},
            {"text": {"unexpected": "object"}},
            {"text": "valid", "unexpected": "field"},
        ):
            console.send_json(message | extra)
            assert console.receive_json()["code"] == "INVALID_MESSAGE"
        # No rejected payload may have reached the Android connection.
        payload = message | {"text": "still connected"}
        console.send_json(payload)
        assert peer.receive_json() == payload
    assert client.get("/api/auth/me", headers=auth_headers).status_code == 200


def test_access_token_expiry_is_enforced_even_when_login_session_is_live(
    client, owner_token, auth_headers
):
    settings = client.app.state.settings
    claims = jwt.decode(owner_token, settings.secret_key, algorithms=["HS256"])
    assert claims["exp"] - claims["iat"] == 60 * 60  # Default is one hour, not 24.
    assert client.get("/api/auth/me", headers=auth_headers).status_code == 200
    claims["exp"] = claims["iat"] - 1
    claims["iat"] -= 60
    expired = jwt.encode(claims, settings.secret_key, algorithm="HS256")
    assert client.get(
        "/api/auth/me", headers={"Authorization": "Bearer " + expired}
    ).status_code == 401
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect(
            "/console/ws", subprotocols=["mydesk", "bearer." + expired]
        ):
            pytest.fail("Expired access token accepted")
    assert error.value.code == 4401
    assert client.get("/api/auth/me", headers=auth_headers).status_code == 200


def test_cookies_do_not_authorize_state_changes_and_foreign_preflight_is_denied(
    client, owner_token, auth_headers
):
    response = client.post(
        "/api/pairing-codes",
        headers={
            "Origin": "https://attacker.example",
            "Cookie": f"access_token={owner_token}; session={owner_token}",
        },
    )
    assert response.status_code == 401
    with client.app.state.SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(PairingCode)) == 0
    response = client.options(
        "/api/pairing-codes",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers
    assert client.post("/api/pairing-codes", headers=auth_headers).status_code == 200


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded"])
def test_browser_form_content_types_cannot_submit_json_login(
    client, owner_token, content_type
):
    response = client.post(
        "/api/auth/login",
        headers={"Origin": "https://attacker.example", "Content-Type": content_type},
        content=json.dumps({"username": "admin", "password": "Quercia!Viola7Sentiero"}),
    )
    assert response.status_code == 422
    with client.app.state.SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(LoginSession)) == 1


def test_database_error_responses_and_logs_do_not_contain_sql_or_parameters(
    client, caplog
):
    secret = "private-database-parameter"
    statement = "UPDATE users SET password_hash=:password_hash"

    @client.app.get("/test/reported-error")
    def fail():
        raise StatementError(
            "Query failed", statement, {"password_hash": secret}, RuntimeError(secret)
        )

    response = client.get("/test/reported-error")
    assert response.status_code == 500
    assert response.json()["error_code"] == "DATABASE_ERROR"
    for value in (secret, statement, "Query failed"):
        assert value not in response.text
        assert value not in caplog.text


def test_only_one_concurrent_password_reset_can_consume_a_token(
    client, owner_token, monkeypatch
):
    token = create_reset_token(client, "admin")
    token_hash = hash_secret(token)
    barrier = Barrier(2, timeout=10)
    original = Session.scalar

    def synchronized_lookup(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        if isinstance(result, PasswordResetToken) and result.token_hash == token_hash:
            barrier.wait()
        return result

    monkeypatch.setattr(Session, "scalar", synchronized_lookup)
    passwords = ["Canyon!Maple9River", "Silver!Orchid9Garden"]

    def reset(password):
        return client.post(
            "/api/auth/password-reset", json={"token": token, "new_password": password}
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(reset, passwords))
    monkeypatch.setattr(Session, "scalar", original)
    assert sorted(r.status_code for r in responses) == [200, 400]
    assert reset("Copper!Meadow8Falcon-new").status_code == 400
    with client.app.state.SessionLocal() as db:
        stored = db.scalar(select(PasswordResetToken))
        assert stored.used_at is not None
        user = db.get(User, stored.user_id)
        for password, response in zip(passwords, responses):
            assert verify_password(password, user.password_hash) == (response.status_code == 200)
        assert db.scalar(
            select(func.count()).select_from(AuditLog).where(
                AuditLog.event_type == "password_reset"
            )
        ) == 1
