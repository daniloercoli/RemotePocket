from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
import os
import time

import pytest
import jwt
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.websockets import WebSocketDisconnect

from app.models import AuditLog, LoginAttempt, PasswordResetToken, RefreshToken, User
from app.security import (
    create_access_token,
    hash_secret,
    verify_access_token,
)
from app.config import Settings
from app.timeutils import utc_now, naive_utc
from tests.conftest import create_reset_token


@pytest.fixture
def account(client):
    response = client.post(
        "/api/auth/register",
        json={
            "username": "review_user",
            "password": "Review!Meadow8Lantern",
            "email": "review@example.com",
        },
    )
    assert response.status_code == 200
    return response.json()["user"]


def login(client, password="Review!Meadow8Lantern"):
    return client.post(
        "/api/auth/login", json={"username": "review_user", "password": password}
    )


def test_recovery_disabled_without_issuing_tokens(client, account):
    for email in ("review@example.com", "unknown@example.com"):
        response = client.post(
            "/api/auth/password-reset-request", json={"email": email}
        )
        assert response.status_code == 503
        assert "reset_token" not in response.json()
    with client.app.state.SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(PasswordResetToken)) == 0


def test_http_failures_lock_account_and_preserve_audit(client, account):
    for _ in range(5):
        assert login(client, "wrong-password").status_code == 401
    assert "locked" in login(client).json()["detail"]
    with client.app.state.SessionLocal() as db:
        user = db.get(User, account["id"])
        assert user.failed_login_attempts == 5
        assert naive_utc(user.locked_until) > utc_now()
        attempts = db.scalars(select(LoginAttempt)).all()
        assert len(attempts) == 6
        assert all(not a.success and a.user_id == user.id for a in attempts)
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(AuditLog.event_type == "login_failed")
            )
            == 5
        )


def test_correct_password_after_four_failures_succeeds(client, account):
    for _ in range(4):
        assert login(client, "wrong-password").status_code == 401
    assert login(client).status_code == 200
    with client.app.state.SessionLocal() as db:
        user = db.get(User, account["id"])
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
        assert (
            db.scalar(
                select(func.count())
                .select_from(LoginAttempt)
                .where(LoginAttempt.success.is_(True))
            )
            == 1
        )


def test_expired_lockout_allows_login(client, account):
    with client.app.state.SessionLocal() as db:
        user = db.get(User, account["id"])
        user.failed_login_attempts = 5
        user.locked_until = utc_now() - timedelta(seconds=1)
        db.commit()
    assert login(client).status_code == 200


@pytest.mark.parametrize("kind", ["login", "refresh"])
def test_http_and_websocket_accept_same_credentials(client, account, kind):
    tokens = login(client).json()
    if kind == "refresh":
        response = client.post(
            "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert response.status_code == 200
        tokens = response.json()
    token = tokens["access_token"]
    assert (
        client.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
        ).status_code
        == 200
    )
    with client.websocket_connect(
        "/console/ws", subprotocols=["mydesk", f"bearer.{token}"]
    ) as ws:
        assert ws.receive_json()["type"] == "console_registered"


def test_disabled_user_loses_http_and_ws_access(client, account):
    tokens = login(client).json()
    token = tokens["access_token"]
    with client.websocket_connect(
        "/console/ws", subprotocols=["mydesk", f"bearer.{token}"]
    ) as ws:
        assert ws.receive_json()["type"] == "console_registered"
        with client.app.state.SessionLocal() as db:
            db.get(User, account["id"]).is_active = False
            db.commit()
        assert (
            client.post(
                "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
            ).status_code
            == 401
        )
        assert (
            client.get(
                "/api/devices", headers={"Authorization": f"Bearer {token}"}
            ).status_code
            == 401
        )
        ws.send_json({"type": "device_list_request"})
        with pytest.raises(WebSocketDisconnect) as error:
            ws.receive_json()
        assert error.value.code == 4401
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            "/console/ws", subprotocols=["mydesk", f"bearer.{token}"]
        ):
            pytest.fail("Inactive user was accepted")


def test_password_reset_revokes_all_prior_credentials(client, account, monkeypatch):
    import app.routes.websocket as websocket_routes

    monkeypatch.setattr(websocket_routes, "AUTH_RECHECK_SECONDS", 0.05)
    tokens = [login(client).json(), login(client).json()]
    reset_token = create_reset_token(client, "review_user")
    with client.websocket_connect(
        "/console/ws", subprotocols=["mydesk", f"bearer.{tokens[0]['access_token']}"]
    ) as ws:
        assert ws.receive_json()["type"] == "console_registered"
        response = client.post(
            "/api/auth/password-reset",
            json={
                "token": reset_token,
                "new_password": "Canyon!Maple9River",
            },
        )
        assert response.status_code == 200
        # An idle connection must also be closed after credential invalidation.
        with pytest.raises(WebSocketDisconnect) as error:
            ws.receive_json()
        assert error.value.code == 4401
    for old in tokens:
        assert (
            client.post(
                "/api/auth/refresh", json={"refresh_token": old["refresh_token"]}
            ).status_code
            == 401
        )
    for access in (t["access_token"] for t in tokens):
        assert (
            client.get(
                "/api/auth/me", headers={"Authorization": f"Bearer {access}"}
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/api/auth/password-reset",
            json={
                "token": reset_token,
                "new_password": "Silver!Orchid9Garden",
            },
        ).status_code
        == 400
    )
    assert login(client).status_code == 401
    new = login(client, "Canyon!Maple9River")
    assert new.status_code == 200
    assert (
        client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {new.json()['access_token']}"},
        ).status_code
        == 200
    )


def test_reset_rejects_passwords_that_login_cannot_accept(client, account):
    token = create_reset_token(client, "review_user")
    assert (
        client.post(
            "/api/auth/password-reset", json={"token": token, "new_password": "a" * 201}
        ).status_code
        == 422
    )
    assert login(client).status_code == 200


def test_refresh_rotation_is_atomic(client, account, monkeypatch):
    token = login(client).json()["refresh_token"]
    barrier = Barrier(2, timeout=10)
    original = Session.scalar
    token_hash = hash_secret(token)

    def synchronized_lookup(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        if isinstance(result, RefreshToken) and result.token_hash == token_hash:
            barrier.wait()
        return result

    monkeypatch.setattr(Session, "scalar", synchronized_lookup)

    def refresh(_):
        return client.post("/api/auth/refresh", json={"refresh_token": token})

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(refresh, range(2)))
    assert sorted(r.status_code for r in responses) == [200, 401]
    monkeypatch.setattr(Session, "scalar", original)
    winner = next(r.json() for r in responses if r.status_code == 200)
    assert (
        client.post(
            "/api/auth/refresh", json={"refresh_token": winner["refresh_token"]}
        ).status_code
        == 401
    )
    assert (
        client.post("/api/auth/refresh", json={"refresh_token": token}).status_code
        == 401
    )


@pytest.mark.skipif(
    not hasattr(time, "tzset"), reason="POSIX timezone control unavailable"
)
@pytest.mark.parametrize("timezone", ["UTC", "Europe/Rome", "America/New_York"])
def test_jwt_expiry_is_independent_of_timezone(timezone):
    previous = os.environ.get("TZ")
    try:
        os.environ["TZ"] = timezone
        time.tzset()
        settings = Settings(
            secret_key="test-secret-key-with-at-least-32-chars",
            access_token_ttl_minutes=15,
        )
        token = create_access_token("review_user", settings, "login_test")
        remaining = (
            jwt.decode(token, options={"verify_signature": False})["exp"]
            - datetime.now(UTC).timestamp()
        )
        assert verify_access_token(token, settings) is not None
        assert 895 < remaining <= 900
    finally:
        if previous is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous
        time.tzset()
