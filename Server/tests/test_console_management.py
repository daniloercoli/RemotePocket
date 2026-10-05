"""Account management exposed by the web console keeps ownership and revocation guarantees."""

import pytest
from sqlalchemy import select

from app.auth_service import AuthService
from app.models import User
from tests.conftest import create_reset_token

PASSWORD = "Quercia!Viola7Sentiero"
NEW_PASSWORD = "Orizzonte!Fiume9Cartolina"


def login(client, username="admin", password=PASSWORD):
    response = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200
    return {"Authorization": "Bearer " + response.json()["access_token"]}


@pytest.mark.parametrize(
    "path",
    [
        "/login",
        "/register",
        "/setup",
        "/forgot-password",
        "/reset-password",
        "/verify-email",
        "/two-factor",
        "/recovery-codes",
        "/app",
        "/app/devices",
        "/app/sessions",
        "/app/activity",
        "/app/account",
        "/app/help",
    ],
)
def test_console_deep_links_work_without_exposing_account_data(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert 'src="/static/application.js"' in response.text
    assert 'id="appShell" class="app-shell" hidden' in response.text
    assert "no-store" in response.headers["cache-control"]
    assert "unsafe-inline" not in response.headers["content-security-policy"]


def test_unknown_routes_and_api_routes_are_not_caught_by_console(client):
    assert client.get("/app/not-a-page").status_code == 404
    assert client.get("/api/not-an-endpoint").status_code == 404
    assert client.get("/api/auth/sessions").status_code == 401
    assert (
        client.post(
            "/api/auth/password-change",
            json={"password": PASSWORD, "new_password": NEW_PASSWORD},
        ).status_code
        == 401
    )
    assert client.get("/static/favicon.svg").status_code == 200


def test_password_change_revokes_all_sessions_refresh_tokens_and_old_reset_links(
    client, auth_headers
):
    second = login(client)
    reset = create_reset_token(client, "admin")
    response = client.post(
        "/api/auth/password-change",
        headers=auth_headers,
        json={"password": PASSWORD, "new_password": NEW_PASSWORD},
    )
    assert response.status_code == 200
    for headers in (auth_headers, second):
        assert client.get("/api/auth/me", headers=headers).status_code == 401
    assert (
        client.post(
            "/api/auth/password-reset",
            json={"token": reset, "new_password": "Faro!Mare9Costellazione"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        ).status_code
        == 401
    )
    assert (
        client.get(
            "/api/auth/me", headers=login(client, password=NEW_PASSWORD)
        ).status_code
        == 200
    )


@pytest.mark.parametrize(
    "old,new,status",
    [
        ("wrong-password", NEW_PASSWORD, 401),
        (PASSWORD, "weak", 422),
        (PASSWORD, PASSWORD, 400),
    ],
)
def test_password_change_rejects_wrong_current_password_and_reuse(
    client, auth_headers, old, new, status
):
    response = client.post(
        "/api/auth/password-change",
        headers=auth_headers,
        json={"password": old, "new_password": new},
    )
    assert response.status_code == status
    assert client.get("/api/auth/me", headers=auth_headers).status_code == 200
    assert client.get("/api/auth/me", headers=login(client)).status_code == 200


def test_login_sessions_are_owner_scoped_and_revoke_only_selected_login(
    client, auth_headers
):
    second = login(client)
    with client.app.state.SessionLocal() as db:
        AuthService(db, client.app.state.settings).register("another_owner", PASSWORD)
        db.commit()
    foreign = login(client, username="another_owner")
    sessions = client.get("/api/auth/sessions", headers=auth_headers).json()["sessions"]
    assert len(sessions) == 2
    assert sum(item["current"] for item in sessions) == 1
    assert not any(
        "token" in key or "fingerprint" in key for item in sessions for key in item
    )
    other = next(item for item in sessions if not item["current"])
    assert (
        client.post(
            f"/api/auth/sessions/{other['id']}/revoke", headers=foreign
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/auth/sessions/{other['id']}/revoke", headers=auth_headers
        ).status_code
        == 200
    )
    assert client.get("/api/auth/me", headers=second).status_code == 401
    assert client.get("/api/auth/me", headers=auth_headers).status_code == 200
    assert (
        len(client.get("/api/auth/sessions", headers=foreign).json()["sessions"]) == 1
    )


def test_password_change_requires_second_factor_when_enabled(client, auth_headers):
    from cryptography.fernet import Fernet
    from app.account_service import encrypt
    import pyotp

    client.app.state.settings.encryption_key = Fernet.generate_key().decode()
    secret = pyotp.random_base32()
    with client.app.state.SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        user.totp_secret = encrypt(client.app.state.settings, secret)
        db.commit()
    body = {"password": PASSWORD, "new_password": NEW_PASSWORD}
    assert (
        client.post(
            "/api/auth/password-change", headers=auth_headers, json=body
        ).status_code
        == 401
    )
    body["code"] = pyotp.TOTP(secret).now()
    assert (
        client.post(
            "/api/auth/password-change", headers=auth_headers, json=body
        ).status_code
        == 200
    )
    assert client.get("/api/auth/me", headers=auth_headers).status_code == 401
