"""Login denials must not disclose account existence, activity or lockout."""

from datetime import timedelta
from unittest.mock import Mock

import pytest
from sqlalchemy import select

from app import security
from app.models import User
from app.timeutils import utc_now


@pytest.mark.parametrize(
    "state,correct_password",
    [
        ("missing", False),
        ("active", False),
        ("locked", False),
        ("locked", True),
        ("inactive", False),
        ("inactive", True),
    ],
)
def test_login_denials_have_the_same_response_and_always_verify_a_hash(
    client, owner_token, monkeypatch, state, correct_password
):
    with client.app.state.SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        if state == "locked":
            user.locked_until = utc_now() + timedelta(minutes=15)
        if state == "inactive":
            user.is_active = False
        db.commit()

    hasher = Mock(wraps=security._password_hasher)
    monkeypatch.setattr(security, "_password_hasher", hasher)
    response = client.post(
        "/api/auth/login",
        headers={"X-Request-ID": "enumeration-regression"},
        json={
            "username": "missing_owner" if state == "missing" else "admin",
            "password": "Quercia!Viola7Sentiero" if correct_password else "wrong-password",
        },
    )
    assert response.status_code == 401
    assert response.json() == {
        "detail": "Invalid credentials",
        "error_code": "HTTP_401",
        "request_id": "enumeration-regression",
    }
    # Check the expensive operation instead of asserting noisy wall-clock timings.
    assert hasher.verify.call_count == 1
    assert hasher.verify.call_args.args[0].startswith("$argon2id$")
