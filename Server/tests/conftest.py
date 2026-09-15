from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("MYDESK_DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("MYDESK_CHECK_PASSWORD_BREACHES", "false")
os.environ.setdefault("MYDESK_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("MYDESK_SECRET_KEY", "test-secret-key-with-at-least-32-chars")
os.environ.setdefault(
    "MYDESK_MONITORING_TOKEN", "test-monitoring-key-with-at-least-32-chars"
)

from app.config import Settings
from app.auth_service import AuthService
from app.main import create_app
from app.models import User
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from app.database import create_db_engine
import uuid


@pytest.fixture
def database_url(tmp_path):
    postgres_url = os.environ.get("MYDESK_TEST_POSTGRES_URL")
    if not postgres_url:
        yield f"sqlite+pysqlite:///{tmp_path / 'mydesk-test.db'}"
        return
    # Isolate each integration test in a newly generated schema.
    schema = "test_" + uuid.uuid4().hex
    engine = create_db_engine(postgres_url)
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    url = make_url(postgres_url).update_query_dict(
        {"options": f"-csearch_path={schema} -ctimezone=UTC"}
    )
    try:
        yield url.render_as_string(hide_password=False)
    finally:
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()


@pytest.fixture
def client(database_url):
    settings = Settings(
        database_url=database_url,
        secret_key="test-secret-key-with-at-least-32-chars",
        pairing_code_ttl_minutes=10,
    )
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def owner_token(client: TestClient) -> str:
    response = client.post(
        "/api/auth/bootstrap",
        json={"username": "admin", "password": "Quercia!Viola7Sentiero"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture
def auth_headers(owner_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {owner_token}"}


def create_reset_token(client: TestClient, username: str) -> str:
    """Trusted test issuer; public HTTP endpoints must never expose this secret."""
    with client.app.state.SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))
        token = AuthService(db, client.app.state.settings).create_password_reset_token(
            user.id
        )
        db.commit()
        return token


def register_device(
    client: TestClient, auth_headers: dict[str, str], *, name: str = "Pixel test"
):
    pairing_response = client.post("/api/pairing-codes", headers=auth_headers)
    assert pairing_response.status_code == 200
    code = pairing_response.json()["code"]

    device_response = client.post(
        "/api/devices/pair",
        json={
            "pairing_code": code,
            "name": name,
            "device_password": "password-device",
        },
    )
    assert device_response.status_code == 200
    return device_response.json()


@pytest.fixture
def monitoring_headers(client):
    return {"Authorization": "Bearer " + client.app.state.settings.monitoring_token}
