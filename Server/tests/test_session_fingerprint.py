"""IP/UA fingerprinting is an audited refresh signal, not token binding."""

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select

from app.models import AuditLog, LoginSession
from app.session_management import SessionManager


def changes(client):
    with client.app.state.SessionLocal() as db:
        return db.scalars(
            select(AuditLog).where(AuditLog.event_type == "session_fingerprint_changed")
        ).all()


@pytest.mark.parametrize(
    "new_ip,new_agent",
    [
        ("192.0.2.20", "Browser/1"),
        ("192.0.2.10", "Browser/2"),
        ("192.0.2.20", "Browser/2"),
    ],
)
def test_changed_fingerprint_remains_usable_and_is_audited_once_at_refresh(
    client, owner_token, new_ip, new_agent
):
    with TestClient(
        client.app, client=("192.0.2.10", 1000), headers={"User-Agent": "Browser/1"}
    ) as initial:
        response = initial.post(
            "/api/auth/login",
            json={"username": "admin", "password": "Quercia!Viola7Sentiero"},
        )
        assert response.status_code == 200
        tokens = response.json()
    with TestClient(
        client.app, client=(new_ip, 2000), headers={"User-Agent": new_agent}
    ) as changed:
        assert (
            changed.get(
                "/api/auth/me",
                headers={"Authorization": "Bearer " + tokens["access_token"]},
            ).status_code
            == 200
        )
        with changed.websocket_connect(
            "/console/ws", subprotocols=["mydesk", "bearer." + tokens["access_token"]]
        ) as ws:
            assert ws.receive_json()["type"] == "console_registered"
            ws.send_json({"type": "heartbeat"})
            assert ws.receive_json()["type"] == "heartbeat_ack"
        assert not changes(client)  # Ordinary HTTP and WS requests do not compare it.
        for _ in range(2):
            response = changed.post(
                "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
            )
            assert response.status_code == 200
            tokens = response.json()
        audit = changes(client)
        assert len(audit) == 1
        assert audit[0].ip_address == new_ip
        assert audit[0].user_agent == new_agent
        with client.app.state.SessionLocal() as db:
            session = db.get(LoginSession, tokens["session_id"])
            assert session.revoked_at is None
            assert session.ip_address == new_ip
            assert session.user_agent == new_agent
            assert (
                session.device_fingerprint
                == SessionManager.generate_device_fingerprint(new_agent, new_ip)
            )


def test_forwarded_headers_cannot_override_fingerprint_at_the_application(
    client, owner_token
):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Quercia!Viola7Sentiero"},
    )
    tokens = response.json()
    with client.app.state.SessionLocal() as db:
        original = db.get(LoginSession, tokens["session_id"]).device_fingerprint
    response = client.post(
        "/api/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
        headers={"X-Forwarded-For": "192.0.2.99", "X-Real-IP": "192.0.2.99"},
    )
    assert response.status_code == 200
    assert not changes(client)
    with client.app.state.SessionLocal() as db:
        assert db.get(LoginSession, tokens["session_id"]).device_fingerprint == original
