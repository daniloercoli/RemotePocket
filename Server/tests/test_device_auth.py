"""Password-free session starts, RFC proof vector and replay defenses."""

import base64
from contextlib import ExitStack
import hashlib
import hmac
import logging
import secrets
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from app import device_auth
from app.models import Device, User
from tests.conftest import device_proof, register_device


def challenge(ws, device_id):
    ws.send_json(
        {
            "type": "session_challenge_request",
            "deviceId": device_id,
            "clientNonce": secrets.token_hex(32),
        }
    )
    response = ws.receive_json()
    assert response["type"] == "session_challenge"
    return response


@pytest.fixture
def connected(client, auth_headers, owner_token):
    paired = register_device(client, auth_headers)
    with ExitStack() as stack:
        peer = stack.enter_context(
            client.websocket_connect(
                "/device/ws?device_id=" + paired["device_id"],
                headers={"Authorization": "Bearer " + paired["device_token"]},
            )
        )
        ws = stack.enter_context(
            client.websocket_connect(
                "/console/ws",
                subprotocols=["mydesk", "bearer." + owner_token],
            )
        )
        peer.receive_json()
        ws.receive_json()
        yield peer, ws, paired


def test_rfc7677_proof_vector(monkeypatch):
    # https://www.rfc-editor.org/rfc/rfc7677#section-3
    salt = "W22ZaJ0SNY7soEsUEjb6gQ=="
    client_nonce = "rOprNGfwEbeRWgbNEkqO"
    nonce = client_nonce + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
    monkeypatch.setattr(device_auth, "ITERATIONS", 4096)
    monkeypatch.setattr(
        device_auth.secrets, "token_bytes", lambda size: base64.b64decode(salt)
    )
    stored = device_auth.credentials("pencil")
    transcript = device_auth.auth_message("user", client_nonce, nonce, salt, 4096)
    assert (
        device_auth.verify_proof(
            stored["access_auth_stored_key"],
            stored["access_auth_server_key"],
            transcript,
            "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
        )
        == "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
    )


def test_success_verifies_server_and_does_not_log_password_or_proof(
    connected, client, auth_headers, caplog
):
    peer, ws, paired = connected
    with caplog.at_level(logging.DEBUG):
        issued = challenge(ws, paired["device_id"])
        proof = device_proof(issued)
        ws.send_json(proof)
        started = ws.receive_json()
        assert started["type"] == "session_started"
        assert peer.receive_json()["sessionId"] == started["sessionId"]
    salted = hashlib.pbkdf2_hmac(
        "sha256",
        b"password-device",
        base64.b64decode(issued["salt"]),
        issued["iterations"],
    )
    transcript = device_auth.auth_message(
        paired["device_id"],
        issued["clientNonce"],
        issued["nonce"],
        issued["salt"],
        issued["iterations"],
    )
    expected = hmac.digest(
        hmac.digest(salted, b"Server Key", "sha256"), transcript, "sha256"
    )
    assert started["serverProof"] == base64.b64encode(expected).decode()
    assert "password-device" not in caplog.text
    assert proof["proof"] not in caplog.text
    with client.app.state.SessionLocal() as db:
        device = db.get(Device, paired["device_id"])
        assert device.access_auth_stored_key not in caplog.text
        assert device.access_auth_server_key not in caplog.text
    public = client.get("/api/devices", headers=auth_headers)
    assert public.status_code == 200
    assert "access_auth" not in public.text


def test_used_proof_cannot_reopen_session(connected, client):
    peer, ws, paired = connected
    proof = device_proof(challenge(ws, paired["device_id"]))
    ws.send_json(proof)
    session = ws.receive_json()["sessionId"]
    peer.receive_json()
    ws.send_json({"type": "session_end", "sessionId": session})
    ws.receive_json()
    peer.receive_json()
    ws.send_json(proof)
    assert ws.receive_json()["code"] == "AUTH_FAILED"
    assert not client.app.state.ws_manager.session_routes


def test_failed_proof_is_consumed_and_fresh_challenge_can_succeed(connected):
    peer, ws, paired = connected
    issued = challenge(ws, paired["device_id"])
    ws.send_json(device_proof(issued, "incorrect-password"))
    assert ws.receive_json()["code"] == "AUTH_FAILED"
    ws.send_json(device_proof(issued))
    assert ws.receive_json()["code"] == "AUTH_FAILED"
    ws.send_json(device_proof(challenge(ws, paired["device_id"])))
    assert ws.receive_json()["type"] == "session_started"
    peer.receive_json()


def test_challenge_is_bound_to_console_connection(connected, client, owner_token):
    peer, ws, paired = connected
    proof = device_proof(challenge(ws, paired["device_id"]))
    with client.websocket_connect(
        "/console/ws", subprotocols=["mydesk", "bearer." + owner_token]
    ) as other:
        other.receive_json()
        other.send_json(proof)
        assert other.receive_json()["code"] == "AUTH_FAILED"
        ws.send_json(proof)
        assert ws.receive_json()["type"] == "session_started"
        peer.receive_json()


def test_expired_and_replaced_challenges_are_rejected(connected, monkeypatch):
    _, ws, paired = connected
    now = [100.0]
    monkeypatch.setattr(device_auth, "time", SimpleNamespace(monotonic=lambda: now[0]))
    first = challenge(ws, paired["device_id"])
    now[0] += device_auth.CHALLENGE_TTL_SECONDS
    ws.send_json(device_proof(first))
    assert ws.receive_json()["code"] == "AUTH_FAILED"
    old = challenge(ws, paired["device_id"])
    new = challenge(ws, paired["device_id"])
    assert old["nonce"] != new["nonce"]
    ws.send_json(device_proof(old))
    assert ws.receive_json()["code"] == "AUTH_FAILED"
    ws.send_json(device_proof(new))
    assert ws.receive_json()["code"] == "AUTH_FAILED"


def test_challenge_rechecks_device_revocation(connected, client, auth_headers):
    peer, ws, paired = connected
    issued = challenge(ws, paired["device_id"])
    assert (
        client.post(
            f"/api/devices/{paired['device_id']}/revoke", headers=auth_headers
        ).status_code
        == 200
    )
    ws.send_json(device_proof(issued))
    assert ws.receive_json()["code"] == "DEVICE_NOT_FOUND"
    assert not client.app.state.ws_manager.session_routes


def test_password_payload_is_rejected(connected):
    _, ws, paired = connected
    ws.send_json(
        {
            "type": "session_start_request",
            "deviceId": paired["device_id"],
            "devicePassword": "password-device",
        }
    )
    assert ws.receive_json()["code"] == "INVALID_MESSAGE"


def test_challenge_does_not_reveal_another_owners_verifier(connected, client):
    _, _, paired = connected
    credentials = {
        "username": "other_challenge_owner",
        "password": "Meadow!Harbor7Lantern",
    }
    assert client.post("/api/auth/register", json=credentials).status_code == 200
    token = client.post("/api/auth/login", json=credentials).json()["access_token"]
    with client.websocket_connect(
        "/console/ws", subprotocols=["mydesk", "bearer." + token]
    ) as other:
        other.receive_json()
        other.send_json(
            {
                "type": "session_challenge_request",
                "deviceId": paired["device_id"],
                "clientNonce": secrets.token_hex(32),
            }
        )
        result = other.receive_json()
        assert result["code"] == "DEVICE_NOT_FOUND"
        assert "salt" not in result


def test_challenge_storage_is_bounded_and_expired_slots_are_reusable(monkeypatch):
    now = [10.0]
    monkeypatch.setattr(device_auth, "time", SimpleNamespace(monotonic=lambda: now[0]))
    pending = device_auth.DeviceChallenges(limit=1)
    device = SimpleNamespace(
        id="one", access_auth_salt="salt", access_auth_iterations=600000
    )
    first = pending.issue(device, "a" * 64)
    device.id = "two"
    assert pending.issue(device, "b" * 64) is None
    assert len(pending.pending) == 1
    now[0] += 60
    assert pending.issue(device, "b" * 64) is not None
    assert pending.consume("one", first.id) is None


def test_same_password_uses_distinct_salts_and_verifiers():
    first, second = [device_auth.credentials("device-password") for _ in range(2)]
    assert first["access_auth_salt"] != second["access_auth_salt"]
    assert first["access_auth_stored_key"] != second["access_auth_stored_key"]


def test_proof_cannot_be_retargeted_to_another_device(connected, client, auth_headers):
    _, ws, paired = connected
    other = register_device(client, auth_headers)
    with client.websocket_connect(
        "/device/ws?device_id=" + other["device_id"],
        headers={"Authorization": "Bearer " + other["device_token"]},
    ) as second:
        second.receive_json()
        original = device_proof(challenge(ws, paired["device_id"]))
        target = challenge(ws, other["device_id"])
        ws.send_json(
            original
            | {"deviceId": other["device_id"], "challengeId": target["challengeId"]}
        )
        assert ws.receive_json()["code"] == "AUTH_FAILED"
        assert not client.app.state.ws_manager.session_routes


def test_account_revocation_between_challenge_and_proof_is_enforced(connected, client):
    _, ws, paired = connected
    issued = challenge(ws, paired["device_id"])
    with client.app.state.SessionLocal.begin() as db:
        db.scalar(select(User)).is_active = False
    ws.send_json(device_proof(issued))
    with pytest.raises(WebSocketDisconnect) as error:
        ws.receive_json()
    assert error.value.code == 4401
    assert not client.app.state.ws_manager.session_routes


def test_challenge_requests_have_an_owner_rate_limit(connected, client):
    _, ws, paired = connected
    client.app.state.settings.rate_limit_enabled = True
    for _ in range(5):
        challenge(ws, paired["device_id"])
    ws.send_json(
        {
            "type": "session_challenge_request",
            "deviceId": paired["device_id"],
            "clientNonce": secrets.token_hex(32),
        }
    )
    assert ws.receive_json()["code"] == "RATE_LIMITED"


def test_unicode_password_keeps_literal_utf8_encoding(monkeypatch):
    password = "caffè☕🔒device"
    stored = device_auth.credentials(password)
    issued = {
        "deviceId": "dev_unicode",
        "clientNonce": "a" * 64,
        "nonce": "a" * 64 + "b" * 64,
        "challengeId": "unused",
        "salt": stored["access_auth_salt"],
        "iterations": stored["access_auth_iterations"],
    }
    proof = device_proof(issued, password)
    transcript = device_auth.auth_message(
        issued["deviceId"],
        issued["clientNonce"],
        issued["nonce"],
        issued["salt"],
        issued["iterations"],
    )
    assert device_auth.verify_proof(
        stored["access_auth_stored_key"],
        stored["access_auth_server_key"],
        transcript,
        proof["proof"],
    )
