"""Per-connection burst limits complement the shared owner/device budget."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from starlette.websockets import WebSocketDisconnect

from app.config import Settings
from app.models import Device, RemoteSession
from app.websocket_limits import WebSocketRateLimiter
from tests.conftest import register_device, request_session


@pytest.fixture
def local_clock(monkeypatch):
    now = [10.0]
    # Do not freeze the event loop or shared rate limiter's clocks.
    monkeypatch.setattr(
        "app.websocket_limits.time", SimpleNamespace(monotonic=lambda: now[0])
    )
    return now


def console(client, token):
    return client.websocket_connect(
        "/console/ws", subprotocols=["mydesk", "bearer." + token]
    )


def device_socket(client, device):
    return client.websocket_connect(
        "/device/ws?device_id=" + device["device_id"],
        headers={"Authorization": "Bearer " + device["device_token"]},
    )


def assert_control_limited(ws):
    with pytest.raises(WebSocketDisconnect) as error:
        ws.receive_json()
    assert error.value.code == 4429
    assert error.value.reason == "control_rate_limit"


def test_control_window_is_rolling_and_memory_stays_bounded(local_clock):
    limiter = WebSocketRateLimiter(2)
    assert limiter.accept()
    local_clock[0] = 10.5
    assert limiter.accept()
    local_clock[0] = 10.999
    for _ in range(1000):
        assert not limiter.accept()
    assert len(limiter.messages) == 2
    local_clock[0] = 11.0
    assert limiter.accept()  # Only the first message has expired.
    assert not limiter.accept()
    local_clock[0] = 11.5
    assert limiter.accept()
    assert not limiter.accept()
    local_clock[0] = 20.0
    assert limiter.accept()
    assert limiter.accept()
    assert not limiter.accept()


@pytest.mark.parametrize("value", [0, 301])
def test_control_limit_configuration_is_bounded(value):
    with pytest.raises(ValidationError):
        Settings(rate_limit_ws_control_per_second=value)


@pytest.mark.parametrize("endpoint", ["console", "device"])
@pytest.mark.parametrize("shared_enabled", [False, True])
def test_bursts_count_malformed_messages_before_shared_storage_and_parsing(
    client, owner_token, auth_headers, monkeypatch, local_clock, endpoint, shared_enabled
):
    from app.routes import websocket as routes

    device = register_device(client, auth_headers)
    settings = client.app.state.settings
    settings.rate_limit_ws_control_per_second = 2
    settings.rate_limit_enabled = shared_enabled
    connection = (
        console(client, owner_token)
        if endpoint == "console"
        else device_socket(client, device)
    )
    with connection as ws:
        ws.receive_json()
        hit = Mock(wraps=client.app.state.rate_limiter.hit)
        parse = Mock(wraps=routes.parse_control)
        auth = Mock(wraps=routes.authenticate_user)
        monkeypatch.setattr(client.app.state.rate_limiter, "hit", hit)
        monkeypatch.setattr(routes, "parse_control", parse)
        monkeypatch.setattr(routes, "authenticate_user", auth)
        ws.send_text("invalid json")
        assert ws.receive_json()["code"] == "INVALID_MESSAGE"
        ws.send_json({"type": "heartbeat"})
        assert ws.receive_json()["type"] == "heartbeat_ack"
        ws.send_text("invalid json")
        assert_control_limited(ws)
        assert hit.call_count == (2 if shared_enabled else 0)
        assert parse.call_count == 2
        assert auth.call_count == (2 if endpoint == "console" else 0)


def test_console_connections_have_independent_windows(client, owner_token, local_clock):
    client.app.state.settings.rate_limit_ws_control_per_second = 1
    with console(client, owner_token) as first, console(client, owner_token) as second:
        first.receive_json()
        second.receive_json()
        first.send_json({"type": "heartbeat"})
        assert first.receive_json()["type"] == "heartbeat_ack"
        first.send_json({"type": "heartbeat"})
        assert_control_limited(first)
        second.send_json({"type": "heartbeat"})
        assert second.receive_json()["type"] == "heartbeat_ack"
        local_clock[0] += 1
        second.send_json({"type": "heartbeat"})
        assert second.receive_json()["type"] == "heartbeat_ack"


@pytest.mark.parametrize("endpoint", ["console", "device"])
def test_reconnecting_resets_local_window_but_preserves_shared_budget(
    client, owner_token, auth_headers, local_clock, endpoint
):
    device = register_device(client, auth_headers)
    settings = client.app.state.settings
    settings.rate_limit_ws_control_per_second = 2
    settings.rate_limit_ws_control = 3
    settings.rate_limit_enabled = True

    def connect():
        return (
            console(client, owner_token)
            if endpoint == "console"
            else device_socket(client, device)
        )

    with connect() as first:
        first.receive_json()
        for _ in range(2):
            first.send_json({"type": "heartbeat"})
            assert first.receive_json()["type"] == "heartbeat_ack"
        first.send_json({"type": "heartbeat"})
        assert_control_limited(first)
    with connect() as replacement:
        replacement.receive_json()
        replacement.send_json({"type": "heartbeat"})
        assert replacement.receive_json()["type"] == "heartbeat_ack"
        replacement.send_json({"type": "heartbeat"})
        with pytest.raises(WebSocketDisconnect) as error:
            replacement.receive_json()
        assert error.value.code == 4429
        assert error.value.reason != "control_rate_limit"  # Shared limit, not local.


def test_console_binary_messages_cannot_bypass_control_budget(
    client, owner_token, local_clock
):
    client.app.state.settings.rate_limit_ws_control_per_second = 1
    with console(client, owner_token) as ws:
        ws.receive_json()
        ws.send_bytes(b"unexpected binary")
        assert ws.receive_json()["code"] == "INVALID_MESSAGE"
        ws.send_bytes(b"unexpected binary")
        assert_control_limited(ws)


def test_device_frames_use_their_own_budget(client, auth_headers, local_clock):
    device = register_device(client, auth_headers)
    client.app.state.settings.rate_limit_ws_control_per_second = 1
    with device_socket(client, device) as peer:
        peer.receive_json()
        peer.send_json({"type": "heartbeat"})
        assert peer.receive_json()["type"] == "heartbeat_ack"
        for _ in range(2):
            peer.send_bytes(b"invalid frame")
            assert peer.receive_json()["code"] == "INVALID_SCREEN_FRAME"
        peer.send_json({"type": "heartbeat"})
        assert_control_limited(peer)


@pytest.mark.parametrize("endpoint", ["console", "device"])
def test_control_limit_disconnect_cleans_up_sessions_and_notifies_peer(
    client, owner_token, auth_headers, local_clock, endpoint
):
    device = register_device(client, auth_headers)
    client.app.state.settings.rate_limit_ws_control_per_second = 2
    with device_socket(client, device) as peer, console(client, owner_token) as ws:
        peer.receive_json()
        ws.receive_json()
        request_session(ws, device["device_id"])
        session_id = ws.receive_json()["sessionId"]
        assert peer.receive_json()["type"] == "session_start"
        offender, observer = (ws, peer) if endpoint == "console" else (peer, ws)
        if endpoint == "device":
            for _ in range(2):
                peer.send_json({"type": "heartbeat"})
                assert peer.receive_json()["type"] == "heartbeat_ack"
        offender.send_json({"type": "heartbeat"})
        assert_control_limited(offender)
        ended = observer.receive_json()
        assert ended["type"] == "session_end"
        assert ended["sessionId"] == session_id
        assert not client.app.state.ws_manager.session_routes
        with client.app.state.SessionLocal() as db:
            session = db.get(RemoteSession, session_id)
            assert session.status == "ended"
            assert session.ended_at is not None
            assert db.get(Device, device["device_id"]).status == (
                "online" if endpoint == "console" else "offline"
            )
