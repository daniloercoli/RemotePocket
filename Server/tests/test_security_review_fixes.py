"""Reproduce the September review findings through the public HTTP/WS interfaces."""

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from app.config import Settings
from app.main import create_app
from app.models import AuditLog
from app.websocket_limits import FrameBudget
from app.websocket_manager import WebSocketManager
from tests.conftest import register_device


def console(client, token):
    return client.websocket_connect(
        "/console/ws", subprotocols=["mydesk", "bearer." + token]
    )


def other_owner(client):
    credentials = {
        "username": "other_review_owner",
        "password": "Meadow!Harbor7Lantern",
    }
    assert client.post("/api/auth/register", json=credentials).status_code == 200
    return client.post("/api/auth/login", json=credentials).json()["access_token"]


def test_console_quota_shared_per_owner_and_released_on_disconnect(client, owner_token):
    other = other_owner(client)
    manager = client.app.state.ws_manager
    manager.max_console_connections = 2
    with console(client, owner_token) as first:
        first.receive_json()
        with console(client, owner_token) as second, console(client, other) as third:
            second.receive_json()
            third.receive_json()
            with console(client, owner_token) as rejected:
                assert rejected.accepted_subprotocol == "mydesk"
                with pytest.raises(WebSocketDisconnect) as error:
                    rejected.receive_json()
                assert error.value.code == 4429
            assert len(manager.console_connections) == 3
        with console(client, owner_token) as replacement:
            assert replacement.receive_json()["type"] == "console_registered"
    assert not manager.console_connections
    assert not manager._connecting_consoles


def test_failed_handshake_releases_console_reservation(
    client, owner_token, monkeypatch
):
    from fastapi import WebSocket

    original = WebSocket.accept

    async def failed(*args, **kwargs):
        raise RuntimeError("simulated handshake failure")

    manager = client.app.state.ws_manager
    manager.max_console_connections = 1
    monkeypatch.setattr(WebSocket, "accept", failed)
    with pytest.raises(WebSocketDisconnect):
        with console(client, owner_token) as ws:
            ws.receive_json()
    assert not manager._connecting_consoles
    monkeypatch.setattr(WebSocket, "accept", original)
    with console(client, owner_token) as ws:
        assert ws.receive_json()["type"] == "console_registered"


def test_pending_handshakes_count_towards_shared_connection_capacity():
    async def run():
        manager = WebSocketManager(max_console_connections=1, max_connections=2)
        assert manager.reserve_console("pending", "owner")
        assert not manager.reserve_console("duplicate", "owner")
        assert manager.reserve_console("other", "other-owner")
        assert not await manager.connect_device("device", AsyncMock())
        manager.release_console_reservation("other")
        failing = AsyncMock()
        failing.accept.side_effect = RuntimeError("handshake failed")
        with pytest.raises(RuntimeError):
            await manager.connect_device("device", failing)
        assert not manager._connecting_devices
        assert await manager.connect_device("device", AsyncMock())

    asyncio.run(run())


def test_upgrade_limit_applies_before_authentication_and_is_shared_between_routes(
    client,
):
    settings = client.app.state.settings
    settings.rate_limit_enabled = True
    settings.rate_limit_ws_upgrade = 1
    with pytest.raises(WebSocketDisconnect) as denied:
        with client.websocket_connect("/console/ws"):
            pass
    assert denied.value.code == 4401
    with client.websocket_connect("/device/ws?device_id=missing") as limited:
        with pytest.raises(WebSocketDisconnect) as error:
            limited.receive_json()
        assert error.value.code == 4429


def test_device_lists_share_http_and_websocket_budget(
    client, owner_token, auth_headers
):
    other = other_owner(client)
    client.app.state.settings.rate_limit_enabled = True
    with console(client, owner_token) as first, console(client, owner_token) as second:
        first.receive_json()
        second.receive_json()
        for _ in range(29):
            assert client.get("/api/devices", headers=auth_headers).status_code == 200
        first.send_json({"type": "device_list_request"})
        assert first.receive_json()["type"] == "device_list"
        assert client.get("/api/devices", headers=auth_headers).status_code == 429
        second.send_json({"type": "device_list_request"})
        assert second.receive_json()["code"] == "RATE_LIMITED"
        with console(client, other) as independent:
            independent.receive_json()
            independent.send_json({"type": "device_list_request"})
            assert independent.receive_json()["type"] == "device_list"


def test_control_budget_shared_across_connections_counts_malformed_messages(
    client, owner_token
):
    settings = client.app.state.settings
    settings.rate_limit_enabled = True
    settings.rate_limit_ws_control = 2
    with console(client, owner_token) as first, console(client, owner_token) as second:
        first.receive_json()
        second.receive_json()
        first.send_text("invalid json")
        assert first.receive_json()["code"] == "INVALID_MESSAGE"
        first.send_json({"type": "heartbeat"})
        assert first.receive_json()["type"] == "heartbeat_ack"
        second.send_json({"type": "heartbeat"})
        with pytest.raises(WebSocketDisconnect) as error:
            second.receive_json()
        assert error.value.code == 4429


def test_websocket_limits_fail_closed_when_storage_fails(
    client, owner_token, monkeypatch
):
    client.app.state.settings.rate_limit_enabled = True
    with console(client, owner_token) as ws:
        ws.receive_json()
        monkeypatch.setattr(
            client.app.state.rate_limiter,
            "hit",
            lambda *args: (_ for _ in ()).throw(ConnectionError()),
        )
        ws.send_json({"type": "heartbeat"})
        with pytest.raises(WebSocketDisconnect) as error:
            ws.receive_json()
        assert error.value.code == 1013
    with console(client, owner_token) as ws:
        with pytest.raises(WebSocketDisconnect) as error:
            ws.receive_json()
        assert error.value.code == 1013


def test_remote_session_limit_is_atomic_across_console_connections(
    client, owner_token, auth_headers
):
    devices = [
        register_device(client, auth_headers, name=f"Review {i}") for i in range(4)
    ]
    with ExitStack() as stack:
        device_sockets = [
            stack.enter_context(
                client.websocket_connect(
                    "/device/ws?device_id=" + d["device_id"],
                    headers={"Authorization": "Bearer " + d["device_token"]},
                )
            )
            for d in devices
        ]
        for ws in device_sockets:
            ws.receive_json()
        consoles = [stack.enter_context(console(client, owner_token)) for _ in range(2)]
        for ws in consoles:
            ws.receive_json()

        def start(pair):
            ws, device = pair
            ws.send_json(
                {
                    "type": "session_start_request",
                    "deviceId": device["device_id"],
                    "devicePassword": "password-device",
                }
            )
            return ws.receive_json()

        opened = [start((consoles[0], d)) for d in devices[:2]]
        for ws in device_sockets[:2]:
            ws.receive_json()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(start, zip(consoles, devices[2:])))
        assert sorted(r["type"] for r in results) == [
            "session_error",
            "session_started",
        ]
        rejected = next(
            i for i, result in enumerate(results) if result["type"] == "session_error"
        )
        assert results[rejected]["code"] == "SESSION_LIMIT"
        assert len(client.app.state.ws_manager.session_routes) == 3
        consoles[0].send_json(
            {"type": "session_end", "sessionId": opened[0]["sessionId"]}
        )
        assert consoles[0].receive_json()["type"] == "session_end"
        assert device_sockets[0].receive_json()["type"] == "session_end"
        assert (
            start((consoles[rejected], devices[rejected + 2]))["type"]
            == "session_started"
        )


def test_refresh_reuse_revokes_descendants_and_websocket_only_for_that_session(
    client, monkeypatch
):
    monkeypatch.setattr("app.routes.websocket.AUTH_RECHECK_SECONDS", 0.01)
    credentials = {"username": "review_refresh", "password": "Meadow!Harbor7Lantern"}
    first = client.post("/api/auth/bootstrap", json=credentials).json()
    other = client.post("/api/auth/login", json=credentials).json()
    rotated = client.post(
        "/api/auth/refresh", json={"refresh_token": first["refresh_token"]}
    ).json()
    with console(client, rotated["access_token"]) as ws:
        ws.receive_json()
        assert (
            client.post(
                "/api/auth/refresh", json={"refresh_token": first["refresh_token"]}
            ).status_code
            == 401
        )
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()
    for tokens in [first, rotated]:
        assert (
            client.get(
                "/api/auth/me",
                headers={"Authorization": "Bearer " + tokens["access_token"]},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
            ).status_code
            == 401
        )
    assert (
        client.get(
            "/api/auth/me", headers={"Authorization": "Bearer " + other["access_token"]}
        ).status_code
        == 200
    )
    with client.app.state.SessionLocal() as db:
        assert (
            len(
                db.scalars(
                    select(AuditLog).where(
                        AuditLog.event_type == "refresh_token_reused"
                    )
                ).all()
            )
            == 1
        )


@pytest.mark.parametrize(
    "path", ["/metrics", "/api/health/ready", "/api/health/advanced"]
)
def test_diagnostics_require_dedicated_credentials(
    client, auth_headers, monitoring_headers, path
):
    assert client.get(path).status_code == 401
    assert client.get(path, headers=auth_headers).status_code == 401
    assert (
        client.get(path, headers={"Authorization": "Bearer wrong-token"}).status_code
        == 401
    )
    assert client.get(path, headers=monitoring_headers).status_code == 200
    assert client.get("/api/health").status_code == 200


def test_diagnostics_are_closed_when_monitoring_token_is_unconfigured():
    app = create_app(
        Settings(database_url="sqlite+pysqlite:///:memory:", monitoring_token="")
    )
    with TestClient(app) as client:
        for path in ["/metrics", "/api/health/ready", "/api/health/advanced"]:
            assert client.get(path).status_code == 404
        assert client.get("/api/health").json() == {"status": "ok"}


def test_streaming_budget_has_independent_frame_and_byte_limits(monkeypatch):
    now = [1.0]
    monkeypatch.setattr("app.websocket_limits.time.monotonic", lambda: now[0])
    budget = FrameBudget(
        Settings(max_screen_frames_per_second=2, max_screen_bytes_per_second=100)
    )
    assert budget.accept(60)
    assert not budget.accept(41)
    assert budget.accept(40)
    assert not budget.accept(1)
    now[0] += 1.01
    assert budget.accept(100)


def test_excess_screen_frames_close_device_and_end_session(
    client, owner_token, auth_headers, monkeypatch
):
    client.app.state.settings.max_screen_frames_per_second = 1
    # Avoid changing the event loop clock while keeping the frame window deterministic.
    import app.websocket_limits as ws_limits
    from types import SimpleNamespace

    monkeypatch.setattr(ws_limits, "time", SimpleNamespace(monotonic=lambda: 1.0))
    device = register_device(client, auth_headers)
    with (
        client.websocket_connect(
            "/device/ws?device_id=" + device["device_id"],
            headers={"Authorization": "Bearer " + device["device_token"]},
        ) as peer,
        console(client, owner_token) as ws,
    ):
        peer.receive_json()
        ws.receive_json()
        ws.send_json(
            {
                "type": "session_start_request",
                "deviceId": device["device_id"],
                "devicePassword": "password-device",
            }
        )
        session_id = ws.receive_json()["sessionId"]
        peer.receive_json()
        header = json.dumps(
            {
                "type": "screen_frame",
                "sessionId": session_id,
                "frameId": 1,
                "width": 1,
                "height": 1,
                "format": "jpeg",
            }
        ).encode()
        frame = len(header).to_bytes(4, "little") + header + b"\xff\xd8\xff\xd9"
        peer.send_bytes(frame)
        assert ws.receive_bytes() == frame
        peer.send_bytes(frame)
        with pytest.raises(WebSocketDisconnect) as error:
            peer.receive_json()
        assert error.value.code == 4429
        assert ws.receive_json()["type"] == "session_end"
        assert not client.app.state.ws_manager.session_routes
