"""Regressions for stalled transports and atomic session cleanup."""

import asyncio
from contextlib import ExitStack
from unittest.mock import AsyncMock

import pytest

from app.models import Device, RemoteSession
from app.observability import ObservabilityMiddleware
from tests.conftest import request_session, register_device


@pytest.mark.parametrize("disconnect", ["console", "device"])
def test_disconnect_commits_sessions_before_notifying_peers(
    client, auth_headers, owner_token, monkeypatch, disconnect
):
    manager = client.app.state.ws_manager
    devices = [register_device(client, auth_headers) for _ in range(2)]
    observed = []
    sessions = []
    method = "send_to_device" if disconnect == "console" else "send_to_console"
    original = getattr(manager, method)

    async def observe(destination, message):
        if message.get("type") == "session_end":
            checked_out = client.app.state.db_engine.pool.checkedout()
            with client.app.state.SessionLocal() as db:
                observed.append(
                    (
                        checked_out,
                        [db.get(RemoteSession, sid).status for sid in sessions],
                        [db.get(Device, d["device_id"]).status for d in devices],
                    )
                )
        return await original(destination, message)

    monkeypatch.setattr(manager, method, observe)
    with ExitStack() as stack:
        peers = [
            stack.enter_context(
                client.websocket_connect(
                    "/device/ws?device_id=" + d["device_id"],
                    headers={"Authorization": "Bearer " + d["device_token"]},
                )
            )
            for d in devices
        ]
        for peer in peers:
            peer.receive_json()
        with client.websocket_connect(
            "/console/ws", subprotocols=["mydesk", "bearer." + owner_token]
        ) as console:
            console.receive_json()
            for device, peer in zip(devices, peers):
                request_session(console, device["device_id"], "password-device")
                sessions.append(console.receive_json()["sessionId"])
                peer.receive_json()
            if disconnect == "console":
                console.close()
                for peer in peers:
                    assert peer.receive_json()["reason"] == "console_disconnected"
                assert observed == [(0, ["ended", "ended"], ["online", "online"])] * 2
                assert not manager.session_routes
            else:
                peers[0].close()
                assert console.receive_json()["reason"] == "device_disconnected"
                assert observed == [
                    (0, ["ended", "in_session"], ["offline", "in_session"])
                ]
                assert manager.get_route(sessions[0]) is None
                assert manager.get_route(sessions[1]) is not None


@pytest.mark.parametrize(
    "message",
    [
        {"type": "websocket.accept", "headers": []},
        {"type": "websocket.send", "text": "private-payload"},
        {"type": "websocket.send", "bytes": b"private-payload"},
        {"type": "websocket.close", "code": 1000},
    ],
)
def test_stalled_websocket_writes_release_handler_even_if_close_also_stalls(
    client, monkeypatch, message
):
    monkeypatch.setattr("app.observability.WEBSOCKET_SEND_TIMEOUT_SECONDS", 0.01)

    async def run():
        cleaned_up = False

        async def endpoint(scope, receive, send):
            nonlocal cleaned_up
            try:
                await send(message)
            finally:
                cleaned_up = True

        async def blocked_send(message):
            await asyncio.Event().wait()

        send = AsyncMock(side_effect=blocked_send)
        scope = {
            "type": "websocket",
            "app": client.app,
            "headers": [],
            "path": "/console/ws",
            "state": {},
        }
        await asyncio.wait_for(
            ObservabilityMiddleware(endpoint)(scope, AsyncMock(), send), 0.5
        )
        assert cleaned_up
        assert send.await_count == 2
        assert send.call_args.args[0] == {"type": "websocket.close", "code": 1011}

    asyncio.run(run())


@pytest.mark.parametrize("device", [False, True])
def test_deeply_nested_control_is_rejected_without_losing_connection(
    client, owner_token, auth_headers, device
):
    if device:
        paired = register_device(client, auth_headers)
        connection = client.websocket_connect(
            "/device/ws?device_id=" + paired["device_id"],
            headers={"Authorization": "Bearer " + paired["device_token"]},
        )
    else:
        connection = client.websocket_connect(
            "/console/ws", subprotocols=["mydesk", "bearer." + owner_token]
        )
    with connection as ws:
        ws.receive_json()
        ws.send_text("[" * 2000 + "0" + "]" * 2000)
        assert ws.receive_json()["code"] == "INVALID_MESSAGE"
        ws.send_json({"type": "heartbeat"})
        assert ws.receive_json()["type"] == "heartbeat_ack"
