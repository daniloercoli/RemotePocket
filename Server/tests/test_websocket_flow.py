from __future__ import annotations

import json
import struct

from fastapi.testclient import TestClient
import pytest

from tests.conftest import register_device


JPEG_BYTES = b"\xff\xd8\x00\xfe\xff\xd9"


def binary_frame(session_id: str, **overrides) -> bytes:
    header = json.dumps(
        {
            "type": "screen_frame",
            "sessionId": session_id,
            "frameId": 1,
            "timestamp": 1,
            "width": 100,
            "height": 200,
            "format": "jpeg",
            "quality": 60,
            **overrides,
        },
        ensure_ascii=False,
    ).encode("utf-8")
    return struct.pack("<I", len(header)) + header + JPEG_BYTES


def test_device_websocket_marks_device_online_and_offline(
    client: TestClient,
    auth_headers: dict[str, str],
):
    device = register_device(client, auth_headers)

    with client.websocket_connect(
        f"/device/ws?device_id={device['device_id']}",
        headers={"Authorization": "Bearer " + device["device_token"]},
    ) as device_ws:
        accepted = device_ws.receive_json()
        assert accepted["type"] == "device_registered"
        assert accepted["status"] == "online"

        devices = client.get("/api/devices", headers=auth_headers).json()["devices"]
        assert devices[0]["status"] == "online"

        device_ws.send_json({"type": "heartbeat"})
        assert device_ws.receive_json()["type"] == "heartbeat_ack"

    devices = client.get("/api/devices", headers=auth_headers).json()["devices"]
    assert devices[0]["status"] == "offline"


@pytest.mark.parametrize("token_source", ["bootstrap", "login", "refresh"])
def test_console_starts_session_and_relays_messages(
    client: TestClient,
    auth_headers: dict[str, str],
    owner_token: str,
    token_source: str,
):
    if token_source != "bootstrap":
        tokens = client.post(
            "/api/auth/login",
            json={
                "username": "admin",
                "password": "Quercia!Viola7Sentiero",
            },
        ).json()
        if token_source == "refresh":
            tokens = client.post(
                "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
            ).json()
        owner_token = tokens["access_token"]
    device = register_device(client, auth_headers)

    with client.websocket_connect(
        f"/device/ws?device_id={device['device_id']}",
        headers={"Authorization": "Bearer " + device["device_token"]},
    ) as device_ws:
        assert device_ws.receive_json()["type"] == "device_registered"

        with client.websocket_connect(
            "/console/ws", subprotocols=["mydesk", f"bearer.{owner_token}"]
        ) as console_ws:
            assert console_ws.receive_json()["type"] == "console_registered"

            console_ws.send_json(
                {
                    "type": "session_start_request",
                    "deviceId": device["device_id"],
                    "devicePassword": "password-device",
                }
            )

            start_for_device = device_ws.receive_json()
            assert start_for_device["type"] == "session_start"
            session_id = start_for_device["sessionId"]

            started_for_console = console_ws.receive_json()
            assert started_for_console["type"] == "session_started"
            assert started_for_console["sessionId"] == session_id

            console_ws.send_json(
                {
                    "type": "input_tap",
                    "sessionId": session_id,
                    "x": 10,
                    "y": 20,
                    "screenWidth": 100,
                    "screenHeight": 200,
                }
            )
            relayed_tap = device_ws.receive_json()
            assert relayed_tap["type"] == "input_tap"
            assert relayed_tap["x"] == 10

            payload = binary_frame(session_id)
            device_ws.send_bytes(payload)
            assert console_ws.receive_bytes() == payload

            # Text control messages and successive binary frames share the socket.
            device_ws.send_json({"type": "heartbeat", "sessionId": session_id})
            assert device_ws.receive_json()["type"] == "heartbeat_ack"
            next_payload = binary_frame(session_id, frameId=2)
            device_ws.send_bytes(next_payload)
            assert console_ws.receive_bytes() == next_payload

            console_ws.send_json(
                {
                    "type": "session_end",
                    "sessionId": session_id,
                    "reason": "user_closed",
                }
            )
            ended_for_device = device_ws.receive_json()
            assert ended_for_device["type"] == "session_end"
            assert ended_for_device["reason"] == "user_closed"

            device_ws.send_bytes(payload)
            assert device_ws.receive_json()["code"] == "SESSION_NOT_AUTHORIZED"


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x01\x00\x00",
        struct.pack("<I", 0) + JPEG_BYTES,
        struct.pack("<I", 16 * 1024 + 1) + b" " * (16 * 1024 + 1) + JPEG_BYTES,
        struct.pack("<I", 1000) + b"{}" + JPEG_BYTES,
        struct.pack("<I", 2) + b"{}",  # No JPEG payload.
        struct.pack("<I", 1) + b"\xff" + JPEG_BYTES,
        struct.pack("<I", 1) + b"{" + JPEG_BYTES,
        struct.pack("<I", 2) + b"[]" + JPEG_BYTES,
        binary_frame("session", type="heartbeat"),
        binary_frame("session", format="png"),
        binary_frame(""),
        binary_frame("session", sessionId=[]),
        binary_frame("session", width=0),
        binary_frame("session", height=True),
        binary_frame("session", frameId=-1),
    ],
)
def test_invalid_binary_frame_does_not_disconnect_device(client, auth_headers, payload):
    device = register_device(client, auth_headers)
    with client.websocket_connect(
        f"/device/ws?device_id={device['device_id']}",
        headers={"Authorization": "Bearer " + device["device_token"]},
    ) as device_ws:
        assert device_ws.receive_json()["type"] == "device_registered"
        device_ws.send_bytes(payload)
        assert device_ws.receive_json()["code"] == "INVALID_SCREEN_FRAME"
        device_ws.send_json({"type": "heartbeat"})
        assert device_ws.receive_json()["type"] == "heartbeat_ack"


def test_device_cannot_inject_frames_into_another_devices_session(
    client, auth_headers, owner_token
):
    target = register_device(client, auth_headers)
    other = register_device(client, auth_headers, name="Other device")
    with (
        client.websocket_connect(
            f"/device/ws?device_id={target['device_id']}",
            headers={"Authorization": "Bearer " + target["device_token"]},
        ) as target_ws,
        client.websocket_connect(
            f"/device/ws?device_id={other['device_id']}",
            headers={"Authorization": "Bearer " + other["device_token"]},
        ) as other_ws,
        client.websocket_connect(
            "/console/ws", subprotocols=["mydesk", f"bearer.{owner_token}"]
        ) as console_ws,
    ):
        assert target_ws.receive_json()["type"] == "device_registered"
        assert other_ws.receive_json()["type"] == "device_registered"
        assert console_ws.receive_json()["type"] == "console_registered"
        console_ws.send_json(
            {
                "type": "session_start_request",
                "deviceId": target["device_id"],
                "devicePassword": "password-device",
            }
        )
        session_id = target_ws.receive_json()["sessionId"]
        assert console_ws.receive_json()["type"] == "session_started"
        other_ws.send_bytes(binary_frame(session_id, frameId=999))
        assert other_ws.receive_json()["code"] == "SESSION_NOT_AUTHORIZED"

        payload = binary_frame(session_id)
        target_ws.send_bytes(payload)
        assert console_ws.receive_bytes() == payload


def test_screen_frames_require_binary_messages(client, auth_headers):
    device = register_device(client, auth_headers)
    with client.websocket_connect(
        f"/device/ws?device_id={device['device_id']}",
        headers={"Authorization": "Bearer " + device["device_token"]},
    ) as device_ws:
        device_ws.receive_json()
        device_ws.send_json(
            {"type": "screen_frame", "sessionId": "session", "data": "base64"}
        )
        assert device_ws.receive_json()["code"] == "INVALID_MESSAGE"
