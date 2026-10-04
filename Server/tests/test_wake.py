from datetime import UTC
from pathlib import Path

from cryptography.fernet import Fernet
from sqlalchemy import select, text

from app.database import init_db
from app.models import AuditLog, Device
from app.timeutils import utc_now
from app.wake_protocol import sign_message, verify_message
from tests.conftest import register_device


def vector():
    return dict(
        line.split("=", 1)
        for line in (
            Path(__file__).resolve().parents[2] / "protocol/wake-vectors.properties"
        )
        .read_text()
        .splitlines()
        if line and not line.startswith("#")
    )


def configure(client, device, mode="on_demand"):
    return client.put(
        f"/api/devices/{device['device_id']}/agent-configuration",
        headers={"Authorization": f"Bearer {device['device_token']}"},
        json={"connection_mode": mode},
    )


def test_shared_wake_vector():
    v = vector()
    assert (
        sign_message(v["device_id"], int(v["expires_at"]), v["key"], v["nonce"])
        == v["message"]
    )
    assert len(v["message"]) <= 160 and v["message"].isascii()
    assert verify_message(v["message"], v["device_id"], v["key"], int(v["now"]))
    for message, device, key, now in [
        (v["message"].replace("RPW1", "RPW2"), v["device_id"], v["key"], int(v["now"])),
        (v["message"], "dev_" + "B" * 22, v["key"], int(v["now"])),
        (v["message"], v["device_id"], "A" * 43, int(v["now"])),
        (v["message"], v["device_id"], v["key"], int(v["expires_at"])),
        (v["message"], v["device_id"], v["key"], int(v["now"]) - 61),
    ]:
        assert not verify_message(message, device, key, now)


def test_configuration_and_manual_wake_without_new_pairing(client, auth_headers):
    client.app.state.settings.encryption_key = Fernet.generate_key().decode()
    device = register_device(client, auth_headers)
    path = f"/api/devices/{device['device_id']}"
    assert client.post(path + "/wake-message", headers=auth_headers).status_code == 409
    first = configure(client, device)
    assert first.status_code == 200
    assert first.headers["cache-control"] == "no-store"
    key = first.json()["wake_key"]
    assert configure(client, device, "persistent").json()["wake_key"] == key
    assert configure(client, device).json()["wake_key"] == key
    listed = client.get("/api/devices", headers=auth_headers).json()["devices"][0]
    assert listed["connection_mode"] == "on_demand" and listed["wake_configured"]
    assert key not in str(listed)
    wake = client.post(path + "/wake-message", headers=auth_headers)
    assert wake.status_code == 200
    assert wake.headers["cache-control"] == "no-store"
    now = int(utc_now().replace(tzinfo=UTC).timestamp())
    assert verify_message(wake.json()["message"], device["device_id"], key, now)
    with client.app.state.SessionLocal() as db:
        record = db.get(Device, device["device_id"])
        assert record.wake_key_encrypted != key and key not in record.wake_key_encrypted
        events = db.scalars(select(AuditLog)).all()
        assert all(
            key not in str(event.event_payload_json)
            and wake.json()["message"] not in str(event.event_payload_json)
            for event in events
        )


def test_wake_auth_revocation_and_limits(client, auth_headers):
    client.app.state.settings.encryption_key = Fernet.generate_key().decode()
    device = register_device(client, auth_headers)
    other = register_device(client, auth_headers)
    path = f"/api/devices/{device['device_id']}"
    assert (
        client.put(
            path + "/agent-configuration",
            headers=auth_headers,
            json={"connection_mode": "on_demand"},
        ).status_code
        == 401
    )
    assert (
        client.put(
            path + "/agent-configuration",
            headers={"Authorization": f"Bearer {other['device_token']}"},
            json={"connection_mode": "on_demand"},
        ).status_code
        == 401
    )
    assert configure(client, device).status_code == 200
    assert client.post(path + "/wake-message").status_code == 401
    password = "Quercia!Viola7Sentiero"
    client.post(
        "/api/auth/register",
        json={"username": "other_wake_owner", "password": password},
    )
    other_token = client.post(
        "/api/auth/login", json={"username": "other_wake_owner", "password": password}
    ).json()["access_token"]
    assert (
        client.post(
            path + "/wake-message", headers={"Authorization": "Bearer " + other_token}
        ).status_code
        == 404
    )
    client.app.state.settings.rate_limit_enabled = True
    for _ in range(3):
        assert (
            client.post(path + "/wake-message", headers=auth_headers).status_code == 200
        )
    assert client.post(path + "/wake-message", headers=auth_headers).status_code == 429
    client.app.state.settings.rate_limit_enabled = False
    client.post(path + "/revoke", headers=auth_headers)
    assert configure(client, device).status_code == 401
    assert client.post(path + "/wake-message", headers=auth_headers).status_code == 404


def test_missing_cipher_keeps_pairing_and_legacy_connection(client, auth_headers):
    client.app.state.settings.encryption_key = ""
    device = register_device(client, auth_headers)
    assert configure(client, device).status_code == 503
    with client.websocket_connect(
        f"/device/ws?device_id={device['device_id']}",
        headers={"Authorization": f"Bearer {device['device_token']}"},
    ) as ws:
        assert ws.receive_json()["type"] == "device_registered"


def test_existing_schema_upgrade_is_additive_and_idempotent(client, auth_headers):
    device = register_device(client, auth_headers)
    with client.app.state.SessionLocal() as db:
        engine = db.get_bind()
    with engine.begin() as db:
        db.execute(text("ALTER TABLE devices DROP COLUMN connection_mode"))
        db.execute(text("ALTER TABLE devices DROP COLUMN wake_key_encrypted"))
    init_db(engine)
    init_db(engine)
    with client.app.state.SessionLocal() as db:
        record = db.get(Device, device["device_id"])
        assert record.name == "Pixel test"
        assert record.connection_mode == "persistent"
        assert record.wake_key_encrypted is None
    client.app.state.settings.encryption_key = Fernet.generate_key().decode()
    assert configure(client, device).status_code == 200


def test_console_receives_presence_and_wake_channel(client, auth_headers):
    client.app.state.settings.encryption_key = Fernet.generate_key().decode()
    device = register_device(client, auth_headers)
    configure(client, device)
    with client.websocket_connect("/console/ws", headers=auth_headers) as console:
        console.receive_json()  # console_ready
        console.send_json({"type": "device_list_request", "watch": True})
        assert console.receive_json()["type"] == "device_list"
        with client.websocket_connect(
            f"/device/ws?device_id={device['device_id']}",
            headers={"Authorization": f"Bearer {device['device_token']}"},
        ) as ws:
            ws.receive_json()
            changed = console.receive_json()
            assert changed["device"]["status"] == "online"
            ws.send_json(
                {
                    "type": "device_hello",
                    "wake": {"channel": "telegram", "nonce": "A" * 22},
                }
            )
            ws.receive_json()
            assert console.receive_json()["device"]["wake_configured"]
        assert console.receive_json()["device"]["status"] == "offline"
    events = client.get(
        "/api/activity?event_type=device_woken", headers=auth_headers
    ).json()["events"]
    assert events[0]["details"] == {"channel": "telegram"}
