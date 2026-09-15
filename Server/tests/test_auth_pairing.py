from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import register_device


def test_bootstrap_login_and_me(client: TestClient):
    bootstrap = client.post(
        "/api/auth/bootstrap",
        json={"username": "admin", "password": "Quercia!Viola7Sentiero"},
    )
    assert bootstrap.status_code == 200
    token = bootstrap.json()["access_token"]

    duplicate = client.post(
        "/api/auth/bootstrap",
        json={"username": "altro", "password": "Quercia!Viola7Sentiero"},
    )
    assert duplicate.status_code == 409

    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Quercia!Viola7Sentiero"},
    )
    assert login.status_code == 200

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["username"] == "admin"


def test_console_page_is_served(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    assert "MyDesk Console" in response.text


def test_pairing_code_registers_device_once(
    client: TestClient,
    auth_headers: dict[str, str],
):
    pairing = client.post("/api/pairing-codes", headers=auth_headers)
    assert pairing.status_code == 200
    code = pairing.json()["code"]

    first_pair = client.post(
        "/api/devices/pair",
        json={
            "pairing_code": code.lower(),
            "name": "Pixel casa",
            "device_password": "password-device",
        },
    )
    assert first_pair.status_code == 200
    assert first_pair.json()["device_id"].startswith("dev_")
    assert first_pair.json()["device_token"]

    second_pair = client.post(
        "/api/devices/pair",
        json={
            "pairing_code": code,
            "name": "Pixel duplicato",
            "device_password": "password-device",
        },
    )
    assert second_pair.status_code == 400

    devices = client.get("/api/devices", headers=auth_headers)
    assert devices.status_code == 200
    assert devices.json()["devices"][0]["name"] == "Pixel casa"
    assert devices.json()["devices"][0]["status"] == "offline"


def test_revoke_device(client: TestClient, auth_headers: dict[str, str]):
    device = register_device(client, auth_headers)
    revoke = client.post(
        f"/api/devices/{device['device_id']}/revoke", headers=auth_headers
    )
    assert revoke.status_code == 200
    assert revoke.json()["device"]["status"] == "revoked"
