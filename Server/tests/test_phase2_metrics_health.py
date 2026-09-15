"""Behavioral regressions for monitoring, failures and app isolation."""

from contextlib import ExitStack
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.config import Settings
from app.main import create_app
from tests.conftest import register_device


def test_metrics_exports_requests_and_bounds_endpoint_cardinality(
    client, monitoring_headers
):
    for suffix in ("one", "two", "three"):
        assert client.get(f"/unknown/{suffix}").status_code == 404
    response = client.get("/metrics", headers=monitoring_headers)
    assert response.status_code == 200
    assert (
        'http_requests_total{endpoint="/unmatched",method="GET",status="404"} 3.0'
        in response.text
    )
    assert "/unknown/one" not in response.text
    assert "request_duration_seconds_bucket" in response.text
    assert "text/plain" in response.headers["content-type"]


def test_metrics_can_be_disabled_and_apps_do_not_share_collectors(client):
    first = client.app.state.metrics.registry
    app = create_app(
        Settings(database_url="sqlite+pysqlite:///:memory:", metrics_enabled=False)
    )
    with TestClient(app) as other:
        assert other.get("/metrics").status_code == 404
        assert other.get("/api/health").status_code == 200
        assert (
            app.state.metrics.registry.get_sample_value(
                "http_requests_total",
                {"method": "GET", "endpoint": "/api/health", "status": "200"},
            )
            is None
        )
    assert client.app.state.metrics.registry is first
    assert first is not app.state.metrics.registry


def test_database_failure_keeps_health_503_and_static_metrics_available(
    client, monitoring_headers
):
    with patch.object(
        client.app.state.db_engine,
        "connect",
        side_effect=OperationalError("SELECT", {}, Exception("private-db-secret")),
    ):
        for path in ("/api/health", "/api/health/ready", "/api/health/advanced"):
            response = client.get(path, headers=monitoring_headers)
            assert response.status_code == 503
            assert "private-db-secret" not in response.text
        assert client.get("/").status_code == 200
        assert client.get("/metrics", headers=monitoring_headers).status_code == 200


def test_readiness_checks_actual_app_storage_even_in_dev(client, monitoring_headers):
    with patch.object(
        client.app.state.rate_limiter.storage,
        "check",
        side_effect=TimeoutError("secret-host"),
    ):
        response = client.get("/api/health/ready", headers=monitoring_headers)
    assert response.status_code == 503
    assert "secret-host" not in response.text
    assert (
        next(c for c in response.json()["checks"] if c["name"] == "rate_limit_storage")[
            "error"
        ]
        == "TimeoutError"
    )


def test_health_uses_app_engine_not_global_settings(client, monitoring_headers):
    with patch.object(
        client.app.state.db_engine, "connect", wraps=client.app.state.db_engine.connect
    ) as connect:
        assert (
            client.get("/api/health/advanced", headers=monitoring_headers).status_code
            == 200
        )
    connect.assert_called_once()


def test_live_session_gauges_and_events_change_without_http_polling(
    client, auth_headers, owner_token
):
    devices = [
        register_device(client, auth_headers, name=f"Device {i}") for i in range(2)
    ]
    metrics = client.app.state.metrics
    with ExitStack() as stack:
        sockets = [
            stack.enter_context(
                client.websocket_connect(
                    f"/device/ws?device_id={device['device_id']}",
                    headers={"Authorization": "Bearer " + device["device_token"]},
                )
            )
            for device in devices
        ]
        for socket in sockets:
            assert socket.receive_json()["type"] == "device_registered"
        console = stack.enter_context(
            client.websocket_connect(
                "/console/ws", subprotocols=["mydesk", f"bearer.{owner_token}"]
            )
        )
        console.receive_json()
        sessions = []
        for device, socket in zip(devices, sockets):
            console.send_json(
                {
                    "type": "session_start_request",
                    "deviceId": device["device_id"],
                    "devicePassword": "password-device",
                }
            )
            sessions.append(socket.receive_json()["sessionId"])
            assert console.receive_json()["type"] == "session_started"
        assert metrics.registry.get_sample_value("active_sessions") == 2
        assert (
            metrics.registry.get_sample_value(
                "active_websocket_connections", {"connection_type": "device"}
            )
            == 2
        )
        console.send_json({"type": "session_end", "sessionId": sessions[0]})
        assert sockets[0].receive_json()["type"] == "session_end"
        assert metrics.registry.get_sample_value("active_sessions") == 1
        assert (
            metrics.registry.get_sample_value(
                "session_events_total", {"event_type": "opened"}
            )
            == 2
        )
        assert (
            metrics.registry.get_sample_value(
                "session_events_total", {"event_type": "closed"}
            )
            == 1
        )
    assert metrics.registry.get_sample_value("active_sessions") == 0
    assert (
        metrics.registry.get_sample_value(
            "active_websocket_connections", {"connection_type": "device"}
        )
        == 0
    )


def test_auth_failures_are_counted(client):
    response = client.post(
        "/api/auth/login", json={"username": "missing", "password": "wrong-password"}
    )
    assert response.status_code == 401
    assert (
        client.app.state.metrics.registry.get_sample_value(
            "auth_failures_total", {"auth_type": "http"}
        )
        == 1
    )


def test_timed_out_probes_share_the_same_background_check():
    import asyncio
    from threading import Event
    from app.health_checks import HealthChecker

    started, release = Event(), Event()
    calls = []

    def slow_check():
        calls.append(1)
        started.set()
        release.wait(timeout=2)
        return True

    async def run():
        checker = HealthChecker()
        try:
            first = await checker.probe("database", slow_check, 0.01)
            assert started.is_set() and first.status == "unhealthy"
            second = await checker.probe("database", slow_check, 0.01)
            assert second.status == "unhealthy"
            assert len(calls) == 1
            release.set()
        finally:
            release.set()
            checker.close()

    asyncio.run(run())


def test_failed_session_delivery_does_not_report_started_or_leave_route(
    client, auth_headers, owner_token
):
    from unittest.mock import AsyncMock

    device = register_device(client, auth_headers)
    manager = client.app.state.ws_manager
    with client.websocket_connect(
        f"/device/ws?device_id={device['device_id']}",
        headers={"Authorization": "Bearer " + device["device_token"]},
    ) as ws:
        ws.receive_json()
        with client.websocket_connect(
            "/console/ws", subprotocols=["mydesk", "bearer." + owner_token]
        ) as console:
            console.receive_json()
            with patch.object(
                manager, "send_to_device", new=AsyncMock(return_value=False)
            ):
                console.send_json(
                    {
                        "type": "session_start_request",
                        "deviceId": device["device_id"],
                        "devicePassword": "password-device",
                    }
                )
                response = console.receive_json()
                assert response["type"] == "session_error"
                assert response["code"] == "DEVICE_OFFLINE"
            assert not manager.session_routes
