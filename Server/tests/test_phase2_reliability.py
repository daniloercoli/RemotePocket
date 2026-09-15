"""Integration regressions for errors, tracing, logging and shutdown."""

import asyncio
import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.websockets import WebSocketDisconnect

from app.config import Settings
from app.correlation import correlation_id_context, get_request_id
from app.error_handlers import MyDeskError
from app.logging_config import StructuredJsonFormatter
from app.main import create_app
from app.shutdown import GracefulShutdownHandler, ShutdownConfig
from app.websocket_manager import WebSocketManager
from tests.conftest import register_device


@pytest.mark.parametrize("environment", ["prod", "staging"])
def test_valid_production_settings_load(environment):
    settings = Settings(
        environment=environment,
        encryption_key=Fernet.generate_key().decode(),
        public_base_url="https://desk.example.com",
        secret_key="test-key-at-least-32-characters-long",
        database_url="postgresql+psycopg2://db/test",
        redis_url="redis://redis/0",
        cors_allowed_origins="https://desk.example.com",
        rate_limit_enabled=True,
        check_password_breaches=True,
    )
    assert not settings.redis_relay_enabled


def test_error_handlers_preserve_contract_and_do_not_expose_secrets(client):
    app = client.app

    @app.get("/test/error/{kind}")
    def fail(kind):
        if kind == "http":
            raise HTTPException(429, "Wait", headers={"Retry-After": "17"})
        if kind == "business":
            raise MyDeskError("Known failure", "KNOWN")
        if kind == "sql":
            raise SQLAlchemyError("private-password")
        raise RuntimeError("private-password")

    for kind, expected in (
        ("http", 429),
        ("business", 400),
        ("sql", 500),
        ("unexpected", 500),
    ):
        response = client.get(
            f"/test/error/{kind}", headers={"X-Request-ID": "review-correlation"}
        )
        assert response.status_code == expected
        assert response.json()["request_id"] == "review-correlation"
        assert response.headers["x-request-id"] == "review-correlation"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "detail" in response.json()
        assert "private-password" not in response.text
        if kind == "http":
            assert response.headers["retry-after"] == "17"
    assert (
        app.state.metrics.registry.get_sample_value(
            "http_requests_total",
            {"method": "GET", "endpoint": "/test/error/{kind}", "status": "500"},
        )
        == 2
    )


def test_validation_does_not_log_or_return_input(client, caplog):
    secret = "secret-that-must-not-be-logged"
    with caplog.at_level(logging.INFO):
        response = client.post(
            "/api/auth/login", json={"username": "a", "password": {"secret": secret}}
        )
    assert response.status_code == 422
    assert secret not in response.text
    assert secret not in caplog.text
    assert isinstance(response.json()["detail"], list)


def test_websocket_send_failures_do_not_log_exception_payloads(caplog):
    async def run():
        manager = WebSocketManager()
        socket = AsyncMock()
        socket.send_json.side_effect = RuntimeError("private-websocket-payload")
        socket.send_bytes.side_effect = RuntimeError("private-websocket-payload")
        await manager.connect_device("device", socket)
        await manager.connect_console("console", "owner", socket)
        assert not await manager.send_to_device("device", {"type": "ping"})
        assert not await manager.send_to_console("console", b"frame")

    with caplog.at_level(logging.ERROR):
        asyncio.run(run())
    assert "private-websocket-payload" not in caplog.text
    failures = [record for record in caplog.records if record.levelno == logging.ERROR]
    assert len(failures) == 2
    assert all(
        record.extra_fields["error_type"] == "RuntimeError" for record in failures
    )


def test_json_logging_does_not_serialize_raw_exception_details():
    error = RuntimeError("private-exception-details")
    record = logging.LogRecord(
        "app",
        logging.ERROR,
        __file__,
        1,
        "Operation failed",
        (),
        (type(error), error, None),
    )
    rendered = StructuredJsonFormatter("prod").format(record)
    assert "private-exception-details" not in rendered
    assert json.loads(rendered)["error_type"] == "RuntimeError"


def test_websocket_database_failure_uses_websocket_close(client, owner_token):
    from app.routes.websocket import authenticate_user

    calls = 0

    def fail_after_registration(*args):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise SQLAlchemyError("private-database-error")
        return authenticate_user(*args)

    with patch(
        "app.routes.websocket.authenticate_user",
        side_effect=fail_after_registration,
    ):
        with pytest.raises(WebSocketDisconnect) as closed:
            with client.websocket_connect(
                "/console/ws", subprotocols=["mydesk", "bearer." + owner_token]
            ) as socket:
                assert socket.receive_json()["type"] == "console_registered"
                socket.receive_json()
    assert closed.value.code == 1011
    assert client.app.state.db_engine.pool.checkedout() == 0


@pytest.mark.parametrize("failure_point", ["accept", "registered"])
def test_console_registration_failure_releases_connection_and_database(
    client, owner_token, failure_point
):
    from starlette.websockets import WebSocket

    original_send = WebSocket.send_json

    async def fail_registered(socket, data, *args, **kwargs):
        if data.get("type") == "console_registered":
            raise RuntimeError("registration failed")
        await original_send(socket, data, *args, **kwargs)

    replacement = (
        AsyncMock(side_effect=RuntimeError("accept failed"))
        if failure_point == "accept"
        else fail_registered
    )
    method = "accept" if failure_point == "accept" else "send_json"
    with patch.object(WebSocket, method, replacement):
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                "/console/ws", subprotocols=["mydesk", "bearer." + owner_token]
            ) as socket:
                socket.receive_json()
    assert not client.app.state.ws_manager.console_connections
    assert client.app.state.db_engine.pool.checkedout() == 0


def test_access_logs_and_correlation_are_real_and_isolated(client, caplog):
    with caplog.at_level(logging.INFO):
        response = client.get("/", headers={"X-Request-ID": "accepted-id"})
        generated = client.get("/", headers={"X-Request-ID": "bad id"})
    assert response.headers["x-request-id"] == "accepted-id"
    assert generated.headers["x-request-id"] != "bad id"
    entries = [r for r in caplog.records if r.msg == "HTTP request completed"]
    assert {r.request_id for r in entries} >= {
        "accepted-id",
        generated.headers["x-request-id"],
    }
    assert get_request_id() is None
    parsed = json.loads(StructuredJsonFormatter("prod").format(entries[0]))
    assert parsed["endpoint"] == "/"
    assert parsed["status"] == 200
    with correlation_id_context("outer"):
        with correlation_id_context("inner"):
            assert get_request_id() == "inner"
        assert get_request_id() == "outer"


def test_tracing_emits_http_database_and_websocket_spans_with_parent_context():
    app = create_app(Settings(database_url="sqlite+pysqlite:///:memory:"))
    exporter = InMemorySpanExporter()
    app.state.tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))

    @app.get("/test/query")
    def query():
        with app.state.db_engine.connect() as connection:
            return {"result": connection.scalar(text("SELECT 1"))}

    with TestClient(app) as client:
        exporter.clear()
        response = client.get(
            "/test/query?access_token=do-not-export-this-secret",
            headers={
                "traceparent": "00-12345678901234567890123456789012-1234567890123456-01"
            },
        )
        assert response.status_code == 200
        spans = exporter.get_finished_spans()
        http = next(s for s in spans if s.name == "GET /test/query")
        db = next(s for s in spans if s.name == "db.query")
        assert http.context.trace_id == int("12345678901234567890123456789012", 16)
        assert db.parent.span_id == http.context.span_id
        assert "db.statement" not in db.attributes
        assert "do-not-export-this-secret" not in str(
            [dict(s.attributes) for s in spans]
        )
        tokens = client.post(
            "/api/auth/bootstrap",
            json={"username": "admin", "password": "Quercia!Viola7Sentiero"},
        ).json()
        with client.websocket_connect(
            "/console/ws",
            subprotocols=["mydesk", "bearer." + tokens["access_token"]],
            headers={"X-Request-ID": "ws-request"},
        ) as ws:
            assert ws.receive_json()["type"] == "console_registered"
            ws.send_json({"type": "heartbeat"})
            assert ws.receive_json()["type"] == "heartbeat_ack"
        assert any("/console/ws" in s.name for s in exporter.get_finished_spans()), (
            sorted({s.name for s in exporter.get_finished_spans()})
        )


def test_shutdown_rejects_new_work_and_fails_readiness(client, monitoring_headers):
    client.app.state.shutdown_handler.begin_shutdown()
    assert (
        client.get("/api/health/ready", headers=monitoring_headers).status_code == 503
    )
    assert client.get("/").status_code == 503
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect("/console/ws"):
            pass
    assert error.value.code == 1012


def test_shutdown_bounds_a_socket_that_never_finishes():
    async def run():
        blocked = AsyncMock(side_effect=lambda **kwargs: None)
        cancelled = asyncio.Event()

        async def close(**kwargs):
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        blocked.side_effect = close
        app = SimpleNamespace(
            state=SimpleNamespace(
                ws_manager=SimpleNamespace(
                    device_connections={"dev": SimpleNamespace(close=blocked)},
                    console_connections={},
                )
            )
        )
        handler = GracefulShutdownHandler(
            ShutdownConfig(timeout_seconds=0.2, websocket_drain_timeout=0.02)
        )
        await asyncio.wait_for(handler.initiate_shutdown(app), 1)
        assert cancelled.is_set()
        assert handler.is_shutdown_initiated
        await handler.initiate_shutdown(app)
        assert blocked.await_count == 1

    asyncio.run(run())


def test_real_uvicorn_sigterm_closes_websocket_and_exits(tmp_path):
    import os
    import signal
    import socket
    import subprocess
    import sys
    import time

    import httpx
    from websockets.exceptions import (
        ConnectionClosedOK,
        ConnectionClosedError,
        InvalidStatus,
    )
    from websockets.sync.client import connect

    if os.name != "posix":
        pytest.skip("POSIX signal integration test")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen()
    script = """import socket, sys, uvicorn
from app.server import MyDeskServer, app
listener = socket.socket(fileno=int(sys.argv[1]))
MyDeskServer(uvicorn.Config(app, host="127.0.0.1", port=0, access_log=False)).run(sockets=[listener])
"""
    env = {
        **os.environ,
        "MYDESK_DATABASE_URL": "sqlite+pysqlite:///:memory:",
        "MYDESK_ENVIRONMENT": "dev",
        "MYDESK_CHECK_PASSWORD_BREACHES": "false",
        "MYDESK_RATE_LIMIT_ENABLED": "false",
        "MYDESK_TRACING_ENABLED": "false",
    }
    output = tmp_path / "server.log"
    with output.open("w") as log:
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(listener.fileno())],
            pass_fds=[listener.fileno()],
            stdout=log,
            stderr=log,
            env=env,
        )
        listener.close()
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=1) as client:
                for _ in range(100):
                    if process.poll() is not None:
                        pytest.fail(output.read_text())
                    try:
                        if client.get("/api/health").status_code == 200:
                            break
                    except httpx.TransportError:
                        time.sleep(0.02)
                else:
                    pytest.fail("Uvicorn did not start")
                response = client.post(
                    "/api/auth/bootstrap",
                    json={"username": "admin", "password": "Quercia!Viola7Sentiero"},
                )
                assert response.status_code == 200, response.text
                token = response.json()["access_token"]
                device = register_device(client, {"Authorization": "Bearer " + token})
                device_url = (
                    f"ws://127.0.0.1:{port}/device/ws?device_id={device['device_id']}"
                )
                device_headers = {"Authorization": "Bearer " + device["device_token"]}
                # Validate the wire protocol: TestClient preserves pre-accept close
                # codes, whereas Uvicorn converts them into HTTP 403 denials.
                with connect(device_url, additional_headers=device_headers) as first:
                    assert (
                        json.loads(first.recv(timeout=2))["type"] == "device_registered"
                    )
                    with connect(
                        device_url, additional_headers=device_headers
                    ) as duplicate:
                        with pytest.raises(ConnectionClosedError) as conflict:
                            duplicate.recv(timeout=2)
                        assert conflict.value.rcvd.code == 4409
                    first.send(json.dumps({"type": "heartbeat"}))
                    assert json.loads(first.recv(timeout=2))["type"] == "heartbeat_ack"
                    with pytest.raises(InvalidStatus) as invalid:
                        with connect(
                            device_url,
                            additional_headers={"Authorization": "Bearer invalid"},
                        ):
                            pytest.fail("Invalid credentials were accepted")
                    assert invalid.value.response.status_code == 403
                for _ in range(100):
                    devices = client.get(
                        "/api/devices", headers={"Authorization": "Bearer " + token}
                    ).json()["devices"]
                    if devices[0]["status"] == "offline":
                        break
                    time.sleep(0.02)
                with connect(
                    device_url, additional_headers=device_headers
                ) as reconnected:
                    assert (
                        json.loads(reconnected.recv(timeout=2))["type"]
                        == "device_registered"
                    )
                with connect(
                    f"ws://127.0.0.1:{port}/console/ws",
                    subprotocols=["mydesk", "bearer." + token],
                ) as ws:
                    assert (
                        json.loads(ws.recv(timeout=2))["type"] == "console_registered"
                    )
                    process.send_signal(signal.SIGTERM)
                    with pytest.raises(ConnectionClosedOK) as closed:
                        ws.recv(timeout=3)
                    assert closed.value.rcvd.code == 1001
                # Uvicorn re-raises the original SIGTERM after graceful cleanup on POSIX.
                assert process.wait(timeout=5) in {0, -signal.SIGTERM}, (
                    output.read_text()
                )
                assert "Application shutdown complete" in output.read_text()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
