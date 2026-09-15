"""ASGI request context, access logs and metrics, including failures and WebSockets."""

import logging
import re
import time

from starlette.datastructures import Headers, MutableHeaders
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.correlation import generate_request_id, reset_request_id, set_request_id
from app.error_handlers import handle_error

logger = logging.getLogger(__name__)
REQUEST_ID = re.compile(r"[a-zA-Z0-9._-]{1,128}\Z")


def endpoint_name(scope):
    route = scope.get("route")
    return getattr(route, "path", None) or (
        "/static/*" if scope.get("path", "").startswith("/static/") else "/unmatched"
    )


class ObservabilityMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            return await self.app(scope, receive, send)
        state = scope["app"].state
        headers = Headers(scope=scope)
        supplied_id = headers.get("x-request-id", "")
        request_id = (
            supplied_id if REQUEST_ID.fullmatch(supplied_id) else generate_request_id()
        )
        token = set_request_id(request_id)
        metrics = state.metrics
        shutdown = state.shutdown_handler
        is_http = scope["type"] == "http"
        started = time.monotonic()
        status = 500
        response_started = False
        accepted = False
        pending_message = None
        connection_type = "device" if scope["path"] == "/device/ws" else "console"
        if is_http:
            shutdown.active_requests += 1

        def finish_message():
            nonlocal pending_message
            if pending_message is not None:
                kind, timestamp = pending_message
                if metrics.enabled:
                    metrics.websocket_duration.labels(kind).observe(
                        time.monotonic() - timestamp
                    )
                pending_message = None

        async def observed_receive():
            nonlocal pending_message, status
            finish_message()
            message = await receive()
            if message["type"] == "websocket.receive":
                pending_message = (
                    "binary" if message.get("bytes") is not None else "control",
                    time.monotonic(),
                )
            elif message["type"] == "websocket.disconnect":
                status = message.get("code", 1000)
            return message

        async def observed_send(message):
            nonlocal status, response_started, accepted
            if message["type"] in {"http.response.start", "websocket.accept"}:
                response_headers = MutableHeaders(scope=message)
                response_headers["X-Request-ID"] = request_id
                if is_http:
                    response_started = True
                    status = message["status"]
                    for key, value in (
                        scope.get("state", {}).get("rate_limit_headers", {}).items()
                    ):
                        response_headers[key] = value
                    response_headers["X-Content-Type-Options"] = "nosniff"
                    response_headers["X-Frame-Options"] = "DENY"
                    response_headers["Referrer-Policy"] = "no-referrer"
                    response_headers["Content-Security-Policy"] = (
                        state.settings.content_security_policy
                    )
                    response_headers["Cache-Control"] = "no-store"
                    if scope.get("scheme") == "https":
                        response_headers["Strict-Transport-Security"] = (
                            f"max-age={state.settings.strict_transport_security_max_age}; includeSubDomains"
                        )
                    if status == 401:
                        metrics.record_auth_failure("http")
                else:
                    accepted, status = True, 1000
            elif message["type"] == "websocket.close":
                status = message.get("code", 1000)
                if status == 4401:
                    metrics.record_auth_failure(connection_type)
            await send(message)

        try:
            if shutdown.is_shutdown_initiated and scope["path"] not in {
                "/api/health",
                "/api/health/ready",
                "/api/health/advanced",
                "/metrics",
            }:
                if is_http:
                    await JSONResponse(
                        {"detail": "Server shutting down", "request_id": request_id},
                        status_code=503,
                    )(scope, receive, observed_send)
                else:
                    await observed_send({"type": "websocket.close", "code": 1012})
                return
            try:
                await self.app(scope, observed_receive, observed_send)
            except Exception as error:
                # Do not log str(error), SQL parameters, request headers or payloads.
                logger.error(
                    "Request failed",
                    extra={"extra_fields": {"error_type": type(error).__name__}},
                )
                if is_http and not response_started:
                    response = await handle_error(Request(scope), error)
                    origin = headers.get("origin")
                    if origin in state.settings.allowed_origins_list:
                        response.headers["Access-Control-Allow-Origin"] = origin
                        response.headers["Access-Control-Allow-Credentials"] = "true"
                        response.headers["Vary"] = "Origin"
                    await response(scope, receive, observed_send)
                elif not is_http:
                    await observed_send({"type": "websocket.close", "code": 1011})
                else:
                    raise
        finally:
            duration = time.monotonic() - started
            endpoint = endpoint_name(scope)
            if is_http:
                shutdown.active_requests -= 1
                metrics.record_request(scope["method"], endpoint, status, duration)
            else:
                finish_message()
                if accepted and metrics.enabled:
                    metrics.websocket_disconnects.labels(connection_type).inc()
            logger.info(
                "HTTP request completed"
                if is_http
                else "WebSocket connection completed",
                extra={
                    "endpoint": endpoint,
                    "method": scope.get("method", "WEBSOCKET"),
                    "duration": duration * 1000,
                    "status": status,
                },
            )
            reset_request_id(token)
