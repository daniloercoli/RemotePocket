"""Application factory with isolated database, monitoring and rate-limit state."""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from limits.storage import storage_from_string
from limits.strategies import FixedWindowRateLimiter
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import update
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

from app.config import get_settings, Settings
from app.database import create_db_engine, create_session_factory, init_db
from app.dependencies import require_monitoring_access
from app.email_outbox import EmailOutbox
from app.error_handlers import setup_error_handlers
from app.health_checks import HealthChecker, run_health_check
from app.logging_config import setup_logging
from app.metrics import Metrics
from app.models import Device, RemoteSession
from app.observability import ObservabilityMiddleware
from app.routes import activity, account, auth, console, devices, pairing, websocket
from app.shutdown import GracefulShutdownHandler, ShutdownConfig
from app.timeutils import utc_now
from app.tracing import instrument, setup_tracing
from app.websocket_manager import WebSocketManager


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    setup_logging(settings.environment, settings.log_level)
    engine = create_db_engine(
        settings.database_url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_recycle=settings.database_pool_recycle_seconds,
    )
    init_db(engine)
    storage = storage_from_string(
        "memory://" if settings.is_dev else settings.redis_url,
        **(
            {}
            if settings.is_dev
            else {"socket_connect_timeout": 2, "socket_timeout": 2}
        ),
    )
    metrics = Metrics(settings.metrics_enabled)
    manager = WebSocketManager(
        metrics=metrics,
        max_console_connections=settings.max_console_connections,
        max_connections=settings.max_websocket_connections,
    )
    shutdown = GracefulShutdownHandler(
        ShutdownConfig(
            settings.shutdown_timeout_seconds, settings.websocket_drain_timeout_seconds
        )
    )
    provider = (
        setup_tracing(
            environment=settings.environment,
            otlp_endpoint=settings.tracing_endpoint or None,
            otlp_protocol=settings.tracing_protocol,
            otlp_insecure=settings.tracing_insecure,
        )
        if settings.tracing_enabled
        else None
    )

    lifespan_users = 0

    @asynccontextmanager
    async def lifespan(app):
        nonlocal lifespan_users
        # Nested TestClients share this app; only the outer lifespan owns resources.
        lifespan_users += 1
        if lifespan_users > 1:
            try:
                yield
            finally:
                lifespan_users -= 1
            return
        app.state.shutdown_handler = GracefulShutdownHandler(shutdown.config)
        app.state.health_checker = HealthChecker()
        try:
            # Deployment remains single-worker; no connection survives a process restart.
            with app.state.SessionLocal.begin() as db:
                db.execute(
                    update(Device)
                    .where(Device.revoked_at.is_(None))
                    .values(status="offline")
                )
                db.execute(
                    update(RemoteSession)
                    .where(RemoteSession.status == "in_session")
                    .values(
                        status="ended",
                        ended_at=utc_now(),
                        end_reason="server_restarted",
                    )
                )
            if settings.redis_relay_enabled:
                from app.websocket_relay import WebSocketRelay

                manager.relay = WebSocketRelay(settings.redis_url)
                await manager.relay.start(manager.handle_relay_message)
                manager.relay.broadcast({"type": "snapshot_request"})
            await app.state.email_outbox.start()
            yield
        finally:
            lifespan_users -= 1
            await app.state.shutdown_handler.initiate_shutdown(app)
            await app.state.email_outbox.close()
            if manager.relay is not None:
                await manager.relay.close()
            if provider is not None:
                await asyncio.to_thread(provider.shutdown)
            app.state.health_checker.close()
            engine.dispose()

    app = FastAPI(
        title="MyDesk Server",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs" if settings.debug else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.debug else None,
    )
    app.state.settings = settings
    app.state.db_engine = engine
    app.state.SessionLocal = create_session_factory(engine)
    app.state.email_outbox = EmailOutbox(app.state.SessionLocal, settings, metrics)
    app.state.ws_manager = manager
    app.state.metrics = metrics
    app.state.health_checker = HealthChecker()
    app.state.tracer_provider = provider
    app.state.shutdown_handler = shutdown
    app.state.rate_limiter = FixedWindowRateLimiter(storage)
    metrics.bind(
        manager, engine, settings.database_pool_size + settings.database_max_overflow
    )
    setup_error_handlers(app)

    if not settings.is_dev:
        app.add_middleware(HTTPSRedirectMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=[
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "Retry-After",
            "X-Request-ID",
        ],
        max_age=600,
    )
    app.add_middleware(ObservabilityMiddleware)
    app.mount(
        "/static",
        StaticFiles(directory=Path(__file__).parent / "static"),
        name="static",
    )
    for router in (
        auth.router,
        account.router,
        activity.router,
        pairing.router,
        devices.router,
        websocket.router,
        console.router,
    ):
        app.include_router(router)

    @app.get("/api/health")
    async def health():
        result = await run_health_check(app)
        healthy = result.status == "healthy"
        return JSONResponse(
            status_code=200 if healthy else 503,
            content={"status": "ok" if healthy else "unavailable"},
        )

    @app.get("/api/health/advanced", dependencies=[Depends(require_monitoring_access)])
    async def health_advanced():
        result = await run_health_check(app, advanced=True)
        return JSONResponse(
            status_code=200 if result.status == "healthy" else 503,
            content=result.to_dict(),
        )

    @app.get("/api/health/ready", dependencies=[Depends(require_monitoring_access)])
    async def health_ready():
        result = await run_health_check(app)
        return JSONResponse(
            status_code=200 if result.status == "healthy" else 503,
            content=result.to_dict(),
        )

    if settings.metrics_enabled:

        @app.get(
            "/metrics",
            include_in_schema=False,
            dependencies=[Depends(require_monitoring_access)],
        )
        def prometheus_metrics():
            return Response(
                generate_latest(metrics.registry),
                headers={"Content-Type": CONTENT_TYPE_LATEST},
            )

    if provider is not None:
        instrument(app, engine, provider)
    return app


app = create_app()
