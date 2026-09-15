"""Bounded probes using the application's actual database and limits storage."""

import asyncio
import shutil
import time
from dataclasses import asdict, dataclass
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from datetime import datetime, timezone

from sqlalchemy import text


@dataclass
class HealthCheckResult:
    name: str
    status: str
    duration_ms: float
    details: dict | None = None
    error: str | None = None

    def to_dict(self):
        return asdict(self)


@dataclass
class HealthStatus:
    status: str
    checked_at: str
    duration_ms: float
    checks: list[HealthCheckResult]

    def to_dict(self):
        return asdict(self)


def database_available(engine):
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return True


def disk_available():
    return shutil.disk_usage("/").free >= 1024**3


class HealthChecker:
    """Share in-flight probes instead of accumulating work after a timeout."""

    def __init__(self):
        self.executor = ThreadPoolExecutor(
            max_workers=3, thread_name_prefix="mydesk-health"
        )
        self.pending = {}
        self.lock = Lock()

    async def probe(self, name, function, timeout):
        start = time.monotonic()
        try:
            with self.lock:
                future = self.pending.get(name)
                if future is None or future.done():
                    future = self.executor.submit(function)
                    self.pending[name] = future
            wrapped = asyncio.wrap_future(future)
            # Retrieve late failures even after a caller timed out, so asyncio
            # never logs an unobserved exception containing driver parameters.
            wrapped.add_done_callback(
                lambda done: None if done.cancelled() else done.exception()
            )
            healthy = await asyncio.wait_for(asyncio.shield(wrapped), timeout)
            return HealthCheckResult(
                name,
                "healthy" if healthy else "unhealthy",
                (time.monotonic() - start) * 1000,
            )
        except Exception as error:
            return HealthCheckResult(
                name,
                "unhealthy",
                (time.monotonic() - start) * 1000,
                error=type(error).__name__,
            )

    def close(self):
        self.executor.shutdown(wait=False, cancel_futures=True)


async def run_health_check(app, *, advanced=False) -> HealthStatus:
    start = time.monotonic()
    timeout = app.state.settings.health_check_timeout_seconds
    checker = app.state.health_checker
    checks = await asyncio.gather(
        checker.probe(
            "database", lambda: database_available(app.state.db_engine), timeout
        ),
        checker.probe(
            "rate_limit_storage", app.state.rate_limiter.storage.check, timeout
        ),
    )
    if advanced:
        checks.append(await checker.probe("disk_space", disk_available, timeout))
    handler = app.state.shutdown_handler
    checks.append(
        HealthCheckResult(
            "accepting_connections",
            "unhealthy" if handler.is_shutdown_initiated else "healthy",
            0,
        )
    )
    relay = app.state.ws_manager.relay
    if relay is not None:
        checks.append(
            HealthCheckResult(
                "websocket_relay", "healthy" if relay.healthy else "unhealthy", 0
            )
        )
    healthy = all(check.status == "healthy" for check in checks)
    if app.state.metrics.enabled:
        app.state.metrics.ready.set(int(healthy))
    return HealthStatus(
        "healthy" if healthy else "unhealthy",
        datetime.now(timezone.utc).isoformat(),
        (time.monotonic() - start) * 1000,
        list(checks),
    )


async def check_readiness(app):
    return await run_health_check(app)
