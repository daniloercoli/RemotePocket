"""Production entry point: start draining before Uvicorn closes live connections."""

import time

import uvicorn

from app.main import app


class MyDeskServer(uvicorn.Server):
    async def shutdown(self, sockets=None):
        started = time.monotonic()
        await app.state.shutdown_handler.initiate_shutdown(app)
        self.config.timeout_graceful_shutdown = max(
            0,
            app.state.settings.shutdown_timeout_seconds - (time.monotonic() - started),
        )
        await super().shutdown(sockets=sockets)


def main():
    settings = app.state.settings
    config = uvicorn.Config(
        app,
        # Container listener; production publishes only the nginx ports.
        host="0.0.0.0",  # nosec B104
        port=8000,
        workers=1,
        proxy_headers=True,
        ws_max_size=5_000_000,
        access_log=False,
        log_config=None,
        timeout_graceful_shutdown=settings.shutdown_timeout_seconds,
    )
    MyDeskServer(config).run()


if __name__ == "__main__":
    main()
