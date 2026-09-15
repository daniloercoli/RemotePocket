"""Bound WebSocket work before database lookups; streaming budgets stay local."""

import time
from collections import deque

from fastapi import HTTPException

from app.rate_limiting import enforce_limit


async def reject_connection(websocket, code, reason=""):
    # Keep the negotiated browser protocol so the client can read the close code.
    await websocket.accept(
        subprotocol="mydesk"
        if "mydesk" in websocket.scope.get("subprotocols", [])
        else None
    )
    await websocket.close(code=code, reason=reason)


async def allow_upgrade(websocket):
    settings = websocket.app.state.settings
    try:
        enforce_limit(
            websocket.app,
            "ws-upgrade",
            websocket.client.host if websocket.client else "unknown",
            settings.rate_limit_ws_upgrade,
            60,
        )
        return True
    except HTTPException as error:
        # Convey a retryable close code; pre-accept 403 means revoked credentials to Android.
        await reject_connection(websocket, 4429 if error.status_code == 429 else 1013)
        return False


async def allow_control(websocket, scope, owner_id):
    try:
        enforce_limit(
            websocket.app,
            scope,
            owner_id,
            websocket.app.state.settings.rate_limit_ws_control,
            60,
        )
        return True
    except HTTPException as error:
        await websocket.close(code=4429 if error.status_code == 429 else 1013)
        return False


class FrameBudget:
    """A rolling second of frames and bytes; no Redis calls per screenshot."""

    def __init__(self, settings):
        self.frames = deque()
        self.bytes = 0
        self.max_frames = settings.max_screen_frames_per_second
        self.max_bytes = settings.max_screen_bytes_per_second

    def accept(self, size):
        now = time.monotonic()
        while self.frames and self.frames[0][0] <= now - 1:
            self.bytes -= self.frames.popleft()[1]
        if (
            size > 5_000_000
            or len(self.frames) >= self.max_frames
            or self.bytes + size > self.max_bytes
        ):
            return False
        self.frames.append((now, size))
        self.bytes += size
        return True
