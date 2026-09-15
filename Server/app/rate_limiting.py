"""App-scoped limits storage shared by HTTP and WebSocket authentication paths."""

import hashlib
import hmac
import math
import time
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Response
from limits import RateLimitItemPerSecond

from app.dependencies import get_current_user
from app.models import User


def enforce_limit(app, scope, key, amount, seconds):
    if not app.state.settings.rate_limit_enabled:
        return {}
    item = RateLimitItemPerSecond(amount, seconds)
    limiter = app.state.rate_limiter
    try:
        accepted = limiter.hit(item, scope, key)
        reset, remaining = limiter.get_window_stats(item, scope, key)
    except Exception as error:
        raise HTTPException(503, "Rate limit service unavailable") from error
    headers = {
        "X-RateLimit-Limit": str(amount),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(math.ceil(reset)),
    }
    if not accepted:
        headers["Retry-After"] = str(max(1, math.ceil(reset - time.time())))
        raise HTTPException(429, "Rate limit exceeded", headers=headers)
    return headers


def recipient_limit(request, email, scope, owner=""):
    settings = request.app.state.settings
    key = hmac.new(
        settings.secret_key.encode(), email.encode(), hashlib.sha256
    ).hexdigest()
    if owner:
        enforce_limit(request.app, scope + "-owner", owner, 3, 3600)
        enforce_limit(request.app, scope + "-interval", key, 1, 60)
    # The recipient budget must be shared across owners and issuance endpoints.
    headers = enforce_limit(request.app, scope, key, 3, 3600)
    request.state.rate_limit_headers = headers


def rate_limit(scope, amount, seconds, *, per_user=False):
    def apply(request, response, key):
        settings = request.app.state.settings
        count = getattr(settings, amount) if isinstance(amount, str) else amount
        window = getattr(settings, seconds) if isinstance(seconds, str) else seconds
        headers = enforce_limit(request.app, scope, key, count, window)
        request.state.rate_limit_headers = headers
        response.headers.update(headers)

    if per_user:

        def dependency(
            request: Request,
            response: Response,
            user: Annotated[User, Depends(get_current_user)],
        ):
            apply(request, response, user.id)
    else:

        def dependency(request: Request, response: Response):
            apply(
                request, response, request.client.host if request.client else "unknown"
            )

    return Depends(dependency)
