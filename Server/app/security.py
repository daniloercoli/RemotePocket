from __future__ import annotations

import hashlib
import secrets
import string
from datetime import UTC, timedelta
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
import jwt

from app.config import Settings
from app.timeutils import utc_now

_password_hasher = PasswordHasher()
# Match the cost of a real credential check when the account does not exist.
# Generate once per process; this value can never authenticate an account.
_dummy_password_hash = _password_hasher.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        verified = _password_hasher.verify(password_hash or _dummy_password_hash, password)
        return bool(password_hash) and verified
    except (VerificationError, InvalidHashError):
        return False


def hash_secret(secret: str) -> str:
    # Per token/codici casuali basta un digest non reversibile.
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(16)}"


def generate_device_token() -> str:
    return secrets.token_urlsafe(48)


def generate_pairing_code() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(8))


def create_access_token(
    user_id: str,
    settings: Settings,
    session_id: str,
) -> str:
    """Create a JWT access token using the standard JWT library."""
    now = utc_now().replace(tzinfo=UTC)
    expires_at = now + timedelta(minutes=settings.access_token_ttl_minutes)
    payload = {
        "sub": user_id,
        "exp": int(expires_at.timestamp()),
        "iat": int(now.timestamp()),
        "type": "access",
        "sid": session_id,
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def create_refresh_token() -> str:
    """Create an opaque refresh token."""
    return secrets.token_urlsafe(64)


def verify_access_token(token: str, settings: Settings) -> dict[str, Any] | None:
    """Verify a JWT access token and return payload if valid."""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"],
            options={"require": ["sub", "sid", "exp", "iat"]},
        )
        if payload.get("type") != "access":
            return None
        return payload
    except jwt.PyJWTError:
        return None
