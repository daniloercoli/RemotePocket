"""RPW1: the same short, authenticated wake command over SMS and Telegram."""

import base64
import hashlib
import hmac
import re
import secrets

WAKE_TTL_SECONDS = 600
COMMAND = re.compile(
    r"RPW1 (dev_[A-Za-z0-9_-]{22}) ([0-9]{10}) ([A-Za-z0-9_-]{22}) ([A-Za-z0-9_-]{43})",
    re.ASCII,
)


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def new_key() -> str:
    return encode(secrets.token_bytes(32))


def sign_message(
    device_id: str, expires_at: int, key: str, nonce: str | None = None
) -> str:
    payload = (
        f"RPW1 {device_id} {expires_at} {nonce or encode(secrets.token_bytes(16))}"
    )
    signature = encode(
        hmac.digest(
            base64.urlsafe_b64decode(key + "="), payload.encode("ascii"), hashlib.sha256
        )
    )
    message = f"{payload} {signature}"
    if not COMMAND.fullmatch(message) or len(message) > 160:
        raise ValueError("Invalid wake command")
    return message


def verify_message(message: str, device_id: str, key: str, now: int) -> bool:
    match = COMMAND.fullmatch(message.strip())
    if (
        not match
        or match[1] != device_id
        or not now < int(match[2]) <= now + WAKE_TTL_SECONDS + 60
    ):
        return False
    expected = sign_message(device_id, int(match[2]), key, match[3])
    return hmac.compare_digest(expected, message.strip())
