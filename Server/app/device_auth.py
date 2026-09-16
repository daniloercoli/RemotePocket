"""Device proofs using the SCRAM-SHA-256 construction (RFC 5802/7677).

The application exchanges structured WebSocket messages, not SASL frames.
Passwords retain their literal UTF-8 encoding, without SASLprep normalization.
Only salt, iterations, StoredKey and ServerKey are persisted.
"""

import base64
from dataclasses import dataclass
import hashlib
import hmac
import secrets
import time

ITERATIONS = 600_000
CHALLENGE_TTL_SECONDS = 60


def encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def credentials(password: str) -> dict:
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    client_key = hmac.digest(salted, b"Client Key", "sha256")
    return {
        "access_auth_salt": encode(salt),
        "access_auth_iterations": ITERATIONS,
        "access_auth_stored_key": encode(hashlib.sha256(client_key).digest()),
        "access_auth_server_key": encode(hmac.digest(salted, b"Server Key", "sha256")),
    }


def auth_message(device_id, client_nonce, nonce, salt, iterations) -> bytes:
    # SCRAM's username escaping keeps the transcript unambiguous.
    name = device_id.replace("=", "=3D").replace(",", "=2C")
    return (
        f"n={name},r={client_nonce},r={nonce},s={salt},i={iterations},c=biws,r={nonce}"
    ).encode("utf-8")


def verify_proof(
    stored_key: str, server_key: str, transcript: bytes, proof: str
) -> str | None:
    try:
        stored = base64.b64decode(stored_key, validate=True)
        server = base64.b64decode(server_key, validate=True)
        supplied = base64.b64decode(proof, validate=True)
        if not all(len(value) == 32 for value in (stored, server, supplied)):
            return None
    except ValueError:
        return None
    signature = hmac.digest(stored, transcript, "sha256")
    client_key = bytes(a ^ b for a, b in zip(supplied, signature))
    if not hmac.compare_digest(hashlib.sha256(client_key).digest(), stored):
        return None
    return encode(hmac.digest(server, transcript, "sha256"))


@dataclass(frozen=True)
class Challenge:
    id: str
    device_id: str
    client_nonce: str
    nonce: str
    salt: str
    iterations: int
    expires_at: float

    @property
    def transcript(self):
        return auth_message(
            self.device_id, self.client_nonce, self.nonce, self.salt, self.iterations
        )

    def response(self):
        return {
            "type": "session_challenge",
            "deviceId": self.device_id,
            "challengeId": self.id,
            "clientNonce": self.client_nonce,
            "nonce": self.nonce,
            "salt": self.salt,
            "iterations": self.iterations,
            "expiresIn": CHALLENGE_TTL_SECONDS,
        }


class DeviceChallenges:
    """Owned by one authenticated console connection; never shared or persisted."""

    def __init__(self, limit):
        self.limit = limit
        self.pending: dict[str, Challenge] = {}

    def issue(self, device, client_nonce):
        now = time.monotonic()
        self.pending = {
            key: value for key, value in self.pending.items() if value.expires_at > now
        }
        if device.id not in self.pending and len(self.pending) >= self.limit:
            return None
        challenge = Challenge(
            secrets.token_urlsafe(32),
            device.id,
            client_nonce,
            client_nonce + secrets.token_hex(32),
            device.access_auth_salt,
            device.access_auth_iterations,
            now + CHALLENGE_TTL_SECONDS,
        )
        self.pending[device.id] = challenge
        return challenge

    def consume(self, device_id, challenge_id):
        # Consume before validation, with no await: even a failed guess is single-use.
        challenge = self.pending.pop(device_id, None)
        if (
            challenge
            and challenge.id == challenge_id
            and challenge.expires_at > time.monotonic()
        ):
            return challenge
        return None
