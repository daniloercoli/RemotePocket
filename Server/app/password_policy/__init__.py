"""Password complexity, zxcvbn scoring, HIBP range checks and Argon2 history."""

import hashlib
import re

import httpx
from zxcvbn import zxcvbn
from zxcvbn.frequency_lists import FREQUENCY_LISTS

from app.config import Settings
from app.security import verify_password

COMMON_PASSWORDS = frozenset(FREQUENCY_LISTS["passwords"][:1000])


class BreachCheckUnavailable(RuntimeError):
    pass


def check_password_breach(password: str, timeout: float = 5.0) -> bool:
    # SHA-1 is required by HIBP's range protocol; never used for password storage.
    digest = (
        # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
        hashlib.sha1(password.encode("utf-8"), usedforsecurity=False)
        .hexdigest()
        .upper()
    )
    try:
        response = httpx.get(
            f"https://api.pwnedpasswords.com/range/{digest[:5]}",
            headers={"Add-Padding": "true"},
            timeout=timeout,
        )
        response.raise_for_status()
        lines = response.text.splitlines()
        if not lines:
            raise ValueError("Empty breach response")
        found = False
        for line in lines:
            suffix, count = line.strip().split(":")
            if not re.fullmatch(r"[0-9A-F]{35}", suffix) or not count.isdigit():
                raise ValueError("Invalid breach response")
            if suffix == digest[5:] and int(count) > 0:
                found = True
        return found
    except (httpx.HTTPError, ValueError) as error:
        raise BreachCheckUnavailable(
            "Password breach check unavailable; retry later"
        ) from error


def validate_password(
    password, password_history=None, check_breaches=None, *, settings=None
):
    settings = settings or Settings()
    errors = []
    if not settings.min_password_length <= len(password) <= 200:
        return False, [
            f"Password must be at least {settings.min_password_length} characters and at most 200 characters"
        ]
    requirements = (
        (settings.require_password_uppercase, r"[A-Z]", "uppercase letter"),
        (settings.require_password_lowercase, r"[a-z]", "lowercase letter"),
        (settings.require_password_number, r"[0-9]", "number"),
        (settings.require_password_special, r"[^\w\s]", "special character"),
    )
    for required, pattern, label in requirements:
        if required and not re.search(pattern, password):
            errors.append(f"Password must contain at least one {label}")
    if password.lower() in COMMON_PASSWORDS:
        errors.append("This is a commonly used password")
    if zxcvbn(password, max_length=200)["score"] < settings.min_password_strength:
        errors.append("Password is too weak; use a longer, unpredictable password")
    if any(
        verify_password(password, old)
        for old in (password_history or [])[: settings.password_history_count]
    ):
        errors.append(
            f"You cannot reuse your last {settings.password_history_count} passwords"
        )
    if not errors and (
        settings.check_password_breaches if check_breaches is None else check_breaches
    ):
        if check_password_breach(password):
            errors.append("This password has been compromised in a data breach")
    return not errors, errors
