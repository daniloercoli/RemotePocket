from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    # SQLite restituisce datetime senza timezone: manteniamo UTC ma senza tzinfo.
    return datetime.now(UTC).replace(tzinfo=None)


def naive_utc(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value


def iso_utc(value: datetime | None) -> str | None:
    return naive_utc(value).isoformat() + "Z" if value else None
