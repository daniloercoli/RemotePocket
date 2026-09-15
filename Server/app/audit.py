from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog
from app.security import generate_id


def write_audit(
    db: Session,
    event_type: str,
    *,
    owner_id: str | None = None,
    device_id: str | None = None,
    session_id: str | None = None,
    payload: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    username: str | None = None,
    **kwargs: Any,
) -> None:
    """Write an audit log entry.

    Additional keyword arguments are stored in the event_payload_json.
    """
    # Build payload from additional kwargs
    event_payload = payload or {}
    event_payload.update(kwargs)
    if username:
        event_payload["username"] = username

    db.add(
        AuditLog(
            id=generate_id("audit"),
            owner_id=owner_id,
            device_id=device_id,
            session_id=session_id,
            event_type=event_type,
            event_payload_json=event_payload if event_payload else None,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    )

