"""Owner-only activity API with stable descending keyset pagination."""

import base64
import json
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, and_, cast, func, or_, select
from sqlalchemy.orm import Session

from app.dependencies import get_current_user, get_db
from app.models import AuditLog, Device, RemoteSession, User
from app.rate_limiting import rate_limit
from app.timeutils import iso_utc, naive_utc, utc_now

router = APIRouter(
    prefix="/api/activity",
    tags=["activity"],
    dependencies=[rate_limit("activity", 30, 60, per_user=True)],
)
DB = Annotated[Session, Depends(get_db)]
Owner = Annotated[User, Depends(get_current_user)]
# Unknown event payloads are deliberately empty.
SAFE_FIELDS = {
    "session_closed": {"reason"},
    "session_ended": {"reason"},
    "session_failed": {"reason"},
    "device_renamed": {"name"},
    "session_error": {"code"},
    "device_local_stop": {"reason"},
}


def filters(user, start, end, event_type, device_id):
    end = naive_utc(end) if end else utc_now()
    start = naive_utc(start) if start else end - timedelta(days=7)
    if end <= start or end - start > timedelta(days=90):
        raise HTTPException(400, "Intervallo non valido: massimo 90 giorni")
    conditions = [
        AuditLog.owner_id == user.id,
        AuditLog.created_at >= start,
        AuditLog.created_at <= end,
    ]
    if event_type:
        conditions.append(AuditLog.event_type == event_type)
    if device_id:
        conditions.append(AuditLog.device_id == device_id)
    return conditions


@router.get("")
def activity(
    db: DB,
    user: Owner,
    start: datetime | None = None,
    end: datetime | None = None,
    event_type: str | None = Query(None, max_length=120),
    device_id: str | None = Query(None, max_length=64),
    cursor: str | None = Query(None, max_length=512),
    limit: int = Query(50, ge=1, le=100),
):
    conditions = filters(user, start, end, event_type, device_id)
    if cursor:
        try:
            stamp, identifier = json.loads(base64.urlsafe_b64decode(cursor).decode())
            stamp = naive_utc(datetime.fromisoformat(stamp))
            if not isinstance(identifier, str) or len(identifier) > 64:
                raise ValueError()
        except Exception:
            raise HTTPException(400, "Cursore non valido") from None
        column = AuditLog.created_at
        if db.bind.dialect.name == "sqlite":
            # SQLite CURRENT_TIMESTAMP has no fraction; normalize without losing microseconds.
            column = func.substr(cast(column, String) + ".000000", 1, 26)
            stamp = stamp.strftime("%Y-%m-%d %H:%M:%S.%f")
        conditions.append(
            or_(
                column < stamp,
                and_(column == stamp, AuditLog.id < identifier),
            )
        )
    rows = db.scalars(
        select(AuditLog)
        .where(*conditions)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(limit + 1)
    ).all()
    more = len(rows) > limit
    rows = rows[:limit]
    return {
        "events": [
            {
                "id": row.id,
                "created_at": iso_utc(row.created_at),
                "event_type": row.event_type,
                "device_id": row.device_id,
                "session_id": row.session_id,
                "details": {
                    key: value
                    for key, value in (row.event_payload_json or {}).items()
                    if key in SAFE_FIELDS.get(row.event_type, set())
                },
            }
            for row in rows
        ],
        "next_cursor": base64.urlsafe_b64encode(
            json.dumps([iso_utc(rows[-1].created_at), rows[-1].id]).encode()
        ).decode()
        if more
        else None,
    }


@router.get("/summary")
def summary(
    db: DB,
    user: Owner,
    start: datetime | None = None,
    end: datetime | None = None,
    event_type: str | None = Query(None, max_length=120),
    device_id: str | None = Query(None, max_length=64),
):
    conditions = filters(user, start, end, event_type, device_id)

    def count(model, *where):
        if device_id and model is Device:
            where = (*where, Device.id == device_id)
        elif device_id and model is RemoteSession:
            where = (*where, RemoteSession.device_id == device_id)
        return db.scalar(select(func.count()).select_from(model).where(*where))

    return {
        "devices": count(
            Device, Device.owner_id == user.id, Device.revoked_at.is_(None)
        ),
        "connected_devices": count(
            Device,
            Device.owner_id == user.id,
            Device.revoked_at.is_(None),
            Device.status.in_(["online", "in_session"]),
        ),
        "active_sessions": count(
            RemoteSession,
            RemoteSession.owner_id == user.id,
            RemoteSession.status == "in_session",
        ),
        "sessions_started": count(
            AuditLog, *conditions, AuditLog.event_type == "session_opened"
        ),
        "authentication_failures": count(
            AuditLog,
            *conditions,
            AuditLog.event_type.in_(
                [
                    "login_failed",
                    "login_blocked",
                    "mfa_failed",
                    "account_confirmation_failed",
                ]
            ),
        ),
    }
