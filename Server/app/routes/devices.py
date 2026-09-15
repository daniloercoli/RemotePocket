from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, update
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.dependencies import get_current_user, get_db
from app.models import Device, RemoteSession, User
from app.timeutils import utc_now, iso_utc
from app.rate_limiting import rate_limit

router = APIRouter(prefix="/api/devices", tags=["devices"])


def serialize_device(device: Device) -> dict:
    return {
        "id": device.id,
        "name": device.name,
        "status": device.status,
        "capabilities": device.capabilities_json or {},
        "created_at": iso_utc(device.created_at),
        "last_seen_at": iso_utc(device.last_seen_at),
        "revoked_at": iso_utc(device.revoked_at),
    }


@router.get("", dependencies=[rate_limit("devices", 30, 60, per_user=True)])
def list_devices(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    devices = db.scalars(
        select(Device).where(Device.owner_id == user.id).order_by(Device.created_at)
    ).all()
    return {"devices": [serialize_device(device) for device in devices]}


@router.post(
    "/{device_id}/revoke",
    dependencies=[rate_limit("revoke-device", 10, 3600, per_user=True)],
)
async def revoke_device(
    device_id: str,
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    device = db.get(Device, device_id)
    if device is None or device.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Device non trovato")

    claimed = db.execute(
        update(Device)
        .where(Device.id == device.id, Device.revoked_at.is_(None))
        .values(revoked_at=utc_now(), status="revoked")
    )
    if claimed.rowcount != 1:
        db.refresh(device)
        return {"device": serialize_device(device)}
    now = utc_now()
    device.revoked_at = now
    device.status = "revoked"

    active_sessions = db.scalars(
        select(RemoteSession)
        .where(RemoteSession.device_id == device.id)
        .where(RemoteSession.status == "in_session")
    ).all()
    for session in active_sessions:
        session.status = "ended"
        session.ended_at = now
        session.end_reason = "device_revoked"

    write_audit(db, "device_revoked", owner_id=user.id, device_id=device.id)
    db.commit()

    manager = request.app.state.ws_manager
    for session in active_sessions:
        manager.unbind_session(session.id)
    for session in active_sessions:
        await manager.send_to_console(
            session.console_connection_id,
            {
                "type": "session_end",
                "sessionId": session.id,
                "reason": "device_revoked",
            },
        )
    await manager.disconnect_device_if_present(device.id, code=4003)

    return {"device": serialize_device(device)}


class RenameDevice(BaseModel):
    name: str = Field(min_length=1, max_length=200)

    @field_validator("name", mode="before")
    @classmethod
    def clean(cls, value):
        return value.strip() if isinstance(value, str) else value


@router.patch(
    "/{device_id}", dependencies=[rate_limit("rename-device", 30, 60, per_user=True)]
)
def rename_device(
    device_id: str,
    payload: RenameDevice,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    device = db.scalar(
        select(Device).where(Device.id == device_id, Device.owner_id == user.id)
    )
    if device is None:
        raise HTTPException(404, "Device non trovato")
    device.name = payload.name
    write_audit(
        db,
        "device_renamed",
        owner_id=user.id,
        device_id=device.id,
        payload={"name": device.name},
    )
    db.commit()
    return {"device": serialize_device(device)}
