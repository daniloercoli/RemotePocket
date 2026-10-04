from __future__ import annotations

from typing import Annotated
import secrets
from datetime import UTC, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select, update
from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Literal
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.dependencies import get_current_user, get_db
from app.models import Device, RemoteSession, User
from app.timeutils import utc_now, iso_utc
from app.rate_limiting import rate_limit
from app.rate_limiting import enforce_limit
from app.security import hash_secret
from app.account_service import encrypt, decrypt
from app.wake_protocol import new_key, sign_message, WAKE_TTL_SECONDS

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
        "connection_mode": device.connection_mode,
        "wake_configured": bool(device.wake_key_encrypted),
    }


async def publish_device(request, device):
    manager = request.app.state.ws_manager
    message = {"type": "device_changed", "device": serialize_device(device)}
    for connection in list(manager.console_connections.values()):
        if connection.owner_id == device.owner_id and connection.watch_devices:
            await manager.send_to_console(connection.connection_id, message)


class AgentConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    connection_mode: Literal["persistent", "on_demand"]


@router.put(
    "/{device_id}/agent-configuration",
    dependencies=[rate_limit("agent-config-ip", 30, 60)],
)
async def configure_agent(
    device_id: str,
    payload: AgentConfiguration,
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
):
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    device = db.get(Device, device_id)
    if (
        device is None
        or device.revoked_at is not None
        or scheme.lower() != "bearer"
        or not secrets.compare_digest(device.token_hash, hash_secret(token))
    ):
        raise HTTPException(401, "Token dispositivo non valido")
    enforce_limit(request.app, "agent-config-device", device.id, 10, 60)
    settings = request.app.state.settings
    if not settings.encryption_key:
        raise HTTPException(503, "Configurare MYDESK_ENCRYPTION_KEY per l’attivazione")
    # Concurrent first provisioning must return the same key to every caller.
    if device.wake_key_encrypted is None:
        db.execute(
            update(Device)
            .where(Device.id == device.id, Device.wake_key_encrypted.is_(None))
            .values(wake_key_encrypted=encrypt(settings, new_key()))
        )
        db.refresh(device)
    device.connection_mode = payload.connection_mode
    key = decrypt(settings, device.wake_key_encrypted)
    write_audit(
        db,
        "agent_configured",
        owner_id=device.owner_id,
        device_id=device.id,
        payload={"connection_mode": device.connection_mode},
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    await publish_device(request, device)
    return {
        "connection_mode": device.connection_mode,
        "wake_key": key,
        "wake_protocol": "RPW1",
    }


@router.post(
    "/{device_id}/wake-message",
    dependencies=[rate_limit("wake-message", 10, 60, per_user=True)],
)
def create_wake_message(
    device_id: str,
    request: Request,
    response: Response,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    device = db.get(Device, device_id)
    if device is None or device.owner_id != user.id or device.revoked_at is not None:
        raise HTTPException(404, "Device non trovato")
    if not device.wake_key_encrypted:
        raise HTTPException(409, "Configurare l’attivazione nell’app Android")
    if not request.app.state.settings.encryption_key:
        raise HTTPException(503, "Cifratura attivazione non configurata")
    enforce_limit(request.app, "wake-message-device", device.id, 3, 60)
    expires = (utc_now() + timedelta(seconds=WAKE_TTL_SECONDS)).replace(microsecond=0)
    message = sign_message(
        device.id,
        int(expires.replace(tzinfo=UTC).timestamp()),
        decrypt(request.app.state.settings, device.wake_key_encrypted),
    )
    write_audit(db, "wake_message_created", owner_id=user.id, device_id=device.id)
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return {"message": message, "expires_at": iso_utc(expires)}


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
    await publish_device(request, device)

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
