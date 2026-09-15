from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.dependencies import get_current_user, get_db
from app.models import Device, PairingCode, User
from app.security import (
    generate_device_token,
    generate_id,
    generate_pairing_code,
    hash_password,
    hash_secret,
)
from app.timeutils import utc_now
from app.rate_limiting import rate_limit

router = APIRouter(prefix="/api", tags=["pairing"])


class PairDeviceRequest(BaseModel):
    pairing_code: str = Field(min_length=8, max_length=8, pattern=r"^[A-Za-z0-9]{8}$")
    name: str = Field(min_length=1, max_length=200)
    device_password: str = Field(min_length=8, max_length=200)

    @field_validator("name")
    @classmethod
    def trim_name(cls, value):
        value = value.strip()
        if not value:
            raise ValueError("Device name cannot be blank")
        return value


@router.post(
    "/pairing-codes",
    dependencies=[rate_limit("pairing-codes", 10, 3600, per_user=True)],
)
def create_pairing_code(
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    code = generate_pairing_code()
    expires_at = utc_now() + timedelta(
        minutes=request.app.state.settings.pairing_code_ttl_minutes
    )

    pairing = PairingCode(
        id=generate_id("pair"),
        owner_id=user.id,
        code_hash=hash_secret(code),
        expires_at=expires_at,
    )
    db.add(pairing)
    write_audit(
        db, "pairing_code_created", owner_id=user.id, payload={"pairing_id": pairing.id}
    )
    db.commit()

    return {
        "pairing_id": pairing.id,
        "code": code,
        "expires_at": expires_at.isoformat() + "Z",
    }


@router.post("/devices/pair", dependencies=[rate_limit("pair-device", 10, 3600)])
def pair_device(payload: PairDeviceRequest, db: Annotated[Session, Depends(get_db)]):
    now = utc_now()
    code_hash = hash_secret(payload.pairing_code.strip().upper())
    pairing = db.scalar(
        select(PairingCode)
        .where(PairingCode.code_hash == code_hash)
        .where(PairingCode.used_at.is_(None))
        .where(PairingCode.expires_at > now)
    )
    if pairing is None:
        raise HTTPException(status_code=400, detail="Pairing code non valido o scaduto")

    device_token = generate_device_token()
    device = Device(
        id=generate_id("dev"),
        owner_id=pairing.owner_id,
        name=payload.name,
        token_hash=hash_secret(device_token),
        access_password_hash=hash_password(payload.device_password),
        status="offline",
    )

    claimed = db.execute(
        update(PairingCode)
        .where(
            PairingCode.id == pairing.id,
            PairingCode.used_at.is_(None),
            PairingCode.expires_at > utc_now(),
        )
        .values(used_at=now, created_device_id=device.id)
        .execution_options(synchronize_session=False)
    )
    if claimed.rowcount != 1:
        raise HTTPException(status_code=400, detail="Pairing code non valido o scaduto")
    db.add(device)
    write_audit(
        db,
        "device_registered",
        owner_id=device.owner_id,
        device_id=device.id,
        payload={"device_name": device.name},
    )
    db.commit()

    return {
        "device_id": device.id,
        "device_token": device_token,
        "device_name": device.name,
    }
