import io
from typing import Annotated

import qrcode
import qrcode.image.svg
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.account_service import AccountService, normalize_email
from app.auth_service import AuthenticationError
from app.audit import write_audit
from app.dependencies import get_current_user, get_db
from app.email_outbox import enqueue, notification, queue_verification
from app.models import MfaChallenge, User
from app.rate_limiting import enforce_limit, rate_limit, recipient_limit
from app.security import hash_secret, verify_access_token

router = APIRouter(prefix="/api/auth", tags=["account"])
DB = Annotated[Session, Depends(get_db)]
Owner = Annotated[User, Depends(get_current_user)]


class EmailRequest(BaseModel):
    email: str = Field(max_length=255)

    @field_validator("email")
    @classmethod
    def normalize(cls, value):
        return normalize_email(value)


class Confirmation(BaseModel):
    password: str = Field(min_length=1, max_length=200)
    code: str | None = Field(default=None, max_length=6, pattern=r"^\d{6}$")
    recovery_code: str | None = Field(default=None, max_length=128)


class EmailChange(EmailRequest, Confirmation):
    pass


class TokenRequest(BaseModel):
    token: str = Field(min_length=1, max_length=200)


class FactorRequest(BaseModel):
    code: str | None = Field(default=None, max_length=6, pattern=r"^\d{6}$")
    recovery_code: str | None = Field(default=None, max_length=128)


class ChallengeRequest(FactorRequest):
    challenge_token: str = Field(min_length=1, max_length=200)


def session_id(request):
    token = request.headers["authorization"].split()[1]
    return verify_access_token(token, request.app.state.settings)["sid"]


def execute(db, operation):
    try:
        result = operation()
        db.commit()
        return result
    except AuthenticationError as error:
        db.commit()
        raise HTTPException(401, str(error)) from None
    except (ValueError, IntegrityError) as error:
        db.rollback()
        raise HTTPException(
            400,
            "Operazione non valida"
            if isinstance(error, IntegrityError)
            else str(error),
        ) from None


@router.get("/config")
def config(request: Request, db: DB):
    settings = request.app.state.settings
    return {
        "bootstrap_available": not bool(db.scalar(select(func.count(User.id)))),
        "email_available": settings.email_available,
        "totp_available": bool(settings.encryption_key),
    }


@router.post(
    "/password-reset-request",
    status_code=202,
    dependencies=[rate_limit("recovery", 3, 3600)],
)
def recovery(payload: EmailRequest, request: Request, db: DB):
    recipient_limit(request, payload.email, "recovery-recipient")
    enqueue(db, request.app.state.settings, "reset", {"email": payload.email})
    db.commit()
    return {"message": "Se l'indirizzo e' idoneo riceverai le istruzioni."}


@router.post("/email-change-request")
def change_email(payload: EmailChange, request: Request, db: DB, user: Owner):
    recipient_limit(request, payload.email, "verification", user.id)

    def operation():
        service = AccountService(db, request.app.state.settings)
        locked = service.confirm_identity(
            user, payload.password, payload.code, payload.recovery_code
        )
        locked.pending_email = payload.email
        queue_verification(db, service.settings, locked)
        write_audit(db, "email_change_requested", owner_id=user.id)
        return {"message": "Conferma il nuovo indirizzo tramite email."}

    return execute(db, operation)


@router.post("/email-verification-request")
def resend(request: Request, db: DB, user: Owner):
    recipient_limit(request, user.pending_email or "", "verification", user.id)

    def operation():
        service = AccountService(db, request.app.state.settings)
        locked = service._lock_user(user.id)
        queue_verification(db, service.settings, locked)
        return {"message": "Verifica accodata."}

    return execute(db, operation)


@router.post("/email-verify", dependencies=[rate_limit("email-verify", 10, 60)])
def verify_email(payload: TokenRequest, request: Request, db: DB):
    def operation():
        settings = request.app.state.settings
        user, previous = AccountService(db, settings).verify_email(payload.token)
        for email in set(filter(None, [previous, user.email])):
            notification(
                db,
                settings,
                email,
                "L'indirizzo email del tuo account MyDesk e' stato confermato o modificato.",
            )
        return {"message": "Email verificata."}

    return execute(db, operation)


@router.post("/mfa/verify", dependencies=[rate_limit("mfa-verify", 5, 60)])
def verify_mfa(payload: ChallengeRequest, request: Request, db: DB):
    challenge = db.scalar(
        select(MfaChallenge).where(
            MfaChallenge.token_hash == hash_secret(payload.challenge_token)
        )
    )
    if challenge:
        enforce_limit(request.app, "mfa-account", challenge.user_id, 5, 60)
    from app.routes.auth import request_info

    return execute(
        db,
        lambda: AccountService(db, request.app.state.settings).verify_challenge(
            payload.challenge_token,
            payload.code,
            payload.recovery_code,
            request_info(request),
        ),
    )


@router.post("/mfa/setup", dependencies=[rate_limit("mfa-setup", 5, 60, per_user=True)])
def setup(payload: Confirmation, request: Request, db: DB, user: Owner):
    def operation():
        secret, uri = AccountService(db, request.app.state.settings).setup(
            user, session_id(request), payload.password
        )
        image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
        output = io.BytesIO()
        image.save(output)
        return {
            "secret": secret,
            "qr_svg": output.getvalue().decode(),
            "expires_in": 600,
        }

    return execute(db, operation)


@router.post(
    "/mfa/confirm", dependencies=[rate_limit("mfa-confirm", 5, 60, per_user=True)]
)
def confirm(payload: FactorRequest, request: Request, db: DB, user: Owner):
    return execute(
        db,
        lambda: {
            "recovery_codes": AccountService(
                db, request.app.state.settings
            ).confirm_setup(user, session_id(request), payload.code)
        },
    )


def change_mfa(payload, request, db, user, disable):
    service = AccountService(db, request.app.state.settings)
    user = service.confirm_identity(
        user, payload.password, payload.code, payload.recovery_code
    )
    if not user.totp_secret:
        raise ValueError("TOTP non attiva")
    codes = [] if disable else service.recovery_codes(user)
    if disable:
        from sqlalchemy import delete
        from app.models import RecoveryCode

        user.totp_secret = None
        user.totp_last_step = -1
        db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    service.revoke_credentials(user)
    write_audit(
        db, "mfa_disabled" if disable else "mfa_recovery_regenerated", owner_id=user.id
    )
    notification(
        db,
        service.settings,
        user.email if user.email_verified else None,
        "Le impostazioni MFA di MyDesk sono state modificate.",
    )
    return {
        "message": "Accedi nuovamente.",
        **({} if disable else {"recovery_codes": codes}),
    }


@router.post(
    "/mfa/disable", dependencies=[rate_limit("mfa-change", 5, 60, per_user=True)]
)
def disable(payload: Confirmation, request: Request, db: DB, user: Owner):
    return execute(db, lambda: change_mfa(payload, request, db, user, True))


@router.post(
    "/mfa/recovery-codes/regenerate",
    dependencies=[rate_limit("mfa-change", 5, 60, per_user=True)],
)
def regenerate(payload: Confirmation, request: Request, db: DB, user: Owner):
    return execute(db, lambda: change_mfa(payload, request, db, user, False))
