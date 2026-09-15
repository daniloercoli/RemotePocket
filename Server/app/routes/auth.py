from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, StringConstraints
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth_service import AuthenticationError, AuthService
from app.dependencies import get_current_user, get_db
from app.models import User, BootstrapLock
from app.rate_limiting import rate_limit, recipient_limit

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
Username = Annotated[
    str, StringConstraints(strip_whitespace=True, pattern=r"^[a-zA-Z0-9_]{3,30}$")
]


class AuthRequest(BaseModel):
    username: Username
    password: str = Field(min_length=8, max_length=200)


class RegisterRequest(AuthRequest):
    email: EmailStr | None = Field(default=None, max_length=255)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1, max_length=200)


class PasswordResetRequest(BaseModel):
    token: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=8, max_length=200)


def request_info(request):
    return {
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent", "")[:1000],
    }


@router.post("/bootstrap", dependencies=[rate_limit("bootstrap", 3, 3600)])
def bootstrap_owner(
    payload: RegisterRequest, request: Request, db: Annotated[Session, Depends(get_db)]
):
    # A seeded singleton row serializes concurrent first-owner creation on both databases.
    db.execute(update(BootstrapLock).where(BootstrapLock.id == 1).values(id=1))
    if db.scalar(select(func.count(User.id))):
        raise HTTPException(409, "Owner gia' inizializzato")
    service = AuthService(db, request.app.state.settings)
    try:
        user = service.register(payload.username, payload.password, payload.email)
        if user.pending_email and service.settings.email_available:
            recipient_limit(request, user.pending_email, "verification", user.id)
        result = service.login(user.username, payload.password, request_info(request))
        result["user"] = {"id": user.id, "username": user.username}
        db.commit()
        return result
    except ValueError as error:
        raise HTTPException(400, str(error)) from error


@router.post(
    "/register",
    dependencies=[
        rate_limit(
            "register", "rate_limit_register", "rate_limit_register_window_seconds"
        )
    ],
)
def register_user(
    payload: RegisterRequest, request: Request, db: Annotated[Session, Depends(get_db)]
):
    try:
        # Use the same lock as bootstrap so registration cannot race first-owner setup.
        db.execute(update(BootstrapLock).where(BootstrapLock.id == 1).values(id=1))
        user = AuthService(db, request.app.state.settings).register(
            payload.username, payload.password, payload.email
        )
        if user.pending_email and request.app.state.settings.email_available:
            recipient_limit(request, user.pending_email, "verification", user.id)
        db.commit()
        return {
            "message": "User registered successfully",
            "user": {"id": user.id, "username": user.username, "email": user.email},
        }
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(400, "Username or email already registered") from error
    except ValueError as error:
        raise HTTPException(400, str(error)) from error


@router.post(
    "/login",
    dependencies=[
        rate_limit("login", "rate_limit_login", "rate_limit_login_window_seconds")
    ],
)
def login_owner(
    payload: AuthRequest, request: Request, db: Annotated[Session, Depends(get_db)]
):
    try:
        result = AuthService(db, request.app.state.settings).login(
            payload.username, payload.password, request_info(request)
        )
        db.commit()
        return (
            JSONResponse(result, status_code=202)
            if result.get("mfa_required")
            else result
        )
    except AuthenticationError as error:
        db.commit()
        raise HTTPException(401, str(error)) from error


@router.post("/refresh", dependencies=[rate_limit("refresh", 10, 60)])
def refresh_token(
    payload: RefreshRequest, request: Request, db: Annotated[Session, Depends(get_db)]
):
    try:
        result = AuthService(db, request.app.state.settings).refresh(
            payload.refresh_token, request_info(request)
        )
        db.commit()
        return result
    except AuthenticationError as error:
        db.commit()
        raise HTTPException(401, str(error)) from error


@router.post("/logout", dependencies=[rate_limit("logout", 10, 60, per_user=True)])
def logout(
    payload: RefreshRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    try:
        AuthService(db, request.app.state.settings).logout(
            user.id, payload.refresh_token
        )
        db.commit()
        return {"message": "Logged out successfully"}
    except ValueError as error:
        raise HTTPException(400, str(error)) from error


@router.get("/me", dependencies=[rate_limit("me", 30, 60, per_user=True)])
def get_me(user: Annotated[User, Depends(get_current_user)]):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "email_verified": user.email_verified,
        "pending_email": user.pending_email,
        "totp_enabled": bool(user.totp_secret),
    }


@router.post("/password-reset", dependencies=[rate_limit("password-reset", 3, 3600)])
def password_reset(
    payload: PasswordResetRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    try:
        AuthService(db, request.app.state.settings).reset_password(
            payload.token, payload.new_password
        )
        db.commit()
        return {"message": "Password reset successfully"}
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
