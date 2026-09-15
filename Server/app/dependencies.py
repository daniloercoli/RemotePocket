from __future__ import annotations

from typing import Annotated
import secrets

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.authentication import authenticate_user
from app.models import User

bearer_scheme = HTTPBearer(auto_error=False)


def require_monitoring_access(request: Request):
    """Independent of database availability and of ordinary owner accounts."""
    expected = request.app.state.settings.monitoring_token
    if not expected:
        raise HTTPException(404, "Not found")
    scheme, _, supplied = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(
        supplied.encode(), expected.encode()
    ):
        raise HTTPException(
            401,
            "Monitoring credentials required",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_db(request: Request):
    session_factory = request.app.state.SessionLocal
    db = session_factory()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Token owner mancante")

    user = authenticate_user(db, credentials.credentials, request.app.state.settings)
    if user is None:
        raise HTTPException(status_code=401, detail="Token owner non valido")
    return user
