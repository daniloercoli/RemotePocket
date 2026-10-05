from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter(tags=["console"])


@router.get("/", include_in_schema=False)
@router.get("/login", include_in_schema=False)
@router.get("/register", include_in_schema=False)
@router.get("/setup", include_in_schema=False)
@router.get("/forgot-password", include_in_schema=False)
@router.get("/reset-password", include_in_schema=False)
@router.get("/verify-email", include_in_schema=False)
@router.get("/two-factor", include_in_schema=False)
@router.get("/recovery-codes", include_in_schema=False)
@router.get("/app", include_in_schema=False)
@router.get("/app/devices", include_in_schema=False)
@router.get("/app/sessions", include_in_schema=False)
@router.get("/app/activity", include_in_schema=False)
@router.get("/app/account", include_in_schema=False)
@router.get("/app/help", include_in_schema=False)
def console_index():
    static_file = Path(__file__).resolve().parents[1] / "static" / "console.html"
    return FileResponse(static_file)
