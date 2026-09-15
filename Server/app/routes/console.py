from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter(tags=["console"])


@router.get("/", include_in_schema=False)
def console_index():
    static_file = Path(__file__).resolve().parents[1] / "static" / "console.html"
    return FileResponse(static_file)

