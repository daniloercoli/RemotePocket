"""Centralized, credential-safe errors preserving the existing HTTP detail contract.

Questo programma è software libera: puoi ridistribuirlo e/o modificarlo
sotto i termini della GNU General Public License come pubblicata dalla
Free Software Foundation, versione 3 della Licenza o (a propria scelta)
qualsiasi versione successiva.

Questo programma è distribuito nella speranza che sia utile, ma SENZA
ALCUNA GARANZIA; senza neppure la garanzia implicita di COMMERCIABILITÀ
o IDONEITÀ PER UNO SCOPO PARTICOLARE. Vedere la GNU General Public License
per dettagli.

Dovresti aver ricevuto una copia della GNU General Public License
insieme a questo programma. Se non è così, vedere <https://www.gnu.org/licenses/>.
"""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException
from starlette.websockets import WebSocket, WebSocketState

from app.correlation import get_request_id
from app.password_policy import BreachCheckUnavailable


class MyDeskError(Exception):
    status_code = 400

    def __init__(self, message: str, error_code: str = "INTERNAL_ERROR"):
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class ValidationError(MyDeskError):
    status_code = 422

    def __init__(self, message: str, error_code: str = "VALIDATION_ERROR"):
        super().__init__(message, error_code)


class AuthenticationError(MyDeskError):
    status_code = 401

    def __init__(
        self, message: str = "Autenticazione fallita", error_code: str = "AUTH_FAILED"
    ):
        super().__init__(message, error_code)


class AuthorizationError(MyDeskError):
    status_code = 403

    def __init__(
        self, message: str = "Non autorizzato", error_code: str = "AUTHZ_FAILED"
    ):
        super().__init__(message, error_code)


class ResourceNotFoundError(MyDeskError):
    status_code = 404

    def __init__(self, resource: str, resource_id: str, error_code: str = "NOT_FOUND"):
        super().__init__(f"{resource} non trovata", error_code)


def create_error_response(error: Exception, settings=None) -> JSONResponse:
    headers = None
    if isinstance(error, HTTPException):
        status, detail, code = (
            error.status_code,
            error.detail,
            f"HTTP_{error.status_code}",
        )
        headers = error.headers
    elif isinstance(error, RequestValidationError):
        status, code = 422, "VALIDATION_ERROR"
        # Never serialize input, ctx or str(error): these can contain passwords/tokens.
        detail = [
            {"loc": e["loc"], "msg": e["msg"], "type": e["type"]}
            for e in error.errors()
        ]
    elif isinstance(error, BreachCheckUnavailable):
        status, detail, code = (
            503,
            "Password breach check unavailable",
            "BREACH_CHECK_UNAVAILABLE",
        )
    elif isinstance(error, MyDeskError):
        status, detail, code = error.status_code, error.message, error.error_code
    elif isinstance(error, SQLAlchemyError):
        status, detail, code = 500, "Errore database", "DATABASE_ERROR"
    else:
        status, detail, code = 500, "Errore interno server", "INTERNAL_ERROR"
    return JSONResponse(
        status_code=status,
        content={"detail": detail, "error_code": code, "request_id": get_request_id()},
        headers=headers,
    )


async def handle_error(
    request: Request | WebSocket, exc: Exception
) -> JSONResponse | None:
    # Request middleware logs status and correlation, without exception strings or SQL params.
    if (
        isinstance(request, WebSocket)
        and request.application_state != WebSocketState.CONNECTING
    ):
        # Once accepted, an HTTP error response is no longer a valid ASGI message.
        if request.application_state == WebSocketState.CONNECTED:
            await request.close(code=1011)
        return None
    return create_error_response(exc)


def setup_error_handlers(app: FastAPI) -> None:
    for kind in (
        HTTPException,
        RequestValidationError,
        SQLAlchemyError,
        MyDeskError,
        BreachCheckUnavailable,
        Exception,
    ):
        app.add_exception_handler(kind, handle_error)
