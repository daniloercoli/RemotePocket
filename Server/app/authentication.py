from sqlalchemy.orm import Session

from app.config import Settings
from app.models import User
from app.security import verify_access_token
from app.session_management import SessionManager


def authenticate_user(db: Session, token: str, settings: Settings) -> User | None:
    """Require a live persistent session for both HTTP and WebSocket access."""
    payload = verify_access_token(token, settings)
    if (
        payload is None
        or not isinstance(payload.get("sub"), str)
        or not isinstance(payload.get("sid"), str)
    ):
        return None
    session = SessionManager(db, settings).validate_session(payload["sid"])
    if session is None or session.user_id != payload["sub"]:
        return None
    user = db.get(User, session.user_id, populate_existing=True)
    return user if user is not None and user.is_active else None
