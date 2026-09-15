"""Persistent login sessions. The caller owns the transaction."""

from sqlalchemy import func, select, update

from app.audit import write_audit
from app.models import LoginSession, RefreshToken
from app.security import generate_id, hash_secret
from app.timeutils import utc_now, naive_utc


class SessionManager:
    def __init__(self, db, settings):
        self.db = db
        self.settings = settings

    @staticmethod
    def generate_device_fingerprint(user_agent, ip_address):
        return hash_secret(f"{user_agent or 'unknown'}:{ip_address or 'unknown'}")

    def get_active_session_count(self, user_id):
        return self.db.scalar(
            select(func.count())
            .select_from(LoginSession)
            .where(
                LoginSession.user_id == user_id,
                LoginSession.revoked_at.is_(None),
                LoginSession.expires_at > utc_now(),
            )
        )

    def create_session(self, user_id, expires_at, user_agent=None, ip_address=None):
        session = LoginSession(
            id=generate_id("login"),
            user_id=user_id,
            created_at=utc_now(),
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
            device_fingerprint=self.generate_device_fingerprint(user_agent, ip_address),
        )
        self.db.add(session)
        self.db.flush()
        self.enforce_concurrent_session_limit(user_id)
        return session

    def enforce_concurrent_session_limit(self, user_id):
        maximum = self.settings.max_concurrent_sessions
        sessions = self.db.scalars(
            select(LoginSession)
            .where(
                LoginSession.user_id == user_id,
                LoginSession.revoked_at.is_(None),
                LoginSession.expires_at > utc_now(),
            )
            .order_by(LoginSession.created_at, LoginSession.id)
        ).all()
        revoked = sessions[: max(0, len(sessions) - maximum)]
        for session in revoked:
            self.revoke_session(session.id, "concurrent_session_limit")
        return revoked

    def revoke_session(self, session_id, reason="user_logout"):
        session = self.db.get(LoginSession, session_id, populate_existing=True)
        if session is None or session.revoked_at is not None:
            return False
        session.revoked_at = utc_now()
        self.db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.session_id == session_id, RefreshToken.revoked_at.is_(None)
            )
            .values(revoked_at=utc_now())
            .execution_options(synchronize_session=False)
        )
        write_audit(
            self.db,
            "session_revoked",
            owner_id=session.user_id,
            payload={"login_session_id": session_id, "reason": reason},
        )
        self.db.flush()
        return True

    def revoke_all_sessions(self, user_id):
        ids = self.db.scalars(
            select(LoginSession.id).where(
                LoginSession.user_id == user_id, LoginSession.revoked_at.is_(None)
            )
        ).all()
        return [sid for sid in ids if self.revoke_session(sid, "all_sessions")]

    def validate_session(self, session_id):
        session = self.db.get(LoginSession, session_id, populate_existing=True)
        if (
            session is None
            or session.revoked_at is not None
            or naive_utc(session.expires_at) <= utc_now()
        ):
            return None
        return session

    def check_fingerprint(self, session, user_agent, ip_address):
        # IP/UA changes are a signal, not proof: mobile networks legitimately change.
        fingerprint = self.generate_device_fingerprint(user_agent, ip_address)
        if session.device_fingerprint != fingerprint:
            write_audit(
                self.db,
                "session_fingerprint_changed",
                owner_id=session.user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                payload={"login_session_id": session.id},
            )
            session.user_agent = user_agent
            session.ip_address = ip_address
            session.device_fingerprint = fingerprint
