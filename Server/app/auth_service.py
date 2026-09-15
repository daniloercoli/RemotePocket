from __future__ import annotations

import secrets
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.config import Settings
from app.models import (
    MfaChallenge,
    PasswordHistory,
    LoginAttempt,
    LoginSession,
    PasswordResetToken,
    RefreshToken,
    User,
)
from app.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    hash_secret,
    verify_password,
)
from app.timeutils import naive_utc, utc_now
from app.password_policy import validate_password
from app.session_management import SessionManager


class AuthenticationError(ValueError):
    """Expected denial whose audit and lockout changes must be committed."""


class AuthService:
    """Service for user authentication operations."""

    def __init__(self, db: Session, settings: Settings):
        self.db = db
        self.settings = settings
        self.session_manager = SessionManager(db, settings)

    def register(self, username: str, password: str, email: str | None = None) -> User:
        """Register a new user."""
        if email:
            from app.account_service import normalize_email

            email = normalize_email(email)
        # Check if user already exists
        existing_user = self.db.scalar(select(User).where(User.username == username))
        if existing_user:
            raise ValueError("Username or email already registered")

        # Check email if provided
        if email:
            existing_email = self.db.scalar(select(User).where(User.email == email))
            if existing_email:
                raise ValueError("Username or email already registered")

        valid, errors = validate_password(password, settings=self.settings)
        if not valid:
            raise ValueError("; ".join(errors))

        # Create user
        user = User(
            id=secrets.token_urlsafe(16),
            username=username,
            email=email,
            pending_email=email,
            password_hash=hash_password(password),
            is_active=True,
        )
        self.db.add(user)
        self.db.flush()  # Persist the user before related rows
        self._remember_password(user)
        if email and self.settings.email_available:
            from app.email_outbox import queue_verification

            queue_verification(self.db, self.settings, user)

        write_audit(
            self.db,
            "user_registered",
            owner_id=user.id,
            ip_address=None,
            user_agent=None,
        )

        return user

    def login(
        self, username: str, password: str, request_info: dict | None = None
    ) -> dict:
        """
        Authenticate a user and return tokens.

        request_info should contain 'ip_address' and 'user_agent' keys if available.
        """
        request_info = request_info or {}
        ip_address = request_info.get("ip_address")
        user_agent = request_info.get("user_agent")

        user_id = self.db.scalar(select(User.id).where(User.username == username))
        user = self._lock_user(user_id) if user_id else None

        # Check lockout
        if self._check_lockout(user):
            write_audit(
                self.db,
                "login_blocked",
                owner_id=user.id if user else None,
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            self._record_login_attempt(
                user,
                username,
                ip_address,
                user_agent,
                success=False,
                count_failure=False,
            )
            raise AuthenticationError(
                "Account temporarily locked due to too many failed attempts"
            )

        # Validate password
        if user is None or not verify_password(password, user.password_hash):
            self._record_login_attempt(
                user, username, ip_address, user_agent, success=False
            )
            write_audit(
                self.db,
                "login_failed",
                owner_id=user.id if user else None,
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise AuthenticationError("Invalid credentials")

        # Check if user is active
        if not user.is_active:
            self._record_login_attempt(
                user,
                username,
                ip_address,
                user_agent,
                success=False,
                count_failure=False,
            )
            write_audit(
                self.db,
                "login_blocked",
                owner_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise AuthenticationError("Account is not active")

        if user.totp_secret:
            write_audit(self.db, "mfa_challenge_created", owner_id=user.id)
            challenge = secrets.token_urlsafe(32)
            self.db.add(
                MfaChallenge(
                    id=secrets.token_urlsafe(16),
                    user_id=user.id,
                    token_hash=hash_secret(challenge),
                    expires_at=utc_now() + timedelta(minutes=5),
                )
            )
            return {
                "mfa_required": True,
                "challenge_token": challenge,
                "expires_in": 300,
            }
        return self.complete_login(user, request_info)

    def complete_login(self, user, request_info):
        ip_address = request_info.get("ip_address")
        user_agent = request_info.get("user_agent")
        username = user.username
        self._record_login_attempt(user, username, ip_address, user_agent, success=True)
        login_session = self.session_manager.create_session(
            user.id,
            utc_now() + timedelta(days=self.settings.refresh_token_ttl_days),
            user_agent,
            ip_address,
        )
        # Update user
        user.last_login_at = utc_now()
        user.failed_login_attempts = 0
        user.locked_until = None

        write_audit(
            self.db,
            "login_success",
            owner_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return self._issue_tokens(login_session)

    def refresh(
        self, refresh_token_value: str, request_info: dict | None = None
    ) -> dict:
        """
        Refresh access token using a valid refresh token.

        request_info should contain 'ip_address' and 'user_agent' keys if available.
        """
        request_info = request_info or {}
        ip_address = request_info.get("ip_address")
        user_agent = request_info.get("user_agent")

        refresh_token_hash = hash_secret(refresh_token_value)

        # Retain consumed tokens so reuse can revoke their entire login session.
        refresh_token = self.db.scalar(
            select(RefreshToken).where(
                RefreshToken.token_hash == refresh_token_hash,
                RefreshToken.expires_at > utc_now(),
            )
        )

        if refresh_token is None:
            write_audit(
                self.db,
                "token_refresh_failed",
                owner_id=None,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise AuthenticationError("Invalid refresh token")

        user = self._lock_user(refresh_token.user_id)
        login_session = self.session_manager.validate_session(refresh_token.session_id)
        if (
            user is None
            or not user.is_active
            or login_session is None
            or login_session.user_id != user.id
        ):
            raise AuthenticationError("Invalid refresh token")
        # Compare-and-set consumption: only one transaction can rotate a token.
        claimed = self.db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.id == refresh_token.id,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > utc_now(),
            )
            .values(revoked_at=utc_now())
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            self.session_manager.revoke_session(login_session.id, "refresh_token_reuse")
            write_audit(
                self.db,
                "refresh_token_reused",
                owner_id=refresh_token.user_id,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise AuthenticationError("Invalid refresh token")

        self.session_manager.check_fingerprint(login_session, user_agent, ip_address)
        write_audit(
            self.db,
            "token_refreshed",
            owner_id=refresh_token.user_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return self._issue_tokens(login_session)

    def _issue_tokens(self, session: LoginSession) -> dict:
        refresh_value = create_refresh_token()
        self.db.add(
            RefreshToken(
                id=secrets.token_urlsafe(16),
                user_id=session.user_id,
                session_id=session.id,
                token_hash=hash_secret(refresh_value),
                expires_at=session.expires_at,
            )
        )
        self.db.flush()
        return {
            "access_token": create_access_token(
                session.user_id, self.settings, session.id
            ),
            "session_id": session.id,
            "token_type": "bearer",
            "expires_in": self.settings.access_token_ttl_minutes * 60,
            "refresh_token": refresh_value,
        }

    def _lock_user(self, user_id: str) -> User | None:
        # Serialize credential changes with one lock order: user, then sessions/tokens.
        # A no-op UPDATE also locks on SQLite, which ignores SELECT FOR UPDATE.
        self.db.flush()
        self.db.execute(
            update(User)
            .where(User.id == user_id)
            .values(updated_at=User.updated_at)
            .execution_options(synchronize_session=False)
        )
        return self.db.get(User, user_id, populate_existing=True)

    def logout(self, user_id: str, refresh_token_value: str) -> None:
        self._lock_user(user_id)
        token = self.db.scalar(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.token_hash == hash_secret(refresh_token_value),
            )
        )
        if token is None:
            raise ValueError("Invalid refresh token")
        self.session_manager.revoke_session(token.session_id)
        write_audit(self.db, "logout", owner_id=user_id)

    def _check_lockout(self, user: User | None) -> bool:
        """Check if the user is currently locked out."""
        if user is None or user.locked_until is None:
            return False

        if utc_now() < naive_utc(user.locked_until):
            return True

        # Lockout period expired, reset
        user.locked_until = None
        user.failed_login_attempts = 0
        self.db.add(user)
        return False

    def _record_login_attempt(
        self,
        user: User | None,
        username: str,
        ip_address: str | None,
        user_agent: str | None,
        success: bool,
        *,
        count_failure: bool = True,
    ) -> None:
        """Record a login attempt."""
        login_attempt = LoginAttempt(
            id=secrets.token_urlsafe(16),
            user_id=user.id if user else None,
            username=username,
            success=success,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.db.add(login_attempt)
        self.db.flush()

        # The caller holds the user lock, so concurrent failures cannot lose increments.
        if not success and count_failure and user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= self.settings.max_login_attempts:
                user.locked_until = utc_now() + timedelta(
                    minutes=self.settings.lockout_duration_minutes
                )

    def _remember_password(self, user: User) -> None:
        self.db.add(
            PasswordHistory(
                id=secrets.token_urlsafe(16),
                user_id=user.id,
                password_hash=user.password_hash,
                created_at=utc_now(),
            )
        )
        self.db.flush()
        history = self.db.scalars(
            select(PasswordHistory)
            .where(PasswordHistory.user_id == user.id)
            .order_by(PasswordHistory.created_at.desc(), PasswordHistory.id.desc())
        ).all()
        for entry in history[self.settings.password_history_count :]:
            self.db.delete(entry)

    def create_password_reset_token(self, user_id: str) -> str:
        """Create a password reset token."""
        user = self._lock_user(user_id)
        if user is None:
            raise ValueError("User not found")

        token = secrets.token_urlsafe(32)
        token_hash = hash_secret(token)

        self.db.execute(
            update(PasswordResetToken)
            .where(
                PasswordResetToken.user_id == user_id,
                PasswordResetToken.used_at.is_(None),
            )
            .values(used_at=utc_now())
            .execution_options(synchronize_session=False)
        )

        # Create new token
        reset_token = PasswordResetToken(
            id=secrets.token_urlsafe(16),
            user_id=user_id,
            token_hash=token_hash,
            expires_at=utc_now() + timedelta(minutes=30),
        )
        self.db.add(reset_token)

        write_audit(
            self.db,
            "password_reset_token_created",
            owner_id=user_id,
            ip_address=None,
            user_agent=None,
        )

        return token

    def reset_password(self, token: str, new_password: str) -> None:
        """Reset password using a reset token."""
        token_hash = hash_secret(token)

        reset_token = self.db.scalar(
            select(PasswordResetToken).where(
                PasswordResetToken.token_hash == token_hash,
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.expires_at > utc_now(),
            )
        )

        if reset_token is None:
            raise ValueError("Invalid or expired reset token")

        user = self._lock_user(reset_token.user_id)
        if user is None or not user.is_active:
            raise ValueError("Invalid or expired reset token")
        history = self.db.scalars(
            select(PasswordHistory.password_hash)
            .where(PasswordHistory.user_id == reset_token.user_id)
            .order_by(PasswordHistory.created_at.desc(), PasswordHistory.id.desc())
            .limit(self.settings.password_history_count)
        ).all()
        valid, errors = validate_password(
            new_password, list(history), settings=self.settings
        )
        if not valid:
            raise ValueError("; ".join(errors))
        consumed = self.db.execute(
            update(PasswordResetToken)
            .where(
                PasswordResetToken.id == reset_token.id,
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.expires_at > utc_now(),
            )
            .values(used_at=utc_now())
            .execution_options(synchronize_session=False)
        )
        if consumed.rowcount != 1:
            raise ValueError("Invalid or expired reset token")

        # Update user password
        user.password_hash = hash_password(new_password)
        self._remember_password(user)
        self.session_manager.revoke_all_sessions(user.id)
        from app.email_outbox import notification

        notification(
            self.db,
            self.settings,
            user.email if user.email_verified else None,
            "La password del tuo account MyDesk e' stata reimpostata.",
        )
        self.db.execute(
            update(MfaChallenge)
            .where(MfaChallenge.user_id == user.id)
            .values(used_at=utc_now())
        )
        user.failed_login_attempts = 0
        user.locked_until = None
        self.db.add(user)
        write_audit(
            self.db,
            "password_reset",
            owner_id=user.id,
            ip_address=None,
            user_agent=None,
        )
