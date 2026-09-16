"""Unit tests for AuthService."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.auth_service import AuthService
from app.config import Settings
from app.database import Base
from app.models import PasswordResetToken, RefreshToken, User
from app.security import hash_password, hash_secret, verify_password
from app.timeutils import utc_now
import secrets


@pytest.fixture
def engine():
    """Create an in-memory SQLite engine for testing."""
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture
def db_session(engine):
    """Create a database session for testing."""
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def auth_service(db_session):
    """Create an AuthService instance for testing."""
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        secret_key="test-secret-key-with-at-least-32-chars",
        access_token_ttl_minutes=120,
        refresh_token_ttl_days=7,
        max_login_attempts=5,
        lockout_duration_minutes=15,
        min_password_length=8,
    )
    return AuthService(db_session, settings)


class TestAuthServiceRegister:
    """Tests for the register method."""

    def test_register_success(self, auth_service, db_session):
        """Test successful user registration."""
        user = auth_service.register(
            "testuser", "Violet!Harbor7Lantern", "test@example.com"
        )
        db_session.commit()

        # Check user has an ID and other required fields
        assert user.id is not None
        assert len(user.id) > 0
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_active is True
        assert user.failed_login_attempts == 0

        # Verify password is hashed
        stored_user = db_session.scalar(select(User).where(User.id == user.id))
        assert stored_user.password_hash.startswith("$argon2")

    def test_register_duplicate_username(self, auth_service, db_session):
        """Test registering with a duplicate username."""
        auth_service.register("testuser", "Violet!Harbor7Lantern")
        db_session.commit()

        # Try to register again with same username
        with pytest.raises(ValueError, match="Username or email already registered"):
            auth_service.register("testuser", "Copper!Meadow8Falcon")

    def test_register_duplicate_email(self, auth_service, db_session):
        """Test registering with a duplicate email."""
        auth_service.register("user1", "Violet!Harbor7Lantern", "test@example.com")
        db_session.commit()

        # Try to register with same email
        with pytest.raises(ValueError, match="Username or email already registered"):
            auth_service.register("user2", "Copper!Meadow8Falcon", "test@example.com")

    def test_register_short_password(self, auth_service, db_session):
        """Test registering with a password that's too short."""
        with pytest.raises(ValueError, match="Password must be at least 8 characters"):
            auth_service.register("testuser", "short")


class TestAuthServiceLogin:
    """Tests for the login method."""

    def test_login_success(self, auth_service, db_session):
        """Test successful login."""
        auth_service.register("testuser", "Violet!Harbor7Lantern")
        db_session.commit()

        result = auth_service.login("testuser", "Violet!Harbor7Lantern")

        assert "access_token" in result
        assert "refresh_token" in result
        assert result["token_type"] == "bearer"
        assert "expires_in" in result

    def test_login_invalid_credentials(self, auth_service, db_session):
        """Test login with invalid credentials."""
        auth_service.register("testuser", "Violet!Harbor7Lantern")
        db_session.commit()

        with pytest.raises(ValueError, match="Invalid credentials"):
            auth_service.login("testuser", "wrongpassword")

    def test_login_user_not_found(self, auth_service, db_session):
        """Test login with non-existent user."""
        with pytest.raises(ValueError, match="Invalid credentials"):
            auth_service.login("nonexistent", "Violet!Harbor7Lantern")

    def test_login_account_locked(self, auth_service, db_session):
        """Test login with locked account."""
        # Create user with lockout
        user = User(
            id=secrets.token_urlsafe(16),
            username="testuser",
            password_hash=hash_password("Violet!Harbor7Lantern"),
            failed_login_attempts=5,
            locked_until=utc_now() + timedelta(minutes=1),
        )
        db_session.add(user)
        db_session.commit()

        with pytest.raises(ValueError, match="Invalid credentials"):
            auth_service.login("testuser", "Violet!Harbor7Lantern")


class TestAuthServiceRefresh:
    """Tests for the refresh method."""

    def test_refresh_success(self, auth_service, db_session):
        """Test successful token refresh."""
        auth_service.register("testuser", "Violet!Harbor7Lantern")
        db_session.commit()

        # First login to get refresh token
        login_result = auth_service.login("testuser", "Violet!Harbor7Lantern")
        refresh_token = login_result["refresh_token"]

        # Refresh the token
        result = auth_service.refresh(refresh_token)

        assert "access_token" in result
        assert "refresh_token" in result
        assert result["token_type"] == "bearer"

    def test_refresh_invalid_token(self, auth_service, db_session):
        """Test refresh with invalid token."""
        with pytest.raises(ValueError, match="Invalid refresh token"):
            auth_service.refresh("invalid_token")

    def test_refresh_revoked_token(self, auth_service, db_session):
        """Test refresh with revoked token."""
        user = auth_service.register("testuser", "Violet!Harbor7Lantern")
        db_session.commit()

        # Login and get refresh token
        login_result = auth_service.login("testuser", "Violet!Harbor7Lantern")
        refresh_token = login_result["refresh_token"]

        # Logout (which revokes the token)
        auth_service.logout(user.id, refresh_token)
        db_session.commit()

        # Try to refresh with revoked token
        with pytest.raises(ValueError, match="Invalid refresh token"):
            auth_service.refresh(refresh_token)


class TestAuthServiceLogout:
    """Tests for the logout method."""

    def test_logout_success(self, auth_service, db_session):
        """Test successful logout."""
        user = auth_service.register("testuser", "Violet!Harbor7Lantern")
        db_session.commit()

        # Login and get refresh token
        login_result = auth_service.login("testuser", "Violet!Harbor7Lantern")
        refresh_token = login_result["refresh_token"]

        # Logout
        auth_service.logout(user.id, refresh_token)
        db_session.commit()

        # Verify token is revoked by checking it doesn't appear as active
        token_hash = hash_secret(refresh_token)

        revoked_token = db_session.scalar(
            select(RefreshToken).where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.revoked_at != None,  # noqa: E711
            )
        )
        assert revoked_token is not None
        assert revoked_token.revoked_at is not None


class TestPasswordReset:
    """Tests for password reset functionality."""

    def test_create_password_reset_token(self, auth_service, db_session):
        """Test creating a password reset token."""
        user = auth_service.register("testuser", "Violet!Harbor7Lantern")
        db_session.commit()

        token = auth_service.create_password_reset_token(user.id)
        db_session.commit()

        # Verify token was created
        stored_token = db_session.scalar(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used_at == None,  # noqa: E711
            )
        )
        assert stored_token is not None
        assert stored_token.token_hash == hash_secret(token)

    def test_reset_password_success(self, auth_service, db_session):
        """Test successful password reset."""
        user = auth_service.register("testuser", "Violet!Harbor7Lantern")
        db_session.commit()

        # Create reset token
        token = auth_service.create_password_reset_token(user.id)
        db_session.commit()

        # Reset password
        auth_service.reset_password(token, "Copper!Meadow8Falcon-new")
        db_session.commit()

        # Verify password was updated
        user = db_session.get(User, user.id)
        assert verify_password("Copper!Meadow8Falcon-new", user.password_hash)
        assert not verify_password("Violet!Harbor7Lantern", user.password_hash)

    def test_reset_password_invalid_token(self, auth_service, db_session):
        """Test password reset with invalid token."""
        with pytest.raises(ValueError, match="Invalid or expired reset token"):
            auth_service.reset_password("invalid_token", "Copper!Meadow8Falcon-new")


class TestLockout:
    """Tests for account lockout functionality."""

    def test_lockout_after_max_attempts(self, auth_service, db_session):
        """Test account lockout after max failed attempts."""
        # Create user with valid argon2 hash
        valid_hash = hash_password("Violet!Harbor7Lantern")  # Generate a valid hash
        user = User(
            id=secrets.token_urlsafe(16),
            username="testuser",
            password_hash=valid_hash,
            failed_login_attempts=4,
        )
        db_session.add(user)
        db_session.commit()

        # Try to login (5th attempt) - this doesn't commit
        with pytest.raises(ValueError, match="Invalid credentials"):
            auth_service.login("testuser", "wrongpassword")

        # The update happened in the session. Commit to persist it.
        db_session.commit()

        # Now check in a fresh query
        user = db_session.scalar(select(User).where(User.username == "testuser"))
        assert user.failed_login_attempts == 5
        assert user.locked_until is not None

    def test_unlock_after_lockout_period(self, auth_service, db_session):
        """Test account unlocks after lockout period expires."""
        # Create user with valid hash and past lockout
        valid_hash = hash_password("Violet!Harbor7Lantern")
        user = User(
            id=secrets.token_urlsafe(16),
            username="testuser",
            password_hash=valid_hash,
            failed_login_attempts=5,
            locked_until=utc_now() - timedelta(minutes=1),  # Past time
        )
        db_session.add(user)
        db_session.commit()

        # Check lockout status
        assert auth_service._check_lockout(user) is False

        # User should be unlocked now
        user = db_session.scalar(select(User).where(User.username == "testuser"))
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
