"""Integration tests for auth endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import create_reset_token


def test_register_endpoint(client: TestClient):
    """Test user registration endpoint."""
    response = client.post(
        "/api/auth/register",
        json={
            "username": "newuser",
            "password": "Violet!Harbor7Lantern",
            "email": "newuser@example.com",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "User registered successfully"
    assert data["user"]["username"] == "newuser"
    assert data["user"]["email"] == "newuser@example.com"


def test_register_duplicate_username(client: TestClient):
    """Test registering with duplicate username."""
    # First registration
    client.post(
        "/api/auth/register",
        json={
            "username": "existinguser",
            "password": "Violet!Harbor7Lantern",
        },
    )

    # Second registration with same username
    response = client.post(
        "/api/auth/register",
        json={
            "username": "existinguser",
            "password": "Copper!Meadow8Falcon",
        },
    )

    assert response.status_code == 400
    assert "already" in response.json()["detail"].lower()


def test_register_short_password(client: TestClient):
    """Test registering with short password."""
    response = client.post(
        "/api/auth/register",
        json={
            "username": "newuser",
            "password": "short",  # Too short - Pydantic validation will catch this
        },
    )

    # Pydantic validation returns 422, not 400
    assert response.status_code == 422


def test_login_endpoint(client: TestClient):
    """Test login endpoint."""
    # First register a user
    client.post(
        "/api/auth/register",
        json={
            "username": "testuser",
            "password": "Violet!Harbor7Lantern",
        },
    )

    # Then login
    response = client.post(
        "/api/auth/login",
        json={
            "username": "testuser",
            "password": "Violet!Harbor7Lantern",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["token_type"] == "bearer"
    # The response uses expires_in (seconds) not expires_at
    assert "expires_in" in data or "expires_at" in data


def test_login_invalid_credentials(client: TestClient):
    """Test login with invalid credentials."""
    # Register a user first
    client.post(
        "/api/auth/register",
        json={
            "username": "testuser",
            "password": "Violet!Harbor7Lantern",
        },
    )

    # Login with wrong password
    response = client.post(
        "/api/auth/login",
        json={
            "username": "testuser",
            "password": "wrongpassword",
        },
    )

    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]


def test_login_invalid_username(client: TestClient):
    """Test login with non-existent user."""
    response = client.post(
        "/api/auth/login",
        json={
            "username": "nonexistent",
            "password": "Violet!Harbor7Lantern",
        },
    )

    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]


def test_refresh_endpoint(client: TestClient):
    """Test token refresh endpoint."""
    # Register and login
    client.post(
        "/api/auth/register",
        json={
            "username": "testuser",
            "password": "Violet!Harbor7Lantern",
        },
    )

    login_response = client.post(
        "/api/auth/login",
        json={
            "username": "testuser",
            "password": "Violet!Harbor7Lantern",
        },
    )

    refresh_token = login_response.json()["refresh_token"]

    # Refresh token
    response = client.post(
        "/api/auth/refresh",
        json={"refresh_token": refresh_token},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_refresh_invalid_token(client: TestClient):
    """Test refresh with invalid token."""
    response = client.post(
        "/api/auth/refresh",
        json={"refresh_token": "invalid_token"},
    )

    assert response.status_code == 401
    assert "Invalid refresh token" in response.json()["detail"]


def test_logout_endpoint(client: TestClient):
    """Test logout endpoint."""
    # Register and login
    client.post(
        "/api/auth/register",
        json={
            "username": "testuser",
            "password": "Violet!Harbor7Lantern",
        },
    )

    login_response = client.post(
        "/api/auth/login",
        json={
            "username": "testuser",
            "password": "Violet!Harbor7Lantern",
        },
    )

    access_token = login_response.json()["access_token"]
    refresh_token = login_response.json()["refresh_token"]

    # Logout with both access token (for auth) and refresh token
    response = client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"refresh_token": refresh_token},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Logged out successfully"


def test_me_endpoint(client: TestClient):
    """Test getting current user info."""
    # Register and login
    client.post(
        "/api/auth/register",
        json={
            "username": "testuser",
            "password": "Violet!Harbor7Lantern",
        },
    )

    login_response = client.post(
        "/api/auth/login",
        json={
            "username": "testuser",
            "password": "Violet!Harbor7Lantern",
        },
    )

    access_token = login_response.json()["access_token"]

    # Get current user
    response = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["id"] is not None


def test_password_reset_request(client: TestClient):
    """Test password reset request endpoint."""
    # Register a user
    client.post(
        "/api/auth/register",
        json={
            "username": "testuser",
            "password": "Violet!Harbor7Lantern",
            "email": "test@example.com",
        },
    )

    # Request password reset
    response = client.post(
        "/api/auth/password-reset-request",
        json={"email": "test@example.com"},
    )

    assert response.status_code == 503
    assert "reset_token" not in response.json()
    unknown = client.post(
        "/api/auth/password-reset-request", json={"email": "unknown@example.com"}
    )
    assert unknown.status_code == response.status_code
    # Correlation IDs are unique; the recovery result must not reveal whether an account exists.
    assert {k: v for k, v in unknown.json().items() if k != "request_id"} == {
        k: v for k, v in response.json().items() if k != "request_id"
    }


def test_password_reset(client: TestClient):
    """Test password reset endpoint."""
    # Register a user
    client.post(
        "/api/auth/register",
        json={
            "username": "testuser",
            "password": "Violet!Harbor7Lantern",
            "email": "test@example.com",
        },
    )

    reset_token = create_reset_token(client, "testuser")

    # Reset password
    response = client.post(
        "/api/auth/password-reset",
        json={
            "token": reset_token,
            "new_password": "Copper!Meadow8Falcon-new",
        },
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Password reset successfully"

    # Verify we can login with new password
    login_response = client.post(
        "/api/auth/login",
        json={
            "username": "testuser",
            "password": "Copper!Meadow8Falcon-new",
        },
    )

    assert login_response.status_code == 200


def test_password_reset_invalid_token(client: TestClient):
    """Test password reset with invalid token."""
    response = client.post(
        "/api/auth/password-reset",
        json={
            "token": "invalid_token",
            "new_password": "Copper!Meadow8Falcon-new",
        },
    )

    assert response.status_code == 400
    assert "Invalid or expired" in response.json()["detail"]


def test_bootstrap_endpoint(client: TestClient):
    """Test bootstrap endpoint for creating initial user."""
    response = client.post(
        "/api/auth/bootstrap",
        json={
            "username": "admin",
            "password": "Cobalt!Garden7Lantern",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["access_token"]
    assert data["user"]["username"] == "admin"


def test_bootstrap_duplicate(client: TestClient):
    """Test bootstrap with existing users."""
    # First bootstrap
    client.post(
        "/api/auth/bootstrap",
        json={
            "username": "admin",
            "password": "Cobalt!Garden7Lantern",
        },
    )

    # Second bootstrap should fail
    response = client.post(
        "/api/auth/bootstrap",
        json={
            "username": "admin2",
            "password": "Silver!Orchid9Canyon",
        },
    )

    assert response.status_code == 409
