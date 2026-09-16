"""JWT signing requires an explicit key, including in local development."""

from pathlib import Path
import secrets

from cryptography.fernet import Fernet
from pydantic import ValidationError
import pytest

from app.config import Settings
from app.security import create_access_token, verify_access_token


@pytest.fixture
def configuration(monkeypatch):
    monkeypatch.delenv("MYDESK_SECRET_KEY", raising=False)
    return {
        "_env_file": None,
        "_secrets_dir": None,
        "encryption_key": Fernet.generate_key().decode(),
        "public_base_url": "https://desk.example.com",
        "database_url": "postgresql+psycopg2://db/test",
        "cors_allowed_origins": "https://desk.example.com",
        "check_password_breaches": True,
        "rate_limit_enabled": True,
        "debug": False,
    }


@pytest.mark.parametrize("environment", ["dev", "staging", "prod"])
@pytest.mark.parametrize(
    "secret",
    [
        None,
        "",
        " " * 32,
        "short",
        "s" * 31,
        "dev-secret-change-me-in-production",
        "  dev-secret-change-me-in-production  ",
    ],
)
def test_missing_or_unsafe_key_prevents_startup(configuration, environment, secret):
    configuration["environment"] = environment
    if secret is not None:
        configuration["secret_key"] = secret
    with pytest.raises(ValidationError, match="MYDESK_SECRET_KEY") as error:
        Settings(**configuration)
    if secret and secret.strip():
        assert secret not in str(error.value)


@pytest.mark.parametrize("environment", ["dev", "staging", "prod"])
@pytest.mark.parametrize("source", ["environment", "dotenv", "secret_file"])
def test_configured_key_signs_tokens_and_survives_settings_reload(
    configuration, environment, source, tmp_path, monkeypatch
):
    key = secrets.token_urlsafe(48)
    configuration["environment"] = environment
    if source == "environment":
        monkeypatch.setenv("MYDESK_SECRET_KEY", key)
    elif source == "dotenv":
        dotenv = tmp_path / ".env"
        dotenv.write_text("MYDESK_SECRET_KEY=" + key + "\n")
        configuration["_env_file"] = dotenv
    else:
        (tmp_path / "MYDESK_SECRET_KEY").write_text(key)
        configuration["_secrets_dir"] = tmp_path
    settings = Settings(**configuration)
    assert settings.secret_key == key
    assert key not in repr(settings)
    token = create_access_token("owner", settings, "session")
    reloaded = Settings(**configuration)
    assert verify_access_token(token, reloaded)["sub"] == "owner"


def test_example_environment_requires_a_personal_key(configuration):
    configuration["_env_file"] = Path(__file__).parents[1] / ".env.example"
    with pytest.raises(ValidationError, match="MYDESK_SECRET_KEY"):
        Settings(**configuration)
