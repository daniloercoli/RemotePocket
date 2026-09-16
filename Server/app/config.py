"""Validated environment configuration; Docker secret files override environment values."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MYDESK_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        hide_input_in_errors=True,
    )
    environment: Literal["dev", "staging", "prod"] = "dev"
    debug: bool = False
    secret_key: str = Field(default="", repr=False)
    access_token_ttl_minutes: int = Field(default=60, ge=1, le=1440)
    refresh_token_ttl_days: int = Field(default=30, ge=1, le=30)
    max_login_attempts: int = Field(default=5, ge=1, le=10)
    lockout_duration_minutes: int = Field(default=15, ge=5, le=60)
    min_password_length: int = Field(default=8, ge=8, le=128)
    require_password_uppercase: bool = True
    require_password_lowercase: bool = True
    require_password_number: bool = True
    require_password_special: bool = True
    check_password_breaches: bool = True
    password_history_count: int = Field(default=3, ge=0, le=12)
    min_password_strength: int = Field(default=3, ge=0, le=4)
    database_url: str = Field(default="sqlite+pysqlite:///./mydesk.db", repr=False)
    database_pool_size: int = Field(default=10, ge=1, le=50)
    database_max_overflow: int = Field(default=20, ge=0, le=100)
    database_pool_recycle_seconds: int = Field(default=3600, ge=60)
    redis_url: str = Field(default="redis://localhost:6379/0", repr=False)
    pairing_code_ttl_minutes: int = Field(default=10, ge=1, le=60)
    max_concurrent_sessions: int = Field(default=3, ge=1, le=10)
    cors_allowed_origins: str = "http://localhost:3000,http://localhost:8000"
    rate_limit_enabled: bool = True
    rate_limit_login: int = Field(default=5, ge=1, le=20)
    rate_limit_login_window_seconds: int = Field(default=60, ge=1, le=300)
    rate_limit_register: int = Field(default=3, ge=1, le=10)
    rate_limit_register_window_seconds: int = Field(default=3600, ge=1, le=7200)
    content_security_policy: str = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' blob:; font-src 'self'; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
    )
    strict_transport_security_max_age: int = Field(default=31536000, ge=0)

    public_base_url: str = "http://localhost:8000"
    encryption_key: str = Field(default="", repr=False)
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = ""
    smtp_password: str = Field(default="", repr=False)
    smtp_from: str = ""
    smtp_tls: Literal["starttls", "ssl", "none"] = "starttls"
    email_outbox_limit: int = Field(default=1000, ge=1, le=10000)
    max_remote_sessions: int = Field(default=3, ge=1, le=10)
    max_console_connections: int = Field(default=6, ge=1, le=30)
    max_websocket_connections: int = Field(default=1000, ge=1, le=10000)
    rate_limit_ws_upgrade: int = Field(default=30, ge=1, le=300)
    rate_limit_ws_control: int = Field(default=600, ge=1, le=6000)
    rate_limit_ws_control_per_second: int = Field(default=30, ge=1, le=300)
    max_screen_frames_per_second: int = Field(default=30, ge=1, le=60)
    max_screen_bytes_per_second: int = Field(default=10_000_000, ge=1, le=100_000_000)
    monitoring_token: str = Field(default="", repr=False)

    # Phase 2: Reliability & Monitoring
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    metrics_enabled: bool = Field(default=True, description="Enable Prometheus metrics")
    health_check_timeout_seconds: float = Field(default=3.0, ge=0.1, le=10.0)
    tracing_enabled: bool = Field(
        default=True, description="Enable OpenTelemetry tracing"
    )
    tracing_endpoint: str = Field(default="", description="OTLP endpoint for tracing")
    tracing_protocol: Literal["http", "grpc"] = "http"
    tracing_insecure: bool = Field(
        default=False, description="Use insecure connection for OTLP"
    )
    shutdown_timeout_seconds: float = Field(
        default=30.0, ge=5.0, le=120.0, description="Timeout for graceful shutdown"
    )
    websocket_drain_timeout_seconds: float = Field(
        default=10.0,
        ge=1.0,
        le=60.0,
        description="Timeout for draining WebSocket connections",
    )
    redis_relay_enabled: bool = Field(
        default=False, description="Enable distributed WebSocket relay via Redis"
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        return init_settings, file_secret_settings, env_settings, dotenv_settings

    @model_validator(mode="after")
    def validate_environment(self):
        if len(self.secret_key.strip()) < 32 or self.secret_key.strip().startswith(
            "dev-secret"
        ):
            raise ValueError(
                "MYDESK_SECRET_KEY must be configured with a random key of at least 32 characters"
            )
        if self.monitoring_token and (
            len(self.monitoring_token) < 32
            or self.monitoring_token in {self.secret_key, self.encryption_key}
        ):
            raise ValueError(
                "MONITORING_TOKEN must be at least 32 characters and distinct from other keys"
            )
        public = urlsplit(self.public_base_url)
        if (
            public.scheme not in {"http", "https"}
            or not public.hostname
            or public.username
            or public.password
            or public.query
            or public.fragment
        ):
            raise ValueError("PUBLIC_BASE_URL must be an absolute HTTP(S) URL")
        if self.encryption_key:
            from cryptography.fernet import Fernet

            try:
                Fernet(self.encryption_key.encode())
            except Exception:
                raise ValueError("ENCRYPTION_KEY must be a Fernet key") from None
            if self.encryption_key == self.secret_key:
                raise ValueError("Encryption and JWT keys must be distinct")
        if not self.is_dev and (
            not self.encryption_key
            or public.scheme != "https"
            or self.smtp_tls == "none"
        ):
            raise ValueError(
                "Staging/production require ENCRYPTION_KEY, HTTPS public URL and SMTP TLS"
            )
        if self.smtp_tls == "none" and self.smtp_host not in {
            "",
            "localhost",
            "127.0.0.1",
            "::1",
        }:
            raise ValueError("Unencrypted SMTP is restricted to local development")
        url = make_url(self.database_url)
        if url.drivername not in {
            "sqlite",
            "sqlite+pysqlite",
            "postgresql",
            "postgresql+psycopg2",
        }:
            raise ValueError(
                "Use SQLite or synchronous PostgreSQL (postgresql+psycopg2)"
            )
        for origin in self.allowed_origins_list:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.path
                or parsed.query
                or parsed.fragment
                or "*" in origin
            ):
                raise ValueError(
                    "CORS origins must be explicit HTTP(S) origins without paths"
                )
        if not self.is_dev:
            if self.debug:
                raise ValueError("DEBUG must be false in staging/production")
            if url.get_backend_name() != "postgresql":
                raise ValueError("PostgreSQL is required in staging/production")
            if urlsplit(self.redis_url).scheme not in {"redis", "rediss"}:
                raise ValueError("Redis is required in staging/production")
            if not self.allowed_origins_list or any(
                not o.startswith("https://") for o in self.allowed_origins_list
            ):
                raise ValueError(
                    "Explicit HTTPS CORS origins are required in staging/production"
                )
            if not self.rate_limit_enabled or not self.check_password_breaches:
                raise ValueError(
                    "Rate limiting and breach checking must be enabled in staging/production"
                )
            if (
                self.min_password_strength < 3
                or self.password_history_count < 3
                or not all(
                    (
                        self.require_password_uppercase,
                        self.require_password_lowercase,
                        self.require_password_number,
                        self.require_password_special,
                    )
                )
            ):
                raise ValueError(
                    "The phase 1 password policy is required in staging/production"
                )
            if self.redis_relay_enabled:
                raise ValueError(
                    "Distributed WebSocket lifecycle is not ready for staging/production; keep redis_relay_enabled=false"
                )
        return self

    @property
    def email_available(self) -> bool:
        return bool(self.encryption_key and self.smtp_host and self.smtp_from)

    @property
    def is_dev(self) -> bool:
        return self.environment == "dev"

    @property
    def allowed_origins_list(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.cors_allowed_origins.split(",")
            if origin.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    from pathlib import Path

    return Settings(
        _secrets_dir="/run/secrets" if Path("/run/secrets").is_dir() else None
    )
