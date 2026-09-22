"""12-factor configuration (Pydantic Settings). Every variable is documented in `.env.example`."""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


# OWASP Password Storage Cheat Sheet minimums for argon2id.
_MIN_ARGON2_MEMORY_KIB = 19_456
_MIN_ARGON2_TIME_COST = 2


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINELX_", env_file=".env", extra="ignore")

    environment: Environment = Environment.DEVELOPMENT
    app_name: str = "Sentinel-X"
    log_level: str = "INFO"
    log_json: bool = True

    # --- persistence
    database_url: str = "postgresql+asyncpg://sentinelx:sentinelx@localhost:5432/sentinelx"
    database_echo: bool = False
    redis_url: str | None = None

    # --- event store (ADR-0011); ingestion and event search are unavailable until this is set
    opensearch_url: str | None = None
    opensearch_username: str | None = None
    opensearch_password: SecretStr | None = None
    opensearch_verify_certs: bool = True
    opensearch_shards: int = Field(default=1, ge=1)
    opensearch_replicas: int = Field(default=0, ge=0)
    event_retention_days: int = Field(default=90, ge=1, le=3650)

    # --- threat intelligence (ADR-0018); every provider is optional and none is required
    ti_local_feed: Path | None = None  # CSV or JSON indicator file
    otx_api_key: SecretStr | None = None  # AlienVault OTX; external lookups are off without a key
    otx_base_url: str = "https://otx.alienvault.com"
    ti_cache_hours: int = Field(default=24, ge=1, le=720)
    ti_timeout_seconds: float = Field(default=5.0, gt=0, le=30)

    # --- ingestion
    ingest_rate_limit: int = Field(default=600, ge=1)
    ingest_rate_window_seconds: int = Field(default=60, ge=1)

    # --- HTTP
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    expose_api_docs: bool = True

    # --- tokens (ADR-0010)
    jwt_private_key_file: Path | None = None
    jwt_private_key: SecretStr | None = None
    jwt_previous_public_key_file: Path | None = None
    jwt_issuer: str = "sentinel-x"
    jwt_audience: str = "sentinel-x-api"
    access_token_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    refresh_token_ttl_seconds: int = Field(default=7 * 24 * 3600, ge=3600, le=30 * 24 * 3600)
    refresh_cookie_name: str = "sx_refresh"
    cookie_secure: bool = True

    # --- password hashing (argon2id)
    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_cost_kib: int = Field(default=65_536, ge=8)
    argon2_parallelism: int = Field(default=4, ge=1)

    # --- abuse protection
    login_rate_limit: int = Field(default=10, ge=1)
    login_rate_window_seconds: int = Field(default=300, ge=1)

    # --- observability
    metrics_enabled: bool = True
    otel_enabled: bool = False
    otel_exporter_endpoint: str | None = None

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    @model_validator(mode="after")
    def _production_guards(self) -> Settings:
        """Refuse to boot production with development-grade security settings."""
        if not self.is_production:
            return self
        problems: list[str] = []
        if self.jwt_private_key is None and self.jwt_private_key_file is None:
            problems.append("a JWT signing key (SENTINELX_JWT_PRIVATE_KEY[_FILE]) is required")
        if not self.redis_url:
            problems.append("SENTINELX_REDIS_URL is required (token blocklist, rate limits)")
        if not self.cookie_secure:
            problems.append("SENTINELX_COOKIE_SECURE must be true")
        if self.database_url.startswith("sqlite"):
            problems.append("SQLite is not a production database")
        if self.argon2_memory_cost_kib < _MIN_ARGON2_MEMORY_KIB:
            problems.append(f"argon2 memory cost must be >= {_MIN_ARGON2_MEMORY_KIB} KiB")
        if self.argon2_time_cost < _MIN_ARGON2_TIME_COST:
            problems.append(f"argon2 time cost must be >= {_MIN_ARGON2_TIME_COST}")
        if "*" in self.cors_origins:
            problems.append("wildcard CORS origin is not allowed")
        if not self.opensearch_url:
            problems.append("SENTINELX_OPENSEARCH_URL is required (event store)")
        elif self.opensearch_url.startswith("https") and not self.opensearch_verify_certs:
            problems.append("SENTINELX_OPENSEARCH_VERIFY_CERTS must be true")
        if not self.otx_base_url.startswith("https://"):
            problems.append("SENTINELX_OTX_BASE_URL must use https")
        if problems:
            raise ValueError("insecure production configuration: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
