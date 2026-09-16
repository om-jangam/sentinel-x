from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Environment, Settings


def _production(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "_env_file": None,
        "environment": Environment.PRODUCTION,
        "database_url": "postgresql+asyncpg://u:p@db/sx",
        "redis_url": "redis://redis:6379/0",
        "jwt_private_key_file": "/run/secrets/jwt_private.pem",
        "opensearch_url": "https://opensearch:9200",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_secure_production_configuration_is_accepted() -> None:
    assert _production().is_production


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"jwt_private_key_file": None}, "JWT signing key"),
        ({"redis_url": None}, "REDIS_URL"),
        ({"cookie_secure": False}, "COOKIE_SECURE"),
        ({"database_url": "sqlite+aiosqlite:///x.db"}, "SQLite"),
        ({"argon2_memory_cost_kib": 1024}, "argon2 memory"),
        ({"cors_origins": ["*"]}, "wildcard CORS"),
        ({"opensearch_url": None}, "OPENSEARCH_URL"),
        ({"opensearch_verify_certs": False}, "OPENSEARCH_VERIFY_CERTS"),
    ],
)
def test_insecure_production_configuration_is_refused(override: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        _production(**override)
