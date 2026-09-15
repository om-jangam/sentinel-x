from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import update

from app.conftest import Seeded, bearer
from app.core.audit.models import AuditLogModel
from app.core.container import Container


async def test_liveness_needs_no_auth(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_readiness_reports_dependencies(client: httpx.AsyncClient) -> None:
    response = await client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "checks": {"database": "ok", "redis": "not_configured"}}


async def test_readiness_fails_when_database_is_down(
    client: httpx.AsyncClient, container: Container, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(container.database, "ping", AsyncMock(return_value=False))
    response = await client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["checks"]["database"] == "failing"


async def test_metrics_use_route_templates(client: httpx.AsyncClient, seeded: Seeded) -> None:
    await client.get(f"/api/v1/users/{seeded.admin.id}")
    body = (await client.get("/metrics")).text
    assert "sentinelx_http_requests_total" in body
    assert 'route="/api/v1/users/{user_id}"' in body
    assert str(seeded.admin.id) not in body, "raw ids would explode label cardinality"


async def test_health_and_config_require_platform_read(client: httpx.AsyncClient, admin_token: str) -> None:
    assert (await client.get("/api/v1/health")).status_code == 401
    health = (await client.get("/api/v1/health", headers=bearer(admin_token))).json()
    assert health["status"] == "ok"
    assert health["environment"] == "test"

    config = (await client.get("/api/v1/config", headers=bearer(admin_token))).json()
    assert config["access_token_ttl_seconds"] == 600
    serialized = str(config).lower()
    assert "private" not in serialized
    assert "database_url" not in serialized


async def test_audit_listing_filters_and_paginates(client: httpx.AsyncClient, admin_token: str) -> None:
    everything = (await client.get("/api/v1/audit?limit=200", headers=bearer(admin_token))).json()["items"]
    assert everything
    indexes = [e["chain_index"] for e in everything]
    assert indexes == sorted(indexes, reverse=True)

    roles_only = (await client.get("/api/v1/audit?resource_type=role", headers=bearer(admin_token))).json()["items"]
    assert roles_only
    assert {e["resource_type"] for e in roles_only} == {"role"}

    page = (await client.get("/api/v1/audit?limit=3", headers=bearer(admin_token))).json()
    following = (
        await client.get(f"/api/v1/audit?limit=3&cursor={page['next_cursor']}", headers=bearer(admin_token))
    ).json()
    assert following["items"][0]["chain_index"] == page["items"][-1]["chain_index"] - 1


async def test_audit_verification_detects_tampering(
    client: httpx.AsyncClient, admin_token: str, container: Container, seeded: Seeded
) -> None:
    verified = (await client.get("/api/v1/audit/verify", headers=bearer(admin_token))).json()
    assert verified["valid"] is True
    assert verified["entries_checked"] > 0

    if container.database.dialect_name == "postgresql":
        return  # UPDATE is blocked outright by the append-only trigger there

    async with container.database.sessionmaker() as session:
        await session.execute(
            update(AuditLogModel)
            .where(AuditLogModel.org_id == seeded.org.id, AuditLogModel.chain_index == 0)
            .values(action="org.nothing_to_see_here")
        )
        await session.commit()

    tampered = (await client.get("/api/v1/audit/verify", headers=bearer(admin_token))).json()
    assert tampered["valid"] is False
    assert tampered["broken_at_index"] == 0


async def test_security_headers_and_correlation_ids(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/me", headers={"X-Correlation-ID": "trace-abc.123"})
    assert response.headers["x-correlation-id"] == "trace-abc.123"
    assert response.json()["correlation_id"] == "trace-abc.123"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in response.headers["content-security-policy"]

    injected = await client.get("/healthz", headers={"X-Correlation-ID": "bad value\r\nSet-Cookie: x"})
    assert injected.headers["x-correlation-id"] != "bad value\r\nSet-Cookie: x"


async def test_unknown_routes_are_problem_documents(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    body = response.json()
    assert body["type"].endswith("/not-found")
    assert body["instance"] == "/api/v1/does-not-exist"


async def test_cors_allows_only_configured_origins(client: httpx.AsyncClient) -> None:
    allowed = await client.options(
        "/api/v1/auth/login",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert allowed.headers.get("access-control-allow-credentials") == "true"

    denied = await client.options(
        "/api/v1/auth/login",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in denied.headers
