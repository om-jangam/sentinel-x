from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.core.container import Container
from app.core.errors import NotFoundError, ValidationFailedError
from app.core.http.deps import get_container, get_session, require_permission
from app.core.observability.metrics import render_latest
from app.core.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, Page, decode_cursor, encode_cursor
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.modules.platform.application.audit_service import AuditFilter, AuditQueryService
from app.modules.platform.infrastructure.audit_reader import SqlAuditLogReader

CheckState = Literal["ok", "failing", "not_configured"]


class ReadinessReport(BaseModel):
    status: Literal["ok", "degraded"]
    checks: dict[str, CheckState]


class HealthReport(ReadinessReport):
    version: str
    environment: str


class PlatformConfig(BaseModel):
    """Non-secret runtime configuration only."""

    version: str
    environment: str
    access_token_ttl_seconds: int
    refresh_token_ttl_seconds: int
    login_rate_limit: int
    login_rate_window_seconds: int
    redis_configured: bool
    metrics_enabled: bool
    tracing_enabled: bool
    jwt_signing_kid: str


class AuditEntryRead(BaseModel):
    id: UUID
    chain_index: int
    ts: datetime
    actor_id: UUID | None
    actor_type: str
    action: str
    resource_type: str
    resource_id: str | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    context: dict[str, Any] | None
    correlation_id: str | None
    entry_hash: str = Field(description="SHA-256 link in the tamper-evident chain")


class AuditVerificationRead(BaseModel):
    valid: bool
    entries_checked: int
    head_hash: str | None
    broken_at_index: int | None
    reason: str | None


async def _readiness(container: Container) -> ReadinessReport:
    redis = await container.ping_redis()
    checks: dict[str, CheckState] = {
        "database": "ok" if await container.database.ping() else "failing",
        "redis": "not_configured" if redis is None else ("ok" if redis else "failing"),
    }
    return ReadinessReport(
        status="degraded" if "failing" in checks.values() else "ok",
        checks=checks,
    )


probes_router = APIRouter(tags=["platform"], include_in_schema=False)


@probes_router.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness: the process is serving. Never touches dependencies."""
    return {"status": "ok"}


@probes_router.get("/readyz")
async def readyz(container: Container = Depends(get_container)) -> JSONResponse:
    report = await _readiness(container)
    code = status.HTTP_200_OK if report.status == "ok" else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(report.model_dump(), status_code=code)


@probes_router.get("/metrics")
async def metrics(container: Container = Depends(get_container)) -> Response:
    if not container.settings.metrics_enabled:
        raise NotFoundError()
    body, content_type = render_latest()
    return Response(content=body, media_type=content_type)


platform_router = APIRouter(prefix="/api/v1", tags=["platform"])


@platform_router.get("/health", response_model=HealthReport)
async def health(
    _: Principal = Depends(require_permission(Permission.PLATFORM_READ)),
    container: Container = Depends(get_container),
) -> HealthReport:
    report = await _readiness(container)
    return HealthReport(**report.model_dump(), version=__version__, environment=container.settings.environment.value)


@platform_router.get("/config", response_model=PlatformConfig)
async def config(
    _: Principal = Depends(require_permission(Permission.PLATFORM_READ)),
    container: Container = Depends(get_container),
) -> PlatformConfig:
    s = container.settings
    return PlatformConfig(
        version=__version__,
        environment=s.environment.value,
        access_token_ttl_seconds=s.access_token_ttl_seconds,
        refresh_token_ttl_seconds=s.refresh_token_ttl_seconds,
        login_rate_limit=s.login_rate_limit,
        login_rate_window_seconds=s.login_rate_window_seconds,
        redis_configured=container.redis is not None,
        metrics_enabled=s.metrics_enabled,
        tracing_enabled=s.otel_enabled,
        jwt_signing_kid=container.keyring.signing_kid,
    )


def get_audit_service(session: AsyncSession = Depends(get_session)) -> AuditQueryService:
    return AuditQueryService(SqlAuditLogReader(session))


@platform_router.get("/audit", response_model=Page[AuditEntryRead])
async def list_audit(
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
    action: Annotated[str | None, Query(max_length=128)] = None,
    resource_type: Annotated[str | None, Query(max_length=64)] = None,
    actor_id: UUID | None = None,
    principal: Principal = Depends(require_permission(Permission.AUDIT_READ)),
    service: AuditQueryService = Depends(get_audit_service),
) -> Page[AuditEntryRead]:
    before_index: int | None = None
    if cursor is not None:
        try:
            before_index = int(decode_cursor(cursor))
        except ValueError as exc:
            raise ValidationFailedError("Invalid pagination cursor") from exc
    page = await service.list_entries(
        principal,
        limit=limit,
        before_index=before_index,
        filters=AuditFilter(action=action, resource_type=resource_type, actor_id=actor_id),
    )
    return Page[AuditEntryRead](
        items=[AuditEntryRead.model_validate(entry, from_attributes=True) for entry in page.items],
        next_cursor=None if page.next_before_index is None else encode_cursor(str(page.next_before_index)),
    )


@platform_router.get("/audit/verify", response_model=AuditVerificationRead)
async def verify_audit(
    principal: Principal = Depends(require_permission(Permission.AUDIT_READ)),
    service: AuditQueryService = Depends(get_audit_service),
) -> AuditVerificationRead:
    result = await service.verify(principal)
    return AuditVerificationRead(
        valid=result.valid,
        entries_checked=result.entries_checked,
        head_hash=result.head_hash,
        broken_at_index=result.broken_at_index,
        reason=result.reason,
    )


routers = (probes_router, platform_router)
