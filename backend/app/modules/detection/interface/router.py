from __future__ import annotations

from datetime import datetime
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ServiceUnavailableError
from app.core.http.deps import get_session, require_permission
from app.core.pagination import decode_cursor
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.modules.detection.application.finding_service import FindingQueryService, RuleCatalog
from app.modules.detection.domain.findings import MAX_PAGE_SIZE, FindingCursor, FindingQuery
from app.modules.detection.domain.rules import RuleSet
from app.modules.detection.infrastructure.unit_of_work import SqlDetectionUnitOfWork
from app.modules.detection.interface.schemas import FindingPageResponse, FindingRead, RuleRead


def get_finding_service(session: AsyncSession = Depends(get_session)) -> FindingQueryService:
    return FindingQueryService(SqlDetectionUnitOfWork(session))


def get_rule_catalog(request: Request) -> RuleCatalog:
    rules = getattr(request.app.state, "detection_rules", None)
    if rules is None:  # wiring bug, not a client error
        raise ServiceUnavailableError("Detection rules are not loaded")
    return RuleCatalog(cast(RuleSet, rules))


findings_router = APIRouter(prefix="/api/v1/findings", tags=["detection"])
rules_router = APIRouter(prefix="/api/v1/detection", tags=["detection"])


@findings_router.get("", summary="List findings, newest first")
async def list_findings(
    time_from: datetime | None = Query(default=None, description="Earliest last_seen (inclusive)"),
    time_to: datetime | None = Query(default=None, description="Latest last_seen (inclusive)"),
    severity_min: int | None = Query(default=None, ge=1, le=5),
    rule_id: str | None = Query(default=None, max_length=64),
    technique: str | None = Query(default=None, max_length=16, examples=["T1110.003"]),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.FINDING_READ)),
    service: FindingQueryService = Depends(get_finding_service),
) -> FindingPageResponse:
    query = FindingQuery(
        time_from=time_from,
        time_to=time_to,
        severity_min=severity_min,
        rule_id=rule_id,
        technique=technique.upper() if technique else None,
        limit=limit,
        cursor=FindingCursor.decode(decode_cursor(cursor)) if cursor else None,
    )
    return FindingPageResponse.from_page(await service.search(principal, query))


@findings_router.get("/{finding_id}", summary="Fetch one finding with its evidence event ids")
async def get_finding(
    finding_id: UUID,
    principal: Principal = Depends(require_permission(Permission.FINDING_READ)),
    service: FindingQueryService = Depends(get_finding_service),
) -> FindingRead:
    return FindingRead.from_entity(await service.get(principal, finding_id))


@rules_router.get("/rules", summary="List the loaded detection rules")
async def list_rules(
    principal: Principal = Depends(require_permission(Permission.RULE_READ)),
    catalog: RuleCatalog = Depends(get_rule_catalog),
) -> list[RuleRead]:
    return [RuleRead.from_rule(rule) for rule in catalog.list_rules(principal)]


@rules_router.get("/rules/{rule_id}", summary="Inspect one detection rule")
async def get_rule(
    rule_id: str,
    principal: Principal = Depends(require_permission(Permission.RULE_READ)),
    catalog: RuleCatalog = Depends(get_rule_catalog),
) -> RuleRead:
    return RuleRead.from_rule(catalog.get_rule(principal, rule_id))


routers = (findings_router, rules_router)
