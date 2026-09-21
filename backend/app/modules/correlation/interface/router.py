from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.http.deps import get_session, require_permission
from app.core.pagination import decode_cursor
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.modules.correlation.application.incident_service import IncidentService
from app.modules.correlation.domain.incidents import MAX_PAGE_SIZE, IncidentCursor, IncidentQuery, IncidentStatus
from app.modules.correlation.infrastructure.unit_of_work import SqlCorrelationUnitOfWork
from app.modules.correlation.interface.schemas import (
    IncidentDetailRead,
    IncidentPageResponse,
    IncidentRead,
    IncidentStatusChange,
)


def get_incident_service(session: AsyncSession = Depends(get_session)) -> IncidentService:
    return IncidentService(SqlCorrelationUnitOfWork(session))


router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


@router.get("", summary="List incidents, most recent activity first")
async def list_incidents(
    time_from: datetime | None = Query(default=None, description="Earliest last_seen (inclusive)"),
    time_to: datetime | None = Query(default=None, description="Latest last_seen (inclusive)"),
    status: IncidentStatus | None = Query(default=None),
    severity_min: int | None = Query(default=None, ge=1, le=5),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.INCIDENT_READ)),
    service: IncidentService = Depends(get_incident_service),
) -> IncidentPageResponse:
    query = IncidentQuery(
        time_from=time_from,
        time_to=time_to,
        status=status,
        severity_min=severity_min,
        limit=limit,
        cursor=IncidentCursor.decode(decode_cursor(cursor)) if cursor else None,
    )
    return IncidentPageResponse.from_page(await service.search(principal, query))


@router.get("/{incident_id}", summary="Fetch an incident with its links, entities and assessment")
async def get_incident(
    incident_id: UUID,
    principal: Principal = Depends(require_permission(Permission.INCIDENT_READ)),
    service: IncidentService = Depends(get_incident_service),
) -> IncidentDetailRead:
    return IncidentDetailRead.from_detail(await service.detail(principal, incident_id))


@router.patch("/{incident_id}", summary="Change the status of an incident (audited)")
async def change_incident_status(
    incident_id: UUID,
    body: IncidentStatusChange,
    principal: Principal = Depends(require_permission(Permission.INCIDENT_UPDATE)),
    service: IncidentService = Depends(get_incident_service),
) -> IncidentRead:
    incident = await service.change_status(
        principal,
        incident_id,
        status=body.status,
        resolution=body.resolution,
        expected_version=body.version,
    )
    return IncidentRead.from_entity(incident)


routers = (router,)
