from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clock import utcnow
from app.core.http.deps import get_session, require_permission
from app.core.pagination import decode_cursor
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.modules.correlation.application.incident_service import IncidentService
from app.modules.correlation.domain.exports import attack_flow, navigator_layer
from app.modules.correlation.domain.incidents import MAX_PAGE_SIZE, IncidentCursor, IncidentQuery, IncidentStatus
from app.modules.correlation.infrastructure.unit_of_work import SqlCorrelationUnitOfWork
from app.modules.correlation.interface.schemas import (
    EvidenceResponse,
    GraphResponse,
    IncidentDetailRead,
    IncidentPageResponse,
    IncidentRead,
    IncidentStatusChange,
    NoteCreate,
    NoteRead,
    TimelineResponse,
    TimelineStepRead,
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


@router.get("/{incident_id}/timeline", summary="The attack timeline: evidence events in order, grouped into steps")
async def get_timeline(
    incident_id: UUID,
    principal: Principal = Depends(require_permission(Permission.INCIDENT_READ)),
    service: IncidentService = Depends(get_incident_service),
) -> TimelineResponse:
    steps, evidence = await service.timeline(principal, incident_id)
    return TimelineResponse(
        steps=[TimelineStepRead.from_step(step) for step in steps], unresolved_events=evidence.unresolved
    )


@router.get(
    "/{incident_id}/exports/attack-navigator",
    summary="The incident as a MITRE ATT&CK Navigator layer (v4.5), scored by events per technique",
)
async def get_navigator_layer(
    incident_id: UUID,
    principal: Principal = Depends(require_permission(Permission.INCIDENT_READ)),
    service: IncidentService = Depends(get_incident_service),
) -> dict[str, Any]:
    return navigator_layer(await service.detail(principal, incident_id), generated=utcnow())


@router.get(
    "/{incident_id}/exports/attack-flow",
    summary="The incident as a STIX 2.1 Attack Flow bundle; each action cites its events",
)
async def get_attack_flow(
    incident_id: UUID,
    principal: Principal = Depends(require_permission(Permission.INCIDENT_READ)),
    service: IncidentService = Depends(get_incident_service),
) -> dict[str, Any]:
    detail = await service.detail(principal, incident_id)
    steps, _ = await service.timeline(principal, incident_id)
    return attack_flow(detail, steps, generated=utcnow())


@router.get("/{incident_id}/graph", summary="The entity graph: every edge cites the events that state it")
async def get_graph(
    incident_id: UUID,
    principal: Principal = Depends(require_permission(Permission.INCIDENT_READ)),
    service: IncidentService = Depends(get_incident_service),
) -> GraphResponse:
    return GraphResponse.from_graph(await service.graph(principal, incident_id))


@router.get("/{incident_id}/evidence", summary="Digests of the evidence events and the links that cite them")
async def get_evidence(
    incident_id: UUID,
    principal: Principal = Depends(require_permission(Permission.INCIDENT_READ)),
    service: IncidentService = Depends(get_incident_service),
) -> EvidenceResponse:
    return EvidenceResponse.from_evidence(await service.evidence(principal, incident_id))


@router.get("/{incident_id}/notes", summary="Analyst notes, oldest first")
async def list_notes(
    incident_id: UUID,
    principal: Principal = Depends(require_permission(Permission.INCIDENT_READ)),
    service: IncidentService = Depends(get_incident_service),
) -> list[NoteRead]:
    return [NoteRead.from_note(note) for note in await service.notes(principal, incident_id)]


@router.post("/{incident_id}/notes", status_code=status.HTTP_201_CREATED, summary="Add an analyst note (audited)")
async def add_note(
    incident_id: UUID,
    body: NoteCreate,
    principal: Principal = Depends(require_permission(Permission.INCIDENT_UPDATE)),
    service: IncidentService = Depends(get_incident_service),
) -> NoteRead:
    return NoteRead.from_note(await service.add_note(principal, incident_id, body.body))


routers = (router,)
