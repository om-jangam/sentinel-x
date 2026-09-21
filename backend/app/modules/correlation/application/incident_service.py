"""Reading incidents and changing their status. Correlation owns their contents; analysts own their status."""

from __future__ import annotations

from uuid import UUID

from app.core.audit.port import AuditEvent
from app.core.clock import Clock, utcnow
from app.core.errors import NotFoundError
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.modules.correlation.domain.incidents import (
    Incident,
    IncidentDetail,
    IncidentPage,
    IncidentQuery,
    IncidentStatus,
    Resolution,
)
from app.modules.correlation.domain.ports import CorrelationUnitOfWork


class IncidentService:
    def __init__(self, uow: CorrelationUnitOfWork, *, clock: Clock = utcnow) -> None:
        self._uow = uow
        self._clock = clock

    async def search(self, principal: Principal, query: IncidentQuery) -> IncidentPage:
        principal.require(Permission.INCIDENT_READ)
        return await self._uow.incidents.search(principal.org_id, query)

    async def detail(self, principal: Principal, incident_id: UUID) -> IncidentDetail:
        principal.require(Permission.INCIDENT_READ)
        incident = await self._require(principal.org_id, incident_id)
        links = await self._uow.incidents.links(incident.id)
        entities = await self._uow.incidents.entities(incident.id)
        return IncidentDetail(incident=incident, links=links, entities=entities)

    async def change_status(
        self,
        principal: Principal,
        incident_id: UUID,
        *,
        status: IncidentStatus,
        resolution: Resolution | None,
        expected_version: int,
    ) -> Incident:
        principal.require(Permission.INCIDENT_UPDATE)
        incident = await self._require(principal.org_id, incident_id)
        # Closing decides what happened, and reopening overrides that decision: both need resolve rights.
        if status is IncidentStatus.CLOSED or incident.status is IncidentStatus.CLOSED:
            principal.require(Permission.INCIDENT_RESOLVE)
        before = incident.audit_view()
        incident.change_status(status, resolution, expected_version=expected_version, now=self._clock())
        await self._uow.incidents.update(incident)
        await self._uow.audit.record(
            AuditEvent(
                org_id=principal.org_id,
                action="incident.status_changed",
                resource_type="incident",
                resource_id=str(incident.id),
                actor_id=principal.user_id,
                before=before,
                after=incident.audit_view(),
            )
        )
        await self._uow.commit()
        return incident

    async def _require(self, org_id: UUID, incident_id: UUID) -> Incident:
        incident = await self._uow.incidents.get(org_id, incident_id)
        if incident is None:
            raise NotFoundError("Incident not found")
        return incident
