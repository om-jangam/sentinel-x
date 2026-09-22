"""Reading incidents and changing their status. Correlation owns their contents; analysts own their status."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from uuid import UUID

from app.core.audit.port import AuditEvent
from app.core.clock import Clock, utcnow
from app.core.errors import NotFoundError
from app.core.ids import uuid7
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.modules.correlation.domain.evidence import EvidenceEvent
from app.modules.correlation.domain.graph import EntityGraph, build_graph
from app.modules.correlation.domain.incidents import (
    Incident,
    IncidentDetail,
    IncidentLink,
    IncidentNote,
    IncidentPage,
    IncidentQuery,
    IncidentStatus,
    Resolution,
)
from app.modules.correlation.domain.ports import CorrelationUnitOfWork
from app.modules.correlation.domain.timeline import TimelineStep, build_timeline


@dataclass(frozen=True, slots=True)
class IncidentEvidence:
    """The incident's evidence events: digests where correlation had the event, and the ones it didn't."""

    events: list[EvidenceEvent]
    cited_by: dict[str, list[str]]  # event_uid → link ids
    unresolved: list[str]  # cited by a link, but no digest was recorded (see the module doc)


def _evidence(links: list[IncidentLink], events: list[EvidenceEvent]) -> IncidentEvidence:
    cited_by: dict[str, list[str]] = {}
    for link in links:
        for uid in link.evidence:
            cited_by.setdefault(uid, []).append(str(link.id))
    recorded = {event.event_uid for event in events}
    return IncidentEvidence(
        events=events, cited_by=cited_by, unresolved=sorted(uid for uid in cited_by if uid not in recorded)
    )


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

    async def evidence(self, principal: Principal, incident_id: UUID) -> IncidentEvidence:
        principal.require(Permission.INCIDENT_READ)
        incident = await self._require(principal.org_id, incident_id)
        links = await self._uow.incidents.links(incident.id)
        events = await self._uow.incidents.evidence(incident.id)
        if not principal.has(Permission.EVENT_READ):
            # The excerpt is the original record itself: only those who may read events see it.
            events = [replace(event, raw=None) for event in events]
        return _evidence(links, events)

    async def timeline(self, principal: Principal, incident_id: UUID) -> tuple[list[TimelineStep], IncidentEvidence]:
        principal.require(Permission.INCIDENT_READ)
        incident = await self._require(principal.org_id, incident_id)
        links = await self._uow.incidents.links(incident.id)
        evidence = _evidence(links, await self._uow.incidents.evidence(incident.id))
        return build_timeline(evidence.events, links), evidence

    async def graph(self, principal: Principal, incident_id: UUID) -> EntityGraph:
        principal.require(Permission.INCIDENT_READ)
        incident = await self._require(principal.org_id, incident_id)
        return build_graph(await self._uow.incidents.evidence(incident.id))

    async def notes(self, principal: Principal, incident_id: UUID) -> list[IncidentNote]:
        principal.require(Permission.INCIDENT_READ)
        incident = await self._require(principal.org_id, incident_id)
        return await self._uow.incidents.notes(incident.id)

    async def add_note(self, principal: Principal, incident_id: UUID, body: str) -> IncidentNote:
        principal.require(Permission.INCIDENT_UPDATE)
        incident = await self._require(principal.org_id, incident_id)
        note = IncidentNote(
            id=uuid7(),
            org_id=principal.org_id,
            incident_id=incident.id,
            author_id=principal.user_id,
            author_email=principal.email,
            body=body,
            created_at=self._clock(),
        )
        await self._uow.incidents.add_note(note)
        await self._uow.audit.record(
            AuditEvent(
                org_id=principal.org_id,
                action="incident.note_added",
                resource_type="incident",
                resource_id=str(incident.id),
                actor_id=principal.user_id,
                # The hash lets the audit trail show a stored note was never altered, without copying it.
                after={
                    "note_id": str(note.id),
                    "length": len(note.body),
                    "sha256": hashlib.sha256(note.body.encode("utf-8")).hexdigest(),
                },
            )
        )
        await self._uow.commit()
        return note

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
