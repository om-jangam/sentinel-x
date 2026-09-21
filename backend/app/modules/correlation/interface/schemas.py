from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.pagination import encode_cursor
from app.modules.correlation.domain.incidents import (
    Incident,
    IncidentDetail,
    IncidentEntity,
    IncidentLink,
    IncidentPage,
    IncidentStatus,
    Resolution,
)


class IncidentRead(BaseModel):
    id: UUID
    title: str
    severity_id: int
    severity: str
    status: IncidentStatus
    resolution: Resolution | None
    techniques: list[str]
    tactics: list[str]
    finding_count: int
    event_count: int
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    version: int = Field(description="Send back when changing the status; a stale version is a 409")

    @classmethod
    def from_entity(cls, incident: Incident) -> IncidentRead:
        return cls(
            id=incident.id,
            title=incident.title,
            severity_id=incident.severity_id,
            severity=incident.severity,
            status=incident.status,
            resolution=incident.resolution,
            techniques=incident.techniques,
            tactics=incident.tactics,
            finding_count=incident.finding_count,
            event_count=incident.event_count,
            first_seen=incident.first_seen,
            last_seen=incident.last_seen,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            closed_at=incident.closed_at,
            version=incident.version,
        )


class IncidentPageResponse(BaseModel):
    items: list[IncidentRead]
    next_cursor: str | None = None

    @classmethod
    def from_page(cls, page: IncidentPage) -> IncidentPageResponse:
        return cls(
            items=[IncidentRead.from_entity(incident) for incident in page.items],
            next_cursor=encode_cursor(page.next_cursor.encode()) if page.next_cursor else None,
        )


class MatchedEntityRead(BaseModel):
    key: str = Field(description="`type:value`, e.g. `ip:203.0.113.45`")
    incident_events: list[str] = Field(description="event_uids already in the incident that show this entity")
    new_events: list[str] = Field(description="event_uids of the linked item that show this entity")


class IncidentLinkRead(BaseModel):
    id: UUID
    kind: str = Field(description="`finding` or `event`")
    rule: str = Field(description="The correlation rule that created the link")
    reason: str
    finding_id: UUID | None
    event_uid: str | None
    evidence: list[str] = Field(description="event_uids this link brings into the incident")
    matched: list[MatchedEntityRead]
    detail: dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    created_at: datetime

    @classmethod
    def from_entity(cls, link: IncidentLink) -> IncidentLinkRead:
        return cls(
            id=link.id,
            kind=link.kind.value,
            rule=link.rule.value,
            reason=link.reason,
            finding_id=link.finding_id,
            event_uid=link.event_uid,
            evidence=list(link.evidence),
            matched=[
                MatchedEntityRead(key=m.key, incident_events=list(m.incident_events), new_events=list(m.new_events))
                for m in link.matched
            ],
            detail=link.detail,
            first_seen=link.first_seen,
            last_seen=link.last_seen,
            created_at=link.created_at,
        )


class IncidentEntityRead(BaseModel):
    key: str
    type: str
    value: str
    links: bool = Field(description="Whether this entity can join findings into the incident")
    first_seen: datetime
    last_seen: datetime
    events: list[str] = Field(description="event_uids it was seen in (at most 20)")

    @classmethod
    def from_entity(cls, entity: IncidentEntity) -> IncidentEntityRead:
        return cls(
            key=entity.key,
            type=entity.type,
            value=entity.value,
            links=entity.links,
            first_seen=entity.first_seen,
            last_seen=entity.last_seen,
            events=entity.events,
        )


class IncidentDetailRead(IncidentRead):
    assessment: list[dict[str, Any]]
    links: list[IncidentLinkRead]
    entities: list[IncidentEntityRead]

    @classmethod
    def from_detail(cls, detail: IncidentDetail) -> IncidentDetailRead:
        return cls(
            **IncidentRead.from_entity(detail.incident).model_dump(),
            assessment=detail.incident.assessment,
            links=[IncidentLinkRead.from_entity(link) for link in detail.links],
            entities=[IncidentEntityRead.from_entity(entity) for entity in detail.entities],
        )


class IncidentStatusChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: IncidentStatus
    resolution: Resolution | None = None
    version: int = Field(ge=1, description="The version you last read")
