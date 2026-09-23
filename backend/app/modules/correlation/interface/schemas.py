from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.pagination import encode_cursor
from app.modules.correlation.application.incident_service import IncidentEvidence, NoveltyReport
from app.modules.correlation.domain.graph import EntityGraph
from app.modules.correlation.domain.incidents import (
    MAX_NOTE_LENGTH,
    Incident,
    IncidentDetail,
    IncidentEntity,
    IncidentLink,
    IncidentNote,
    IncidentPage,
    IncidentStatus,
    Resolution,
)
from app.modules.correlation.domain.timeline import TimelineStep


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


class StepCitationRead(BaseModel):
    link_id: UUID
    rule: str
    title: str
    techniques: list[str]


class TimelineStepRead(BaseModel):
    id: str = Field(description="event_uid of the first event in the step")
    first_seen: datetime
    last_seen: datetime
    action: str
    outcome: str | None
    host: str | None
    users: list[str]
    process: str | None
    parent_process: str | None
    command_lines: list[str]
    remote: str | None = Field(description="The other side: the client of a logon, or the far end of a connection")
    remote_ports: list[int]
    domains: list[str]
    citations: list[StepCitationRead] = Field(description="Findings and correlation links citing these events")
    events: list[str] = Field(description="event_uids this step stands for, in time order")
    entities: list[str]

    @classmethod
    def from_step(cls, step: TimelineStep) -> TimelineStepRead:
        return cls(
            id=step.id,
            first_seen=step.first_seen,
            last_seen=step.last_seen,
            action=step.action,
            outcome=step.outcome,
            host=step.host,
            users=list(step.users),
            process=step.process,
            parent_process=step.parent_process,
            command_lines=list(step.command_lines),
            remote=step.remote,
            remote_ports=list(step.remote_ports),
            domains=list(step.domains),
            citations=[
                StepCitationRead(link_id=UUID(c.link_id), rule=c.rule, title=c.title, techniques=list(c.techniques))
                for c in step.citations
            ],
            events=list(step.events),
            entities=list(step.entities),
        )


class TimelineResponse(BaseModel):
    steps: list[TimelineStepRead]
    unresolved_events: list[str] = Field(
        description="Evidence event_uids with no recorded digest, so absent from the timeline and graph"
    )


class GraphNodeRead(BaseModel):
    key: str
    type: str
    value: str
    external: bool
    first_seen: datetime
    last_seen: datetime
    event_count: int
    events: list[str] = Field(description="event_uids it appears in (at most 20)")


class GraphEdgeRead(BaseModel):
    id: str
    source: str
    target: str
    relation: str
    label: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    events: list[str] = Field(description="event_uids stating this relationship (at most 20)")
    detail: dict[str, Any]


class GraphResponse(BaseModel):
    nodes: list[GraphNodeRead]
    edges: list[GraphEdgeRead]

    @classmethod
    def from_graph(cls, graph: EntityGraph) -> GraphResponse:
        return cls(
            nodes=[
                GraphNodeRead(
                    key=n.key,
                    type=n.type,
                    value=n.value,
                    external=n.external,
                    first_seen=n.first_seen,
                    last_seen=n.last_seen,
                    event_count=n.event_count,
                    events=n.events,
                )
                for n in graph.nodes
            ],
            edges=[
                GraphEdgeRead(
                    id=e.id,
                    source=e.source,
                    target=e.target,
                    relation=e.relation,
                    label=e.label,
                    first_seen=e.first_seen,
                    last_seen=e.last_seen,
                    event_count=e.event_count,
                    events=e.events,
                    detail=e.detail,
                )
                for e in graph.edges
            ],
        )


class EvidenceEventRead(BaseModel):
    event_uid: str
    time: datetime
    class_uid: int
    activity_id: int | None
    status_id: int | None
    action: str
    outcome: str | None
    message: str | None
    raw: str | None = Field(
        description="Excerpt of the original record (at most 2,048 characters); null without event:read"
    )
    roles: dict[str, list[str]]
    detail: dict[str, Any]
    cited_by: list[UUID] = Field(description="Links that cite this event")


class EvidenceResponse(BaseModel):
    events: list[EvidenceEventRead]
    unresolved_events: list[str]

    @classmethod
    def from_evidence(cls, evidence: IncidentEvidence) -> EvidenceResponse:
        return cls(
            events=[
                EvidenceEventRead(
                    event_uid=e.event_uid,
                    time=e.time,
                    class_uid=e.class_uid,
                    activity_id=e.activity_id,
                    status_id=e.status_id,
                    action=e.action,
                    outcome=e.outcome,
                    message=e.message,
                    raw=e.raw,
                    roles=e.roles,
                    detail=e.detail,
                    cited_by=[UUID(link) for link in evidence.cited_by.get(e.event_uid, [])],
                )
                for e in evidence.events
            ],
            unresolved_events=evidence.unresolved,
        )


class NoteRead(BaseModel):
    id: UUID
    author_id: UUID
    author_email: str
    body: str
    created_at: datetime

    @classmethod
    def from_note(cls, note: IncidentNote) -> NoteRead:
        return cls(
            id=note.id,
            author_id=note.author_id,
            author_email=note.author_email,
            body=note.body,
            created_at=note.created_at,
        )


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(min_length=1, max_length=MAX_NOTE_LENGTH)


class NoveltyItem(BaseModel):
    kind: str = Field(description="`process_pair`, `host_remote` or `remote`")
    key: str
    observations: int = Field(description="How often the organisation has seen this, in total")
    first_seen: datetime | None = Field(description="When it was first seen anywhere in the organisation")
    new_here: bool = Field(description="Nothing was seen before this incident started")
    summary: str


class NoveltyResponse(BaseModel):
    """Context, never detection: counts of what the organisation had seen before this incident."""

    items: list[NoveltyItem]
    coverage_from: datetime | None = Field(description="Since when the baseline has been counting")
    coverage_to: datetime | None
    new_count: int

    @classmethod
    def from_report(cls, report: NoveltyReport) -> NoveltyResponse:
        return cls(
            items=[
                NoveltyItem(
                    kind=item.kind,
                    key=item.key,
                    observations=item.observations,
                    first_seen=item.first_seen,
                    new_here=item.new_here,
                    summary=item.describe(),
                )
                for item in report.items
            ],
            coverage_from=report.coverage_from,
            coverage_to=report.coverage_to,
            new_count=sum(item.new_here for item in report.items),
        )
