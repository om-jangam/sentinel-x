"""Incidents: findings and events joined by correlation rules, each link carrying the evidence that justifies it."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID

from app.core.errors import ConflictError, ValidationFailedError

MAX_ENTITY_SIGHTINGS = 20  # event_uids kept per incident entity
MAX_MATCH_SIGHTINGS = 5  # event_uids quoted per side of a shared-entity match
MAX_QUERY_WINDOW = timedelta(days=90)
MAX_PAGE_SIZE = 200
MAX_NOTE_LENGTH = 10_000
SEVERITY_NAMES = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}


class IncidentStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


class Resolution(StrEnum):
    TRUE_POSITIVE = "true_positive"
    BENIGN_POSITIVE = "benign_positive"
    FALSE_POSITIVE = "false_positive"


class LinkKind(StrEnum):
    FINDING = "finding"
    EVENT = "event"


class CorrelationRule(StrEnum):
    OPENED = "opened"
    SHARED_ENTITY = "shared-entity"
    AUTH_SUCCESS_AFTER_FAILURES = "auth-success-after-failures"


@dataclass(frozen=True, slots=True)
class FindingSignal:
    """What correlation needs from a stored detection finding (the composition root adapts findings to this)."""

    id: UUID
    rule_id: str
    rule_title: str
    severity_id: int
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]
    evidence: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True, slots=True)
class MatchedEntity:
    """An entity both sides share, with the events on each side that show it."""

    key: str
    incident_events: tuple[str, ...]
    new_events: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {"key": self.key, "incident_events": list(self.incident_events), "new_events": list(self.new_events)}


@dataclass(frozen=True, slots=True)
class IncidentLink:
    """Why a finding or an event belongs to an incident. `evidence` is never empty."""

    id: UUID
    org_id: UUID
    incident_id: UUID
    kind: LinkKind
    rule: CorrelationRule
    reason: str
    evidence: tuple[str, ...]
    matched: tuple[MatchedEntity, ...]
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    finding_id: UUID | None = None
    event_uid: str | None = None
    # A snapshot of the finding (rule, severity, ATT&CK) so the incident can be assessed from its links alone.
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("an incident link must cite at least one event")
        if (self.kind is LinkKind.FINDING) != (self.finding_id is not None):
            raise ValueError("finding links, and only finding links, carry a finding_id")
        if self.rule is not CorrelationRule.OPENED and not self.matched:
            raise ValueError("a correlation link must name the entities that justify it")

    @property
    def techniques(self) -> tuple[str, ...]:
        return tuple(self.detail.get("techniques", ()))

    @property
    def tactics(self) -> tuple[str, ...]:
        return tuple(self.detail.get("tactics", ()))


@dataclass(slots=True)
class IncidentEntity:
    key: str
    type: str
    value: str
    links: bool
    first_seen: datetime
    last_seen: datetime
    events: list[str]


@dataclass(slots=True)
class Incident:
    id: UUID
    org_id: UUID
    title: str
    severity_id: int
    status: IncidentStatus
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    assessment: list[dict[str, Any]] = field(default_factory=list)
    finding_count: int = 0
    event_count: int = 0
    resolution: Resolution | None = None
    closed_at: datetime | None = None
    version: int = 1

    @property
    def severity(self) -> str:
        return SEVERITY_NAMES.get(self.severity_id, "Unknown")

    @property
    def is_open(self) -> bool:
        return self.status is not IncidentStatus.CLOSED

    def audit_view(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "resolution": None if self.resolution is None else self.resolution.value,
            "severity_id": self.severity_id,
            "finding_count": self.finding_count,
            "event_count": self.event_count,
        }

    def change_status(
        self, status: IncidentStatus, resolution: Resolution | None, *, expected_version: int, now: datetime
    ) -> None:
        if expected_version != self.version:
            raise ConflictError("The incident changed since you loaded it; reload and try again")
        if status is IncidentStatus.CLOSED and resolution is None:
            raise ValidationFailedError(
                "Closing an incident needs a resolution",
                errors=[{"loc": ["resolution"], "msg": "required when status is closed", "type": "missing"}],
            )
        if status is not IncidentStatus.CLOSED and resolution is not None:
            raise ValidationFailedError(
                "Only closed incidents have a resolution",
                errors=[{"loc": ["resolution"], "msg": "only allowed when status is closed", "type": "unexpected"}],
            )
        if status is self.status and resolution is self.resolution:
            raise ConflictError(f"The incident is already {status.value}")
        if status is IncidentStatus.NEW and self.status is not IncidentStatus.NEW:
            raise ConflictError("An incident can't go back to new; reopen it as investigating")
        self.status = status
        self.resolution = resolution
        self.closed_at = now if status is IncidentStatus.CLOSED else None
        self.updated_at = now
        self.version += 1


@dataclass(frozen=True, slots=True)
class IncidentCursor:
    last_seen_us: int
    incident_id: str

    def encode(self) -> str:
        return f"{self.last_seen_us}:{self.incident_id}"

    @classmethod
    def decode(cls, value: str) -> IncidentCursor:
        micros, _, incident_id = value.partition(":")
        if not incident_id or not micros.lstrip("-").isdigit():
            raise ValidationFailedError("Invalid pagination cursor")
        try:
            UUID(incident_id)
        except ValueError as exc:
            raise ValidationFailedError("Invalid pagination cursor") from exc
        return cls(last_seen_us=int(micros), incident_id=incident_id)


@dataclass(frozen=True, slots=True)
class IncidentQuery:
    time_from: datetime | None = None
    time_to: datetime | None = None
    status: IncidentStatus | None = None
    severity_min: int | None = None
    limit: int = 50
    cursor: IncidentCursor | None = None

    def __post_init__(self) -> None:
        problems: list[dict[str, Any]] = []

        def fail(loc: str, msg: str) -> None:
            problems.append({"loc": [loc], "msg": msg, "type": "incident_query"})

        if self.time_from and self.time_to:
            if self.time_from >= self.time_to:
                fail("time_from", "must be earlier than time_to")
            elif self.time_to - self.time_from > MAX_QUERY_WINDOW:
                fail("time_to", f"window may not exceed {MAX_QUERY_WINDOW.days} days")
        if not 1 <= self.limit <= MAX_PAGE_SIZE:
            fail("limit", f"must be between 1 and {MAX_PAGE_SIZE}")
        if self.severity_min is not None and self.severity_min not in SEVERITY_NAMES:
            fail("severity_min", "must be 1-5")
        if problems:
            raise ValidationFailedError("Invalid incident search", errors=problems)


@dataclass(frozen=True, slots=True)
class IncidentPage:
    items: list[Incident]
    next_cursor: IncidentCursor | None = None


@dataclass(frozen=True, slots=True)
class IncidentNote:
    """An analyst's note. Append-only: an assertion by a person, never evidence, and never edited."""

    id: UUID
    org_id: UUID
    incident_id: UUID
    author_id: UUID
    author_email: str  # as it was when the note was written
    body: str
    created_at: datetime

    def __post_init__(self) -> None:
        if not self.body.strip():
            raise ValidationFailedError(
                "A note can't be empty", errors=[{"loc": ["body"], "msg": "must not be blank", "type": "blank"}]
            )
        if len(self.body) > MAX_NOTE_LENGTH:
            raise ValidationFailedError(
                "Note too long",
                errors=[{"loc": ["body"], "msg": f"at most {MAX_NOTE_LENGTH} characters", "type": "too_long"}],
            )


@dataclass(frozen=True, slots=True)
class IncidentDetail:
    incident: Incident
    links: list[IncidentLink]
    entities: list[IncidentEntity]
