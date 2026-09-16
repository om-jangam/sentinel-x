"""Constrained event search (docs/06 §2: never raw backend query pass-through)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.errors import ValidationFailedError
from app.ingest_pipeline.ocsf import EventClass, Severity, Status

MAX_SEARCH_WINDOW = timedelta(days=90)
MAX_PAGE_SIZE = 200
MAX_TEXT_LENGTH = 256
TOTAL_HITS_CAP = 10_000


@dataclass(frozen=True, slots=True)
class EventDocument:
    """One normalised event ready for the event store; `id` is its content fingerprint."""

    stream: str
    id: str
    body: Mapping[str, Any]

    def to_message(self) -> dict[str, Any]:
        return {"stream": self.stream, "id": self.id, "body": dict(self.body)}

    @classmethod
    def from_message(cls, message: Mapping[str, Any]) -> EventDocument:
        return cls(stream=str(message["stream"]), id=str(message["id"]), body=dict(message["body"]))


@dataclass(frozen=True, slots=True)
class IndexOutcome:
    indexed: int
    duplicates: int
    failed: int
    errors: Sequence[str] = ()


@dataclass(frozen=True, slots=True)
class EventCursor:
    """search_after position: newest first, tie-broken by event uid."""

    time_ms: int
    event_uid: str

    def encode(self) -> str:
        return f"{self.time_ms}:{self.event_uid}"

    @classmethod
    def decode(cls, value: str) -> EventCursor:
        time_part, _, uid = value.partition(":")
        if not uid or not time_part.lstrip("-").isdigit():
            raise ValidationFailedError("Invalid pagination cursor")
        return cls(time_ms=int(time_part), event_uid=uid)


@dataclass(frozen=True, slots=True)
class EventQuery:
    time_from: datetime
    time_to: datetime
    class_uids: tuple[int, ...] = ()
    severity_min: int | None = None
    status_id: int | None = None
    text: str | None = None
    ip: str | None = None
    user_name: str | None = None
    hostname: str | None = None
    source_id: UUID | None = None
    limit: int = 50
    cursor: EventCursor | None = None

    def __post_init__(self) -> None:
        problems: list[dict[str, Any]] = []

        def fail(loc: str, msg: str) -> None:
            problems.append({"loc": [loc], "msg": msg, "type": "event_query"})

        if self.time_from >= self.time_to:
            fail("time_from", "must be earlier than time_to")
        elif self.time_to - self.time_from > MAX_SEARCH_WINDOW:
            fail("time_to", f"search window may not exceed {MAX_SEARCH_WINDOW.days} days")
        if not 1 <= self.limit <= MAX_PAGE_SIZE:
            fail("limit", f"must be between 1 and {MAX_PAGE_SIZE}")
        known_classes = {int(c) for c in EventClass}
        for class_uid in self.class_uids:
            if class_uid not in known_classes:
                fail("class_uids", f"unsupported class_uid {class_uid}")
        if self.severity_min is not None and self.severity_min not in {int(s) for s in Severity}:
            fail("severity_min", "unknown severity_id")
        if self.status_id is not None and self.status_id not in {int(s) for s in Status}:
            fail("status_id", "unknown status_id")
        if self.text is not None and len(self.text) > MAX_TEXT_LENGTH:
            fail("text", f"must be at most {MAX_TEXT_LENGTH} characters")
        if problems:
            raise ValidationFailedError("Invalid event search", errors=problems)


@dataclass(frozen=True, slots=True)
class EventPage:
    items: list[dict[str, Any]]
    total: int
    total_is_lower_bound: bool
    took_ms: int
    next_cursor: EventCursor | None = None
    facets: Mapping[str, Mapping[str, int]] = field(default_factory=dict)
