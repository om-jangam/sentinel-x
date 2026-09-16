from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.pagination import encode_cursor
from app.ingest_pipeline.ocsf import EventClass
from app.modules.ingestion.domain.entities import IngestSource, SourceHealth
from app.modules.ingestion.domain.events import MAX_PAGE_SIZE, MAX_TEXT_LENGTH, EventPage


class _Strict(BaseModel):
    """Unknown fields are rejected, so a typo in a request body never silently does nothing."""

    model_config = ConfigDict(extra="forbid")


class ParserRead(BaseModel):
    name: str
    description: str


class SourceCreate(_Strict):
    name: str = Field(min_length=3, max_length=64, examples=["web-01-auth"])
    description: str = Field(default="", max_length=255)
    parser: str = Field(examples=["linux_auth"])


class SourceUpdate(_Strict):
    is_enabled: bool


class SourceRead(BaseModel):
    id: UUID
    name: str
    description: str
    parser: str
    is_enabled: bool
    token_prefix: str
    health: SourceHealth
    last_event_at: datetime | None
    events_accepted: int
    events_rejected: int
    last_error: str | None
    last_error_at: datetime | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_entity(cls, source: IngestSource, *, now: datetime) -> SourceRead:
        return cls(
            id=source.id,
            name=source.name,
            description=source.description,
            parser=source.parser,
            is_enabled=source.is_enabled,
            token_prefix=source.token_prefix,
            health=source.health(now),
            last_event_at=source.last_event_at,
            events_accepted=source.events_accepted,
            events_rejected=source.events_rejected,
            last_error=source.last_error,
            last_error_at=source.last_error_at,
            created_at=source.created_at,
            updated_at=source.updated_at,
        )


class SourceWithToken(BaseModel):
    """Returned only by create and rotate: the token is never retrievable afterwards."""

    source: SourceRead
    token: str


class IngestErrorRead(BaseModel):
    index: int
    reason: str


class IngestResponse(BaseModel):
    accepted: int
    rejected: int
    errors: list[IngestErrorRead]


class EventSearchRequest(_Strict):
    time_from: datetime
    time_to: datetime
    class_uids: list[int] = Field(default_factory=list, max_length=len(EventClass))
    severity_min: int | None = Field(default=None, ge=0, le=99)
    status_id: int | None = Field(default=None, ge=0, le=99)
    text: str | None = Field(default=None, max_length=MAX_TEXT_LENGTH)
    ip: str | None = Field(default=None, max_length=45)
    user_name: str | None = Field(default=None, max_length=255)
    hostname: str | None = Field(default=None, max_length=255)
    source_id: UUID | None = None
    limit: int = Field(default=50, ge=1, le=MAX_PAGE_SIZE)
    cursor: str | None = None


class EventPageResponse(BaseModel):
    items: list[dict[str, Any]]
    total: int
    total_is_lower_bound: bool
    took_ms: int
    next_cursor: str | None = None

    @classmethod
    def from_page(cls, page: EventPage) -> EventPageResponse:
        return cls(
            items=page.items,
            total=page.total,
            total_is_lower_bound=page.total_is_lower_bound,
            took_ms=page.took_ms,
            next_cursor=encode_cursor(page.next_cursor.encode()) if page.next_cursor else None,
        )
