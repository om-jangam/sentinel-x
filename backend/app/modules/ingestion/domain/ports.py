from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from app.core.audit.port import AuditRecorder
from app.modules.ingestion.domain.entities import IngestSource
from app.modules.ingestion.domain.events import EventDocument, EventPage, EventQuery, IndexOutcome


class SourceRepository(Protocol):
    async def list_for_org(self, org_id: UUID) -> list[IngestSource]: ...

    async def get(self, org_id: UUID, source_id: UUID) -> IngestSource | None: ...

    async def get_by_token_hash(self, token_hash: str) -> IngestSource | None: ...

    async def name_exists(self, org_id: UUID, name: str) -> bool: ...

    async def add(self, source: IngestSource) -> None: ...

    async def update(self, source: IngestSource) -> None: ...

    async def record_batch(
        self,
        source_id: UUID,
        *,
        accepted: int,
        rejected: int,
        last_event_at: datetime | None,
        error: str | None,
        at: datetime,
    ) -> None:
        """Atomic counter increments; concurrent batches from one source never lose updates."""
        ...


class IngestionUnitOfWork(Protocol):
    @property
    def sources(self) -> SourceRepository: ...

    @property
    def audit(self) -> AuditRecorder: ...

    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...


class EventStore(Protocol):
    async def ensure_ready(self) -> None:
        """Create or update index templates and lifecycle policies (idempotent)."""
        ...

    async def ping(self) -> bool: ...

    async def index(self, documents: Sequence[EventDocument]) -> IndexOutcome: ...

    async def search(self, org_id: UUID, query: EventQuery) -> EventPage: ...

    async def get(self, org_id: UUID, event_uid: str) -> dict[str, Any] | None: ...

    async def get_many(self, org_id: UUID, event_uids: Sequence[str]) -> dict[str, dict[str, Any]]:
        """The stored documents among `event_uids`, keyed by event_uid; missing ones are simply absent."""
        ...
