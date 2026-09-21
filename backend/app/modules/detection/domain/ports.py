from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from app.modules.detection.domain.findings import Finding, FindingPage, FindingQuery
from app.modules.detection.domain.predicates import Document


class FindingRepository(Protocol):
    async def add(self, finding: Finding) -> bool:
        """Store a finding; False when its dedupe key already exists (a redelivered event)."""
        ...

    async def get(self, org_id: UUID, finding_id: UUID) -> Finding | None: ...

    async def get_by_dedupe_key(self, org_id: UUID, dedupe_key: str) -> Finding | None: ...

    async def search(self, org_id: UUID, query: FindingQuery) -> FindingPage: ...


class DetectionUnitOfWork(Protocol):
    @property
    def findings(self) -> FindingRepository: ...

    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...


UnitOfWorkFactory = Callable[[], AbstractAsyncContextManager[DetectionUnitOfWork]]

# Called after a batch's findings are durable, with the stored findings (including ones a redelivered batch
# had already created) and the batch's documents. The composition root wires correlation in here, so a
# downstream failure makes the bus redeliver and the sink sees the same findings again.
FindingSink = Callable[[UUID, Sequence[Finding], Sequence[Document]], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class WindowEntry:
    event_uid: str
    at_ms: int
    value: str | None = None


class WindowStore(Protocol):
    """Sliding windows of event time for threshold rules, keyed by org, rule and group."""

    async def add(self, key: str, entry: WindowEntry, *, window_ms: int) -> list[WindowEntry]:
        """Record an entry (idempotent per event_uid); return the entries within `window_ms` before it."""
        ...

    async def last_fired(self, key: str) -> int | None: ...

    async def mark_fired(self, key: str, at_ms: int, *, window_ms: int) -> None: ...
