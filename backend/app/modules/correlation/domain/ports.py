from __future__ import annotations

from collections.abc import Callable, Iterable
from contextlib import AbstractAsyncContextManager
from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.core.audit.port import AuditRecorder
from app.modules.correlation.domain.entities import Sighting
from app.modules.correlation.domain.incidents import (
    Incident,
    IncidentEntity,
    IncidentLink,
    IncidentPage,
    IncidentQuery,
)


class IncidentRepository(Protocol):
    async def lock(self, org_id: UUID) -> None:
        """Serialise correlation per organisation so concurrent workers can't open two incidents for one story."""
        ...

    async def get(self, org_id: UUID, incident_id: UUID) -> Incident | None: ...

    async def add(self, incident: Incident) -> None: ...

    async def update(self, incident: Incident) -> None: ...

    async def search(self, org_id: UUID, query: IncidentQuery) -> IncidentPage: ...

    async def incident_for_finding(self, org_id: UUID, finding_id: UUID) -> UUID | None: ...

    async def has_event_link(self, incident_id: UUID, event_uid: str) -> bool: ...

    async def open_incidents_with(
        self, org_id: UUID, keys: Iterable[str], *, start: datetime, end: datetime
    ) -> list[tuple[Incident, dict[str, IncidentEntity]]]:
        """Open incidents active within [start, end] holding any of `keys`, with the matching entities."""
        ...

    async def add_link(self, link: IncidentLink) -> None: ...

    async def links(self, incident_id: UUID) -> list[IncidentLink]: ...

    async def entities(self, incident_id: UUID) -> list[IncidentEntity]: ...

    async def record_sightings(self, org_id: UUID, incident_id: UUID, sightings: Iterable[Sighting]) -> None: ...


class CorrelationUnitOfWork(Protocol):
    @property
    def incidents(self) -> IncidentRepository: ...

    @property
    def audit(self) -> AuditRecorder: ...

    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...


UnitOfWorkFactory = Callable[[], AbstractAsyncContextManager[CorrelationUnitOfWork]]
