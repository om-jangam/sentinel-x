"""Read side: constrained event search and single-event lookup."""

from __future__ import annotations

from typing import Any

from app.core.errors import NotFoundError
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.modules.ingestion.domain.events import EventPage, EventQuery
from app.modules.ingestion.domain.ports import EventStore


class EventQueryService:
    def __init__(self, store: EventStore) -> None:
        self._store = store

    async def search(self, principal: Principal, query: EventQuery) -> EventPage:
        principal.require(Permission.EVENT_READ)
        return await self._store.search(principal.org_id, query)

    async def get(self, principal: Principal, event_uid: str) -> dict[str, Any]:
        principal.require(Permission.EVENT_READ)
        document = await self._store.get(principal.org_id, event_uid)
        if document is None:
            raise NotFoundError("Event not found")
        return document
