"""An in-memory event store so the suite exercises the whole ingest path without OpenSearch.

The OpenSearch adapter itself (query building, bulk results, index setup) is covered against a
stubbed client in `test_opensearch_store.py`; no live cluster is exercised by the suite.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID

import httpx
import pytest
from fastapi import FastAPI

from app.conftest import Seeded, bearer
from app.core.container import Container
from app.core.events.bus import InMemoryEventBus
from app.core.events.topics import EVENTS_NORMALIZED
from app.modules.ingestion.application.indexing_service import IndexingService
from app.modules.ingestion.domain.events import EventCursor, EventDocument, EventPage, EventQuery, IndexOutcome


class FakeEventStore:
    """Behaves like the real store for the properties the tests assert: idempotent ids, org scoping."""

    def __init__(self) -> None:
        self.documents: dict[str, dict[str, Any]] = {}
        self.queries: list[EventQuery] = []
        self.fail_next = False

    async def ensure_ready(self) -> None:
        return None

    async def ping(self) -> bool:
        return True

    async def index(self, documents: Sequence[EventDocument]) -> IndexOutcome:
        if self.fail_next:
            self.fail_next = False
            return IndexOutcome(indexed=0, duplicates=0, failed=len(documents), errors=["injected failure"])
        indexed = duplicates = 0
        for document in documents:
            if document.id in self.documents:
                duplicates += 1
            else:
                indexed += 1
            self.documents[document.id] = dict(document.body)
        return IndexOutcome(indexed=indexed, duplicates=duplicates, failed=0)

    async def search(self, org_id: UUID, query: EventQuery) -> EventPage:
        self.queries.append(query)
        matches = [
            document
            for document in self.documents.values()
            if document["sx"]["org_id"] == str(org_id)
            and query.time_from.timestamp() * 1000 <= document["time"] <= query.time_to.timestamp() * 1000
            and (not query.class_uids or document["class_uid"] in query.class_uids)
            and (query.severity_min is None or document["severity_id"] >= query.severity_min)
            and (query.text is None or query.text.lower() in str(document.get("message", "")).lower())
        ]
        matches.sort(key=lambda d: (d["time"], d["sx"]["event_uid"]), reverse=True)
        page = matches[: query.limit]
        next_cursor = None
        if len(page) == query.limit and page:
            next_cursor = EventCursor(time_ms=page[-1]["time"], event_uid=page[-1]["sx"]["event_uid"])
        return EventPage(
            items=page,
            total=len(matches),
            total_is_lower_bound=False,
            took_ms=1,
            next_cursor=next_cursor,
        )

    async def get(self, org_id: UUID, event_uid: str) -> dict[str, Any] | None:
        for document in self.documents.values():
            if document["sx"]["event_uid"] == event_uid and document["sx"]["org_id"] == str(org_id):
                return document
        return None


@pytest.fixture
def event_store(app: FastAPI, container: Container) -> FakeEventStore:
    """Installs the fake store and wires indexing the way a Redis-less deployment does."""
    store = FakeEventStore()
    app.state.event_store = store
    bus = container.event_bus
    assert isinstance(bus, InMemoryEventBus)
    bus.subscribe(EVENTS_NORMALIZED, IndexingService(store).handle)
    return store


@pytest.fixture
async def source_token(client: httpx.AsyncClient, admin_token: str, seeded: Seeded) -> str:
    response = await client.post(
        "/api/v1/ingest/sources",
        headers=bearer(admin_token),
        json={"name": "web-01-auth", "description": "sshd on web-01", "parser": "linux_auth"},
    )
    assert response.status_code == 201, response.text
    token: str = response.json()["token"]
    return token


def ingest_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
