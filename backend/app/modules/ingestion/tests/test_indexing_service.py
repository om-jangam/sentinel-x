from __future__ import annotations

import pytest

from app.core.events.bus import Event
from app.core.events.topics import EVENTS_NORMALIZED
from app.modules.ingestion.application.indexing_service import IndexingFailedError, IndexingService
from app.modules.ingestion.domain.events import EventDocument
from app.modules.ingestion.tests.conftest import FakeEventStore


def bus_event(*documents: EventDocument) -> Event:
    return Event(topic=EVENTS_NORMALIZED, payload={"documents": [d.to_message() for d in documents]})


def document(fingerprint: str) -> EventDocument:
    return EventDocument(
        stream="events-ocsf-iam",
        id=fingerprint,
        body={
            "@timestamp": "2026-09-15T09:14:02.519000Z",
            "time": 1_789_463_642_519,
            "sx": {"event_uid": fingerprint, "ingested_at": "2026-09-15T09:15:00.000000Z"},
        },
    )


async def test_indexes_documents_and_tolerates_redelivery() -> None:
    store = FakeEventStore()
    service = IndexingService(store)

    await service.handle(bus_event(document("fp-1"), document("fp-2")))
    await service.handle(bus_event(document("fp-1"), document("fp-2")))

    assert set(store.documents) == {"fp-1", "fp-2"}


async def test_failed_writes_raise_so_the_message_stays_pending() -> None:
    """The Redis Streams consumer acks only after the handler returns; raising keeps it for redelivery."""
    store = FakeEventStore()
    store.fail_next = True

    with pytest.raises(IndexingFailedError, match="1 events could not be indexed"):
        await IndexingService(store).handle(bus_event(document("fp-1")))
    assert not store.documents

    await IndexingService(store).handle(bus_event(document("fp-1")))
    assert set(store.documents) == {"fp-1"}, "the redelivered message succeeds"


async def test_empty_messages_are_ignored() -> None:
    store = FakeEventStore()
    await IndexingService(store).handle(Event(topic=EVENTS_NORMALIZED, payload={}))
    assert not store.documents
