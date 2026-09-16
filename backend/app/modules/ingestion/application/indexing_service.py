"""Bus consumer: writes normalised events into the event store."""

from __future__ import annotations

import logging
from datetime import datetime

from app.core.clock import Clock, ensure_utc, utcnow
from app.core.events.bus import Event
from app.core.observability.metrics import EVENT_AGE, INDEXED_EVENTS, INGEST_LAG
from app.modules.ingestion.domain.events import EventDocument
from app.modules.ingestion.domain.ports import EventStore

logger = logging.getLogger(__name__)


class IndexingFailedError(RuntimeError):
    """Raised so the bus message stays pending and is redelivered."""


def _parse(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return ensure_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


class IndexingService:
    def __init__(self, store: EventStore, *, clock: Clock = utcnow) -> None:
        self._store = store
        self._clock = clock

    async def handle(self, event: Event) -> None:
        documents = [EventDocument.from_message(message) for message in event.payload.get("documents", [])]
        if not documents:
            return

        outcome = await self._store.index(documents)
        INDEXED_EVENTS.labels(outcome="indexed").inc(outcome.indexed)
        INDEXED_EVENTS.labels(outcome="duplicate").inc(outcome.duplicates)
        INDEXED_EVENTS.labels(outcome="failed").inc(outcome.failed)
        self._observe_latency(documents)

        if outcome.failed:
            logger.error("indexing failed for %d events: %s", outcome.failed, "; ".join(outcome.errors[:3]))
            raise IndexingFailedError(f"{outcome.failed} events could not be indexed")

    def _observe_latency(self, documents: list[EventDocument]) -> None:
        now = self._clock()
        for document in documents:
            sx = document.body.get("sx", {})
            ingested_at = _parse(sx.get("ingested_at") if isinstance(sx, dict) else None)
            if ingested_at is not None:
                INGEST_LAG.observe(max(0.0, (now - ingested_at).total_seconds()))
            occurred_at = _parse(document.body.get("@timestamp"))
            if occurred_at is not None:
                EVENT_AGE.observe(max(0.0, (now - occurred_at).total_seconds()))
