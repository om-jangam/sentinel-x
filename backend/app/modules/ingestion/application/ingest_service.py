"""Accept raw telemetry: normalise, validate, attribute, and hand to the bus (ADR-0013)."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from itertools import batched
from typing import Any

from pydantic import ValidationError

from app.core.clock import Clock, utcnow
from app.core.errors import ConflictError, ValidationFailedError
from app.core.events.bus import Event, EventBus
from app.core.events.topics import EVENTS_NORMALIZED
from app.core.observability.metrics import INGEST_EVENTS
from app.ingest_pipeline.ocsf import event_uid_for
from app.ingest_pipeline.parsers import ParseError, normalize
from app.modules.ingestion.domain.entities import IngestSource
from app.modules.ingestion.domain.events import EventDocument
from app.modules.ingestion.domain.policies import MAX_EVENTS_PER_REQUEST
from app.modules.ingestion.domain.ports import IngestionUnitOfWork

logger = logging.getLogger(__name__)

# Bus messages stay small enough to keep Redis Streams entries manageable.
DOCUMENTS_PER_MESSAGE = 200
MAX_REPORTED_ERRORS = 50


@dataclass(frozen=True, slots=True)
class IngestError:
    index: int
    reason: str


@dataclass(frozen=True, slots=True)
class IngestResult:
    accepted: int
    rejected: int
    errors: list[IngestError]


def _describe(error: ValidationError) -> str:
    first = error.errors()[0]
    location = ".".join(str(part) for part in first.get("loc", ())) or "event"
    return f"{location}: {first.get('msg', 'is invalid')}"


class IngestService:
    def __init__(self, uow: IngestionUnitOfWork, *, bus: EventBus, clock: Clock = utcnow) -> None:
        self._uow = uow
        self._bus = bus
        self._clock = clock

    async def ingest(self, *, source: IngestSource, records: Sequence[Mapping[str, Any]]) -> IngestResult:
        if not source.is_enabled:
            raise ConflictError("This ingest source is disabled")
        if len(records) > MAX_EVENTS_PER_REQUEST:
            raise ValidationFailedError(f"At most {MAX_EVENTS_PER_REQUEST} events per request")

        now = self._clock()
        documents: list[EventDocument] = []
        errors: list[IngestError] = []
        latest_event_at: datetime | None = None
        org_id, source_id = str(source.org_id), str(source.id)

        for position, record in enumerate(records):
            try:
                event = normalize(source.parser, record)
            except ParseError as exc:
                errors.append(IngestError(position, str(exc)))
                continue
            except ValidationError as exc:
                errors.append(IngestError(position, _describe(exc)))
                continue

            fingerprint = event.fingerprint(org_id=org_id, source_id=source_id)
            documents.append(
                EventDocument(
                    stream=event.data_stream,
                    id=fingerprint,
                    body=event.to_document(
                        org_id=org_id, source_id=source_id, event_uid=event_uid_for(fingerprint), ingested_at=now
                    ),
                )
            )
            latest_event_at = event.time if latest_event_at is None else max(latest_event_at, event.time)

        INGEST_EVENTS.labels(parser=source.parser, outcome="accepted").inc(len(documents))
        INGEST_EVENTS.labels(parser=source.parser, outcome="rejected").inc(len(errors))

        # Published before the bookkeeping commit: redelivery is safe (documents are content-addressed),
        # silently dropping accepted telemetry is not.
        for chunk in batched(documents, DOCUMENTS_PER_MESSAGE):
            await self._bus.publish(
                Event(
                    topic=EVENTS_NORMALIZED,
                    org_id=source.org_id,
                    payload={
                        "source_id": source_id,
                        "documents": [document.to_message() for document in chunk],
                    },
                )
            )

        await self._uow.sources.record_batch(
            source.id,
            accepted=len(documents),
            rejected=len(errors),
            last_event_at=latest_event_at,
            error=errors[0].reason if errors and not documents else None,
            at=now,
        )
        await self._uow.commit()

        if errors:
            logger.info(
                "ingest batch partially rejected",
                extra={"source": source.name, "accepted": len(documents), "rejected": len(errors)},
            )
        return IngestResult(accepted=len(documents), rejected=len(errors), errors=errors[:MAX_REPORTED_ERRORS])
