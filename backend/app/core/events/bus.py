"""Event-bus abstraction (docs/03 §6).

Producers and consumers depend only on `EventBus`; the transport upgrades from Redis Streams to
Redpanda without touching them.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from app.core.clock import ensure_utc, utcnow
from app.core.ids import uuid7
from app.core.observability.context import get_correlation_id

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Event:
    topic: str
    payload: Mapping[str, Any]
    org_id: UUID | None = None
    id: UUID = field(default_factory=uuid7)
    occurred_at: datetime = field(default_factory=utcnow)
    correlation_id: str | None = field(default_factory=get_correlation_id)

    def to_json(self) -> str:
        return json.dumps(
            {
                "id": str(self.id),
                "topic": self.topic,
                "org_id": None if self.org_id is None else str(self.org_id),
                "occurred_at": self.occurred_at.isoformat(),
                "correlation_id": self.correlation_id,
                "payload": dict(self.payload),
            },
            default=str,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> Event:
        data = json.loads(raw)
        return cls(
            id=UUID(data["id"]),
            topic=data["topic"],
            org_id=None if data["org_id"] is None else UUID(data["org_id"]),
            occurred_at=ensure_utc(datetime.fromisoformat(data["occurred_at"])),
            correlation_id=data["correlation_id"],
            payload=data["payload"],
        )


EventHandler = Callable[[Event], Awaitable[None]]


class EventBus(Protocol):
    async def publish(self, event: Event) -> None: ...


class InMemoryEventBus:
    """In-process bus for development and tests; a failing handler never blocks the others."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, topic: str, handler: EventHandler) -> None:
        self._handlers[topic].append(handler)

    async def publish(self, event: Event) -> None:
        for handler in self._handlers.get(event.topic, []):
            try:
                await handler(event)
            except Exception:
                logger.exception("event handler failed", extra={"topic": event.topic})
