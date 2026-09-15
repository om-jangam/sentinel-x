"""The audit port application services depend on (framework-free)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol
from uuid import UUID

ActorType = Literal["user", "service", "system"]


@dataclass(frozen=True, slots=True)
class AuditEvent:
    org_id: UUID
    action: str
    resource_type: str
    resource_id: str | None = None
    actor_id: UUID | None = None
    actor_type: ActorType = "user"
    before: Mapping[str, Any] | None = None
    after: Mapping[str, Any] | None = None
    context: Mapping[str, Any] | None = None


class AuditRecorder(Protocol):
    """Appends to the tamper-evident chain inside the caller's transaction (docs/05 §4)."""

    async def record(self, event: AuditEvent) -> None: ...
