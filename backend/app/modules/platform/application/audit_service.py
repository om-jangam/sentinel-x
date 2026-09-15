"""Read-only audit use-cases. The audit log is never mutable through the API (docs/07 §4)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from app.core.audit.chain import ChainVerification
from app.core.security.permissions import Permission
from app.core.security.principal import Principal


@dataclass(frozen=True, slots=True)
class AuditEntryView:
    id: UUID
    chain_index: int
    ts: datetime
    actor_id: UUID | None
    actor_type: str
    action: str
    resource_type: str
    resource_id: str | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    context: dict[str, Any] | None
    correlation_id: str | None
    entry_hash: str


@dataclass(frozen=True, slots=True)
class AuditFilter:
    action: str | None = None
    resource_type: str | None = None
    actor_id: UUID | None = None


class AuditLogReader(Protocol):
    async def list_entries(
        self, org_id: UUID, *, limit: int, before_index: int | None, filters: AuditFilter
    ) -> list[AuditEntryView]: ...

    async def verify(self, org_id: UUID) -> ChainVerification: ...


@dataclass(frozen=True, slots=True)
class AuditPage:
    items: list[AuditEntryView]
    next_before_index: int | None


class AuditQueryService:
    def __init__(self, reader: AuditLogReader) -> None:
        self._reader = reader

    async def list_entries(
        self, principal: Principal, *, limit: int, before_index: int | None, filters: AuditFilter
    ) -> AuditPage:
        principal.require(Permission.AUDIT_READ)
        rows = await self._reader.list_entries(
            principal.org_id, limit=limit + 1, before_index=before_index, filters=filters
        )
        items = rows[:limit]
        has_more = len(rows) > limit
        return AuditPage(items=items, next_before_index=items[-1].chain_index if has_more and items else None)

    async def verify(self, principal: Principal) -> ChainVerification:
        principal.require(Permission.AUDIT_READ)
        return await self._reader.verify(principal.org_id)
