from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.chain import GENESIS_HASH, ChainEntry, compute_entry_hash, normalize_json
from app.core.audit.models import AuditLogModel
from app.core.audit.port import AuditEvent
from app.core.clock import Clock, utcnow
from app.core.ids import uuid7
from app.core.observability.context import get_correlation_id
from app.core.observability.metrics import AUDIT_WRITES

logger = logging.getLogger(__name__)


def _advisory_lock_key(org_id: UUID) -> int:
    return int.from_bytes(org_id.bytes[:8], "big", signed=True)


class SqlAuditRecorder:
    """Writes audit entries in the caller's transaction — no lost audit on crash.

    On PostgreSQL a transaction-scoped advisory lock per org serialises writers so two concurrent
    transactions can never fork the chain; the `(org_id, chain_index)` unique constraint is the
    backstop on every dialect.
    """

    def __init__(self, session: AsyncSession, *, clock: Clock = utcnow) -> None:
        self._session = session
        self._clock = clock

    async def record(self, event: AuditEvent) -> None:
        await self.append(event)

    async def append(self, event: AuditEvent) -> AuditLogModel:
        session = self._session
        if session.get_bind().dialect.name == "postgresql":
            await session.execute(select(func.pg_advisory_xact_lock(_advisory_lock_key(event.org_id))))

        last = (
            await session.execute(
                select(AuditLogModel.chain_index, AuditLogModel.entry_hash)
                .where(AuditLogModel.org_id == event.org_id)
                .order_by(AuditLogModel.chain_index.desc())
                .limit(1)
            )
        ).first()
        chain_index = 0 if last is None else last.chain_index + 1
        prev_hash = GENESIS_HASH if last is None else last.entry_hash

        entry = ChainEntry(
            org_id=event.org_id,
            chain_index=chain_index,
            ts=self._clock(),
            actor_id=event.actor_id,
            actor_type=event.actor_type,
            action=event.action,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            before=normalize_json(event.before),
            after=normalize_json(event.after),
            context=normalize_json(event.context),
            correlation_id=get_correlation_id(),
        )
        row = AuditLogModel(
            id=uuid7(),
            org_id=entry.org_id,
            chain_index=entry.chain_index,
            ts=entry.ts,
            actor_id=entry.actor_id,
            actor_type=entry.actor_type,
            action=entry.action,
            resource_type=entry.resource_type,
            resource_id=entry.resource_id,
            before=entry.before,
            after=entry.after,
            context=entry.context,
            correlation_id=entry.correlation_id,
            prev_hash=prev_hash,
            entry_hash=compute_entry_hash(prev_hash, entry),
        )
        session.add(row)
        await session.flush()
        AUDIT_WRITES.labels(action=event.action).inc()
        logger.info(
            "audit",
            extra={"audit_action": event.action, "resource_type": event.resource_type},
        )
        return row
