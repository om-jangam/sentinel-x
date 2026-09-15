from __future__ import annotations

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.chain import ChainVerification
from app.core.audit.models import AuditLogModel
from app.core.audit.repository import list_audit_entries, verify_audit_chain
from app.modules.platform.application.audit_service import AuditEntryView, AuditFilter


def _view(row: AuditLogModel) -> AuditEntryView:
    return AuditEntryView(
        id=row.id,
        chain_index=row.chain_index,
        ts=row.ts,
        actor_id=row.actor_id,
        actor_type=row.actor_type,
        action=row.action,
        resource_type=row.resource_type,
        resource_id=row.resource_id,
        before=row.before,
        after=row.after,
        context=row.context,
        correlation_id=row.correlation_id,
        entry_hash=row.entry_hash,
    )


class SqlAuditLogReader:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_entries(
        self, org_id: UUID, *, limit: int, before_index: int | None, filters: AuditFilter
    ) -> list[AuditEntryView]:
        rows = await list_audit_entries(
            self._session,
            org_id,
            limit=limit,
            before_index=before_index,
            action=filters.action,
            resource_type=filters.resource_type,
            actor_id=filters.actor_id,
        )
        return [_view(r) for r in rows]

    async def verify(self, org_id: UUID) -> ChainVerification:
        return await verify_audit_chain(self._session, org_id)
