"""Read side of the audit log: listing and chain verification."""

from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.chain import ChainVerification, ChainVerifier
from app.core.audit.models import AuditLogModel


async def list_audit_entries(
    session: AsyncSession,
    org_id: UUID,
    *,
    limit: int,
    before_index: int | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    actor_id: UUID | None = None,
) -> list[AuditLogModel]:
    """Newest first; keyset-paginated on `chain_index`."""
    stmt = select(AuditLogModel).where(AuditLogModel.org_id == org_id)
    if before_index is not None:
        stmt = stmt.where(AuditLogModel.chain_index < before_index)
    if action is not None:
        stmt = stmt.where(AuditLogModel.action == action)
    if resource_type is not None:
        stmt = stmt.where(AuditLogModel.resource_type == resource_type)
    if actor_id is not None:
        stmt = stmt.where(AuditLogModel.actor_id == actor_id)
    stmt = stmt.order_by(AuditLogModel.chain_index.desc()).limit(limit)
    return list((await session.scalars(stmt)).all())


async def iter_audit_chain(
    session: AsyncSession, org_id: UUID, *, batch_size: int = 500
) -> AsyncIterator[AuditLogModel]:
    """Oldest first, in bounded batches so verification never loads the whole log."""
    after = -1
    while True:
        batch = (
            await session.scalars(
                select(AuditLogModel)
                .where(AuditLogModel.org_id == org_id, AuditLogModel.chain_index > after)
                .order_by(AuditLogModel.chain_index)
                .limit(batch_size)
            )
        ).all()
        if not batch:
            return
        for row in batch:
            yield row
        after = batch[-1].chain_index
        session.expunge_all()


async def verify_audit_chain(session: AsyncSession, org_id: UUID) -> ChainVerification:
    verifier = ChainVerifier(org_id)
    async for row in iter_audit_chain(session, org_id):
        if not verifier.feed(row.to_chain_entry(), prev_hash=row.prev_hash, entry_hash=row.entry_hash):
            break
    return verifier.result()


async def list_audited_org_ids(session: AsyncSession) -> list[UUID]:
    return list((await session.scalars(select(AuditLogModel.org_id).distinct())).all())
