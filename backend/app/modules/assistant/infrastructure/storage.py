from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Float, ForeignKey, Index, Integer, String, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from app.core.audit.writer import SqlAuditRecorder
from app.core.db.base import Base, JsonType, UUIDPrimaryKeyMixin
from app.modules.assistant.domain.records import AnalysisRecord, AnalysisStatus

MAX_HISTORY = 20


class AnalysisModel(UUIDPrimaryKeyMixin, Base):
    """One request to the assistant and what survived validation. Written once, never updated."""

    __tablename__ = "incident_analyses"
    __table_args__ = (Index("ix_incident_analyses_incident_id_created_at", "incident_id", "created_at"),)

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="RESTRICT"))
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime]
    status: Mapped[str] = mapped_column(String(16))
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(32))
    bundle_hash: Mapped[str] = mapped_column(String(64))
    duration_ms: Mapped[int] = mapped_column(Integer)
    output: Mapped[dict[str, Any] | None] = mapped_column(JsonType)
    dropped: Mapped[list[dict[str, Any]]] = mapped_column(JsonType)
    reason: Mapped[str | None] = mapped_column(String(500))
    citation_validity: Mapped[float | None] = mapped_column(Float)
    stats: Mapped[dict[str, Any]] = mapped_column(JsonType)


def _record(model: AnalysisModel) -> AnalysisRecord:
    return AnalysisRecord(
        id=model.id,
        org_id=model.org_id,
        incident_id=model.incident_id,
        requested_by=model.requested_by,
        created_at=model.created_at,
        status=AnalysisStatus(model.status),
        provider=model.provider,
        model=model.model,
        prompt_version=model.prompt_version,
        bundle_hash=model.bundle_hash,
        duration_ms=model.duration_ms,
        output=model.output,
        dropped=list(model.dropped),
        reason=model.reason,
        citation_validity=model.citation_validity,
        stats=dict(model.stats),
    )


class SqlAnalysisRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, record: AnalysisRecord) -> None:
        self._session.add(
            AnalysisModel(
                id=record.id,
                org_id=record.org_id,
                incident_id=record.incident_id,
                requested_by=record.requested_by,
                created_at=record.created_at,
                status=record.status.value,
                provider=record.provider,
                model=record.model[:128],
                prompt_version=record.prompt_version,
                bundle_hash=record.bundle_hash,
                duration_ms=record.duration_ms,
                output=record.output,
                dropped=record.dropped,
                reason=record.reason,
                citation_validity=record.citation_validity,
                stats=record.stats,
            )
        )
        await self._session.flush()

    async def list_for_incident(self, org_id: UUID, incident_id: UUID) -> list[AnalysisRecord]:
        rows = await self._session.scalars(
            select(AnalysisModel)
            .where(AnalysisModel.org_id == org_id, AnalysisModel.incident_id == incident_id)
            .order_by(AnalysisModel.created_at.desc(), AnalysisModel.id.desc())
            .limit(MAX_HISTORY)
        )
        return [_record(row) for row in rows]


class SqlAssistantUnitOfWork:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._analyses = SqlAnalysisRepository(session)
        self._audit = SqlAuditRecorder(session)

    @property
    def analyses(self) -> SqlAnalysisRepository:
        return self._analyses

    @property
    def audit(self) -> SqlAuditRecorder:
        return self._audit

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()
