from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import case, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ingestion.domain.entities import IngestSource
from app.modules.ingestion.infrastructure.models import IngestSourceModel

MAX_ERROR_CHARS = 500


def _to_entity(model: IngestSourceModel) -> IngestSource:
    return IngestSource(
        id=model.id,
        org_id=model.org_id,
        name=model.name,
        description=model.description,
        parser=model.parser,
        is_enabled=model.is_enabled,
        token_prefix=model.token_prefix,
        token_hash=model.token_hash,
        created_at=model.created_at,
        updated_at=model.updated_at,
        last_event_at=model.last_event_at,
        events_accepted=model.events_accepted,
        events_rejected=model.events_rejected,
        last_error=model.last_error,
        last_error_at=model.last_error_at,
    )


class SqlSourceRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_for_org(self, org_id: UUID) -> list[IngestSource]:
        result = await self._session.scalars(
            select(IngestSourceModel).where(IngestSourceModel.org_id == org_id).order_by(IngestSourceModel.name)
        )
        return [_to_entity(model) for model in result]

    async def get(self, org_id: UUID, source_id: UUID) -> IngestSource | None:
        model = await self._session.scalar(
            select(IngestSourceModel).where(IngestSourceModel.org_id == org_id, IngestSourceModel.id == source_id)
        )
        return None if model is None else _to_entity(model)

    async def get_by_token_hash(self, token_hash: str) -> IngestSource | None:
        """Token lookup is org-agnostic: the credential itself determines the tenant."""
        model = await self._session.scalar(select(IngestSourceModel).where(IngestSourceModel.token_hash == token_hash))
        return None if model is None else _to_entity(model)

    async def name_exists(self, org_id: UUID, name: str) -> bool:
        found = await self._session.scalar(
            select(IngestSourceModel.id).where(IngestSourceModel.org_id == org_id, IngestSourceModel.name == name)
        )
        return found is not None

    async def add(self, source: IngestSource) -> None:
        self._session.add(
            IngestSourceModel(
                id=source.id,
                org_id=source.org_id,
                name=source.name,
                description=source.description,
                parser=source.parser,
                is_enabled=source.is_enabled,
                token_prefix=source.token_prefix,
                token_hash=source.token_hash,
                created_at=source.created_at,
                updated_at=source.updated_at,
            )
        )
        await self._session.flush()

    async def update(self, source: IngestSource) -> None:
        await self._session.execute(
            update(IngestSourceModel)
            .where(IngestSourceModel.id == source.id, IngestSourceModel.org_id == source.org_id)
            .values(
                name=source.name,
                description=source.description,
                is_enabled=source.is_enabled,
                token_prefix=source.token_prefix,
                token_hash=source.token_hash,
                updated_at=source.updated_at,
            )
        )

    async def record_batch(
        self,
        source_id: UUID,
        *,
        accepted: int,
        rejected: int,
        last_event_at: datetime | None,
        error: str | None,
        at: datetime,
    ) -> None:
        values: dict[str, Any] = {
            "events_accepted": IngestSourceModel.events_accepted + accepted,
            "events_rejected": IngestSourceModel.events_rejected + rejected,
        }
        if last_event_at is not None:
            # Out-of-order batches must not rewind the freshness clock (GREATEST is not portable).
            values["last_event_at"] = case(
                (IngestSourceModel.last_event_at.is_(None), last_event_at),
                (IngestSourceModel.last_event_at < last_event_at, last_event_at),
                else_=IngestSourceModel.last_event_at,
            )
        if error is not None:
            values["last_error"] = error[:MAX_ERROR_CHARS]
            values["last_error_at"] = at
        await self._session.execute(update(IngestSourceModel).where(IngestSourceModel.id == source_id).values(**values))
