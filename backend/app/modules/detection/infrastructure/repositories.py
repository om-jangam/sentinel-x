from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.detection.domain.findings import Finding, FindingCursor, FindingPage, FindingQuery
from app.modules.detection.domain.rules import RuleType
from app.modules.detection.infrastructure.models import FindingModel, FindingTechniqueModel

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MICROSECOND = timedelta(microseconds=1)


def _micros(value: datetime) -> int:
    return (value - _EPOCH) // _MICROSECOND


def _to_entity(model: FindingModel) -> Finding:
    return Finding(
        id=model.id,
        org_id=model.org_id,
        rule_id=model.rule_id,
        rule_title=model.rule_title,
        rule_type=RuleType(model.rule_type),
        rule_version=model.rule_version,
        severity_id=model.severity_id,
        techniques=tuple(row.technique_id for row in model.techniques),
        tactics=tuple(model.tactics),
        entities={name: list(values) for name, values in model.entities.items()},
        evidence=tuple(model.evidence),
        first_seen=model.first_seen,
        last_seen=model.last_seen,
        dedupe_key=model.dedupe_key,
        created_at=model.created_at,
    )


class SqlFindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, finding: Finding) -> bool:
        # A concurrent duplicate still fails on the unique constraint; the bus redelivers and this check wins.
        duplicate = await self._session.scalar(
            select(FindingModel.id).where(
                FindingModel.org_id == finding.org_id, FindingModel.dedupe_key == finding.dedupe_key
            )
        )
        if duplicate is not None:
            return False
        self._session.add(
            FindingModel(
                id=finding.id,
                org_id=finding.org_id,
                rule_id=finding.rule_id,
                rule_title=finding.rule_title,
                rule_type=finding.rule_type.value,
                rule_version=finding.rule_version,
                severity_id=finding.severity_id,
                tactics=list(finding.tactics),
                entities=finding.entities,
                evidence=list(finding.evidence),
                evidence_count=len(finding.evidence),
                first_seen=finding.first_seen,
                last_seen=finding.last_seen,
                dedupe_key=finding.dedupe_key,
                created_at=finding.created_at,
                techniques=[FindingTechniqueModel(technique_id=technique) for technique in finding.techniques],
            )
        )
        await self._session.flush()
        return True

    async def get(self, org_id: UUID, finding_id: UUID) -> Finding | None:
        model = await self._session.scalar(
            select(FindingModel).where(FindingModel.org_id == org_id, FindingModel.id == finding_id)
        )
        return None if model is None else _to_entity(model)

    async def search(self, org_id: UUID, query: FindingQuery) -> FindingPage:
        statement = select(FindingModel).where(FindingModel.org_id == org_id)
        if query.time_from is not None:
            statement = statement.where(FindingModel.last_seen >= query.time_from)
        if query.time_to is not None:
            statement = statement.where(FindingModel.last_seen <= query.time_to)
        if query.severity_min is not None:
            statement = statement.where(FindingModel.severity_id >= query.severity_min)
        if query.rule_id is not None:
            statement = statement.where(FindingModel.rule_id == query.rule_id)
        if query.technique is not None:
            statement = statement.where(
                exists().where(
                    FindingTechniqueModel.finding_id == FindingModel.id,
                    FindingTechniqueModel.technique_id == query.technique,
                )
            )
        if query.cursor is not None:
            last_seen = _EPOCH + timedelta(microseconds=query.cursor.last_seen_us)
            statement = statement.where(
                or_(
                    FindingModel.last_seen < last_seen,
                    and_(FindingModel.last_seen == last_seen, FindingModel.id < UUID(query.cursor.finding_id)),
                )
            )
        statement = statement.order_by(FindingModel.last_seen.desc(), FindingModel.id.desc()).limit(query.limit + 1)
        rows = list(await self._session.scalars(statement))
        items = [_to_entity(model) for model in rows[: query.limit]]
        next_cursor = None
        if len(rows) > query.limit and items:
            last = items[-1]
            next_cursor = FindingCursor(last_seen_us=_micros(last.last_seen), finding_id=str(last.id))
        return FindingPage(items=items, next_cursor=next_cursor)
