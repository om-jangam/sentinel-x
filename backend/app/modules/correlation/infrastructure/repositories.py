from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.correlation.domain.entities import Sighting
from app.modules.correlation.domain.incidents import (
    MAX_ENTITY_SIGHTINGS,
    CorrelationRule,
    Incident,
    IncidentCursor,
    IncidentEntity,
    IncidentLink,
    IncidentPage,
    IncidentQuery,
    IncidentStatus,
    LinkKind,
    MatchedEntity,
    Resolution,
)
from app.modules.correlation.infrastructure.models import IncidentEntityModel, IncidentLinkModel, IncidentModel

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MICROSECOND = timedelta(microseconds=1)
# Distinct from the audit writer's key space; correlation takes this lock before the audit lock, always.
_LOCK_NAMESPACE = 0x436F7272  # "Corr"


def _micros(value: datetime) -> int:
    return (value - _EPOCH) // _MICROSECOND


def _lock_key(org_id: UUID) -> int:
    return int.from_bytes(org_id.bytes[8:], "big", signed=True) ^ _LOCK_NAMESPACE


def _incident(model: IncidentModel) -> Incident:
    return Incident(
        id=model.id,
        org_id=model.org_id,
        title=model.title,
        severity_id=model.severity_id,
        status=IncidentStatus(model.status),
        first_seen=model.first_seen,
        last_seen=model.last_seen,
        created_at=model.created_at,
        updated_at=model.updated_at,
        techniques=list(model.techniques),
        tactics=list(model.tactics),
        assessment=list(model.assessment),
        finding_count=model.finding_count,
        event_count=model.event_count,
        resolution=None if model.resolution is None else Resolution(model.resolution),
        closed_at=model.closed_at,
        version=model.version,
    )


def _link(model: IncidentLinkModel) -> IncidentLink:
    return IncidentLink(
        id=model.id,
        org_id=model.org_id,
        incident_id=model.incident_id,
        kind=LinkKind(model.kind),
        rule=CorrelationRule(model.rule),
        reason=model.reason,
        evidence=tuple(model.evidence),
        matched=tuple(
            MatchedEntity(m["key"], tuple(m["incident_events"]), tuple(m["new_events"])) for m in model.matched
        ),
        first_seen=model.first_seen,
        last_seen=model.last_seen,
        created_at=model.created_at,
        finding_id=model.finding_id,
        event_uid=model.event_uid,
        detail=dict(model.detail),
    )


def _entity(model: IncidentEntityModel) -> IncidentEntity:
    return IncidentEntity(
        key=model.key,
        type=model.type,
        value=model.value,
        links=model.links,
        first_seen=model.first_seen,
        last_seen=model.last_seen,
        events=list(model.events),
    )


class SqlIncidentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def lock(self, org_id: UUID) -> None:
        # SQLite serialises writers itself; PostgreSQL needs the lock for concurrent worker replicas.
        if self._session.get_bind().dialect.name == "postgresql":
            await self._session.execute(select(func.pg_advisory_xact_lock(_lock_key(org_id))))

    async def get(self, org_id: UUID, incident_id: UUID) -> Incident | None:
        model = await self._session.scalar(
            select(IncidentModel).where(IncidentModel.org_id == org_id, IncidentModel.id == incident_id)
        )
        return None if model is None else _incident(model)

    async def add(self, incident: Incident) -> None:
        self._session.add(
            IncidentModel(
                id=incident.id,
                org_id=incident.org_id,
                title=incident.title,
                severity_id=incident.severity_id,
                status=incident.status.value,
                resolution=None,
                first_seen=incident.first_seen,
                last_seen=incident.last_seen,
                techniques=list(incident.techniques),
                tactics=list(incident.tactics),
                assessment=list(incident.assessment),
                finding_count=incident.finding_count,
                event_count=incident.event_count,
                created_at=incident.created_at,
                updated_at=incident.updated_at,
                closed_at=None,
                version=incident.version,
            )
        )
        await self._session.flush()

    async def update(self, incident: Incident) -> None:
        model = await self._session.get(IncidentModel, incident.id)
        if model is None or model.org_id != incident.org_id:
            raise LookupError(f"incident {incident.id} is not stored")
        model.title = incident.title
        model.severity_id = incident.severity_id
        model.status = incident.status.value
        model.resolution = None if incident.resolution is None else incident.resolution.value
        model.first_seen = incident.first_seen
        model.last_seen = incident.last_seen
        model.techniques = list(incident.techniques)
        model.tactics = list(incident.tactics)
        model.assessment = list(incident.assessment)
        model.finding_count = incident.finding_count
        model.event_count = incident.event_count
        model.updated_at = incident.updated_at
        model.closed_at = incident.closed_at
        model.version = incident.version
        await self._session.flush()

    async def search(self, org_id: UUID, query: IncidentQuery) -> IncidentPage:
        statement = select(IncidentModel).where(IncidentModel.org_id == org_id)
        if query.time_from is not None:
            statement = statement.where(IncidentModel.last_seen >= query.time_from)
        if query.time_to is not None:
            statement = statement.where(IncidentModel.last_seen <= query.time_to)
        if query.status is not None:
            statement = statement.where(IncidentModel.status == query.status.value)
        if query.severity_min is not None:
            statement = statement.where(IncidentModel.severity_id >= query.severity_min)
        if query.cursor is not None:
            last_seen = _EPOCH + timedelta(microseconds=query.cursor.last_seen_us)
            statement = statement.where(
                or_(
                    IncidentModel.last_seen < last_seen,
                    and_(IncidentModel.last_seen == last_seen, IncidentModel.id < UUID(query.cursor.incident_id)),
                )
            )
        statement = statement.order_by(IncidentModel.last_seen.desc(), IncidentModel.id.desc()).limit(query.limit + 1)
        rows = list(await self._session.scalars(statement))
        items = [_incident(model) for model in rows[: query.limit]]
        next_cursor = None
        if len(rows) > query.limit and items:
            last = items[-1]
            next_cursor = IncidentCursor(last_seen_us=_micros(last.last_seen), incident_id=str(last.id))
        return IncidentPage(items=items, next_cursor=next_cursor)

    async def incident_for_finding(self, org_id: UUID, finding_id: UUID) -> UUID | None:
        result: UUID | None = await self._session.scalar(
            select(IncidentLinkModel.incident_id).where(
                IncidentLinkModel.org_id == org_id, IncidentLinkModel.finding_id == finding_id
            )
        )
        return result

    async def has_event_link(self, incident_id: UUID, event_uid: str) -> bool:
        found = await self._session.scalar(
            select(IncidentLinkModel.id).where(
                IncidentLinkModel.incident_id == incident_id, IncidentLinkModel.event_uid == event_uid
            )
        )
        return found is not None

    async def open_incidents_with(
        self, org_id: UUID, keys: Iterable[str], *, start: datetime, end: datetime
    ) -> list[tuple[Incident, dict[str, IncidentEntity]]]:
        wanted = sorted(set(keys))
        if not wanted:
            return []
        rows = await self._session.execute(
            select(IncidentModel, IncidentEntityModel)
            .join(IncidentEntityModel, IncidentEntityModel.incident_id == IncidentModel.id)
            .where(
                IncidentEntityModel.org_id == org_id,
                IncidentEntityModel.key.in_(wanted),
                IncidentModel.org_id == org_id,
                IncidentModel.status != IncidentStatus.CLOSED.value,
                IncidentModel.last_seen >= start,
                IncidentModel.first_seen <= end,
            )
            .order_by(IncidentModel.id, IncidentEntityModel.key)
        )
        found: dict[UUID, tuple[Incident, dict[str, IncidentEntity]]] = {}
        for incident_model, entity_model in rows.tuples():
            if incident_model.id not in found:
                found[incident_model.id] = (_incident(incident_model), {})
            found[incident_model.id][1][entity_model.key] = _entity(entity_model)
        return list(found.values())

    async def add_link(self, link: IncidentLink) -> None:
        self._session.add(
            IncidentLinkModel(
                id=link.id,
                org_id=link.org_id,
                incident_id=link.incident_id,
                kind=link.kind.value,
                rule=link.rule.value,
                reason=link.reason[:1024],
                finding_id=link.finding_id,
                event_uid=link.event_uid,
                evidence=list(link.evidence),
                matched=[m.as_json() for m in link.matched],
                detail=dict(link.detail),
                first_seen=link.first_seen,
                last_seen=link.last_seen,
                created_at=link.created_at,
            )
        )
        await self._session.flush()

    async def links(self, incident_id: UUID) -> list[IncidentLink]:
        rows = await self._session.scalars(
            select(IncidentLinkModel)
            .where(IncidentLinkModel.incident_id == incident_id)
            .order_by(IncidentLinkModel.first_seen, IncidentLinkModel.id)
        )
        return [_link(model) for model in rows]

    async def entities(self, incident_id: UUID) -> list[IncidentEntity]:
        rows = await self._session.scalars(
            select(IncidentEntityModel)
            .where(IncidentEntityModel.incident_id == incident_id)
            .order_by(IncidentEntityModel.first_seen, IncidentEntityModel.key)
        )
        return [_entity(model) for model in rows]

    async def record_sightings(self, org_id: UUID, incident_id: UUID, sightings: Iterable[Sighting]) -> None:
        for sighting in sightings:
            at = datetime.fromtimestamp(sighting.at_ms / 1000, UTC)
            key = sighting.entity.key
            model = await self._session.get(IncidentEntityModel, (incident_id, key))
            if model is None:
                self._session.add(
                    IncidentEntityModel(
                        incident_id=incident_id,
                        key=key,
                        org_id=org_id,
                        type=sighting.entity.type.value,
                        value=sighting.entity.value,
                        links=sighting.entity.links,
                        first_seen=at,
                        last_seen=at,
                        events=[sighting.event_uid],
                    )
                )
                await self._session.flush()
                continue
            model.first_seen = min(model.first_seen, at)
            model.last_seen = max(model.last_seen, at)
            if sighting.event_uid not in model.events and len(model.events) < MAX_ENTITY_SIGHTINGS:
                model.events = [*model.events, sighting.event_uid]  # a new list, so the JSON change is persisted
        await self._session.flush()
