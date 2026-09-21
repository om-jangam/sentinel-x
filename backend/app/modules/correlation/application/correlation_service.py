"""Correlation: join findings (and the events that complete them) into incidents, recording why for every link.

Runs after detection has stored a batch's findings, inside one transaction per batch. It is idempotent: a
finding belongs to at most one incident and an event is linked to an incident at most once, so a redelivered
batch changes nothing. Two rules create links:

- shared-entity: a finding joins the open incident it shares the most linking entities with (external IP,
  host, scoped user, domain, hash) if their activity overlaps within `CORRELATION_WINDOW`; otherwise it
  opens a new incident.
- auth-success-after-failures: a successful logon joins an open incident that holds brute-force findings
  from the same source address against the same host, within `AUTH_SEQUENCE_WINDOW` after them.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from app.core.audit.port import AuditEvent
from app.core.clock import Clock, utcnow
from app.core.ids import uuid7
from app.core.observability.metrics import CORRELATION_LINKS
from app.modules.correlation.domain.entities import (
    Document,
    EntityType,
    Sighting,
    event_identity,
    extract,
    is_successful_logon,
)
from app.modules.correlation.domain.incidents import (
    MAX_MATCH_SIGHTINGS,
    CorrelationRule,
    FindingSignal,
    Incident,
    IncidentEntity,
    IncidentLink,
    IncidentStatus,
    LinkKind,
    MatchedEntity,
)
from app.modules.correlation.domain.policy import (
    AUTH_SEQUENCE_WINDOW,
    CORRELATION_WINDOW,
    assess,
    is_auth_failure_link,
)
from app.modules.correlation.domain.ports import CorrelationUnitOfWork, UnitOfWorkFactory

logger = logging.getLogger(__name__)


def _at(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, UTC)


def _unique(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))[:MAX_MATCH_SIGHTINGS]


@dataclass(slots=True)
class _Touched:
    incident: Incident
    opened: bool
    before: dict[str, object]
    links_added: int = 0


class CorrelationService:
    def __init__(self, *, uow_factory: UnitOfWorkFactory, clock: Clock = utcnow) -> None:
        self._uow_factory = uow_factory
        self._clock = clock

    async def handle(self, org_id: UUID, findings: Sequence[FindingSignal], documents: Sequence[Document]) -> None:
        sightings: dict[str, list[Sighting]] = {}
        logons: list[tuple[str, int]] = []
        for document in documents:
            identity = event_identity(document)
            if identity is None:
                continue
            sightings[identity[0]] = extract(document)
            if is_successful_logon(document):
                logons.append(identity)
        if not findings and not logons:
            return

        async with self._uow_factory() as uow:
            await uow.incidents.lock(org_id)
            touched: dict[UUID, _Touched] = {}
            for finding in sorted(findings, key=lambda f: (f.first_seen, str(f.id))):
                await self._correlate_finding(uow, org_id, finding, sightings, touched)
            for uid, at_ms in sorted(logons, key=lambda item: (item[1], item[0])):
                await self._correlate_logon(uow, org_id, uid, _at(at_ms), sightings.get(uid, []), touched)
            if not touched:
                return
            await self._finalise(uow, touched)
            await uow.commit()

        opened = sum(t.opened for t in touched.values())
        logger.info(
            "incidents correlated",
            extra={"incidents_opened": opened, "incidents_updated": len(touched) - opened, "org_id": str(org_id)},
        )

    async def _track(self, touched: dict[UUID, _Touched], incident: Incident, *, opened: bool = False) -> Incident:
        """One object per incident per batch, so later links see earlier ones' changes."""
        if incident.id not in touched:
            touched[incident.id] = _Touched(incident, opened, incident.audit_view())
        return touched[incident.id].incident

    async def _link(
        self,
        uow: CorrelationUnitOfWork,
        touched: dict[UUID, _Touched],
        incident: Incident,
        link: IncidentLink,
        sightings: Sequence[Sighting],
    ) -> None:
        await uow.incidents.add_link(link)
        await uow.incidents.record_sightings(incident.org_id, incident.id, sightings)
        # Widen now, so the next finding in this batch is matched against the incident's true extent.
        incident.first_seen = min(incident.first_seen, link.first_seen)
        incident.last_seen = max(incident.last_seen, link.last_seen)
        await uow.incidents.update(incident)
        touched[incident.id].links_added += 1
        CORRELATION_LINKS.labels(rule=link.rule.value).inc()

    async def _correlate_finding(
        self,
        uow: CorrelationUnitOfWork,
        org_id: UUID,
        finding: FindingSignal,
        sightings: Mapping[str, list[Sighting]],
        touched: dict[UUID, _Touched],
    ) -> None:
        if await uow.incidents.incident_for_finding(org_id, finding.id) is not None:
            return  # redelivered: already correlated
        own = [s for uid in finding.evidence for s in sightings.get(uid, [])]
        keys = {s.entity.key for s in own if s.entity.links}
        candidates = (
            await uow.incidents.open_incidents_with(
                org_id,
                keys,
                start=finding.first_seen - CORRELATION_WINDOW,
                end=finding.last_seen + CORRELATION_WINDOW,
            )
            if keys
            else []
        )
        now = self._clock()
        matched: tuple[MatchedEntity, ...] = ()
        if candidates:
            best, shared = max(candidates, key=lambda c: (len(c[1]), c[0].last_seen, str(c[0].id)))
            incident = await self._track(touched, best)
            matched = tuple(
                MatchedEntity(
                    key=key,
                    incident_events=_unique(entity.events),
                    new_events=_unique([s.event_uid for s in own if s.entity.key == key]),
                )
                for key, entity in sorted(shared.items())
            )
            rule = CorrelationRule.SHARED_ENTITY
            reason = (
                f"shares {', '.join(sorted(shared))} with the incident, "
                f"within {int(CORRELATION_WINDOW.total_seconds() // 3600)}h of its activity"
            )
        else:
            incident = Incident(
                id=uuid7(),
                org_id=org_id,
                title=finding.rule_title[:255],
                severity_id=finding.severity_id,
                status=IncidentStatus.NEW,
                first_seen=finding.first_seen,
                last_seen=finding.last_seen,
                created_at=now,
                updated_at=now,
            )
            await uow.incidents.add(incident)
            await self._track(touched, incident, opened=True)
            rule = CorrelationRule.OPENED
            reason = "no open incident shares an entity with this finding within the correlation window"

        link = IncidentLink(
            id=uuid7(),
            org_id=org_id,
            incident_id=incident.id,
            kind=LinkKind.FINDING,
            rule=rule,
            reason=reason,
            evidence=finding.evidence,
            matched=matched,
            first_seen=finding.first_seen,
            last_seen=finding.last_seen,
            created_at=now,
            finding_id=finding.id,
            detail={
                "rule_id": finding.rule_id,
                "rule_title": finding.rule_title,
                "severity_id": finding.severity_id,
                "techniques": list(finding.techniques),
                "tactics": list(finding.tactics),
            },
        )
        await self._link(uow, touched, incident, link, own)

    async def _correlate_logon(
        self,
        uow: CorrelationUnitOfWork,
        org_id: UUID,
        event_uid: str,
        at: datetime,
        own: Sequence[Sighting],
        touched: dict[UUID, _Touched],
    ) -> None:
        source = next((s for s in own if s.entity.type is EntityType.IP and s.field == "src_endpoint.ip"), None)
        host_keys = {s.entity.key for s in own if s.entity.type is EntityType.HOST}
        if source is None or not host_keys:
            return
        candidates = await uow.incidents.open_incidents_with(
            org_id, {source.entity.key, *host_keys}, start=at - AUTH_SEQUENCE_WINDOW, end=at
        )
        for candidate, shared in candidates:
            source_entity = shared.get(source.entity.key)
            hosts = sorted(key for key in shared if key in host_keys)
            if source_entity is None or not hosts:
                continue  # must be the same source against the same host
            if await uow.incidents.has_event_link(candidate.id, event_uid):
                continue
            from_source = set(source_entity.events)
            failures = [
                link
                for link in await uow.incidents.links(candidate.id)
                if is_auth_failure_link(link)
                and link.first_seen <= at
                and at - link.last_seen <= AUTH_SEQUENCE_WINDOW
                and from_source.intersection(link.evidence)
            ]
            if not failures:
                continue
            incident = await self._track(touched, candidate)
            failure_events = [uid for link in failures for uid in link.evidence if uid in from_source]
            matched = (
                MatchedEntity(source.entity.key, _unique(failure_events), (event_uid,)),
                *(MatchedEntity(key, _unique(shared[key].events), (event_uid,)) for key in hosts),
            )
            user = next((s.entity.value for s in own if s.entity.type is EntityType.USER), None)
            link = IncidentLink(
                id=uuid7(),
                org_id=org_id,
                incident_id=incident.id,
                kind=LinkKind.EVENT,
                rule=CorrelationRule.AUTH_SUCCESS_AFTER_FAILURES,
                reason=(
                    f"successful logon{f' as {user}' if user else ''} from {source.entity.value} "
                    f"to {', '.join(h.split(':', 1)[1] for h in hosts)} after {len(failures)} brute-force finding(s) "
                    "from the same source"
                ),
                evidence=(event_uid,),
                matched=matched,
                first_seen=at,
                last_seen=at,
                created_at=self._clock(),
                event_uid=event_uid,
                detail={"failure_links": [str(link.id) for link in failures], "user": user},
            )
            await self._link(uow, touched, incident, link, own)

    async def _finalise(self, uow: CorrelationUnitOfWork, touched: dict[UUID, _Touched]) -> None:
        now = self._clock()
        for state in touched.values():
            incident = state.incident
            entities: list[IncidentEntity] = await uow.incidents.entities(incident.id)
            assess(incident, await uow.incidents.links(incident.id), entities)
            incident.updated_at = now
            if not state.opened:
                incident.version += 1
            await uow.incidents.update(incident)
            await uow.audit.record(
                AuditEvent(
                    org_id=incident.org_id,
                    action="incident.opened" if state.opened else "incident.correlated",
                    resource_type="incident",
                    resource_id=str(incident.id),
                    actor_type="system",
                    before=None if state.opened else state.before,
                    after=incident.audit_view(),
                    context={"links_added": state.links_added},
                )
            )
