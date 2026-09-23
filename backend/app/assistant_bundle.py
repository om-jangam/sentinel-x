"""Builds the assistant's evidence bundle from correlation and threat-intel data (composition root).

Lives here so the assistant module depends on neither: it only sees the `EvidenceBundle` it is handed.
Everything is taken from stored, evidence-backed data: digests, links, the derived timeline and graph,
and cached intel with its source and retrieval time.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.assistant.domain.bundle import (
    MAX_COMMAND,
    MAX_EVENTS,
    MAX_RAW,
    BundleEdge,
    BundleEvent,
    BundleFinding,
    BundleIntel,
    BundleLink,
    BundleStep,
    EvidenceBundle,
)
from app.modules.correlation.domain.graph import build_graph
from app.modules.correlation.domain.incidents import LinkKind
from app.modules.correlation.domain.timeline import build_timeline
from app.modules.correlation.infrastructure.unit_of_work import SqlCorrelationUnitOfWork
from app.modules.threatintel.domain.indicators import Indicator
from app.modules.threatintel.infrastructure.repositories import SqlIntelUnitOfWork


def _value(key: str) -> str:
    return key.split(":", 1)[-1]


class SqlBundleSource:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def build(self, org_id: UUID, incident_id: UUID) -> EvidenceBundle | None:
        repo = SqlCorrelationUnitOfWork(self._session).incidents
        incident = await repo.get(org_id, incident_id)
        if incident is None:
            return None
        links = await repo.links(incident.id)
        digests = await repo.evidence(incident.id)
        entities = await repo.entities(incident.id)

        kept = digests[:MAX_EVENTS]
        kept_uids = {event.event_uid for event in kept}

        def only_kept(uids: tuple[str, ...] | list[str]) -> list[str]:
            return [uid for uid in uids if uid in kept_uids]

        events = []
        for digest in kept:
            detail = {k: v for k, v in digest.detail.items() if k != "cmd_line"}
            if isinstance(digest.detail.get("cmd_line"), str):
                detail["cmd_line"] = digest.detail["cmd_line"][:MAX_COMMAND]
            events.append(
                BundleEvent(
                    event_uid=digest.event_uid,
                    time=digest.time.isoformat(),
                    action=digest.action,
                    outcome=digest.outcome,
                    entities={role: [_value(key) for key in keys] for role, keys in sorted(digest.roles.items())},
                    detail=detail,
                    raw=None if digest.raw is None else digest.raw[:MAX_RAW],
                )
            )
        findings = [
            BundleFinding(
                link_id=str(link.id),
                rule_title=str(link.detail.get("rule_title", "")),
                severity_id=int(link.detail.get("severity_id", 1)),
                techniques=list(link.techniques),
                tactics=list(link.tactics),
                events=only_kept(link.evidence),
            )
            for link in links
            if link.kind is LinkKind.FINDING
        ]
        correlations = [
            BundleLink(
                link_id=str(link.id),
                rule=link.rule.value,
                reason=link.reason,
                shared_entities=[m.key for m in link.matched],
                events=only_kept(link.evidence),
            )
            for link in links
        ]
        steps = [
            BundleStep(
                time=step.first_seen.isoformat(),
                action=step.action,
                count=len(step.events),
                host=step.host,
                users=list(step.users),
                process=step.process,
                remote=step.remote,
                events=only_kept(step.events),
            )
            for step in build_timeline(kept, links)
        ]
        edges = [
            BundleEdge(
                source=edge.source,
                relation=edge.label,
                target=edge.target,
                events=only_kept(edge.events),
                name=edge.relation,
            )
            for edge in build_graph(kept).edges
        ]
        indicators = [i for i in (Indicator.parse(entity.key) for entity in entities) if i is not None]
        intel = [
            BundleIntel(
                indicator=result.indicator.key,
                provider=result.provider,
                verdict=result.verdict.value,
                summary=result.summary,
                retrieved_at=result.retrieved_at.isoformat(),
            )
            for result in await SqlIntelUnitOfWork(self._session).results.get_many(org_id, indicators)
            if result.status.value == "found"
        ]
        return EvidenceBundle(
            incident={
                "id": str(incident.id),
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status.value,
                "first_seen": incident.first_seen.isoformat(),
                "last_seen": incident.last_seen.isoformat(),
                "techniques": list(incident.techniques),
                "tactics": list(incident.tactics),
                "assessment": [str(entry.get("because", "")) for entry in incident.assessment],
            },
            findings=findings,
            links=correlations,
            events=events,
            timeline=steps,
            graph=edges,
            intel=sorted(intel, key=lambda i: (i.indicator, i.provider)),
            entities=sorted(entity.key for entity in entities),
            omitted_events=len(digests) - len(kept),
        )
