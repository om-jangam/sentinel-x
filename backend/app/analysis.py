"""Composition of the analysis pipeline: detection, then correlation, on each batch of normalised events.

Lives at the composition root so neither module imports the other: detection hands its stored findings to a
sink, and this adapter turns them into the signals correlation understands.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from uuid import UUID

from app.core.db.session import Database
from app.core.events.bus import Event
from app.core.events.topics import INCIDENTS_CHANGED
from app.modules.correlation.application.correlation_service import CorrelationService
from app.modules.correlation.domain.incidents import FindingSignal
from app.modules.correlation.domain.ports import EvidenceLookup
from app.modules.correlation.infrastructure.unit_of_work import sql_uow_factory as correlation_uow_factory
from app.modules.detection.application.detection_service import DetectionService
from app.modules.detection.domain.findings import Finding
from app.modules.detection.domain.ports import WindowStore
from app.modules.detection.domain.predicates import Document
from app.modules.detection.domain.rules import RuleSet
from app.modules.detection.infrastructure.unit_of_work import sql_uow_factory as detection_uow_factory


def signal(finding: Finding) -> FindingSignal:
    return FindingSignal(
        id=finding.id,
        rule_id=finding.rule_id,
        rule_title=finding.rule_title,
        severity_id=finding.severity_id,
        techniques=finding.techniques,
        tactics=finding.tactics,
        evidence=finding.evidence,
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
    )


Publish = Callable[[Event], Awaitable[None]]


def build_analysis(
    rules: RuleSet,
    database: Database,
    windows: WindowStore,
    *,
    lookup: EvidenceLookup | None = None,
    publish: Publish | None = None,
) -> DetectionService:
    """`lookup` fetches stored events (the event store's `get_many`), for evidence from earlier batches.

    `publish` announces changed incidents' indicators on `incidents.changed`, for threat-intel enrichment.
    """
    correlation = CorrelationService(uow_factory=correlation_uow_factory(database), lookup=lookup)

    async def correlate(org_id: UUID, findings: Sequence[Finding], documents: Sequence[Document]) -> None:
        indicators = await correlation.handle(org_id, [signal(finding) for finding in findings], documents)
        if indicators and publish is not None:
            await publish(Event(topic=INCIDENTS_CHANGED, org_id=org_id, payload={"indicators": indicators}))

    return DetectionService(rules, uow_factory=detection_uow_factory(database), windows=windows, on_findings=correlate)
