"""Asking the assistant about an incident: bundle the evidence, ask the model, validate, record, audit.

The assistant only explains. It has no tools and changes nothing: an analysis is a stored, audited record
next to the incident, and the incident, its links and its evidence are untouched by it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from time import perf_counter
from uuid import UUID

from app.core.audit.port import AuditEvent
from app.core.clock import Clock, utcnow
from app.core.errors import NotFoundError, ServiceUnavailableError
from app.core.ids import uuid7
from app.core.observability.metrics import ASSISTANT_ANALYSES
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.modules.assistant.domain.analysis import validate
from app.modules.assistant.domain.ports import (
    AssistantUnitOfWork,
    BundleSource,
    LanguageModel,
    ModelUnavailableError,
)
from app.modules.assistant.domain.prompt import OUTPUT_SCHEMA, PROMPT_VERSION, messages
from app.modules.assistant.domain.records import AnalysisRecord, AnalysisStatus

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AssistantStatus:
    enabled: bool
    provider: str | None
    model: str | None
    prompt_version: str


class AssistantService:
    def __init__(
        self,
        *,
        model: LanguageModel | None,
        bundles: BundleSource,
        uow: AssistantUnitOfWork,
        clock: Clock = utcnow,
    ) -> None:
        self._model = model
        self._bundles = bundles
        self._uow = uow
        self._clock = clock

    def status(self, principal: Principal) -> AssistantStatus:
        principal.require(Permission.INCIDENT_READ)
        return AssistantStatus(
            enabled=self._model is not None,
            provider=None if self._model is None else self._model.provider,
            model=None if self._model is None else self._model.model,
            prompt_version=PROMPT_VERSION,
        )

    async def history(self, principal: Principal, incident_id: UUID) -> list[AnalysisRecord]:
        principal.require(Permission.INCIDENT_READ)
        return await self._uow.analyses.list_for_incident(principal.org_id, incident_id)

    async def analyse(self, principal: Principal, incident_id: UUID) -> AnalysisRecord:
        principal.require(Permission.ASSISTANT_USE)
        if self._model is None:
            raise ServiceUnavailableError("The AI assistant is not configured (SENTINELX_AI_PROVIDER)")
        bundle = await self._bundles.build(principal.org_id, incident_id)
        if bundle is None:
            raise NotFoundError("Incident not found")
        # End the read before a model call that can take minutes, so no transaction is held open meanwhile.
        await self._uow.rollback()

        started = perf_counter()
        status, reason, output, dropped = AnalysisStatus.UNAVAILABLE, None, None, []
        validity: float | None = None
        stats: dict[str, int] = {}
        try:
            raw = await self._model.complete(messages(bundle), OUTPUT_SCHEMA)
        except ModelUnavailableError as exc:
            reason = str(exc)[:500]
        else:
            result = validate(raw, bundle)
            dropped = [{"item": d.item, "reason": d.reason} for d in result.dropped]
            validity, stats = result.citation_validity, result.stats
            if result.analysis is None:
                status, reason = AnalysisStatus.REJECTED, result.rejected_reason
            else:
                status, output = AnalysisStatus.COMPLETED, result.analysis.as_json()
        duration_ms = int((perf_counter() - started) * 1000)
        ASSISTANT_ANALYSES.labels(status=status.value).observe(duration_ms / 1000)

        record = AnalysisRecord(
            id=uuid7(),
            org_id=principal.org_id,
            incident_id=incident_id,
            requested_by=principal.user_id,
            created_at=self._clock(),
            status=status,
            provider=self._model.provider,
            model=self._model.model,
            prompt_version=PROMPT_VERSION,
            bundle_hash=bundle.digest,
            duration_ms=duration_ms,
            output=output,
            dropped=dropped,
            reason=reason,
            citation_validity=validity,
            stats=stats,
        )
        await self._uow.analyses.add(record)
        await self._uow.audit.record(
            AuditEvent(
                org_id=principal.org_id,
                action="incident.analysis_requested",
                resource_type="incident",
                resource_id=str(incident_id),
                actor_id=principal.user_id,
                after=record.audit_view(),
            )
        )
        await self._uow.commit()
        logger.info(
            "assistant analysis recorded",
            extra={"analysis_status": status.value, "duration_ms": duration_ms, "dropped_items": len(dropped)},
        )
        return record
