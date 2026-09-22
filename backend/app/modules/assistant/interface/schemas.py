from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.modules.assistant.application.assistant_service import AssistantStatus
from app.modules.assistant.domain.records import AnalysisRecord


class AssistantStatusRead(BaseModel):
    enabled: bool
    provider: str | None
    model: str | None
    prompt_version: str

    @classmethod
    def from_status(cls, status: AssistantStatus) -> AssistantStatusRead:
        return cls(
            enabled=status.enabled, provider=status.provider, model=status.model, prompt_version=status.prompt_version
        )


class AnalysisRead(BaseModel):
    id: UUID
    incident_id: UUID
    requested_by: UUID
    created_at: datetime
    status: str = Field(description="`completed`, `rejected` (nothing could be grounded) or `unavailable`")
    provider: str
    model: str
    prompt_version: str
    bundle_hash: str = Field(description="SHA-256 of the exact evidence the model was given")
    duration_ms: int
    output: dict[str, Any] | None = Field(
        description="The validated analysis: summary, FACT / INFERENCE / UNCERTAINTY statements, techniques, next steps"
    )
    dropped: list[dict[str, Any]] = Field(description="What validation removed, each with the reason")
    reason: str | None
    citation_validity: float | None = Field(description="Share of the model's citations that existed in the evidence")
    stats: dict[str, Any]

    @classmethod
    def from_record(cls, record: AnalysisRecord) -> AnalysisRead:
        return cls(
            id=record.id,
            incident_id=record.incident_id,
            requested_by=record.requested_by,
            created_at=record.created_at,
            status=record.status.value,
            provider=record.provider,
            model=record.model,
            prompt_version=record.prompt_version,
            bundle_hash=record.bundle_hash,
            duration_ms=record.duration_ms,
            output=record.output,
            dropped=record.dropped,
            reason=record.reason,
            citation_validity=record.citation_validity,
            stats=record.stats,
        )
