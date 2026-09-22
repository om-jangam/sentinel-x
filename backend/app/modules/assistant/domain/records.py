"""A stored analysis: what was asked, of which model, on which exact evidence, and what survived validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID


class AnalysisStatus(StrEnum):
    COMPLETED = "completed"  # at least one statement survived validation
    REJECTED = "rejected"  # the model answered, but nothing it said could be grounded
    UNAVAILABLE = "unavailable"  # the model could not be reached or timed out


@dataclass(frozen=True, slots=True)
class AnalysisRecord:
    id: UUID
    org_id: UUID
    incident_id: UUID
    requested_by: UUID
    created_at: datetime
    status: AnalysisStatus
    provider: str
    model: str
    prompt_version: str
    bundle_hash: str
    duration_ms: int
    output: dict[str, Any] | None = None  # the validated analysis
    dropped: list[dict[str, Any]] = field(default_factory=list)  # what validation removed, with reasons
    reason: str | None = None  # why it was rejected or unavailable
    citation_validity: float | None = None  # share of the raw citations that existed in the bundle
    stats: dict[str, int] = field(default_factory=dict)

    def audit_view(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "provider": self.provider,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "bundle_hash": self.bundle_hash,
            "statements_kept": self.stats.get("statements_kept", 0),
            "dropped": len(self.dropped),
        }
