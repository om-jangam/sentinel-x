from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.modules.threatintel.application.intel_service import MAX_LOOKUP
from app.modules.threatintel.domain.intel import IntelResult, ProviderInfo


class ProviderRead(BaseModel):
    name: str
    title: str
    kind: str = Field(description="`local` (a file this deployment loads) or `external` (a third-party service)")
    supports: list[str]
    detail: dict[str, Any]

    @classmethod
    def from_info(cls, info: ProviderInfo) -> ProviderRead:
        return cls(name=info.name, title=info.title, kind=info.kind, supports=list(info.supports), detail=info.detail)


class RelatedRead(BaseModel):
    type: str
    value: str
    relation: str


class IntelResultRead(BaseModel):
    indicator: str = Field(description="`type:value`, matching incident entity keys")
    provider: str
    status: str = Field(description="`found`, `not_found` (asked, nothing known) or `error` (couldn't ask)")
    verdict: str = Field(description="The provider's own classification; Sentinel-X does not merge providers")
    confidence: int | None
    summary: str
    tags: list[str]
    related: list[RelatedRead]
    references: list[str]
    provider_first_seen: datetime | None
    provider_last_seen: datetime | None
    retrieved_at: datetime = Field(description="When the provider was asked")
    expires_at: datetime
    error: str | None

    @classmethod
    def from_result(cls, result: IntelResult) -> IntelResultRead:
        return cls(
            indicator=result.indicator.key,
            provider=result.provider,
            status=result.status.value,
            verdict=result.verdict.value,
            confidence=result.confidence,
            summary=result.summary,
            tags=list(result.tags),
            related=[RelatedRead(type=r.type, value=r.value, relation=r.relation) for r in result.related],
            references=list(result.references),
            provider_first_seen=result.provider_first_seen,
            provider_last_seen=result.provider_last_seen,
            retrieved_at=result.retrieved_at,
            expires_at=result.expires_at,
            error=result.error,
        )


class IntelLookup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicators: list[str] = Field(max_length=MAX_LOOKUP, description="`ip:…`, `domain:…` or `hash:…` keys")


class IntelLookupResponse(BaseModel):
    results: list[IntelResultRead]
    skipped: list[str] = Field(description="Keys that aren't indicators Sentinel-X looks up (e.g. internal IPs)")
