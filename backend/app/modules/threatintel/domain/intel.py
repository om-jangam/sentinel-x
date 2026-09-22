"""What a provider said about an indicator, and when. Intel is context from a named source, never evidence.

Sentinel-X records the provider's own classification. It does not merge providers into one verdict:
analysts see each source, what it said, and when it was asked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from app.modules.threatintel.domain.indicators import Indicator

MAX_RELATED = 20
MAX_TAGS = 20
MAX_REFERENCES = 10
MAX_SUMMARY = 500
# A failed lookup is retried after this, not after the full cache period, but not hammered either.
ERROR_RETRY = timedelta(minutes=15)


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class LookupStatus(StrEnum):
    FOUND = "found"  # the provider has something to say about the indicator
    NOT_FOUND = "not_found"  # the provider was asked and knows nothing
    ERROR = "error"  # the provider could not be asked


@dataclass(frozen=True, slots=True)
class RelatedIndicator:
    type: str
    value: str
    relation: str  # e.g. "resolved to", "pulse"

    def as_json(self) -> dict[str, str]:
        return {"type": self.type, "value": self.value, "relation": self.relation}


@dataclass(frozen=True, slots=True)
class ProviderAnswer:
    """What a provider returns for one indicator; the service stamps it with source and times."""

    verdict: Verdict
    summary: str
    confidence: int | None = None  # 0-100, only when the provider states one
    tags: tuple[str, ...] = ()
    related: tuple[RelatedIndicator, ...] = ()
    references: tuple[str, ...] = ()
    provider_first_seen: datetime | None = None
    provider_last_seen: datetime | None = None


@dataclass(frozen=True, slots=True)
class IntelResult:
    provider: str
    indicator: Indicator
    status: LookupStatus
    verdict: Verdict
    summary: str
    retrieved_at: datetime
    expires_at: datetime
    confidence: int | None = None
    tags: tuple[str, ...] = ()
    related: tuple[RelatedIndicator, ...] = ()
    references: tuple[str, ...] = ()
    provider_first_seen: datetime | None = None
    provider_last_seen: datetime | None = None
    error: str | None = None

    @classmethod
    def from_answer(
        cls, provider: str, indicator: Indicator, answer: ProviderAnswer | None, *, now: datetime, ttl: timedelta
    ) -> IntelResult:
        if answer is None:
            return cls(
                provider=provider,
                indicator=indicator,
                status=LookupStatus.NOT_FOUND,
                verdict=Verdict.UNKNOWN,
                summary="No information from this provider.",
                retrieved_at=now,
                expires_at=now + ttl,
            )
        confidence = None if answer.confidence is None else max(0, min(100, answer.confidence))
        return cls(
            provider=provider,
            indicator=indicator,
            status=LookupStatus.FOUND,
            verdict=answer.verdict,
            summary=answer.summary[:MAX_SUMMARY],
            retrieved_at=now,
            expires_at=now + ttl,
            confidence=confidence,
            tags=tuple(dict.fromkeys(tag[:64] for tag in answer.tags if tag))[:MAX_TAGS],
            related=answer.related[:MAX_RELATED],
            references=tuple(ref for ref in answer.references if ref.startswith("https://"))[:MAX_REFERENCES],
            provider_first_seen=answer.provider_first_seen,
            provider_last_seen=answer.provider_last_seen,
        )

    @classmethod
    def failed(cls, provider: str, indicator: Indicator, reason: str, *, now: datetime) -> IntelResult:
        return cls(
            provider=provider,
            indicator=indicator,
            status=LookupStatus.ERROR,
            verdict=Verdict.UNKNOWN,
            summary="The provider could not be reached.",
            retrieved_at=now,
            expires_at=now + ERROR_RETRY,
            error=reason[:200],
        )

    def is_fresh(self, now: datetime) -> bool:
        return self.expires_at > now


@dataclass(frozen=True, slots=True)
class ProviderInfo:
    name: str
    title: str
    kind: str  # "local" or "external"
    supports: tuple[str, ...]
    detail: dict[str, Any] = field(default_factory=dict)
    cache_ttl: timedelta | None = None  # None: the service default
