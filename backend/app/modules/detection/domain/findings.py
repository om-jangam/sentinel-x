from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.errors import ValidationFailedError
from app.modules.detection.domain.rules import TECHNIQUE_ID, RuleType

MAX_EVIDENCE = 100
MAX_ENTITY_VALUES = 20
MAX_QUERY_WINDOW = timedelta(days=90)
MAX_PAGE_SIZE = 200

SEVERITY_NAMES = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}


@dataclass(frozen=True, slots=True)
class Finding:
    """What a rule saw, and exactly which stored events show it. Immutable once written."""

    id: UUID
    org_id: UUID
    rule_id: str
    rule_title: str
    rule_type: RuleType
    rule_version: str
    severity_id: int
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]
    entities: dict[str, list[str]]
    evidence: tuple[str, ...]  # sx.event_uid of each supporting event, in event-time order
    first_seen: datetime
    last_seen: datetime
    dedupe_key: str
    created_at: datetime

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("a finding must cite at least one event")
        if len(self.evidence) > MAX_EVIDENCE:
            raise ValueError(f"a finding cites at most {MAX_EVIDENCE} events")

    @property
    def severity(self) -> str:
        return SEVERITY_NAMES.get(self.severity_id, "Unknown")

    def audit_view(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "severity_id": self.severity_id, "evidence_count": len(self.evidence)}


@dataclass(frozen=True, slots=True)
class FindingCursor:
    last_seen_us: int
    finding_id: str

    def encode(self) -> str:
        return f"{self.last_seen_us}:{self.finding_id}"

    @classmethod
    def decode(cls, value: str) -> FindingCursor:
        micros, _, finding_id = value.partition(":")
        if not finding_id or not micros.lstrip("-").isdigit():
            raise ValidationFailedError("Invalid pagination cursor")
        try:
            UUID(finding_id)
        except ValueError as exc:
            raise ValidationFailedError("Invalid pagination cursor") from exc
        return cls(last_seen_us=int(micros), finding_id=finding_id)


@dataclass(frozen=True, slots=True)
class FindingQuery:
    time_from: datetime | None = None
    time_to: datetime | None = None
    severity_min: int | None = None
    rule_id: str | None = None
    technique: str | None = None
    limit: int = 50
    cursor: FindingCursor | None = None

    def __post_init__(self) -> None:
        problems: list[dict[str, Any]] = []

        def fail(loc: str, msg: str) -> None:
            problems.append({"loc": [loc], "msg": msg, "type": "finding_query"})

        if self.time_from and self.time_to:
            if self.time_from >= self.time_to:
                fail("time_from", "must be earlier than time_to")
            elif self.time_to - self.time_from > MAX_QUERY_WINDOW:
                fail("time_to", f"window may not exceed {MAX_QUERY_WINDOW.days} days")
        if not 1 <= self.limit <= MAX_PAGE_SIZE:
            fail("limit", f"must be between 1 and {MAX_PAGE_SIZE}")
        if self.severity_min is not None and self.severity_min not in SEVERITY_NAMES:
            fail("severity_min", "must be 1-5")
        if self.technique is not None and not TECHNIQUE_ID.fullmatch(self.technique):
            fail("technique", "must look like T1110 or T1110.003")
        if problems:
            raise ValidationFailedError("Invalid finding search", errors=problems)


@dataclass(frozen=True, slots=True)
class FindingPage:
    items: list[Finding]
    next_cursor: FindingCursor | None = None
