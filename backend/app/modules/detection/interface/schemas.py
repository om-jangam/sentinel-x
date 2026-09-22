from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.core.pagination import encode_cursor
from app.modules.detection.domain.findings import Finding, FindingPage
from app.modules.detection.domain.rules import Rule, SingleEventRule


class FindingRead(BaseModel):
    id: UUID
    rule_id: str
    rule_title: str
    rule_type: str
    rule_version: str
    rule_author: str
    rule_source: str | None
    severity_id: int
    severity: str
    techniques: list[str]
    tactics: list[str]
    entities: dict[str, list[str]]
    evidence: list[str]
    evidence_count: int
    first_seen: datetime
    last_seen: datetime
    created_at: datetime

    @classmethod
    def from_entity(cls, finding: Finding) -> FindingRead:
        return cls(
            id=finding.id,
            rule_id=finding.rule_id,
            rule_title=finding.rule_title,
            rule_type=finding.rule_type.value,
            rule_version=finding.rule_version,
            rule_author=finding.rule_author,
            rule_source=finding.rule_source,
            severity_id=finding.severity_id,
            severity=finding.severity,
            techniques=list(finding.techniques),
            tactics=list(finding.tactics),
            entities=finding.entities,
            evidence=list(finding.evidence),
            evidence_count=len(finding.evidence),
            first_seen=finding.first_seen,
            last_seen=finding.last_seen,
            created_at=finding.created_at,
        )


class FindingPageResponse(BaseModel):
    items: list[FindingRead]
    next_cursor: str | None = None

    @classmethod
    def from_page(cls, page: FindingPage) -> FindingPageResponse:
        return cls(
            items=[FindingRead.from_entity(finding) for finding in page.items],
            next_cursor=encode_cursor(page.next_cursor.encode()) if page.next_cursor else None,
        )


class ThresholdSettings(BaseModel):
    group_by: list[str]
    count_distinct: str | None
    threshold: int
    window_seconds: int


class RuleRead(BaseModel):
    id: str
    title: str
    description: str
    type: str
    level: str
    severity_id: int
    techniques: list[str]
    tactics: list[str]
    version: str
    path: str
    author: str
    source_url: str | None
    references: list[str]
    false_positives: list[str]
    logsource: str | None = None
    threshold: ThresholdSettings | None = None

    @classmethod
    def from_rule(cls, rule: Rule) -> RuleRead:
        meta = rule.meta
        base = {
            "id": meta.id,
            "title": meta.title,
            "description": meta.description,
            "type": rule.type.value,
            "level": meta.level,
            "severity_id": meta.severity_id,
            "techniques": list(meta.attack.techniques),
            "tactics": list(meta.attack.tactics),
            "version": meta.version,
            "path": meta.path,
            "author": meta.author,
            "source_url": meta.source_url,
            "references": list(meta.references),
            "false_positives": list(meta.false_positives),
        }
        if isinstance(rule, SingleEventRule):
            return cls(**base, logsource=rule.logsource)
        return cls(
            **base,
            threshold=ThresholdSettings(
                group_by=list(rule.group_by),
                count_distinct=rule.count_distinct,
                threshold=rule.threshold,
                window_seconds=rule.window_ms // 1000,
            ),
        )
