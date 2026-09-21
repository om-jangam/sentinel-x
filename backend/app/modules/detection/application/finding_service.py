"""Read side: findings and the loaded rule catalogue."""

from __future__ import annotations

from uuid import UUID

from app.core.errors import NotFoundError
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.modules.detection.domain.findings import Finding, FindingPage, FindingQuery
from app.modules.detection.domain.ports import DetectionUnitOfWork
from app.modules.detection.domain.rules import Rule, RuleSet


class FindingQueryService:
    def __init__(self, uow: DetectionUnitOfWork) -> None:
        self._uow = uow

    async def search(self, principal: Principal, query: FindingQuery) -> FindingPage:
        principal.require(Permission.FINDING_READ)
        return await self._uow.findings.search(principal.org_id, query)

    async def get(self, principal: Principal, finding_id: UUID) -> Finding:
        principal.require(Permission.FINDING_READ)
        finding = await self._uow.findings.get(principal.org_id, finding_id)
        if finding is None:
            raise NotFoundError("Finding not found")
        return finding


class RuleCatalog:
    def __init__(self, rules: RuleSet) -> None:
        self._rules = rules

    def list_rules(self, principal: Principal) -> list[Rule]:
        principal.require(Permission.RULE_READ)
        return self._rules.all()

    def get_rule(self, principal: Principal, rule_id: str) -> Rule:
        principal.require(Permission.RULE_READ)
        return self._rules.get(rule_id)
