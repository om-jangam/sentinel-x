"""Loaded, validated detection rules. Rules are code: YAML reviewed in git, compiled once at start-up."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from app.core.errors import NotFoundError, ValidationFailedError
from app.modules.detection.domain.predicates import Predicate


class RuleType(StrEnum):
    SIGMA = "sigma"
    THRESHOLD = "threshold"


# Sigma levels map onto OCSF severity_id.
LEVEL_SEVERITY = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

# MITRE ATT&CK Enterprise tactics, as Sigma writes them in `attack.<tactic>` tags.
TACTICS = frozenset(
    {
        "reconnaissance",
        "resource_development",
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "discovery",
        "lateral_movement",
        "collection",
        "command_and_control",
        "exfiltration",
        "impact",
    }
)
_TECHNIQUE_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")


@dataclass(frozen=True, slots=True)
class Attack:
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]


def attack_from_tags(tags: Iterable[str]) -> Attack:
    """`attack.t1110.003` → `T1110.003`; `attack.credential_access` → tactic. Other tags are ignored."""
    techniques: list[str] = []
    tactics: list[str] = []
    for tag in tags:
        lowered = tag.strip().lower()
        if match := _TECHNIQUE_TAG.fullmatch(lowered):
            technique = match.group(1).upper()
            if technique not in techniques:
                techniques.append(technique)
        elif lowered.startswith("attack.") and lowered[7:].replace("-", "_") in TACTICS:
            tactic = lowered[7:].replace("-", "_")
            if tactic not in tactics:
                tactics.append(tactic)
    return Attack(techniques=tuple(techniques), tactics=tuple(tactics))


@dataclass(frozen=True, slots=True)
class RuleMeta:
    id: str
    title: str
    description: str
    level: str
    severity_id: int
    attack: Attack
    version: str  # SHA-256 of the rule file: findings record exactly which text fired
    path: str
    references: tuple[str, ...] = ()
    false_positives: tuple[str, ...] = ()
    # Who wrote the rule, and where it came from. Community rules are licensed on the condition that
    # matches keep naming their author (Detection Rule License 1.1), so findings carry both.
    author: str = ""
    source_url: str | None = None


@dataclass(frozen=True, slots=True)
class SingleEventRule:
    """A Sigma rule: evaluated against each event on its own."""

    meta: RuleMeta
    logsource: str
    predicate: Predicate
    type: RuleType = RuleType.SIGMA


@dataclass(frozen=True, slots=True)
class ThresholdRule:
    """A platform pattern rule: enough matching events for one group within a window of event time."""

    meta: RuleMeta
    match: Predicate
    group_by: tuple[str, ...]
    threshold: int
    window_ms: int
    count_distinct: str | None = None
    type: RuleType = RuleType.THRESHOLD


Rule = SingleEventRule | ThresholdRule


@dataclass(frozen=True, slots=True)
class RuleSet:
    single_event: tuple[SingleEventRule, ...] = ()
    threshold: tuple[ThresholdRule, ...] = ()

    def __post_init__(self) -> None:
        ids = [rule.meta.id for rule in self.all()]
        duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate rule ids: {', '.join(duplicates)}")

    def all(self) -> list[Rule]:
        rules: list[Rule] = [*self.single_event, *self.threshold]
        return sorted(rules, key=lambda rule: rule.meta.title.casefold())

    def get(self, rule_id: str) -> Rule:
        for rule in self.all():
            if rule.meta.id == rule_id:
                return rule
        raise NotFoundError("Detection rule not found")

    def page(self, *, limit: int, after: str | None = None) -> RulePage:
        """One page of the catalogue, in `all()`'s order, resuming after the rule with id `after`.

        The cursor is a rule id rather than an offset. Ids are unique and the order is by title, so a page
        boundary survives a reload that adds or removes rules — an offset would silently skip or repeat.
        """
        rules = self.all()
        start = 0
        if after is not None:
            index = next((i for i, rule in enumerate(rules) if rule.meta.id == after), None)
            if index is None:
                # The rule the last page ended on is gone (the pack was re-imported). Resuming would skip
                # or repeat rules without saying so, so the client is told to start again.
                raise ValidationFailedError("Invalid pagination cursor")
            start = index + 1
        window = tuple(rules[start : start + limit])
        exhausted = start + len(window) >= len(rules)
        return RulePage(items=window, next_after=None if exhausted or not window else window[-1].meta.id)


@dataclass(frozen=True, slots=True)
class RulePage:
    items: tuple[Rule, ...]
    next_after: str | None = None
