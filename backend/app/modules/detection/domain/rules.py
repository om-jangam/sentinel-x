"""Loaded, validated detection rules. Rules are code: YAML reviewed in git, compiled once at start-up."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.core.errors import NotFoundError, ValidationFailedError
from app.modules.detection.domain.predicates import Predicate


class RuleType(StrEnum):
    SIGMA = "sigma"
    THRESHOLD = "threshold"


# Sigma levels map onto OCSF severity_id.
LEVEL_SEVERITY = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

# MITRE ATT&CK Enterprise tactics (v17), as Sigma writes them in `attack.<tactic>` tags. v17 renamed
# TA0005 Defense Evasion to **Stealth** and added TA0112 **Defense Impairment**; the shipped SigmaHQ pack
# uses the new names on 413 tags, every one of which this set silently dropped before they were added.
TACTICS = frozenset(
    {
        "reconnaissance",
        "resource_development",
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "stealth",
        "defense_impairment",
        "credential_access",
        "discovery",
        "lateral_movement",
        "collection",
        "command_and_control",
        "exfiltration",
        "impact",
    }
)
# Older rules (including one of Sentinel-X's own) still use the pre-v17 name for the same tactic id.
RENAMED_TACTICS = {"defense_evasion": "stealth"}
_TECHNIQUE_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")
# The catalogue is in memory, so a page is a slice of a list; the bounds match the API's envelope.
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
MAX_LOGSOURCE = 64


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
        elif lowered.startswith("attack."):
            # TA0005 was renamed, not replaced, so a rule still tagged `defense_evasion` means Stealth.
            tactic = RENAMED_TACTICS.get(lowered[7:].replace("-", "_"), lowered[7:].replace("-", "_"))
            if tactic in TACTICS and tactic not in tactics:
                tactics.append(tactic)
    return Attack(techniques=tuple(techniques), tactics=tuple(tactics))


def covers_technique(tagged: str, wanted: str) -> bool:
    """Same technique, its parent, or one of its sub-techniques.

    A rule tagged `T1059.001` is a rule for `T1059`, so asking for the parent finds it; asking for
    `T1059.001` also finds a rule tagged only with the parent, because that rule claims the whole
    technique. Used for the rule catalogue's filter and for scoring the public-recording evaluation, so
    both mean the same thing by "covers".
    """
    tagged, wanted = tagged.upper(), wanted.upper()
    return tagged == wanted or wanted.startswith(tagged + ".") or tagged.startswith(wanted + ".")


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

    def page(self, query: RuleQuery) -> RulePage:
        """One page of the matching rules, in `all()`'s order, resuming after the rule with id `after`.

        The cursor is a rule id rather than an offset. Ids are unique and the order is by title, so a page
        boundary survives a reload that adds or removes rules — an offset would silently skip or repeat.
        """
        rules = [rule for rule in self.all() if query.selects(rule)]
        start = 0
        if query.after is not None:
            index = next((i for i, rule in enumerate(rules) if rule.meta.id == query.after), None)
            if index is None:
                # Either the rule the last page ended on is gone (the pack was re-imported), or the
                # filters changed between pages. Resuming would skip or repeat rules without saying so,
                # so the client is told to start again.
                raise ValidationFailedError("Invalid pagination cursor")
            start = index + 1
        window = tuple(rules[start : start + query.limit])
        exhausted = start + len(window) >= len(rules)
        return RulePage(
            items=window,
            next_after=None if exhausted or not window else window[-1].meta.id,
            total=len(rules),
        )


@dataclass(frozen=True, slots=True)
class RuleQuery:
    """What a client asked of the catalogue, validated once before anything is searched."""

    limit: int = DEFAULT_PAGE_SIZE
    after: str | None = None
    technique: str | None = None
    logsource: str | None = None

    def __post_init__(self) -> None:
        problems: list[dict[str, Any]] = []

        def fail(loc: str, msg: str) -> None:
            problems.append({"loc": [loc], "msg": msg, "type": "rule_query"})

        if not 1 <= self.limit <= MAX_PAGE_SIZE:
            fail("limit", f"must be between 1 and {MAX_PAGE_SIZE}")
        if self.technique is not None and not TECHNIQUE_ID.fullmatch(self.technique.upper()):
            fail("technique", "must look like T1110 or T1110.003")
        if self.logsource is not None and not 1 <= len(self.logsource) <= MAX_LOGSOURCE:
            fail("logsource", f"must be 1 to {MAX_LOGSOURCE} characters")
        if problems:
            raise ValidationFailedError("Invalid rule search", errors=problems)

    def selects(self, rule: Rule) -> bool:
        if self.technique is not None and not any(
            covers_technique(tagged, self.technique) for tagged in rule.meta.attack.techniques
        ):
            return False
        if self.logsource is not None:
            # Only Sigma rules have a logsource. A platform threshold rule matches normalised OCSF fields
            # across sources at once (ADR-0015), so it belongs to no single log and matches no value here.
            if not isinstance(rule, SingleEventRule):
                return False
            if rule.logsource.casefold() != self.logsource.casefold():
                return False
        return True


@dataclass(frozen=True, slots=True)
class RulePage:
    items: tuple[Rule, ...]
    next_after: str | None = None
    total: int = 0
