"""What the loaded rules look for, as an ATT&CK Navigator layer.

This answers "what would this installation notice?" — and only that. A technique appears because a loaded
rule is tagged with it, which is a statement about the rule, not about the estate: the
[evaluation](../../../../../docs/evaluation/README.md) measured 917 community rules moving no technique
verdict on eight public recordings, so a full row in this layer is not evidence that anything would be
caught. The layer's own description says so, because a coverage map that implies otherwise is the most
flattering lie a detection product can tell.

Scores are counted the way the incident layer counts them: a technique is scored by rules that **name**
it, never by rules that name its parent or a sub-technique. Navigator already shows sub-techniques under
their parent, so inventing a parent score from its children would overstate the row an analyst reads
first.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.attack_navigator import Scored, layer
from app.modules.detection.domain.rules import Rule

COMMUNITY_PREFIX = "sigmahq/"
MAX_TITLES = 5


@dataclass(frozen=True, slots=True)
class TechniqueCoverage:
    technique_id: str
    rules: int
    own: int
    community: int
    titles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Coverage:
    """The rule set as techniques and tactics, plus what it does not place anywhere."""

    techniques: tuple[TechniqueCoverage, ...] = ()
    tactics: tuple[tuple[str, int], ...] = ()
    rule_count: int = 0
    untagged_rules: int = 0

    @property
    def technique_count(self) -> int:
        return len(self.techniques)

    @property
    def sub_technique_count(self) -> int:
        return sum(1 for technique in self.techniques if "." in technique.technique_id)


def coverage(rules: Sequence[Rule]) -> Coverage:
    """Group the rules by the techniques and tactics they name."""
    by_technique: dict[str, _Bucket] = {}
    tactics: Counter[str] = Counter()
    untagged = 0

    for rule in rules:
        attack = rule.meta.attack
        if not attack.techniques:
            untagged += 1
        for tactic in attack.tactics:
            tactics[tactic] += 1
        for technique in attack.techniques:
            bucket = by_technique.setdefault(technique.upper(), _Bucket())
            bucket.titles.append(rule.meta.title)
            if rule.meta.path.startswith(COMMUNITY_PREFIX):
                bucket.community += 1
            else:
                bucket.own += 1

    techniques = tuple(
        TechniqueCoverage(
            technique_id=technique,
            rules=bucket.own + bucket.community,
            own=bucket.own,
            community=bucket.community,
            # The most useful few, in a stable order: the whole list of 60 would not fit a comment.
            titles=tuple(sorted(bucket.titles)[:MAX_TITLES]),
        )
        for technique, bucket in sorted(by_technique.items())
    )
    return Coverage(
        techniques=techniques,
        tactics=tuple(sorted(tactics.items(), key=lambda item: (-item[1], item[0]))),
        rule_count=len(rules),
        untagged_rules=untagged,
    )


def coverage_layer(rules: Sequence[Rule], *, generated: datetime) -> dict[str, Any]:
    """The rule set as a Navigator layer, scored by how many rules name each technique."""
    counted = coverage(rules)
    return layer(
        name="Sentinel-X · rule coverage",
        description=(
            f"{counted.rule_count:,} loaded detection rules name {counted.technique_count:,} ATT&CK "
            f"techniques ({counted.sub_technique_count:,} of them sub-techniques); "
            f"{counted.untagged_rules:,} rules name none and appear nowhere in this layer. "
            f"Exported by Sentinel-X on {generated.astimezone().date().isoformat()}. "
            "A score is how many rules look for a technique — not evidence that it would be caught, and "
            "not a measurement: for what the rules actually found on public attack recordings, see "
            "docs/evaluation."
        ),
        techniques=[
            Scored(
                technique_id=technique.technique_id,
                score=technique.rules,
                comment="; ".join(technique.titles),
                metadata=(
                    ("rules", str(technique.rules)),
                    ("Sentinel-X rules", str(technique.own)),
                    ("community rules", str(technique.community)),
                ),
            )
            for technique in counted.techniques
        ],
        legend="Rules look for this technique",
    )


@dataclass
class _Bucket:
    own: int = 0
    community: int = 0
    titles: list[str] = field(default_factory=list)
