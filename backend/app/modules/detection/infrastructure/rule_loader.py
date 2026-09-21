"""Load the shipped rule files: Sigma rules and Sentinel-X threshold rules. Any bad file stops start-up."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.modules.detection.domain.predicates import AllOf, AnyOf, Equals, ExternalIp, FieldMatch, Predicate
from app.modules.detection.domain.rules import (
    LEVEL_SEVERITY,
    RuleMeta,
    RuleSet,
    SingleEventRule,
    ThresholdRule,
    attack_from_tags,
)
from app.modules.detection.infrastructure.ocsf_paths import is_known_path
from app.modules.detection.infrastructure.sigma_loader import LOGSOURCES, RuleLoadError, compile_sigma

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
MAX_WINDOW_MS = 24 * 3600 * 1000
_DURATION = re.compile(r"(\d+)(s|m|h)")
_UNIT_MS = {"s": 1000, "m": 60_000, "h": 3_600_000}


class ThresholdSpec(BaseModel):
    """The threshold rule file format (see docs/modules/detection.md)."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    title: str = Field(min_length=3, max_length=200)
    description: str = ""
    level: Literal["informational", "low", "medium", "high", "critical"]
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    match: dict[str, Any] = Field(min_length=1)
    group_by: list[str] = Field(min_length=1, max_length=5)
    count_distinct: str | None = None
    threshold: int = Field(ge=2, le=10_000)
    window: str

    @field_validator("window")
    @classmethod
    def _window(cls, value: str) -> str:
        if _duration_ms(value) > MAX_WINDOW_MS:
            raise ValueError("window may not exceed 24h")
        return value

    @property
    def window_ms(self) -> int:
        return _duration_ms(self.window)


def _duration_ms(value: str) -> int:
    match = _DURATION.fullmatch(value)
    if match is None:
        raise ValueError("window must look like 90s, 10m or 1h")
    return int(match.group(1)) * _UNIT_MS[match.group(2)]


def _match_predicate(match: dict[str, Any], path: str) -> Predicate:
    """`field: value` (equality), `field: [a, b]` (any of), `field|external: true` (a public IP)."""
    clauses: list[Predicate] = []
    for key, expected in match.items():
        field_path, _, operator = key.partition("|")
        if not is_known_path(field_path):
            raise RuleLoadError(f"{path}: unknown field '{field_path}' in match")
        if operator == "external":
            if expected is not True:
                raise RuleLoadError(f"{path}: '{key}' only accepts true")
            clauses.append(FieldMatch((field_path,), ExternalIp()))
        elif operator:
            raise RuleLoadError(f"{path}: unsupported match operator '|{operator}'")
        elif isinstance(expected, list):
            if not expected:
                raise RuleLoadError(f"{path}: empty list for '{key}'")
            clauses.append(AnyOf(tuple(FieldMatch((field_path,), Equals(item)) for item in expected)))
        elif isinstance(expected, str | int | float | bool):
            clauses.append(FieldMatch((field_path,), Equals(expected)))
        else:
            raise RuleLoadError(f"{path}: '{key}' must be a scalar or a list of scalars")
    return AllOf(tuple(clauses))


def compile_threshold(text: str, *, path: str) -> ThresholdRule:
    try:
        spec = ThresholdSpec.model_validate(yaml.safe_load(text))
    except (yaml.YAMLError, ValidationError) as exc:
        raise RuleLoadError(f"{path}: invalid threshold rule: {exc}") from exc

    for field_path in [*spec.group_by, *([spec.count_distinct] if spec.count_distinct else [])]:
        if not is_known_path(field_path):
            raise RuleLoadError(f"{path}: unknown field '{field_path}'")
    return ThresholdRule(
        meta=RuleMeta(
            id=str(spec.id),
            title=spec.title,
            description=spec.description,
            level=spec.level,
            severity_id=LEVEL_SEVERITY[spec.level],
            attack=attack_from_tags(spec.tags),
            version=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            path=path,
            references=tuple(spec.references),
            false_positives=tuple(spec.falsepositives),
        ),
        match=_match_predicate(spec.match, path),
        group_by=tuple(spec.group_by),
        count_distinct=spec.count_distinct,
        threshold=spec.threshold,
        window_ms=spec.window_ms,
    )


def check_field_mappings() -> list[str]:
    """Every OCSF path the Sigma mappings point at must exist in stored documents."""
    return [
        f"logsource {mapping.name}: {sigma_field} → unknown path {ocsf_path}"
        for mapping in LOGSOURCES
        for sigma_field, paths in mapping.fields.items()
        for ocsf_path in (*paths,)
        if not is_known_path(ocsf_path)
    ] + [
        f"logsource {mapping.name}: unknown keyword path {ocsf_path}"
        for mapping in LOGSOURCES
        for ocsf_path in mapping.keyword_paths
        if not is_known_path(ocsf_path)
    ]


def load_rules(directory: Path = RULES_DIR) -> RuleSet:
    problems = check_field_mappings()
    single_event: list[SingleEventRule] = []
    threshold: list[ThresholdRule] = []
    for file in sorted((directory / "sigma").glob("*.yml")):
        try:
            single_event.append(compile_sigma(file.read_text(encoding="utf-8"), path=f"sigma/{file.name}"))
        except RuleLoadError as exc:
            problems.append(str(exc))
    for file in sorted((directory / "threshold").glob("*.yml")):
        try:
            threshold.append(compile_threshold(file.read_text(encoding="utf-8"), path=f"threshold/{file.name}"))
        except RuleLoadError as exc:
            problems.append(str(exc))
    if problems:
        raise RuleLoadError("detection rules failed to load:\n  " + "\n  ".join(problems))
    try:
        return RuleSet(single_event=tuple(single_event), threshold=tuple(threshold))
    except ValueError as exc:
        raise RuleLoadError(str(exc)) from exc
