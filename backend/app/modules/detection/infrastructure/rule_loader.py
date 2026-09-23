"""Load the shipped rule files: Sigma rules and Sentinel-X threshold rules. Any bad file stops start-up."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from functools import lru_cache
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
from app.modules.detection.infrastructure.sigma_loader import (
    LOGSOURCES,
    RuleLoadError,
    compile_correlation,
    compile_sigma,
)

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
VENDOR_DIR = "sigmahq"  # community rules, unmodified, with their own manifest and licence notice
MANIFEST = "MANIFEST.json"
MAX_WINDOW_MS = 24 * 3600 * 1000
_DURATION = re.compile(r"(\d+)(s|m|h)")
_UNIT_MS = {"s": 1000, "m": 60_000, "h": 3_600_000}


class ThresholdSpec(BaseModel):
    """The threshold rule file format (see docs/modules/detection.md)."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    title: str = Field(min_length=3, max_length=200)
    description: str = ""
    author: str = "Sentinel-X"
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
            author=spec.author,
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


def _rule_files(directory: Path) -> tuple[tuple[Path, str], ...]:
    """Every rule file with the path recorded on findings, own rules first."""
    own = [(file, f"sigma/{file.name}") for file in sorted((directory / "sigma").glob("*.yml"))]
    vendor = [
        (file, f"{VENDOR_DIR}/{file.relative_to(directory / VENDOR_DIR).as_posix()}")
        for file in sorted((directory / VENDOR_DIR).rglob("*.yml"))
    ]
    return tuple(own + vendor)


def _rule_name(text: str) -> str | None:
    """Sigma's `name:`, which a correlation rule refers to."""
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    name = parsed.get("name") if isinstance(parsed, dict) else None
    return name if isinstance(name, str) and name else None


def _source_urls(directory: Path) -> dict[str, str]:
    """`MANIFEST.json` in the vendor directory says where each community rule came from."""
    manifest = directory / VENDOR_DIR / MANIFEST
    if not manifest.is_file():
        return {}
    data = json.loads(manifest.read_text(encoding="utf-8"))
    base = str(data.get("rule_base_url", "")).rstrip("/")
    return {f"{VENDOR_DIR}/{name}": f"{base}/{upstream}" for name, upstream in data.get("files", {}).items()}


def load_rules(directory: Path = RULES_DIR) -> RuleSet:
    """Compile every shipped rule. Cached per directory contents: a rule set is loaded once per process."""
    files = _rule_files(directory)
    fingerprint = tuple((path, path.stat().st_mtime_ns, path.stat().st_size) for path, _ in files)
    return _compile_rules(directory, fingerprint)


def _documents(text: str, path: str) -> list[str]:
    """A rule file may hold several YAML documents: Sigma keeps a correlation beside its base rule."""
    try:
        parsed = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"{path}: not valid YAML: {exc}") from exc
    if len(parsed) <= 1:
        return [text]
    return [yaml.safe_dump(document, sort_keys=False) for document in parsed if isinstance(document, dict)]


def _is_correlation(text: str) -> bool:
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError:
        return False
    return isinstance(parsed, dict) and "correlation" in parsed


def _referenced(text: str) -> list[str]:
    """The base rules a correlation names, so they are not also evaluated as detections of their own."""
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    correlation = parsed.get("correlation") if isinstance(parsed, dict) else None
    rules = correlation.get("rules") if isinstance(correlation, dict) else None
    if isinstance(rules, str):
        return [rules]
    return [rule for rule in rules or [] if isinstance(rule, str)]


@lru_cache(maxsize=4)
def _compile_rules(directory: Path, _fingerprint: tuple[tuple[Path, int, int], ...]) -> RuleSet:
    problems = check_field_mappings()
    single_event: list[SingleEventRule] = []
    threshold: list[ThresholdRule] = []
    sources = _source_urls(directory)
    named: dict[str, SingleEventRule] = {}
    documents: list[tuple[str, str, str]] = []  # (text, where, file path)
    for file, path in _rule_files(directory):
        try:
            texts = _documents(file.read_text(encoding="utf-8"), path)
        except RuleLoadError as exc:
            problems.append(str(exc))
            continue
        documents += [
            (text, path if len(texts) == 1 else f"{path}#{index + 1}", path) for index, text in enumerate(texts)
        ]

    correlations = [(text, where) for text, where, _ in documents if _is_correlation(text)]
    # A rule a correlation counts is support, not a detection: on its own it would flag every event it
    # matches ("an outbound connection happened"), which is noise, not a finding.
    referenced = {name for text, _ in correlations for name in _referenced(text)}
    for text, where, path in documents:
        if _is_correlation(text):
            continue
        try:
            rule = compile_sigma(text, path=where)
        except RuleLoadError as exc:
            problems.append(str(exc))
            continue
        if (source := sources.get(path)) is not None:
            rule = replace(rule, meta=replace(rule.meta, source_url=source))
        name = _rule_name(text)
        if name is not None:
            named[name] = rule
        if name not in referenced:
            single_event.append(rule)
    for text, where in correlations:
        try:
            threshold.append(compile_correlation(text, path=where, base_rules=named))
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
