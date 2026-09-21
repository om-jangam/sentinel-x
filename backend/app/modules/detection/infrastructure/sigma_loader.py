"""Translate Sigma rules (parsed by pySigma) into predicates over normalised OCSF documents (ADR-0015).

Coverage is explicit: a rule loads only if its logsource is mapped below and every field, modifier and
value type it uses is supported. Anything else is refused with a reason.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import yaml
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError
from sigma.rule import SigmaLogSource, SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

from app.modules.detection.domain.predicates import (
    AllOf,
    AnyOf,
    BoolEquals,
    Cidr,
    Comparison,
    Equals,
    FieldExists,
    FieldIsNull,
    FieldMatch,
    Glob,
    GlobPart,
    Matcher,
    Not,
    NumberCompare,
    NumberEquals,
    Predicate,
    Regex,
    Wildcard,
)
from app.modules.detection.domain.rules import LEVEL_SEVERITY, RuleMeta, SingleEventRule, attack_from_tags


class RuleLoadError(ValueError):
    """A rule file that can't be loaded as written."""


@dataclass(frozen=True, slots=True)
class LogsourceMapping:
    """Which normalised events a Sigma logsource means, and where its fields live in OCSF."""

    name: str
    scope: Predicate
    fields: Mapping[str, tuple[str, ...]]
    category: str | None = None
    product: str | None = None
    service: str | None = None
    keyword_paths: tuple[str, ...] = field(default=("message", "raw_data"))

    def applies_to(self, logsource: SigmaLogSource) -> bool:
        wanted = {"category": self.category, "product": self.product, "service": self.service}
        return all(
            expected is None or (getattr(logsource, key) or "").lower() == expected for key, expected in wanted.items()
        )


def _eq(path: str, value: Any) -> Predicate:
    return FieldMatch((path,), Equals(value))


PROCESS_CREATION_FIELDS: Mapping[str, tuple[str, ...]] = {
    "Image": ("process.file.path",),
    "CommandLine": ("process.cmd_line",),
    "ParentImage": ("process.parent_process.file.path",),
    "ParentCommandLine": ("process.parent_process.cmd_line",),
    "ProcessId": ("process.pid",),
    "ParentProcessId": ("process.parent_process.pid",),
    "User": ("actor.user.name", "process.user.name"),
    "Computer": ("device.hostname",),
}

WINDOWS_SECURITY_FIELDS: Mapping[str, tuple[str, ...]] = {
    "EventID": ("unmapped.event_id",),
    "TargetUserName": ("user.name",),
    "TargetDomainName": ("user.domain",),
    "TargetUserSid": ("user.uid",),
    "SubjectUserName": ("actor.user.name",),
    "SubjectDomainName": ("actor.user.domain",),
    "IpAddress": ("src_endpoint.ip",),
    "IpPort": ("src_endpoint.port",),
    "WorkstationName": ("src_endpoint.hostname",),
    "LogonType": ("logon_type_id",),
    "AuthenticationPackageName": ("auth_protocol",),
    "NewProcessName": ("process.file.path",),
    "CommandLine": ("process.cmd_line",),
    "ParentProcessName": ("process.parent_process.file.path",),
    "Status": ("unmapped.status",),
    "SubStatus": ("unmapped.sub_status",),
    "FailureReason": ("unmapped.failure_reason",),
    "Computer": ("device.hostname",),
}

NETWORK_CONNECTION_FIELDS: Mapping[str, tuple[str, ...]] = {
    "SourceIp": ("src_endpoint.ip",),
    "SourcePort": ("src_endpoint.port",),
    "SourceHostname": ("src_endpoint.hostname",),
    "DestinationIp": ("dst_endpoint.ip",),
    "DestinationPort": ("dst_endpoint.port",),
    "DestinationHostname": ("dst_endpoint.hostname",),
    "Protocol": ("connection_info.protocol_name",),
}

DNS_FIELDS: Mapping[str, tuple[str, ...]] = {
    "QueryName": ("query.hostname",),
    "QueryType": ("query.type",),
    "QueryResults": ("answers.rdata",),
    "SourceIp": ("src_endpoint.ip",),
}

LOGSOURCES: tuple[LogsourceMapping, ...] = (
    LogsourceMapping(
        name="process_creation",
        category="process_creation",
        scope=AllOf((_eq("class_uid", 1007), _eq("activity_id", 1))),
        fields=PROCESS_CREATION_FIELDS,
        keyword_paths=("process.cmd_line", "raw_data"),
    ),
    LogsourceMapping(
        name="windows/security",
        product="windows",
        service="security",
        scope=AllOf((_eq("metadata.product.name", "Microsoft Windows"), _eq("metadata.log_name", "Security"))),
        fields=WINDOWS_SECURITY_FIELDS,
    ),
    LogsourceMapping(
        name="linux/auth",
        product="linux",
        service="auth",
        scope=_eq("metadata.log_name", "auth.log"),
        fields={},
    ),
    LogsourceMapping(
        name="linux/sshd",
        product="linux",
        service="sshd",
        scope=_eq("metadata.log_name", "auth.log"),
        fields={},
    ),
    LogsourceMapping(
        name="network_connection",
        category="network_connection",
        scope=_eq("class_uid", 4001),
        fields=NETWORK_CONNECTION_FIELDS,
        keyword_paths=(),
    ),
    LogsourceMapping(name="dns_query", category="dns_query", scope=_eq("class_uid", 4003), fields=DNS_FIELDS),
    LogsourceMapping(name="dns", category="dns", scope=_eq("class_uid", 4003), fields=DNS_FIELDS),
)

_COMPARISONS = {"LT": Comparison.LT, "LTE": Comparison.LTE, "GT": Comparison.GT, "GTE": Comparison.GTE}
_REGEX_FLAGS = {
    SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE,
    SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
    SigmaRegularExpressionFlag.DOTALL: re.DOTALL,
}


def _glob_parts(value: SigmaString) -> list[GlobPart]:
    parts: list[GlobPart] = []
    for part in value.s:
        if part is SpecialChars.WILDCARD_MULTI:
            parts.append(Wildcard.ANY)
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(Wildcard.ONE)
        elif isinstance(part, str):
            parts.append(part)
        else:
            raise RuleLoadError(f"unsupported value part {part!r} (placeholders are not supported)")
    return parts


def _matcher(value: Any) -> Matcher:
    if isinstance(value, SigmaCasedString):
        return Glob.of(_glob_parts(value), case_sensitive=True)
    if isinstance(value, SigmaString):
        return Glob.of(_glob_parts(value))
    if isinstance(value, SigmaBool):
        return BoolEquals(value.boolean)
    if isinstance(value, SigmaNumber):
        return NumberEquals(float(value.number))
    if isinstance(value, SigmaRegularExpression):
        flags = 0
        for flag in value.flags:
            flags |= _REGEX_FLAGS[flag]
        try:
            return Regex(re.compile(value.regexp.to_plain(), flags))
        except re.error as exc:
            raise RuleLoadError(f"invalid regular expression: {exc}") from exc
    if isinstance(value, SigmaCIDRExpression):
        return Cidr(value.network)
    if isinstance(value, SigmaCompareExpression):
        if value.op.name == "NEQ":
            return NumberCompare(Comparison.NEQ, float(value.number.number))
        return NumberCompare(_COMPARISONS[value.op.name], float(value.number.number))
    raise RuleLoadError(f"unsupported value type {type(value).__name__}")


class _Translator:
    def __init__(self, mapping: LogsourceMapping) -> None:
        self.mapping = mapping

    def translate(self, node: Any) -> Predicate:
        if isinstance(node, ConditionAND):
            return AllOf(tuple(self.translate(arg) for arg in node.args))
        if isinstance(node, ConditionOR):
            return AnyOf(tuple(self.translate(arg) for arg in node.args))
        if isinstance(node, ConditionNOT):
            return Not(self.translate(node.args[0]))
        if isinstance(node, ConditionFieldEqualsValueExpression):
            paths = self.mapping.fields.get(node.field)
            if paths is None:
                raise RuleLoadError(
                    f"field '{node.field}' is not mapped for logsource {self.mapping.name} "
                    f"(mapped: {', '.join(sorted(self.mapping.fields)) or 'none'})"
                )
            return self._field(paths, node.value)
        if isinstance(node, ConditionValueExpression):
            if not self.mapping.keyword_paths:
                raise RuleLoadError(f"keyword searches are not supported for logsource {self.mapping.name}")
            return self._keyword(node.value)
        raise RuleLoadError(f"unsupported condition element {type(node).__name__}")

    def _field(self, paths: tuple[str, ...], value: Any) -> Predicate:
        if isinstance(value, SigmaNull):
            return FieldIsNull(paths)
        if isinstance(value, SigmaExists):
            return FieldExists(paths, value.exists)
        if isinstance(value, SigmaExpansion):
            return AnyOf(tuple(self._field(paths, item) for item in value.values))
        return FieldMatch(paths, _matcher(value))

    def _keyword(self, value: Any) -> Predicate:
        """Keywords are full-text: a plain keyword matches anywhere in the searched fields."""
        paths = self.mapping.keyword_paths
        if isinstance(value, SigmaExpansion):
            return AnyOf(tuple(self._keyword(item) for item in value.values))
        if isinstance(value, SigmaString) and not value.contains_special():
            return FieldMatch(paths, Glob.of([Wildcard.ANY, *_glob_parts(value), Wildcard.ANY]))
        if isinstance(value, SigmaNumber):
            return FieldMatch(paths, Glob.contains(str(value.number)))
        return FieldMatch(paths, _matcher(value))


def compile_sigma(text: str, *, path: str) -> SingleEventRule:
    try:
        rule = SigmaRule.from_yaml(text)
    except (SigmaError, yaml.YAMLError) as exc:
        raise RuleLoadError(f"{path}: not a valid Sigma rule: {exc}") from exc

    if rule.id is None:
        raise RuleLoadError(f"{path}: Sigma rules must have an id")
    if rule.level is None:
        raise RuleLoadError(f"{path}: Sigma rules must have a level")
    mapping = next((candidate for candidate in LOGSOURCES if candidate.applies_to(rule.logsource)), None)
    if mapping is None:
        logsource = rule.logsource
        raise RuleLoadError(
            f"{path}: unsupported logsource category={logsource.category} product={logsource.product} "
            f"service={logsource.service}"
        )

    translator = _Translator(mapping)
    try:
        conditions = [translator.translate(condition.parse()) for condition in rule.detection.parsed_condition]
    except RuleLoadError as exc:
        raise RuleLoadError(f"{path}: {exc}") from exc
    except SigmaError as exc:
        raise RuleLoadError(f"{path}: invalid condition: {exc}") from exc

    level = rule.level.name.lower()
    matched = conditions[0] if len(conditions) == 1 else AnyOf(tuple(conditions))
    return SingleEventRule(
        meta=RuleMeta(
            id=str(rule.id),
            title=rule.title,
            description=rule.description or "",
            level=level,
            severity_id=LEVEL_SEVERITY[level],
            attack=attack_from_tags(str(tag) for tag in rule.tags),
            version=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            path=path,
            references=tuple(rule.references or ()),
            false_positives=tuple(rule.falsepositives or ()),
        ),
        logsource=mapping.name,
        predicate=AllOf((mapping.scope, matched)),
    )
