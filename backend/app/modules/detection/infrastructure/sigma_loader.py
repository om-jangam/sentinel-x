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
from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
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
from app.modules.detection.domain.rules import (
    LEVEL_SEVERITY,
    RuleMeta,
    SingleEventRule,
    ThresholdRule,
    attack_from_tags,
)


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


SYSMON_LOG_NAME = "Microsoft-Windows-Sysmon/Operational"

# Sysmon's own field names, used by most SigmaHQ Windows rules. Where OCSF has no attribute, the Sysmon
# parser keeps the value as written under `unmapped` (see parsers/windows_sysmon.py).
_ACTOR_IMAGE_FIELDS: Mapping[str, tuple[str, ...]] = {
    "Image": ("actor.process.file.path",),
    "ProcessId": ("actor.process.pid",),
    "ProcessGuid": ("actor.process.uid",),
    "User": ("unmapped.user",),
    "Computer": ("device.hostname",),
}

PROCESS_CREATION_FIELDS: Mapping[str, tuple[str, ...]] = {
    "Image": ("process.file.path",),
    "CommandLine": ("process.cmd_line",),
    "ParentImage": ("process.parent_process.file.path",),
    "ParentCommandLine": ("process.parent_process.cmd_line",),
    "ProcessId": ("process.pid",),
    "ParentProcessId": ("process.parent_process.pid",),
    "ProcessGuid": ("process.uid",),
    "ParentProcessGuid": ("process.parent_process.uid",),
    # Security 4688 has the user name only; Sysmon writes DOMAIN\name, kept as written in unmapped.user.
    "User": ("actor.user.name", "process.user.name", "unmapped.user"),
    "ParentUser": ("process.parent_process.user.name",),
    "IntegrityLevel": ("process.integrity",),
    "CurrentDirectory": ("process.working_directory",),
    "OriginalFileName": ("unmapped.original_file_name",),
    "Hashes": ("unmapped.hashes",),
    "Company": ("process.file.company_name",),
    "Description": ("process.file.desc",),
    "Product": ("process.file.product.name",),
    "FileVersion": ("process.file.version",),
    "LogonId": ("unmapped.logon_id",),
    "Computer": ("device.hostname",),
}

PROCESS_TERMINATION_FIELDS: Mapping[str, tuple[str, ...]] = {
    "Image": ("process.file.path",),
    "ProcessId": ("process.pid",),
    "ProcessGuid": ("process.uid",),
    "User": ("unmapped.user",),
    "Computer": ("device.hostname",),
}

CROSS_PROCESS_FIELDS: Mapping[str, tuple[str, ...]] = {
    "SourceImage": ("actor.process.file.path",),
    "SourceProcessId": ("actor.process.pid",),
    "SourceProcessGuid": ("actor.process.uid",),
    "SourceProcessGUID": ("actor.process.uid",),  # Sysmon 10 capitalises GUID; Sysmon 8 does not
    "SourceUser": ("actor.user.name",),
    "TargetImage": ("process.file.path",),
    "TargetProcessId": ("process.pid",),
    "TargetProcessGuid": ("process.uid",),
    "TargetProcessGUID": ("process.uid",),
    "TargetUser": ("process.user.name",),
    "Computer": ("device.hostname",),
}

PROCESS_ACCESS_FIELDS: Mapping[str, tuple[str, ...]] = {
    **CROSS_PROCESS_FIELDS,
    "GrantedAccess": ("unmapped.granted_access",),
    "CallTrace": ("unmapped.call_trace",),
}

CREATE_REMOTE_THREAD_FIELDS: Mapping[str, tuple[str, ...]] = {
    **CROSS_PROCESS_FIELDS,
    "StartAddress": ("module.start_address",),
    "StartModule": ("unmapped.start_module",),
    "StartFunction": ("module.function_name",),
}

IMAGE_LOAD_FIELDS: Mapping[str, tuple[str, ...]] = {
    **_ACTOR_IMAGE_FIELDS,
    "ImageLoaded": ("module.file.path",),
    "OriginalFileName": ("unmapped.original_file_name",),
    "Hashes": ("unmapped.hashes",),
    "Company": ("module.file.company_name",),
    "Description": ("module.file.desc",),
    "Product": ("module.file.product.name",),
    "FileVersion": ("module.file.version",),
    "Signed": ("unmapped.signed",),
    "Signature": ("unmapped.signature",),
    "SignatureStatus": ("unmapped.signature_status",),
}

FILE_EVENT_FIELDS: Mapping[str, tuple[str, ...]] = {
    **_ACTOR_IMAGE_FIELDS,
    "TargetFilename": ("file.path",),
    "Hashes": ("unmapped.hashes",),
}

REGISTRY_FIELDS: Mapping[str, tuple[str, ...]] = {
    **_ACTOR_IMAGE_FIELDS,
    "TargetObject": ("reg_key.path", "reg_value.path", "prev_reg_key.path"),
    "Details": ("reg_value.data",),
    "EventType": ("unmapped.event_type",),
    "NewName": ("reg_key.path",),
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
    **_ACTOR_IMAGE_FIELDS,
    "Initiated": ("unmapped.initiated",),
    "SourceIp": ("src_endpoint.ip",),
    "SourcePort": ("src_endpoint.port",),
    "SourceHostname": ("src_endpoint.hostname",),
    "DestinationIp": ("dst_endpoint.ip",),
    "DestinationPort": ("dst_endpoint.port",),
    "DestinationHostname": ("dst_endpoint.hostname",),
    "Protocol": ("connection_info.protocol_name",),
}

DNS_FIELDS: Mapping[str, tuple[str, ...]] = {
    **_ACTOR_IMAGE_FIELDS,
    "QueryStatus": ("unmapped.query_status",),
    "QueryName": ("query.hostname",),
    "QueryType": ("query.type",),
    "QueryResults": ("answers.rdata",),
    "SourceIp": ("src_endpoint.ip",),
}

# `product: windows, service: sysmon` rules select by EventID and may use any Sysmon field.
SYSMON_FIELDS: Mapping[str, tuple[str, ...]] = {
    **IMAGE_LOAD_FIELDS,
    **FILE_EVENT_FIELDS,
    **REGISTRY_FIELDS,
    **{name: paths for name, paths in NETWORK_CONNECTION_FIELDS.items() if name not in _ACTOR_IMAGE_FIELDS},
    **{name: paths for name, paths in DNS_FIELDS.items() if name not in _ACTOR_IMAGE_FIELDS},
    **PROCESS_ACCESS_FIELDS,
    **CREATE_REMOTE_THREAD_FIELDS,
    # Event 1 calls its own new process `Image`; every other Sysmon event calls the acting process `Image`.
    "Image": ("process.file.path", "actor.process.file.path"),
    "CommandLine": ("process.cmd_line",),
    "ParentImage": ("process.parent_process.file.path",),
    "ParentCommandLine": ("process.parent_process.cmd_line",),
    "IntegrityLevel": ("process.integrity",),
    "CurrentDirectory": ("process.working_directory",),
    "EventID": ("unmapped.event_id",),
}


def _sysmon(scope: Predicate) -> Predicate:
    return AllOf((_eq("metadata.log_name", SYSMON_LOG_NAME), scope))


def _event_type(*names: str) -> Predicate:
    return _sysmon(AnyOf(tuple(_eq("unmapped.event_type", name) for name in names)))


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
    LogsourceMapping(
        name="process_termination",
        category="process_termination",
        scope=AllOf((_eq("class_uid", 1007), _eq("activity_id", 2))),
        fields=PROCESS_TERMINATION_FIELDS,
        keyword_paths=(),
    ),
    LogsourceMapping(
        name="process_access",
        category="process_access",
        scope=AllOf((_eq("class_uid", 1007), _eq("activity_id", 3))),
        fields=PROCESS_ACCESS_FIELDS,
        keyword_paths=(),
    ),
    LogsourceMapping(
        name="create_remote_thread",
        category="create_remote_thread",
        scope=AllOf((_eq("class_uid", 1007), _eq("activity_id", 4))),
        fields=CREATE_REMOTE_THREAD_FIELDS,
        keyword_paths=(),
    ),
    LogsourceMapping(
        name="image_load",
        category="image_load",
        scope=AllOf((_eq("class_uid", 1005), _eq("activity_id", 1))),
        fields=IMAGE_LOAD_FIELDS,
        keyword_paths=(),
    ),
    LogsourceMapping(
        name="file_event",
        category="file_event",
        scope=AllOf((_eq("class_uid", 1001), _eq("activity_id", 1))),
        fields=FILE_EVENT_FIELDS,
        keyword_paths=(),
    ),
    LogsourceMapping(
        name="file_delete",
        category="file_delete",
        scope=AllOf((_eq("class_uid", 1001), _eq("activity_id", 4))),
        fields=FILE_EVENT_FIELDS,
        keyword_paths=(),
    ),
    # Sigma's registry categories follow Sysmon's event types: add is a key created, delete a key or value
    # deleted, set a value set, rename a key or value renamed, and event any of them.
    LogsourceMapping(
        name="registry_add",
        category="registry_add",
        scope=_event_type("CreateKey"),
        fields=REGISTRY_FIELDS,
        keyword_paths=(),
    ),
    LogsourceMapping(
        name="registry_delete",
        category="registry_delete",
        scope=_event_type("DeleteKey", "DeleteValue"),
        fields=REGISTRY_FIELDS,
        keyword_paths=(),
    ),
    LogsourceMapping(
        name="registry_set",
        category="registry_set",
        scope=_event_type("SetValue"),
        fields=REGISTRY_FIELDS,
        keyword_paths=(),
    ),
    LogsourceMapping(
        name="registry_rename",
        category="registry_rename",
        scope=_event_type("RenameKey", "RenameValue"),
        fields=REGISTRY_FIELDS,
        keyword_paths=(),
    ),
    LogsourceMapping(
        name="registry_event",
        category="registry_event",
        scope=AnyOf((_eq("class_uid", 201001), _eq("class_uid", 201002))),
        fields=REGISTRY_FIELDS,
        keyword_paths=(),
    ),
    LogsourceMapping(
        name="windows/sysmon",
        product="windows",
        service="sysmon",
        scope=_eq("metadata.log_name", SYSMON_LOG_NAME),
        fields=SYSMON_FIELDS,
    ),
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


SUPPORTED_CORRELATIONS = ("event_count", "value_count")
MAX_CORRELATION_WINDOW_MS = 24 * 3600 * 1000


def compile_correlation(text: str, *, path: str, base_rules: Mapping[str, SingleEventRule]) -> ThresholdRule:
    """A Sigma correlation rule (`event_count` / `value_count`) over one named base rule.

    Sigma expresses "enough of these events in a window" the way Sentinel-X's own threshold rules do, so a
    correlation rule compiles to the same `ThresholdRule` the engine already evaluates. What the standard
    ties to a logsource, it cannot say across sources; `temporal` correlations need several rules at once
    and are refused with that reason.
    """
    try:
        rule = SigmaCorrelationRule.from_yaml(text)
    except (SigmaError, yaml.YAMLError) as exc:
        raise RuleLoadError(f"{path}: not a valid Sigma correlation rule: {exc}") from exc

    if rule.id is None:
        raise RuleLoadError(f"{path}: Sigma correlation rules must have an id")
    if rule.level is None:
        raise RuleLoadError(f"{path}: Sigma correlation rules must have a level")
    kind = str(rule.type.name).lower()
    if kind not in SUPPORTED_CORRELATIONS:
        raise RuleLoadError(
            f"{path}: unsupported correlation type '{kind}' (supported: {', '.join(SUPPORTED_CORRELATIONS)})"
        )
    references = [reference.reference for reference in rule.rules or []]
    if len(references) != 1:
        raise RuleLoadError(f"{path}: one correlation rule over one base rule; this names {len(references)}")
    base = base_rules.get(references[0])
    if base is None:
        raise RuleLoadError(f"{path}: no rule named '{references[0]}' (a base rule needs a `name:`)")

    window_ms = int(rule.timespan.seconds * 1000)
    if window_ms <= 0 or window_ms > MAX_CORRELATION_WINDOW_MS:
        raise RuleLoadError(f"{path}: timespan must be more than zero and at most 24h")
    condition = rule.condition
    if not isinstance(condition, SigmaCorrelationCondition):
        raise RuleLoadError(f"{path}: extended correlation conditions are not supported")
    if condition.op is not SigmaCorrelationConditionOperator.GTE:
        raise RuleLoadError(f"{path}: only 'gte' conditions are supported, not '{condition.op.name.lower()}'")
    if not isinstance(condition.count, int) or condition.count < 2:
        raise RuleLoadError(f"{path}: the condition count must be 2 or more")

    mapping = next((candidate for candidate in LOGSOURCES if candidate.name == base.logsource), None)
    if mapping is None:  # pragma: no cover - a compiled base rule always has a mapped logsource
        raise RuleLoadError(f"{path}: the base rule's logsource is not mapped")

    def path_of(field: str, what: str) -> str:
        paths = mapping.fields.get(field)
        if not paths:
            raise RuleLoadError(f"{path}: {what} field '{field}' is not mapped for logsource {mapping.name}")
        return paths[0]

    if not rule.group_by:
        raise RuleLoadError(f"{path}: a correlation rule must group by at least one field")
    group_by = tuple(path_of(field, "group-by") for field in rule.group_by)
    distinct = None
    if kind == "value_count":
        if not isinstance(condition.fieldref, str) or not condition.fieldref:
            raise RuleLoadError(f"{path}: a value_count condition must name one field to count")
        distinct = path_of(condition.fieldref, "counted")

    level = rule.level.name.lower()
    return ThresholdRule(
        meta=RuleMeta(
            id=str(rule.id),
            title=rule.title or base.meta.title,
            description=rule.description or base.meta.description,
            level=level,
            severity_id=LEVEL_SEVERITY[level],
            attack=attack_from_tags(str(tag) for tag in rule.tags),
            version=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            path=path,
            references=tuple(rule.references or ()),
            false_positives=tuple(rule.falsepositives or ()),
            author=str(rule.author or ""),
        ),
        match=base.predicate,
        group_by=group_by,
        threshold=condition.count,
        window_ms=window_ms,
        count_distinct=distinct,
    )


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
            author=str(rule.author or "")[:255],
        ),
        logsource=mapping.name,
        predicate=AllOf((mapping.scope, matched)),
    )
