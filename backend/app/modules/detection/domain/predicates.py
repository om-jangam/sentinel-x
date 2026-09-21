"""Predicates over normalised OCSF documents. Sigma and threshold rules compile to these at load time.

Documents are the stored event bodies (plain JSON). A field path is dotted (`process.file.path`); lists fan
out, so `answers.rdata` yields every answer. A field comparison is true when *any* value at *any* of its
paths matches, as in Sigma.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

Document = Mapping[str, Any]


def values_at(document: Document, path: str) -> list[Any]:
    """Every scalar value at `path`. Missing, null and non-scalar values yield nothing."""
    nodes: list[Any] = [document]
    for part in path.split("."):
        found: list[Any] = []
        for node in nodes:
            if not isinstance(node, Mapping):
                continue
            value = node.get(part)
            if value is None:
                continue
            if isinstance(value, list):
                found.extend(item for item in value if item is not None)
            else:
                found.append(value)
        if not found:
            return []
        nodes = found
    return [value for value in nodes if not isinstance(value, Mapping | list)]


class Predicate(Protocol):
    def evaluate(self, document: Document) -> bool: ...


class Matcher(Protocol):
    def matches(self, value: Any) -> bool: ...


# ------------------------------------------------------------------ matchers
class Wildcard(Enum):
    ANY = "*"
    ONE = "?"


GlobPart = str | Wildcard


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


@dataclass(frozen=True, slots=True)
class Glob:
    """Sigma string semantics: whole-value match, `*` and `?` wildcards, case-insensitive unless `cased`."""

    pattern: re.Pattern[str]

    @classmethod
    def of(cls, parts: Sequence[GlobPart], *, case_sensitive: bool = False) -> Glob:
        regex = "".join(
            ".*" if part is Wildcard.ANY else "." if part is Wildcard.ONE else re.escape(part) for part in parts
        )
        flags = re.DOTALL | (0 if case_sensitive else re.IGNORECASE)
        return cls(re.compile(regex, flags))

    @classmethod
    def contains(cls, text: str) -> Glob:
        return cls.of([Wildcard.ANY, text, Wildcard.ANY])

    def matches(self, value: Any) -> bool:
        return self.pattern.fullmatch(_text(value)) is not None


@dataclass(frozen=True, slots=True)
class Regex:
    """Sigma `re`: an unanchored search."""

    pattern: re.Pattern[str]

    def matches(self, value: Any) -> bool:
        return self.pattern.search(_text(value)) is not None


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    try:
        return float(str(value))
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class NumberEquals:
    number: float

    def matches(self, value: Any) -> bool:
        return _number(value) == self.number


class Comparison(Enum):
    LT = "lt"
    LTE = "lte"
    GT = "gt"
    GTE = "gte"
    NEQ = "neq"


@dataclass(frozen=True, slots=True)
class NumberCompare:
    op: Comparison
    number: float

    def matches(self, value: Any) -> bool:
        actual = _number(value)
        if actual is None:
            return False
        return {
            Comparison.LT: actual < self.number,
            Comparison.LTE: actual <= self.number,
            Comparison.GT: actual > self.number,
            Comparison.GTE: actual >= self.number,
            Comparison.NEQ: actual != self.number,
        }[self.op]


@dataclass(frozen=True, slots=True)
class BoolEquals:
    expected: bool

    def matches(self, value: Any) -> bool:
        return isinstance(value, bool) and value is self.expected


@dataclass(frozen=True, slots=True)
class Cidr:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network

    def matches(self, value: Any) -> bool:
        try:
            return ipaddress.ip_address(_text(value)) in self.network
        except ValueError:
            return False


# Not reachable from outside an organisation: RFC 1918, CGNAT, loopback, link-local, unique-local,
# unspecified and multicast. Documentation ranges (RFC 5737) deliberately count as external.
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "224.0.0.0/4",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "::/128",
        "ff00::/8",
    )
)


@dataclass(frozen=True, slots=True)
class ExternalIp:
    def matches(self, value: Any) -> bool:
        try:
            address = ipaddress.ip_address(_text(value))
        except ValueError:
            return False
        return not any(address.version == net.version and address in net for net in _INTERNAL_NETWORKS)


@dataclass(frozen=True, slots=True)
class Equals:
    """Threshold-rule equality: numbers numerically, strings case-insensitively."""

    expected: Any

    def matches(self, value: Any) -> bool:
        if isinstance(self.expected, bool) or isinstance(value, bool):
            return value is self.expected
        if isinstance(self.expected, int | float):
            return _number(value) == float(self.expected)
        return _text(value).casefold() == _text(self.expected).casefold()


# ---------------------------------------------------------------- predicates
@dataclass(frozen=True, slots=True)
class FieldMatch:
    paths: tuple[str, ...]
    matcher: Matcher

    def evaluate(self, document: Document) -> bool:
        return any(self.matcher.matches(value) for path in self.paths for value in values_at(document, path))


@dataclass(frozen=True, slots=True)
class FieldIsNull:
    paths: tuple[str, ...]

    def evaluate(self, document: Document) -> bool:
        return not any(values_at(document, path) for path in self.paths)


@dataclass(frozen=True, slots=True)
class FieldExists:
    paths: tuple[str, ...]
    expected: bool = True

    def evaluate(self, document: Document) -> bool:
        return any(values_at(document, path) for path in self.paths) is self.expected


@dataclass(frozen=True, slots=True)
class AllOf:
    children: tuple[Predicate, ...] = field(default_factory=tuple)

    def evaluate(self, document: Document) -> bool:
        return all(child.evaluate(document) for child in self.children)


@dataclass(frozen=True, slots=True)
class AnyOf:
    children: tuple[Predicate, ...] = field(default_factory=tuple)

    def evaluate(self, document: Document) -> bool:
        return any(child.evaluate(document) for child in self.children)


@dataclass(frozen=True, slots=True)
class Not:
    child: Predicate

    def evaluate(self, document: Document) -> bool:
        return not self.child.evaluate(document)
