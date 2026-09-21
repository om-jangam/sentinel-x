from __future__ import annotations

import ipaddress
import re
from typing import Any

import pytest

from app.modules.detection.domain.predicates import (
    AllOf,
    AnyOf,
    BoolEquals,
    Cidr,
    Comparison,
    Equals,
    ExternalIp,
    FieldExists,
    FieldIsNull,
    FieldMatch,
    Glob,
    Not,
    NumberCompare,
    NumberEquals,
    Regex,
    Wildcard,
    values_at,
)

DOC: dict[str, Any] = {
    "class_uid": 1007,
    "process": {"file": {"path": r"C:\Windows\System32\cmd.exe"}, "pid": 4242, "cmd_line": "cmd /c whoami"},
    "answers": [{"rdata": "192.0.2.66"}, {"rdata": "192.0.2.67"}, {"type": "A"}],
    "src_endpoint": {"ip": "10.0.5.17"},
    "is_mfa": False,
    "unmapped": {"event_id": 4688},
}


def test_values_at_walks_nested_objects_and_fans_out_lists() -> None:
    assert values_at(DOC, "process.file.path") == [r"C:\Windows\System32\cmd.exe"]
    assert values_at(DOC, "answers.rdata") == ["192.0.2.66", "192.0.2.67"]
    assert values_at(DOC, "process.file") == [], "objects are not values"
    assert values_at(DOC, "process.parent_process.pid") == []
    assert values_at(DOC, "nope") == []


@pytest.mark.parametrize(
    ("parts", "case_sensitive", "value", "expected"),
    [
        ([Wildcard.ANY, "\\cmd.exe"], False, r"C:\Windows\System32\CMD.EXE", True),
        ([Wildcard.ANY, "\\cmd.exe"], True, r"C:\Windows\System32\CMD.EXE", False),
        (["cmd /c", Wildcard.ANY], False, "cmd /c whoami", True),
        (["cmd", Wildcard.ONE, "/c whoami"], False, "cmd /c whoami", True),
        (["cmd"], False, "cmd /c whoami", False),  # no wildcard means the whole value
        (["a.b"], False, "axb", False),  # literal dots are escaped
        (["4688"], False, 4688, True),  # numbers compare as text
    ],
)
def test_glob_follows_sigma_string_semantics(
    parts: list[str | Wildcard], case_sensitive: bool, value: object, expected: bool
) -> None:
    assert Glob.of(parts, case_sensitive=case_sensitive).matches(value) is expected


def test_regex_searches_rather_than_anchoring() -> None:
    assert Regex(re.compile(r"who.mi")).matches("cmd /c whoami")
    assert not Regex(re.compile(r"^whoami")).matches("cmd /c whoami")


@pytest.mark.parametrize(
    ("matcher", "value", "expected"),
    [
        (NumberEquals(4688), 4688, True),
        (NumberEquals(4688), "4688", True),
        (NumberEquals(4688), True, False),
        (NumberCompare(Comparison.GT, 100), 4242, True),
        (NumberCompare(Comparison.LTE, 100), "not a number", False),
        (NumberCompare(Comparison.NEQ, 1), 2, True),
        (BoolEquals(False), False, True),
        (BoolEquals(False), 0, False),
        (Cidr(ipaddress.ip_network("10.0.0.0/8")), "10.0.5.17", True),
        (Cidr(ipaddress.ip_network("10.0.0.0/8")), "garbage", False),
        (Equals(3002), "3002", True),
        (Equals("OpenSSH"), "openssh", True),
        (Equals(True), 1, False),
    ],
)
def test_scalar_matchers(matcher: Any, value: object, expected: bool) -> None:
    assert matcher.matches(value) is expected


@pytest.mark.parametrize(
    ("address", "external"),
    [
        ("192.0.2.66", True),  # documentation range: not an internal network
        ("8.8.8.8", True),
        ("10.0.2.10", False),
        ("172.20.1.1", False),
        ("192.168.1.1", False),
        ("100.64.0.1", False),
        ("127.0.0.1", False),
        ("fe80::1", False),
        ("2001:db8::1", True),
        ("not-an-ip", False),
    ],
)
def test_external_ip(address: str, external: bool) -> None:
    assert ExternalIp().matches(address) is external


def test_boolean_composition_null_and_exists() -> None:
    is_process = FieldMatch(("class_uid",), Equals(1007))
    has_parent = FieldExists(("process.parent_process.pid",))
    assert AllOf((is_process, Not(has_parent))).evaluate(DOC)
    assert AnyOf((has_parent, FieldIsNull(("process.parent_process.pid",)))).evaluate(DOC)
    assert not FieldIsNull(("answers.rdata",)).evaluate(DOC)
    assert FieldExists(("process.parent_process.pid",), expected=False).evaluate(DOC)
    assert FieldMatch(("answers.rdata", "src_endpoint.ip"), Cidr(ipaddress.ip_network("10.0.0.0/8"))).evaluate(DOC)
