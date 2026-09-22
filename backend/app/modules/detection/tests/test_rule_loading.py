"""Sigma translation and threshold rule parsing: what loads, what is refused, and why."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.modules.detection.domain.rules import RuleType
from app.modules.detection.infrastructure.ocsf_paths import is_known_path
from app.modules.detection.infrastructure.rule_loader import (
    RULES_DIR,
    check_field_mappings,
    compile_threshold,
    load_rules,
)
from app.modules.detection.infrastructure.sigma_loader import RuleLoadError, compile_sigma
from app.modules.detection.tests.conftest import document

WINDOWS_4688 = {
    "EventID": 4688,
    "TimeCreated": "2026-09-15T09:42:37Z",
    "Computer": "WS-FIN-07",
    "EventData": {
        "SubjectUserName": "jsmith",
        "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "NewProcessId": "0x1a4c",
        "CommandLine": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
        "ParentProcessName": r"C:\Windows\explorer.exe",
        "ProcessId": "0x0f20",
    },
}
PROCESS = document(WINDOWS_4688, "windows_security")
SSHD = document(
    {
        "message": "2026-09-15T09:14:02Z web-01 sshd[1]: "
        "Failed password for invalid user admin from 203.0.113.45 port 1 ssh2"
    },
    "linux_auth",
)


def sigma(detection: str, logsource: str = "{category: process_creation, product: windows}", **extra: str) -> str:
    fields = "".join(f"{key}: {value}\n" for key, value in extra.items())
    return (
        "title: test rule\nid: 5d0c3cf1-7f1b-4c43-9a0b-8f3cd5e0f7b1\nstatus: test\n"
        f"logsource: {logsource}\ndetection:\n{detection}\nlevel: {extra.pop('level', 'high')}\n{fields}"
    )


@pytest.mark.parametrize(
    ("detection", "fires"),
    [
        ("  sel:\n    Image|endswith: '\\powershell.exe'\n  condition: sel", True),
        ("  sel:\n    Image|endswith: '\\cmd.exe'\n  condition: sel", False),
        ("  sel:\n    CommandLine|contains|all: ['-noprofile', '-encodedcommand']\n  condition: sel", True),
        ("  sel:\n    CommandLine|contains|all: ['-noprofile', '-nonexistent']\n  condition: sel", False),
        ("  sel:\n    CommandLine|windash|contains: ' /encodedcommand '\n  condition: sel", True),
        ("  sel:\n    CommandLine|cased|contains: 'EncodedCommand'\n  condition: sel", True),
        ("  sel:\n    CommandLine|cased|contains: 'encodedcommand'\n  condition: sel", False),
        ("  sel:\n    CommandLine|re: '-Enc\\w*\\s+[A-Za-z0-9+/=]{8,}'\n  condition: sel", True),
        ("  sel:\n    CommandLine|re: '-ENCODEDCOMMAND'\n  condition: sel", False),  # re is case-sensitive
        ("  sel:\n    CommandLine|re|i: '-ENCODEDCOMMAND'\n  condition: sel", True),
        ("  sel:\n    ProcessId|gt: 1000\n  condition: sel", True),
        ("  sel:\n    ParentCommandLine: null\n  condition: sel", True),
        ("  sel:\n    User|exists: true\n  condition: sel", True),
        (
            "  a:\n    Image|endswith: '\\cmd.exe'\n  b:\n    ParentImage|endswith: '\\explorer.exe'\n"
            "  condition: 1 of a or b",
            True,
        ),
        (
            "  sel:\n    Image|endswith: '\\powershell.exe'\n  filter:\n    ParentImage|endswith: '\\explorer.exe'\n"
            "  condition: sel and not filter",
            False,
        ),
        ("  keywords:\n    - 'EncodedCommand'\n  condition: keywords", True),
    ],
)
def test_sigma_semantics_against_a_normalised_windows_event(detection: str, fires: bool) -> None:
    rule = compile_sigma(sigma(detection), path="t.yml")
    assert rule.predicate.evaluate(PROCESS) is fires


def test_logsource_scope_keeps_rules_on_their_own_events() -> None:
    rule = compile_sigma(sigma("  keywords:\n    - 'admin'\n  condition: keywords"), path="t.yml")
    assert not rule.predicate.evaluate(SSHD), "a process_creation rule never matches an authentication event"

    linux = compile_sigma(
        sigma("  keywords:\n    - 'invalid user'\n  condition: keywords", "{product: linux, service: sshd}"),
        path="t.yml",
    )
    assert linux.predicate.evaluate(SSHD)
    assert not linux.predicate.evaluate(PROCESS)


def test_windows_security_fields_map_to_ocsf() -> None:
    rule = compile_sigma(
        sigma(
            "  sel:\n    EventID: 4688\n    SubjectUserName: jsmith\n  condition: sel",
            "{product: windows, service: security}",
        ),
        path="t.yml",
    )
    assert rule.logsource == "windows/security"
    assert rule.predicate.evaluate(PROCESS)


def test_metadata_is_captured() -> None:
    rule = compile_sigma(
        sigma(
            "  sel:\n    Image|endswith: '\\powershell.exe'\n  condition: sel",
            tags="[attack.execution, attack.t1059.001, attack.g0016, attack.credential-access]",
        ),
        path="t.yml",
    )
    assert rule.meta.attack.techniques == ("T1059.001",)
    assert rule.meta.attack.tactics == ("execution", "credential_access")
    assert rule.meta.severity_id == 4
    assert len(rule.meta.version) == 64


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        (sigma("  sel:\n    TerminalSessionId: 1\n  condition: sel"), "field 'TerminalSessionId' is not mapped"),
        (sigma("  sel:\n    Image: x\n  condition: sel", "{product: windows}"), "unsupported logsource"),
        (
            sigma("  sel:\n    Image: x\n  condition: sel", "{category: pipe_created, product: windows}"),
            "unsupported logsource",
        ),
        (sigma("  keywords:\n    - x\n  condition: keywords", "{category: network_connection}"), "keyword searches"),
        (sigma("  sel:\n    Image|fieldref: CommandLine\n  condition: sel"), "unsupported value type"),
        (sigma("  sel:\n    CommandLine|re: '(unclosed'\n  condition: sel"), "is invalid"),
        (
            "title: x\nlogsource: {category: process_creation}\n"
            "detection:\n  a: {Image: x}\n  condition: a\nlevel: high\n",
            "must have an id",
        ),
        ("title: [unbalanced\n", "not a valid Sigma rule"),
    ],
)
def test_unsupported_rules_are_refused_with_a_reason(text: str, reason: str) -> None:
    with pytest.raises(RuleLoadError, match=reason):
        compile_sigma(text, path="bad.yml")


THRESHOLD = """
id: 4f8b2c6d-1a37-4e95-b0c2-7d6e9f1a3b58
title: test threshold
level: medium
tags: [attack.credential_access, attack.t1110.003]
match:
  class_uid: 3002
  status_id: [2, 99]
  dst_endpoint.ip|external: true
group_by: [src_endpoint.ip]
count_distinct: user.name
threshold: 3
window: 90s
"""


def test_threshold_rules_parse() -> None:
    rule = compile_threshold(THRESHOLD, path="t.yml")
    assert (rule.threshold, rule.window_ms, rule.count_distinct) == (3, 90_000, "user.name")
    assert rule.meta.attack.techniques == ("T1110.003",)
    auth_to_external = {"class_uid": 3002, "status_id": 99, "dst_endpoint": {"ip": "192.0.2.1"}}
    assert rule.match.evaluate(auth_to_external)
    assert not rule.match.evaluate({**auth_to_external, "dst_endpoint": {"ip": "10.0.0.1"}})
    assert not rule.match.evaluate({**auth_to_external, "status_id": 1})


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (("class_uid: 3002", "clas_uid: 3002"), "unknown field 'clas_uid'"),
        (("group_by: [src_endpoint.ip]", "group_by: [src_endpoint.address]"), "unknown field 'src_endpoint.address'"),
        (("window: 90s", "window: 2d"), "window must look like"),
        (("window: 90s", "window: 25h"), "may not exceed 24h"),
        (("threshold: 3", "threshold: 1"), "greater than or equal to 2"),
        (("dst_endpoint.ip|external: true", "dst_endpoint.ip|startswith: x"), "unsupported match operator"),
        (("dst_endpoint.ip|external: true", "dst_endpoint.ip|external: false"), "only accepts true"),
        (("level: medium", "level: severe"), "level"),
        (("title: test threshold", "title: test threshold\nsurprise: 1"), "Extra inputs"),
    ],
)
def test_bad_threshold_rules_are_refused(change: tuple[str, str], reason: str) -> None:
    with pytest.raises(RuleLoadError, match=reason):
        compile_threshold(THRESHOLD.replace(*change), path="t.yml")


def test_every_shipped_rule_loads_and_every_mapping_points_at_a_real_field() -> None:
    assert check_field_mappings() == []
    rules = load_rules()
    own = [rule for rule in rules.all() if not rule.meta.path.startswith("sigmahq/")]
    community = [rule for rule in rules.all() if rule.meta.path.startswith("sigmahq/")]
    assert len([r for r in own if r.type is RuleType.SIGMA]) == 4
    assert len(rules.threshold) == 3
    assert len(community) >= 150, "the SigmaHQ pack is shipped"
    for rule in rules.all():
        assert rule.meta.attack.techniques, f"{rule.meta.path} names no ATT&CK technique"
        assert rule.meta.description, f"{rule.meta.path} has no description"


def test_community_rules_keep_their_author_and_a_link_to_the_original() -> None:
    """The Detection Rule License requires every match to name the rule's author (rules/sigmahq/NOTICE.md)."""
    rules = load_rules()
    manifest = json.loads((RULES_DIR / "sigmahq" / "MANIFEST.json").read_text(encoding="utf-8"))
    for rule in rules.all():
        if not rule.meta.path.startswith("sigmahq/"):
            assert rule.meta.author == "Sentinel-X", f"{rule.meta.path} is not attributed"
            assert rule.meta.source_url is None
            continue
        upstream = rule.meta.path.removeprefix("sigmahq/")
        assert upstream in manifest["files"], f"{upstream} is not in MANIFEST.json"
        assert rule.meta.author, f"{rule.meta.path} lost its author"
        assert rule.meta.source_url == f"{manifest['rule_base_url']}/{manifest['files'][upstream]}"


def test_every_vendored_file_is_listed_in_the_manifest() -> None:
    manifest = json.loads((RULES_DIR / "sigmahq" / "MANIFEST.json").read_text(encoding="utf-8"))
    on_disk = {path.relative_to(RULES_DIR / "sigmahq").as_posix() for path in (RULES_DIR / "sigmahq").rglob("*.yml")}
    assert on_disk == set(manifest["files"])
    assert manifest["license"].startswith("Detection Rule License")


def test_one_bad_file_stops_loading_with_every_problem_listed(tmp_path: Path) -> None:
    for kind in ("sigma", "threshold"):
        (tmp_path / kind).mkdir()
    (tmp_path / "sigma" / "a.yml").write_text(sigma("  sel:\n    Nope: x\n  condition: sel"), encoding="utf-8")
    (tmp_path / "threshold" / "b.yml").write_text(THRESHOLD.replace("window: 90s", "window: forever"), encoding="utf-8")

    with pytest.raises(RuleLoadError) as error:
        load_rules(tmp_path)
    assert "sigma/a.yml" in str(error.value)
    assert "threshold/b.yml" in str(error.value)


def test_duplicate_rule_ids_are_refused(tmp_path: Path) -> None:
    for kind in ("sigma", "threshold"):
        (tmp_path / kind).mkdir()
    rule = (RULES_DIR / "sigma" / "win_proc_whoami_privilege_discovery.yml").read_text(encoding="utf-8")
    (tmp_path / "sigma" / "one.yml").write_text(rule, encoding="utf-8")
    (tmp_path / "sigma" / "two.yml").write_text(rule, encoding="utf-8")
    with pytest.raises(RuleLoadError, match="duplicate rule ids"):
        load_rules(tmp_path)


@pytest.mark.parametrize(
    ("path", "known"),
    [
        ("process.parent_process.file.hashes.value", True),
        ("answers.rdata", True),
        ("sx.event_uid", True),
        ("unmapped.event_id", True),
        ("unmapped.", False),
        ("process.image", False),
    ],
)
def test_known_paths(path: str, known: bool) -> None:
    assert is_known_path(path) is known
