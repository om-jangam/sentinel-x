"""Sigma rules over normalised Sysmon events: each category loads, fires on its event, and only on it.

The detections are written in SigmaHQ's style for the techniques in `sysmon_records`; they are test rules,
not copies of SigmaHQ rules.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.ingest_pipeline.tests import sysmon_records as r
from app.modules.detection.infrastructure.sigma_loader import compile_sigma
from app.modules.detection.tests.conftest import document
from app.modules.detection.tests.test_rule_loading import PROCESS as SECURITY_4688
from app.modules.detection.tests.test_rule_loading import sigma

DOCS: dict[str, dict[str, Any]] = {
    "process_create": document(r.PROCESS_CREATE, "windows_sysmon"),
    "network": document(r.NETWORK, "windows_sysmon"),
    "terminate": document(r.TERMINATE, "windows_sysmon"),
    "image_load": document(r.IMAGE_LOAD, "windows_sysmon"),
    "remote_thread": document(r.REMOTE_THREAD, "windows_sysmon"),
    "lsass_access": document(r.LSASS_ACCESS, "windows_sysmon"),
    "file_create": document(r.FILE_CREATE, "windows_sysmon"),
    "reg_create_key": document(r.REG_CREATE_KEY, "windows_sysmon"),
    "reg_set_run_key": document(r.REG_SET_RUN_KEY, "windows_sysmon"),
    "reg_rename": document(r.REG_RENAME, "windows_sysmon"),
    "dns": document(r.DNS, "windows_sysmon"),
    "file_delete": document(r.FILE_DELETE, "windows_sysmon"),
}

CASES = [
    (
        "process_creation",
        "  sel:\n    ParentImage|endswith: '\\WINWORD.EXE'\n    Image|endswith: '\\powershell.exe'\n  condition: sel",
        {"process_create"},
    ),
    (
        "process_creation",
        "  sel:\n    OriginalFileName: 'PowerShell.EXE'\n    IntegrityLevel: 'Medium'\n"
        "    Hashes|contains: 'IMPHASH=F1D2E3C4'\n  condition: sel",
        {"process_create"},
    ),
    (
        "network_connection",
        "  sel:\n    Image|endswith: '\\powershell.exe'\n    Initiated: 'true'\n    DestinationPort: 443\n"
        "  condition: sel",
        {"network"},
    ),
    ("process_termination", "  sel:\n    Image|endswith: '\\powershell.exe'\n  condition: sel", {"terminate"}),
    (
        "image_load",
        "  sel:\n    ImageLoaded|endswith: '\\vaultcli.dll'\n    Image|endswith: '\\powershell.exe'\n  condition: sel",
        {"image_load"},
    ),
    (
        "create_remote_thread",
        "  sel:\n    SourceImage|endswith: '\\powershell.exe'\n    TargetImage|endswith: '\\explorer.exe'\n"
        "  condition: sel",
        {"remote_thread"},
    ),
    (
        "process_access",
        "  sel:\n    TargetImage|endswith: '\\lsass.exe'\n    GrantedAccess: '0x1010'\n"
        "    CallTrace|contains: 'UNKNOWN('\n  condition: sel",
        {"lsass_access"},
    ),
    (
        "file_event",
        "  sel:\n    TargetFilename|contains: '\\AppData\\Local\\Temp\\'\n  condition: sel",
        {"file_create"},
    ),
    ("file_delete", "  sel:\n    TargetFilename|endswith: '\\m.exe'\n  condition: sel", {"file_delete"}),
    (
        "registry_add",
        "  sel:\n    TargetObject|contains: '\\ms-settings\\shell\\open\\command'\n  condition: sel",
        {"reg_create_key"},
    ),
    (
        "registry_set",
        "  sel:\n    TargetObject|contains: '\\CurrentVersion\\Run\\'\n    Details|contains: '\\Temp\\'\n"
        "  condition: sel",
        {"reg_set_run_key"},
    ),
    ("registry_rename", "  sel:\n    NewName|endswith: '\\New'\n  condition: sel", {"reg_rename"}),
    (
        "registry_event",
        "  sel:\n    TargetObject|startswith: 'HK'\n  condition: sel",
        {"reg_create_key", "reg_set_run_key", "reg_rename"},
    ),
    (
        "dns_query",
        "  sel:\n    QueryName|endswith: '.bad.example'\n    Image|endswith: '\\powershell.exe'\n  condition: sel",
        {"dns"},
    ),
]


@pytest.mark.parametrize(("category", "detection", "expected"), CASES)
def test_each_sysmon_category_fires_only_on_its_own_events(category: str, detection: str, expected: set[str]) -> None:
    rule = compile_sigma(sigma(detection, f"{{category: {category}, product: windows}}"), path="t.yml")
    assert rule.logsource == category
    fired = {name for name, doc in DOCS.items() if rule.predicate.evaluate(doc)}
    assert fired == expected


def test_process_creation_rules_cover_both_security_4688_and_sysmon_1() -> None:
    rule = compile_sigma(sigma("  sel:\n    Image|endswith: '\\powershell.exe'\n  condition: sel"), path="t.yml")
    assert rule.predicate.evaluate(SECURITY_4688)
    assert rule.predicate.evaluate(DOCS["process_create"])


def test_sysmon_user_matches_as_sysmon_writes_it() -> None:
    rule = compile_sigma(sigma("  sel:\n    User|contains: 'CORP\\jsmith'\n  condition: sel"), path="t.yml")
    assert rule.predicate.evaluate(DOCS["process_create"])


def test_event_id_rules_on_the_sysmon_service() -> None:
    rule = compile_sigma(
        sigma(
            "  sel:\n    EventID: 10\n    TargetImage|endswith: '\\lsass.exe'\n  condition: sel",
            "{product: windows, service: sysmon}",
        ),
        path="t.yml",
    )
    assert rule.logsource == "windows/sysmon"
    assert {name for name, doc in DOCS.items() if rule.predicate.evaluate(doc)} == {"lsass_access"}
    assert not rule.predicate.evaluate(SECURITY_4688)


def test_image_on_the_sysmon_service_never_matches_the_parent_of_event_1() -> None:
    rule = compile_sigma(
        sigma(
            "  sel:\n    EventID: 1\n    Image|endswith: '\\WINWORD.EXE'\n  condition: sel",
            "{product: windows, service: sysmon}",
        ),
        path="t.yml",
    )
    assert not rule.predicate.evaluate(DOCS["process_create"])
