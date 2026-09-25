"""Splunk results → parser records: what maps, what is refused, and why."""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.ingest_pipeline.parsers import normalize
from app.ingest_pipeline.splunk import SplunkMappingError, to_record
from app.ingest_pipeline.tests.test_wineventlog_text import PROCESS as RENDERED_4688
from app.ingest_pipeline.tests.test_winxml import SECURITY_4688, SYSMON_1

SYSLOG_LINE = (
    "2026-09-15T09:14:02Z web-01 sshd[1]: Failed password for invalid user admin from 203.0.113.45 port 1 ssh2"
)
OCSF_EVENT = {
    "class_uid": 3002,
    "activity_id": 1,
    "severity_id": 1,
    "status_id": 1,
    "time": "2026-09-15T09:14:02Z",
    "metadata": {"product": {"name": "Aegis"}},
    "user": {"name": "jsmith"},
}


def result(sourcetype: str, raw: str, **extra: Any) -> dict[str, Any]:
    return {"sourcetype": sourcetype, "_raw": raw, "_time": "2026-09-15T09:14:02.000+00:00", **extra}


@pytest.mark.parametrize(
    ("sourcetype", "raw", "parser"),
    [
        ("XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", SYSMON_1, "windows_sysmon"),
        ("xmlwineventlog", SYSMON_1, "windows_sysmon"),
        ("XmlWinEventLog:Security", SECURITY_4688, "windows_security"),
        ("WinEventLog:Security", RENDERED_4688, "windows_security"),
        ("linux_secure", SYSLOG_LINE, "linux_auth"),
        ("syslog", SYSLOG_LINE, "linux_auth"),
        ("ocsf:events", json.dumps(OCSF_EVENT), "ocsf"),
        ("_json", json.dumps(OCSF_EVENT), "ocsf"),
    ],
)
def test_each_mapped_sourcetype_produces_a_record_its_parser_reads(sourcetype: str, raw: str, parser: str) -> None:
    mapped = to_record(result(sourcetype, raw))
    assert mapped.parser == parser
    normalize(mapped.parser, mapped.record)  # the record really is readable, not just routed


def test_a_rendered_windows_result_keeps_the_time_in_the_event_not_splunks() -> None:
    """The record states its own time; `_time` is a fallback only for a `_raw` that starts at the header."""
    mapped = to_record(result("WinEventLog:Security", RENDERED_4688))
    assert mapped.record["TimeCreated"] == "2020-12-04T13:19:21Z"
    headless = to_record(result("WinEventLog:Security", RENDERED_4688.split("\n", 1)[1]))
    assert headless.record["TimeCreated"] == "2026-09-15T09:14:02.000+00:00"


def test_a_syslog_result_keeps_splunks_event_time() -> None:
    mapped = to_record(result("syslog", "Sep 15 09:14:02 web-01 sshd[1]: Invalid user admin from 203.0.113.45"))
    assert mapped.record["timestamp"] == "2026-09-15T09:14:02.000+00:00"
    event = normalize("linux_auth", mapped.record)
    assert event.time.year == 2026, "a BSD syslog line has no year; Splunk's _time supplies it"


@pytest.mark.parametrize(
    ("bad", "message"),
    [
        (result("WinEventLog:Security", "12/04/2020 01:19:21 PM\nMessage=no code\n"), "no numeric EventCode"),
        (result("WinEventLog:System", "12/04/2020 01:19:21 PM\nEventCode=4688\n"), "no parser for channel"),
        (result("XmlWinEventLog:System", "<Event><System><Channel>System</Channel></System></Event>"), "no parser"),
        (result("XmlWinEventLog:Security", "<Event>broken"), "malformed event XML"),
        (result("ocsf", "{not json}"), "_raw is not JSON"),
        (result("ocsf", json.dumps({"hello": "world"})), "without class_uid"),
        (result("cisco:asa", "%ASA-6-302013: Built inbound TCP"), "no parser is mapped"),
        ({"sourcetype": "syslog"}, "no _raw"),
        ({"_raw": SYSLOG_LINE}, "no sourcetype"),
    ],
)
def test_unmappable_results_say_why(bad: dict[str, Any], message: str) -> None:
    with pytest.raises(SplunkMappingError, match=message):
        to_record(bad)
