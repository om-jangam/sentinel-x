"""Parsers are exercised against every line of the shipped demo telemetry (pipeline/samples)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.ingest_pipeline.ocsf import EventClass, Status
from app.ingest_pipeline.parsers import PARSER_DESCRIPTIONS, PARSERS, ParseError, normalize
from app.ingest_pipeline.parsers.base import as_int, as_ip, clean

SAMPLES = Path(__file__).resolve().parents[4] / "pipeline" / "samples"


def _lines(name: str) -> list[str]:
    return [line for line in (SAMPLES / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def _jsonl(name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in _lines(name)]


def test_every_parser_is_described() -> None:
    assert set(PARSERS) == set(PARSER_DESCRIPTIONS)


# ------------------------------------------------------------ linux_auth
def test_linux_auth_sample_maps_every_authentication_outcome() -> None:
    events, skipped = [], []
    for line in _lines("linux_auth.log"):
        try:
            events.append(normalize("linux_auth", {"message": line}))
        except ParseError:
            skipped.append(line)

    assert len(events) == 14
    assert len(skipped) == 1
    assert "pam_unix" in skipped[0]
    assert all(e.class_uid is EventClass.AUTHENTICATION for e in events)
    assert sum(e.status_id is Status.FAILURE for e in events) == 11
    assert sum(e.status_id is Status.SUCCESS for e in events) == 3


def test_linux_auth_failed_invalid_user_details() -> None:
    event = normalize(
        "linux_auth",
        {
            "message": "2026-09-15T09:14:02.519004+00:00 web-01 sshd[2211]: "
            "Failed password for invalid user admin from 203.0.113.45 port 41822 ssh2"
        },
    )
    assert event.status_id is Status.FAILURE
    assert event.user is not None
    assert event.user.name == "admin"
    assert event.src_endpoint is not None
    assert str(event.src_endpoint.ip) == "203.0.113.45"
    assert event.src_endpoint.port == 41822
    assert event.device is not None
    assert event.device.hostname == "web-01"
    assert event.unmapped == {"auth_method": "password", "invalid_user": True, "pid": 2211}
    assert event.raw_data is not None
    assert event.raw_data.startswith("2026-09-15T09:14:02")


def test_linux_auth_bsd_syslog_uses_supplied_timestamp() -> None:
    event = normalize(
        "linux_auth",
        {
            "message": "Sep 15 09:14:19 web-01 sshd[2231]: "
            "Accepted password for deploy from 203.0.113.45 port 41958 ssh2",
            "timestamp": "2026-09-15T09:14:19Z",
        },
    )
    assert event.status_id is Status.SUCCESS
    assert event.time.isoformat() == "2026-09-15T09:14:19+00:00"


def test_linux_auth_bsd_syslog_without_timestamp_assumes_current_year_utc() -> None:
    event = normalize(
        "linux_auth",
        {"message": "Jan  3 01:02:03 web-01 sshd[1]: Invalid user bob from 203.0.113.9 port 22"},
    )
    assert (event.time.month, event.time.day, event.time.hour) == (1, 3, 1)


def test_linux_auth_hostname_source_address() -> None:
    event = normalize(
        "linux_auth",
        {"message": "2026-09-15T09:00:00Z web-01 sshd[9]: Failed password for bob from attacker.example port 22 ssh2"},
    )
    assert event.src_endpoint is not None
    assert event.src_endpoint.ip is None
    assert event.src_endpoint.hostname == "attacker.example"


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"message": ""},
        {"message": "2026-09-15T09:00:00Z web-01 cron[1]: job ran"},
        {"message": "2026-09-15T09:00:00Z web-01 sshd[1]: Connection closed by 10.0.0.1 port 22"},
    ],
)
def test_linux_auth_rejects_non_authentication_records(record: dict[str, Any]) -> None:
    with pytest.raises(ParseError):
        normalize("linux_auth", record)


# ------------------------------------------------------ windows_security
def test_windows_sample_maps_logons_and_process_creation() -> None:
    events = [normalize("windows_security", record) for record in _jsonl("windows_security.jsonl")]
    by_class: dict[EventClass, int] = {}
    for event in events:
        by_class[event.class_uid] = by_class.get(event.class_uid, 0) + 1
    assert by_class == {EventClass.AUTHENTICATION: 9, EventClass.PROCESS_ACTIVITY: 3}
    assert sum(e.status_id is Status.FAILURE for e in events) == 6


def test_windows_failed_network_logon() -> None:
    record = _jsonl("windows_security.jsonl")[1]
    event = normalize("windows_security", record)
    assert event.status_id is Status.FAILURE
    assert event.logon_type == "Network"
    assert event.logon_type_id == 3
    assert event.auth_protocol == "NTLM"
    assert event.user is not None
    assert (event.user.name, event.user.domain) == ("jsmith", "ACME")
    assert event.src_endpoint is not None
    assert str(event.src_endpoint.ip) == "198.51.100.23"
    assert event.metadata.uid == "880310"
    assert event.unmapped is not None
    assert event.unmapped["sub_status"] == "0xc000006a"


def test_windows_rdp_logon_ignores_zero_port_and_interactive_logon_has_no_ip() -> None:
    records = _jsonl("windows_security.jsonl")
    rdp = normalize("windows_security", records[7])
    assert rdp.logon_type == "RemoteInteractive"
    assert rdp.src_endpoint is not None
    assert rdp.src_endpoint.port is None
    interactive = normalize("windows_security", records[0])
    assert interactive.src_endpoint is not None
    assert interactive.src_endpoint.ip is None
    assert interactive.src_endpoint.hostname == "WS-FIN-07"


def test_windows_process_creation_decodes_hex_pids() -> None:
    event = normalize("windows_security", _jsonl("windows_security.jsonl")[8])
    assert event.class_uid is EventClass.PROCESS_ACTIVITY
    process = event.process
    assert process is not None
    assert (process.name, process.pid) == ("powershell.exe", 0x1A4C)
    assert process.cmd_line is not None
    assert "-EncodedCommand" in process.cmd_line
    assert process.parent_process is not None
    assert (process.parent_process.name, process.parent_process.pid) == ("explorer.exe", 0x0F20)
    assert event.actor is not None
    assert event.actor.user is not None
    assert event.actor.user.name == "jsmith"
    assert {"process.name", "process.file.path", "actor.user.name"} <= {o.name for o in event.observables}


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ({"TimeCreated": "2026-09-15T09:00:00Z"}, "EventID"),
        ({"EventID": 4104, "TimeCreated": "2026-09-15T09:00:00Z"}, "unsupported"),
        ({"EventID": 4624, "EventData": {}}, "TimeCreated"),
        ({"EventID": 4688, "TimeCreated": "2026-09-15T09:00:00Z", "EventData": {}}, "NewProcessName"),
        ({"EventID": 4624, "TimeCreated": "2026-09-15T09:00:00Z", "EventData": []}, "object"),
    ],
)
def test_windows_rejects_unmappable_records(record: dict[str, Any], message: str) -> None:
    with pytest.raises(ParseError, match=message):
        normalize("windows_security", record)


# ------------------------------------------------------------------ ocsf
def test_ocsf_sample_passes_through_and_validates() -> None:
    events = [normalize("ocsf", record) for record in _jsonl("ocsf_network.jsonl")]
    assert [e.class_uid for e in events].count(EventClass.NETWORK_ACTIVITY) == 6
    assert events[0].class_uid is EventClass.DNS_ACTIVITY
    assert events[0].query is not None
    assert events[0].query.hostname == "cdn-telemetry-sync.example"
    assert events[0].raw_data is not None, "raw record is preserved when the producer sent none"


def test_ocsf_passthrough_requires_class_uid() -> None:
    with pytest.raises(ParseError, match="class_uid"):
        normalize("ocsf", {"activity_id": 1})


def test_ocsf_passthrough_still_validates() -> None:
    with pytest.raises(ValidationError):
        normalize("ocsf", {"class_uid": 4001, "activity_id": 6})


def test_unknown_parser() -> None:
    with pytest.raises(ParseError, match="unknown parser"):
        normalize("cisco_asa", {})


# --------------------------------------------------------------- helpers
def test_value_helpers() -> None:
    assert clean(" - ") is None
    assert clean("x ") == "x"
    assert as_ip("::1") == "::1"
    assert as_ip("not-an-ip") is None
    assert as_int("0x1a", base=16) == 26
    assert as_int("abc") is None
    assert as_int(7) == 7
