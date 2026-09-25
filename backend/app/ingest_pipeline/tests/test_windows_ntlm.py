"""Windows NTLM auditing → OCSF: who was tried, from where, and what the record does not say."""

from __future__ import annotations

from typing import Any

import pytest

from app.ingest_pipeline.ocsf import EventClass, Status
from app.ingest_pipeline.parsers import ParseError, normalize

EVENT_DATA: dict[str, str] = {
    "SChannelName": "VICTIM_PC",
    "UserName": "backup",
    "DomainName": "CORP",
    "WorkstationName": "WIN-SHKRDLDI338",
    "SChannelType": "2",
}
AUDIT: dict[str, Any] = {
    "EventID": 8004,
    "TimeCreated": "2024-01-18T05:04:59.727635Z",
    "Computer": "attack_dc.attack_range.lan",
    "EventRecordID": 2728229667,
    "Channel": "Microsoft-Windows-NTLM/Operational",
    "EventData": EVENT_DATA,
}


def parse(record: dict[str, Any]) -> Any:
    return normalize("windows_ntlm", record)


def test_an_audited_attempt_names_the_account_and_the_workstation() -> None:
    event = parse(AUDIT)
    assert event.class_uid is EventClass.AUTHENTICATION
    assert event.activity_id == 1
    assert event.user is not None
    assert (event.user.name, event.user.domain) == ("backup", "CORP")
    assert event.src_endpoint is not None
    assert event.src_endpoint.hostname == "WIN-SHKRDLDI338"
    assert event.device is not None
    assert event.device.hostname == "attack_dc.attack_range.lan"
    assert event.auth_protocol == "NTLM"
    assert event.metadata.log_name == "Microsoft-Windows-NTLM/Operational"
    assert event.unmapped is not None
    assert event.unmapped["secure_channel_name"] == "VICTIM_PC"


def test_the_outcome_is_unknown_because_the_record_does_not_state_it() -> None:
    """8004 says NTLM was used, never whether it worked; guessing either way would invent evidence."""
    assert parse(AUDIT).status_id is Status.UNKNOWN


@pytest.mark.parametrize("absent", ["NULL", "null", "-", ""])
def test_rendered_empty_values_are_read_as_absent(absent: str) -> None:
    record = {**AUDIT, "EventData": {**EVENT_DATA, "WorkstationName": absent, "DomainName": absent}}
    event = parse(record)
    assert event.src_endpoint is None
    assert event.user is not None
    assert event.user.domain is None
    assert event.user.name == "backup", "the account is still named"


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ({**AUDIT, "EventID": 8002}, "unsupported Windows NTLM event 8002"),
        ({**AUDIT, "EventID": None}, "no numeric EventID"),
        ({**AUDIT, "EventData": {**EVENT_DATA, "UserName": "NULL"}}, "no UserName"),
        ({k: v for k, v in AUDIT.items() if k != "TimeCreated"}, "no TimeCreated"),
        ({**AUDIT, "EventData": "x"}, "EventData must be an object"),
    ],
)
def test_unmappable_records_are_rejected_with_a_reason(record: dict[str, Any], message: str) -> None:
    with pytest.raises(ParseError, match=message):
        parse(record)
