"""The Security events that show credential use: explicit credentials, privileges, Kerberos, NTLM.

Field names and values are taken from the records in `.cache/detection-datasets/*/*/windows-security.log`.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.ingest_pipeline.ocsf import AuthProtocol, EventClass, Status
from app.ingest_pipeline.parsers import ParseError, normalize


def record(event_id: int, **data: Any) -> dict[str, Any]:
    return {
        "EventID": event_id,
        "TimeCreated": "2020-11-20T09:43:21Z",
        "Computer": "win-dc-255.attackrange.local",
        "EventRecordID": 233325,
        "EventData": data,
    }


def parse(event_id: int, **data: Any) -> Any:
    return normalize("windows_security", record(event_id, **data))


def test_explicit_credentials_name_both_accounts_and_the_server() -> None:
    """4648 is the runas event: who asked, whose credentials, and against what."""
    event = parse(
        4648,
        SubjectUserName="EC2AMAZ-O5EOQ54$",
        SubjectDomainName="WORKGROUP",
        TargetUserName="svc_backup",
        TargetDomainName="ATTACKRANGE",
        TargetServerName="FILE-01",
        ProcessName="C:\\Windows\\System32\\runas.exe",
        ProcessId="0x29c",
        IpAddress="10.0.1.15",
    )
    assert event.class_uid is EventClass.AUTHENTICATION
    assert event.activity_id == 7, "Account Switch: the subject used another account's credentials"
    assert event.user is not None
    assert (event.user.name, event.user.domain) == ("svc_backup", "ATTACKRANGE")
    assert event.actor is not None
    assert event.actor.user is not None
    assert event.actor.user.name == "EC2AMAZ-O5EOQ54$"
    assert event.actor.process is not None
    assert (event.actor.process.name, event.actor.process.pid) == ("runas.exe", 668)
    assert event.dst_endpoint is not None
    assert event.dst_endpoint.hostname == "FILE-01"


def test_an_attempted_logon_is_not_recorded_as_a_successful_one() -> None:
    """Windows writes 4648 for the attempt, whatever happens next; a status would be invented."""
    assert parse(4648, TargetUserName="svc_backup").status_id is Status.UNKNOWN


def test_special_privileges_are_listed_as_what_the_session_was_given() -> None:
    event = parse(
        4672,
        SubjectUserName="administrator",
        SubjectDomainName="ATTACKRANGE",
        PrivilegeList="SeAssignPrimaryTokenPrivilege\n\t\t\tSeAuditPrivilege\n\t\t\tSeTcbPrivilege",
    )
    assert event.class_uid is EventClass.AUTHORIZE_SESSION
    assert event.activity_id == 1, "Assign Privileges"
    assert event.privileges == ["SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeTcbPrivilege"]
    assert event.user is not None
    assert event.user.name == "administrator"
    assert event.status_id is Status.UNKNOWN, "the record says what was granted, not what was done with it"


def test_a_kerberos_ticket_request_names_the_account_the_service_and_the_client() -> None:
    event = parse(
        4768,
        TargetUserName="jsmith",
        TargetDomainName="ATTACKRANGE.LOCAL",
        ServiceName="krbtgt",
        ServiceSid="S-1-5-21-1004336348-1177238915-682003330-502",
        IpAddress="::ffff:10.0.1.14",
        IpPort="58211",
        Status="0x0",
        TicketEncryptionType="0x12",
    )
    assert event.activity_id == 3, "Authentication Ticket"
    assert event.auth_protocol == "Kerberos"
    assert event.auth_protocol_id is AuthProtocol.KERBEROS
    assert event.service is not None
    assert event.service.name == "krbtgt"
    assert event.status_id is Status.SUCCESS
    assert event.src_endpoint is not None
    assert str(event.src_endpoint.ip) == "10.0.1.14", "an IPv4-mapped address is the IPv4 address"
    assert event.unmapped is not None
    assert event.unmapped["ticket_encryption_type"] == "0x12"


def test_a_service_ticket_request_for_a_weak_cipher_keeps_the_cipher_and_the_service() -> None:
    """What kerberoasting looks like in a log: a service ticket asked for with RC4 (0x17)."""
    event = parse(
        4769,
        TargetUserName="jsmith@ATTACKRANGE.LOCAL",
        TargetDomainName="ATTACKRANGE.LOCAL",
        ServiceName="svc_sql",
        TicketEncryptionType="0x17",
        TicketOptions="0x40810000",
        Status="0x0",
    )
    assert event.activity_id == 4, "Service Ticket Request"
    assert event.service is not None
    assert event.service.name == "svc_sql"
    assert event.unmapped is not None
    assert event.unmapped["ticket_encryption_type"] == "0x17"


@pytest.mark.parametrize(
    ("event_id", "status", "expected"),
    [
        (4768, "0x0", Status.SUCCESS),
        (4768, "0x6", Status.FAILURE),  # the account does not exist
        (4769, "0x0", Status.SUCCESS),
        (4769, "0x1F", Status.FAILURE),
        (4771, "0x18", Status.FAILURE),  # pre-authentication failed: a wrong password
        (4776, "0x0", Status.SUCCESS),
        (4776, "0xC000006A", Status.FAILURE),  # wrong password
    ],
)
def test_the_outcome_comes_from_the_result_code_the_record_states(event_id: int, status: str, expected: Status) -> None:
    event = parse(event_id, TargetUserName="jsmith", ServiceName="krbtgt", Status=status)
    assert event.status_id is expected
    assert event.unmapped is not None
    assert event.unmapped["status"] == status


def test_4771_is_a_failure_whatever_the_code_says() -> None:
    """A pre-authentication *failure* event cannot be a success, so the code only gives the reason."""
    event = parse(4771, TargetUserName="jsmith", Status="0x0")
    assert event.activity_id == 6, "Preauth"
    assert event.status_id is Status.FAILURE


def test_credential_validation_is_ntlm_whichever_name_windows_uses_for_it() -> None:
    """4776 names the package MSV1_0; the NTLM log says "NTLM". One id so a rule can match both."""
    event = parse(
        4776,
        PackageName="MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
        TargetUserName="Administrator",
        Workstation="EC2AMAZ-FDGG73M",
        Status="0x0",
    )
    assert event.auth_protocol == "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0", "stated verbatim"
    assert event.auth_protocol_id is AuthProtocol.NTLM
    assert event.user is not None
    assert event.user.name == "Administrator"
    assert event.src_endpoint is not None
    assert event.src_endpoint.hostname == "EC2AMAZ-FDGG73M"


@pytest.mark.parametrize(
    ("package", "expected"),
    [("NTLM", AuthProtocol.NTLM), ("Kerberos", AuthProtocol.KERBEROS), ("Negotiate", None)],
)
def test_a_logons_protocol_id_is_set_only_where_the_package_names_one(
    package: str, expected: AuthProtocol | None
) -> None:
    """ "Negotiate" picked NTLM or Kerberos and does not say which, so no id is claimed."""
    event = parse(4624, TargetUserName="jsmith", AuthenticationPackageName=package, LogonType="3")
    assert event.auth_protocol == package
    assert event.auth_protocol_id is expected


@pytest.mark.parametrize(
    ("event_id", "data", "message"),
    [
        (4672, {"PrivilegeList": "SeDebugPrivilege"}, "4672 event names no account"),
        (4776, {"Status": "0x0"}, "4776 event names no account"),
    ],
)
def test_records_that_name_no_account_are_refused(event_id: int, data: dict[str, Any], message: str) -> None:
    with pytest.raises(ParseError, match=message):
        parse(event_id, **data)
