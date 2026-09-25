"""Splunk's rendered `WinEventLog` text: what the prose says, and what it must not be read as saying.

The blocks below are shaped exactly like the ones in the public recordings under
`.cache/detection-datasets/*/*/windows-security.log`.
"""

from __future__ import annotations

import pytest

from app.ingest_pipeline.parsers import UnsupportedEventError, normalize
from app.ingest_pipeline.parsers.windows_security import _HANDLERS
from app.ingest_pipeline.wineventlog_text import LABELS, WinEventLogTextError, iter_records, parse_record

LOGON = """12/04/2020 02:20:56 PM
LogName=Security
SourceName=Microsoft Windows security auditing.
EventCode=4624
EventType=0
Type=Information
ComputerName=EC2AMAZ-8BAVDVD
TaskCategory=Logon
OpCode=Info
RecordNumber=231502
Keywords=Audit Success
Message=An account was successfully logged on.

Subject:
\tSecurity ID:\t\tS-1-5-18
\tAccount Name:\t\tEC2AMAZ-8BAVDVD$
\tAccount Domain:\t\tATTACKRANGE
\tLogon ID:\t\t0x3E7

Logon Information:
\tLogon Type:\t\t3
\tRestricted Admin Mode:\t-

New Logon:
\tSecurity ID:\t\tATTACKRANGE\\Administrator
\tAccount Name:\t\tAdministrator
\tAccount Domain:\t\tATTACKRANGE
\tLogon ID:\t\t0x1FD9A1

Process Information:
\tProcess ID:\t\t0x0
\tProcess Name:\t\t-

Network Information:
\tWorkstation Name:\tEC2AMAZ-O5EOQ54
\tSource Network Address:\t10.0.1.15
\tSource Port:\t\t51234

Detailed Authentication Information:
\tLogon Process:\t\tNtLmSsp
\tAuthentication Package:\tNTLM
"""

PROCESS = """12/04/2020 01:19:21 PM
LogName=Security
EventCode=4688
ComputerName=EC2AMAZ-O5EOQ54
RecordNumber=231333
Message=A new process has been created.

Creator Subject:
\tSecurity ID:\t\tATTACKRANGE\\Administrator
\tAccount Name:\t\tAdministrator
\tAccount Domain:\t\tATTACKRANGE

Process Information:
\tNew Process ID:\t\t0x1bc
\tNew Process Name:\tC:\\Windows\\System32\\whoami.exe
\tToken Elevation Type:\t%%1936
\tCreator Process ID:\t0x198
\tCreator Process Name:\tC:\\Windows\\System32\\cmd.exe
\tProcess Command Line:\twhoami.exe /priv
"""


def test_a_logon_is_read_as_who_logged_on_not_who_asked() -> None:
    """The label "Account Name" appears three times here; only the one under New Logon is the account."""
    record = parse_record(LOGON)
    data = record["EventData"]
    assert record["EventID"] == 4624
    assert (data["TargetUserName"], data["TargetDomainName"]) == ("Administrator", "ATTACKRANGE")
    assert (data["SubjectUserName"], data["SubjectDomainName"]) == ("EC2AMAZ-8BAVDVD$", "ATTACKRANGE")
    assert data["LogonType"] == "3"
    assert (data["IpAddress"], data["IpPort"]) == ("10.0.1.15", "51234")
    assert data["WorkstationName"] == "EC2AMAZ-O5EOQ54"
    assert data["AuthenticationPackageName"] == "NTLM"
    assert record["Computer"] == "EC2AMAZ-8BAVDVD"
    assert record["EventRecordID"] == "231502"
    assert record["Channel"] == "Security"


def test_the_rendered_time_is_read_as_utc_because_it_carries_no_zone() -> None:
    """01:19:21 PM is 13:19:21. The zone is the indexer's and is not written down, so UTC is assumed."""
    assert parse_record(PROCESS)["TimeCreated"] == "2020-12-04T13:19:21Z"


def test_a_resolved_account_is_not_stored_as_a_sid() -> None:
    """Here "Security ID" renders as `ATTACKRANGE\\Administrator`; user.uid must hold a SID or nothing."""
    assert "TargetUserSid" not in parse_record(LOGON)["EventData"]
    assert parse_record(LOGON)["EventData"]["SubjectUserSid"] == "S-1-5-18", "a real SID is kept"


def test_a_process_creation_names_the_program_its_parent_and_the_command() -> None:
    data = parse_record(PROCESS)["EventData"]
    assert data["NewProcessName"] == "C:\\Windows\\System32\\whoami.exe"
    assert data["ParentProcessName"] == "C:\\Windows\\System32\\cmd.exe"
    assert data["CommandLine"] == "whoami.exe /priv"
    assert (data["NewProcessId"], data["ProcessId"]) == ("0x1bc", "0x198")
    assert "Token Elevation Type" not in data, "an unmapped label is left out, not invented into a field"


def test_dashes_mean_absent() -> None:
    assert "ProcessName" not in parse_record(LOGON)["EventData"], "Process Name renders as -"


def test_the_records_feed_the_windows_parser_unchanged() -> None:
    logon = normalize("windows_security", parse_record(LOGON))
    assert logon.user is not None
    assert logon.user.name == "Administrator"
    assert logon.src_endpoint is not None
    assert str(logon.src_endpoint.ip) == "10.0.1.15"

    process = normalize("windows_security", parse_record(PROCESS))
    assert process.process is not None
    assert process.process.name == "whoami.exe"
    assert process.process.parent_process is not None
    assert process.process.parent_process.name == "cmd.exe"


def test_a_file_of_records_is_read_in_order() -> None:
    other = "12/04/2020 01:19:22 PM\nLogName=Security\nEventCode=4672\nMessage=Special privileges assigned.\n"
    items = list(iter_records(f"{PROCESS}\n{other}\n{LOGON}"))
    assert [item["EventID"] for item in items if isinstance(item, dict)] == [4688, 4672, 4624]


def test_an_event_type_nothing_maps_is_refused_by_the_parser_not_the_reader() -> None:
    """One place decides what Sentinel-X maps: the reader hands the record over, the parser names the type."""
    record = parse_record("12/04/2020 01:19:22 PM\nLogName=Security\nEventCode=4672\nMessage=Privileges.\n")
    assert record["EventData"] == {}
    with pytest.raises(UnsupportedEventError, match="unsupported Windows Security event 4672"):
        normalize("windows_security", record)


def test_every_event_the_parser_maps_has_labels_to_read_it_from_prose() -> None:
    """Without this, a parser that learned a new event would silently get empty records from this reader."""
    assert set(_HANDLERS) <= set(LABELS)


@pytest.mark.parametrize(
    ("block", "message"),
    [
        ("LogName=Security\nEventCode=4624\n", "no rendered timestamp"),
        ("12/04/2020 01:19:21 PM\nLogName=Security\n", "no numeric EventCode"),
        ("12/04/2020 01:19:21 PM\nEventCode=x\n", "no numeric EventCode"),
    ],
)
def test_unreadable_records_are_refused_with_a_reason(block: str, message: str) -> None:
    with pytest.raises(WinEventLogTextError, match=message):
        parse_record(block)


def test_an_oversized_record_is_refused_before_it_is_parsed() -> None:
    """A file without record breaks would otherwise arrive as one enormous block."""
    with pytest.raises(WinEventLogTextError, match="exceeds 200000 characters"):
        parse_record(f"12/04/2020 01:19:21 PM\nEventCode=4688\nMessage={'x' * 200_001}")


def test_splunk_can_supply_the_time_when_the_block_starts_at_the_header() -> None:
    """A Splunk result's `_raw` may begin at `LogName=`; Splunk holds the time in `_time`."""
    headless = PROCESS.split("\n", 1)[1]
    record = parse_record(headless, default_time="2020-12-04T13:19:21Z")
    assert record["TimeCreated"] == "2020-12-04T13:19:21Z"
    assert record["EventData"]["CommandLine"] == "whoami.exe /priv"
