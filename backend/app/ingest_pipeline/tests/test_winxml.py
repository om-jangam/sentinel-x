"""Windows event XML → parser records, and refusal of hostile XML."""

from __future__ import annotations

import pytest

from app.ingest_pipeline.parsers import normalize
from app.ingest_pipeline.winxml import WindowsXmlError, WindowsXmlEvent, iter_events, parse_event

NS = "xmlns='http://schemas.microsoft.com/win/2004/08/events/event'"


def event_xml(event_id: int, channel: str, data: dict[str, str], *, time: str = "2021-07-27T20:21:39.1386553Z") -> str:
    fields = "".join(f"<Data Name='{name}'>{value}</Data>" for name, value in data.items())
    return (
        f"<Event {NS}><System><Provider Name='x'/><EventID>{event_id}</EventID>"
        f"<TimeCreated SystemTime='{time}'/><EventRecordID>77</EventRecordID><Correlation/>"
        f"<Channel>{channel}</Channel><Computer>win-dc-128.attackrange.local</Computer></System>"
        f"<EventData>{fields}</EventData></Event>"
    )


SYSMON_1 = event_xml(
    1,
    "Microsoft-Windows-Sysmon/Operational",
    {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
        "User": r"ATTACKRANGE\Administrator",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
    },
)
SECURITY_4688 = event_xml(
    4688,
    "Security",
    {
        "SubjectUserName": "Administrator",
        "NewProcessName": r"C:\Windows\System32\whoami.exe",
        "NewProcessId": "0x1a4c",
        "CommandLine": "whoami /all",
    },
)


def test_a_sysmon_event_becomes_a_record_the_sysmon_parser_reads() -> None:
    event = parse_event(SYSMON_1)
    assert event.channel == "Microsoft-Windows-Sysmon/Operational"
    assert event.record["EventID"] == "1"
    assert event.record["Computer"] == "win-dc-128.attackrange.local"
    assert event.record["EventRecordID"] == "77"
    ocsf = normalize("windows_sysmon", event.record)
    assert ocsf.process is not None
    assert ocsf.process.name == "powershell.exe"
    assert ocsf.time.isoformat().startswith("2021-07-27T20:21:39.138655"), "7-digit Windows fractions"


def test_a_security_event_becomes_a_record_the_security_parser_reads() -> None:
    ocsf = normalize("windows_security", parse_event(SECURITY_4688).record)
    assert ocsf.process is not None
    assert ocsf.process.cmd_line == "whoami /all"


def test_one_event_per_line_or_spread_over_lines() -> None:
    text = f"{SYSMON_1}\n{SECURITY_4688.replace('><', '>\n<')}\n"
    events = list(iter_events(text))
    assert [e.channel for e in events if isinstance(e, WindowsXmlEvent)] == [
        "Microsoft-Windows-Sysmon/Operational",
        "Security",
    ]


def test_a_broken_event_is_reported_without_losing_the_rest() -> None:
    events = list(iter_events(f"<Event {NS}><System><EventID>1</System></Event>\n{SECURITY_4688}"))
    assert isinstance(events[0], WindowsXmlError)
    assert isinstance(events[1], WindowsXmlEvent)


@pytest.mark.parametrize(
    "text",
    [
        "<!DOCTYPE x [<!ENTITY a 'b'>]>" + SYSMON_1,
        SYSMON_1.replace("<System>", "<!DOCTYPE x [<!ENTITY a SYSTEM 'file:///etc/passwd'>]><System>"),
    ],
)
def test_document_type_declarations_are_refused(text: str) -> None:
    with pytest.raises(WindowsXmlError, match="declarations are not allowed"):
        list(iter_events(text))


def test_an_event_without_system_is_refused() -> None:
    with pytest.raises(WindowsXmlError, match="no System element"):
        parse_event(f"<Event {NS}><EventData/></Event>")
