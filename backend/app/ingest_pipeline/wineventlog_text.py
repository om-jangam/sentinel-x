"""Splunk's rendered `WinEventLog` text → the records the Windows parsers read.

Splunk's older Windows input stores each event as a header of `key=value` lines followed by the message
Windows renders for a person:

```
12/04/2020 01:19:21 PM
LogName=Security
EventCode=4688
ComputerName=EC2AMAZ-O5EOQ54
RecordNumber=231333
Message=A new process has been created.

Creator Subject:
    Account Name:       -
Process Information:
    New Process Name:   C:\\Windows\\System32\\autochk.exe
    Creator Process Name:   C:\\Windows\\System32\\smss.exe
```

[ADR-0021](../../../docs/adr/ADR-0021-splunk-as-a-pull-source.md) refused to read this, because prose is
not a record. What makes it readable without guessing is that the prose is **structured**: labelled values
sit under named sections, and the same label means different things in different sections — "Account Name"
under `Subject:` is who asked, under `New Logon:` it is who logged on. So the mapping is explicit, per
event and per section (`LABELS` below), and anything not listed is left out rather than interpreted.

Two limits an operator has to know, both reported rather than hidden:

- **English only.** Windows renders these labels in the machine's language; a German or Japanese host
  writes different words and nothing will match. Forwarding `XmlWinEventLog` avoids the whole problem.
- **The header time carries no time zone.** It is the indexer's local time, so it is read as UTC and may
  be out by the host's offset. The XML form carries a real UTC timestamp; this one does not.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

MAX_RECORD_CHARS = 200_000
# "12/04/2020 01:19:21 PM" at the start of a line begins a record.
_RECORD_START = re.compile(r"(?m)^(?=\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M\s*$)")
_HEADER = re.compile(r"(?m)^([A-Za-z][A-Za-z0-9_]*)=(.*)$")
# These four are matched against one line at a time; see `_values`.
_SECTION = re.compile(r"([A-Z][A-Za-z /()]*):\s*")
_LABELLED = re.compile(r"[ \t]+([A-Za-z][A-Za-z0-9 /()\-.]*?):[ \t]+(.*?)\s*")
# 4672 and 4776 put labelled values hard against the left margin: "Logon Account:\tAdministrator".
_UNINDENTED = re.compile(r"([A-Z][A-Za-z0-9 /()\-.]*?):[ \t]+(\S.*?)\s*")
# A list value continues on the following indented lines, which carry no label of their own:
#     Privileges:		SeAssignPrimaryTokenPrivilege
#     			SeAuditPrivilege
_CONTINUATION = re.compile(r"[ \t]+([A-Za-z][A-Za-z0-9_]*)\s*")
_TIME = re.compile(r"^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M)\s*$", re.MULTILINE)
# The rendering resolves a SID to an account where it can, so "Security ID" is sometimes
# `NT AUTHORITY\SYSTEM` and sometimes `S-1-5-18`. A SID field only takes an actual SID.
_SID = re.compile(r"^S-1-[0-9]+(-[0-9]+)*$")

# (section or None for "any section", rendered label) → the field name the Windows parsers read.
# A label is only left unqualified where it means one thing in the whole message.
LABELS: dict[int, tuple[tuple[str | None, str, str], ...]] = {
    4624: (
        ("Subject", "Security ID", "SubjectUserSid"),
        ("Subject", "Account Name", "SubjectUserName"),
        ("Subject", "Account Domain", "SubjectDomainName"),
        ("New Logon", "Account Name", "TargetUserName"),
        ("New Logon", "Account Domain", "TargetDomainName"),
        ("New Logon", "Security ID", "TargetUserSid"),
        (None, "Logon Type", "LogonType"),
        (None, "Workstation Name", "WorkstationName"),
        (None, "Source Network Address", "IpAddress"),
        (None, "Source Port", "IpPort"),
        (None, "Authentication Package", "AuthenticationPackageName"),
        ("Process Information", "Process Name", "ProcessName"),
    ),
    4625: (
        ("Subject", "Security ID", "SubjectUserSid"),
        ("Subject", "Account Name", "SubjectUserName"),
        ("Subject", "Account Domain", "SubjectDomainName"),
        ("Account For Which Logon Failed", "Account Name", "TargetUserName"),
        ("Account For Which Logon Failed", "Account Domain", "TargetDomainName"),
        ("Account For Which Logon Failed", "Security ID", "TargetUserSid"),
        (None, "Logon Type", "LogonType"),
        (None, "Workstation Name", "WorkstationName"),
        (None, "Source Network Address", "IpAddress"),
        (None, "Source Port", "IpPort"),
        (None, "Authentication Package", "AuthenticationPackageName"),
        (None, "Failure Reason", "FailureReason"),
        ("Failure Information", "Status", "Status"),
        ("Failure Information", "Sub Status", "SubStatus"),
        ("Process Information", "Process Name", "ProcessName"),
    ),
    4634: (
        ("Subject", "Account Name", "TargetUserName"),
        ("Subject", "Account Domain", "TargetDomainName"),
        ("Subject", "Security ID", "TargetUserSid"),
        (None, "Logon Type", "LogonType"),
    ),
    4688: (
        ("Creator Subject", "Account Name", "SubjectUserName"),
        ("Creator Subject", "Account Domain", "SubjectDomainName"),
        ("Creator Subject", "Security ID", "SubjectUserSid"),
        (None, "New Process Name", "NewProcessName"),
        (None, "New Process ID", "NewProcessId"),
        (None, "Process Command Line", "CommandLine"),
        (None, "Creator Process Name", "ParentProcessName"),
        (None, "Creator Process ID", "ProcessId"),
    ),
    4648: (
        ("Subject", "Security ID", "SubjectUserSid"),
        ("Subject", "Account Name", "SubjectUserName"),
        ("Subject", "Account Domain", "SubjectDomainName"),
        ("Account Whose Credentials Were Used", "Account Name", "TargetUserName"),
        ("Account Whose Credentials Were Used", "Account Domain", "TargetDomainName"),
        (None, "Target Server Name", "TargetServerName"),
        ("Process Information", "Process Name", "ProcessName"),
        ("Process Information", "Process ID", "ProcessId"),
        ("Network Information", "Network Address", "IpAddress"),
        ("Network Information", "Port", "IpPort"),
    ),
    4672: (
        ("Subject", "Security ID", "SubjectUserSid"),
        ("Subject", "Account Name", "SubjectUserName"),
        ("Subject", "Account Domain", "SubjectDomainName"),
        (None, "Privileges", "PrivilegeList"),
    ),
    4768: (
        ("Account Information", "Account Name", "TargetUserName"),
        ("Account Information", "Supplied Realm Name", "TargetDomainName"),
        ("Service Information", "Service Name", "ServiceName"),
        ("Service Information", "Service ID", "ServiceSid"),
        (None, "Client Address", "IpAddress"),
        (None, "Client Port", "IpPort"),
        (None, "Result Code", "Status"),
        (None, "Ticket Options", "TicketOptions"),
        (None, "Ticket Encryption Type", "TicketEncryptionType"),
        (None, "Pre-Authentication Type", "PreAuthType"),
    ),
    4769: (
        ("Account Information", "Account Name", "TargetUserName"),
        ("Account Information", "Account Domain", "TargetDomainName"),
        ("Service Information", "Service Name", "ServiceName"),
        ("Service Information", "Service ID", "ServiceSid"),
        (None, "Client Address", "IpAddress"),
        (None, "Client Port", "IpPort"),
        (None, "Failure Code", "Status"),
        (None, "Ticket Options", "TicketOptions"),
        (None, "Ticket Encryption Type", "TicketEncryptionType"),
        (None, "Transited Services", "TransmittedServices"),
    ),
    4771: (
        ("Account Information", "Account Name", "TargetUserName"),
        ("Account Information", "Security ID", "TargetUserSid"),
        ("Service Information", "Service Name", "ServiceName"),
        (None, "Client Address", "IpAddress"),
        (None, "Client Port", "IpPort"),
        (None, "Failure Code", "Status"),
        (None, "Ticket Options", "TicketOptions"),
        (None, "Pre-Authentication Type", "PreAuthType"),
    ),
    # 4776 renders as four labelled lines with no sections at all.
    4776: (
        (None, "Authentication Package", "PackageName"),
        (None, "Logon Account", "TargetUserName"),
        (None, "Source Workstation", "Workstation"),
        (None, "Error Code", "Status"),
    ),
}
LABELS[4647] = LABELS[4634]


class WinEventLogTextError(ValueError):
    """One rendered record could not be read; the rest of the file still can be."""


def _values(message: str) -> tuple[dict[tuple[str, str], str], dict[str, list[str]]]:
    """Labelled values by (section, label), and by label alone so a repeated label can be spotted."""
    by_section: dict[tuple[str, str], str] = {}
    section = ""
    listed: tuple[str, str] | None = None  # the value that an indented bare line continues
    for line in message.splitlines():
        if (heading := _SECTION.fullmatch(line)) is not None:
            section, listed = heading.group(1), None
            continue
        if (labelled := _LABELLED.fullmatch(line) or _UNINDENTED.fullmatch(line)) is not None:
            label, value = labelled.group(1), labelled.group(2).strip()
            key = (section, label)
            listed = None
            if key not in by_section:
                by_section[key] = value
                listed = key
            continue
        if listed is not None and (more := _CONTINUATION.fullmatch(line)) is not None:
            # One value spread over several lines, as 4672 renders a privilege list. Joined with newlines,
            # which is how the XML form writes the same field, so the parser splits it the one way.
            by_section[listed] += "\n" + more.group(1)
            continue
        listed = None
    # Built last, so a value that grew over several lines is the one a label-only lookup sees.
    by_label: dict[str, list[str]] = {}
    for (_, label), value in by_section.items():
        by_label.setdefault(label, []).append(value)
    return by_section, by_label


def _time(rendered: str) -> str:
    """`12/04/2020 01:19:21 PM` → ISO 8601.

    The rendering carries no time zone, so this is read as UTC and can be out by the host's offset. It is
    the one thing this format loses that the XML form keeps; see the module note.
    """
    try:
        at = datetime.strptime(rendered, "%m/%d/%Y %I:%M:%S %p").replace(tzinfo=UTC)
    except ValueError as exc:  # pragma: no cover - the record regex already required this shape
        raise WinEventLogTextError(f"unreadable timestamp {rendered!r}") from exc
    return at.isoformat().replace("+00:00", "Z")


def parse_record(block: str, *, default_time: str | None = None) -> dict[str, Any]:
    """One rendered event to the record shape `windows_security` reads.

    `default_time` is used only when the block carries no rendered timestamp of its own — a Splunk result
    whose `_raw` begins at the header, where Splunk holds the time in `_time` instead.
    """
    if len(block) > MAX_RECORD_CHARS:
        raise WinEventLogTextError(f"record exceeds {MAX_RECORD_CHARS} characters")
    time_match = _TIME.search(block)
    if time_match is None and default_time is None:
        raise WinEventLogTextError("record has no rendered timestamp")

    header_end = block.find("Message=")
    header = dict(_HEADER.findall(block if header_end == -1 else block[:header_end]))
    code = header.get("EventCode") or header.get("EventID")
    if code is None or not code.strip().isdigit():
        raise WinEventLogTextError("record has no numeric EventCode")
    event_id = int(code.strip())
    # An event with no label map still becomes a record: the parser is the one place that decides which
    # Windows events Sentinel-X maps, and its refusal names the event type. The two sets are kept in step
    # by a test, so a parser that learns a new event without labels here fails the suite rather than
    # quietly producing an empty record.
    labels = LABELS.get(event_id, ())

    message = "" if header_end == -1 else block[header_end + len("Message=") :]
    by_section, by_label = _values(message)
    data: dict[str, str] = {}
    for section, label, field in labels:
        if section is not None:
            value = by_section.get((section, label))
        else:
            seen = by_label.get(label, [])
            # An unqualified label must mean one thing; if the rendering repeats it, the mapping is wrong
            # for this event and leaving the field out beats picking one at random.
            value = seen[0] if len(set(seen)) == 1 else None
        if value is None or value.strip() in ("", "-"):
            continue
        value = value.strip()
        if field.endswith("Sid") and not _SID.match(value):
            continue  # a resolved account name, not the SID this field means
        data[field] = value

    record: dict[str, Any] = {
        "EventID": event_id,
        "TimeCreated": _time(time_match.group(1)) if time_match is not None else default_time,
        "EventData": data,
    }
    if (computer := header.get("ComputerName")) is not None and computer.strip():
        record["Computer"] = computer.strip()
    if (number := header.get("RecordNumber")) is not None and number.strip():
        record["EventRecordID"] = number.strip()
    if (log := header.get("LogName")) is not None and log.strip():
        record["Channel"] = log.strip()
    return record


def iter_records(text: str) -> Iterator[dict[str, Any] | WinEventLogTextError]:
    """Every rendered event in a file, in order. A record that cannot be read yields its error."""
    for block in _RECORD_START.split(text):
        if not _TIME.search(block):
            continue  # leading whitespace or a fragment before the first record
        try:
            yield parse_record(block)
        except WinEventLogTextError as exc:
            yield exc
