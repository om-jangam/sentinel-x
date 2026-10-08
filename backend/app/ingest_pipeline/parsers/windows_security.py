"""Windows Security event log (JSON, e.g. from Winlogbeat/NXLog/WEF) → OCSF.

| Event ID | Meaning | OCSF |
|---|---|---|
| Event ID | Meaning | OCSF |
|---|---|---|
| 4624 | Successful logon | Authentication · Logon · Success |
| 4625 | Failed logon | Authentication · Logon · Failure |
| 4634, 4647 | Logoff | Authentication · Logoff |
| 4648 | Logon with explicitly supplied credentials | Authentication · Account Switch · Unknown |
| 4672 | Special privileges assigned to a logon | Authorize Session · Assign Privileges |
| 4688 | Process creation | Process Activity · Launch |
| 4768 | Kerberos TGT requested | Authentication · Authentication Ticket |
| 4769 | Kerberos service ticket requested | Authentication · Service Ticket Request |
| 4771 | Kerberos pre-authentication failed | Authentication · Preauth · Failure |
| 4776 | NTLM credential validation | Authentication · Logon |

Two outcomes are deliberately `Unknown`. 4648 says a logon was *attempted* with another account's
credentials; it is written whether or not that logon then worked, so claiming success would invent
evidence. 4672 states what privileges a session was given, not whether anything was done with them.
"""

from __future__ import annotations

import json
from pathlib import PureWindowsPath
from typing import Any

from app.ingest_pipeline.ocsf import (
    MAX_RAW_DATA_CHARS,
    OCSF_VERSION,
    AuthProtocol,
    EventClass,
    Severity,
    Status,
)
from app.ingest_pipeline.parsers.base import ParseError, Record, UnsupportedEventError, as_int, as_ip, clean

# The Windows authentication packages that are NTLM, as Windows names them.
NTLM_PACKAGES = frozenset({"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0", "NTLM", "NtLmSsp"})

LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}


def _user(data: Record, prefix: str) -> dict[str, Any] | None:
    user = {
        "name": clean(data.get(f"{prefix}UserName")),
        "domain": clean(data.get(f"{prefix}DomainName")),
        "uid": clean(data.get(f"{prefix}UserSid")),
    }
    user = {k: v for k, v in user.items() if v is not None}
    return user or None


def _source(data: Record) -> dict[str, Any]:
    """Where the attempt came from, as the record states it."""
    return {
        k: v
        for k, v in {
            "ip": as_ip(data.get("IpAddress")),
            "port": as_int(data.get("IpPort")) or None,
            "hostname": clean(data.get("WorkstationName")),
        }.items()
        if v is not None
    }


def _protocol_id(package: Any) -> int | None:
    """The protocol Windows named, as the OCSF id — only where the package *is* that protocol."""
    if package in NTLM_PACKAGES:
        return int(AuthProtocol.NTLM)
    if package == "Kerberos":
        return int(AuthProtocol.KERBEROS)
    return None  # "Negotiate" picked one of them and does not say which


def _service(data: Record) -> dict[str, Any] | None:
    service = {"name": clean(data.get("ServiceName")), "uid": clean(data.get("ServiceSid"))}
    service = {k: v for k, v in service.items() if v is not None}
    return service or None


def _image(path: Any) -> dict[str, Any] | None:
    text = clean(path)
    if not isinstance(text, str):
        return None
    return {"name": PureWindowsPath(text).name, "file": {"path": text, "name": PureWindowsPath(text).name}}


def _base(record: Record, event_id: int) -> dict[str, Any]:
    time = record.get("TimeCreated") or record.get("@timestamp") or record.get("timestamp")
    if time is None:
        raise ParseError("Windows event has no TimeCreated")
    computer = clean(record.get("Computer"))
    metadata: dict[str, Any] = {
        "version": OCSF_VERSION,
        "product": {"name": "Microsoft Windows", "vendor_name": "Microsoft"},
        "log_name": "Security",
    }
    if (record_id := record.get("EventRecordID")) is not None:
        metadata["uid"] = str(record_id)
    return {
        "time": time,
        "metadata": metadata,
        "device": {"hostname": computer} if computer else None,
        "raw_data": json.dumps(record, default=str, separators=(",", ":"))[:MAX_RAW_DATA_CHARS],
        "unmapped": {"event_id": event_id},
    }


def _logon(record: Record, data: Record, event_id: int) -> dict[str, Any]:
    success = event_id == 4624
    event = _base(record, event_id)
    logon_type_id = as_int(data.get("LogonType"))
    package = clean(data.get("AuthenticationPackageName"))
    event.update(
        class_uid=int(EventClass.AUTHENTICATION),
        activity_id=1,
        status_id=int(Status.SUCCESS if success else Status.FAILURE),
        severity_id=int(Severity.INFORMATIONAL if success else Severity.LOW),
        message="An account was successfully logged on." if success else "An account failed to log on.",
        user=_user(data, "Target"),
        src_endpoint=_source(data) or None,
        dst_endpoint={"hostname": event["device"]["hostname"]} if event["device"] else None,
        auth_protocol=package,
        auth_protocol_id=_protocol_id(package),
        logon_type_id=logon_type_id,
        logon_type=LOGON_TYPES.get(logon_type_id) if logon_type_id is not None else None,
    )
    if (process := _image(data.get("ProcessName"))) is not None:
        event["actor"] = {"process": process}
    if not success:
        event["unmapped"].update(
            failure_reason=clean(data.get("FailureReason")),
            status=clean(data.get("Status")),
            sub_status=clean(data.get("SubStatus")),
        )
    return event


def _logoff(record: Record, data: Record, event_id: int) -> dict[str, Any]:
    event = _base(record, event_id)
    logon_type_id = as_int(data.get("LogonType"))
    event.update(
        class_uid=int(EventClass.AUTHENTICATION),
        activity_id=2,
        status_id=int(Status.SUCCESS),
        severity_id=int(Severity.INFORMATIONAL),
        message="An account was logged off.",
        user=_user(data, "Target"),
        logon_type_id=logon_type_id,
        logon_type=LOGON_TYPES.get(logon_type_id) if logon_type_id is not None else None,
    )
    return event


def _explicit_credentials(record: Record, data: Record, event_id: int) -> dict[str, Any]:
    """4648: someone ran something as another account (`runas`, PsExec, a scheduled task)."""
    event = _base(record, event_id)
    event.update(
        class_uid=int(EventClass.AUTHENTICATION),
        activity_id=7,  # Account Switch
        # Windows writes 4648 for the attempt, before and regardless of its outcome.
        status_id=int(Status.UNKNOWN),
        severity_id=int(Severity.INFORMATIONAL),
        message="A logon was attempted using explicit credentials.",
        user=_user(data, "Target"),
        src_endpoint=_source(data) or None,
        dst_endpoint={"hostname": server} if (server := clean(data.get("TargetServerName"))) else None,
    )
    actor: dict[str, Any] = {}
    if (subject := _user(data, "Subject")) is not None:
        actor["user"] = subject
    if (process := _image(data.get("ProcessName"))) is not None:
        process["pid"] = as_int(data.get("ProcessId"), base=16)
        actor["process"] = process
    event["actor"] = actor or None
    return event


def _special_privileges(record: Record, data: Record, event_id: int) -> dict[str, Any]:
    """4672: the privileges a session was granted — what an account could do, not what it did."""
    event = _base(record, event_id)
    user = _user(data, "Subject")
    if user is None:
        raise ParseError("4672 event names no account")
    privileges = [line.strip() for line in str(clean(data.get("PrivilegeList")) or "").splitlines() if line.strip()]
    event.update(
        class_uid=int(EventClass.AUTHORIZE_SESSION),
        activity_id=1,  # Assign Privileges
        status_id=int(Status.UNKNOWN),
        severity_id=int(Severity.INFORMATIONAL),
        message="Special privileges assigned to new logon.",
        user=user,
        privileges=privileges[:64] or None,
    )
    return event


KERBEROS_ACTIVITY = {4768: 3, 4769: 4, 4771: 6}  # Authentication Ticket, Service Ticket Request, Preauth
KERBEROS_MESSAGE = {
    4768: "A Kerberos authentication ticket (TGT) was requested.",
    4769: "A Kerberos service ticket was requested.",
    4771: "Kerberos pre-authentication failed.",
}


def _kerberos(record: Record, data: Record, event_id: int) -> dict[str, Any]:
    """4768/4769/4771: what the domain controller was asked for, by whom, from where.

    The result code is stated, so the outcome is read from it rather than assumed: `0x0` is a success and
    anything else is a failure, with the code itself kept so the reason survives.
    """
    event = _base(record, event_id)
    status = clean(data.get("Status"))
    success = event_id != 4771 and str(status or "0x0").lower() in ("0x0", "0x00000000", "0")
    event.update(
        class_uid=int(EventClass.AUTHENTICATION),
        activity_id=KERBEROS_ACTIVITY[event_id],
        status_id=int(Status.SUCCESS if success else Status.FAILURE),
        severity_id=int(Severity.INFORMATIONAL if success else Severity.LOW),
        message=KERBEROS_MESSAGE[event_id],
        user=_user(data, "Target"),
        src_endpoint=_source(data) or None,
        dst_endpoint={"hostname": event["device"]["hostname"]} if event["device"] else None,
        auth_protocol="Kerberos",
        auth_protocol_id=int(AuthProtocol.KERBEROS),
        service=_service(data),
    )
    event["unmapped"].update(
        status=status,
        ticket_options=clean(data.get("TicketOptions")),
        ticket_encryption_type=clean(data.get("TicketEncryptionType")),
        pre_auth_type=clean(data.get("PreAuthType")),
        transmitted_services=clean(data.get("TransmittedServices")),
    )
    return event


def _credential_validation(record: Record, data: Record, event_id: int) -> dict[str, Any]:
    """4776: a domain controller checked an account's password, and says whether it matched."""
    event = _base(record, event_id)
    user = clean(data.get("TargetUserName"))
    if user is None:
        raise ParseError("4776 event names no account")
    status = clean(data.get("Status"))
    success = str(status or "0x0").lower() in ("0x0", "0x00000000", "0")
    package = clean(data.get("PackageName"))
    event.update(
        class_uid=int(EventClass.AUTHENTICATION),
        activity_id=1,
        status_id=int(Status.SUCCESS if success else Status.FAILURE),
        severity_id=int(Severity.INFORMATIONAL if success else Severity.LOW),
        message="The computer attempted to validate the credentials for an account.",
        user={"name": user},
        src_endpoint={"hostname": station} if (station := clean(data.get("Workstation"))) else None,
        dst_endpoint={"hostname": event["device"]["hostname"]} if event["device"] else None,
        auth_protocol=package,
        # MSV1_0 is Windows' NTLM authentication package; the id lets a rule say "NTLM" once and match
        # both this event and the NTLM operational log, which spell the protocol differently.
        auth_protocol_id=int(AuthProtocol.NTLM) if package in NTLM_PACKAGES else None,
    )
    event["unmapped"]["status"] = status
    return event


def _process_creation(record: Record, data: Record, event_id: int) -> dict[str, Any]:
    event = _base(record, event_id)
    process = _image(data.get("NewProcessName"))
    if process is None:
        raise ParseError("4688 event has no NewProcessName")
    process["pid"] = as_int(data.get("NewProcessId"), base=16)
    if (cmd_line := clean(data.get("CommandLine"))) is not None:
        process["cmd_line"] = cmd_line
    if (parent := _image(data.get("ParentProcessName"))) is not None:
        parent["pid"] = as_int(data.get("ProcessId"), base=16)
        process["parent_process"] = parent
    event.update(
        class_uid=int(EventClass.PROCESS_ACTIVITY),
        activity_id=1,
        status_id=int(Status.SUCCESS),
        severity_id=int(Severity.INFORMATIONAL),
        message="A new process has been created.",
        process=process,
        actor={"user": _user(data, "Subject")},
    )
    return event


_HANDLERS = {
    4624: _logon,
    4625: _logon,
    4634: _logoff,
    4647: _logoff,
    4648: _explicit_credentials,
    4672: _special_privileges,
    4688: _process_creation,
    4768: _kerberos,
    4769: _kerberos,
    4771: _kerberos,
    4776: _credential_validation,
}


def parse(record: Record) -> dict[str, Any]:
    event_id = as_int(record.get("EventID"))
    if event_id is None:
        raise ParseError("record has no numeric EventID")
    handler = _HANDLERS.get(event_id)
    if handler is None:
        raise UnsupportedEventError(f"unsupported Windows Security event {event_id}")
    data = record.get("EventData")
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ParseError("EventData must be an object")
    return {k: v for k, v in handler(record, data, event_id).items() if v is not None}
