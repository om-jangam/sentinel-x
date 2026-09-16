"""Windows Security event log (JSON, e.g. from Winlogbeat/NXLog/WEF) → OCSF.

| Event ID | Meaning | OCSF |
|---|---|---|
| 4624 | Successful logon | Authentication · Logon · Success |
| 4625 | Failed logon | Authentication · Logon · Failure |
| 4634, 4647 | Logoff | Authentication · Logoff |
| 4688 | Process creation | Process Activity · Launch |
"""

from __future__ import annotations

import json
from pathlib import PureWindowsPath
from typing import Any

from app.ingest_pipeline.ocsf import MAX_RAW_DATA_CHARS, OCSF_VERSION, EventClass, Severity, Status
from app.ingest_pipeline.parsers.base import ParseError, Record, as_int, as_ip, clean

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
    src_endpoint = {
        k: v
        for k, v in {
            "ip": as_ip(data.get("IpAddress")),
            "port": as_int(data.get("IpPort")) or None,
            "hostname": clean(data.get("WorkstationName")),
        }.items()
        if v is not None
    }
    event.update(
        class_uid=int(EventClass.AUTHENTICATION),
        activity_id=1,
        status_id=int(Status.SUCCESS if success else Status.FAILURE),
        severity_id=int(Severity.INFORMATIONAL if success else Severity.LOW),
        message="An account was successfully logged on." if success else "An account failed to log on.",
        user=_user(data, "Target"),
        src_endpoint=src_endpoint or None,
        dst_endpoint={"hostname": event["device"]["hostname"]} if event["device"] else None,
        auth_protocol=clean(data.get("AuthenticationPackageName")),
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


_HANDLERS = {4624: _logon, 4625: _logon, 4634: _logoff, 4647: _logoff, 4688: _process_creation}


def parse(record: Record) -> dict[str, Any]:
    event_id = as_int(record.get("EventID"))
    if event_id is None:
        raise ParseError("record has no numeric EventID")
    handler = _HANDLERS.get(event_id)
    if handler is None:
        raise ParseError(f"unsupported Windows Security event {event_id}")
    data = record.get("EventData")
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ParseError("EventData must be an object")
    return {k: v for k, v in handler(record, data, event_id).items() if v is not None}
