"""Windows Sysmon (Microsoft-Windows-Sysmon/Operational) JSON → OCSF.

Records have the same shape as the Windows Security parser's: `EventID`, `Computer`, `TimeCreated`
(or Sysmon's own `UtcTime`) and the event's fields in `EventData`, as Winlogbeat, NXLog or WEF forward
them.

| Event ID | Sysmon | OCSF |
|---|---|---|
| 1 | Process creation | Process Activity · Launch |
| 3 | Network connection | Network Activity · Open |
| 5 | Process terminated | Process Activity · Terminate |
| 7 | Image loaded | Module Activity · Load |
| 8 | CreateRemoteThread | Process Activity · Inject |
| 10 | ProcessAccess | Process Activity · Open |
| 11 | FileCreate | File System Activity · Create |
| 12 | Registry key or value created / deleted | Registry Key · Create/Delete, Registry Value · Delete |
| 13 | Registry value set | Registry Value Activity · Set |
| 14 | Registry key or value renamed | Registry Key Activity · Rename |
| 22 | DNS query | DNS Activity · Query |
| 23, 26 | File deleted | File System Activity · Delete |

Sysmon fields that OCSF has no attribute for are kept under `unmapped` (all strings, as Sysmon wrote them):
`original_file_name`, `hashes`, `user`, `initiated`, `granted_access`, `call_trace`, `signed`,
`signature`, `signature_status`, `query_status`, `event_type`, `start_module`, `rule_name`. Sigma rules
match these as written, for example `Hashes|contains: 'IMPHASH=…'` or `GrantedAccess: '0x1010'`.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import PureWindowsPath
from typing import Any

from app.ingest_pipeline.ocsf import MAX_RAW_DATA_CHARS, OCSF_VERSION, EventClass, HashAlgorithm, Severity, Status
from app.ingest_pipeline.parsers.base import ParseError, Record, UnsupportedEventError, as_int, as_ip, clean

LOG_NAME = "Microsoft-Windows-Sysmon/Operational"

_HASH_ALGORITHMS = {
    "MD5": HashAlgorithm.MD5,
    "SHA1": HashAlgorithm.SHA1,
    "SHA256": HashAlgorithm.SHA256,
    "IMPHASH": HashAlgorithm.OTHER,
}

Event = dict[str, Any]


def _drop_none(mapping: dict[str, Any]) -> dict[str, Any] | None:
    kept = {k: v for k, v in mapping.items() if v is not None and v != {}}
    return kept or None


def _user(value: Any) -> dict[str, Any] | None:
    """Sysmon writes `DOMAIN\\name`."""
    text = clean(value)
    if not isinstance(text, str):
        return None
    domain, sep, name = text.rpartition("\\")
    return {"name": name, "domain": domain} if sep and domain else {"name": text}


def _hashes(value: Any) -> list[dict[str, Any]] | None:
    """`SHA1=…,MD5=…,SHA256=…,IMPHASH=…`; malformed or unknown entries are skipped, not guessed."""
    text = clean(value)
    if not isinstance(text, str):
        return None
    found = []
    for part in text.split(","):
        algorithm, sep, digest = part.strip().partition("=")
        algorithm_id = _HASH_ALGORITHMS.get(algorithm.strip().upper())
        digest = digest.strip()
        if not sep or algorithm_id is None or not digest:
            continue
        if algorithm_id is not HashAlgorithm.OTHER and not _is_hex(digest):
            continue
        found.append({"algorithm_id": int(algorithm_id), "algorithm": algorithm.strip().upper(), "value": digest})
    return found or None


def _is_hex(text: str) -> bool:
    try:
        int(text, 16)
    except ValueError:
        return False
    return True


def _file(path: Any, data: Record | None = None) -> dict[str, Any] | None:
    text = clean(path)
    if not isinstance(text, str):
        return None
    file: dict[str, Any] = {"path": text, "name": PureWindowsPath(text).name}
    if data is not None:
        file.update(
            hashes=_hashes(data.get("Hashes")),
            company_name=clean(data.get("Company")),
            desc=clean(data.get("Description")),
            product=_drop_none({"name": clean(data.get("Product"))}),
            version=clean(data.get("FileVersion")),
        )
    return _drop_none(file)


def _process(image: Any, *, pid: Any = None, guid: Any = None, data: Record | None = None) -> dict[str, Any] | None:
    file = _file(image, data)
    if file is None:
        return None
    return _drop_none({"name": file["name"], "file": file, "pid": as_int(pid), "uid": clean(guid)})


def _base(record: Record, data: Record, event_id: int) -> Event:
    time = record.get("TimeCreated") or record.get("@timestamp") or record.get("timestamp") or data.get("UtcTime")
    if time is None:
        raise ParseError("Sysmon event has no TimeCreated or UtcTime")
    computer = clean(record.get("Computer"))
    metadata: dict[str, Any] = {
        "version": OCSF_VERSION,
        "product": {"name": "Sysmon", "vendor_name": "Microsoft"},
        "log_name": LOG_NAME,
    }
    if (record_id := record.get("EventRecordID")) is not None:
        metadata["uid"] = str(record_id)
    unmapped = {"event_id": event_id, "rule_name": clean(data.get("RuleName"))}
    return {
        "time": time,
        "metadata": metadata,
        "device": {"hostname": computer} if computer else None,
        "severity_id": int(Severity.INFORMATIONAL),
        "raw_data": json.dumps(record, default=str, separators=(",", ":"))[:MAX_RAW_DATA_CHARS],
        "unmapped": unmapped,
    }


def _actor(data: Record) -> dict[str, Any] | None:
    """The process that acted: every Sysmon event except 1 names it `Image`."""
    return _drop_none(
        {
            "process": _process(data.get("Image"), pid=data.get("ProcessId"), guid=data.get("ProcessGuid")),
            "user": _user(data.get("User")),
        }
    )


def _process_create(event: Event, data: Record) -> None:
    process = _process(data.get("Image"), pid=data.get("ProcessId"), guid=data.get("ProcessGuid"), data=data)
    if process is None:
        raise ParseError("Sysmon event 1 has no Image")
    process.update(
        _drop_none(
            {
                "cmd_line": clean(data.get("CommandLine")),
                "user": _user(data.get("User")),
                "integrity": clean(data.get("IntegrityLevel")),
                "working_directory": clean(data.get("CurrentDirectory")),
            }
        )
        or {}
    )
    parent = _process(data.get("ParentImage"), pid=data.get("ParentProcessId"), guid=data.get("ParentProcessGuid"))
    if parent is not None:
        parent.update(
            _drop_none({"cmd_line": clean(data.get("ParentCommandLine")), "user": _user(data.get("ParentUser"))}) or {}
        )
        process["parent_process"] = parent
    event.update(
        class_uid=int(EventClass.PROCESS_ACTIVITY),
        activity_id=1,
        status_id=int(Status.SUCCESS),
        message="Process created.",
        process=process,
        # The parent is recorded once, as process.parent_process. Repeating it as actor.process would let a
        # Sysmon rule on `Image` match the parent's path.
        actor=_drop_none({"user": _user(data.get("ParentUser"))}),
    )
    event["unmapped"].update(
        original_file_name=clean(data.get("OriginalFileName")),
        hashes=clean(data.get("Hashes")),
        user=clean(data.get("User")),
        logon_id=clean(data.get("LogonId")),
    )


def _process_terminate(event: Event, data: Record) -> None:
    process = _process(data.get("Image"), pid=data.get("ProcessId"), guid=data.get("ProcessGuid"))
    if process is None:
        raise ParseError("Sysmon event 5 has no Image")
    if (user := _user(data.get("User"))) is not None:
        process["user"] = user
    event.update(
        class_uid=int(EventClass.PROCESS_ACTIVITY),
        activity_id=2,
        status_id=int(Status.SUCCESS),
        message="Process terminated.",
        process=process,
    )
    event["unmapped"]["user"] = clean(data.get("User"))


def _network(event: Event, data: Record) -> None:
    initiated = str(clean(data.get("Initiated")) or "").lower()
    src = _drop_none(
        {
            "ip": as_ip(data.get("SourceIp")),
            "port": as_int(data.get("SourcePort")),
            "hostname": clean(data.get("SourceHostname")),
        }
    )
    dst = _drop_none(
        {
            "ip": as_ip(data.get("DestinationIp")),
            "port": as_int(data.get("DestinationPort")),
            "hostname": clean(data.get("DestinationHostname")),
        }
    )
    if src is None and dst is None:
        raise ParseError("Sysmon event 3 has no source or destination")
    protocol = clean(data.get("Protocol"))
    event.update(
        class_uid=int(EventClass.NETWORK_ACTIVITY),
        activity_id=1,
        status_id=int(Status.SUCCESS),
        message="Network connection detected.",
        src_endpoint=src,
        dst_endpoint=dst,
        # OCSF direction_id: 1 inbound, 2 outbound. Sysmon's Initiated is true when this host connected out.
        connection_info=_drop_none(
            {
                "protocol_name": protocol.lower() if isinstance(protocol, str) else None,
                "direction_id": {"true": 2, "false": 1}.get(initiated),
            }
        ),
        actor=_actor(data),
    )
    event["unmapped"].update(initiated=clean(data.get("Initiated")), user=clean(data.get("User")))


def _image_load(event: Event, data: Record) -> None:
    module_file = _file(data.get("ImageLoaded"), data)
    if module_file is None:
        raise ParseError("Sysmon event 7 has no ImageLoaded")
    event.update(
        class_uid=int(EventClass.MODULE_ACTIVITY),
        activity_id=1,
        status_id=int(Status.SUCCESS),
        message="Image loaded.",
        module={"file": module_file},
        actor=_actor(data),
    )
    event["unmapped"].update(
        original_file_name=clean(data.get("OriginalFileName")),
        hashes=clean(data.get("Hashes")),
        signed=clean(data.get("Signed")),
        signature=clean(data.get("Signature")),
        signature_status=clean(data.get("SignatureStatus")),
        user=clean(data.get("User")),
    )


def _cross_process(event: Event, data: Record, *, activity_id: int, message: str) -> None:
    target = _process(
        data.get("TargetImage"),
        pid=data.get("TargetProcessId"),
        guid=data.get("TargetProcessGuid") or data.get("TargetProcessGUID"),
    )
    if target is None:
        raise ParseError(f"Sysmon event {event['unmapped']['event_id']} has no TargetImage")
    if (target_user := _user(data.get("TargetUser"))) is not None:
        target["user"] = target_user
    source_user = _user(data.get("SourceUser"))
    event.update(
        class_uid=int(EventClass.PROCESS_ACTIVITY),
        activity_id=activity_id,
        status_id=int(Status.SUCCESS),
        message=message,
        process=target,
        actor=_drop_none(
            {
                "process": _process(
                    data.get("SourceImage"),
                    pid=data.get("SourceProcessId"),
                    guid=data.get("SourceProcessGuid") or data.get("SourceProcessGUID"),
                ),
                "user": source_user,
            }
        ),
    )


def _create_remote_thread(event: Event, data: Record) -> None:
    _cross_process(event, data, activity_id=4, message="A thread was created in another process.")
    event.update(
        injection_type="Remote Thread",
        module=_drop_none(
            {
                "file": _file(data.get("StartModule")),
                "function_name": clean(data.get("StartFunction")),
                "start_address": clean(data.get("StartAddress")),
            }
        ),
    )
    event["unmapped"]["start_module"] = clean(data.get("StartModule"))


def _process_access(event: Event, data: Record) -> None:
    _cross_process(event, data, activity_id=3, message="A process opened another process.")
    access = clean(data.get("GrantedAccess"))
    if isinstance(access, str) and access.lower().startswith("0x"):
        event["actual_permissions"] = as_int(access[2:], base=16)
    event["unmapped"].update(granted_access=access, call_trace=clean(data.get("CallTrace")))


def _file_event(event: Event, data: Record, *, activity_id: int, message: str) -> None:
    file = _file(data.get("TargetFilename"))
    if file is None:
        raise ParseError(f"Sysmon event {event['unmapped']['event_id']} has no TargetFilename")
    if (hashes := _hashes(data.get("Hashes"))) is not None:
        file["hashes"] = hashes
    event.update(
        class_uid=int(EventClass.FILE_SYSTEM_ACTIVITY),
        activity_id=activity_id,
        status_id=int(Status.SUCCESS),
        message=message,
        file=file,
        actor=_actor(data),
    )
    event["unmapped"].update(hashes=clean(data.get("Hashes")), user=clean(data.get("User")))


def _registry(event: Event, data: Record) -> None:
    event_type = clean(data.get("EventType"))
    target = clean(data.get("TargetObject"))
    if not isinstance(target, str):
        raise ParseError(f"Sysmon event {event['unmapped']['event_id']} has no TargetObject")
    value_name = target.rpartition("\\")[2]
    event.update(status_id=int(Status.SUCCESS), actor=_actor(data))
    event["unmapped"].update(event_type=event_type, user=clean(data.get("User")))
    match event_type:
        case "CreateKey":
            event.update(class_uid=int(EventClass.REGISTRY_KEY_ACTIVITY), activity_id=1, reg_key={"path": target})
            event["message"] = "Registry key created."
        case "DeleteKey":
            event.update(class_uid=int(EventClass.REGISTRY_KEY_ACTIVITY), activity_id=4, reg_key={"path": target})
            event["message"] = "Registry key deleted."
        case "DeleteValue":
            event.update(
                class_uid=int(EventClass.REGISTRY_VALUE_ACTIVITY),
                activity_id=4,
                reg_value={"path": target, "name": value_name or None},
            )
            event["message"] = "Registry value deleted."
        case "SetValue":
            event.update(
                class_uid=int(EventClass.REGISTRY_VALUE_ACTIVITY),
                activity_id=2,
                reg_value=_drop_none({"path": target, "name": value_name or None, "data": clean(data.get("Details"))}),
            )
            event["message"] = "Registry value set."
        case "RenameKey" | "RenameValue":
            new_name = clean(data.get("NewName"))
            event.update(
                class_uid=int(EventClass.REGISTRY_KEY_ACTIVITY),
                activity_id=5,
                reg_key={"path": new_name if isinstance(new_name, str) else target},
                prev_reg_key={"path": target},
            )
            event["message"] = "Registry object renamed."
        case _:
            raise ParseError(f"unsupported Sysmon registry EventType {event_type!r}")


def _dns(event: Event, data: Record) -> None:
    name = clean(data.get("QueryName"))
    if not isinstance(name, str):
        raise ParseError("Sysmon event 22 has no QueryName")
    results = clean(data.get("QueryResults"))
    answers = []
    # `type:  5 cdn.example.com;::ffff:192.0.2.10;` — keep addresses; CNAME entries carry a type prefix.
    for part in (results or "").split(";") if isinstance(results, str) else []:
        part = part.strip()
        if not part or part.startswith("type:"):
            continue
        address = as_ip(part.removeprefix("::ffff:"))
        answers.append({"rdata": address or part})
    status = as_int(data.get("QueryStatus"))
    event.update(
        class_uid=int(EventClass.DNS_ACTIVITY),
        activity_id=1,
        status_id=int(Status.SUCCESS if status in (0, None) else Status.FAILURE),
        message="DNS query.",
        query={"hostname": name},
        answers=answers[:50] or None,
        actor=_actor(data),
    )
    event["unmapped"].update(query_status=clean(data.get("QueryStatus")), user=clean(data.get("User")))


_HANDLERS: dict[int, Callable[[Event, Record], None]] = {
    1: _process_create,
    3: _network,
    5: _process_terminate,
    7: _image_load,
    8: _create_remote_thread,
    10: _process_access,
    11: lambda event, data: _file_event(event, data, activity_id=1, message="File created."),
    12: _registry,
    13: _registry,
    14: _registry,
    22: _dns,
    23: lambda event, data: _file_event(event, data, activity_id=4, message="File deleted."),
    26: lambda event, data: _file_event(event, data, activity_id=4, message="File deleted."),
}


def parse(record: Record) -> dict[str, Any]:
    event_id = as_int(record.get("EventID"))
    if event_id is None:
        raise ParseError("record has no numeric EventID")
    handler = _HANDLERS.get(event_id)
    if handler is None:
        raise UnsupportedEventError(f"unsupported Sysmon event {event_id}")
    data = record.get("EventData")
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ParseError("EventData must be an object")
    event = _base(record, data, event_id)
    handler(event, data)
    event["unmapped"] = {k: v for k, v in event["unmapped"].items() if v is not None}
    return {k: v for k, v in event.items() if v is not None}
