"""Windows NTLM auditing (Microsoft-Windows-NTLM/Operational) → OCSF.

A domain controller writes event 8004 for each NTLM authentication routed to it, naming the account and
the workstation it came from. Records have the same shape as the other Windows parsers': `EventID`,
`TimeCreated`, `Computer` and `EventData`.

**The record does not say whether the authentication succeeded**, so the event is mapped with status
`Unknown` rather than being guessed either way. What it does show is who was tried, and from where, which
is enough to see one workstation working through a list of accounts.

| EventID | Meaning | OCSF |
|---|---|---|
| 8004 | NTLM authentication audited by the domain controller | Authentication · Logon · Unknown |

Splunk and Windows render an absent value here as the literal `NULL` (and sometimes `-`); both are read
as absent. A workstation genuinely named `NULL` would be lost, which is the trade for not inventing a
source for every anonymous attempt.
"""

from __future__ import annotations

import json
from typing import Any

from app.ingest_pipeline.ocsf import MAX_RAW_DATA_CHARS, OCSF_VERSION, EventClass, Severity, Status
from app.ingest_pipeline.parsers.base import ParseError, Record, UnsupportedEventError, as_int, clean

LOG_NAME = "Microsoft-Windows-NTLM/Operational"
AUDIT_EVENT = 8004
_ABSENT = {"null", "-", ""}


def _value(raw: Any) -> str | None:
    text = clean(raw)
    if not isinstance(text, str) or text.strip().lower() in _ABSENT:
        return None
    return text


def parse(record: Record) -> dict[str, Any]:
    event_id = as_int(record.get("EventID"))
    if event_id is None:
        raise ParseError("record has no numeric EventID")
    if event_id != AUDIT_EVENT:
        raise UnsupportedEventError(f"unsupported Windows NTLM event {event_id}")
    data = record.get("EventData")
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ParseError("EventData must be an object")

    user_name = _value(data.get("UserName"))
    if user_name is None:
        raise ParseError("NTLM event 8004 has no UserName")
    time = record.get("TimeCreated") or record.get("@timestamp") or record.get("timestamp")
    if time is None:
        raise ParseError("NTLM event has no TimeCreated")

    computer = _value(record.get("Computer"))
    workstation = _value(data.get("WorkstationName"))
    user: dict[str, Any] = {"name": user_name}
    if (domain := _value(data.get("DomainName"))) is not None:
        user["domain"] = domain

    event: dict[str, Any] = {
        "class_uid": int(EventClass.AUTHENTICATION),
        "activity_id": 1,
        # The audit record states that NTLM was used, not whether it worked.
        "status_id": int(Status.UNKNOWN),
        "severity_id": int(Severity.INFORMATIONAL),
        "time": time,
        "message": "NTLM authentication was audited by the domain controller.",
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "Microsoft Windows", "vendor_name": "Microsoft"},
            "log_name": LOG_NAME,
        },
        "user": user,
        "auth_protocol": "NTLM",
        "raw_data": json.dumps(record, default=str, separators=(",", ":"))[:MAX_RAW_DATA_CHARS],
        "unmapped": {
            "event_id": event_id,
            "secure_channel_name": _value(data.get("SChannelName")),
            "secure_channel_type": _value(data.get("SChannelType")),
        },
    }
    if (record_id := record.get("EventRecordID")) is not None:
        event["metadata"]["uid"] = str(record_id)
    if computer is not None:
        event["device"] = {"hostname": computer}
        event["dst_endpoint"] = {"hostname": computer}
    if workstation is not None:
        event["src_endpoint"] = {"hostname": workstation}
    event["unmapped"] = {k: v for k, v in event["unmapped"].items() if v is not None}
    return event
