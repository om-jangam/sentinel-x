"""Evidence digests: what one stored event says, reduced to the facts a timeline and a graph are built from.

A digest is a projection of an immutable event, taken when correlation links the event into an incident.
The event store stays the source of truth: every digest carries its `event_uid`, and `raw` is a capped
excerpt of the original record, not a replacement for it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.modules.correlation.domain.entities import (
    AUTHENTICATION,
    NETWORK_CLASSES,
    Document,
    EntityType,
    event_identity,
    roles,
)

MAX_MESSAGE = 512
MAX_RAW = 2048
MAX_COMMAND_LINE = 1024

PROCESS_ACTIVITY, NETWORK_ACTIVITY, HTTP_ACTIVITY, DNS_ACTIVITY, FILE_ACTIVITY = 1007, 4001, 4002, 4003, 1001

# Which role an entity plays, by the field it came from. Anything not listed keeps its entity type as role.
_FIELD_ROLES = {
    "src_endpoint.ip": "src_ip",
    "dst_endpoint.ip": "dst_ip",
    "device.ip": "host_ip",
    "answers.rdata": "answer",
    "process.name": "process",
    "process.parent_process.name": "parent_process",
    "actor.process.name": "actor_process",
}


@dataclass(frozen=True, slots=True)
class EvidenceEvent:
    event_uid: str
    time: datetime
    class_uid: int
    activity_id: int | None
    status_id: int | None
    action: str
    outcome: str | None
    message: str | None = None
    raw: str | None = None
    roles: dict[str, list[str]] = field(default_factory=dict)  # role → entity keys, in first-seen order
    detail: dict[str, Any] = field(default_factory=dict)

    def role(self, name: str) -> list[str]:
        return self.roles.get(name, [])


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _capped(value: Any, limit: int) -> str | None:
    return value[:limit] if isinstance(value, str) and value.strip() else None


_ACTIVITIES = {
    (AUTHENTICATION, 2): "Logged off",
    (PROCESS_ACTIVITY, 1): "Process started",
    (PROCESS_ACTIVITY, 2): "Process terminated",
}
_CLASSES = {
    AUTHENTICATION: "Authentication",
    PROCESS_ACTIVITY: "Process activity",
    NETWORK_ACTIVITY: "Network connection",
    HTTP_ACTIVITY: "HTTP request",
    DNS_ACTIVITY: "DNS query",
    FILE_ACTIVITY: "File activity",
}


def _action(class_uid: int, activity_id: int | None, status_id: int | None, document: Document) -> str:
    if class_uid == AUTHENTICATION and activity_id == 1:
        return {1: "Logged on", 2: "Failed logon"}.get(status_id or 0, "Logon attempt")
    if (class_uid, activity_id) in _ACTIVITIES:
        return _ACTIVITIES[(class_uid, activity_id or 0)]
    if class_uid in _CLASSES:
        return _CLASSES[class_uid]
    activity = document.get("activity_name")
    return activity if isinstance(activity, str) and activity else f"OCSF class {class_uid}"


def digest(document: Document) -> EvidenceEvent | None:
    identity = event_identity(document)
    class_uid = _int(document.get("class_uid"))
    if identity is None or class_uid is None:
        return None
    uid, at_ms = identity
    activity_id, status_id = _int(document.get("activity_id")), _int(document.get("status_id"))

    by_role: dict[str, list[str]] = {}
    for source_field, entity in roles(document):
        role = _FIELD_ROLES.get(source_field, entity.type.value)
        if entity.type is EntityType.HOST:
            # In a connection our own destination (an internal server) is not where the activity came from.
            inbound = class_uid in NETWORK_CLASSES and source_field == "dst_endpoint.hostname"
            role = "dst_host" if inbound else "host"
        keys = by_role.setdefault(role, [])
        if entity.key not in keys:
            keys.append(entity.key)

    detail: dict[str, Any] = {}
    process = document.get("process")
    if isinstance(process, Mapping):
        command = _capped(process.get("cmd_line"), MAX_COMMAND_LINE)
        if command:
            detail["cmd_line"] = command
    for side in ("src_endpoint", "dst_endpoint"):
        endpoint = document.get(side)
        port = _int(endpoint.get("port")) if isinstance(endpoint, Mapping) else None
        if port is not None:
            detail[f"{side.split('_')[0]}_port"] = port
    logon_type = _int(document.get("logon_type_id"))
    if logon_type is not None:
        detail["logon_type_id"] = logon_type

    return EvidenceEvent(
        event_uid=uid,
        time=datetime.fromtimestamp(at_ms / 1000, UTC),
        class_uid=class_uid,
        activity_id=activity_id,
        status_id=status_id,
        action=_action(class_uid, activity_id, status_id, document),
        outcome={1: "success", 2: "failure"}.get(status_id or 0),
        message=_capped(document.get("message"), MAX_MESSAGE),
        raw=_capped(document.get("raw_data"), MAX_RAW),
        roles=by_role,
        detail=detail,
    )
