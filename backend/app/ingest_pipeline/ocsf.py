"""OCSF 1.6 — the trimmed, detection-relevant subset Sentinel-X normalises to (ADR-0003).

Only fields detection, hunting and investigation need are modelled; everything else stays in
`raw_data` / `unmapped`. Unknown attributes are ignored rather than rejected so native OCSF producers
can send full events.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator

from app.core.clock import ensure_utc, utcnow

OCSF_VERSION = "1.6.0"
MAX_RAW_DATA_CHARS = 32_768
MAX_UNMAPPED_CHARS = 16_384
MAX_FUTURE_SKEW = timedelta(hours=24)


class Category(IntEnum):
    SYSTEM = 1
    FINDINGS = 2
    IAM = 3
    NETWORK = 4
    DISCOVERY = 5
    APPLICATION = 6


CATEGORY_SLUGS: Mapping[Category, str] = {
    Category.SYSTEM: "system",
    Category.FINDINGS: "findings",
    Category.IAM: "iam",
    Category.NETWORK: "network",
    Category.DISCOVERY: "discovery",
    Category.APPLICATION: "application",
}


# OCSF 1.6 category captions, verbatim (the enum names are identifiers, not display names).
CATEGORY_CAPTIONS: Mapping[Category, str] = {
    Category.SYSTEM: "System Activity",
    Category.FINDINGS: "Findings",
    Category.IAM: "Identity & Access Management",
    Category.NETWORK: "Network Activity",
    Category.DISCOVERY: "Discovery",
    Category.APPLICATION: "Application Activity",
}


class EventClass(IntEnum):
    FILE_SYSTEM_ACTIVITY = 1001
    PROCESS_ACTIVITY = 1007
    AUTHENTICATION = 3002
    NETWORK_ACTIVITY = 4001
    HTTP_ACTIVITY = 4002
    DNS_ACTIVITY = 4003

    @property
    def category(self) -> Category:
        return Category(self.value // 1000)

    @property
    def caption(self) -> str:
        return self.name.replace("_", " ").title().replace("Http", "HTTP").replace("Dns", "DNS")


UNKNOWN_ACTIVITY = 0
OTHER_ACTIVITY = 99

ACTIVITY_NAMES: Mapping[EventClass, Mapping[int, str]] = {
    EventClass.FILE_SYSTEM_ACTIVITY: {
        1: "Create", 2: "Read", 3: "Update", 4: "Delete", 5: "Rename", 6: "Set Attributes",
        7: "Set Security", 8: "Get Attributes", 9: "Get Security", 10: "Encrypt", 11: "Decrypt",
        12: "Mount", 13: "Unmount", 14: "Open",
    },
    EventClass.PROCESS_ACTIVITY: {1: "Launch", 2: "Terminate", 3: "Open", 4: "Inject", 5: "Set User ID"},
    EventClass.AUTHENTICATION: {
        1: "Logon", 2: "Logoff", 3: "Authentication Ticket", 4: "Service Ticket Request",
        5: "Service Ticket Renew", 6: "Preauth",
    },
    EventClass.NETWORK_ACTIVITY: {1: "Open", 2: "Close", 3: "Reset", 4: "Fail", 5: "Refuse", 6: "Traffic", 7: "Listen"},
    EventClass.HTTP_ACTIVITY: {
        1: "Connect", 2: "Delete", 3: "Get", 4: "Head", 5: "Options", 6: "Post", 7: "Put", 8: "Trace", 9: "Patch",
    },
    EventClass.DNS_ACTIVITY: {1: "Query", 2: "Response", 6: "Traffic"},
}  # fmt: skip


class Severity(IntEnum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6
    OTHER = 99


class Status(IntEnum):
    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2
    OTHER = 99


class ObservableType(IntEnum):
    UNKNOWN = 0
    HOSTNAME = 1
    IP_ADDRESS = 2
    MAC_ADDRESS = 3
    USER_NAME = 4
    EMAIL_ADDRESS = 5
    URL_STRING = 6
    FILE_NAME = 7
    HASH = 8
    PROCESS_NAME = 9
    OTHER = 99


def parse_event_time(value: Any) -> datetime:
    """OCSF `timestamp_t` is epoch milliseconds; RFC 3339 strings are accepted too."""
    if isinstance(value, datetime):
        return ensure_utc(value)
    if isinstance(value, bool):
        raise ValueError("time must be epoch milliseconds or an RFC 3339 string")
    if isinstance(value, int | float):
        # Values below 1e11 are epoch seconds (1e11 ms is 1973; 1e11 s is year 5138).
        seconds = value / 1000 if abs(value) >= 1e11 else value
        return datetime.fromtimestamp(seconds, UTC)
    if isinstance(value, str):
        text = value.strip()
        if text.lstrip("-").isdigit():
            return parse_event_time(int(text))
        try:
            return ensure_utc(datetime.fromisoformat(text.replace("Z", "+00:00")))
        except ValueError as exc:
            raise ValueError("time must be epoch milliseconds or an RFC 3339 string") from exc
    raise ValueError("time must be epoch milliseconds or an RFC 3339 string")


EventTime = Annotated[datetime, BeforeValidator(parse_event_time)]
S16 = Annotated[str, Field(max_length=16)]
S64 = Annotated[str, Field(max_length=64)]
S255 = Annotated[str, Field(max_length=255)]
S1024 = Annotated[str, Field(max_length=1024)]
S4096 = Annotated[str, Field(max_length=4096)]
Port = Annotated[int, Field(ge=0, le=65535)]
Count = Annotated[int, Field(ge=0)]


class _Object(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)


class OperatingSystem(_Object):
    name: S255 | None = None
    type: S64 | None = None


class Device(_Object):
    hostname: S255 | None = None
    ip: IPvAnyAddress | None = None
    uid: S255 | None = None
    os: OperatingSystem | None = None


class Endpoint(_Object):
    ip: IPvAnyAddress | None = None
    port: Port | None = None
    hostname: S255 | None = None
    domain: S255 | None = None


class User(_Object):
    name: S255 | None = None
    uid: S255 | None = None
    domain: S255 | None = None


class File(_Object):
    path: S4096 | None = None
    name: S255 | None = None


class ParentProcess(_Object):
    pid: Count | None = None
    name: S255 | None = None
    cmd_line: S4096 | None = None
    file: File | None = None


class Process(_Object):
    pid: Count | None = None
    name: S255 | None = None
    cmd_line: S4096 | None = None
    file: File | None = None
    user: User | None = None
    parent_process: ParentProcess | None = None


class Actor(_Object):
    user: User | None = None
    process: Process | None = None


class Product(_Object):
    name: S255
    vendor_name: S255 | None = None
    version: S64 | None = None


class Metadata(_Object):
    version: S16 = OCSF_VERSION
    product: Product
    log_name: S255 | None = None
    uid: S255 | None = None
    original_time: S64 | None = None

    @field_validator("version")
    @classmethod
    def _major_version(cls, value: str) -> str:
        if not value.startswith("1."):
            raise ValueError("only OCSF 1.x events are supported")
        return value


class DnsQuery(_Object):
    hostname: S255
    type: S16 | None = None


class DnsAnswer(_Object):
    rdata: S1024 | None = None
    type: S16 | None = None
    ttl: Count | None = None


class Url(_Object):
    url_string: S4096 | None = None
    hostname: S255 | None = None
    path: S4096 | None = None
    scheme: S16 | None = None


class HttpRequest(_Object):
    http_method: S16 | None = None
    url: Url | None = None
    user_agent: S1024 | None = None


class HttpResponse(_Object):
    code: Annotated[int, Field(ge=100, le=599)] | None = None


class ConnectionInfo(_Object):
    protocol_name: S16 | None = None
    direction_id: Annotated[int, Field(ge=0, le=99)] | None = None


class Traffic(_Object):
    bytes_in: Count | None = None
    bytes_out: Count | None = None
    packets_in: Count | None = None
    packets_out: Count | None = None


class Observable(_Object):
    name: S255
    type_id: ObservableType
    value: S1024


# Minimum context each class needs to be useful for detection (a Sentinel-X rule, stricter than OCSF).
_REQUIRED_CONTEXT: Mapping[EventClass, tuple[tuple[str, ...], str]] = {
    EventClass.AUTHENTICATION: (("user",), "user"),
    EventClass.NETWORK_ACTIVITY: (("src_endpoint", "dst_endpoint"), "src_endpoint or dst_endpoint"),
    EventClass.DNS_ACTIVITY: (("query",), "query"),
    EventClass.PROCESS_ACTIVITY: (("process",), "process"),
    EventClass.HTTP_ACTIVITY: (("http_request",), "http_request"),
    EventClass.FILE_SYSTEM_ACTIVITY: (("file",), "file"),
}


class OcsfEvent(_Object):
    class_uid: EventClass
    category_uid: Category | None = None
    activity_id: Annotated[int, Field(ge=0, le=99)]
    type_uid: int | None = None
    severity_id: Severity
    status_id: Status | None = None
    time: EventTime
    message: Annotated[str, Field(max_length=8192)] | None = None
    metadata: Metadata

    actor: Actor | None = None
    user: User | None = None
    device: Device | None = None
    src_endpoint: Endpoint | None = None
    dst_endpoint: Endpoint | None = None
    process: Process | None = None
    file: File | None = None
    query: DnsQuery | None = None
    answers: Annotated[list[DnsAnswer], Field(max_length=50)] | None = None
    http_request: HttpRequest | None = None
    http_response: HttpResponse | None = None
    connection_info: ConnectionInfo | None = None
    traffic: Traffic | None = None

    auth_protocol: S64 | None = None
    logon_type: S64 | None = None
    logon_type_id: Annotated[int, Field(ge=0, le=99)] | None = None
    is_mfa: bool | None = None

    observables: Annotated[list[Observable], Field(max_length=100)] = Field(default_factory=list)
    raw_data: Annotated[str, Field(max_length=MAX_RAW_DATA_CHARS)] | None = None
    unmapped: dict[str, Any] | None = None

    @field_validator("unmapped")
    @classmethod
    def _bounded_unmapped(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None and len(json.dumps(value, default=str)) > MAX_UNMAPPED_CHARS:
            raise ValueError(f"unmapped exceeds {MAX_UNMAPPED_CHARS} characters")
        return value

    @model_validator(mode="after")
    def _consistency(self) -> OcsfEvent:
        expected_category = self.class_uid.category
        if self.category_uid is None:
            self.category_uid = expected_category
        elif self.category_uid != expected_category:
            raise ValueError(f"category_uid {int(self.category_uid)} does not match class_uid {int(self.class_uid)}")

        defined = ACTIVITY_NAMES[self.class_uid]
        if self.activity_id not in defined and self.activity_id not in (UNKNOWN_ACTIVITY, OTHER_ACTIVITY):
            raise ValueError(f"activity_id {self.activity_id} is not defined for {self.class_uid.caption}")

        expected_type = int(self.class_uid) * 100 + self.activity_id
        if self.type_uid is None:
            self.type_uid = expected_type
        elif self.type_uid != expected_type:
            raise ValueError(f"type_uid must be {expected_type} (class_uid * 100 + activity_id)")

        fields, label = _REQUIRED_CONTEXT[self.class_uid]
        if all(getattr(self, name) is None for name in fields):
            raise ValueError(f"{self.class_uid.caption} events require {label}")

        if self.time > utcnow() + MAX_FUTURE_SKEW:
            raise ValueError("time is more than 24 hours in the future")

        if not self.observables:
            self.observables = derive_observables(self)
        return self

    # ----------------------------------------------------------- derived views
    @property
    def activity_name(self) -> str:
        if self.activity_id == UNKNOWN_ACTIVITY:
            return "Unknown"
        return ACTIVITY_NAMES[self.class_uid].get(self.activity_id, "Other")

    @property
    def data_stream(self) -> str:
        return f"events-ocsf-{CATEGORY_SLUGS[self.class_uid.category]}"

    def canonical_json(self) -> str:
        return json.dumps(self.model_dump(mode="json", exclude_none=True), sort_keys=True, separators=(",", ":"))

    def fingerprint(self, *, org_id: str, source_id: str) -> str:
        """Content identity: the same record delivered twice yields the same document id."""
        digest = hashlib.sha256()
        for part in (org_id, source_id, self.canonical_json()):
            digest.update(part.encode("utf-8"))
            digest.update(b"\x1f")
        return digest.hexdigest()

    def to_document(self, *, org_id: str, source_id: str, event_uid: str, ingested_at: datetime) -> dict[str, Any]:
        """The OpenSearch document: OCSF fields, captions, `@timestamp`, and Sentinel-X attribution."""
        document = self.model_dump(mode="json", exclude_none=True)
        document["time"] = int(self.time.timestamp() * 1000)
        document["@timestamp"] = _rfc3339(self.time)
        document["class_name"] = self.class_uid.caption
        document["category_name"] = CATEGORY_CAPTIONS[self.class_uid.category]
        document["activity_name"] = self.activity_name
        document["severity"] = Severity(self.severity_id).name.title()
        if self.status_id is not None:
            document["status"] = Status(self.status_id).name.title()
        document["sx"] = {
            "org_id": org_id,
            "source_id": source_id,
            "event_uid": event_uid,
            "ingested_at": _rfc3339(ingested_at),
            "fingerprint": self.fingerprint(org_id=org_id, source_id=source_id),
        }
        return document


def _rfc3339(value: datetime) -> str:
    return ensure_utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def derive_observables(event: OcsfEvent) -> list[Observable]:
    """Index the entities a record mentions so hunts and the risk engine can pivot on them."""
    observables: list[Observable] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, type_id: ObservableType, value: object) -> None:
        if value is None or value == "" or len(observables) >= 100:
            return
        text = str(value)
        if (name, text) not in seen:
            seen.add((name, text))
            observables.append(Observable(name=name, type_id=type_id, value=text[:1024]))

    for prefix, endpoint in (("src_endpoint", event.src_endpoint), ("dst_endpoint", event.dst_endpoint)):
        if endpoint is not None:
            add(f"{prefix}.ip", ObservableType.IP_ADDRESS, endpoint.ip)
            add(f"{prefix}.hostname", ObservableType.HOSTNAME, endpoint.hostname)
    if event.device is not None:
        add("device.hostname", ObservableType.HOSTNAME, event.device.hostname)
        add("device.ip", ObservableType.IP_ADDRESS, event.device.ip)
    if event.user is not None:
        add("user.name", ObservableType.USER_NAME, event.user.name)
    if event.actor is not None:
        if event.actor.user is not None:
            add("actor.user.name", ObservableType.USER_NAME, event.actor.user.name)
        if event.actor.process is not None:
            add("actor.process.name", ObservableType.PROCESS_NAME, event.actor.process.name)
    if event.process is not None:
        add("process.name", ObservableType.PROCESS_NAME, event.process.name)
        if event.process.file is not None:
            add("process.file.path", ObservableType.FILE_NAME, event.process.file.path)
    if event.file is not None:
        add("file.path", ObservableType.FILE_NAME, event.file.path)
    if event.query is not None:
        add("query.hostname", ObservableType.HOSTNAME, event.query.hostname)
    if event.http_request is not None and event.http_request.url is not None:
        add("http_request.url.url_string", ObservableType.URL_STRING, event.http_request.url.url_string)
    return observables
