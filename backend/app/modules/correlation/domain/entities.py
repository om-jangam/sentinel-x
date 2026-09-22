"""Entity extraction: which things an event names, in which role, and which of them may join incidents.

Roles matter more than field names. In an authentication event `src_endpoint.hostname` is whatever name the
client claimed (attackers send `UNKNOWN-HOST`), so it is not one of our hosts; in an outbound connection
`dst_endpoint.hostname` is the remote service, so it is a domain, not a host. Every sighting keeps the
event_uid it came from, so any link built on it can be traced back to the events.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.core.netaddr import is_external_ip

Document = Mapping[str, Any]

AUTHENTICATION = 3002
NETWORK_CLASSES = frozenset({4001, 4002, 4003})

# Placeholders and built-in principals say nothing about who or what was involved.
_JUNK_HOSTS = frozenset({"", "-", "unknown", "unknown-host", "localhost", "workstation"})
_JUNK_USERS = frozenset(
    {"", "-", "system", "local service", "network service", "anonymous logon", "dwm-1", "umfd-0", "umfd-1"}
)
MAX_VALUE_LENGTH = 255
MAX_ENTITY_LENGTH = 280  # a scoped user is domain\name


class EntityType(StrEnum):
    IP = "ip"
    HOST = "host"
    USER = "user"
    DOMAIN = "domain"
    PROCESS = "process"
    FILE = "file"
    HASH = "hash"


@dataclass(frozen=True, slots=True)
class Entity:
    type: EntityType
    value: str
    # Only entities specific enough to mean "the same thing" may join findings into one incident. Internal
    # addresses (a DNS resolver every host talks to), process names and system file paths may not.
    links: bool

    @property
    def key(self) -> str:
        return f"{self.type.value}:{self.value}"


@dataclass(frozen=True, slots=True)
class Sighting:
    entity: Entity
    event_uid: str
    at_ms: int
    field: str


def _get(document: Document, path: str) -> Any:
    value: Any = document
    for part in path.split("."):
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


def _text(value: Any) -> str | None:
    if isinstance(value, str | int) and not isinstance(value, bool):
        text = str(value).strip()
        return text[:MAX_VALUE_LENGTH] if text else None
    return None


def normalise_host(value: str) -> str | None:
    """Short, lower-case host name: `WS-FIN-07.acme.example` and `WS-FIN-07` are the same machine."""
    text = value.strip().rstrip(".").lower()
    try:
        ipaddress.ip_address(text)
        return None  # an address in a hostname field is an IP, not a name
    except ValueError:
        pass
    short = text.split(".", 1)[0]
    return None if short in _JUNK_HOSTS else short


def normalise_domain(value: str) -> str | None:
    text = value.strip().rstrip(".").lower()
    return text if "." in text and " " not in text else None


def _ip(value: str) -> str | None:
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError:
        return None


def event_identity(document: Document) -> tuple[str, int] | None:
    sx = document.get("sx")
    uid = sx.get("event_uid") if isinstance(sx, Mapping) else None
    time = document.get("time")
    if isinstance(uid, str) and uid and isinstance(time, int) and not isinstance(time, bool):
        return uid, time
    return None


def _is_internal_side(document: Document, endpoint: str) -> bool:
    """An endpoint is one of ours when its address is internal, or it has no address but a name."""
    address = _text(_get(document, f"{endpoint}.ip"))
    return address is None or not is_external_ip(address)


def extract(document: Document) -> list[Sighting]:
    """One sighting per distinct entity in the event (the first field it appeared in)."""
    identity = event_identity(document)
    if identity is None:
        return []
    uid, at_ms = identity
    sightings: dict[str, Sighting] = {}
    for field, entity in roles(document):
        sightings.setdefault(entity.key, Sighting(entity, uid, at_ms, field))
    return list(sightings.values())


def roles(document: Document) -> list[tuple[str, Entity]]:
    """Every (field, entity) pair in the event, so one entity can hold several roles (parent and child)."""
    class_uid = document.get("class_uid")
    found: list[tuple[str, Entity]] = []

    def add(entity_type: EntityType, value: str | None, field: str, *, links: bool) -> None:
        if value:
            pair = (field, Entity(entity_type, value[:MAX_ENTITY_LENGTH], links))
            if pair not in found:
                found.append(pair)

    # Hosts: the device that logged the event, plus our own side of a network connection.
    host_fields = ["device.hostname"]
    if class_uid == AUTHENTICATION:
        host_fields.append("dst_endpoint.hostname")  # the host being logged on to
    elif class_uid in NETWORK_CLASSES:
        host_fields += [
            f"{side}.hostname" for side in ("src_endpoint", "dst_endpoint") if _is_internal_side(document, side)
        ]
    hosts: list[str] = []
    for field in host_fields:
        raw = _text(_get(document, field))
        host = normalise_host(raw) if raw else None
        if host:
            hosts.append(host)
            add(EntityType.HOST, host, field, links=True)

    for field in ("src_endpoint.ip", "dst_endpoint.ip", "device.ip"):
        raw = _text(_get(document, field))
        address = _ip(raw) if raw else None
        if address:
            add(EntityType.IP, address, field, links=is_external_ip(address))

    # Users are scoped: `root` on web-01 and `root` on db-02 are different accounts.
    for prefix in ("user", "actor.user", "process.user"):
        name = _text(_get(document, f"{prefix}.name"))
        if not name or name.lower() in _JUNK_USERS or name.endswith("$"):
            continue
        domain = _text(_get(document, f"{prefix}.domain"))
        if domain and domain != "-":
            add(EntityType.USER, f"{domain.lower()}\\{name.lower()}", f"{prefix}.name", links=True)
        elif hosts:
            add(EntityType.USER, f"{name.lower()}@{hosts[0]}", f"{prefix}.name", links=True)

    domain_fields = ["query.hostname", "src_endpoint.domain", "dst_endpoint.domain"]
    if class_uid in NETWORK_CLASSES:
        domain_fields += [
            f"{side}.hostname" for side in ("src_endpoint", "dst_endpoint") if not _is_internal_side(document, side)
        ]
    for field in domain_fields:
        raw = _text(_get(document, field))
        add(EntityType.DOMAIN, normalise_domain(raw) if raw else None, field, links=True)

    answers = document.get("answers")
    for answer in answers if isinstance(answers, list) else []:
        raw = _text(answer.get("rdata")) if isinstance(answer, Mapping) else None
        address = _ip(raw) if raw else None
        if address:
            add(EntityType.IP, address, "answers.rdata", links=is_external_ip(address))

    for field in ("process.name", "process.parent_process.name", "actor.process.name"):
        raw = _text(_get(document, field))
        add(EntityType.PROCESS, raw.lower() if raw else None, field, links=False)
    for field in ("process.file.path", "file.path"):
        raw = _text(_get(document, field))
        add(EntityType.FILE, raw, field, links=False)
    for field in ("process.file.hashes", "process.parent_process.file.hashes", "file.hashes"):
        hashes = _get(document, field)
        for fingerprint in hashes if isinstance(hashes, list) else []:
            value = _text(fingerprint.get("value")) if isinstance(fingerprint, Mapping) else None
            add(EntityType.HASH, value.lower() if value else None, f"{field}.value", links=True)
    return found


def is_successful_logon(document: Document) -> bool:
    return (
        document.get("class_uid") == AUTHENTICATION
        and document.get("activity_id") == 1
        and document.get("status_id") == 1
    )
