"""What this organisation has seen before, so an investigation can say what is new (docs/12 step 5).

A rule cannot express "unusual here": `wmic process call create notepad.exe` is ordinary on its own, and
the same command is worth a second look the first time it ever runs. Elastic's higher-order rules and the
NDSS paper *NoDoze* rank alerts that way; both score how rare an alert's context is.

Sentinel-X keeps that signal evidence-first:

- only relationships an event states are counted (the same rule the graph follows);
- a count is a count: "seen 412 times, first on 2026-08-30", never a probability or a risk score;
- it is **context, not detection**. Novelty raises nothing by itself and never opens an incident.

Three kinds are counted, because they are the ones a single event states and an analyst reasons about:

| kind | key | why |
|------|-----|-----|
| `process_pair` | `parent → child` process names | a parent that never spawns a shell doing so is the signal |
| `host_remote` | `host → external address or domain` | this machine has never talked to that destination before |
| `remote` | the external address or domain alone | nobody here has ever talked to it |
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.core.netaddr import is_external_ip
from app.modules.correlation.domain.entities import Document, EntityType, normalise_domain, normalise_host, roles
from app.modules.correlation.domain.evidence import EvidenceEvent

PROCESS_PAIR = "process_pair"
HOST_REMOTE = "host_remote"
REMOTE = "remote"
MAX_KEY = 280


@dataclass(frozen=True, slots=True)
class Observation:
    """One thing an event states, as counted in the baseline."""

    kind: str
    key: str


@dataclass(frozen=True, slots=True)
class BatchSighting:
    """How often one thing appears in a batch, and when, in the events' own time.

    Event time, never ingestion time: "first seen" has to mean when it happened, or an incident built
    from last week's logs would find that everything it touches is newer than itself.
    """

    count: int
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True, slots=True)
class Baseline:
    kind: str
    key: str
    first_seen: datetime
    last_seen: datetime
    observations: int


@dataclass(frozen=True, slots=True)
class Novelty:
    """What the baseline says about one thing this incident involves."""

    kind: str
    key: str
    observations: int
    first_seen: datetime | None
    new_here: bool  # nothing was seen before this incident started

    def describe(self) -> str:
        if self.first_seen is None:
            return f"{self.key}: never seen outside this incident"
        seen = self.first_seen.strftime("%Y-%m-%d")
        if self.new_here:
            return f"{self.key}: first seen in this incident ({seen}), {self.observations} times since"
        return f"{self.key}: seen {self.observations} times, first on {seen}"


def _text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _get(document: Document, path: str) -> Any:
    current: Any = document
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def _remotes(document: Document) -> list[str]:
    """External destinations the event names: an address outside every internal range, or a domain."""
    found: list[str] = []
    for field, entity in roles(document):
        if entity.type is EntityType.IP and is_external_ip(entity.value) and field != "device.ip":
            found.append(entity.value)
        elif entity.type is EntityType.DOMAIN:
            domain = normalise_domain(entity.value)
            if domain:
                found.append(domain)
    return list(dict.fromkeys(found))


def observations(document: Document) -> list[Observation]:
    """Everything this one event states that the baseline counts. Order is stable for the same event."""
    found: list[Observation] = []

    child = _text(_get(document, "process.name"))
    parent = _text(_get(document, "process.parent_process.name"))
    if child and parent:
        found.append(Observation(PROCESS_PAIR, f"{parent.lower()} -> {child.lower()}"[:MAX_KEY]))

    host_value = _text(_get(document, "device.hostname"))
    host = normalise_host(host_value) if host_value else None
    for remote in _remotes(document):
        found.append(Observation(REMOTE, remote[:MAX_KEY]))
        if host:
            found.append(Observation(HOST_REMOTE, f"{host} -> {remote}"[:MAX_KEY]))
    return found


def batch_observations(documents: Iterable[Document]) -> dict[Observation, BatchSighting]:
    """How often each thing appears in one batch and when, so a batch is one write per key."""
    counted: dict[Observation, BatchSighting] = {}
    for document in documents:
        at = _event_time(document)
        if at is None:
            continue  # a stored event always has a time; anything else cannot be placed in a baseline
        for observation in observations(document):
            seen = counted.get(observation)
            counted[observation] = (
                BatchSighting(1, at, at)
                if seen is None
                else BatchSighting(seen.count + 1, min(seen.first_seen, at), max(seen.last_seen, at))
            )
    return counted


def _event_time(document: Document) -> datetime | None:
    value = document.get("time")
    if isinstance(value, int) and not isinstance(value, bool):
        return datetime.fromtimestamp(value / 1000, UTC)
    return None


def novelty(
    keys: Sequence[Observation], baselines: Mapping[tuple[str, str], Baseline], *, incident_first_seen: datetime
) -> list[Novelty]:
    """What is new about this incident, newest first. Unknown keys are reported, never guessed at."""
    found = []
    for observation in dict.fromkeys(keys):
        baseline = baselines.get((observation.kind, observation.key))
        found.append(
            Novelty(
                kind=observation.kind,
                key=observation.key,
                observations=baseline.observations if baseline else 0,
                first_seen=baseline.first_seen if baseline else None,
                new_here=baseline is None or baseline.first_seen >= incident_first_seen,
            )
        )
    return sorted(found, key=lambda item: (not item.new_here, item.observations, item.key))


def evidence_observations(event: EvidenceEvent) -> list[Observation]:
    """The same keys, read from a stored evidence digest rather than the original document.

    `observations()` reads the document as it is ingested; this reads what correlation kept. A test holds
    the two to the same answer, because a baseline written by one and read by the other would silently
    make everything look new.
    """
    found: list[Observation] = []

    def values(role: str) -> list[str]:
        return [key.split(":", 1)[1] for key in event.role(role)]

    parents, children = values("parent_process"), values("process")
    if parents and children:
        found.append(Observation(PROCESS_PAIR, f"{parents[0].lower()} -> {children[0].lower()}"[:MAX_KEY]))

    hosts = values("host")
    remotes = [value for role in ("dst_ip", "src_ip") for value in values(role) if is_external_ip(value)]
    remotes += [value for value in values("domain")]
    for remote in dict.fromkeys(remotes):
        found.append(Observation(REMOTE, remote[:MAX_KEY]))
        if hosts:
            found.append(Observation(HOST_REMOTE, f"{hosts[0]} -> {remote}"[:MAX_KEY]))
    return found
