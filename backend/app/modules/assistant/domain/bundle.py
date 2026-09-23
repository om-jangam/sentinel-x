"""The evidence bundle: everything the assistant may know about an incident, and nothing else.

Built deterministically from stored incident data, so the same incident always yields the same bundle
(and the same hash, recorded with every analysis). Everything citable is in here: an event_uid the model
cites must appear in `events`, and an address or hash it mentions must appear somewhere in the bundle.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

MAX_EVENTS = 80
MAX_RAW = 300
MAX_COMMAND = 500


@dataclass(frozen=True, slots=True)
class BundleEvent:
    event_uid: str
    time: str
    action: str
    outcome: str | None
    entities: dict[str, list[str]]  # role -> values, e.g. {"host": ["ws-fin-07"], "src_ip": ["198.51.100.23"]}
    detail: dict[str, Any] = field(default_factory=dict)
    raw: str | None = None


@dataclass(frozen=True, slots=True)
class BundleFinding:
    link_id: str
    rule_title: str
    severity_id: int
    techniques: list[str]
    tactics: list[str]
    events: list[str]


@dataclass(frozen=True, slots=True)
class BundleLink:
    link_id: str
    rule: str
    reason: str
    shared_entities: list[str]
    events: list[str]


@dataclass(frozen=True, slots=True)
class BundleStep:
    time: str
    action: str
    count: int
    host: str | None
    users: list[str]
    process: str | None
    remote: str | None
    events: list[str]


@dataclass(frozen=True, slots=True)
class BundleEdge:
    source: str
    relation: str  # the label the model reads, e.g. "connected to"
    target: str
    events: list[str]
    # The relation's own name, e.g. "connected_to". The label reads better in a prompt; the name is what
    # the attribution check compares against, and the two must not be confused (they were once).
    name: str = ""


@dataclass(frozen=True, slots=True)
class BundleIntel:
    """Third-party context, never evidence: who said what about an indicator, and when."""

    indicator: str
    provider: str
    verdict: str
    summary: str
    retrieved_at: str


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    incident: dict[str, Any]
    findings: list[BundleFinding]
    links: list[BundleLink]
    events: list[BundleEvent]
    timeline: list[BundleStep]
    graph: list[BundleEdge]
    intel: list[BundleIntel]
    entities: list[str]  # every incident entity key, e.g. "ip:198.51.100.23"
    omitted_events: int = 0  # evidence events left out to fit the budget: reported, not silently lost

    def as_json(self) -> dict[str, Any]:
        return asdict(self)

    def canonical(self) -> str:
        return json.dumps(self.as_json(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    @property
    def event_uids(self) -> frozenset[str]:
        return frozenset(event.event_uid for event in self.events)

    @property
    def known_values(self) -> frozenset[str]:
        """Every value the bundle states: what a statement may mention without inventing it."""
        values: set[str] = set()
        for key in self.entities:
            values.add(key.split(":", 1)[-1].lower())
        for event in self.events:
            for items in event.entities.values():
                values.update(item.lower() for item in items)
        for intel in self.intel:
            values.add(intel.indicator.split(":", 1)[-1].lower())
        return frozenset(values)

    def for_prompt(self) -> str:
        """JSON for the prompt, with `<` escaped so no field can close the evidence delimiter."""
        text = json.dumps(self.as_json(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return text.replace("<", "\\u003c")
