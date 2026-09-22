"""Entity graph: who and what an incident involves, and how, with every edge citing the events that show it.

Edges come only from entities appearing together in one event, in roles that event states (a logon from
this address to this host, this user started this process). Nothing is inferred across events: two nodes
are connected only if some stored event connects them.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.netaddr import is_external_ip
from app.modules.correlation.domain.entities import AUTHENTICATION
from app.modules.correlation.domain.evidence import (
    DNS_ACTIVITY,
    FILE_ACTIVITY,
    HTTP_ACTIVITY,
    NETWORK_ACTIVITY,
    PROCESS_ACTIVITY,
    EvidenceEvent,
)

MAX_EDGE_EVENTS = 20
PROCESS_LAUNCH, PROCESS_OPEN, PROCESS_INJECT = 1, 3, 4

RELATION_LABELS = {
    "failed_logon": "failed logon to",
    "logon": "logged on to",
    "failed_logon_as": "failed logon as",
    "logon_as": "logged on as",
    "ran_as": "ran processes as",
    "started": "started",
    "spawned": "spawned",
    "image": "image",
    "hash": "hash",
    "connected_to": "connected to",
    "named": "named in the record as",
    "queried": "queried",
    "resolved_to": "resolved to",
    "file_activity": "file activity",
    "opened": "opened",
    "injected_into": "injected a thread into",
}

# Left-to-right layout order: where an attack usually starts to where it ends.
TYPE_ORDER = ("ip", "host", "user", "process", "file", "hash", "domain")


@dataclass(slots=True)
class GraphEdge:
    id: str
    source: str
    target: str
    relation: str
    label: str
    first_seen: datetime
    last_seen: datetime
    event_count: int = 0
    events: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class GraphNode:
    key: str
    type: str
    value: str
    external: bool
    first_seen: datetime
    last_seen: datetime
    event_count: int = 0
    events: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class EntityGraph:
    nodes: list[GraphNode]
    edges: list[GraphEdge]


def _pairs(sources: Iterable[str], targets: Iterable[str]) -> list[tuple[str, str]]:
    return [(s, t) for s in sources for t in targets if s != t]


def relations(event: EvidenceEvent) -> list[tuple[str, str, str]]:
    """(source key, relation, target key) for everything this one event states."""
    r = event.role
    found: list[tuple[str, str, str]] = []

    def add(relation: str, pairs: list[tuple[str, str]]) -> None:
        found.extend((s, relation, t) for s, t in pairs)

    if event.class_uid == AUTHENTICATION and event.activity_id == 1 and event.outcome:
        prefix = "logon" if event.outcome == "success" else "failed_logon"
        add(prefix, _pairs(r("src_ip"), r("host")))
        add(f"{prefix}_as", _pairs(r("host"), r("user")))
    elif event.class_uid == PROCESS_ACTIVITY and event.activity_id == PROCESS_OPEN:
        # One process opened another (Sysmon 10), e.g. a tool reading lsass.exe memory.
        add("opened", _pairs(r("actor_process"), r("process")))
    elif event.class_uid == PROCESS_ACTIVITY and event.activity_id == PROCESS_INJECT:
        add("injected_into", _pairs(r("actor_process"), r("process")))
    elif event.class_uid == PROCESS_ACTIVITY:
        add("ran_as", _pairs(r("host"), r("user")))
        if event.activity_id in (None, PROCESS_LAUNCH):
            add("started", _pairs(r("user") or r("host"), r("process")))
            add("spawned", _pairs(r("parent_process"), r("process")))
        add("image", _pairs(r("process"), r("file")))
        add("hash", _pairs(r("file"), r("hash")))
    elif event.class_uid in (NETWORK_ACTIVITY, HTTP_ACTIVITY):
        addresses = r("dst_ip") + r("src_ip")
        remote = [key for key in addresses if is_external_ip(key.split(":", 1)[1])] or r("dst_host") or r("dst_ip")
        add("connected_to", _pairs(r("host"), remote))
        # Only when the event itself names the process that made the connection (Sysmon 3 does; a
        # firewall log doesn't), so "which program connected out" is stated, not inferred.
        add("connected_to", _pairs(r("actor_process"), remote))
        add("named", _pairs(remote, r("domain")))
    elif event.class_uid == DNS_ACTIVITY:
        add("queried", _pairs(r("host"), r("domain")))
        add("queried", _pairs(r("actor_process"), r("domain")))
        add("resolved_to", _pairs(r("domain"), r("answer")))
    elif event.class_uid == FILE_ACTIVITY:
        add("file_activity", _pairs(r("host"), r("file")))
        add("file_activity", _pairs(r("actor_process"), r("file")))
        add("hash", _pairs(r("file"), r("hash")))
    return found


def _node(key: str, event: EvidenceEvent) -> GraphNode:
    entity_type, _, value = key.partition(":")
    external = (entity_type == "ip" and is_external_ip(value)) or entity_type == "domain"
    return GraphNode(key, entity_type, value, external, event.time, event.time)


def _touch(item: GraphNode | GraphEdge, event: EvidenceEvent) -> None:
    item.first_seen = min(item.first_seen, event.time)
    item.last_seen = max(item.last_seen, event.time)
    if event.event_uid not in item.events:
        item.event_count += 1
        if len(item.events) < MAX_EDGE_EVENTS:
            item.events.append(event.event_uid)


def build_graph(events: Sequence[EvidenceEvent]) -> EntityGraph:
    nodes: dict[str, GraphNode] = {}
    edges: dict[str, GraphEdge] = {}
    for event in sorted(events, key=lambda e: (e.time, e.event_uid)):
        for source, relation, target in relations(event):
            edge_id = f"{source}|{relation}|{target}"
            edge = edges.get(edge_id)
            if edge is None:
                edge = edges[edge_id] = GraphEdge(
                    edge_id, source, target, relation, RELATION_LABELS[relation], event.time, event.time
                )
            _touch(edge, event)
            port = event.detail.get("dst_port")
            if relation == "connected_to" and isinstance(port, int):
                edge.detail["ports"] = sorted({*edge.detail.get("ports", []), port})
            for key in (source, target):
                node = nodes.get(key)
                if node is None:
                    node = nodes[key] = _node(key, event)
                _touch(node, event)
    order = {name: index for index, name in enumerate(TYPE_ORDER)}
    return EntityGraph(
        nodes=sorted(nodes.values(), key=lambda n: (order.get(n.type, len(order)), not n.external, n.first_seen)),
        edges=sorted(edges.values(), key=lambda e: (e.first_seen, e.id)),
    )
