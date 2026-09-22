"""Attack timeline: an incident's evidence events in time order, with repeated actions folded into one step.

Every step lists the event_uids it stands for and the findings and correlation links that cite them, so
each line of the timeline can be traced to stored events. Nothing is added that the events don't say:
steps are the evidence, grouped, not a narrative.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.core.netaddr import is_external_ip
from app.modules.correlation.domain.evidence import EvidenceEvent
from app.modules.correlation.domain.incidents import IncidentLink, LinkKind

# Consecutive events doing the same thing fold into one step unless this far apart.
STEP_GAP = timedelta(minutes=10)
MAX_STEP_VALUES = 20


@dataclass(frozen=True, slots=True)
class StepCitation:
    link_id: str
    rule: str
    title: str
    techniques: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TimelineStep:
    id: str
    first_seen: datetime
    last_seen: datetime
    action: str
    outcome: str | None
    host: str | None
    users: tuple[str, ...]
    process: str | None
    parent_process: str | None
    command_lines: tuple[str, ...]
    remote: str | None
    remote_ports: tuple[int, ...]
    domains: tuple[str, ...]
    citations: tuple[StepCitation, ...]
    events: tuple[str, ...]
    entities: tuple[str, ...]


def _value(key: str | None) -> str | None:
    return None if key is None else key.split(":", 1)[1]


def remote_key(event: EvidenceEvent) -> str | None:
    """The other side: the client of a logon, or the external end of a connection."""
    if event.role("src_ip") and event.class_uid == 3002:
        return event.role("src_ip")[0]
    addresses = event.role("dst_ip") + event.role("src_ip")
    external = [key for key in addresses if is_external_ip(key.split(":", 1)[1])]
    if external:
        return external[0]
    internal = event.role("dst_host") + event.role("dst_ip")
    return internal[0] if internal else None


def _first(event: EvidenceEvent, role: str) -> str | None:
    values = event.role(role)
    return values[0] if values else None


def _group_key(event: EvidenceEvent) -> tuple[object, ...]:
    return (
        event.action,
        event.outcome,
        _first(event, "host"),
        remote_key(event),
        _first(event, "process"),
        _first(event, "parent_process"),
    )


def _unique(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))[:MAX_STEP_VALUES]


def build_timeline(events: Sequence[EvidenceEvent], links: Sequence[IncidentLink]) -> list[TimelineStep]:
    citations: dict[str, list[StepCitation]] = {}
    for link in links:
        if link.kind is LinkKind.FINDING:
            citation = StepCitation(
                link_id=str(link.id),
                rule=link.rule.value,
                title=str(link.detail.get("rule_title", "")),
                techniques=link.techniques,
            )
        else:
            citation = StepCitation(link_id=str(link.id), rule=link.rule.value, title=link.reason, techniques=())
        for uid in link.evidence:
            citations.setdefault(uid, []).append(citation)

    groups: list[list[EvidenceEvent]] = []
    for event in sorted(events, key=lambda e: (e.time, e.event_uid)):
        last = groups[-1] if groups else None
        if last and _group_key(last[-1]) == _group_key(event) and event.time - last[-1].time <= STEP_GAP:
            last.append(event)
        else:
            groups.append([event])
    return [_step(group, citations) for group in groups]


def _step(group: list[EvidenceEvent], citations: dict[str, list[StepCitation]]) -> TimelineStep:
    first = group[0]
    cited: dict[str, StepCitation] = {}
    for event in group:
        for citation in citations.get(event.event_uid, []):
            cited.setdefault(citation.link_id, citation)
    ports = sorted({p for e in group if isinstance(p := e.detail.get("dst_port"), int)})
    return TimelineStep(
        id=first.event_uid,
        first_seen=first.time,
        last_seen=group[-1].time,
        action=first.action,
        outcome=first.outcome,
        host=_value(_first(first, "host")),
        users=_unique([_value(key) or "" for e in group for key in e.role("user")]),
        process=_value(_first(first, "process")),
        parent_process=_value(_first(first, "parent_process")),
        command_lines=_unique([str(e.detail["cmd_line"]) for e in group if e.detail.get("cmd_line")]),
        remote=_value(remote_key(first)),
        remote_ports=tuple(ports[:MAX_STEP_VALUES]),
        domains=_unique([_value(key) or "" for e in group for key in e.role("domain")]),
        citations=tuple(cited.values()),
        events=tuple(e.event_uid for e in group),
        entities=_unique([key for e in group for keys in e.roles.values() for key in keys]),
    )
