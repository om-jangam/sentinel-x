"""Phase 4 acceptance: every timeline step and graph edge of a sample incident traces back to stored events.

Runs the production composition (detection → correlation → evidence digests) against SQL, then builds the
timeline and graph exactly as the API does.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

import pytest

from app.analysis import build_analysis
from app.conftest import Seeded
from app.core.container import Container
from app.modules.correlation.application.incident_service import IncidentEvidence, _evidence
from app.modules.correlation.domain.graph import EntityGraph, build_graph
from app.modules.correlation.domain.incidents import IncidentQuery
from app.modules.correlation.domain.ports import EvidenceLookup
from app.modules.correlation.domain.timeline import TimelineStep, build_timeline
from app.modules.correlation.infrastructure.unit_of_work import SqlCorrelationUnitOfWork
from app.modules.detection.infrastructure.rule_loader import load_rules
from app.modules.detection.infrastructure.window_store import InMemoryWindowStore
from app.modules.detection.tests.conftest import bus_event
from app.tests.test_correlation_pipeline import Documents, _stories

Workspace = tuple[list[TimelineStep], EntityGraph, IncidentEvidence]


async def _run(
    container: Container, seeded: Seeded, batches: Sequence[Documents], lookup: EvidenceLookup | None = None
) -> None:
    analysis = build_analysis(load_rules(), container.database, InMemoryWindowStore(), lookup=lookup)
    for batch in batches:
        await analysis.handle(bus_event(batch, org_id=seeded.org.id))


async def _workspaces(container: Container, seeded: Seeded) -> dict[str, Workspace]:
    """Keyed by the host in the title (web-01 / ws-fin-07)."""
    found: dict[str, Workspace] = {}
    async with container.database.sessionmaker() as session:
        repo = SqlCorrelationUnitOfWork(session).incidents
        for incident in (await repo.search(seeded.org.id, IncidentQuery(limit=50))).items:
            links = await repo.links(incident.id)
            events = await repo.evidence(incident.id)
            host = "ws-fin-07" if "ws-fin-07" in incident.title else "web-01"
            found[host] = (build_timeline(events, links), build_graph(events), _evidence(links, events))
    return found


def _edges(graph: EntityGraph) -> set[tuple[str, str, str]]:
    return {(edge.source, edge.relation, edge.target) for edge in graph.edges}


async def test_every_step_and_edge_cites_the_incident_evidence(container: Container, seeded: Seeded) -> None:
    await _run(container, seeded, list(_stories(seeded).values()))
    workspaces = await _workspaces(container, seeded)
    assert set(workspaces) == {"web-01", "ws-fin-07"}

    for steps, graph, evidence in workspaces.values():
        cited = set(evidence.cited_by)
        assert evidence.unresolved == [], "every evidence event was in its batch, so every one has a digest"
        assert {event.event_uid for event in evidence.events} == cited
        # The timeline is exactly the evidence: each event in one step, no step without events.
        in_steps = [uid for step in steps for uid in step.events]
        assert sorted(in_steps) == sorted(cited)
        assert all(step.citations for step in steps), "every step is cited by a finding or correlation link"
        for edge in graph.edges:
            assert edge.events
            assert set(edge.events) <= cited
            assert edge.event_count == len(edge.events)
        for node in graph.nodes:
            assert node.events
            assert set(node.events) <= cited
        assert {key for edge in graph.edges for key in (edge.source, edge.target)} == {n.key for n in graph.nodes}


async def test_the_windows_story_reads_in_order(container: Container, seeded: Seeded) -> None:
    await _run(container, seeded, list(_stories(seeded).values()))
    steps, graph, _ = (await _workspaces(container, seeded))["ws-fin-07"]

    assert [(step.action, step.process or step.remote, len(step.events)) for step in steps] == [
        ("Failed logon", "198.51.100.23", 5),
        ("Logged on", "198.51.100.23", 1),
        ("Process started", "powershell.exe", 1),
        ("Process started", "whoami.exe", 1),
        ("Process started", "net.exe", 1),
        ("Network connection", "192.0.2.66", 5),
    ]
    burst, logon, powershell, *_rest, beacon = steps
    assert burst.users == ("acme\\jsmith",)
    assert {c.title for c in burst.citations} == {"Burst of authentication failures for one account from one source"}
    assert [c.rule for c in logon.citations] == ["auth-success-after-failures"]
    assert powershell.command_lines[0].startswith("powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand")
    assert powershell.parent_process == "explorer.exe"
    assert (beacon.remote_ports, beacon.domains) == ((443,), ("cdn-telemetry-sync.example",))

    assert {
        ("ip:198.51.100.23", "failed_logon", "host:ws-fin-07"),
        ("ip:198.51.100.23", "logon", "host:ws-fin-07"),
        ("host:ws-fin-07", "logon_as", "user:acme\\jsmith"),
        ("user:acme\\jsmith", "started", "process:powershell.exe"),
        ("process:powershell.exe", "spawned", "process:whoami.exe"),
        ("process:powershell.exe", "spawned", "process:net.exe"),
        ("host:ws-fin-07", "connected_to", "ip:192.0.2.66"),
        ("ip:192.0.2.66", "named", "domain:cdn-telemetry-sync.example"),
    } <= _edges(graph)
    connection = next(edge for edge in graph.edges if edge.relation == "connected_to")
    assert (connection.event_count, connection.detail) == (5, {"ports": [443]})
    assert "host:fs-01" not in {node.key for node in graph.nodes}, "the SMB session is not evidence"


async def test_the_linux_story_reads_in_order(container: Container, seeded: Seeded) -> None:
    await _run(container, seeded, list(_stories(seeded).values()))
    steps, graph, _ = (await _workspaces(container, seeded))["web-01"]

    assert [(step.action, step.remote, len(step.events)) for step in steps] == [
        ("Failed logon", "203.0.113.45", 7),
        ("Logged on", "203.0.113.45", 1),
    ]
    assert steps[0].users == (
        "admin@web-01",
        "oracle@web-01",
        "test@web-01",
        "root@web-01",
        "ubuntu@web-01",
        "postgres@web-01",
    )
    assert steps[1].users == ("deploy@web-01",)
    assert ("ip:203.0.113.45", "logon", "host:web-01") in _edges(graph)
    assert ("host:web-01", "logon_as", "user:deploy@web-01") in _edges(graph)


class StoredEvents:
    """Stands in for the event store: every delivered document, fetched by event_uid."""

    def __init__(self, documents: Sequence[Mapping[str, Any]], *, fail: bool = False) -> None:
        self.documents = {doc["sx"]["event_uid"]: doc for doc in documents}
        self.fail = fail
        self.requests: list[list[str]] = []

    async def __call__(self, org_id: UUID, event_uids: Sequence[str]) -> Mapping[str, Mapping[str, Any]]:
        self.requests.append(list(event_uids))
        if self.fail:
            raise ConnectionError("event store unreachable")
        return {uid: self.documents[uid] for uid in event_uids if uid in self.documents}


def _one_by_one(seeded: Seeded) -> list[Documents]:
    stories = _stories(seeded)
    return [[doc] for doc in sorted((d for docs in stories.values() for d in docs), key=lambda d: d["time"])]


async def test_evidence_from_earlier_batches_is_fetched_from_the_event_store(
    container: Container, seeded: Seeded
) -> None:
    batches = _one_by_one(seeded)
    store = StoredEvents([doc for batch in batches for doc in batch])
    await _run(container, seeded, batches, lookup=store)

    for steps, _, evidence in (await _workspaces(container, seeded)).values():
        assert evidence.unresolved == []
        assert sorted(uid for step in steps for uid in step.events) == sorted(evidence.cited_by)
    # Only threshold findings reach back to earlier batches, and only for the events they lacked.
    assert store.requests
    assert all(len(request) <= 100 for request in store.requests)


async def test_without_the_event_store_earlier_evidence_is_reported_unresolved(
    container: Container, seeded: Seeded, caplog: pytest.LogCaptureFixture
) -> None:
    batches = _one_by_one(seeded)
    store = StoredEvents([], fail=True)
    with caplog.at_level(logging.WARNING):
        await _run(container, seeded, batches, lookup=store)

    workspaces = await _workspaces(container, seeded)
    assert set(workspaces) == {"web-01", "ws-fin-07"}, "correlation still happens"
    unresolved = {uid for _, _, evidence in workspaces.values() for uid in evidence.unresolved}
    assert unresolved, "the threshold findings' earlier events could not be fetched"
    for steps, _, evidence in workspaces.values():
        shown = {uid for step in steps for uid in step.events}
        assert shown.isdisjoint(evidence.unresolved)
        assert shown | set(evidence.unresolved) == set(evidence.cited_by)
    assert "evidence lookup failed" in caplog.text
