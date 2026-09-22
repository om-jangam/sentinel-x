"""Phase 3 acceptance: the sample attack stories become incidents built only from evidence-backed links.

Runs the production composition (`build_analysis`: detection → stored findings → correlation) against SQL.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import func, select

from app.analysis import build_analysis
from app.conftest import Seeded
from app.core.audit.models import AuditLogModel
from app.core.container import Container
from app.modules.correlation.domain.incidents import (
    CorrelationRule,
    IncidentDetail,
    IncidentQuery,
    IncidentStatus,
    LinkKind,
)
from app.modules.correlation.infrastructure.unit_of_work import SqlCorrelationUnitOfWork
from app.modules.detection.infrastructure.models import FindingModel
from app.modules.detection.infrastructure.rule_loader import load_rules
from app.modules.detection.infrastructure.window_store import InMemoryWindowStore
from app.modules.detection.tests.conftest import SAMPLE_SETS, bus_event, sample_documents

Documents = list[dict[str, Any]]


def _stories(seeded: Seeded) -> dict[str, Documents]:
    return {parser: sample_documents(filename, parser, org_id=seeded.org.id) for filename, parser in SAMPLE_SETS}


def _uid(document: dict[str, Any]) -> str:
    uid: str = document["sx"]["event_uid"]
    return uid


async def _run(container: Container, seeded: Seeded, batches: Sequence[Documents]) -> None:
    analysis = build_analysis(load_rules(), container.database, InMemoryWindowStore())
    for batch in batches:
        await analysis.handle(bus_event(batch, org_id=seeded.org.id))


async def _incidents(container: Container, seeded: Seeded) -> list[IncidentDetail]:
    async with container.database.sessionmaker() as session:
        repo = SqlCorrelationUnitOfWork(session).incidents
        page = await repo.search(seeded.org.id, IncidentQuery(limit=50))
        return [
            IncidentDetail(incident, await repo.links(incident.id), await repo.entities(incident.id))
            for incident in page.items
        ]


def _by_host(details: list[IncidentDetail]) -> dict[str, IncidentDetail]:
    return {
        next(e.value for e in detail.entities if e.type == "host"): detail
        for detail in details
        if any(e.type == "host" for e in detail.entities)
    }


async def test_each_story_becomes_one_incident(container: Container, seeded: Seeded) -> None:
    stories = _stories(seeded)
    await _run(container, seeded, list(stories.values()))

    details = await _incidents(container, seeded)
    assert len(details) == 2
    incidents = _by_host(details)
    assert set(incidents) == {"web-01", "ws-fin-07"}

    web = incidents["web-01"]
    assert web.incident.title == "Successful logon after repeated failures from 203.0.113.45 on web-01"
    assert web.incident.finding_count == 7  # six invalid-user attempts and the spray
    assert web.incident.severity == "High"
    assert web.incident.status is IncidentStatus.NEW
    [success] = [link for link in web.links if link.kind is LinkKind.EVENT]
    assert success.rule is CorrelationRule.AUTH_SUCCESS_AFTER_FAILURES
    accepted = next(d for d in stories["linux_auth"] if "Accepted password" in str(d.get("raw_data", "")))
    assert success.evidence == (_uid(accepted),)
    assert {m.key for m in success.matched} == {"ip:203.0.113.45", "host:web-01"}

    windows = incidents["ws-fin-07"]
    rules = {link.detail.get("rule_title") for link in windows.links if link.kind is LinkKind.FINDING}
    assert rules == {
        "Burst of authentication failures for one account from one source",
        "PowerShell started with an encoded command",
        "whoami used to list privileges or groups",
        "net.exe lists the Domain Admins group",
        "Repeated connections from one host to the same external destination",
        # SigmaHQ community rules on the same encoded PowerShell command line.
        "PowerShell Base64 Encoded IEX Cmdlet",
        "Suspicious Encoded PowerShell Command Line",
        "Suspicious PowerShell Encoded Command Patterns",
    }
    assert windows.incident.severity == "Critical"
    assert {a["rule"] for a in windows.incident.assessment} == {
        "highest-finding-severity",
        "credential-compromise",
        "multi-stage",
        "compromise-then-activity",
    }
    assert windows.incident.title == (
        "Successful logon after repeated failures from 198.51.100.23, "
        "then execution, defense evasion, discovery, command and control on ws-fin-07"
    )
    beacon = next(link for link in windows.links if "Repeated connections" in str(link.detail.get("rule_title")))
    # The network story joins because its events name the same machine as the Windows events.
    assert beacon.rule is CorrelationRule.SHARED_ENTITY
    assert "host:ws-fin-07" in {m.key for m in beacon.matched}
    [rdp] = [link for link in windows.links if link.kind is LinkKind.EVENT]
    assert rdp.rule is CorrelationRule.AUTH_SUCCESS_AFTER_FAILURES


async def test_background_activity_stays_out(container: Container, seeded: Seeded) -> None:
    stories = _stories(seeded)
    await _run(container, seeded, list(stories.values()))

    background = {_uid(d) for d in stories["linux_auth"] if (d.get("user") or {}).get("name") == "alice"} | {
        _uid(d) for d in stories["ocsf"] if (d.get("dst_endpoint") or {}).get("hostname") == "FS-01"
    }
    first_logon = next(d for d in stories["windows_security"] if d.get("logon_type_id") == 2)
    background.add(_uid(first_logon))  # the morning console logon precedes the attack
    assert len(background) == 4

    for detail in await _incidents(container, seeded):
        cited = {uid for link in detail.links for uid in link.evidence}
        seen = {uid for entity in detail.entities for uid in entity.events}
        assert not background & (cited | seen)
        assert "host:fs-01" not in {entity.key for entity in detail.entities}


async def test_every_link_and_entity_cites_stored_evidence(container: Container, seeded: Seeded) -> None:
    stories = _stories(seeded)
    await _run(container, seeded, list(stories.values()))
    delivered = {_uid(d) for documents in stories.values() for d in documents}

    async with container.database.sessionmaker() as session:
        findings = {row.id: set(row.evidence) for row in await session.scalars(select(FindingModel))}
    for detail in await _incidents(container, seeded):
        in_incident = {uid for link in detail.links for uid in link.evidence}
        assert in_incident <= delivered
        for link in detail.links:
            assert link.evidence
            if link.kind is LinkKind.FINDING:
                assert link.finding_id in findings
                assert set(link.evidence) == findings[link.finding_id]
            if link.rule is not CorrelationRule.OPENED:
                assert link.matched, "every correlation link names the entities that justify it"
            earlier = {uid for other in detail.links if other.created_at <= link.created_at for uid in other.evidence}
            for match in link.matched:
                # One side is the linked item's own evidence, the other is evidence already in the incident.
                assert match.new_events
                assert set(match.new_events) <= set(link.evidence)
                assert match.incident_events
                assert set(match.incident_events) <= earlier
        for entity in detail.entities:
            assert entity.events
            assert set(entity.events) <= in_incident


async def test_redelivery_changes_nothing(container: Container, seeded: Seeded) -> None:
    stories = list(_stories(seeded).values())
    await _run(container, seeded, stories)
    before = [(d.incident.id, d.incident.version, len(d.links)) for d in await _incidents(container, seeded)]
    async with container.database.sessionmaker() as session:
        audits = await session.scalar(select(func.count()).select_from(AuditLogModel))

    await _run(container, seeded, stories)  # every batch again, as after a worker crash

    after = [(d.incident.id, d.incident.version, len(d.links)) for d in await _incidents(container, seeded)]
    assert after == before
    async with container.database.sessionmaker() as session:
        assert await session.scalar(select(func.count()).select_from(AuditLogModel)) == audits


async def test_arrival_order_does_not_change_the_incidents(container: Container, seeded: Seeded) -> None:
    stories = _stories(seeded)
    # One event per batch, in event-time order across every source: the harshest delivery pattern.
    events = sorted((d for documents in stories.values() for d in documents), key=lambda d: d["time"])
    await _run(container, seeded, [[d] for d in events])

    incidents = _by_host(await _incidents(container, seeded))
    assert set(incidents) == {"web-01", "ws-fin-07"}
    assert incidents["web-01"].incident.finding_count == 7
    assert incidents["ws-fin-07"].incident.finding_count == 8
    assert all(any(link.kind is LinkKind.EVENT for link in detail.links) for detail in incidents.values()), (
        "the successful logon still completes each story"
    )


async def test_sources_delivered_in_reverse_still_join(container: Container, seeded: Seeded) -> None:
    stories = _stories(seeded)
    await _run(container, seeded, [stories["ocsf"], stories["windows_security"], stories["linux_auth"]])
    incidents = _by_host(await _incidents(container, seeded))
    assert set(incidents) == {"web-01", "ws-fin-07"}
    assert incidents["ws-fin-07"].incident.finding_count == 8


async def test_opening_and_correlating_are_audited_as_system(container: Container, seeded: Seeded) -> None:
    await _run(container, seeded, list(_stories(seeded).values()))
    async with container.database.sessionmaker() as session:
        rows = list(await session.scalars(select(AuditLogModel).where(AuditLogModel.resource_type == "incident")))
    # Linux and Windows each open an incident; the network batch arrives later and joins WS-FIN-07's.
    assert sorted(row.action for row in rows) == ["incident.correlated", "incident.opened", "incident.opened"]
    correlated = next(row for row in rows if row.action == "incident.correlated")
    assert correlated.context == {"links_added": 1}
    assert correlated.before is not None
    assert correlated.after is not None
    assert all(row.actor_type == "system" and row.actor_id is None for row in rows)
