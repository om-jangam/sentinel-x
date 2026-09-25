"""Detection end to end on the shipped attack stories, plus threshold window behaviour."""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

import fakeredis.aioredis
import pytest

from app.modules.detection.application.detection_service import DetectionService
from app.modules.detection.domain.ports import WindowEntry
from app.modules.detection.domain.rules import RuleSet
from app.modules.detection.infrastructure.rule_loader import compile_threshold, load_rules
from app.modules.detection.infrastructure.window_store import InMemoryWindowStore, RedisWindowStore
from app.modules.detection.tests.conftest import (
    SAMPLE_SETS,
    MemoryFindings,
    bus_event,
    document,
    memory_uow_factory,
    sample_documents,
)

# What the two sample stories fire, own rules and the SigmaHQ pack together.
EXPECTED = {
    "Authentication failures across many accounts from one source": 1,
    "Burst of authentication failures for one account from one source": 1,
    "PowerShell started with an encoded command": 1,
    "whoami used to list privileges or groups": 1,
    "net.exe lists the Domain Admins group": 1,
    "Repeated connections from one host to the same external destination": 1,
    "SSH authentication attempt for a user that does not exist": 6,
    # SigmaHQ community rules on the same encoded PowerShell command line.
    "PowerShell Base64 Encoded IEX Cmdlet": 1,
    "Suspicious Encoded PowerShell Command Line": 1,
    "Suspicious PowerShell Encoded Command Patterns": 1,
}


def service(findings: MemoryFindings, rules: RuleSet | None = None) -> DetectionService:
    return DetectionService(
        rules or load_rules(), uow_factory=memory_uow_factory(findings), windows=InMemoryWindowStore()
    )


async def test_sample_attack_stories_produce_exactly_the_expected_findings() -> None:
    findings = MemoryFindings()
    detector = service(findings)
    delivered: dict[str, dict[str, Any]] = {}
    for filename, parser in SAMPLE_SETS:
        documents = sample_documents(filename, parser)
        delivered.update({doc["sx"]["event_uid"]: doc for doc in documents})
        await detector.handle(bus_event(documents))

    assert Counter(f.rule_title for f in findings.all) == EXPECTED

    # Evidence integrity: every cited event is one that was actually delivered, in event-time order.
    for finding in findings.all:
        assert set(finding.evidence) <= set(delivered)
        times = [delivered[uid]["time"] for uid in finding.evidence]
        assert times == sorted(times)
        assert finding.first_seen <= finding.last_seen


async def test_detection_runs_cleanly_with_info_logging_enabled(caplog: pytest.LogCaptureFixture) -> None:
    """Production logs at INFO; a broken log call there must fail this test, not the worker."""
    caplog.set_level(logging.INFO)
    findings = MemoryFindings()
    await service(findings).handle(bus_event(sample_documents("windows_security.jsonl", "windows_security")))
    assert any(record.getMessage() == "findings created" for record in caplog.records)
    windows_titles = {
        title
        for title in EXPECTED
        if "SSH" not in title and "many accounts" not in title and "Repeated connections" not in title
    }
    assert {finding.rule_title for finding in findings.all} == windows_titles


async def test_redelivered_batches_create_no_duplicate_findings() -> None:
    findings = MemoryFindings()
    detector = service(findings)
    batches = [sample_documents(filename, parser) for filename, parser in SAMPLE_SETS]
    for _ in range(3):
        for documents in batches:
            await detector.handle(bus_event(documents))
    assert sum(EXPECTED.values()) == len(findings.all)


async def test_threshold_findings_name_their_entities_and_evidence() -> None:
    findings = MemoryFindings()
    await service(findings).handle(bus_event(sample_documents("linux_auth.log", "linux_auth")))
    spray = next(f for f in findings.all if f.rule_title.startswith("Authentication failures across"))

    assert spray.entities["src_endpoint.ip"] == ["203.0.113.45"]
    assert len(spray.entities["user.name"]) == 4
    assert len(spray.evidence) == 5, "the invalid-user probe and four failed accounts"
    assert spray.techniques == ("T1110.003",)
    assert spray.severity_id == 3


async def test_background_activity_raises_nothing() -> None:
    findings = MemoryFindings()
    detector = service(findings)
    benign = [
        doc for doc in sample_documents("linux_auth.log", "linux_auth") if doc.get("user", {}).get("name") == "alice"
    ]
    assert len(benign) == 2
    await detector.handle(bus_event(benign))
    assert findings.all == []


RULE = """
id: 4f8b2c6d-1a37-4e95-b0c2-7d6e9f1a3b58
title: three failures
level: low
tags: [attack.t1110]
match: {class_uid: 3002}
group_by: [src_endpoint.ip]
threshold: 3
window: 60s
"""


def failure(ip: str, second: int, uid: str) -> dict[str, Any]:
    return {
        "class_uid": 3002,
        "time": 1_789_460_000_000 + second * 1000,
        "src_endpoint": {"ip": ip},
        "sx": {"event_uid": uid},
    }


async def test_threshold_windows_groups_cooldown_and_late_events() -> None:
    findings = MemoryFindings()
    detector = service(findings, RuleSet(threshold=(compile_threshold(RULE, path="t.yml"),)))

    # Two groups interleaved: only the one that reaches 3 within 60 s fires.
    await detector.handle(bus_event([failure("198.51.100.1", 0, "a1"), failure("198.51.100.2", 1, "b1")]))
    await detector.handle(bus_event([failure("198.51.100.1", 20, "a2"), failure("198.51.100.1", 40, "a3")]))
    assert [f.evidence for f in findings.all] == [("a1", "a2", "a3")]

    # Within the window the group doesn't fire again.
    await detector.handle(bus_event([failure("198.51.100.1", 50, "a4")]))
    assert len(findings.all) == 1

    # Events spread wider than the window don't add up.
    await detector.handle(bus_event([failure("198.51.100.2", 100, "b2"), failure("198.51.100.2", 200, "b3")]))
    assert len(findings.all) == 1

    # After the window, a fresh burst fires again with only its own evidence.
    await detector.handle(bus_event([failure("198.51.100.1", 300 + s, f"c{s}") for s in range(3)]))
    assert [f.evidence for f in findings.all][-1] == ("c0", "c1", "c2")

    # An event without the grouping field can't be attributed and is ignored.
    await detector.handle(bus_event([{"class_uid": 3002, "time": 1, "sx": {"event_uid": "x"}}]))
    assert len(findings.all) == 2


async def test_messages_without_org_or_evidence_ids_are_ignored() -> None:
    findings = MemoryFindings()
    detector = service(findings)
    documents = sample_documents("windows_security.jsonl", "windows_security")
    event = bus_event(documents)
    await detector.handle(event.__class__(topic=event.topic, payload=event.payload, org_id=None))
    for doc in documents:
        doc["sx"].pop("event_uid")
    await detector.handle(bus_event(documents))
    assert findings.all == []


@pytest.fixture(params=["memory", "redis"])
async def window_store(request: pytest.FixtureRequest) -> Any:
    if request.param == "memory":
        return InMemoryWindowStore()
    return RedisWindowStore(fakeredis.aioredis.FakeRedis())


async def test_window_stores_are_idempotent_windowed_and_remember_firing(window_store: Any) -> None:
    add = window_store.add
    assert [e.event_uid for e in await add("k", WindowEntry("a", 1_000, "alice"), window_ms=1_000)] == ["a"]
    assert len(await add("k", WindowEntry("a", 1_000, "alice"), window_ms=1_000)) == 1, "same event twice"
    entries = await add("k", WindowEntry("b", 1_900, "bob"), window_ms=1_000)
    assert {(e.event_uid, e.at_ms, e.value) for e in entries} == {("a", 1_000, "alice"), ("b", 1_900, "bob")}
    later = await add("k", WindowEntry("c", 2_500, None), window_ms=1_000)
    assert {e.event_uid for e in later} == {"b", "c"}, "a fell out of the window"
    assert {e.event_uid for e in await add("other", WindowEntry("z", 2_500, None), window_ms=1_000)} == {"z"}

    assert await window_store.last_fired("k") is None
    await window_store.mark_fired("k", 2_500, window_ms=1_000)
    assert await window_store.last_fired("k") == 2_500


class RecordingSink:
    def __init__(self) -> None:
        self.calls: list[tuple[list[Any], int]] = []

    async def __call__(self, org_id: Any, findings: Any, documents: Any) -> None:
        self.calls.append((list(findings), len(documents)))


async def test_the_sink_sees_stored_findings_for_every_batch_even_when_redelivered() -> None:
    findings = MemoryFindings()
    sink = RecordingSink()
    detector = DetectionService(
        load_rules(), uow_factory=memory_uow_factory(findings), windows=InMemoryWindowStore(), on_findings=sink
    )
    linux = sample_documents("linux_auth.log", "linux_auth")
    benign = [doc for doc in linux if (doc.get("user") or {}).get("name") == "alice"]

    await detector.handle(bus_event(linux))
    await detector.handle(bus_event(linux))  # redelivered after a downstream failure
    await detector.handle(bus_event(benign))  # no findings, but correlation still reads the events

    first, again, quiet = sink.calls
    assert len(first[0]) == 7
    assert first[1] == len(linux)
    # The redelivery hands over the findings already stored (same ids), including the threshold finding,
    # so a correlation step that failed the first time gets another chance.
    assert [f.id for f in again[0]] == [f.id for f in first[0]]
    assert len(findings.all) == 7
    assert quiet == ([], len(benign))


async def test_ntlm_spray_fires_on_many_accounts_from_one_workstation_but_not_on_normal_use() -> None:
    """The audit records show attempts, not failures; what marks a spray is how many accounts are tried."""
    from app.ingest_pipeline.tests.test_windows_ntlm import AUDIT, EVENT_DATA

    def attempt(user: str, station: str, second: int) -> dict[str, Any]:
        record = {
            **AUDIT,
            "TimeCreated": f"2024-01-18T05:00:{second:02d}Z",
            "EventRecordID": f"{station}-{user}",
            "EventData": {**EVENT_DATA, "UserName": user, "WorkstationName": station},
        }
        return document(record, "windows_ntlm")

    spray = [attempt(f"user{i:02d}", "WIN-ATTACKER", i) for i in range(12)]
    normal = [attempt(user, "WIN-DESK-01", 30) for user in ("jsmith", "backup")]

    findings = MemoryFindings()
    await service(findings).handle(bus_event(spray + normal))

    fired = [f for f in findings.all if "NTLM" in f.rule_title]
    assert len(fired) == 1, "one spray, one finding"
    assert fired[0].entities["src_endpoint.hostname"] == ["WIN-ATTACKER"]
    assert len(fired[0].entities["user.name"]) >= 10, "the accounts it worked through"
    assert fired[0].techniques == ("T1110.003",)
