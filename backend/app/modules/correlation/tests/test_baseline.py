"""What the organisation has seen before: what gets counted, and what "new" means."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.modules.correlation.domain.baseline import (
    HOST_REMOTE,
    PROCESS_PAIR,
    REMOTE,
    Baseline,
    Observation,
    batch_observations,
    evidence_observations,
    novelty,
    observations,
)
from app.modules.correlation.domain.evidence import digest

WHEN = datetime(2026, 9, 15, 9, 42, tzinfo=UTC)
AT_MS = int(WHEN.timestamp() * 1000)


def process_event(**overrides: Any) -> dict[str, Any]:
    return {
        "class_uid": 1007,
        "activity_id": 1,
        "status_id": 1,
        "time": AT_MS,
        "sx": {"event_uid": "e-1"},
        "device": {"hostname": "WS-FIN-07"},
        "process": {"name": "powershell.exe", "parent_process": {"name": "WINWORD.EXE"}},
        "actor": {"user": {"name": "jsmith", "domain": "corp"}},
        **overrides,
    }


def network_event(**overrides: Any) -> dict[str, Any]:
    return {
        "class_uid": 4001,
        "activity_id": 1,
        "status_id": 1,
        "time": AT_MS,
        "sx": {"event_uid": "e-2"},
        "device": {"hostname": "ws-fin-07"},
        "src_endpoint": {"ip": "10.20.30.47"},
        "dst_endpoint": {"ip": "192.0.2.66", "port": 443},
        **overrides,
    }


def test_a_process_event_counts_the_parent_child_pair() -> None:
    assert observations(process_event()) == [Observation(PROCESS_PAIR, "winword.exe -> powershell.exe")]


def test_a_connection_counts_the_destination_and_the_host_that_reached_it() -> None:
    assert observations(network_event()) == [
        Observation(REMOTE, "192.0.2.66"),
        Observation(HOST_REMOTE, "ws-fin-07 -> 192.0.2.66"),
    ]


def test_internal_traffic_is_not_a_destination() -> None:
    internal = network_event(dst_endpoint={"ip": "10.20.30.9"}, src_endpoint={"ip": "10.20.30.47"})
    assert observations(internal) == []


def test_a_dns_answer_counts_the_domain() -> None:
    dns = {
        "class_uid": 4003,
        "activity_id": 1,
        "time": AT_MS,
        "sx": {"event_uid": "e-3"},
        "device": {"hostname": "ws-fin-07"},
        "query": {"hostname": "update.bad.example"},
    }
    assert Observation(REMOTE, "update.bad.example") in observations(dns)


def test_a_batch_counts_repeats_once_per_key_in_event_time() -> None:
    later = AT_MS + 60_000
    counted = batch_observations([process_event(), process_event(sx={"event_uid": "e-9"}, time=later), network_event()])
    pair = counted[Observation(PROCESS_PAIR, "winword.exe -> powershell.exe")]
    assert pair.count == 2
    assert (pair.first_seen, pair.last_seen) == (WHEN, WHEN + timedelta(minutes=1)), "the events' own time"
    assert counted[Observation(REMOTE, "192.0.2.66")].count == 1


def test_an_event_without_a_time_cannot_be_placed_in_a_baseline() -> None:
    assert batch_observations([{**process_event(), "time": None}]) == {}


def test_the_write_path_and_the_read_path_agree() -> None:
    """A baseline written from documents and read from stored evidence must use the same keys."""
    for document in (process_event(), network_event()):
        event = digest(document)
        assert event is not None
        assert evidence_observations(event) == observations(document), document["class_uid"]


def baseline(key: str, kind: str, *, first_seen: datetime, observations_count: int = 5) -> Baseline:
    return Baseline(kind, key, first_seen, first_seen + timedelta(days=1), observations_count)


def test_something_first_seen_in_this_incident_is_new() -> None:
    keys = [Observation(PROCESS_PAIR, "winword.exe -> powershell.exe"), Observation(REMOTE, "192.0.2.66")]
    known = {
        (PROCESS_PAIR, "winword.exe -> powershell.exe"): baseline(
            "winword.exe -> powershell.exe", PROCESS_PAIR, first_seen=WHEN, observations_count=1
        ),
        (REMOTE, "192.0.2.66"): baseline("192.0.2.66", REMOTE, first_seen=WHEN - timedelta(days=20)),
    }
    [pair, remote] = novelty(keys, known, incident_first_seen=WHEN)

    assert pair.new_here is True
    assert "first seen in this incident" in pair.describe()
    assert remote.new_here is False
    assert remote.describe() == "192.0.2.66: seen 5 times, first on 2026-08-26"


def test_a_key_with_no_baseline_row_is_reported_not_guessed() -> None:
    [item] = novelty([Observation(REMOTE, "203.0.113.9")], {}, incident_first_seen=WHEN)
    assert item.new_here is True
    assert item.observations == 0
    assert item.describe() == "203.0.113.9: never seen outside this incident"


def test_new_things_are_listed_first() -> None:
    keys = [Observation(REMOTE, "a.example"), Observation(REMOTE, "b.example")]
    known = {(REMOTE, "b.example"): baseline("b.example", REMOTE, first_seen=WHEN - timedelta(days=5))}
    assert [item.key for item in novelty(keys, known, incident_first_seen=WHEN)] == ["a.example", "b.example"]
