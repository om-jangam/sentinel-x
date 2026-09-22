"""Evidence digests, timeline grouping and graph relations on hand-built events."""

from __future__ import annotations

from typing import Any

from app.modules.correlation.domain.evidence import digest
from app.modules.correlation.domain.graph import build_graph, relations
from app.modules.correlation.domain.timeline import build_timeline

MINUTE_MS = 60_000


def doc(uid: str, class_uid: int, at_ms: int = 1_757_930_000_000, **fields: Any) -> dict[str, Any]:
    return {"class_uid": class_uid, "time": at_ms, "sx": {"event_uid": uid}, **fields}


def failed_logon(uid: str, at_ms: int) -> dict[str, Any]:
    return doc(
        uid,
        3002,
        at_ms,
        activity_id=1,
        status_id=2,
        device={"hostname": "web-01"},
        src_endpoint={"ip": "203.0.113.9"},
        user={"name": "root"},
    )


def test_digest_needs_identity_and_class() -> None:
    assert digest({"class_uid": 3002, "time": 1}) is None
    assert digest({"time": 1, "sx": {"event_uid": "e"}}) is None


def test_actions_fall_back_to_the_event_own_activity_name() -> None:
    event = digest(doc("e", 2004, activity_name="Create"))
    assert event is not None
    assert event.action == "Create"
    unnamed = digest(doc("e", 2004))
    assert unnamed is not None
    assert unnamed.action == "OCSF class 2004"


def test_digests_cap_what_they_copy() -> None:
    event = digest(
        doc("e", 1007, activity_id=1, raw_data="r" * 5000, process={"name": "a.exe", "cmd_line": "c" * 5000})
    )
    assert event is not None
    assert len(event.raw or "") == 2048
    assert len(event.detail["cmd_line"]) == 1024


def test_repeated_actions_fold_into_one_step_unless_far_apart() -> None:
    start = 1_757_930_000_000
    events = [
        digest(failed_logon("a", start)),
        digest(failed_logon("b", start + 2 * MINUTE_MS)),
        digest(failed_logon("c", start + 30 * MINUTE_MS)),  # a separate burst
    ]
    steps = build_timeline([e for e in events if e], [])
    assert [step.events for step in steps] == [("a", "b"), ("c",)]
    assert steps[0].users == ("root@web-01",)
    assert steps[0].citations == ()


def test_a_process_without_a_user_hangs_off_its_host() -> None:
    event = digest(doc("p", 1007, activity_id=1, device={"hostname": "srv"}, process={"name": "cron"}))
    assert event is not None
    assert relations(event) == [("host:srv", "started", "process:cron")]


def test_dns_answers_become_resolution_edges() -> None:
    event = digest(
        doc(
            "d",
            4003,
            activity_id=1,
            src_endpoint={"ip": "10.0.5.17", "hostname": "WS-1"},
            dst_endpoint={"ip": "10.0.0.53"},
            query={"hostname": "evil.example"},
            answers=[{"rdata": "192.0.2.7"}, {"rdata": "not-an-ip"}],
        )
    )
    assert event is not None
    assert set(relations(event)) == {
        ("host:ws-1", "queried", "domain:evil.example"),
        ("domain:evil.example", "resolved_to", "ip:192.0.2.7"),
    }


def test_file_activity_links_host_file_and_hash() -> None:
    event = digest(
        doc(
            "f",
            1001,
            activity_id=1,
            device={"hostname": "h"},
            file={"path": "/srv/drop/x", "hashes": [{"algorithm_id": 3, "value": "AA" * 32}]},
        )
    )
    assert event is not None
    assert set(relations(event)) == {
        ("host:h", "file_activity", "file:/srv/drop/x"),
        ("file:/srv/drop/x", "hash", f"hash:{'aa' * 32}"),
    }


def test_an_event_says_nothing_about_relations_it_does_not_state() -> None:
    logoff = digest(doc("o", 3002, activity_id=2, status_id=1, device={"hostname": "h"}, user={"name": "u"}))
    assert logoff is not None
    assert relations(logoff) == []
    assert build_graph([logoff]).edges == []
    assert build_graph([logoff]).nodes == []


def test_graph_counts_each_event_once_per_edge() -> None:
    start = 1_757_930_000_000
    events = [e for e in (digest(failed_logon(uid, start + i)) for i, uid in enumerate("abc")) if e]
    graph = build_graph(events + events)  # the same events twice
    edge = next(e for e in graph.edges if e.relation == "failed_logon")
    assert (edge.event_count, edge.events) == (3, ["a", "b", "c"])
    assert [n.key for n in graph.nodes] == ["ip:203.0.113.9", "host:web-01", "user:root@web-01"]
    assert graph.nodes[0].external
