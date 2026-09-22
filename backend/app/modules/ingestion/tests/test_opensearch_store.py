"""The OpenSearch adapter against a stubbed client: what it asks the cluster for, and how it reads replies.

These pin the security- and correctness-relevant translation (org scoping on every query, no raw query
pass-through, idempotent writes, bounded mappings). They do not prove behaviour against a live cluster.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID

import pytest

from app.core.config import Environment, Settings
from app.ingest_pipeline.ocsf import CATEGORY_SLUGS
from app.modules.ingestion.domain.events import EventCursor, EventDocument, EventQuery
from app.modules.ingestion.infrastructure.opensearch_store import (
    INDEX_PATTERN,
    MAPPINGS,
    OpenSearchEventStore,
    event_store_from_settings,
    write_alias,
)

ORG = UUID("01a0aaa3-c9b6-7213-b363-20af5c5823ee")
FROM = datetime(2026, 9, 15, tzinfo=UTC)
TO = datetime(2026, 9, 16, tzinfo=UTC)


def query(**filters: Any) -> EventQuery:
    return EventQuery(time_from=FROM, time_to=TO, **filters)


def stub_client(**overrides: Any) -> SimpleNamespace:
    client = SimpleNamespace(
        ping=AsyncMock(return_value=True),
        bulk=AsyncMock(return_value={"items": []}),
        search=AsyncMock(return_value={"took": 3, "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}),
        close=AsyncMock(),
        transport=SimpleNamespace(perform_request=AsyncMock()),
        indices=SimpleNamespace(
            put_index_template=AsyncMock(),
            put_mapping=AsyncMock(),
            exists_alias=AsyncMock(return_value=False),
            create=AsyncMock(),
        ),
    )
    for name, value in overrides.items():
        setattr(client, name, value)
    return client


def store_with(client: SimpleNamespace) -> OpenSearchEventStore:
    return OpenSearchEventStore(client)  # type: ignore[arg-type]


def sent_body(client: SimpleNamespace) -> dict[str, Any]:
    body: dict[str, Any] = client.search.await_args.kwargs["body"]
    return body


# ------------------------------------------------------------------ queries
async def test_every_search_is_scoped_to_the_org_and_time_window() -> None:
    client = stub_client()
    await store_with(client).search(ORG, query())

    assert client.search.await_args.kwargs["index"] == INDEX_PATTERN
    body = sent_body(client)
    filters = body["query"]["bool"]["filter"]
    assert filters[0] == {"term": {"sx.org_id": str(ORG)}}
    assert filters[1] == {"range": {"@timestamp": {"gte": FROM.isoformat(), "lte": TO.isoformat()}}}
    assert body["sort"] == [{"@timestamp": "desc"}, {"sx.event_uid": "desc"}]
    assert body["track_total_hits"] == 10_000
    assert "search_after" not in body


async def test_filters_become_constrained_clauses() -> None:
    client = stub_client()
    source = UUID("01a0aaa3-0000-7000-8000-000000000001")
    filtered = query(
        class_uids=(3002, 1007),
        severity_min=3,
        status_id=2,
        source_id=source,
        ip="203.0.113.45",
        user_name="Deploy",
        hostname="WEB-01",
    )
    await store_with(client).search(ORG, filtered)

    filters = sent_body(client)["query"]["bool"]["filter"]
    assert {"terms": {"class_uid": [3002, 1007]}} in filters
    assert {"range": {"severity_id": {"gte": 3}}} in filters
    assert {"term": {"status_id": 2}} in filters
    assert {"term": {"sx.source_id": str(source)}} in filters

    by_fields = {
        tuple(next(iter(clause["term"])) for clause in f["bool"]["should"]): f["bool"] for f in filters if "bool" in f
    }
    ip_clause = by_fields[("src_endpoint.ip", "dst_endpoint.ip", "device.ip")]
    assert ip_clause["minimum_should_match"] == 1
    assert ip_clause["should"][0]["term"]["src_endpoint.ip"] == {"value": "203.0.113.45"}
    user_clause = by_fields[("user.name", "actor.user.name")]
    assert user_clause["should"][0]["term"]["user.name"] == {"value": "Deploy", "case_insensitive": True}
    assert ("device.hostname", "src_endpoint.hostname", "dst_endpoint.hostname") in by_fields


async def test_free_text_is_a_simple_query_string_never_raw_dsl() -> None:
    client = stub_client()
    hostile = '{"query": {"match_all": {}}}'
    await store_with(client).search(ORG, query(text=hostile))

    must = sent_body(client)["query"]["bool"]["must"]
    assert len(must) == 1
    simple = must[0]["simple_query_string"]
    assert simple["query"] == hostile, "passed through as text to match, not parsed as a query"
    assert simple["fields"] == ["message", "raw_data", "process.cmd_line", "query.hostname"]
    assert "match_all" not in str(sent_body(client)["query"]["bool"]["filter"])


async def test_cursor_becomes_search_after() -> None:
    client = stub_client()
    cursor = EventCursor(time_ms=1_789_463_642_519, event_uid="evt-9")
    await store_with(client).search(ORG, query(cursor=cursor))

    assert sent_body(client)["search_after"] == [1_789_463_642_519, "evt-9"]


async def test_search_reply_becomes_a_page_with_a_cursor_only_when_full() -> None:
    hits = [
        {"_source": {"sx": {"event_uid": "a"}}, "sort": [2000, "a"]},
        {"_source": {"sx": {"event_uid": "b"}}, "sort": [1000, "b"]},
    ]
    reply = {"took": 7, "hits": {"total": {"value": 10000, "relation": "gte"}, "hits": hits}}

    full = await store_with(stub_client(search=AsyncMock(return_value=reply))).search(ORG, query(limit=2))
    partial = await store_with(stub_client(search=AsyncMock(return_value=reply))).search(ORG, query(limit=5))

    assert [item["sx"]["event_uid"] for item in full.items] == ["a", "b"]
    assert (full.total, full.total_is_lower_bound, full.took_ms) == (10000, True, 7)
    assert full.next_cursor == EventCursor(time_ms=1000, event_uid="b")
    assert partial.next_cursor is None


async def test_single_event_lookup_is_org_scoped() -> None:
    client = stub_client()
    assert await store_with(client).get(ORG, "evt-1") is None

    filters = sent_body(client)["query"]["bool"]["filter"]
    assert {"term": {"sx.org_id": str(ORG)}} in filters
    assert {"term": {"sx.event_uid": "evt-1"}} in filters


async def test_batch_lookup_is_org_scoped_bounded_and_keyed_by_event_uid() -> None:
    hits = [
        {"_source": {"sx": {"event_uid": "evt-1", "org_id": str(ORG)}, "time": 1}},
        {"_source": {"sx": {"event_uid": "not-asked-for"}}},
    ]
    client = stub_client(search=AsyncMock(return_value={"hits": {"hits": hits}}))
    found = await store_with(client).get_many(ORG, ["evt-2", "evt-1", "evt-1"])

    assert list(found) == ["evt-1"], "only requested events come back, whatever the cluster returns"
    body = sent_body(client)
    assert {"term": {"sx.org_id": str(ORG)}} in body["query"]["bool"]["filter"]
    assert {"terms": {"sx.event_uid": ["evt-1", "evt-2"]}} in body["query"]["bool"]["filter"]
    assert body["size"] == 2

    many = stub_client()
    assert await store_with(many).get_many(ORG, [f"e{i:03}" for i in range(150)]) == {}
    assert len(sent_body(many)["query"]["bool"]["filter"][1]["terms"]["sx.event_uid"]) == 100
    none = stub_client()
    assert await store_with(none).get_many(ORG, []) == {}
    none.search.assert_not_awaited()


# ------------------------------------------------------------------- writes
async def test_writes_never_overwrite_stored_evidence() -> None:
    items = [
        {"create": {"status": 201}},
        {"create": {"status": 409, "error": {"type": "version_conflict_engine_exception"}}},
        {"create": {"status": 400, "error": {"reason": "mapper_parsing_exception"}}},
    ]
    client = stub_client(bulk=AsyncMock(return_value={"items": items}))
    documents = [EventDocument(stream="events-ocsf-iam", id=f"fp-{i}", body={"n": i}) for i in range(3)]

    outcome = await store_with(client).index(documents)

    assert (outcome.indexed, outcome.duplicates, outcome.failed) == (1, 1, 1)
    assert list(outcome.errors) == ["mapper_parsing_exception"]
    operations = client.bulk.await_args.kwargs["body"]
    assert operations[0] == {"create": {"_index": "events-ocsf-iam-write", "_id": "fp-0"}}
    assert operations[1] == {"n": 0}
    assert not any("index" in op for op in operations[::2]), "`index` would replace the stored copy"


async def test_indexing_nothing_does_not_call_the_cluster() -> None:
    client = stub_client()
    outcome = await store_with(client).index([])
    assert (outcome.indexed, outcome.duplicates, outcome.failed) == (0, 0, 0)
    client.bulk.assert_not_awaited()


# -------------------------------------------------------------------- setup
async def test_setup_creates_only_missing_write_indices() -> None:
    existing = write_alias("events-ocsf-iam")
    client = stub_client()
    client.indices.exists_alias = AsyncMock(side_effect=lambda name: name == existing)

    await store_with(client).ensure_ready()

    client.indices.put_index_template.assert_awaited_once()
    created = [call.kwargs["index"] for call in client.indices.create.await_args_list]
    assert "events-ocsf-iam-000001" not in created
    assert len(created) == len(CATEGORY_SLUGS) - 1
    network = next(call for call in client.indices.create.await_args_list if "network" in call.kwargs["index"])
    assert network.kwargs["body"]["aliases"] == {"events-ocsf-network-write": {"is_write_index": True}}
    # Existing indices get fields added since they were created (for example Sysmon's registry fields).
    client.indices.put_mapping.assert_awaited_once_with(index="events-ocsf-*", body=MAPPINGS)


async def test_setup_tolerates_a_missing_ism_plugin_and_concurrent_index_creation() -> None:
    client = stub_client()
    client.transport.perform_request = AsyncMock(side_effect=RuntimeError("no handler for _plugins/_ism"))
    client.indices.create = AsyncMock(side_effect=RuntimeError("resource_already_exists_exception"))

    await store_with(client).ensure_ready()

    client.indices.put_index_template.assert_awaited_once()


async def test_setup_surfaces_unexpected_index_errors() -> None:
    client = stub_client()
    client.indices.create = AsyncMock(side_effect=RuntimeError("cluster_block_exception"))

    with pytest.raises(RuntimeError, match="cluster_block_exception"):
        await store_with(client).ensure_ready()


async def test_ping_reports_false_when_the_cluster_is_unreachable() -> None:
    assert await store_with(stub_client(ping=AsyncMock(side_effect=ConnectionError()))).ping() is False
    assert await store_with(stub_client()).ping() is True


def test_mappings_are_bounded() -> None:
    assert MAPPINGS["dynamic"] is False, "unknown fields must not create mappings"
    properties = MAPPINGS["properties"]
    assert properties["unmapped"] == {"type": "object", "enabled": False}
    assert properties["sx"]["properties"]["org_id"] == {"type": "keyword"}
    for endpoint in ("src_endpoint", "dst_endpoint", "device"):
        assert properties[endpoint]["properties"]["ip"] == {"type": "ip"}


def test_sysmon_fields_are_searchable() -> None:
    properties = MAPPINGS["properties"]
    assert properties["reg_value"]["properties"]["path"] == {"type": "keyword"}
    assert properties["reg_key"]["properties"]["path"] == {"type": "keyword"}
    assert properties["module"]["properties"]["file"]["properties"]["path"] == {"type": "keyword"}
    assert properties["process"]["properties"]["uid"] == {"type": "keyword"}
    assert properties["process"]["properties"]["integrity"] == {"type": "keyword"}


def test_no_store_without_a_configured_cluster() -> None:
    settings = Settings(_env_file=None, environment=Environment.TEST, database_url="sqlite+aiosqlite://")
    assert event_store_from_settings(settings) is None
