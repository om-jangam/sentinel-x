"""OpenSearch event store (ADR-0011).

Events land in ISM-managed rolling indices behind a per-category write alias rather than in data
streams: data streams reject custom document ids, and we use the content fingerprint as `_id` so a
redelivered batch updates in place instead of duplicating (ADR-0013).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any
from uuid import UUID

from opensearchpy import AsyncHttpConnection, AsyncOpenSearch

from app.core.config import Settings
from app.ingest_pipeline.ocsf import CATEGORY_SLUGS
from app.modules.ingestion.domain.events import (
    TOTAL_HITS_CAP,
    EventCursor,
    EventDocument,
    EventPage,
    EventQuery,
    IndexOutcome,
)

logger = logging.getLogger(__name__)

INDEX_PREFIX = "events-ocsf"
INDEX_PATTERN = f"{INDEX_PREFIX}-*"
TEMPLATE_NAME = "sentinelx-events"
ISM_POLICY_ID = "sentinelx-events"
SEARCHABLE_TEXT = ["message", "raw_data", "process.cmd_line", "query.hostname"]

_KEYWORD = {"type": "keyword"}
_INT = {"type": "integer"}
_ENDPOINT = {
    "properties": {
        "ip": {"type": "ip"},
        "port": _INT,
        "hostname": _KEYWORD,
        "domain": _KEYWORD,
    }
}
_USER = {"properties": {"name": _KEYWORD, "uid": _KEYWORD, "domain": _KEYWORD}}
_FILE = {"properties": {"path": _KEYWORD, "name": _KEYWORD}}
_PROCESS_FIELDS: dict[str, Any] = {
    "pid": {"type": "long"},
    "name": _KEYWORD,
    "cmd_line": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
    "file": _FILE,
}

# `dynamic: false` keeps unmapped telemetry out of the mapping: a trimmed, known field set cannot
# explode into thousands of fields when a noisy producer appears (ADR-0003).
MAPPINGS: dict[str, Any] = {
    "dynamic": False,
    "properties": {
        "@timestamp": {"type": "date"},
        "time": {"type": "long"},
        "class_uid": _INT,
        "category_uid": _INT,
        "activity_id": _INT,
        "type_uid": _INT,
        "severity_id": _INT,
        "status_id": _INT,
        "class_name": _KEYWORD,
        "category_name": _KEYWORD,
        "activity_name": _KEYWORD,
        "severity": _KEYWORD,
        "status": _KEYWORD,
        "message": {"type": "text"},
        "metadata": {
            "properties": {
                "version": _KEYWORD,
                "log_name": _KEYWORD,
                "uid": _KEYWORD,
                "product": {"properties": {"name": _KEYWORD, "vendor_name": _KEYWORD, "version": _KEYWORD}},
            }
        },
        "actor": {"properties": {"user": _USER, "process": {"properties": _PROCESS_FIELDS}}},
        "user": _USER,
        "device": {
            "properties": {
                "hostname": _KEYWORD,
                "ip": {"type": "ip"},
                "uid": _KEYWORD,
                "os": {"properties": {"name": _KEYWORD, "type": _KEYWORD}},
            }
        },
        "src_endpoint": _ENDPOINT,
        "dst_endpoint": _ENDPOINT,
        "process": {
            "properties": {
                **_PROCESS_FIELDS,
                "user": _USER,
                "parent_process": {"properties": _PROCESS_FIELDS},
            }
        },
        "file": _FILE,
        "query": {"properties": {"hostname": _KEYWORD, "type": _KEYWORD}},
        "answers": {"properties": {"rdata": _KEYWORD, "type": _KEYWORD, "ttl": _INT}},
        "http_request": {
            "properties": {
                "http_method": _KEYWORD,
                "user_agent": {"type": "text"},
                "url": {
                    "properties": {
                        "url_string": {
                            "type": "text",
                            "fields": {"keyword": {"type": "keyword", "ignore_above": 2048}},
                        },
                        "hostname": _KEYWORD,
                        "path": _KEYWORD,
                        "scheme": _KEYWORD,
                    }
                },
            }
        },
        "http_response": {"properties": {"code": _INT}},
        "connection_info": {"properties": {"protocol_name": _KEYWORD, "direction_id": _INT}},
        "traffic": {
            "properties": {
                "bytes_in": {"type": "long"},
                "bytes_out": {"type": "long"},
                "packets_in": {"type": "long"},
                "packets_out": {"type": "long"},
            }
        },
        "auth_protocol": _KEYWORD,
        "logon_type": _KEYWORD,
        "logon_type_id": _INT,
        "is_mfa": {"type": "boolean"},
        "observables": {"properties": {"name": _KEYWORD, "type_id": _INT, "value": _KEYWORD}},
        "raw_data": {"type": "text"},
        # Arbitrary source-specific leftovers: stored and returned, never indexed.
        "unmapped": {"type": "object", "enabled": False},
        "sx": {
            "properties": {
                "org_id": _KEYWORD,
                "source_id": _KEYWORD,
                "event_uid": _KEYWORD,
                "fingerprint": _KEYWORD,
                "ingested_at": {"type": "date"},
            }
        },
    },
}


def write_alias(stream: str) -> str:
    return f"{stream}-write"


class OpenSearchEventStore:
    def __init__(
        self,
        client: AsyncOpenSearch,
        *,
        retention_days: int = 90,
        shards: int = 1,
        replicas: int = 0,
        rollover_size_gb: int = 20,
    ) -> None:
        self._client = client
        self._retention_days = retention_days
        self._shards = shards
        self._replicas = replicas
        self._rollover_size_gb = rollover_size_gb

    # ------------------------------------------------------------------ setup
    async def ensure_ready(self) -> None:
        await self._put_ism_policy()
        await self._put_index_template()
        for slug in CATEGORY_SLUGS.values():
            await self._ensure_write_index(f"{INDEX_PREFIX}-{slug}")

    async def _put_ism_policy(self) -> None:
        policy = {
            "policy": {
                "description": "Sentinel-X normalised events: roll over, then expire.",
                "default_state": "hot",
                "states": [
                    {
                        "name": "hot",
                        "actions": [
                            {
                                "rollover": {
                                    "min_size": f"{self._rollover_size_gb}gb",
                                    "min_index_age": "1d",
                                }
                            }
                        ],
                        "transitions": [
                            {"state_name": "expired", "conditions": {"min_index_age": f"{self._retention_days}d"}}
                        ],
                    },
                    {"name": "expired", "actions": [{"delete": {}}], "transitions": []},
                ],
                "ism_template": [{"index_patterns": [INDEX_PATTERN], "priority": 100}],
            }
        }
        try:
            await self._client.transport.perform_request("PUT", f"/_plugins/_ism/policies/{ISM_POLICY_ID}", body=policy)
        except Exception as exc:  # ISM is a plugin; a cluster without it must still serve events.
            if "version_conflict" in str(exc) or "already exists" in str(exc):
                return
            logger.warning("could not install the ISM lifecycle policy: %s", exc)

    async def _put_index_template(self) -> None:
        await self._client.indices.put_index_template(
            name=TEMPLATE_NAME,
            body={
                "index_patterns": [INDEX_PATTERN],
                "priority": 200,
                "template": {
                    "settings": {
                        "number_of_shards": self._shards,
                        "number_of_replicas": self._replicas,
                        "refresh_interval": "5s",
                    },
                    "mappings": MAPPINGS,
                },
            },
        )

    async def _ensure_write_index(self, stream: str) -> None:
        alias = write_alias(stream)
        if await self._client.indices.exists_alias(name=alias):
            return
        try:
            await self._client.indices.create(
                index=f"{stream}-000001",
                body={
                    "aliases": {alias: {"is_write_index": True}},
                    "settings": {"plugins.index_state_management.rollover_alias": alias},
                },
            )
        except Exception as exc:
            if "resource_already_exists_exception" not in str(exc):
                raise

    async def ping(self) -> bool:
        try:
            return bool(await self._client.ping())
        except Exception:
            return False

    # ------------------------------------------------------------------ write
    async def index(self, documents: Sequence[EventDocument]) -> IndexOutcome:
        if not documents:
            return IndexOutcome(indexed=0, duplicates=0, failed=0)

        operations: list[Any] = []
        for document in documents:
            operations.append({"index": {"_index": write_alias(document.stream), "_id": document.id}})
            operations.append(document.body)

        response = await self._client.bulk(body=operations, refresh=False)
        indexed = duplicates = failed = 0
        errors: list[str] = []
        for item in response.get("items", []):
            result = item.get("index", {})
            status = result.get("status", 500)
            if status in (200, 201):
                # 200 means the fingerprint was already present and was overwritten with identical content.
                duplicates += status == 200
                indexed += status == 201
            elif status == 409:
                duplicates += 1
            else:
                failed += 1
                if len(errors) < 5:
                    errors.append(str(result.get("error", {}).get("reason", f"status {status}")))
        return IndexOutcome(indexed=indexed, duplicates=duplicates, failed=failed, errors=errors)

    # ------------------------------------------------------------------- read
    async def search(self, org_id: UUID, query: EventQuery) -> EventPage:
        body = self._build_query(org_id, query)
        response = await self._client.search(index=INDEX_PATTERN, body=body, ignore_unavailable=True)

        hits = response.get("hits", {})
        items = [hit["_source"] for hit in hits.get("hits", [])]
        next_cursor = None
        if len(items) == query.limit and hits.get("hits"):
            sort_values = hits["hits"][-1].get("sort", [])
            if len(sort_values) == 2:
                next_cursor = EventCursor(time_ms=int(sort_values[0]), event_uid=str(sort_values[1]))

        total = hits.get("total", {})
        return EventPage(
            items=items,
            total=int(total.get("value", 0)),
            total_is_lower_bound=total.get("relation") == "gte",
            took_ms=int(response.get("took", 0)),
            next_cursor=next_cursor,
        )

    def _build_query(self, org_id: UUID, query: EventQuery) -> dict[str, Any]:
        filters: list[dict[str, Any]] = [
            {"term": {"sx.org_id": str(org_id)}},
            {
                "range": {
                    "@timestamp": {
                        "gte": query.time_from.isoformat(),
                        "lte": query.time_to.isoformat(),
                    }
                }
            },
        ]
        if query.class_uids:
            filters.append({"terms": {"class_uid": list(query.class_uids)}})
        if query.severity_min is not None:
            filters.append({"range": {"severity_id": {"gte": query.severity_min}}})
        if query.status_id is not None:
            filters.append({"term": {"status_id": query.status_id}})
        if query.source_id is not None:
            filters.append({"term": {"sx.source_id": str(query.source_id)}})
        if query.ip:
            filters.append(self._any_of(["src_endpoint.ip", "dst_endpoint.ip", "device.ip"], query.ip))
        if query.user_name:
            filters.append(self._any_of(["user.name", "actor.user.name"], query.user_name, insensitive=True))
        if query.hostname:
            filters.append(
                self._any_of(
                    ["device.hostname", "src_endpoint.hostname", "dst_endpoint.hostname"],
                    query.hostname,
                    insensitive=True,
                )
            )

        must: list[dict[str, Any]] = []
        if query.text:
            # A constrained text search, never a raw query pass-through (docs/06 §2).
            must.append(
                {
                    "simple_query_string": {
                        "query": query.text,
                        "fields": SEARCHABLE_TEXT,
                        "default_operator": "and",
                        "flags": "AND|OR|NOT|PHRASE|PREFIX|WHITESPACE",
                    }
                }
            )

        body: dict[str, Any] = {
            "size": query.limit,
            "query": {"bool": {"filter": filters, "must": must}},
            "sort": [{"@timestamp": "desc"}, {"sx.event_uid": "desc"}],
            "track_total_hits": TOTAL_HITS_CAP,
        }
        if query.cursor is not None:
            body["search_after"] = [query.cursor.time_ms, query.cursor.event_uid]
        return body

    @staticmethod
    def _any_of(fields: list[str], value: str, *, insensitive: bool = False) -> dict[str, Any]:
        term: dict[str, Any] = {"value": value}
        if insensitive:
            term["case_insensitive"] = True
        return {
            "bool": {
                "should": [{"term": {field: term}} for field in fields],
                "minimum_should_match": 1,
            }
        }

    async def get(self, org_id: UUID, event_uid: str) -> dict[str, Any] | None:
        response = await self._client.search(
            index=INDEX_PATTERN,
            body={
                "size": 1,
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {"sx.org_id": str(org_id)}},
                            {"term": {"sx.event_uid": event_uid}},
                        ]
                    }
                },
            },
            ignore_unavailable=True,
        )
        hits = response.get("hits", {}).get("hits", [])
        return hits[0]["_source"] if hits else None

    async def aclose(self) -> None:
        await self._client.close()


def event_store_from_settings(settings: Settings) -> OpenSearchEventStore | None:
    """None when no cluster is configured: ingestion and search then report 503."""
    if not settings.opensearch_url:
        return None
    password = settings.opensearch_password.get_secret_value() if settings.opensearch_password else None
    return OpenSearchEventStore(
        build_opensearch_client(
            settings.opensearch_url,
            username=settings.opensearch_username,
            password=password,
            verify_certs=settings.opensearch_verify_certs,
        ),
        retention_days=settings.event_retention_days,
        shards=settings.opensearch_shards,
        replicas=settings.opensearch_replicas,
    )


def build_opensearch_client(
    url: str, *, username: str | None = None, password: str | None = None, verify_certs: bool = True
) -> AsyncOpenSearch:
    auth = (username, password) if username and password else None
    return AsyncOpenSearch(
        hosts=[url],
        http_auth=auth,
        use_ssl=url.startswith("https"),
        verify_certs=verify_certs,
        ssl_show_warn=False,
        connection_class=AsyncHttpConnection,
        timeout=30,
        max_retries=3,
        retry_on_timeout=True,
    )
