from __future__ import annotations

from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from app.conftest import bearer, login
from app.modules.ingestion.tests.conftest import FakeEventStore, ingest_headers
from app.modules.ingestion.tests.test_ingest_api import ACCEPTED_LINE, FAILED_LINE, records

WINDOW: dict[str, Any] = {"time_from": "2026-09-15T00:00:00Z", "time_to": "2026-09-16T00:00:00Z"}


async def test_search_returns_ingested_events_newest_first(
    client: httpx.AsyncClient, admin_token: str, source_token: str, event_store: FakeEventStore
) -> None:
    await client.post(
        "/api/v1/ingest/events", headers=ingest_headers(source_token), json=records(FAILED_LINE, ACCEPTED_LINE)
    )

    response = await client.post("/api/v1/events/search", headers=bearer(admin_token), json=WINDOW)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 2
    assert [item["user"]["name"] for item in body["items"]] == ["deploy", "admin"]
    assert body["next_cursor"] is None
    assert body["took_ms"] >= 0


async def test_search_filters_narrow_the_result(
    client: httpx.AsyncClient, admin_token: str, source_token: str, event_store: FakeEventStore
) -> None:
    await client.post(
        "/api/v1/ingest/events", headers=ingest_headers(source_token), json=records(FAILED_LINE, ACCEPTED_LINE)
    )

    failures = await client.post(
        "/api/v1/events/search",
        headers=bearer(admin_token),
        json={**WINDOW, "severity_min": 2, "class_uids": [3002], "text": "Failed password"},
    )

    assert failures.json()["total"] == 1
    query = event_store.queries[-1]
    assert query.class_uids == (3002,)
    assert query.severity_min == 2
    assert query.text == "Failed password"


async def test_search_paginates_with_an_opaque_cursor(
    client: httpx.AsyncClient, admin_token: str, source_token: str, event_store: FakeEventStore
) -> None:
    await client.post(
        "/api/v1/ingest/events", headers=ingest_headers(source_token), json=records(FAILED_LINE, ACCEPTED_LINE)
    )

    first = await client.post("/api/v1/events/search", headers=bearer(admin_token), json={**WINDOW, "limit": 1})
    cursor = first.json()["next_cursor"]
    assert cursor is not None

    second = await client.post(
        "/api/v1/events/search", headers=bearer(admin_token), json={**WINDOW, "limit": 1, "cursor": cursor}
    )

    assert second.status_code == 200
    assert event_store.queries[-1].cursor is not None
    assert event_store.queries[-1].cursor.event_uid == first.json()["items"][0]["sx"]["event_uid"]


async def test_malformed_cursor_is_rejected(
    client: httpx.AsyncClient, admin_token: str, event_store: FakeEventStore
) -> None:
    response = await client.post("/api/v1/events/search", headers=bearer(admin_token), json={**WINDOW, "cursor": "***"})
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"time_from": "2026-09-16T00:00:00Z", "time_to": "2026-09-15T00:00:00Z"}, "earlier"),
        ({"time_from": "2020-01-01T00:00:00Z"}, "90 days"),
        ({"class_uids": [9999]}, "unsupported class_uid"),
        ({"limit": 5000}, "less than or equal"),
        ({"severity_min": 7}, "unknown severity"),
    ],
)
async def test_invalid_searches_are_refused(
    client: httpx.AsyncClient, admin_token: str, event_store: FakeEventStore, overrides: dict[str, Any], message: str
) -> None:
    response = await client.post("/api/v1/events/search", headers=bearer(admin_token), json={**WINDOW, **overrides})
    assert response.status_code == 422
    assert message.lower() in response.text.lower()


async def test_single_event_lookup(
    client: httpx.AsyncClient, admin_token: str, source_token: str, event_store: FakeEventStore
) -> None:
    await client.post("/api/v1/ingest/events", headers=ingest_headers(source_token), json=records(ACCEPTED_LINE))
    event_uid = next(iter(event_store.documents.values()))["sx"]["event_uid"]

    found = await client.get(f"/api/v1/events/{event_uid}", headers=bearer(admin_token))
    missing = await client.get("/api/v1/events/01a0aaa3-0000-7000-8000-000000000000", headers=bearer(admin_token))

    assert found.status_code == 200
    assert found.json()["sx"]["event_uid"] == event_uid
    assert missing.status_code == 404


async def test_event_search_requires_permission(
    client: httpx.AsyncClient, admin_token: str, event_store: FakeEventStore
) -> None:
    await client.post(
        "/api/v1/users",
        headers=bearer(admin_token),
        json={
            "email": "vic@example.com",
            "full_name": "Vic Viewer",
            "password": "a-long-viewer-passphrase",
            "roles": ["viewer"],
        },
    )
    viewer = await login(client, "vic@example.com", "a-long-viewer-passphrase")

    # viewer holds event:read
    allowed = await client.post("/api/v1/events/search", headers=bearer(viewer), json=WINDOW)
    assert allowed.status_code == 200

    anonymous = await client.post("/api/v1/events/search", json=WINDOW)
    assert anonymous.status_code == 401


async def test_search_reports_unavailable_without_an_event_store(
    app: FastAPI, client: httpx.AsyncClient, admin_token: str
) -> None:
    app.state.event_store = None
    response = await client.post("/api/v1/events/search", headers=bearer(admin_token), json=WINDOW)
    assert response.status_code == 503
    assert "OPENSEARCH" in response.json()["detail"]
