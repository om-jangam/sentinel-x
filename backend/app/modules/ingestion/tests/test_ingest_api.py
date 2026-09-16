from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.conftest import Seeded, bearer, login
from app.modules.ingestion.tests.conftest import FakeEventStore, ingest_headers

FAILED_LINE = (
    "2026-09-15T09:14:02.519004+00:00 web-01 sshd[2211]: "
    "Failed password for invalid user admin from 203.0.113.45 port 41822 ssh2"
)
ACCEPTED_LINE = (
    "2026-09-15T09:14:19.590018+00:00 web-01 sshd[2231]: Accepted password for deploy from 203.0.113.45 port 41958 ssh2"
)
NOISE_LINE = "2026-09-15T09:14:19.602113+00:00 web-01 sshd[2231]: pam_unix(sshd:session): session opened"


def records(*lines: str) -> list[dict[str, str]]:
    return [{"message": line} for line in lines]


async def test_source_token_ingests_and_indexes(
    client: httpx.AsyncClient, source_token: str, event_store: FakeEventStore, seeded: Seeded
) -> None:
    response = await client.post(
        "/api/v1/ingest/events",
        headers=ingest_headers(source_token),
        json=records(FAILED_LINE, ACCEPTED_LINE),
    )

    assert response.status_code == 202, response.text
    assert response.json() == {"accepted": 2, "rejected": 0, "errors": []}
    assert len(event_store.documents) == 2

    document = next(d for d in event_store.documents.values() if d["status_id"] == 1)
    assert document["class_uid"] == 3002
    assert document["user"]["name"] == "deploy"
    assert document["src_endpoint"]["ip"] == "203.0.113.45"
    assert document["sx"]["org_id"] == str(seeded.org.id)
    assert document["sx"]["event_uid"]
    assert document["@timestamp"].startswith("2026-09-15T09:14:19")


async def test_unparseable_records_are_reported_per_record(
    client: httpx.AsyncClient, source_token: str, event_store: FakeEventStore
) -> None:
    response = await client.post(
        "/api/v1/ingest/events",
        headers=ingest_headers(source_token),
        json=records(FAILED_LINE, NOISE_LINE, "not a syslog line at all"),
    )

    body = response.json()
    assert response.status_code == 202
    assert (body["accepted"], body["rejected"]) == (1, 2)
    assert [error["index"] for error in body["errors"]] == [1, 2]
    assert "sshd message is not an authentication outcome" in body["errors"][0]["reason"]
    assert len(event_store.documents) == 1, "a bad record never blocks the good ones"


async def test_redelivered_batches_do_not_duplicate_events(
    client: httpx.AsyncClient, source_token: str, event_store: FakeEventStore
) -> None:
    payload = records(FAILED_LINE, ACCEPTED_LINE)
    first = await client.post("/api/v1/ingest/events", headers=ingest_headers(source_token), json=payload)
    second = await client.post("/api/v1/ingest/events", headers=ingest_headers(source_token), json=payload)

    assert (first.status_code, second.status_code) == (202, 202)
    assert second.json()["accepted"] == 2, "the API accepts the retry"
    assert len(event_store.documents) == 2, "but the store deduplicates by content fingerprint"


@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        ('[{"message": "LINE"}]', "application/json"),
        ('{"events": [{"message": "LINE"}]}', "application/json"),
        ('{"message": "LINE"}', "application/json"),
        ('{"message": "LINE"}\n', "application/x-ndjson"),
    ],
)
async def test_accepts_the_body_shapes_producers_send(
    client: httpx.AsyncClient, source_token: str, event_store: FakeEventStore, body: str, content_type: str
) -> None:
    response = await client.post(
        "/api/v1/ingest/events",
        headers={"Authorization": f"Bearer {source_token}", "Content-Type": content_type},
        content=body.replace("LINE", ACCEPTED_LINE),
    )

    assert response.status_code == 202, response.text
    assert response.json()["accepted"] == 1


async def test_malformed_json_is_a_client_error(client: httpx.AsyncClient, source_token: str) -> None:
    response = await client.post("/api/v1/ingest/events", headers=ingest_headers(source_token), content="{not json")
    assert response.status_code == 422
    assert "Malformed request body" in response.json()["detail"]


async def test_batches_above_the_cap_are_refused(client: httpx.AsyncClient, source_token: str) -> None:
    response = await client.post(
        "/api/v1/ingest/events",
        headers=ingest_headers(source_token),
        json=records(*([ACCEPTED_LINE] * 1001)),
    )
    assert response.status_code == 422
    assert "1000 events" in response.json()["detail"]


@pytest.mark.parametrize("token", ["sxi_not-a-real-token", "garbage"])
async def test_invalid_credentials_are_rejected(client: httpx.AsyncClient, token: str) -> None:
    response = await client.post("/api/v1/ingest/events", headers=ingest_headers(token), json=records(ACCEPTED_LINE))
    assert response.status_code == 401


async def test_missing_credentials_are_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post("/api/v1/ingest/events", json=records(ACCEPTED_LINE))
    assert response.status_code == 401


async def test_disabled_sources_cannot_ingest(
    client: httpx.AsyncClient, admin_token: str, source_token: str, event_store: FakeEventStore
) -> None:
    listed = await client.get("/api/v1/ingest/sources", headers=bearer(admin_token))
    source_id = listed.json()[0]["id"]
    disabled = await client.patch(
        f"/api/v1/ingest/sources/{source_id}", headers=bearer(admin_token), json={"is_enabled": False}
    )
    assert disabled.status_code == 200

    response = await client.post(
        "/api/v1/ingest/events", headers=ingest_headers(source_token), json=records(ACCEPTED_LINE)
    )
    assert response.status_code == 409
    assert not event_store.documents


async def test_rate_limited_sources_are_told_to_retry(
    client: httpx.AsyncClient, container: Any, source_token: str, event_store: FakeEventStore
) -> None:
    container.settings.ingest_rate_limit = 2
    for _ in range(2):
        allowed = await client.post(
            "/api/v1/ingest/events", headers=ingest_headers(source_token), json=records(ACCEPTED_LINE)
        )
        assert allowed.status_code == 202

    throttled = await client.post(
        "/api/v1/ingest/events", headers=ingest_headers(source_token), json=records(ACCEPTED_LINE)
    )
    assert throttled.status_code == 429
    assert int(throttled.headers["Retry-After"]) >= 1


async def test_user_token_ingest_requires_permission_and_an_explicit_source(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded, event_store: FakeEventStore
) -> None:
    created = await client.post(
        "/api/v1/ingest/sources",
        headers=bearer(admin_token),
        json={"name": "manual-submission", "description": "", "parser": "ocsf"},
    )
    source_id = created.json()["source"]["id"]

    without_source = await client.post("/api/v1/ingest/events", headers=bearer(admin_token), json=[{"class_uid": 3002}])
    assert without_source.status_code == 422
    assert "source_id" in without_source.text

    event = json.loads(_ocsf_sample())
    accepted = await client.post(
        f"/api/v1/ingest/events?source_id={source_id}", headers=bearer(admin_token), json=[event]
    )
    assert accepted.status_code == 202, accepted.text
    assert accepted.json()["accepted"] == 1

    analyst_token = await _analyst_token(client, admin_token)
    forbidden = await client.post(
        f"/api/v1/ingest/events?source_id={source_id}", headers=bearer(analyst_token), json=[event]
    )
    assert forbidden.status_code == 403


async def test_ingest_updates_source_health_and_counters(
    client: httpx.AsyncClient, admin_token: str, source_token: str, event_store: FakeEventStore
) -> None:
    before = (await client.get("/api/v1/ingest/sources", headers=bearer(admin_token))).json()[0]
    assert before["health"] == "awaiting_data"
    assert (before["events_accepted"], before["events_rejected"]) == (0, 0)

    await client.post(
        "/api/v1/ingest/events",
        headers=ingest_headers(source_token),
        json=records(FAILED_LINE, ACCEPTED_LINE, NOISE_LINE),
    )

    after = (await client.get("/api/v1/ingest/sources", headers=bearer(admin_token))).json()[0]
    assert (after["events_accepted"], after["events_rejected"]) == (2, 1)
    assert after["last_event_at"] is not None
    # The demo telemetry is older than the staleness window, so the source reads as stale, not healthy.
    assert after["health"] == "stale"


def _ocsf_sample() -> str:
    samples = Path(__file__).resolve().parents[5] / "pipeline" / "samples" / "ocsf_network.jsonl"
    return samples.read_text(encoding="utf-8").splitlines()[0]


async def _analyst_token(client: httpx.AsyncClient, admin_token: str) -> str:
    await client.post(
        "/api/v1/users",
        headers=bearer(admin_token),
        json={
            "email": "sam@example.com",
            "full_name": "Sam Analyst",
            "password": "a-long-analyst-passphrase",
            "roles": ["analyst"],
        },
    )
    return await login(client, "sam@example.com", "a-long-analyst-passphrase")
