from __future__ import annotations

import httpx
import pytest

from app.conftest import Seeded, bearer, login
from app.modules.ingestion.tests.conftest import FakeEventStore, ingest_headers
from app.modules.ingestion.tests.test_ingest_api import ACCEPTED_LINE, records


async def analyst_token(client: httpx.AsyncClient, admin_token: str) -> str:
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


async def test_created_source_returns_its_token_exactly_once(client: httpx.AsyncClient, admin_token: str) -> None:
    created = await client.post(
        "/api/v1/ingest/sources",
        headers=bearer(admin_token),
        json={"name": "fw-edge", "description": "perimeter firewall", "parser": "ocsf"},
    )

    assert created.status_code == 201, created.text
    body = created.json()
    token = body["token"]
    assert token.startswith("sxi_")
    assert body["source"]["token_prefix"] == token[:12]
    assert body["source"]["health"] == "awaiting_data"

    listed = await client.get("/api/v1/ingest/sources", headers=bearer(admin_token))
    assert token not in listed.text, "the plaintext token is never retrievable again"
    assert listed.json()[0]["token_prefix"] == token[:12]

    fetched = await client.get(f"/api/v1/ingest/sources/{body['source']['id']}", headers=bearer(admin_token))
    assert "token" not in fetched.json()


async def test_duplicate_source_names_are_refused(client: httpx.AsyncClient, admin_token: str) -> None:
    payload = {"name": "fw-edge", "description": "", "parser": "ocsf"}
    first = await client.post("/api/v1/ingest/sources", headers=bearer(admin_token), json=payload)
    second = await client.post("/api/v1/ingest/sources", headers=bearer(admin_token), json=payload)

    assert first.status_code == 201
    assert second.status_code == 409


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"name": "fw", "description": "", "parser": "ocsf"}, "at least 3"),
        ({"name": "Bad Name", "description": "", "parser": "ocsf"}, "lowercase"),
        ({"name": "fw-edge", "description": "", "parser": "cisco_asa"}, "must be one of"),
        ({"name": "fw-edge", "description": "", "parser": "ocsf", "extra": 1}, "extra"),
    ],
)
async def test_invalid_source_definitions_are_refused(
    client: httpx.AsyncClient, admin_token: str, payload: dict[str, object], message: str
) -> None:
    response = await client.post("/api/v1/ingest/sources", headers=bearer(admin_token), json=payload)
    assert response.status_code == 422
    assert message.lower() in response.text.lower()


async def test_rotating_a_token_revokes_the_previous_one(
    client: httpx.AsyncClient, admin_token: str, source_token: str, event_store: FakeEventStore
) -> None:
    source_id = (await client.get("/api/v1/ingest/sources", headers=bearer(admin_token))).json()[0]["id"]

    rotated = await client.post(f"/api/v1/ingest/sources/{source_id}/rotate-token", headers=bearer(admin_token))
    assert rotated.status_code == 200
    new_token = rotated.json()["token"]
    assert new_token != source_token

    old = await client.post("/api/v1/ingest/events", headers=ingest_headers(source_token), json=records(ACCEPTED_LINE))
    new = await client.post("/api/v1/ingest/events", headers=ingest_headers(new_token), json=records(ACCEPTED_LINE))
    assert old.status_code == 401
    assert new.status_code == 202


async def test_source_administration_needs_the_right_permissions(
    client: httpx.AsyncClient, admin_token: str, source_token: str
) -> None:
    token = await analyst_token(client, admin_token)
    source_id = (await client.get("/api/v1/ingest/sources", headers=bearer(admin_token))).json()[0]["id"]

    assert (await client.get("/api/v1/ingest/sources", headers=bearer(token))).status_code == 200
    assert (await client.get("/api/v1/ingest/parsers", headers=bearer(token))).status_code == 200
    created = await client.post(
        "/api/v1/ingest/sources", headers=bearer(token), json={"name": "nope", "description": "", "parser": "ocsf"}
    )
    assert created.status_code == 403
    rotated = await client.post(f"/api/v1/ingest/sources/{source_id}/rotate-token", headers=bearer(token))
    assert rotated.status_code == 403


async def test_sources_are_scoped_to_their_org(client: httpx.AsyncClient, admin_token: str) -> None:
    missing = await client.get(
        "/api/v1/ingest/sources/01a0aaa3-c9b6-7213-b363-20af5c5823ee", headers=bearer(admin_token)
    )
    assert missing.status_code == 404


async def test_source_changes_are_audited_without_the_token(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    created = await client.post(
        "/api/v1/ingest/sources",
        headers=bearer(admin_token),
        json={"name": "audited-source", "description": "", "parser": "ocsf"},
    )
    token = created.json()["token"]
    source_id = created.json()["source"]["id"]
    await client.post(f"/api/v1/ingest/sources/{source_id}/rotate-token", headers=bearer(admin_token))
    await client.patch(f"/api/v1/ingest/sources/{source_id}", headers=bearer(admin_token), json={"is_enabled": False})

    audit = await client.get("/api/v1/audit?limit=50", headers=bearer(admin_token))
    entries = [e for e in audit.json()["items"] if e["resource_id"] == source_id]
    actions = {entry["action"] for entry in entries}

    assert actions == {"ingest_source.created", "ingest_source.token_rotated", "ingest_source.disabled"}
    assert token not in audit.text
    assert "token_hash" not in audit.text
    for entry in entries:
        assert entry["after"]["token_prefix"].startswith("sxi_")

    verification = await client.get("/api/v1/audit/verify", headers=bearer(admin_token))
    assert verification.json()["valid"] is True


async def test_parsers_are_listed_with_descriptions(client: httpx.AsyncClient, admin_token: str) -> None:
    response = await client.get("/api/v1/ingest/parsers", headers=bearer(admin_token))
    names = {parser["name"] for parser in response.json()}
    assert {"ocsf", "linux_auth", "windows_security"} <= names
    assert all(parser["description"] for parser in response.json())
