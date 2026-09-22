"""Incidents through the real API: ingest the samples over HTTP, then read and triage what correlation built."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import select

from app.conftest import Seeded, bearer, login
from app.core.audit.models import AuditLogModel
from app.core.container import Container

SAMPLES = Path(__file__).resolve().parents[5] / "pipeline" / "samples"
PASSWORD = "a-long-test-password-1"


async def _ingest(client: httpx.AsyncClient, token: str, name: str, parser: str, records: list[Any]) -> None:
    created = await client.post("/api/v1/ingest/sources", headers=bearer(token), json={"name": name, "parser": parser})
    assert created.status_code == 201, created.text
    response = await client.post(
        "/api/v1/ingest/events",
        headers={"Authorization": f"Bearer {created.json()['token']}"},
        json=records,
    )
    assert response.status_code == 202, response.text


async def _ingest_samples(client: httpx.AsyncClient, token: str) -> None:
    def lines(name: str) -> list[str]:
        return [line for line in (SAMPLES / name).read_text(encoding="utf-8").splitlines() if line.strip()]

    await _ingest(client, token, "web-01-auth", "linux_auth", [{"message": line} for line in lines("linux_auth.log")])
    await _ingest(
        client, token, "ws-fin-07", "windows_security", [json.loads(line) for line in lines("windows_security.jsonl")]
    )
    await _ingest(client, token, "zeek", "ocsf", [json.loads(line) for line in lines("ocsf_network.jsonl")])


async def _user_token(client: httpx.AsyncClient, admin_token: str, email: str, role: str) -> str:
    response = await client.post(
        "/api/v1/users",
        headers=bearer(admin_token),
        json={"email": email, "full_name": "Test User", "password": PASSWORD, "roles": [role]},
    )
    assert response.status_code == 201, response.text
    return await login(client, email, PASSWORD)


async def _windows_incident(client: httpx.AsyncClient, token: str) -> dict[str, Any]:
    listing = await client.get("/api/v1/incidents?severity_min=5", headers=bearer(token))
    assert listing.status_code == 200, listing.text
    [incident] = listing.json()["items"]
    body: dict[str, Any] = incident
    return body


async def test_incidents_list_and_detail(client: httpx.AsyncClient, admin_token: str, seeded: Seeded) -> None:
    await _ingest_samples(client, admin_token)

    listing = await client.get("/api/v1/incidents", headers=bearer(admin_token))
    assert listing.status_code == 200, listing.text
    items = listing.json()["items"]
    assert [item["severity"] for item in items] == ["Critical", "High"]  # WS-FIN-07's activity is later
    assert {item["status"] for item in items} == {"new"}

    detail = await client.get(f"/api/v1/incidents/{items[0]['id']}", headers=bearer(admin_token))
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["finding_count"] == 8
    assert {link["rule"] for link in body["links"]} == {"opened", "shared-entity", "auth-success-after-failures"}
    for link in body["links"]:
        assert link["evidence"], "every link cites events"
        if link["kind"] == "finding":
            finding = await client.get(f"/api/v1/findings/{link['finding_id']}", headers=bearer(admin_token))
            assert finding.status_code == 200
            assert finding.json()["evidence"] == link["evidence"]
    assert "host:ws-fin-07" in {entity["key"] for entity in body["entities"]}
    assert {entry["rule"] for entry in body["assessment"]} >= {"credential-compromise", "multi-stage"}

    page = (await client.get("/api/v1/incidents?limit=1", headers=bearer(admin_token))).json()
    rest = (
        await client.get(f"/api/v1/incidents?limit=1&cursor={page['next_cursor']}", headers=bearer(admin_token))
    ).json()
    assert [i["id"] for i in page["items"] + rest["items"]] == [i["id"] for i in items]
    assert rest["next_cursor"] is None
    assert (await client.get("/api/v1/incidents?status=closed", headers=bearer(admin_token))).json()["items"] == []


async def test_triage_follows_roles_and_is_audited(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded, container: Container
) -> None:
    await _ingest_samples(client, admin_token)
    viewer = await _user_token(client, admin_token, "viewer@example.com", "viewer")
    analyst = await _user_token(client, admin_token, "analyst@example.com", "analyst")
    senior = await _user_token(client, admin_token, "senior@example.com", "senior_analyst")
    incident = await _windows_incident(client, viewer)  # viewers can read
    url = f"/api/v1/incidents/{incident['id']}"
    version = incident["version"]

    denied = await client.patch(url, headers=bearer(viewer), json={"status": "investigating", "version": version})
    assert denied.status_code == 403

    taken = await client.patch(url, headers=bearer(analyst), json={"status": "investigating", "version": version})
    assert taken.status_code == 200, taken.text
    assert taken.json()["status"] == "investigating"
    assert taken.json()["version"] == version + 1

    stale = await client.patch(url, headers=bearer(senior), json={"status": "investigating", "version": version})
    assert stale.status_code == 409

    close = {"status": "closed", "resolution": "true_positive", "version": version + 1}
    assert (await client.patch(url, headers=bearer(analyst), json=close)).status_code == 403
    no_resolution = await client.patch(url, headers=bearer(senior), json={"status": "closed", "version": version + 1})
    assert no_resolution.status_code == 422
    closed = await client.patch(url, headers=bearer(senior), json=close)
    assert closed.status_code == 200, closed.text
    assert closed.json()["resolution"] == "true_positive"
    assert closed.json()["closed_at"] is not None

    reopen = {"status": "investigating", "version": version + 2}
    assert (await client.patch(url, headers=bearer(analyst), json=reopen)).status_code == 403

    async with container.database.sessionmaker() as session:
        rows = list(
            await session.scalars(
                select(AuditLogModel)
                .where(AuditLogModel.action == "incident.status_changed")
                .order_by(AuditLogModel.chain_index)
            )
        )
    assert [(row.before or {}).get("status") for row in rows] == ["new", "investigating"]
    assert [(row.after or {}).get("status") for row in rows] == ["investigating", "closed"]
    assert all(row.actor_type == "user" and row.actor_id is not None for row in rows)


async def test_bad_requests(client: httpx.AsyncClient, admin_token: str, seeded: Seeded) -> None:
    await _ingest_samples(client, admin_token)
    incident = await _windows_incident(client, admin_token)
    url = f"/api/v1/incidents/{incident['id']}"

    missing = await client.get("/api/v1/incidents/0190a2b4-0000-7000-8000-000000000000", headers=bearer(admin_token))
    assert missing.status_code == 404
    over_posted = await client.patch(
        url, headers=bearer(admin_token), json={"status": "investigating", "version": 1, "severity_id": 1}
    )
    assert over_posted.status_code == 422, "analysts can't rewrite what correlation derived"
    unchanged = await client.patch(
        url, headers=bearer(admin_token), json={"status": "new", "version": incident["version"]}
    )
    assert unchanged.status_code == 409
    assert (await client.get("/api/v1/incidents?cursor=%%%", headers=bearer(admin_token))).status_code == 422
    assert (await client.get("/api/v1/incidents?status=bogus", headers=bearer(admin_token))).status_code == 422
    assert (await client.get("/api/v1/incidents")).status_code == 401
