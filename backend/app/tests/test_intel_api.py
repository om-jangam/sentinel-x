"""Threat intel end to end through the API: ingest the samples, correlation announces the incidents'
indicators, enrichment looks them up in the demo feed, and the intel API serves the cached answers."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from app.conftest import Seeded, bearer, login
from app.core.config import Settings
from app.modules.correlation.tests.test_incidents_api import PASSWORD, _ingest_samples

DEMO_FEED = Path(__file__).resolve().parents[3] / "pipeline" / "intel" / "demo_indicators.csv"


@pytest.fixture
def settings(settings: Settings) -> Settings:
    return settings.model_copy(update={"ti_local_feed": DEMO_FEED})


async def _entity_keys(client: httpx.AsyncClient, token: str) -> list[str]:
    keys: list[str] = []
    for incident in (await client.get("/api/v1/incidents", headers=bearer(token))).json()["items"]:
        detail = (await client.get(f"/api/v1/incidents/{incident['id']}", headers=bearer(token))).json()
        keys += [entity["key"] for entity in detail["entities"]]
    return keys


async def test_incident_indicators_are_enriched_from_the_feed(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    providers = await client.get("/api/v1/intel/providers", headers=bearer(admin_token))
    assert providers.status_code == 200, providers.text
    assert [(p["name"], p["kind"], p["detail"]["indicators"]) for p in providers.json()] == [("local", "local", 4)]

    await _ingest_samples(client, admin_token)
    keys = await _entity_keys(client, admin_token)
    response = await client.post("/api/v1/intel/lookup", headers=bearer(admin_token), json={"indicators": keys})
    assert response.status_code == 200, response.text
    body = response.json()

    found = {r["indicator"]: r for r in body["results"] if r["status"] == "found"}
    assert {key: r["verdict"] for key, r in found.items()} == {
        "ip:203.0.113.45": "malicious",
        "ip:198.51.100.23": "suspicious",
        "ip:192.0.2.66": "malicious",
        "domain:cdn-telemetry-sync.example": "malicious",
    }
    c2 = found["ip:192.0.2.66"]
    assert (c2["provider"], c2["confidence"]) == ("local", 90)
    assert c2["summary"].startswith("Sentinel-X demo feed:")
    assert c2["retrieved_at"]
    # Hosts, users, processes and internal addresses are never indicators: they are skipped, not looked up.
    assert {"host:ws-fin-07", "user:acme\\jsmith", "ip:10.0.5.17"} <= set(body["skipped"])
    assert not {k for k in (r["indicator"] for r in body["results"]) if k.startswith(("host:", "user:"))}


async def test_intel_reads_are_permissioned_and_bounded(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    created = await client.post(
        "/api/v1/users",
        headers=bearer(admin_token),
        json={"email": "svc@example.com", "full_name": "Svc", "password": PASSWORD, "roles": ["service"]},
    )
    assert created.status_code == 201, created.text
    service = await login(client, "svc@example.com", PASSWORD)
    assert (await client.get("/api/v1/intel/providers", headers=bearer(service))).status_code == 403
    denied = await client.post("/api/v1/intel/lookup", headers=bearer(service), json={"indicators": []})
    assert denied.status_code == 403

    too_many = {"indicators": [f"ip:203.0.113.{i % 250}" for i in range(201)]}
    assert (await client.post("/api/v1/intel/lookup", headers=bearer(admin_token), json=too_many)).status_code == 422
    extra = {"indicators": [], "refresh": True}
    assert (await client.post("/api/v1/intel/lookup", headers=bearer(admin_token), json=extra)).status_code == 422
    empty = await client.post("/api/v1/intel/lookup", headers=bearer(admin_token), json={"indicators": []})
    assert empty.json() == {"results": [], "skipped": []}
    assert (await client.post("/api/v1/intel/lookup", json={"indicators": []})).status_code == 401
