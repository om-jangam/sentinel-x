"""Sysmon through the real API: a `windows_sysmon` source ingests every supported event, and the shipped
process-creation rules fire on Sysmon event 1 exactly as they do on Security event 4688."""

from __future__ import annotations

import httpx

from app.conftest import Seeded, bearer
from app.ingest_pipeline.ocsf import event_uid_for
from app.ingest_pipeline.parsers import normalize
from app.ingest_pipeline.tests import sysmon_records as r


async def test_sysmon_events_are_ingested_and_existing_rules_fire_on_them(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    parsers = await client.get("/api/v1/ingest/parsers", headers=bearer(admin_token))
    assert "windows_sysmon" in {parser["name"] for parser in parsers.json()}

    created = await client.post(
        "/api/v1/ingest/sources",
        headers=bearer(admin_token),
        json={"name": "ws-fin-07-sysmon", "parser": "windows_sysmon"},
    )
    assert created.status_code == 201, created.text
    body = created.json()

    records = [*r.ALL, {"EventID": 255, "TimeCreated": "2026-09-15T10:00:00Z", "EventData": {}}]
    response = await client.post(
        "/api/v1/ingest/events", headers={"Authorization": f"Bearer {body['token']}"}, json=records
    )
    result = response.json()
    assert (result["accepted"], result["rejected"]) == (len(r.ALL), 1)
    assert "unsupported Sysmon event 255" in result["errors"][0]["reason"]

    org_id = (await client.get("/api/v1/me", headers=bearer(admin_token))).json()["org_id"]
    process_create_uid = event_uid_for(
        normalize("windows_sysmon", r.PROCESS_CREATE).fingerprint(org_id=org_id, source_id=body["source"]["id"])
    )

    findings = (await client.get("/api/v1/findings", headers=bearer(admin_token))).json()["items"]
    powershell = next(f for f in findings if f["rule_title"] == "PowerShell started with an encoded command")
    assert powershell["evidence"] == [process_create_uid]
    assert powershell["entities"]["process.name"] == ["powershell.exe"]
