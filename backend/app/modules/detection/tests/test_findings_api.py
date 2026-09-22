"""Findings through the real API: ingest the Windows story, detection runs in-process, read the results."""

from __future__ import annotations

import json
from uuid import UUID

import httpx

from app.conftest import Seeded, bearer, login
from app.ingest_pipeline.ocsf import event_uid_for
from app.ingest_pipeline.parsers import normalize
from app.modules.detection.tests.conftest import SAMPLES


async def _ingest_windows_story(client: httpx.AsyncClient, admin_token: str) -> tuple[str, set[str]]:
    created = await client.post(
        "/api/v1/ingest/sources",
        headers=bearer(admin_token),
        json={"name": "ws-fin-07", "parser": "windows_security"},
    )
    body = created.json()
    records = [
        json.loads(line) for line in (SAMPLES / "windows_security.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    response = await client.post(
        "/api/v1/ingest/events", headers={"Authorization": f"Bearer {body['token']}"}, json=records
    )
    assert response.json()["accepted"] == 12

    org_id = (await client.get("/api/v1/me", headers=bearer(admin_token))).json()["org_id"]
    uids = set()
    for record in records:
        event = normalize("windows_security", record)
        uids.add(event_uid_for(event.fingerprint(org_id=org_id, source_id=body["source"]["id"])))
    return body["source"]["id"], uids


async def test_ingested_events_become_findings_that_cite_them(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    _, stored_uids = await _ingest_windows_story(client, admin_token)

    listing = await client.get("/api/v1/findings", headers=bearer(admin_token))
    assert listing.status_code == 200, listing.text
    items = listing.json()["items"]
    assert {item["rule_title"] for item in items} == {
        "Burst of authentication failures for one account from one source",
        "PowerShell started with an encoded command",
        "whoami used to list privileges or groups",
        "net.exe lists the Domain Admins group",
        # SigmaHQ community rules on the same encoded PowerShell command line.
        "PowerShell Base64 Encoded IEX Cmdlet",
        "Suspicious Encoded PowerShell Command Line",
        "Suspicious PowerShell Encoded Command Patterns",
    }

    # Every finding names who wrote the rule; community ones link to the published rule (DRL-1.1).
    for item in items:
        assert item["rule_author"]
        if item["rule_author"] == "Sentinel-X":
            assert item["rule_source"] is None
        else:
            assert item["rule_source"].startswith("https://github.com/SigmaHQ/sigma/blob/")
    for item in items:
        assert set(item["evidence"]) <= stored_uids, "findings cite only events that were ingested"
        assert item["evidence_count"] == len(item["evidence"])
    last_seen = [item["last_seen"] for item in items]
    assert last_seen == sorted(last_seen, reverse=True)

    powershell = next(i for i in items if i["rule_title"] == "PowerShell started with an encoded command")
    assert powershell["severity"] == "High"
    assert powershell["techniques"] == ["T1027", "T1059.001"]
    assert powershell["entities"]["process.name"] == ["powershell.exe"]
    single = await client.get(f"/api/v1/findings/{powershell['id']}", headers=bearer(admin_token))
    assert single.json() == powershell


async def test_findings_filter_and_paginate(client: httpx.AsyncClient, admin_token: str, seeded: Seeded) -> None:
    await _ingest_windows_story(client, admin_token)

    async def titles(query: str) -> list[str]:
        response = await client.get(f"/api/v1/findings?{query}", headers=bearer(admin_token))
        assert response.status_code == 200, response.text
        return [item["rule_title"] for item in response.json()["items"]]

    assert "PowerShell started with an encoded command" in await titles("severity_min=4")
    assert await titles("severity_min=5") == []
    assert await titles("technique=t1069.002") == ["net.exe lists the Domain Admins group"]
    assert await titles("time_from=2030-01-01T00:00:00Z") == []

    first = (await client.get("/api/v1/findings?limit=4", headers=bearer(admin_token))).json()
    second = (
        await client.get(f"/api/v1/findings?limit=4&cursor={first['next_cursor']}", headers=bearer(admin_token))
    ).json()
    ids = [item["id"] for item in first["items"] + second["items"]]
    assert len(ids) == len(set(ids)) == 7, "two pages, no repeats"
    assert second["next_cursor"] is None


async def test_bad_queries_and_missing_findings(client: httpx.AsyncClient, admin_token: str) -> None:
    for query in (
        "technique=1059",
        "severity_min=9",
        "cursor=***",
        "time_from=2026-09-02T00:00:00Z&time_to=2026-09-01T00:00:00Z",
    ):
        response = await client.get(f"/api/v1/findings?{query}", headers=bearer(admin_token))
        assert response.status_code == 422, query
    missing = await client.get(f"/api/v1/findings/{UUID(int=1)}", headers=bearer(admin_token))
    assert missing.status_code == 404


async def test_rules_catalogue(client: httpx.AsyncClient, admin_token: str) -> None:
    rules = (await client.get("/api/v1/detection/rules", headers=bearer(admin_token))).json()
    assert len(rules) >= 150, "own rules plus the SigmaHQ pack"
    community = [rule for rule in rules if rule["path"].startswith("sigmahq/")]
    assert community, "the community pack is served"
    for rule in community:
        assert rule["author"], f"{rule['path']} must name its author (Detection Rule License)"
        assert rule["source_url"].startswith("https://github.com/SigmaHQ/sigma/blob/")
    assert all(rule["author"] == "Sentinel-X" for rule in rules if not rule["path"].startswith("sigmahq/"))
    spray = next(rule for rule in rules if rule["type"] == "threshold" and "many accounts" in rule["title"])
    assert spray["threshold"] == {
        "group_by": ["src_endpoint.ip"],
        "count_distinct": "user.name",
        "threshold": 4,
        "window_seconds": 600,
    }
    sigma = next(rule for rule in rules if rule["type"] == "sigma")
    assert sigma["logsource"]
    assert sigma["threshold"] is None

    one = await client.get(f"/api/v1/detection/rules/{spray['id']}", headers=bearer(admin_token))
    assert one.json() == spray
    assert (await client.get("/api/v1/detection/rules/nope", headers=bearer(admin_token))).status_code == 404


async def test_permissions(client: httpx.AsyncClient, admin_token: str) -> None:
    await client.post(
        "/api/v1/users",
        headers=bearer(admin_token),
        json={
            "email": "vic@example.com",
            "full_name": "Vic",
            "password": "a-long-viewer-passphrase",
            "roles": ["viewer"],
        },
    )
    viewer = await login(client, "vic@example.com", "a-long-viewer-passphrase")

    assert (await client.get("/api/v1/findings", headers=bearer(viewer))).status_code == 200
    assert (await client.get("/api/v1/detection/rules", headers=bearer(viewer))).status_code == 403
    assert (await client.get("/api/v1/findings")).status_code == 401
