"""Findings through the real API: ingest the Windows story, detection runs in-process, read the results."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import httpx
import pytest

from app.conftest import Seeded, bearer, login
from app.core.pagination import encode_cursor
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


async def rule_pages(
    client: httpx.AsyncClient, token: str, *, limit: int = 200, extra: str = ""
) -> list[dict[str, Any]]:
    """Every matching rule, by following `next_cursor` to the end."""
    rules: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(50):  # a bound, so a cursor that never advances fails the test instead of hanging
        query = f"limit={limit}" + (f"&{extra}" if extra else "") + (f"&cursor={cursor}" if cursor else "")
        page = (await client.get(f"/api/v1/detection/rules?{query}", headers=bearer(token))).json()
        rules += page["items"]
        cursor = page["next_cursor"]
        if cursor is None:
            return rules
    raise AssertionError("pagination did not terminate")


async def test_the_rule_catalogue_is_paginated_in_title_order(client: httpx.AsyncClient, admin_token: str) -> None:
    first = (await client.get("/api/v1/detection/rules?limit=2", headers=bearer(admin_token))).json()
    assert len(first["items"]) == 2
    assert first["next_cursor"], "926 rules do not fit in one page"

    second = (
        await client.get(f"/api/v1/detection/rules?limit=2&cursor={first['next_cursor']}", headers=bearer(admin_token))
    ).json()
    assert [rule["id"] for rule in second["items"]] != [rule["id"] for rule in first["items"]]

    all_rules = await rule_pages(client, admin_token, limit=200)
    titles = [rule["title"].casefold() for rule in all_rules]
    assert titles == sorted(titles), "a stable order, so a page boundary means something"
    assert len({rule["id"] for rule in all_rules}) == len(all_rules), "no rule is served twice"
    # The whole catalogue in one request still works, for a client that wants it.
    one_page = (await client.get("/api/v1/detection/rules?limit=200", headers=bearer(admin_token))).json()
    assert [rule["id"] for rule in one_page["items"]] == [rule["id"] for rule in all_rules[:200]]


@pytest.mark.parametrize("cursor", ["not-base64!", "", "aaaa", encode_cursor("x" * 65)])
async def test_a_cursor_that_is_not_a_rule_is_refused(client: httpx.AsyncClient, admin_token: str, cursor: str) -> None:
    """Including a valid cursor for a rule that no longer exists: resuming would skip rules silently."""
    response = await client.get(f"/api/v1/detection/rules?cursor={cursor}", headers=bearer(admin_token))
    assert response.status_code == 422


async def test_the_catalogue_filters_by_technique_and_logsource(client: httpx.AsyncClient, admin_token: str) -> None:
    async def rules(query: str) -> list[dict[str, Any]]:
        return await rule_pages(client, admin_token, extra=query)

    spraying = await rules("technique=T1110.003")
    assert spraying, "the shipped spray rules are tagged T1110.003"
    for rule in spraying:
        assert any(t.startswith("T1110") for t in rule["techniques"]), rule["title"]

    # The parent technique finds everything the sub-technique does, and more.
    parent = {rule["id"] for rule in await rules("technique=T1110")}
    assert {rule["id"] for rule in spraying} <= parent
    assert len(parent) > len(spraying)

    security = await rules("logsource=windows/security")
    assert security
    assert {rule["logsource"] for rule in security} == {"windows/security"}
    assert all(rule["type"] == "sigma" for rule in security), "threshold rules belong to no logsource"

    both = await rules("technique=T1059.001&logsource=process_creation")
    assert both
    for rule in both:
        assert rule["logsource"] == "process_creation"
        assert any(t.startswith("T1059") for t in rule["techniques"]), rule["title"]

    nothing = (await client.get("/api/v1/detection/rules?technique=T9999", headers=bearer(admin_token))).json()
    assert nothing == {"items": [], "next_cursor": None}, "a technique nothing covers is empty, not an error"


@pytest.mark.parametrize(
    "query",
    ["technique=1110", "technique=T1110.3", "logsource=", "limit=0", "limit=201", "cursor=not-base64!"],
)
async def test_an_unusable_rule_query_is_refused(client: httpx.AsyncClient, admin_token: str, query: str) -> None:
    response = await client.get(f"/api/v1/detection/rules?{query}", headers=bearer(admin_token))
    assert response.status_code == 422, query


async def test_the_rule_set_exports_as_a_navigator_layer(client: httpx.AsyncClient, admin_token: str) -> None:
    layer = (await client.get("/api/v1/detection/exports/attack-navigator", headers=bearer(admin_token))).json()

    assert layer["versions"]["layer"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert len(layer["techniques"]) > 150
    covered = {entry["techniqueID"] for entry in layer["techniques"]}
    assert "T1110.003" in covered, "the technique the shipped spray rules claim"
    assert "not evidence that it would be caught" in layer["description"]

    scores = {entry["techniqueID"]: entry["score"] for entry in layer["techniques"]}
    assert scores["T1110.003"] >= 1
    assert layer["gradient"]["maxValue"] == max(scores.values())


async def test_rules_catalogue(client: httpx.AsyncClient, admin_token: str) -> None:
    rules = await rule_pages(client, admin_token)
    assert len(rules) >= 900, "own rules plus every evaluable SigmaHQ rule"
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
    layer = await client.get("/api/v1/detection/exports/attack-navigator", headers=bearer(viewer))
    assert layer.status_code == 403, "the coverage layer is the rule set, so it needs rule:read too"
    assert (await client.get("/api/v1/findings")).status_code == 401
