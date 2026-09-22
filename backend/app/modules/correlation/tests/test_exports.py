"""Navigator layers and Attack Flow bundles: valid documents that add nothing the incident doesn't hold."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.conftest import Seeded, bearer
from app.modules.correlation.domain.exports import ATTACK_FLOW_EXTENSION, LAYER_VERSION
from app.modules.correlation.tests.test_incidents_api import _ingest_samples


async def incident_id(client: httpx.AsyncClient, token: str) -> str:
    await _ingest_samples(client, token)
    listing = await client.get("/api/v1/incidents", headers=bearer(token))
    assert listing.status_code == 200, listing.text
    windows = next(item for item in listing.json()["items"] if "ws-fin-07" in item["title"])
    return str(windows["id"])


def objects(bundle: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [item for item in bundle["objects"] if item["type"] == kind]


async def test_navigator_layer_scores_the_techniques_the_findings_named(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    uid = await incident_id(client, admin_token)
    detail = (await client.get(f"/api/v1/incidents/{uid}", headers=bearer(admin_token))).json()

    response = await client.get(f"/api/v1/incidents/{uid}/exports/attack-navigator", headers=bearer(admin_token))
    assert response.status_code == 200, response.text
    layer = response.json()

    assert layer["versions"]["layer"] == LAYER_VERSION
    assert layer["domain"] == "enterprise-attack"
    assert str(uid) in layer["description"]
    exported = {technique["techniqueID"] for technique in layer["techniques"]}
    assert exported == {t.upper() for t in detail["techniques"]}, "only techniques the incident already names"
    for technique in layer["techniques"]:
        assert technique["score"] >= 1, "the score is how many events show it"
        assert technique["comment"], "the rule that named it"
        assert "tactic" not in technique, "no tactic row: the score applies wherever the technique appears"
    assert layer["gradient"]["maxValue"] >= max(technique["score"] for technique in layer["techniques"])


async def test_attack_flow_follows_the_timeline_and_cites_its_events(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    uid = await incident_id(client, admin_token)
    timeline = (await client.get(f"/api/v1/incidents/{uid}/timeline", headers=bearer(admin_token))).json()

    response = await client.get(f"/api/v1/incidents/{uid}/exports/attack-flow", headers=bearer(admin_token))
    assert response.status_code == 200, response.text
    bundle = response.json()

    assert bundle["type"] == "bundle"
    assert objects(bundle, "extension-definition")[0]["id"] == ATTACK_FLOW_EXTENSION
    [flow] = objects(bundle, "attack-flow")
    actions = objects(bundle, "attack-action")

    assert flow["scope"] == "incident"
    assert len(actions) == len(timeline["steps"]) > 0
    assert flow["start_refs"] == [actions[0]["id"]]
    # Every action but the last points at the next one, so the flow reads in the order things happened.
    assert [action.get("effect_refs") for action in actions] == [[a["id"]] for a in actions[1:]] + [None]
    for action, step in zip(actions, timeline["steps"], strict=True):
        assert action["spec_version"] == "2.1"
        assert action["extensions"][ATTACK_FLOW_EXTENSION] == {"extension_type": "new-sdo"}
        assert action["name"] == step["action"]
        assert action["x_sentinelx_event_uids"] == step["events"], "the events that show this action"
        assert action["id"].startswith("attack-action--")
    assert any("technique_id" in action for action in actions)

    hosts = {asset["name"] for asset in objects(bundle, "attack-asset") if asset["description"] == "host"}
    assert hosts <= {entity["value"] for entity in (await _entities(client, admin_token, uid))}


async def _entities(client: httpx.AsyncClient, token: str, uid: str) -> list[dict[str, Any]]:
    detail = (await client.get(f"/api/v1/incidents/{uid}", headers=bearer(token))).json()
    return list(detail["entities"])


async def test_exports_are_stable_between_runs(client: httpx.AsyncClient, admin_token: str, seeded: Seeded) -> None:
    """Ids are derived from the incident, so two exports of an unchanged incident are identical."""
    uid = await incident_id(client, admin_token)

    async def flow() -> dict[str, Any]:
        response = await client.get(f"/api/v1/incidents/{uid}/exports/attack-flow", headers=bearer(admin_token))
        return dict(response.json())

    first, second = await flow(), await flow()
    for document in (first, second):
        for item in document["objects"]:
            item.pop("modified", None)
    assert first == second


@pytest.mark.parametrize("export", ["attack-navigator", "attack-flow"])
async def test_exports_need_incident_read(client: httpx.AsyncClient, export: str, seeded: Seeded) -> None:
    uid = "01a0a000-0000-7000-8000-000000000001"
    assert (await client.get(f"/api/v1/incidents/{uid}/exports/{export}")).status_code == 401


async def test_the_report_carries_the_evidence_and_marks_notes_as_statements(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    uid = await incident_id(client, admin_token)
    await client.post(
        f"/api/v1/incidents/{uid}/notes",
        headers=bearer(admin_token),
        json={"body": "Contained the host and reset the account."},
    )
    timeline = (await client.get(f"/api/v1/incidents/{uid}/timeline", headers=bearer(admin_token))).json()

    response = await client.get(f"/api/v1/incidents/{uid}/exports/report.md", headers=bearer(admin_token))
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/markdown")
    report = response.text

    for heading in ("# ", "## Why this severity", "## What happened", "## Findings", "## Entities", "## Analyst notes"):
        assert heading in report
    assert "Statements by people, not evidence." in report
    assert "Contained the host and reset the account." in report
    # Every timeline step appears with the events that show it.
    for step in timeline["steps"]:
        assert step["action"] in report
        assert f"`{step['events'][0]}`" in report
    assert "GET /api/v1/events/{event_uid}" in report, "the reader is told how to check a citation"


async def test_the_report_needs_incident_read(client: httpx.AsyncClient, seeded: Seeded) -> None:
    uid = "01a0a000-0000-7000-8000-000000000001"
    assert (await client.get(f"/api/v1/incidents/{uid}/exports/report.md")).status_code == 401
