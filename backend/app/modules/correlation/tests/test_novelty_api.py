"""Novelty through the API: what the organisation had seen before, counted from every batch."""

from __future__ import annotations

import httpx

from app.conftest import Seeded, bearer
from app.modules.correlation.tests.test_exports import incident_id
from app.modules.correlation.tests.test_incidents_api import _ingest


async def test_novelty_reports_what_was_new_and_since_when(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    uid = await incident_id(client, admin_token)

    response = await client.get(f"/api/v1/incidents/{uid}/novelty", headers=bearer(admin_token))
    assert response.status_code == 200, response.text
    body = response.json()

    keys = {item["key"] for item in body["items"]}
    assert "explorer.exe -> powershell.exe" in keys, "the parent/child pair the events state"
    assert "192.0.2.66" in keys, "the external destination"
    assert "ws-fin-07 -> 192.0.2.66" in keys
    assert all(item["new_here"] for item in body["items"]), "nothing was known before this incident"
    assert body["new_count"] == len(body["items"])
    assert body["coverage_from"] is not None, "the baseline says since when it has been counting"
    for item in body["items"]:
        assert item["summary"]
        assert item["kind"] in {"process_pair", "host_remote", "remote"}


async def test_ordinary_activity_teaches_the_baseline(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    """A batch with no finding still counts: otherwise everything an incident touches looks new."""
    benign = [
        {
            "class_uid": 1007,
            "activity_id": 1,
            "status_id": 1,
            "severity_id": 1,
            "time": "2026-09-14T08:00:00Z",
            "metadata": {"product": {"name": "Sysmon"}},
            "device": {"hostname": "ws-fin-07"},
            "process": {"name": "powershell.exe", "parent_process": {"name": "explorer.exe"}},
        }
    ]
    await _ingest(client, admin_token, "benign-endpoint", "ocsf", benign)
    uid = await incident_id(client, admin_token)

    body = (await client.get(f"/api/v1/incidents/{uid}/novelty", headers=bearer(admin_token))).json()
    pair = next(item for item in body["items"] if item["key"] == "explorer.exe -> powershell.exe")
    assert pair["observations"] >= 2, "the benign event and the incident's own event both count"
    assert pair["new_here"] is False, "it was seen before this incident started"
    assert "seen" in pair["summary"]


async def test_novelty_needs_incident_read(client: httpx.AsyncClient, seeded: Seeded) -> None:
    uid = "01a0a000-0000-7000-8000-000000000001"
    assert (await client.get(f"/api/v1/incidents/{uid}/novelty")).status_code == 401
