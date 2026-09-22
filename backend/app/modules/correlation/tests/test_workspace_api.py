"""The incident workspace API: timeline, graph, evidence and notes, over HTTP after ingesting the samples."""

from __future__ import annotations

import hashlib

import httpx
from sqlalchemy import select

from app.conftest import Seeded, bearer
from app.core.audit.models import AuditLogModel
from app.core.container import Container
from app.modules.correlation.tests.test_incidents_api import _ingest_samples, _user_token, _windows_incident


async def test_timeline_graph_and_evidence_agree(client: httpx.AsyncClient, admin_token: str, seeded: Seeded) -> None:
    await _ingest_samples(client, admin_token)
    incident = await _windows_incident(client, admin_token)
    base = f"/api/v1/incidents/{incident['id']}"

    timeline = await client.get(f"{base}/timeline", headers=bearer(admin_token))
    graph = await client.get(f"{base}/graph", headers=bearer(admin_token))
    evidence = await client.get(f"{base}/evidence", headers=bearer(admin_token))
    detail = await client.get(base, headers=bearer(admin_token))
    for response in (timeline, graph, evidence, detail):
        assert response.status_code == 200, response.text

    steps = timeline.json()["steps"]
    assert [step["action"] for step in steps] == [
        "Failed logon",
        "Logged on",
        "Process started",
        "Process started",
        "Process started",
        "Network connection",
    ]
    assert timeline.json()["unresolved_events"] == []
    cited = {uid for link in detail.json()["links"] for uid in link["evidence"]}
    events = {event["event_uid"]: event for event in evidence.json()["events"]}
    assert set(events) == cited
    assert sorted(uid for step in steps for uid in step["events"]) == sorted(cited)
    link_ids = {link["id"] for link in detail.json()["links"]}
    for step in steps:
        assert {c["link_id"] for c in step["citations"]} <= link_ids
    for edge in graph.json()["edges"]:
        assert set(edge["events"]) <= cited
    for event in events.values():
        assert set(event["cited_by"]) <= link_ids
        assert event["cited_by"]

    powershell = next(e for e in events.values() if "powershell.exe" in e["roles"].get("process", [""])[0])
    assert powershell["detail"]["cmd_line"].startswith("powershell.exe -NoProfile")
    linux = await client.get("/api/v1/incidents?severity_min=4&status=new", headers=bearer(admin_token))
    web = next(i for i in linux.json()["items"] if "web-01" in i["title"])
    web_events = (await client.get(f"/api/v1/incidents/{web['id']}/evidence", headers=bearer(admin_token))).json()
    assert all(event["raw"] and "sshd[" in event["raw"] for event in web_events["events"]), "raw excerpts kept"


async def test_notes_are_append_only_audited_and_permissioned(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded, container: Container
) -> None:
    await _ingest_samples(client, admin_token)
    viewer = await _user_token(client, admin_token, "viewer@example.com", "viewer")
    analyst = await _user_token(client, admin_token, "analyst@example.com", "analyst")
    incident = await _windows_incident(client, viewer)
    url = f"/api/v1/incidents/{incident['id']}/notes"

    assert (await client.get(url, headers=bearer(viewer))).json() == []
    denied = await client.post(url, headers=bearer(viewer), json={"body": "looks bad"})
    assert denied.status_code == 403

    body = "RDP from 198.51.100.23 right after the burst; checking the VPN logs next."
    created = await client.post(url, headers=bearer(analyst), json={"body": body})
    assert created.status_code == 201, created.text
    note = created.json()
    assert (note["author_email"], note["body"]) == ("analyst@example.com", body)
    second = await client.post(url, headers=bearer(admin_token), json={"body": "Escalated to IR."})
    assert second.status_code == 201

    listed = (await client.get(url, headers=bearer(viewer))).json()
    assert [n["body"] for n in listed] == [body, "Escalated to IR."]

    for bad in ({"body": ""}, {"body": "   "}, {"body": "x" * 10_001}, {"body": "ok", "pinned": True}):
        assert (await client.post(url, headers=bearer(analyst), json=bad)).status_code == 422, bad
    # There is no way to edit or delete a note.
    note_url = f"{url}/{note['id']}"
    assert (await client.patch(note_url, headers=bearer(admin_token), json={"body": "x"})).status_code in (404, 405)
    assert (await client.delete(note_url, headers=bearer(admin_token))).status_code in (404, 405)

    async with container.database.sessionmaker() as session:
        rows = list(await session.scalars(select(AuditLogModel).where(AuditLogModel.action == "incident.note_added")))
    assert len(rows) == 2
    first = next(row for row in rows if (row.after or {}).get("note_id") == note["id"])
    assert first.after == {
        "note_id": note["id"],
        "length": len(body),
        "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
    }
    assert first.resource_id == incident["id"]


async def test_workspace_endpoints_are_scoped_and_guarded(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    missing = "/api/v1/incidents/0190a2b4-0000-7000-8000-000000000000"
    for suffix in ("timeline", "graph", "evidence", "notes"):
        assert (await client.get(f"{missing}/{suffix}", headers=bearer(admin_token))).status_code == 404
        assert (await client.get(f"{missing}/{suffix}")).status_code == 401
    posted = await client.post(f"{missing}/notes", headers=bearer(admin_token), json={"body": "x"})
    assert posted.status_code == 404


async def test_raw_record_excerpts_need_event_read(client: httpx.AsyncClient, admin_token: str, seeded: Seeded) -> None:
    await _ingest_samples(client, admin_token)
    role = await client.post(
        "/api/v1/roles", headers=bearer(admin_token), json={"name": "incident_viewer", "permissions": ["incident:read"]}
    )
    assert role.status_code == 201, role.text
    reader = await _user_token(client, admin_token, "reader@example.com", "incident_viewer")
    incident = await _windows_incident(client, reader)
    url = f"/api/v1/incidents/{incident['id']}/evidence"

    limited = (await client.get(url, headers=bearer(reader))).json()["events"]
    full = (await client.get(url, headers=bearer(admin_token))).json()["events"]
    assert any(event["raw"] for event in full)
    assert all(event["raw"] is None for event in limited), "the original record is event content"
    assert [e["event_uid"] for e in limited] == [e["event_uid"] for e in full], "the digests themselves are shown"
