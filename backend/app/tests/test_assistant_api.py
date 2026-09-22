"""The assistant end to end: ingest the samples, build the bundle, ask a scripted model, validate, record, audit.

The scripted model reads the real prompt, so these tests also pin what the model is given: only the
incident's own evidence, delimited, with attacker-controlled text escaped.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx
from fastapi import FastAPI
from sqlalchemy import select

from app.conftest import Seeded, bearer, login
from app.core.audit.models import AuditLogModel
from app.core.container import Container
from app.modules.assistant.domain.ports import ModelUnavailableError
from app.modules.correlation.tests.test_incidents_api import PASSWORD, _ingest_samples, _windows_incident

_EVIDENCE = re.compile(r"<evidence>\n(.*)\n</evidence>", re.DOTALL)


def evidence_of(messages: list[dict[str, str]]) -> dict[str, Any]:
    match = _EVIDENCE.search(messages[-1]["content"])
    assert match, "the evidence is delimited"
    bundle: dict[str, Any] = json.loads(match.group(1))
    return bundle


class ScriptedModel:
    """Answers from the evidence it is handed, plus one invented citation and one invented address."""

    def __init__(self, *, fail: bool = False, invent_only: bool = False) -> None:
        self.fail = fail
        self.invent_only = invent_only
        self.prompts: list[list[dict[str, str]]] = []

    @property
    def provider(self) -> str:
        return "scripted"

    @property
    def model(self) -> str:
        return "scripted-1"

    async def complete(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> str:
        self.prompts.append(messages)
        if self.fail:
            raise ModelUnavailableError("model timed out")
        bundle = evidence_of(messages)
        logon = next(e for e in bundle["events"] if e["action"] == "Logged on")
        process = next(e for e in bundle["events"] if e["action"] == "Process started")
        invented = [{"kind": "FACT", "text": "A file was deleted.", "evidence": ["00000000-dead-beef"]}]
        grounded = [
            {"kind": "FACT", "text": "A remote logon succeeded.", "evidence": [logon["event_uid"]]},
            {
                "kind": "INFERENCE",
                "text": "The attacker ran PowerShell after logging on.",
                "evidence": [logon["event_uid"], process["event_uid"]],
                "reasoning": "Same user, minutes apart.",
                "confidence": "medium",
            },
            {"kind": "FACT", "text": "It then contacted 203.0.113.250.", "evidence": [process["event_uid"]]},
        ]
        return json.dumps(
            {
                "summary": "Brute force, RDP logon, then encoded PowerShell.",
                "statements": invented if self.invent_only else grounded + invented,
                "techniques": [{"technique_id": "T1059.001", "evidence": [process["event_uid"]], "kind": "INFERENCE"}],
                "next_steps": ["Decode the PowerShell command."],
            }
        )

    async def aclose(self) -> None:
        return None


async def _analyse(client: httpx.AsyncClient, token: str, incident_id: str) -> httpx.Response:
    return await client.post(f"/api/v1/incidents/{incident_id}/analyses", headers=bearer(token))


async def test_without_a_model_the_assistant_says_it_is_unavailable(
    client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    status = await client.get("/api/v1/assistant", headers=bearer(admin_token))
    assert status.json() == {"enabled": False, "provider": None, "model": None, "prompt_version": "assistant-v1"}
    await _ingest_samples(client, admin_token)
    incident = await _windows_incident(client, admin_token)
    response = await _analyse(client, admin_token, incident["id"])
    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


async def test_an_analysis_keeps_only_grounded_statements_and_is_audited(
    app: FastAPI, client: httpx.AsyncClient, admin_token: str, seeded: Seeded, container: Container
) -> None:
    model = ScriptedModel()
    app.state.language_model = model
    await _ingest_samples(client, admin_token)
    incident = await _windows_incident(client, admin_token)

    response = await _analyse(client, admin_token, incident["id"])
    assert response.status_code == 201, response.text
    record = response.json()
    assert (record["status"], record["provider"], record["model"]) == ("completed", "scripted", "scripted-1")
    statements = record["output"]["statements"]
    assert [s["kind"] for s in statements] == ["FACT", "INFERENCE"]
    assert {d["reason"].split(":")[0] for d in record["dropped"]} == {
        "mentions 203.0.113.250, which is not in the evidence",
        "cites events that are not in the incident",
    }
    assert record["citation_validity"] == 5 / 6
    assert record["output"]["techniques"] == [
        {"technique_id": "T1059.001", "evidence": statements[1]["evidence"][1:], "kind": "INFERENCE"}
    ]

    # Every citation that survived is evidence of this incident.
    detail = (await client.get(f"/api/v1/incidents/{incident['id']}", headers=bearer(admin_token))).json()
    cited = {uid for link in detail["links"] for uid in link["evidence"]}
    assert {uid for s in statements for uid in s["evidence"]} <= cited

    # The model saw exactly the incident's evidence, and nothing else.
    bundle = evidence_of(model.prompts[0])
    assert {event["event_uid"] for event in bundle["events"]} == cited
    assert bundle["omitted_events"] == 0
    assert "EncodedCommand" in json.dumps(bundle)

    history = (await client.get(f"/api/v1/incidents/{incident['id']}/analyses", headers=bearer(admin_token))).json()
    assert [h["id"] for h in history] == [record["id"]]
    async with container.database.sessionmaker() as session:
        [audit] = list(
            await session.scalars(select(AuditLogModel).where(AuditLogModel.action == "incident.analysis_requested"))
        )
    assert audit.after is not None
    assert audit.after["bundle_hash"] == record["bundle_hash"]
    assert audit.after["prompt_version"] == "assistant-v1"
    assert audit.resource_id == incident["id"]

    # The same incident gives the same bundle, and so the same hash.
    again = (await _analyse(client, admin_token, incident["id"])).json()
    assert again["bundle_hash"] == record["bundle_hash"]


async def test_failures_are_recorded_not_hidden(
    app: FastAPI, client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    await _ingest_samples(client, admin_token)
    incident = await _windows_incident(client, admin_token)

    app.state.language_model = ScriptedModel(fail=True)
    unavailable = (await _analyse(client, admin_token, incident["id"])).json()
    assert (unavailable["status"], unavailable["reason"], unavailable["output"]) == (
        "unavailable",
        "model timed out",
        None,
    )

    app.state.language_model = ScriptedModel(invent_only=True)
    rejected = (await _analyse(client, admin_token, incident["id"])).json()
    assert (rejected["status"], rejected["reason"]) == ("rejected", "no statement survived validation")
    assert rejected["output"] is None
    assert rejected["dropped"]


async def test_only_analysts_can_ask_but_everyone_can_read(
    app: FastAPI, client: httpx.AsyncClient, admin_token: str, seeded: Seeded
) -> None:
    app.state.language_model = ScriptedModel()
    await _ingest_samples(client, admin_token)
    created = await client.post(
        "/api/v1/users",
        headers=bearer(admin_token),
        json={"email": "viewer@example.com", "full_name": "V", "password": PASSWORD, "roles": ["viewer"]},
    )
    assert created.status_code == 201
    viewer = await login(client, "viewer@example.com", PASSWORD)
    incident = await _windows_incident(client, viewer)

    assert (await _analyse(client, viewer, incident["id"])).status_code == 403
    assert (await _analyse(client, admin_token, incident["id"])).status_code == 201
    history = await client.get(f"/api/v1/incidents/{incident['id']}/analyses", headers=bearer(viewer))
    assert len(history.json()) == 1
    missing = await _analyse(client, admin_token, "0190a2b4-0000-7000-8000-000000000000")
    assert missing.status_code == 404
