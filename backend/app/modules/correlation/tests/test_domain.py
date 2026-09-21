from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from app.core.errors import ConflictError, ValidationFailedError
from app.modules.correlation.domain.entities import Entity, extract, normalise_host
from app.modules.correlation.domain.incidents import (
    CorrelationRule,
    Incident,
    IncidentCursor,
    IncidentLink,
    IncidentQuery,
    IncidentStatus,
    LinkKind,
    Resolution,
)

NOW = datetime(2026, 9, 15, 12, tzinfo=UTC)


def doc(class_uid: int, **fields: Any) -> dict[str, Any]:
    return {"class_uid": class_uid, "time": 1_757_930_000_000, "sx": {"event_uid": "e1"}, **fields}


def entities(document: dict[str, Any]) -> dict[str, Entity]:
    return {s.entity.key: s.entity for s in extract(document)}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("WS-FIN-07.acme.example", "ws-fin-07"),
        ("WS-FIN-07", "ws-fin-07"),
        ("web-01.", "web-01"),
        ("UNKNOWN-HOST", None),
        ("-", None),
        ("10.0.5.17", None),
    ],
)
def test_host_names_normalise_to_the_short_name(raw: str, expected: str | None) -> None:
    assert normalise_host(raw) == expected


def test_authentication_ignores_the_client_claimed_workstation_name() -> None:
    found = entities(
        doc(
            3002,
            device={"hostname": "WS-FIN-07.acme.example"},
            src_endpoint={"ip": "198.51.100.23", "hostname": "KALI"},
            user={"name": "jsmith", "domain": "ACME"},
        )
    )
    assert set(found) == {"host:ws-fin-07", "ip:198.51.100.23", "user:acme\\jsmith"}
    assert all(entity.links for entity in found.values())


def test_outbound_connections_name_our_host_and_their_domain() -> None:
    found = entities(
        doc(
            4001,
            src_endpoint={"ip": "10.0.5.17", "hostname": "WS-FIN-07"},
            dst_endpoint={"ip": "192.0.2.66", "hostname": "CDN-Telemetry-Sync.example"},
        )
    )
    assert set(found) == {"host:ws-fin-07", "ip:10.0.5.17", "ip:192.0.2.66", "domain:cdn-telemetry-sync.example"}
    assert not found["ip:10.0.5.17"].links, "internal addresses never join incidents"
    assert found["ip:192.0.2.66"].links


def test_users_without_a_domain_are_scoped_to_the_host() -> None:
    found = entities(doc(3002, device={"hostname": "web-01"}, user={"name": "Root"}))
    assert "user:root@web-01" in found
    assert entities(doc(3002, user={"name": "root"})) == {}, "an unscoped user can't be told apart"


@pytest.mark.parametrize("name", ["SYSTEM", "-", "WS-FIN-07$", "ANONYMOUS LOGON"])
def test_built_in_and_machine_accounts_are_not_users(name: str) -> None:
    assert not any(
        key.startswith("user:") for key in entities(doc(3002, device={"hostname": "h"}, user={"name": name}))
    )


def test_processes_and_paths_are_context_but_hashes_link() -> None:
    found = entities(
        doc(
            1007,
            device={"hostname": "h"},
            process={
                "name": "PowerShell.exe",
                "file": {"path": "C:\\Windows\\powershell.exe", "hashes": [{"algorithm_id": 3, "value": "AB" * 32}]},
            },
        )
    )
    assert not found["process:powershell.exe"].links
    assert not found["file:C:\\Windows\\powershell.exe"].links
    assert found[f"hash:{'ab' * 32}"].links


def test_events_without_identity_have_no_entities() -> None:
    assert extract({"class_uid": 3002, "device": {"hostname": "h"}}) == []


def _incident(**overrides: Any) -> Incident:
    values: dict[str, Any] = {
        "id": uuid4(),
        "org_id": uuid4(),
        "title": "t",
        "severity_id": 3,
        "status": IncidentStatus.NEW,
        "first_seen": NOW,
        "last_seen": NOW,
        "created_at": NOW,
        "updated_at": NOW,
    }
    return Incident(**(values | overrides))


def test_status_changes_bump_the_version() -> None:
    incident = _incident()
    incident.change_status(IncidentStatus.INVESTIGATING, None, expected_version=1, now=NOW)
    incident.change_status(IncidentStatus.CLOSED, Resolution.TRUE_POSITIVE, expected_version=2, now=NOW)
    assert (incident.status, incident.resolution, incident.closed_at, incident.version) == (
        IncidentStatus.CLOSED,
        Resolution.TRUE_POSITIVE,
        NOW,
        3,
    )
    incident.change_status(IncidentStatus.INVESTIGATING, None, expected_version=3, now=NOW)  # reopen
    assert incident.resolution is None
    assert incident.closed_at is None


@pytest.mark.parametrize(
    ("status", "resolution", "version", "error"),
    [
        (IncidentStatus.CLOSED, None, 1, ValidationFailedError),
        (IncidentStatus.INVESTIGATING, Resolution.FALSE_POSITIVE, 1, ValidationFailedError),
        (IncidentStatus.INVESTIGATING, None, 7, ConflictError),
        (IncidentStatus.NEW, None, 1, ConflictError),
    ],
)
def test_invalid_status_changes_are_refused(
    status: IncidentStatus, resolution: Resolution | None, version: int, error: type[Exception]
) -> None:
    with pytest.raises(error):
        _incident().change_status(status, resolution, expected_version=version, now=NOW)


def test_an_investigating_incident_cannot_return_to_new() -> None:
    incident = _incident(status=IncidentStatus.INVESTIGATING)
    with pytest.raises(ConflictError):
        incident.change_status(IncidentStatus.NEW, None, expected_version=1, now=NOW)


def _link(**overrides: Any) -> IncidentLink:
    values: dict[str, Any] = {
        "id": uuid4(),
        "org_id": uuid4(),
        "incident_id": uuid4(),
        "kind": LinkKind.FINDING,
        "rule": CorrelationRule.OPENED,
        "reason": "r",
        "evidence": ("e1",),
        "matched": (),
        "first_seen": NOW,
        "last_seen": NOW,
        "created_at": NOW,
        "finding_id": uuid4(),
    }
    return IncidentLink(**(values | overrides))


def test_links_must_cite_evidence_and_justify_themselves() -> None:
    _link()
    with pytest.raises(ValueError, match="cite"):
        _link(evidence=())
    with pytest.raises(ValueError, match="entities"):
        _link(rule=CorrelationRule.SHARED_ENTITY)
    with pytest.raises(ValueError, match="finding_id"):
        _link(kind=LinkKind.EVENT)


def test_cursor_and_query_validation() -> None:
    cursor = IncidentCursor(123, str(uuid4()))
    assert IncidentCursor.decode(cursor.encode()) == cursor
    for bad in ("x:y", "12", f"abc:{uuid4()}", "12:not-a-uuid"):
        with pytest.raises(ValidationFailedError):
            IncidentCursor.decode(bad)
    with pytest.raises(ValidationFailedError):
        IncidentQuery(time_from=NOW, time_to=NOW)
    with pytest.raises(ValidationFailedError):
        IncidentQuery(limit=0, severity_min=9)
