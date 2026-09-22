"""Sysmon evidence in the graph and timeline: which program did it, when one event says so."""

from __future__ import annotations

from typing import Any

from app.ingest_pipeline.tests import sysmon_records as r
from app.modules.correlation.domain.evidence import EvidenceEvent, digest
from app.modules.correlation.domain.graph import relations
from app.modules.detection.tests.conftest import document

HOST = "host:ws-fin-07"


def evidence(record: dict[str, Any]) -> EvidenceEvent:
    event = digest(document(record, "windows_sysmon"))
    assert event is not None
    return event


def test_a_sysmon_connection_names_the_program_that_connected() -> None:
    found = set(relations(evidence(r.NETWORK)))
    assert (HOST, "connected_to", "ip:192.0.2.66") in found
    assert ("process:powershell.exe", "connected_to", "ip:192.0.2.66") in found


def test_a_connection_without_a_process_does_not_invent_one() -> None:
    """A firewall-style record states host and addresses only; no process edge may appear."""
    record = {**r.NETWORK, "EventData": {k: v for k, v in r.NETWORK["EventData"].items() if k != "Image"}}
    assert not [rel for rel in relations(evidence(record)) if rel[0].startswith("process:")]


def test_process_creation_links_parent_child_and_user() -> None:
    found = set(relations(evidence(r.PROCESS_CREATE)))
    assert ("process:winword.exe", "spawned", "process:powershell.exe") in found
    assert ("user:corp\\jsmith", "started", "process:powershell.exe") in found


def test_lsass_access_is_an_open_not_a_start() -> None:
    found = relations(evidence(r.LSASS_ACCESS))
    assert found == [("process:m.exe", "opened", "process:lsass.exe")]


def test_remote_thread_is_an_injection_edge() -> None:
    assert ("process:powershell.exe", "injected_into", "process:explorer.exe") in relations(evidence(r.REMOTE_THREAD))


def test_a_terminated_process_is_not_reported_as_started() -> None:
    assert not [rel for rel in relations(evidence(r.TERMINATE)) if rel[1] in ("started", "spawned")]


def test_dns_and_file_events_name_the_program() -> None:
    assert ("process:powershell.exe", "queried", "domain:update.bad.example") in relations(evidence(r.DNS))
    file_rels = relations(evidence(r.FILE_CREATE))
    assert ("process:powershell.exe", "file_activity", f"file:{r.MIMIKATZ}") in file_rels


def test_timeline_actions_describe_sysmon_events() -> None:
    assert evidence(r.LSASS_ACCESS).action == "Process opened another process"
    assert evidence(r.REG_SET_RUN_KEY).action == "Registry value set"
    assert evidence(r.IMAGE_LOAD).action == "Module loaded"
    assert evidence(r.FILE_DELETE).action == "File deleted"
