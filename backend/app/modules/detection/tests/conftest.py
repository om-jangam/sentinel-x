"""Detection test helpers: an in-memory finding store and normalised documents built from the shipped samples."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from app.core.events.bus import Event
from app.core.events.topics import EVENTS_NORMALIZED
from app.ingest_pipeline.ocsf import event_uid_for
from app.ingest_pipeline.parsers import ParseError, normalize
from app.modules.detection.domain.findings import Finding, FindingPage, FindingQuery
from app.modules.detection.domain.ports import DetectionUnitOfWork

SAMPLES = Path(__file__).resolve().parents[5] / "pipeline" / "samples"
ORG = UUID("01a0aaa3-c9b6-7213-b363-20af5c5823ee")


class MemoryFindings:
    def __init__(self) -> None:
        self.by_key: dict[str, Finding] = {}

    async def add(self, finding: Finding) -> bool:
        if finding.dedupe_key in self.by_key:
            return False
        self.by_key[finding.dedupe_key] = finding
        return True

    async def get(self, org_id: UUID, finding_id: UUID) -> Finding | None:
        return next((f for f in self.by_key.values() if f.id == finding_id and f.org_id == org_id), None)

    async def search(self, org_id: UUID, query: FindingQuery) -> FindingPage:
        return FindingPage(items=[f for f in self.by_key.values() if f.org_id == org_id])

    @property
    def all(self) -> list[Finding]:
        return list(self.by_key.values())


class MemoryUnitOfWork:
    def __init__(self, findings: MemoryFindings) -> None:
        self.findings = findings
        self.commits = 0

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        return None


def memory_uow_factory(findings: MemoryFindings) -> Any:
    @asynccontextmanager
    async def factory() -> AsyncIterator[DetectionUnitOfWork]:
        yield MemoryUnitOfWork(findings)

    return factory


def document(record: dict[str, Any], parser: str, *, source_id: str = "src-1", org_id: UUID = ORG) -> dict[str, Any]:
    """Normalise a raw record exactly as ingestion does and return the stored document."""
    event = normalize(parser, record)
    fingerprint = event.fingerprint(org_id=str(org_id), source_id=source_id)
    return event.to_document(
        org_id=str(org_id),
        source_id=source_id,
        event_uid=event_uid_for(fingerprint),
        ingested_at=datetime(2026, 9, 15, 12, tzinfo=UTC),
    )


def sample_documents(filename: str, parser: str, *, org_id: UUID = ORG) -> list[dict[str, Any]]:
    lines = [line for line in (SAMPLES / filename).read_text(encoding="utf-8").splitlines() if line.strip()]
    records = (
        [json.loads(line) for line in lines] if filename.endswith(".jsonl") else [{"message": line} for line in lines]
    )
    documents = []
    for record in records:
        try:
            documents.append(document(record, parser, org_id=org_id))
        except (ParseError, ValueError):
            continue
    return documents


def bus_event(documents: list[dict[str, Any]], org_id: UUID = ORG) -> Event:
    return Event(
        topic=EVENTS_NORMALIZED,
        org_id=org_id,
        payload={"documents": [{"stream": "x", "id": "x", "body": body} for body in documents]},
    )


SAMPLE_SETS = (
    ("linux_auth.log", "linux_auth"),
    ("windows_security.jsonl", "windows_security"),
    ("ocsf_network.jsonl", "ocsf"),
)
