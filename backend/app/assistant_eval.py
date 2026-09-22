"""Evaluation of the assistant on labelled incidents from the sample stories (docs/04 §8).

Builds the two sample incidents in a throwaway database through the real pipeline, asks the model about
each, and scores the raw answer:

- citation validity: the share of cited event_uids that exist in the bundle. It must be 100%. The validator
  drops bad citations anyway, but a model that invents them is not fit to deploy.
- key-event recall: how many of the events an analyst must see (the successful logon, the encoded
  PowerShell, …) the surviving statements cite;
- unsupported rate: the share of returned statements the validator dropped;
- technique precision and recall against the ATT&CK techniques the evidence supports.

Key events are labelled by what they are (action, process, remote address), not by event_uid, because
uids depend on the organisation and source they were ingested under.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import select

from app.analysis import build_analysis
from app.assistant_bundle import SqlBundleSource
from app.core.db.session import Database
from app.core.events.bus import Event
from app.core.events.topics import EVENTS_NORMALIZED
from app.core.ids import uuid7
from app.ingest_pipeline.ocsf import event_uid_for
from app.ingest_pipeline.parsers import ParseError, normalize
from app.model_registry import metadata
from app.modules.assistant.domain.analysis import validate
from app.modules.assistant.domain.bundle import BundleEvent, EvidenceBundle
from app.modules.assistant.domain.ports import LanguageModel, ModelUnavailableError
from app.modules.assistant.domain.prompt import OUTPUT_SCHEMA, messages
from app.modules.correlation.infrastructure.models import IncidentModel
from app.modules.detection.infrastructure.rule_loader import load_rules
from app.modules.detection.infrastructure.window_store import InMemoryWindowStore
from app.modules.identity.infrastructure.models import OrgModel

SAMPLES = Path(__file__).resolve().parents[2] / "pipeline" / "samples"
SAMPLE_FILES = (
    ("linux_auth.log", "linux_auth"),
    ("windows_security.jsonl", "windows_security"),
    ("ocsf_network.jsonl", "ocsf"),
)

Matcher = Callable[[BundleEvent], bool]


def _action(action: str, **roles: str) -> Matcher:
    def match(event: BundleEvent) -> bool:
        return event.action == action and all(value in event.entities.get(role, []) for role, value in roles.items())

    return match


@dataclass(frozen=True)
class Case:
    name: str
    host: str  # which sample incident: the one whose title names this host
    key_events: dict[str, Matcher]
    techniques: frozenset[str]  # base technique IDs the evidence supports


CASES = (
    Case(
        name="ws-fin-07 compromise",
        host="ws-fin-07",
        key_events={
            "failed logons from 198.51.100.23": _action("Failed logon", src_ip="198.51.100.23"),
            "successful RDP logon": _action("Logged on", src_ip="198.51.100.23"),
            "encoded PowerShell": _action("Process started", process="powershell.exe"),
            "discovery with whoami": _action("Process started", process="whoami.exe"),
            "discovery with net": _action("Process started", process="net.exe"),
            "beacon to 192.0.2.66": _action("Network connection", dst_ip="192.0.2.66"),
        },
        techniques=frozenset({"T1110", "T1059", "T1027", "T1033", "T1069", "T1071", "T1078", "T1021"}),
    ),
    Case(
        name="web-01 SSH spray",
        host="web-01",
        key_events={
            "failed SSH logons from 203.0.113.45": _action("Failed logon", src_ip="203.0.113.45"),
            "successful logon as deploy": _action("Logged on", src_ip="203.0.113.45"),
        },
        techniques=frozenset({"T1110", "T1078", "T1021"}),
    ),
)


@dataclass
class CaseResult:
    case: str
    status: str
    citation_validity: float | None = None
    key_event_recall: float = 0.0
    unsupported_rate: float | None = None
    technique_precision: float | None = None
    technique_recall: float = 0.0
    missed_key_events: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.status == "completed" and self.citation_validity == 1.0


def score(case: Case, bundle: EvidenceBundle, raw: str) -> CaseResult:
    result = validate(raw, bundle)
    if result.analysis is None:
        return CaseResult(case.name, "rejected", result.citation_validity, detail={"reason": result.rejected_reason})
    cited = {uid for s in result.analysis.statements for uid in s.evidence}
    found = {
        label: any(match(event) and event.event_uid in cited for event in bundle.events)
        for label, match in case.key_events.items()
    }
    suggested = {t.technique_id.split(".")[0] for t in result.analysis.techniques}
    returned = result.stats.get("statements_returned", 0)
    return CaseResult(
        case=case.name,
        status="completed",
        citation_validity=result.citation_validity,
        key_event_recall=sum(found.values()) / len(found),
        unsupported_rate=None if not returned else result.stats.get("dropped", 0) / returned,
        technique_precision=None if not suggested else len(suggested & case.techniques) / len(suggested),
        technique_recall=len(suggested & case.techniques) / len(case.techniques),
        missed_key_events=[label for label, hit in found.items() if not hit],
        detail={"kept": result.stats.get("statements_kept", 0), "dropped": [d.reason for d in result.dropped]},
    )


async def sample_bundles() -> dict[str, EvidenceBundle]:
    """The two sample incidents, built through the real pipeline in a throwaway SQLite database."""
    with tempfile.TemporaryDirectory() as tmp:
        database = Database(f"sqlite+aiosqlite:///{Path(tmp).as_posix()}/eval.db")
        try:
            async with database.engine.begin() as connection:
                await connection.run_sync(metadata.create_all)
            org_id = uuid7()
            async with database.sessionmaker() as session:
                session.add(OrgModel(id=org_id, name="Evaluation", slug="evaluation"))
                await session.commit()
            analysis = build_analysis(load_rules(), database, InMemoryWindowStore())
            for filename, parser in SAMPLE_FILES:
                await analysis.handle(_batch(org_id, filename, parser))
            bundles: dict[str, EvidenceBundle] = {}
            async with database.sessionmaker() as session:
                for incident in await session.scalars(select(IncidentModel)):
                    bundle = await SqlBundleSource(session).build(org_id, incident.id)
                    if bundle is not None:
                        host = next((c.host for c in CASES if c.host in incident.title), incident.title)
                        bundles[host] = bundle
            return bundles
        finally:
            await database.dispose()


def _batch(org_id: UUID, filename: str, parser: str) -> Event:
    lines = [line for line in (SAMPLES / filename).read_text(encoding="utf-8").splitlines() if line.strip()]
    documents = []
    for line in lines:
        record = json.loads(line) if filename.endswith(".jsonl") else {"message": line}
        try:
            event = normalize(parser, record)
        except (ParseError, ValueError):
            continue
        fingerprint = event.fingerprint(org_id=str(org_id), source_id=parser)
        documents.append(
            event.to_document(
                org_id=str(org_id),
                source_id=parser,
                event_uid=event_uid_for(fingerprint),
                ingested_at=datetime.now(UTC),
            )
        )
    return Event(topic=EVENTS_NORMALIZED, org_id=org_id, payload={"documents": [{"body": d} for d in documents]})


async def evaluate(model: LanguageModel) -> list[CaseResult]:
    bundles = await sample_bundles()
    results: list[CaseResult] = []
    for case in CASES:
        bundle = bundles.get(case.host)
        if bundle is None:
            results.append(CaseResult(case.name, "missing", detail={"reason": "the sample incident was not built"}))
            continue
        try:
            raw = await model.complete(messages(bundle), OUTPUT_SCHEMA)
        except ModelUnavailableError as exc:
            results.append(CaseResult(case.name, "unavailable", detail={"reason": str(exc)}))
            continue
        results.append(score(case, bundle, raw))
    return results
