"""Bus consumer: evaluate every normalised event against the rule set and store evidence-citing findings."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from time import perf_counter
from typing import Any
from uuid import UUID

from app.core.clock import Clock, utcnow
from app.core.events.bus import Event
from app.core.ids import uuid7
from app.core.observability.metrics import DETECTION_FINDINGS, DETECTION_SECONDS
from app.modules.detection.domain.findings import MAX_ENTITY_VALUES, MAX_EVIDENCE, Finding
from app.modules.detection.domain.ports import FindingSink, UnitOfWorkFactory, WindowEntry, WindowStore
from app.modules.detection.domain.predicates import Document, values_at
from app.modules.detection.domain.rules import Rule, RuleSet, SingleEventRule, ThresholdRule

logger = logging.getLogger(__name__)

MAX_ENTITY_NAMES = 20
# A threshold rule that fired, and must be recorded as fired once its finding is committed.
Fired = tuple[str, int, int]


def _digest(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8"))
        digest.update(b"\x1f")
    return digest.hexdigest()


def _at(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, UTC)


def _evidence_id(document: Document) -> tuple[str, int] | None:
    """Only stored, timestamped events can be evidence."""
    sx = document.get("sx")
    uid = sx.get("event_uid") if isinstance(sx, Mapping) else None
    time = document.get("time")
    if isinstance(uid, str) and uid and isinstance(time, int) and not isinstance(time, bool):
        return uid, time
    return None


def _entities(document: Document) -> dict[str, list[str]]:
    entities: dict[str, list[str]] = {}
    for observable in document.get("observables") or []:
        if not isinstance(observable, Mapping):
            continue
        name, value = observable.get("name"), observable.get("value")
        if not isinstance(name, str) or value in (None, ""):
            continue
        if name not in entities and len(entities) >= MAX_ENTITY_NAMES:
            continue
        values = entities.setdefault(name, [])
        if str(value) not in values and len(values) < MAX_ENTITY_VALUES:
            values.append(str(value))
    return entities


class DetectionService:
    def __init__(
        self,
        rules: RuleSet,
        *,
        uow_factory: UnitOfWorkFactory,
        windows: WindowStore,
        on_findings: FindingSink | None = None,
        clock: Clock = utcnow,
    ) -> None:
        self._rules = rules
        self._uow_factory = uow_factory
        self._windows = windows
        self._on_findings = on_findings
        self._clock = clock

    async def handle(self, event: Event) -> None:
        if event.org_id is None:
            logger.warning("normalised-event message without org_id ignored", extra={"event_id": str(event.id)})
            return
        documents = [
            message["body"]
            for message in event.payload.get("documents", [])
            if isinstance(message, Mapping) and isinstance(message.get("body"), Mapping)
        ]
        if not documents:
            return
        org_id = event.org_id

        started = perf_counter()
        pending: list[tuple[Finding, Fired | None]] = []
        fired_in_batch: dict[str, int] = {}
        for document in documents:
            identity = _evidence_id(document)
            if identity is None:
                continue
            for rule in self._rules.single_event:
                if rule.predicate.evaluate(document):
                    pending.append((self._single_event_finding(rule, document, identity, org_id), None))
            for threshold in self._rules.threshold:
                result = await self._threshold(threshold, document, identity, org_id, fired_in_batch)
                if result is not None:
                    pending.append(result)

        stored: list[Finding] = []
        if pending:
            created = 0
            async with self._uow_factory() as uow:
                for finding, _ in pending:
                    added = await uow.findings.add(finding)
                    created += added
                    DETECTION_FINDINGS.labels(
                        rule_type=finding.rule_type.value, outcome="created" if added else "duplicate"
                    ).inc()
                    existing = None if added else await uow.findings.get_by_dedupe_key(org_id, finding.dedupe_key)
                    stored.append(existing or finding)
                await uow.commit()
            # Only after the finding is durable: a crash before this point refires into the same dedupe key.
            for _, fired in pending:
                if fired is not None:
                    key, at_ms, window_ms = fired
                    await self._windows.mark_fired(key, at_ms, window_ms=window_ms)
            if created:
                logger.info("findings created", extra={"findings_created": created, "org_id": str(org_id)})
        DETECTION_SECONDS.observe(perf_counter() - started)
        # Every batch, not only ones with findings: correlation also reads events (a successful logon that
        # follows failures usually arrives in a later batch than the findings it completes).
        if self._on_findings is not None:
            await self._on_findings(org_id, stored, documents)

    def _finding(
        self,
        rule: Rule,
        org_id: UUID,
        *,
        evidence: tuple[str, ...],
        first_ms: int,
        last_ms: int,
        entities: dict[str, list[str]],
        dedupe_key: str,
    ) -> Finding:
        meta = rule.meta
        return Finding(
            id=uuid7(),
            org_id=org_id,
            rule_id=meta.id,
            rule_title=meta.title,
            rule_type=rule.type,
            rule_version=meta.version,
            rule_author=meta.author,
            rule_source=meta.source_url,
            severity_id=meta.severity_id,
            techniques=meta.attack.techniques,
            tactics=meta.attack.tactics,
            entities=entities,
            evidence=evidence,
            first_seen=_at(first_ms),
            last_seen=_at(last_ms),
            dedupe_key=dedupe_key,
            created_at=self._clock(),
        )

    def _single_event_finding(
        self, rule: SingleEventRule, document: Document, identity: tuple[str, int], org_id: UUID
    ) -> Finding:
        uid, at_ms = identity
        return self._finding(
            rule,
            org_id,
            evidence=(uid,),
            first_ms=at_ms,
            last_ms=at_ms,
            entities=_entities(document),
            dedupe_key=_digest(rule.meta.id, uid),
        )

    async def _threshold(
        self,
        rule: ThresholdRule,
        document: Document,
        identity: tuple[str, int],
        org_id: UUID,
        fired_in_batch: dict[str, int],
    ) -> tuple[Finding, Fired] | None:
        if not rule.match.evaluate(document):
            return None
        group: list[str] = []
        for path in rule.group_by:
            values = values_at(document, path)
            if not values:
                return None  # an event without the grouping entity can't be attributed to a group
            group.append(str(values[0]))
        distinct: str | None = None
        if rule.count_distinct is not None:
            values = values_at(document, rule.count_distinct)
            if not values:
                return None
            distinct = str(values[0])

        uid, at_ms = identity
        group_key = "\x1f".join(group)
        key = "\x1f".join((str(org_id), rule.meta.id, group_key))
        entries = await self._windows.add(key, WindowEntry(uid, at_ms, distinct), window_ms=rule.window_ms)
        count = len({entry.value for entry in entries}) if rule.count_distinct else len(entries)
        if count < rule.threshold:
            return None

        last = fired_in_batch.get(key)
        if last is None:
            last = await self._windows.last_fired(key)
        # Already fired within the window, unless this is the same trigger redelivered: it rebuilds the same
        # dedupe key, so storage stays idempotent and the sink still sees the finding after a crash.
        if last is not None and last != at_ms and at_ms - last < rule.window_ms:
            return None
        fired_in_batch[key] = at_ms

        ordered = sorted(entries, key=lambda entry: (entry.at_ms, entry.event_uid))[:MAX_EVIDENCE]
        entities: dict[str, list[Any]] = {path: [value] for path, value in zip(rule.group_by, group, strict=True)}
        if rule.count_distinct is not None:
            entities[rule.count_distinct] = sorted({e.value for e in ordered if e.value})[:MAX_ENTITY_VALUES]
        finding = self._finding(
            rule,
            org_id,
            evidence=tuple(entry.event_uid for entry in ordered),
            first_ms=ordered[0].at_ms,
            last_ms=at_ms,
            entities=entities,
            dedupe_key=_digest(rule.meta.id, group_key, str(at_ms), ordered[0].event_uid),
        )
        return finding, (key, at_ms, rule.window_ms)
