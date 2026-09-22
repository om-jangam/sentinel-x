"""Output contract and grounding validator (docs/04 §4-5). The validator, not the prompt, is the guarantee.

A statement survives only if everything it cites is in the bundle and everything it names (IP addresses,
hashes) is too. Dropped statements are kept with the reason, so an analyst can see what was rejected.
A response with no surviving statement is rejected outright.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from app.modules.assistant.domain.bundle import EvidenceBundle

MAX_STATEMENTS = 40
MAX_TEXT = 1000
MAX_SUMMARY = 1200
MAX_NEXT_STEPS = 10
TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")
# Not part of a longer dotted number, but a sentence-ending "." after it is fine.
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


class Kind(StrEnum):
    FACT = "FACT"
    INFERENCE = "INFERENCE"
    UNCERTAINTY = "UNCERTAINTY"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class Statement:
    kind: Kind
    text: str
    evidence: tuple[str, ...] = ()
    reasoning: str | None = None
    confidence: Confidence | None = None
    missing: str | None = None


@dataclass(frozen=True, slots=True)
class TechniqueSuggestion:
    technique_id: str
    evidence: tuple[str, ...]
    kind: Kind


@dataclass(frozen=True, slots=True)
class Dropped:
    item: dict[str, Any]
    reason: str


@dataclass(frozen=True, slots=True)
class Analysis:
    summary: str | None
    statements: tuple[Statement, ...]
    techniques: tuple[TechniqueSuggestion, ...]
    next_steps: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "statements": [
                {
                    k: v
                    for k, v in (
                        ("kind", s.kind.value),
                        ("text", s.text),
                        ("evidence", list(s.evidence)),
                        ("reasoning", s.reasoning),
                        ("confidence", None if s.confidence is None else s.confidence.value),
                        ("missing", s.missing),
                    )
                    if v is not None
                }
                for s in self.statements
            ],
            "techniques": [
                {"technique_id": t.technique_id, "evidence": list(t.evidence), "kind": t.kind.value}
                for t in self.techniques
            ],
            "next_steps": list(self.next_steps),
        }


@dataclass(frozen=True, slots=True)
class Validation:
    analysis: Analysis | None  # None: rejected
    dropped: tuple[Dropped, ...] = ()
    rejected_reason: str | None = None
    citations_total: int = 0  # event_uids cited by the model, before validation
    citations_valid: int = 0  # of those, how many exist in the bundle
    stats: dict[str, int] = field(default_factory=dict)

    @property
    def citation_validity(self) -> float | None:
        return None if not self.citations_total else self.citations_valid / self.citations_total


def _text(value: Any, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _uids(value: Any) -> list[str]:
    return [item.strip() for item in value if isinstance(item, str) and item.strip()] if isinstance(value, list) else []


def unknown_mentions(text: str, known: frozenset[str]) -> list[str]:
    """IP addresses and hashes the text names that the bundle doesn't contain."""
    found: list[str] = []
    for match in _IPV4.findall(text):
        try:
            address = ipaddress.ip_address(match).compressed
        except ValueError:
            continue
        if address not in known:
            found.append(address)
    found += [h.lower() for h in _HEX.findall(text) if h.lower() not in known]
    return found


def parse_json(raw: str) -> dict[str, Any] | None:
    text = _FENCE.sub("", _THINK.sub("", raw).strip()).strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            value = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    return value if isinstance(value, dict) else None


def validate(raw: str, bundle: EvidenceBundle) -> Validation:
    data = parse_json(raw)
    if data is None:
        return Validation(analysis=None, rejected_reason="the model did not return a JSON object")

    uids, known = bundle.event_uids, bundle.known_values
    dropped: list[Dropped] = []
    total = valid = 0

    def check_citations(item: dict[str, Any], evidence: list[str]) -> str | None:
        nonlocal total, valid
        total += len(evidence)
        valid += sum(uid in uids for uid in evidence)
        missing = [uid for uid in evidence if uid not in uids]
        return f"cites events that are not in the incident: {', '.join(missing[:3])}" if missing else None

    statements: list[Statement] = []
    raw_statements = _list(data.get("statements"))
    for item in raw_statements[:MAX_STATEMENTS]:
        if not isinstance(item, dict):
            continue
        try:
            kind = Kind(str(item.get("kind", "")).upper())
        except ValueError:
            dropped.append(Dropped(item, "kind must be FACT, INFERENCE or UNCERTAINTY"))
            continue
        text, evidence = _text(item.get("text"), MAX_TEXT), _uids(item.get("evidence"))
        problem = check_citations(item, evidence)
        if not text:
            problem = problem or "no text"
        if kind is not Kind.UNCERTAINTY and not evidence:
            problem = problem or f"a {kind.value} must cite at least one event"
        reasoning = _text(item.get("reasoning"), MAX_TEXT) or None
        missing_info = _text(item.get("missing"), MAX_TEXT) or None
        if kind is Kind.INFERENCE and not reasoning:
            problem = problem or "an INFERENCE must give its reasoning"
        if kind is Kind.UNCERTAINTY and not missing_info:
            problem = problem or "an UNCERTAINTY must say what information would resolve it"
        mentioned = unknown_mentions(" ".join(filter(None, [text, reasoning, missing_info])), known)
        if mentioned:
            problem = problem or f"mentions {', '.join(mentioned[:3])}, which is not in the evidence"
        if problem:
            dropped.append(Dropped(item, problem))
            continue
        confidence = None
        if kind is Kind.INFERENCE:
            try:
                confidence = Confidence(str(item.get("confidence", "low")).lower())
            except ValueError:
                confidence = Confidence.LOW
        statements.append(
            Statement(
                kind=kind,
                text=text,
                evidence=tuple(dict.fromkeys(evidence)),
                reasoning=reasoning if kind is Kind.INFERENCE else None,
                confidence=confidence,
                missing=missing_info if kind is Kind.UNCERTAINTY else None,
            )
        )

    techniques: list[TechniqueSuggestion] = []
    raw_techniques = _list(data.get("techniques"))
    for item in raw_techniques[:20]:
        if not isinstance(item, dict):
            continue
        technique = _text(item.get("technique_id"), 16).upper()
        evidence = _uids(item.get("evidence"))
        problem = check_citations(item, evidence)
        if not TECHNIQUE_ID.fullmatch(technique):
            problem = problem or "not an ATT&CK technique ID"
        if not evidence:
            problem = problem or "a technique suggestion must cite at least one event"
        if problem:
            dropped.append(Dropped(item, problem))
            continue
        kind = Kind.FACT if str(item.get("kind", "")).upper() == "FACT" else Kind.INFERENCE
        techniques.append(TechniqueSuggestion(technique, tuple(dict.fromkeys(evidence)), kind))

    next_steps: list[str] = []
    raw_steps = _list(data.get("next_steps"))
    for step in raw_steps[:MAX_NEXT_STEPS]:
        text = _text(step, 300)
        mentioned = unknown_mentions(text, known)
        if mentioned:
            dropped.append(Dropped({"next_step": text}, f"mentions {', '.join(mentioned[:3])}, not in the evidence"))
        elif text:
            next_steps.append(text)

    summary = _text(data.get("summary"), MAX_SUMMARY) or None
    if summary and (mentioned := unknown_mentions(summary, known)):
        dropped.append(Dropped({"summary": summary}, f"mentions {', '.join(mentioned[:3])}, not in the evidence"))
        summary = None

    stats = {
        "statements_returned": len(raw_statements),
        "statements_kept": len(statements),
        "techniques_kept": len(techniques),
        "dropped": len(dropped),
    }
    if not statements:
        return Validation(
            analysis=None,
            dropped=tuple(dropped),
            rejected_reason="no statement survived validation",
            citations_total=total,
            citations_valid=valid,
            stats=stats,
        )
    return Validation(
        analysis=Analysis(summary, tuple(statements), tuple(techniques), tuple(next_steps)),
        dropped=tuple(dropped),
        citations_total=total,
        citations_valid=valid,
        stats=stats,
    )
