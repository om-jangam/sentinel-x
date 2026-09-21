"""Correlation policy: time windows, and how an incident's severity and title follow from its links.

Nothing here guesses. Severity starts at the most severe linked finding and is raised only by two named
conditions, each recorded in the incident's assessment with the links that satisfy it.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from app.modules.correlation.domain.incidents import (
    CorrelationRule,
    Incident,
    IncidentEntity,
    IncidentLink,
    LinkKind,
)

# A finding joins an open incident only if it overlaps the incident's activity widened by this much.
CORRELATION_WINDOW = timedelta(hours=2)
# A successful logon completes failures only if it follows them within this.
AUTH_SEQUENCE_WINDOW = timedelta(hours=1)
BRUTE_FORCE_TECHNIQUE = "T1110"
MULTI_STAGE_TACTICS = 3

HIGH, CRITICAL = 4, 5


def is_auth_failure_link(link: IncidentLink) -> bool:
    return link.kind is LinkKind.FINDING and any(t.split(".")[0] == BRUTE_FORCE_TECHNIQUE for t in link.techniques)


def _ordered_unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _pretty(tactic: str) -> str:
    return tactic.replace("_", " ")


def assess(incident: Incident, links: list[IncidentLink], entities: list[IncidentEntity]) -> None:
    """Recompute everything derived from the links; call after links change."""
    ordered = sorted(links, key=lambda link: (link.first_seen, str(link.id)))
    findings = [link for link in ordered if link.kind is LinkKind.FINDING]
    events = [link for link in ordered if link.kind is LinkKind.EVENT]

    incident.first_seen = min(link.first_seen for link in ordered)
    incident.last_seen = max(link.last_seen for link in ordered)
    incident.finding_count = len(findings)
    incident.event_count = len({uid for link in ordered for uid in link.evidence})
    incident.techniques = sorted({t for link in findings for t in link.techniques})
    incident.tactics = _ordered_unique([t for link in findings for t in link.tactics])

    assessment: list[dict[str, Any]] = []
    top = max(findings, key=lambda link: (int(link.detail.get("severity_id", 1)), -link.first_seen.timestamp()))
    severity = int(top.detail.get("severity_id", 1))
    assessment.append(
        {
            "rule": "highest-finding-severity",
            "severity_id": severity,
            "because": f"most severe linked finding: {top.detail.get('rule_title')}",
            "links": [str(top.id)],
        }
    )

    compromises = [link for link in events if link.rule is CorrelationRule.AUTH_SUCCESS_AFTER_FAILURES]
    if compromises:
        severity = max(severity, HIGH)
        assessment.append(
            {
                "rule": "credential-compromise",
                "severity_id": HIGH,
                "because": "a successful logon followed brute-force failures from the same source",
                "links": [str(link.id) for link in compromises],
            }
        )
    multi_stage = len(incident.tactics) >= MULTI_STAGE_TACTICS
    if multi_stage:
        severity = max(severity, HIGH)
        assessment.append(
            {
                "rule": "multi-stage",
                "severity_id": HIGH,
                "because": f"findings span {len(incident.tactics)} ATT&CK tactics: {', '.join(incident.tactics)}",
                "links": [str(link.id) for link in findings if link.tactics],
            }
        )
    if compromises and multi_stage:
        severity = CRITICAL
        assessment.append(
            {
                "rule": "compromise-then-activity",
                "severity_id": CRITICAL,
                "because": "a compromised logon was followed by activity across several tactics",
                "links": [str(link.id) for link in compromises],
            }
        )
    incident.severity_id = severity
    incident.assessment = assessment
    incident.title = _title(top, compromises, incident.tactics, entities)


def _title(
    top: IncidentLink, compromises: list[IncidentLink], tactics: list[str], entities: list[IncidentEntity]
) -> str:
    hosts = [entity.value for entity in sorted(entities, key=lambda e: e.first_seen) if entity.type == "host"]
    where = ""
    if hosts:
        where = f" on {', '.join(hosts[:2])}" + (f" and {len(hosts) - 2} more" if len(hosts) > 2 else "")
    if compromises:
        sources = [m.key.split(":", 1)[1] for m in compromises[0].matched if m.key.startswith("ip:")]
        title = "Successful logon after repeated failures" + (f" from {sources[0]}" if sources else "")
        later = [_pretty(t) for t in tactics if t != "credential_access"]
        if later:
            title += f", then {', '.join(later[:4])}" + (f" and {len(later) - 4} more" if len(later) > 4 else "")
        return (title + where)[:255]
    if len(tactics) >= MULTI_STAGE_TACTICS:
        return (f"Multi-stage activity ({', '.join(_pretty(t) for t in tactics[:4])})" + where)[:255]
    return (str(top.detail.get("rule_title", "Correlated findings")) + where)[:255]
