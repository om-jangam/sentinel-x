"""Incidents in the formats analysts exchange: an ATT&CK Navigator layer and a STIX Attack Flow.

Both are built from what the incident already holds, and neither adds a claim: a technique appears in the
layer because a linked finding named it, and an attack action exists because a timeline step does. Every
action carries the `event_uid`s that show it, so the export is as checkable as the workspace.

- **Navigator layer** ([format v4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md)):
  opens in MITRE's ATT&CK Navigator. Each technique's score is the number of events behind it.
- **Attack Flow** ([CTID Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/language/)):
  a STIX 2.1 bundle whose `attack-action` objects follow the timeline, chained by `effect_refs`.

Identifiers are derived from the incident id, so exporting the same incident twice gives the same
document (a diff between two exports is a real change, not noise).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from app.modules.correlation.domain.incidents import IncidentDetail, LinkKind
from app.modules.correlation.domain.timeline import TimelineStep

LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.1.0"
ATTACK_VERSION = "17"
ATTACK_FLOW_EXTENSION = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"
# Stable ids for repeat exports: a v5 UUID of the incident id and the object's place in the document.
EXPORT_NAMESPACE = uuid.UUID("2f0f4bb1-05f2-4b9f-9d54-9a4c4d55d5e2")
MAX_COMMENT = 500


def _stix_id(kind: str, incident_id: str, discriminator: str) -> str:
    return f"{kind}--{uuid.uuid5(EXPORT_NAMESPACE, f'{incident_id}|{kind}|{discriminator}')}"


def _rfc3339(value: datetime) -> str:
    return value.astimezone(tz=None).astimezone(tz=value.tzinfo).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def navigator_layer(detail: IncidentDetail, *, generated: datetime) -> dict[str, Any]:
    """One layer per incident: the techniques its findings named, scored by how many events show them."""
    incident = detail.incident
    events: dict[str, set[str]] = {}
    rules: dict[str, set[str]] = {}
    for link in detail.links:
        if link.kind is not LinkKind.FINDING:
            continue
        title = str(link.detail.get("rule_title") or "")
        for technique in link.detail.get("techniques") or ():
            key = str(technique).upper()
            events.setdefault(key, set()).update(link.evidence)
            if title:
                rules.setdefault(key, set()).add(title)

    techniques = [
        {
            "techniqueID": technique,
            "tactic": None,
            "score": len(uids),
            "enabled": True,
            "comment": "; ".join(sorted(rules.get(technique, set())))[:MAX_COMMENT],
            "metadata": [{"name": "events", "value": str(len(uids))}],
            "showSubtechniques": "." in technique,
        }
        for technique, uids in sorted(events.items())
    ]
    for entry in techniques:
        if entry["tactic"] is None:
            del entry["tactic"]

    return {
        "name": f"Sentinel-X · {incident.title}"[:100],
        "versions": {"attack": ATTACK_VERSION, "navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION},
        "domain": "enterprise-attack",
        "description": (
            f"Incident {incident.id} ({incident.severity}), {incident.finding_count} findings over "
            f"{incident.event_count} events, {_rfc3339(incident.first_seen)} to {_rfc3339(incident.last_seen)}. "
            f"Exported by Sentinel-X on {_rfc3339(generated)}; every technique is one a finding named."
        ),
        "techniques": techniques,
        "gradient": {
            "colors": ["#e8f5e9", "#1b5e20"],
            "minValue": 0,
            "maxValue": max([1, *(len(uids) for uids in events.values())]),
        },
        "legendItems": [{"label": "Observed in this incident", "color": "#1b5e20"}],
        "sorting": 3,
        "hideDisabled": True,
        "showTacticRowBackground": True,
        "selectTechniquesAcrossTactics": True,
    }


def _asset(incident_id: str, kind: str, value: str) -> dict[str, Any]:
    return {
        "type": "attack-asset",
        "spec_version": "2.1",
        "id": _stix_id("attack-asset", incident_id, f"{kind}:{value}"),
        "name": value,
        "description": kind,
        "extensions": {ATTACK_FLOW_EXTENSION: {"extension_type": "new-sdo"}},
    }


def attack_flow(detail: IncidentDetail, steps: Sequence[TimelineStep], *, generated: datetime) -> dict[str, Any]:
    """A STIX 2.1 bundle: one `attack-action` per timeline step, chained in the order they happened."""
    incident = detail.incident
    incident_id = str(incident.id)
    objects: list[dict[str, Any]] = [
        {
            "type": "extension-definition",
            "spec_version": "2.1",
            "id": ATTACK_FLOW_EXTENSION,
            "name": "Attack Flow",
            "description": "Extends STIX 2.1 with objects for attack flows.",
            "created": "2022-08-02T19:34:35.143Z",
            "modified": "2022-08-02T19:34:35.143Z",
            "created_by_ref": "identity--fb9c968a-745b-4ade-9b25-c324172197f4",
            "schema": "https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema-2.0.0.json",
            "version": "2.0.0",
            "extension_types": ["new-sdo"],
        }
    ]

    assets: dict[str, dict[str, Any]] = {}

    def asset_ref(kind: str, value: str | None) -> str | None:
        if not value:
            return None
        key = f"{kind}:{value}"
        if key not in assets:
            assets[key] = _asset(incident_id, kind, value)
        return str(assets[key]["id"])

    actions: list[dict[str, Any]] = []
    for step in steps:
        techniques = sorted({t.upper() for citation in step.citations for t in citation.techniques})
        rules = sorted({citation.title for citation in step.citations if citation.title})
        refs = [
            ref
            for ref in (
                asset_ref("host", step.host),
                *(asset_ref("user", user) for user in step.users),
                asset_ref("remote address", step.remote),
                *(asset_ref("domain", domain) for domain in step.domains),
            )
            if ref is not None
        ]
        action: dict[str, Any] = {
            "type": "attack-action",
            "spec_version": "2.1",
            "id": _stix_id("attack-action", incident_id, step.id),
            "name": step.action,
            "description": "; ".join(filter(None, [step.process, *step.command_lines, *rules]))[:MAX_COMMENT],
            "execution_start": _rfc3339(step.first_seen),
            "execution_end": _rfc3339(step.last_seen),
            "extensions": {ATTACK_FLOW_EXTENSION: {"extension_type": "new-sdo"}},
            # Sentinel-X's own evidence, kept as STIX custom properties: what proves this action happened.
            "x_sentinelx_event_uids": list(step.events),
            "x_sentinelx_outcome": step.outcome,
            "x_sentinelx_rules": rules,
        }
        if techniques:
            action["technique_id"] = techniques[0]
            if len(techniques) > 1:
                action["x_sentinelx_techniques"] = techniques
        if refs:
            action["asset_refs"] = refs
        actions.append(action)

    for index, action in enumerate(actions[:-1]):
        action["effect_refs"] = [actions[index + 1]["id"]]

    flow = {
        "type": "attack-flow",
        "spec_version": "2.1",
        "id": _stix_id("attack-flow", incident_id, "flow"),
        "created": _rfc3339(incident.created_at),
        "modified": _rfc3339(generated),
        "name": incident.title,
        "description": (
            f"{incident.severity} incident reconstructed by Sentinel-X from {incident.event_count} stored events. "
            "Every action cites the events that show it in x_sentinelx_event_uids."
        ),
        "scope": "incident",
        "start_refs": [actions[0]["id"]] if actions else [],
        "extensions": {ATTACK_FLOW_EXTENSION: {"extension_type": "new-sdo"}},
        "x_sentinelx_incident_id": incident_id,
    }

    objects.append(flow)
    objects.extend(actions)
    objects.extend(assets.values())
    return {"type": "bundle", "id": _stix_id("bundle", incident_id, "bundle"), "objects": objects}
