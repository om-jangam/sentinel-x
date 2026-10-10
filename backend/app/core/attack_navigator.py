"""The ATT&CK Navigator layer format, in one place.

Two things export layers: an incident (the techniques its findings named) and the rule set (the techniques
its rules look for). They say different things, but they say them in the same published format
([layer v4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md)),
and modules are independent, so the format lives here rather than in whichever module wrote it first. A
duplicated `"layer": "4.5"` is a version that drifts.

This module knows the envelope and nothing else: what a score *means* is the caller's business.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.1.0"
ATTACK_VERSION = "17"
MAX_COMMENT = 500
MAX_NAME = 100
GRADIENT = ["#e8f5e9", "#1b5e20"]


@dataclass(frozen=True, slots=True)
class Scored:
    """One technique in a layer: its id, its score, and why it has that score."""

    technique_id: str
    score: int
    comment: str = ""
    metadata: tuple[tuple[str, str], ...] = ()

    def entry(self) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "techniqueID": self.technique_id,
            "score": self.score,
            "enabled": True,
            # Navigator hides a sub-technique unless its parent row is expanded.
            "showSubtechniques": "." in self.technique_id,
        }
        if self.comment:
            entry["comment"] = self.comment[:MAX_COMMENT]
        if self.metadata:
            entry["metadata"] = [{"name": name, "value": value} for name, value in self.metadata]
        return entry


def layer(*, name: str, description: str, techniques: list[Scored], legend: str) -> dict[str, Any]:
    """A Navigator layer around already-scored techniques, sorted by technique id."""
    scored = sorted(techniques, key=lambda technique: technique.technique_id)
    return {
        "name": name[:MAX_NAME],
        "versions": {"attack": ATTACK_VERSION, "navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION},
        "domain": "enterprise-attack",
        "description": description,
        "techniques": [technique.entry() for technique in scored],
        "gradient": {
            "colors": GRADIENT,
            "minValue": 0,
            "maxValue": max([1, *(technique.score for technique in scored)]),
        },
        "legendItems": [{"label": legend, "color": GRADIENT[-1]}],
        "sorting": 3,
        "hideDisabled": True,
        "showTacticRowBackground": True,
        "selectTechniquesAcrossTactics": True,
    }
