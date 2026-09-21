"""The set of field paths a stored event document can contain, derived from the OCSF model.

Rule loading checks every referenced path against it, so a typo in a rule or a field mapping is a load
error rather than a rule that silently never matches.
"""

from __future__ import annotations

import types
from functools import cache
from typing import Annotated, Any, Union, get_args, get_origin

from pydantic import BaseModel

from app.ingest_pipeline.ocsf import OcsfEvent

# Added by `OcsfEvent.to_document`, beyond the model's own fields.
DOCUMENT_FIELDS = frozenset(
    {
        "@timestamp",
        "class_name",
        "category_name",
        "activity_name",
        "severity",
        "status",
        "sx.org_id",
        "sx.source_id",
        "sx.event_uid",
        "sx.ingested_at",
        "sx.fingerprint",
    }
)
# `unmapped` holds source-specific leftovers; parsers document what they put there.
FREEFORM_PREFIXES = ("unmapped.",)


def _models(annotation: Any) -> list[type[BaseModel]]:
    origin = get_origin(annotation)
    if origin is Annotated:
        return _models(get_args(annotation)[0])
    if origin in (Union, types.UnionType, list, tuple):
        return [model for arg in get_args(annotation) for model in _models(arg)]
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    return []


def _walk(model: type[BaseModel], prefix: str, found: set[str], depth: int) -> None:
    for name, field in model.model_fields.items():
        path = f"{prefix}{name}"
        nested = _models(field.annotation)
        if nested and depth < 6:
            for child in nested:
                _walk(child, f"{path}.", found, depth + 1)
        else:
            found.add(path)


@cache
def known_paths() -> frozenset[str]:
    found: set[str] = set()
    _walk(OcsfEvent, "", found, 0)
    return frozenset(found | DOCUMENT_FIELDS)


def is_known_path(path: str) -> bool:
    return path in known_paths() or any(
        path.startswith(prefix) and len(path) > len(prefix) for prefix in FREEFORM_PREFIXES
    )
