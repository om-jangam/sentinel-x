"""Records that are already OCSF (Vector pre-shaped, or native OCSF producers)."""

from __future__ import annotations

from typing import Any

from app.ingest_pipeline.parsers.base import ParseError, Record


def parse(record: Record) -> dict[str, Any]:
    if "class_uid" not in record:
        raise ParseError("not an OCSF event: class_uid is missing")
    return dict(record)
