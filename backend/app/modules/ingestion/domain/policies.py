from __future__ import annotations

import re

from app.core.errors import ValidationFailedError

INGEST_TOKEN_PREFIX = "sxi_"  # noqa: S105 — a token *prefix*, not a secret
TOKEN_DISPLAY_LENGTH = 12  # e.g. "sxi_Ab3dE6gH" — enough to identify, useless to replay
MAX_EVENTS_PER_REQUEST = 1_000
MAX_BODY_BYTES = 5 * 1024 * 1024

_SOURCE_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")


def validate_source_name(name: str) -> None:
    if not _SOURCE_NAME.fullmatch(name):
        raise ValidationFailedError(
            "Invalid source name",
            errors=[
                {
                    "loc": ["name"],
                    "msg": "lowercase letters, digits, '.', '_' or '-'; 3-64 characters",
                    "type": "source_name",
                }
            ],
        )


def is_ingest_token(credential: str) -> bool:
    return credential.startswith(INGEST_TOKEN_PREFIX)
