"""Cursor pagination envelope (docs/06 §2): `{items, next_cursor}`."""

from __future__ import annotations

import base64
import binascii
from typing import Generic, TypeVar

from pydantic import BaseModel

from app.core.errors import ValidationFailedError

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

T = TypeVar("T")


class Page(BaseModel, Generic[T]):  # noqa: UP046 — Pydantic generic models
    items: list[T]
    next_cursor: str | None = None


def encode_cursor(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).rstrip(b"=").decode("ascii")


def decode_cursor(cursor: str) -> str:
    """Cursors are opaque to clients; anything malformed is a 422, never a 500."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True).decode("utf-8")
    except (binascii.Error, UnicodeError, ValueError) as exc:
        raise ValidationFailedError("Invalid pagination cursor") from exc
