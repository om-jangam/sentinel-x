from __future__ import annotations

from collections.abc import Callable, Mapping
from ipaddress import ip_address
from typing import Any

Record = Mapping[str, Any]
Parser = Callable[[Record], dict[str, Any]]


class ParseError(ValueError):
    """The record is well-formed input but can't be mapped to OCSF by this parser."""


def clean(value: Any) -> Any:
    """Windows and syslog use '-' and empty strings for "no value"."""
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return None if stripped in ("", "-") else stripped
    return value


def as_ip(value: Any) -> str | None:
    text = clean(value)
    if not isinstance(text, str):
        return None
    try:
        return str(ip_address(text))
    except ValueError:
        return None


def as_int(value: Any, *, base: int = 10) -> int | None:
    text = clean(value)
    if text is None:
        return None
    if isinstance(text, int) and not isinstance(text, bool):
        return text
    try:
        return int(str(text), base)
    except ValueError:
        return None
