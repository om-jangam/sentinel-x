from __future__ import annotations

from collections.abc import Callable, Mapping
from ipaddress import ip_address
from typing import Any

Record = Mapping[str, Any]
Parser = Callable[[Record], dict[str, Any]]


class ParseError(ValueError):
    """The record is well-formed input but can't be mapped to OCSF by this parser."""


class UnsupportedEventError(ParseError):
    """The record is of a kind this parser does not map — a limit of the mapping, not a broken record.

    Worth separating: a Windows Security log is mostly event types no rule reads (privilege assignment,
    Kerberos service tickets, filtering-platform connections). Counting those as parse failures would
    make the evaluation's parse rate say Sentinel-X is failing where it is simply not interested.
    """


def clean(value: Any) -> Any:
    """Windows and syslog use '-' and empty strings for "no value"."""
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return None if stripped in ("", "-") else stripped
    return value


def as_ip(value: Any) -> str | None:
    """An address as the record states it, except that an IPv4-mapped IPv6 address is read as the IPv4.

    Windows writes Kerberos client addresses as `::ffff:10.0.1.14`. Stored as IPv6 it is normalised to
    `::ffff:a00:10e`: an analyst searching for 10.0.1.14 would not find it, and a rule filtering
    `10.0.0.0/8` would treat the host as external. RFC 4291 says the two spellings are the same address,
    so the IPv4 one is kept.
    """
    text = clean(value)
    if not isinstance(text, str):
        return None
    try:
        address = ip_address(text)
    except ValueError:
        return None
    if (mapped := getattr(address, "ipv4_mapped", None)) is not None:
        return str(mapped)
    return str(address)


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
