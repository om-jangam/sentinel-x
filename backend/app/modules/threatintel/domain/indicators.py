"""Indicators Sentinel-X may look up: external IP addresses, domains and file hashes.

Validation is strict because external providers receive these values. Internal addresses, bare host names
and anything malformed never leave the platform.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum

from app.core.netaddr import is_external_ip

_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
_HEX = re.compile(r"^[0-9a-f]+$")
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


class IndicatorType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"


@dataclass(frozen=True, slots=True, order=True)
class Indicator:
    type: IndicatorType
    value: str

    @property
    def key(self) -> str:
        """Same `type:value` form as incident entity keys, so the two line up without translation."""
        return f"{self.type.value}:{self.value}"

    @classmethod
    def of(cls, type_: str, value: str) -> Indicator | None:
        """A normalised indicator, or None when the value isn't one Sentinel-X may look up."""
        try:
            kind = IndicatorType(type_.strip().lower())
        except ValueError:
            return None
        text = value.strip().lower()
        if kind is IndicatorType.IP:
            try:
                text = ipaddress.ip_address(text).compressed
            except ValueError:
                return None
            return cls(kind, text) if is_external_ip(text) else None
        if kind is IndicatorType.DOMAIN:
            text = text.rstrip(".")
            return cls(kind, text) if _DOMAIN.fullmatch(text) else None
        return cls(kind, text) if len(text) in HASH_LENGTHS and _HEX.fullmatch(text) else None

    @classmethod
    def parse(cls, key: str) -> Indicator | None:
        type_, sep, value = key.partition(":")
        return cls.of(type_, value) if sep else None
