"""Parser registry: every ingest source names one of these (ADR-0013)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from types import MappingProxyType

from app.ingest_pipeline.ocsf import MAX_RAW_DATA_CHARS, OcsfEvent
from app.ingest_pipeline.parsers import linux_auth, ocsf_passthrough, windows_ntlm, windows_security, windows_sysmon
from app.ingest_pipeline.parsers.base import ParseError, Parser, Record

__all__ = ["PARSERS", "PARSER_DESCRIPTIONS", "ParseError", "normalize"]

PARSERS: Mapping[str, Parser] = MappingProxyType(
    {
        "ocsf": ocsf_passthrough.parse,
        "linux_auth": linux_auth.parse,
        "windows_security": windows_security.parse,
        "windows_sysmon": windows_sysmon.parse,
        "windows_ntlm": windows_ntlm.parse,
    }
)

PARSER_DESCRIPTIONS: Mapping[str, str] = MappingProxyType(
    {
        "ocsf": "Events already normalised to OCSF 1.x",
        "linux_auth": "OpenSSH sshd authentication lines from syslog / auth.log",
        "windows_security": "Windows Security log JSON (4624, 4625, 4634, 4647, 4688)",
        "windows_sysmon": "Sysmon Operational log JSON (1, 3, 5, 7, 8, 10, 11, 12, 13, 14, 22, 23, 26)",
        "windows_ntlm": "Windows NTLM Operational log JSON (8004: NTLM authentication audited)",
    }
)


def normalize(parser: str, record: Record) -> OcsfEvent:
    """Map one raw record with the named parser and validate it against the OCSF model.

    Raises `ParseError` when the parser can't map the record and `pydantic.ValidationError` when the
    mapped event violates the model.
    """
    try:
        parse = PARSERS[parser]
    except KeyError as exc:
        raise ParseError(f"unknown parser '{parser}'") from exc
    mapped = parse(record)
    mapped.setdefault("raw_data", json.dumps(dict(record), default=str, separators=(",", ":"))[:MAX_RAW_DATA_CHARS])
    return OcsfEvent.model_validate(mapped)
