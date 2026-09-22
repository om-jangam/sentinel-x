"""Splunk search results → records the Sentinel-X parsers read.

A Splunk result is a flat object: `_raw` holds the event exactly as Splunk stored it, `sourcetype` says
what it is, and `_time` is when it happened. The sourcetype decides which parser reads `_raw`; nothing is
guessed from the text itself, so an event Sentinel-X cannot read is reported rather than mangled.

| Splunk sourcetype | `_raw` holds | Parser |
|---|---|---|
| `XmlWinEventLog…` (any suffix) | a Windows `<Event>` element | by Channel: `windows_sysmon`, `windows_security` |
| `linux_secure`, `syslog`, `sshd`, `auth` | one syslog line | `linux_auth` |
| `ocsf`, `_json` with `class_uid` | an OCSF event as JSON | `ocsf` |

Windows events forwarded as the older `WinEventLog:…` key-value text are **not** read: that format renders
each event as localised prose, and reading it would mean guessing. They are counted and named instead.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.ingest_pipeline.winxml import WindowsXmlError, parse_event

XML_SOURCETYPE = "xmlwineventlog"
CLASSIC_WINDOWS_SOURCETYPE = "wineventlog"
SYSLOG_SOURCETYPES = ("linux_secure", "syslog", "sshd", "auth", "secure")
OCSF_SOURCETYPES = ("ocsf", "_json", "json")

CHANNEL_PARSERS = {
    "Security": "windows_security",
    "Microsoft-Windows-Sysmon/Operational": "windows_sysmon",
}


class SplunkMappingError(ValueError):
    """This result cannot be turned into a record, with the reason an operator needs."""


@dataclass(frozen=True, slots=True)
class SplunkRecord:
    parser: str
    record: dict[str, Any]


def _raw_of(result: dict[str, Any]) -> str:
    raw = result.get("_raw")
    if not isinstance(raw, str) or not raw.strip():
        raise SplunkMappingError("result has no _raw")
    return raw


def to_record(result: dict[str, Any]) -> SplunkRecord:
    """One Splunk result to (parser, record). Raises `SplunkMappingError` when the sourcetype is unknown."""
    sourcetype = str(result.get("sourcetype") or "").strip()
    if not sourcetype:
        raise SplunkMappingError("result has no sourcetype")
    name = sourcetype.lower()
    raw = _raw_of(result)

    if name.startswith(XML_SOURCETYPE):
        try:
            event = parse_event(raw)
        except WindowsXmlError as exc:
            raise SplunkMappingError(f"{sourcetype}: {exc}") from exc
        parser = CHANNEL_PARSERS.get(event.channel or "")
        if parser is None:
            raise SplunkMappingError(f"{sourcetype}: no parser for channel {event.channel or '(none)'}")
        return SplunkRecord(parser, event.record)

    if name.startswith(CLASSIC_WINDOWS_SOURCETYPE):
        raise SplunkMappingError(
            f"{sourcetype}: Splunk's classic WinEventLog text is not read; forward it as XmlWinEventLog"
        )

    if any(name.startswith(prefix) for prefix in SYSLOG_SOURCETYPES):
        record: dict[str, Any] = {"message": raw}
        if isinstance(result.get("_time"), str) and result["_time"]:
            record["timestamp"] = result["_time"]
        return SplunkRecord("linux_auth", record)

    if any(name.startswith(prefix) for prefix in OCSF_SOURCETYPES):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SplunkMappingError(f"{sourcetype}: _raw is not JSON ({exc.msg})") from exc
        if not isinstance(parsed, dict) or "class_uid" not in parsed:
            raise SplunkMappingError(f"{sourcetype}: JSON without class_uid is not an OCSF event")
        return SplunkRecord("ocsf", parsed)

    raise SplunkMappingError(f"{sourcetype}: no parser is mapped to this sourcetype")
