"""Windows event XML (`<Event xmlns=".../win/2004/08/events/event">`) → the JSON record shape the
`windows_security` and `windows_sysmon` parsers read.

This is how Windows itself renders an event, and how Splunk (`XmlWinEventLog`), `wevtutil qe /f:xml` and
many public attack datasets store them. A file may hold one event per line or events spread over lines.

The input is untrusted. Python's expat (2.4.1 and later) refuses entity-expansion attacks and never loads
external entities; on top of that, any document type declaration is refused outright, since Windows never
writes one.
"""

from __future__ import annotations

import pyexpat
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from xml.etree import ElementTree

if pyexpat.version_info < (2, 4, 1):  # pragma: no cover - Python 3.12 bundles a newer expat
    raise ImportError("expat 2.4.1 or later is required to parse untrusted Windows event XML safely")

MAX_EVENT_CHARS = 1_000_000
_EVENT = re.compile(r"<Event[\s>].*?</Event>", re.DOTALL)
_DECLARATION = re.compile(r"<!(?:DOCTYPE|ENTITY)", re.IGNORECASE)


class WindowsXmlError(ValueError):
    """One event could not be read; the others in the file still are."""


@dataclass(frozen=True, slots=True)
class WindowsXmlEvent:
    channel: str | None
    record: dict[str, Any]


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(parent: ElementTree.Element, name: str) -> ElementTree.Element | None:
    return next((child for child in parent if _local(child.tag) == name), None)


def parse_event(text: str) -> WindowsXmlEvent:
    """Convert one `<Event>` element."""
    if len(text) > MAX_EVENT_CHARS:
        raise WindowsXmlError(f"event exceeds {MAX_EVENT_CHARS} characters")
    if _DECLARATION.search(text):
        raise WindowsXmlError("document type declarations are not allowed")
    try:
        # Safe here: expat >= 2.4.1 (checked at import) and declarations refused above; see the module docstring.
        root = ElementTree.fromstring(text)  # noqa: S314
    except ElementTree.ParseError as exc:
        raise WindowsXmlError(f"malformed event XML: {exc}") from exc
    system = _child(root, "System")
    if system is None:
        raise WindowsXmlError("event has no System element")

    def text_of(name: str) -> str | None:
        element = _child(system, name)
        return element.text.strip() if element is not None and element.text else None

    record: dict[str, Any] = {}
    if (event_id := text_of("EventID")) is not None:
        record["EventID"] = event_id
    time_created = _child(system, "TimeCreated")
    if time_created is not None and time_created.get("SystemTime"):
        record["TimeCreated"] = time_created.get("SystemTime")
    for name in ("Computer", "EventRecordID", "Channel"):
        if (value := text_of(name)) is not None:
            record[name] = value

    data: dict[str, Any] = {}
    event_data = _child(root, "EventData")
    for item in event_data if event_data is not None else []:
        if _local(item.tag) == "Data" and item.get("Name"):
            data[str(item.get("Name"))] = (item.text or "").strip()
    record["EventData"] = data
    return WindowsXmlEvent(channel=record.get("Channel"), record=record)


def iter_events(text: str) -> Iterator[WindowsXmlEvent | WindowsXmlError]:
    """Every event in a file, in file order. A bad event yields its error instead of stopping the file.

    A declaration anywhere in the file refuses the whole file: events are cut out of the text, so one
    placed outside an `<Event>` would otherwise never be seen by the parser's own checks.
    """
    if _DECLARATION.search(text):
        raise WindowsXmlError("document type declarations are not allowed")
    for match in _EVENT.finditer(text):
        try:
            yield parse_event(match.group(0))
        except WindowsXmlError as exc:
            yield exc
