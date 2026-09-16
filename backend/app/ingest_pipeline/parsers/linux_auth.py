"""OpenSSH `sshd` authentication lines from syslog / auth.log → OCSF Authentication (3002).

Accepts RFC 3339-prefixed lines (rsyslog/journald default) and classic BSD syslog lines. BSD lines
carry no year or zone: the record's `timestamp` (set by Vector) wins; otherwise UTC in the current
year is assumed.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.clock import utcnow
from app.ingest_pipeline.ocsf import OCSF_VERSION, EventClass, Severity, Status
from app.ingest_pipeline.parsers.base import ParseError, Record, as_int, as_ip

_RFC3339_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"(?P<host>\S+)\s+sshd(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.+)$"
)
_BSD_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.+)$"
)
_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<addr>\S+) port (?P<port>\d+)")
_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<addr>\S+) port (?P<port>\d+)"
)
_INVALID_USER = re.compile(r"^Invalid user (?P<user>\S+) from (?P<addr>\S+)(?: port (?P<port>\d+))?")

LOG_NAME = "auth.log"


def _timestamp(match: re.Match[str], record: Record, *, bsd: bool) -> str:
    supplied = record.get("timestamp")
    if bsd and isinstance(supplied, str) and supplied:
        return supplied
    if not bsd:
        return match.group("ts")
    now = utcnow()
    parsed = datetime.strptime(f"{now.year} {match.group('ts')}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
    if parsed > now + timedelta(days=1):  # a December line read in January
        parsed = parsed.replace(year=now.year - 1)
    return parsed.isoformat()


def parse(record: Record) -> dict[str, Any]:
    line = record.get("message")
    if not isinstance(line, str) or not line.strip():
        raise ParseError("record has no message line")
    line = line.strip()

    match = _RFC3339_LINE.match(line)
    bsd = match is None
    if match is None:
        match = _BSD_LINE.match(line)
    if match is None:
        raise ParseError("not an sshd syslog line")

    message = match.group("msg")
    host = match.group("host")
    if (auth := _ACCEPTED.match(message)) is not None:
        status, severity, invalid = Status.SUCCESS, Severity.INFORMATIONAL, False
    elif (auth := _FAILED.match(message)) is not None:
        status, severity, invalid = Status.FAILURE, Severity.LOW, bool(auth.group("invalid"))
    elif (auth := _INVALID_USER.match(message)) is not None:
        status, severity, invalid = Status.FAILURE, Severity.LOW, True
    else:
        raise ParseError("sshd message is not an authentication outcome")

    address = auth.group("addr")
    ip = as_ip(address)
    src_endpoint: dict[str, Any] = {"ip": ip} if ip else {"hostname": address}
    port = as_int(auth.groupdict().get("port"))
    if port is not None:
        src_endpoint["port"] = port

    groups = auth.groupdict()
    return {
        "class_uid": int(EventClass.AUTHENTICATION),
        "activity_id": 1,  # Logon
        "severity_id": int(severity),
        "status_id": int(status),
        "time": _timestamp(match, record, bsd=bsd),
        "message": message,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "OpenSSH", "vendor_name": "OpenBSD"},
            "log_name": LOG_NAME,
        },
        "user": {"name": groups["user"]},
        "src_endpoint": src_endpoint,
        "dst_endpoint": {"hostname": host},
        "device": {"hostname": host},
        "auth_protocol": "SSH",
        "logon_type": "Network",
        "logon_type_id": 3,
        "unmapped": {
            "auth_method": groups.get("method"),
            "invalid_user": invalid,
            "pid": as_int(match.group("pid")),
        },
        "raw_data": line,
    }
