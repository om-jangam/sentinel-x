"""Pull events from a Splunk server into Sentinel-X (`sentinelx pull-splunk`).

Splunk stays the system of record; Sentinel-X asks it for the events an investigation needs, normalises
them to OCSF and runs its own detection and correlation on them. Nothing is written back to Splunk.

```
Splunk  ──POST /services/search/jobs/export (Bearer token)──▶  collector
                                                                  │ sourcetype → parser
                                                                  ▼
                                    POST /api/v1/ingest/events (this source's ingest token)
```

Safety, mirroring the other outbound clients:

- the Splunk URL must be `https` unless it points at this host, and certificate verification is only
  disabled by an explicit setting (never in production);
- the Splunk token and the ingest token are read from the environment, never from the command line, and
  neither is logged or printed;
- redirects are not followed, the search is sent as data (`POST` body), and each result line is capped;
- the search is run in preview-free export mode with an explicit time range and a result cap, so a
  mistyped search cannot pull an unbounded amount.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.ingest_pipeline.splunk import SplunkMappingError, SplunkRecord, to_record

MAX_LINE_CHARS = 1_000_000
BATCH = 500
DEFAULT_LIMIT = 10_000


class SplunkError(RuntimeError):
    """Splunk could not be searched; the message never contains the token."""


@dataclass(slots=True)
class PullOutcome:
    results: int = 0
    mapped: int = 0
    accepted: int = 0
    rejected: int = 0
    unmapped: dict[str, int] = field(default_factory=dict)
    ingest_errors: list[str] = field(default_factory=list)

    def note(self, reason: str) -> None:
        self.unmapped[reason] = self.unmapped.get(reason, 0) + 1


def search_events(
    client: httpx.Client,
    *,
    search: str,
    earliest: str,
    latest: str,
    limit: int = DEFAULT_LIMIT,
) -> Iterator[dict[str, Any]]:
    """Stream results of a Splunk search. `search` is sent as written, so it must come from an operator."""
    query = search if search.lstrip().startswith(("search ", "|")) else f"search {search}"
    body = {
        "search": query,
        "earliest_time": earliest,
        "latest_time": latest,
        "output_mode": "json",
        "preview": "false",
        "count": str(limit),
    }
    with client.stream("POST", "/services/search/jobs/export", data=body) as response:
        if response.status_code == 401:
            raise SplunkError("Splunk rejected the token (401)")
        if response.status_code >= 400:
            response.read()
            raise SplunkError(f"Splunk search failed ({response.status_code}): {response.text[:200]}")
        seen = 0
        for line in response.iter_lines():
            if not line.strip() or len(line) > MAX_LINE_CHARS:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            result = message.get("result") if isinstance(message, dict) else None
            if not isinstance(result, dict):
                continue  # progress messages and previews carry no result
            seen += 1
            yield result
            if seen >= limit:
                return


def splunk_client(url: str, token: str, *, verify: bool = True, timeout: float = 60.0) -> httpx.Client:
    return httpx.Client(
        base_url=url.rstrip("/"),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        verify=verify,
        timeout=httpx.Timeout(timeout, read=timeout * 5),
        follow_redirects=False,
    )


def _send(api: httpx.Client, ingest_token: str, records: list[dict[str, Any]], outcome: PullOutcome) -> None:
    response = api.post(
        "/api/v1/ingest/events",
        headers={"Authorization": f"Bearer {ingest_token}"},
        json=records,
    )
    if response.status_code == 401:
        raise SplunkError("Sentinel-X rejected the ingest token (401)")
    if response.status_code >= 400:
        raise SplunkError(f"ingest failed ({response.status_code}): {response.text[:200]}")
    body = response.json()
    outcome.accepted += int(body.get("accepted", 0))
    outcome.rejected += int(body.get("rejected", 0))
    for error in body.get("errors", [])[:5]:
        reason = error.get("reason") if isinstance(error, dict) else None
        if isinstance(reason, str) and reason not in outcome.ingest_errors:
            outcome.ingest_errors.append(reason[:120])


def pull(
    splunk: httpx.Client,
    api: httpx.Client,
    *,
    search: str,
    earliest: str,
    latest: str,
    ingest_token: str,
    parser: str,
    limit: int = DEFAULT_LIMIT,
    out: Callable[[str], None] = print,
) -> PullOutcome:
    """Search Splunk and post what maps to this source's parser. Other sourcetypes are counted, not sent.

    One ingest source has one parser, so a pull sends only the records that parser reads; mixing sources
    in one search would attribute events to the wrong producer.
    """
    outcome = PullOutcome()
    batch: list[dict[str, Any]] = []
    for result in search_events(splunk, search=search, earliest=earliest, latest=latest, limit=limit):
        outcome.results += 1
        try:
            mapped: SplunkRecord = to_record(result)
        except SplunkMappingError as exc:
            outcome.note(str(exc)[:160])
            continue
        if mapped.parser != parser:
            outcome.note(f"{mapped.parser} events need a source with that parser")
            continue
        outcome.mapped += 1
        batch.append(mapped.record)
        if len(batch) >= BATCH:
            _send(api, ingest_token, batch, outcome)
            out(f"   sent {outcome.accepted + outcome.rejected} of {outcome.mapped}")
            batch = []
    if batch:
        _send(api, ingest_token, batch, outcome)
    return outcome
