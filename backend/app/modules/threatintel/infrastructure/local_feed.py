"""Local indicator feed: a CSV or JSON file of indicators the organisation already knows about.

Columns (CSV header, or JSON object keys): `type` (ip | domain | hash), `value`, `verdict` (malicious |
suspicious | benign | unknown), and optionally `confidence` (0-100), `source`, `description`, `tags`
(`;`-separated in CSV, a list in JSON), `reference` (https URL), `first_seen`, `last_seen` (RFC 3339).

Rows that aren't valid are skipped and counted, never half-loaded. A row is not a valid indicator if its
value is an internal address or a bare host name.
"""

from __future__ import annotations

import csv
import json
import logging
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from app.core.clock import ensure_utc
from app.modules.threatintel.domain.indicators import Indicator, IndicatorType
from app.modules.threatintel.domain.intel import ProviderAnswer, ProviderInfo, Verdict

logger = logging.getLogger(__name__)

MAX_FEED_BYTES = 20 * 1024 * 1024
MAX_ROWS = 200_000


class FeedError(ValueError):
    """The feed file can't be read at all (missing, too big, not CSV or JSON)."""


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _time(value: Any) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    return ensure_utc(datetime.fromisoformat(text.replace("Z", "+00:00")))


def _row(raw: Mapping[str, Any]) -> tuple[Indicator, ProviderAnswer] | None:
    indicator = Indicator.of(_text(raw.get("type")), _text(raw.get("value")))
    if indicator is None:
        return None
    try:
        verdict = Verdict(_text(raw.get("verdict")).lower() or "unknown")
        confidence_text = _text(str(raw.get("confidence") or ""))
        confidence = int(confidence_text) if confidence_text else None
        if confidence is not None and not 0 <= confidence <= 100:
            return None
        first_seen, last_seen = _time(raw.get("first_seen")), _time(raw.get("last_seen"))
    except ValueError:
        return None
    tags_raw = raw.get("tags")
    tags = (
        [str(tag).strip() for tag in tags_raw]
        if isinstance(tags_raw, list)
        else [tag.strip() for tag in _text(tags_raw).split(";")]
    )
    source = _text(raw.get("source")) or "local feed"
    description = _text(raw.get("description"))
    reference = _text(raw.get("reference"))
    return indicator, ProviderAnswer(
        verdict=verdict,
        summary=f"{source}: {description}" if description else f"Listed in {source}",
        confidence=confidence,
        tags=tuple(tag for tag in tags if tag),
        references=(reference,) if reference.startswith("https://") else (),
        provider_first_seen=first_seen,
        provider_last_seen=last_seen,
    )


def _records(path: Path) -> Iterable[Mapping[str, Any]]:
    if not path.is_file():
        raise FeedError(f"threat-intel feed not found: {path}")
    if path.stat().st_size > MAX_FEED_BYTES:
        raise FeedError(f"threat-intel feed is larger than {MAX_FEED_BYTES // (1024 * 1024)} MiB: {path}")
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise FeedError(f"threat-intel feed is not valid JSON: {exc}") from exc
        if not isinstance(data, list):
            raise FeedError("a JSON threat-intel feed must be a list of indicator objects")
        return [item for item in data if isinstance(item, Mapping)]
    if path.suffix.lower() == ".csv":
        return list(csv.DictReader(line for line in text.splitlines() if not line.lstrip().startswith("#")))
    raise FeedError(f"threat-intel feed must be .csv or .json: {path}")


class LocalFeedProvider:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._entries: dict[Indicator, ProviderAnswer] = {}
        skipped = 0
        for count, raw in enumerate(_records(path), start=1):
            if count > MAX_ROWS:
                raise FeedError(f"threat-intel feed has more than {MAX_ROWS} rows")
            parsed = _row(raw)
            if parsed is None:
                skipped += 1
                continue
            self._entries[parsed[0]] = parsed[1]
        self._skipped = skipped
        if skipped:
            logger.warning("threat-intel feed rows skipped", extra={"feed": path.name, "rows_skipped": skipped})

    @property
    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name="local",
            title=f"Local indicator feed ({self._path.name})",
            kind="local",
            supports=tuple(kind.value for kind in IndicatorType),
            detail={"indicators": len(self._entries), "rows_skipped": self._skipped},
            # The feed is reloaded only at start-up; an hour keeps edits visible without a cache flush.
            cache_ttl=timedelta(hours=1),
        )

    def supports(self, kind: IndicatorType) -> bool:
        return True

    async def lookup(self, indicator: Indicator) -> ProviderAnswer | None:
        return self._entries.get(indicator)

    async def aclose(self) -> None:
        return None
