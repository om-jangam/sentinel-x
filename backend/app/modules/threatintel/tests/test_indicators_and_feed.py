from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.modules.threatintel.domain.indicators import Indicator, IndicatorType
from app.modules.threatintel.domain.intel import Verdict
from app.modules.threatintel.infrastructure.local_feed import FeedError, LocalFeedProvider

DEMO_FEED = Path(__file__).resolve().parents[5] / "pipeline" / "intel" / "demo_indicators.csv"


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("ip:203.0.113.45", "ip:203.0.113.45"),
        ("IP: 2001:DB8::1 ", "ip:2001:db8::1"),
        ("domain:CDN-Telemetry-Sync.Example.", "domain:cdn-telemetry-sync.example"),
        (f"hash:{'AB' * 32}", f"hash:{'ab' * 32}"),
        (f"hash:{'a' * 32}", f"hash:{'a' * 32}"),
    ],
)
def test_indicators_normalise(key: str, expected: str) -> None:
    indicator = Indicator.parse(key)
    assert indicator is not None
    assert indicator.key == expected


@pytest.mark.parametrize(
    "key",
    [
        "ip:10.0.5.17",  # internal addresses never leave the platform
        "ip:127.0.0.1",
        "ip:not-an-ip",
        "domain:ws-fin-07",  # a bare host name is not a domain
        "domain:a/b.example",
        "domain:../../etc.example",
        "hash:xyz",
        f"hash:{'a' * 33}",
        "host:web-01",
        "user:root@web-01",
        "no-separator",
    ],
)
def test_values_that_must_not_be_looked_up_are_refused(key: str) -> None:
    assert Indicator.parse(key) is None


async def test_the_demo_feed_loads_and_answers() -> None:
    feed = LocalFeedProvider(DEMO_FEED)
    assert feed.info.detail == {"indicators": 4, "rows_skipped": 0}
    assert feed.info.kind == "local"

    answer = await feed.lookup(Indicator(IndicatorType.IP, "192.0.2.66"))
    assert answer is not None
    assert answer.verdict is Verdict.MALICIOUS
    assert answer.confidence == 90
    assert answer.summary.startswith("Sentinel-X demo feed: Command-and-control server")
    assert "c2" in answer.tags
    assert answer.provider_first_seen is not None
    assert await feed.lookup(Indicator(IndicatorType.IP, "203.0.113.99")) is None


def test_invalid_rows_are_skipped_and_counted(tmp_path: Path) -> None:
    feed = tmp_path / "feed.csv"
    feed.write_text(
        "type,value,verdict,confidence,reference\n"
        "ip,203.0.113.7,malicious,50,https://intel.example/ip/203.0.113.7\n"
        "ip,10.1.2.3,malicious,50,\n"  # internal
        "ip,203.0.113.8,terrible,50,\n"  # unknown verdict
        "ip,203.0.113.9,malicious,150,\n"  # confidence out of range
        "domain,web-01,malicious,,\n"  # host name
        "domain,ok.example,,,http://insecure.example/x\n",  # verdict defaults to unknown; http reference dropped
        encoding="utf-8",
    )
    provider = LocalFeedProvider(feed)
    assert provider.info.detail == {"indicators": 2, "rows_skipped": 4}


async def test_json_feeds_are_supported(tmp_path: Path) -> None:
    feed = tmp_path / "feed.json"
    feed.write_text(
        json.dumps([{"type": "hash", "value": "d" * 64, "verdict": "suspicious", "tags": ["dropper"]}, "junk"]),
        encoding="utf-8",
    )
    provider = LocalFeedProvider(feed)
    answer = await provider.lookup(Indicator(IndicatorType.HASH, "d" * 64))
    assert answer is not None
    assert (answer.verdict, answer.tags) == (Verdict.SUSPICIOUS, ("dropper",))


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("missing.csv", None, "not found"),
        ("feed.txt", "x", "must be .csv or .json"),
        ("feed.json", "{not json", "not valid JSON"),
        ("feed.json", '{"type": "ip"}', "must be a list"),
    ],
)
def test_unreadable_feeds_stop_start_up(tmp_path: Path, name: str, content: str | None, message: str) -> None:
    path = tmp_path / name
    if content is not None:
        path.write_text(content, encoding="utf-8")
    with pytest.raises(FeedError, match=message):
        LocalFeedProvider(path)
