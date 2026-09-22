"""The OTX adapter against recorded-shape responses (httpx.MockTransport). Not verified against the live API."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.modules.threatintel.domain.indicators import Indicator, IndicatorType
from app.modules.threatintel.domain.intel import Verdict
from app.modules.threatintel.infrastructure.otx import OtxError, OtxProvider

PULSE = {
    "id": "5f0c0ffee",
    "name": "Fictional beaconing campaign",
    "tags": ["c2", "beacon"],
    "references": ["https://blog.example/beacon", "not-a-url"],
    "malware_families": [{"display_name": "FakeRAT"}],
    "created": "2026-08-01T10:00:00.000000",
    "modified": "2026-09-10T12:00:00.000000",
}


def provider(routes: dict[str, Any], seen: list[httpx.Request] | None = None) -> OtxProvider:
    def handle(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        body = routes.get(request.url.path)
        if isinstance(body, httpx.Response):
            return body
        if body is None:
            return httpx.Response(404, json={"detail": "not found"})
        return httpx.Response(200, json=body)

    client = httpx.AsyncClient(base_url="https://otx.test", transport=httpx.MockTransport(handle))
    return OtxProvider(client, api_key="test-key")


async def test_pulses_make_an_indicator_suspicious_with_related_indicators() -> None:
    seen: list[httpx.Request] = []
    otx = provider(
        {
            "/api/v1/indicators/IPv4/192.0.2.66/general": {"pulse_info": {"count": 3, "pulses": [PULSE]}},
            "/api/v1/indicators/IPv4/192.0.2.66/passive_dns": {
                "passive_dns": [{"hostname": "cdn-telemetry-sync.example", "address": "192.0.2.66"}]
            },
        },
        seen,
    )
    answer = await otx.lookup(Indicator(IndicatorType.IP, "192.0.2.66"))

    assert answer is not None
    assert answer.verdict is Verdict.SUSPICIOUS, "pulses are community reports, not a malicious verdict"
    assert answer.summary == "Referenced in 3 OTX community pulse(s): Fictional beaconing campaign"
    assert {"c2", "beacon", "FakeRAT"} <= set(answer.tags)
    assert ("domain", "cdn-telemetry-sync.example") in {(r.type, r.value) for r in answer.related}
    assert "https://otx.alienvault.com/pulse/5f0c0ffee" in answer.references
    assert answer.provider_first_seen is not None and answer.provider_last_seen is not None  # noqa: PT018
    assert all(request.headers["X-OTX-API-KEY"] == "test-key" for request in seen)
    assert [request.url.host for request in seen] == ["otx.test", "otx.test"]


async def test_an_allowlisted_indicator_is_benign() -> None:
    otx = provider(
        {
            "/api/v1/indicators/domain/example.org/general": {
                "validation": [{"source": "whitelist", "name": "Known good domain"}],
                "pulse_info": {"count": 1, "pulses": [PULSE]},
            },
            "/api/v1/indicators/domain/example.org/passive_dns": {"passive_dns": []},
        }
    )
    answer = await otx.lookup(Indicator(IndicatorType.DOMAIN, "example.org"))
    assert answer is not None
    assert answer.verdict is Verdict.BENIGN
    assert "Known good domain" in answer.summary


async def test_nothing_known_is_not_found() -> None:
    hash_value = "e" * 64
    otx = provider({f"/api/v1/indicators/file/{hash_value}/general": {"pulse_info": {"count": 0, "pulses": []}}})
    assert await otx.lookup(Indicator(IndicatorType.HASH, hash_value)) is None
    assert await provider({}).lookup(Indicator(IndicatorType.HASH, hash_value)) is None  # 404


async def test_ipv6_uses_its_own_section() -> None:
    seen: list[httpx.Request] = []
    await provider({}, seen).lookup(Indicator(IndicatorType.IP, "2001:db8::1"))
    assert seen[0].url.raw_path == b"/api/v1/indicators/IPv6/2001%3Adb8%3A%3A1/general"


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(429, json={"detail": "slow down"}),
        httpx.Response(500, text="oops"),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, content=json.dumps({"pad": "x" * (2 * 1024 * 1024)}).encode()),
        httpx.Response(302, headers={"location": "https://elsewhere.example/steal"}),
    ],
)
async def test_failures_raise_so_enrichment_records_an_error(response: httpx.Response) -> None:
    otx = provider({"/api/v1/indicators/IPv4/203.0.113.45/general": response})
    with pytest.raises(OtxError):
        await otx.lookup(Indicator(IndicatorType.IP, "203.0.113.45"))
