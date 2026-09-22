"""AlienVault OTX adapter (https://otx.alienvault.com/api): community pulses and passive DNS.

What OTX says is recorded as what it says. Appearing in community pulses makes an indicator *suspicious*,
not malicious: pulses are reports, not verdicts. An OTX allowlist ("validation") entry makes it *benign*.
Only validated external indicators reach this adapter (see `Indicator`), and only over HTTPS.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any
from urllib.parse import quote

import httpx

from app.core.clock import ensure_utc
from app.modules.threatintel.domain.indicators import Indicator, IndicatorType
from app.modules.threatintel.domain.intel import ProviderAnswer, ProviderInfo, RelatedIndicator, Verdict

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PULSES_NAMED = 5
MAX_PASSIVE_DNS = 10


class OtxError(RuntimeError):
    """OTX answered with something other than data or "not found" (rate limit, outage, bad key)."""


def _section(indicator: Indicator) -> str:
    if indicator.type is IndicatorType.IP:
        return "IPv6" if ipaddress.ip_address(indicator.value).version == 6 else "IPv4"
    return "domain" if indicator.type is IndicatorType.DOMAIN else "file"


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return ensure_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


class OtxProvider:
    def __init__(self, client: httpx.AsyncClient, *, api_key: str) -> None:
        self._client = client
        self._headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}

    @property
    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name="otx",
            title="AlienVault OTX",
            kind="external",
            supports=tuple(kind.value for kind in IndicatorType),
        )

    def supports(self, kind: IndicatorType) -> bool:
        return True

    async def _get(self, indicator: Indicator, part: str) -> dict[str, Any] | None:
        path = f"/api/v1/indicators/{_section(indicator)}/{quote(indicator.value, safe='')}/{part}"
        response = await self._client.get(path, headers=self._headers)
        # 404: nothing known. 400: OTX refuses to look the value up (it rejects reserved names such as
        # `.example`), which also means it has nothing to say; retrying would never succeed.
        if response.status_code in (400, 404):
            return None
        if response.status_code != 200:
            raise OtxError(f"OTX answered {response.status_code}")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise OtxError("OTX response too large")
        try:
            body = response.json()
        except ValueError as exc:
            raise OtxError("OTX answered with invalid JSON") from exc
        return body if isinstance(body, dict) else None

    async def lookup(self, indicator: Indicator) -> ProviderAnswer | None:
        general = await self._get(indicator, "general")
        if general is None:
            return None
        validation = [v for v in general.get("validation") or [] if isinstance(v, dict)]
        pulse_info = general.get("pulse_info") if isinstance(general.get("pulse_info"), dict) else {}
        pulses = [p for p in (pulse_info or {}).get("pulses") or [] if isinstance(p, dict)]
        count = int((pulse_info or {}).get("count") or len(pulses))

        related: list[RelatedIndicator] = [
            RelatedIndicator("pulse", str(p.get("name"))[:200], "referenced in OTX pulse")
            for p in pulses[:MAX_PULSES_NAMED]
            if p.get("name")
        ]
        if indicator.type is not IndicatorType.HASH:
            related += await self._passive_dns(indicator)
        tags = [str(tag) for p in pulses for tag in p.get("tags") or []]
        tags += [
            str(m.get("display_name")) for p in pulses for m in p.get("malware_families") or [] if isinstance(m, dict)
        ]
        references = [f"https://otx.alienvault.com/pulse/{p['id']}" for p in pulses[:MAX_PULSES_NAMED] if p.get("id")]
        references += [str(r) for p in pulses for r in p.get("references") or [] if isinstance(r, str)]
        created = [t for t in (_time(p.get("created")) for p in pulses) if t]
        modified = [t for t in (_time(p.get("modified")) for p in pulses) if t]

        if validation:
            names = ", ".join(sorted({str(v.get("name") or v.get("source") or "allowlist") for v in validation}))
            return ProviderAnswer(
                verdict=Verdict.BENIGN,
                summary=f"On an OTX allowlist ({names}); referenced in {count} pulse(s).",
                tags=tuple(tags),
                related=tuple(related),
                references=tuple(references),
            )
        if count == 0:
            return (
                None
                if not related
                else ProviderAnswer(
                    verdict=Verdict.UNKNOWN,
                    summary="Not referenced in any OTX pulse; passive DNS only.",
                    related=tuple(related),
                )
            )
        named = "; ".join(str(p.get("name")) for p in pulses[:3] if p.get("name"))
        return ProviderAnswer(
            verdict=Verdict.SUSPICIOUS,
            summary=f"Referenced in {count} OTX community pulse(s)" + (f": {named}" if named else "."),
            tags=tuple(tags),
            related=tuple(related),
            references=tuple(references),
            provider_first_seen=min(created) if created else None,
            provider_last_seen=max(modified) if modified else None,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _passive_dns(self, indicator: Indicator) -> list[RelatedIndicator]:
        body = await self._get(indicator, "passive_dns")
        records = [r for r in (body or {}).get("passive_dns") or [] if isinstance(r, dict)]
        related: list[RelatedIndicator] = []
        for record in records[:MAX_PASSIVE_DNS]:
            if indicator.type is IndicatorType.IP and record.get("hostname"):
                related.append(RelatedIndicator("domain", str(record["hostname"])[:253], "resolved to this address"))
            elif indicator.type is IndicatorType.DOMAIN and record.get("address"):
                related.append(RelatedIndicator("ip", str(record["address"])[:64], "this domain resolved to"))
        return related


def otx_client(base_url: str, *, timeout: float) -> httpx.AsyncClient:
    # No redirects: the key is only ever sent to the configured host.
    return httpx.AsyncClient(base_url=base_url, timeout=timeout, follow_redirects=False)
