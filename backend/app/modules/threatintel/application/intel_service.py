"""Reading cached intel. Reads never call a provider, so opening an incident never sends data anywhere."""

from __future__ import annotations

from collections.abc import Sequence

from app.core.errors import ValidationFailedError
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.modules.threatintel.domain.indicators import Indicator
from app.modules.threatintel.domain.intel import IntelResult, ProviderInfo
from app.modules.threatintel.domain.ports import IntelProvider, IntelUnitOfWork

MAX_LOOKUP = 200


class IntelQueryService:
    def __init__(self, uow: IntelUnitOfWork, providers: Sequence[IntelProvider]) -> None:
        self._uow = uow
        self._providers = providers

    def providers(self, principal: Principal) -> list[ProviderInfo]:
        principal.require(Permission.INTEL_READ)
        return [provider.info for provider in self._providers]

    async def results(self, principal: Principal, keys: Sequence[str]) -> tuple[list[IntelResult], list[str]]:
        """Cached results for the indicators, and the keys that aren't indicators Sentinel-X looks up."""
        principal.require(Permission.INTEL_READ)
        if len(keys) > MAX_LOOKUP:
            raise ValidationFailedError(
                "Too many indicators",
                errors=[{"loc": ["indicators"], "msg": f"at most {MAX_LOOKUP}", "type": "too_long"}],
            )
        indicators: list[Indicator] = []
        skipped: list[str] = []
        for key in dict.fromkeys(keys):
            indicator = Indicator.parse(key)
            if indicator is None:
                skipped.append(key)
            else:
                indicators.append(indicator)
        results = await self._uow.results.get_many(principal.org_id, indicators) if indicators else []
        return sorted(results, key=lambda r: (r.indicator, r.provider)), skipped
