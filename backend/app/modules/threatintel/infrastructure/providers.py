"""The providers a deployment has configured. With none, enrichment does nothing and the workspace says so."""

from __future__ import annotations

from app.core.config import Settings
from app.modules.threatintel.domain.ports import IntelProvider
from app.modules.threatintel.infrastructure.local_feed import LocalFeedProvider
from app.modules.threatintel.infrastructure.otx import OtxProvider, otx_client


def providers_from_settings(settings: Settings) -> list[IntelProvider]:
    """A configured feed that can't be read stops start-up, like a rule that can't load."""
    providers: list[IntelProvider] = []
    if settings.ti_local_feed is not None:
        providers.append(LocalFeedProvider(settings.ti_local_feed))
    if settings.otx_api_key is not None and settings.otx_api_key.get_secret_value():
        client = otx_client(settings.otx_base_url, timeout=settings.ti_timeout_seconds)
        providers.append(OtxProvider(client, api_key=settings.otx_api_key.get_secret_value()))
    return providers
