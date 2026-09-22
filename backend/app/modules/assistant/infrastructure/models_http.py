"""Model adapters: a local Ollama server by default, or any OpenAI-compatible endpoint (docs/04 §7).

Both ask for temperature 0 and schema-constrained JSON. Neither follows redirects, so evidence only ever
goes to the configured host. Anything other than a reply is a ModelUnavailableError, never a guess.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.core.config import Settings
from app.modules.assistant.domain.ports import LanguageModel, ModelUnavailableError

MAX_REPLY_BYTES = 1024 * 1024
OLLAMA_DEFAULT_URL = "http://127.0.0.1:11434"


def _reply(response: httpx.Response, where: str) -> dict[str, Any]:
    if response.status_code != 200:
        raise ModelUnavailableError(f"{where} answered {response.status_code}")
    if len(response.content) > MAX_REPLY_BYTES:
        raise ModelUnavailableError(f"{where} reply too large")
    try:
        body = response.json()
    except ValueError as exc:
        raise ModelUnavailableError(f"{where} answered with invalid JSON") from exc
    if not isinstance(body, dict):
        raise ModelUnavailableError(f"{where} answered with an unexpected shape")
    return body


class OllamaModel:
    def __init__(self, client: httpx.AsyncClient, *, model: str, context_tokens: int) -> None:
        self._client = client
        self._model = model
        self._context = context_tokens

    @property
    def provider(self) -> str:
        return "ollama"

    @property
    def model(self) -> str:
        return self._model

    async def complete(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> str:
        body = {
            "model": self._model,
            "messages": messages,
            "stream": False,
            "format": schema,
            "options": {"temperature": 0, "num_ctx": self._context},
        }
        try:
            response = await self._client.post("/api/chat", json=body)
        except httpx.HTTPError as exc:
            raise ModelUnavailableError(f"Ollama unreachable: {type(exc).__name__}") from exc
        message = _reply(response, "Ollama").get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise ModelUnavailableError("Ollama returned no content")
        return content

    async def aclose(self) -> None:
        await self._client.aclose()


class OpenAICompatibleModel:
    def __init__(self, client: httpx.AsyncClient, *, model: str, api_key: str | None) -> None:
        self._client = client
        self._model = model
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    @property
    def provider(self) -> str:
        return "openai"

    @property
    def model(self) -> str:
        return self._model

    async def complete(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> str:
        body = {
            "model": self._model,
            "messages": messages,
            "temperature": 0,
            "response_format": {"type": "json_schema", "json_schema": {"name": "incident_analysis", "schema": schema}},
        }
        try:
            response = await self._client.post("/v1/chat/completions", json=body, headers=self._headers)
        except httpx.HTTPError as exc:
            raise ModelUnavailableError(f"model endpoint unreachable: {type(exc).__name__}") from exc
        choices = _reply(response, "model endpoint").get("choices")
        first = choices[0] if isinstance(choices, list) and choices else None
        message = first.get("message") if isinstance(first, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise ModelUnavailableError("model endpoint returned no content")
        return content

    async def aclose(self) -> None:
        await self._client.aclose()


def model_from_settings(settings: Settings) -> LanguageModel | None:
    """None when no provider is configured: the workspace then says the assistant is unavailable."""
    if settings.ai_provider is None:
        return None
    if not settings.ai_model:
        raise ValueError("SENTINELX_AI_MODEL is required when SENTINELX_AI_PROVIDER is set")
    base_url = settings.ai_base_url or (OLLAMA_DEFAULT_URL if settings.ai_provider == "ollama" else None)
    if base_url is None:
        raise ValueError("SENTINELX_AI_BASE_URL is required for an OpenAI-compatible provider")
    client = httpx.AsyncClient(base_url=base_url, timeout=settings.ai_timeout_seconds, follow_redirects=False)
    if settings.ai_provider == "ollama":
        return OllamaModel(client, model=settings.ai_model, context_tokens=settings.ai_context_tokens)
    key = settings.ai_api_key.get_secret_value() if settings.ai_api_key else None
    return OpenAICompatibleModel(client, model=settings.ai_model, api_key=key)
