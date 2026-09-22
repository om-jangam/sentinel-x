"""Model adapters against mocked HTTP: what they send, and that every failure is 'unavailable', never a guess."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from app.core.config import Environment, Settings
from app.modules.assistant.domain.ports import ModelUnavailableError
from app.modules.assistant.infrastructure.models_http import OllamaModel, OpenAICompatibleModel, model_from_settings

MESSAGES = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
SCHEMA: dict[str, Any] = {"type": "object"}


def client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url="http://model.test", transport=httpx.MockTransport(handler))


async def test_ollama_asks_for_deterministic_schema_constrained_json() -> None:
    sent: list[dict[str, Any]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        assert request.url.path == "/api/chat"
        return httpx.Response(200, json={"message": {"role": "assistant", "content": '{"ok": true}'}})

    model = OllamaModel(client(handle), model="qwen2.5:3b", context_tokens=8192)
    assert await model.complete(MESSAGES, SCHEMA) == '{"ok": true}'
    assert sent[0]["format"] == SCHEMA
    assert sent[0]["stream"] is False
    assert sent[0]["options"] == {"temperature": 0, "num_ctx": 8192}
    assert (model.provider, model.model) == ("ollama", "qwen2.5:3b")


async def test_openai_compatible_sends_the_key_and_a_json_schema() -> None:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"ok": 1}'}}]})

    model = OpenAICompatibleModel(client(handle), model="gpt-x", api_key="sk-test")
    assert await model.complete(MESSAGES, SCHEMA) == '{"ok": 1}'
    body = json.loads(seen[0].content)
    assert seen[0].headers["Authorization"] == "Bearer sk-test"
    assert body["temperature"] == 0
    assert body["response_format"]["json_schema"]["schema"] == SCHEMA


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, text="boom"),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json={"message": {"content": "  "}}),
        httpx.Response(200, json={"unexpected": True}),
        httpx.Response(307, headers={"location": "https://elsewhere.example/"}),
        httpx.Response(200, content=b"{" + b" " * (1024 * 1024) + b"}"),
    ],
)
async def test_bad_replies_are_unavailable(response: httpx.Response) -> None:
    model = OllamaModel(client(lambda _: response), model="m", context_tokens=4096)
    with pytest.raises(ModelUnavailableError):
        await model.complete(MESSAGES, SCHEMA)


async def test_timeouts_and_connection_failures_are_unavailable() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(ModelUnavailableError, match="ReadTimeout"):
        await OllamaModel(client(fail), model="m", context_tokens=4096).complete(MESSAGES, SCHEMA)
    with pytest.raises(ModelUnavailableError, match="ReadTimeout"):
        await OpenAICompatibleModel(client(fail), model="m", api_key=None).complete(MESSAGES, SCHEMA)


def settings(**values: Any) -> Settings:
    return Settings(_env_file=None, environment=Environment.TEST, **values)


async def test_models_are_built_from_settings() -> None:
    assert model_from_settings(settings()) is None
    ollama = model_from_settings(settings(ai_provider="ollama", ai_model="qwen2.5:3b"))
    assert ollama is not None
    assert ollama.provider == "ollama"
    await ollama.aclose()
    remote = model_from_settings(
        settings(ai_provider="openai", ai_model="m", ai_base_url="https://llm.example", ai_api_key=SecretStr("k"))
    )
    assert remote is not None
    assert remote.provider == "openai"
    await remote.aclose()
    with pytest.raises(ValueError, match="SENTINELX_AI_MODEL"):
        model_from_settings(settings(ai_provider="ollama"))
    with pytest.raises(ValueError, match="SENTINELX_AI_BASE_URL"):
        model_from_settings(settings(ai_provider="openai", ai_model="m"))


def test_production_refuses_to_send_evidence_over_plain_http_to_another_host() -> None:
    base: dict[str, Any] = {
        "environment": Environment.PRODUCTION,
        "jwt_private_key": SecretStr("x"),
        "redis_url": "redis://r",
        "database_url": "postgresql+asyncpg://u:p@db/x",
        "opensearch_url": "https://os",
    }
    with pytest.raises(ValueError, match="SENTINELX_AI_BASE_URL must be https"):
        Settings(_env_file=None, ai_base_url="http://llm.internal:8000", **base)
    Settings(_env_file=None, ai_base_url="http://127.0.0.1:11434", **base)
    Settings(_env_file=None, ai_base_url="https://llm.internal", **base)
