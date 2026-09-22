"""The evaluation harness: sample incidents build through the real pipeline, and the scores mean what they say."""

from __future__ import annotations

import json
from typing import Any

from app.assistant_eval import CASES, evaluate, sample_bundles, score
from app.modules.assistant.domain.ports import ModelUnavailableError
from app.tests.test_assistant_api import evidence_of


class Perfect:
    """Cites every key event of the case it is asked about, and only real events."""

    provider, model = "scripted", "perfect"

    async def complete(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> str:
        bundle = evidence_of(messages)
        return json.dumps(
            {
                "summary": "s",
                "statements": [
                    {"kind": "FACT", "text": event["action"], "evidence": [event["event_uid"]]}
                    for event in bundle["events"]
                ],
                "techniques": [
                    {"technique_id": t, "evidence": [bundle["events"][0]["event_uid"]], "kind": "INFERENCE"}
                    for finding in bundle["findings"]
                    for t in finding["techniques"]
                ],
                "next_steps": [],
            }
        )

    async def aclose(self) -> None:
        return None


class Inventive(Perfect):
    async def complete(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> str:
        answer = json.loads(await super().complete(messages, schema))
        answer["statements"].append({"kind": "FACT", "text": "x", "evidence": ["invented-uid"]})
        answer["techniques"].append({"technique_id": "T1486", "evidence": ["invented-uid"], "kind": "INFERENCE"})
        return json.dumps(answer)


class Down(Perfect):
    async def complete(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> str:
        raise ModelUnavailableError("no model")


async def test_the_sample_incidents_are_built_for_evaluation() -> None:
    bundles = await sample_bundles()
    assert set(bundles) == {"ws-fin-07", "web-01"}
    for case in CASES:
        bundle = bundles[case.host]
        for label, match in case.key_events.items():
            assert any(match(event) for event in bundle.events), f"{case.name}: no event is {label}"


async def test_a_grounded_model_passes_with_full_recall() -> None:
    results = await evaluate(Perfect())
    assert [r.passed for r in results] == [True, True]
    for result in results:
        assert result.citation_validity == 1.0
        assert result.key_event_recall == 1.0
        assert result.unsupported_rate == 0.0
        assert result.technique_precision == 1.0


async def test_a_model_that_invents_citations_fails_even_though_validation_cleans_its_answer() -> None:
    results = await evaluate(Inventive())
    assert not any(r.passed for r in results)
    assert all(r.status == "completed" for r in results), "its grounded statements still survive"
    assert all(r.citation_validity is not None and r.citation_validity < 1.0 for r in results)


async def test_an_unavailable_model_scores_nothing() -> None:
    results = await evaluate(Down())
    assert {r.status for r in results} == {"unavailable"}
    assert not any(r.passed for r in results)


async def test_rejected_answers_are_scored_as_rejected() -> None:
    bundles = await sample_bundles()
    result = score(CASES[1], bundles["web-01"], "not json at all")
    assert (result.status, result.passed) == ("rejected", False)
