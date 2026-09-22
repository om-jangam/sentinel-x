# ADR-0019 · AI assistant: local model by default, grounding enforced in code

**Status:** Accepted · **Date:** 2026-09 · **Refines:** [ADR-0007](ADR-0007-model-gateway.md) and
[ADR-0012](ADR-0012-determinism-first-ai.md) (both as amended by ADR-0014); implements
[docs/04](../04-ai-investigation-assistant.md)

## Context

Phase 6 adds the investigation assistant designed in docs/04:
- it explains an incident that detection and correlation have already built;
- every statement is labelled FACT, INFERENCE or UNCERTAINTY and cites stored events;
- it never invents anything or acts.

Four facts shape the build:

1. **Incident evidence is sensitive.** Sending it to a third-party model is a data-egress decision, not a
   default.
2. **Models fabricate.** A prompt asking for grounding is not a guarantee, so the guarantee has to live in
   code that checks every answer.
3. **Local models are slow on modest hardware.** On the development machine (GTX 1650, 4 GB), `deepseek-r1:8b`
   runs mostly on the CPU and spends minutes on its reasoning trace, even for a trivial JSON reply.
4. **Evidence text is attacker-controlled.** Command lines, messages and raw records can contain
   instructions.

## Decision

1. **Two provider adapters, off by default.**
   - Ollama is the default (`SENTINELX_AI_PROVIDER=ollama`), so evidence stays on the host.
   - Any OpenAI-compatible endpoint (`openai`) is optional. Production requires `https`, unless it points at
     this host.
   - Both use temperature 0 and schema-constrained JSON, and follow no redirects.
   - With no provider set, the assistant is simply unavailable.
2. **A deterministic evidence bundle is the model's only input.** It holds the incident summary, findings,
   correlation links, evidence digests (at most 80, with raw excerpts cut to 300 characters), the timeline,
   graph edges and cached intel with its source.
   - Omitted events are counted in the bundle, not silently lost.
   - Its SHA-256 is recorded with every analysis.
3. **Untrusted content is data.**
   - The bundle is sent as JSON between `<evidence>` delimiters, with `<` escaped so no field can close them.
   - The system prompt says nothing inside is an instruction.
   - The model has no tools, so injected text has nothing to invoke.
4. **A grounding validator decides what is shown.** It drops:
   - any statement or technique citing an event_uid not in the bundle;
   - a FACT or INFERENCE without citations, an INFERENCE without reasoning, and an UNCERTAINTY without what
     would resolve it;
   - any text, summary or next step that names an IP address or hash absent from the bundle.

   Each drop is kept with its reason. An answer with no surviving statement is **rejected**. The share of
   the model's raw citations that were valid is recorded.
5. **Every request is recorded and audited, whatever the outcome.** `incident_analyses` stores the status
   (`completed`, `rejected`, `unavailable`), provider, model, prompt version, bundle hash, validated output,
   drops and duration. `incident.analysis_requested` is added to the audit chain.
   - Asking needs `assistant:use` (analysts and above).
   - Reading needs `incident:read`.
   - The assistant changes nothing else.
6. **A labelled evaluation** (`sentinelx evaluate-assistant`) builds the sample incidents through the real
   pipeline and scores the configured model on:
   - citation validity, which must be 100%;
   - key-event recall;
   - the unsupported-statement rate;
   - technique precision and recall.

## Consequences

- The assistant can be wrong, but it cannot put an ungrounded citation or an invented address in front of
  an analyst. What it said and what was removed are both on record.
- Everything else in the workspace works without a model, and the UI says so.
- **Real runs (Phase 7):** `deepseek-r1:8b` timed out (600 s), and the adapter reported it as unavailable,
  as designed. `qwen2.5:3b` scored 100% citation validity on both sample incidents.
  - Under prompt v1 a whole live answer was rejected: every inference lacked reasoning.
  - Prompt **v2** splits statements into `facts`, `inferences` and `uncertainties`, so the schema requires
    each kind's fields. It then kept 12 of 12 statements.
  - The remaining errors are wrong labels and wrong attribution with real citations, which grounding
    cannot catch; see the [module doc](../modules/assistant.md#results-on-the-development-machine-gtx-1650-4-gb).
- The analysis request is synchronous. nginx allows that one route 610 s; a background job would be the
  next step if analyses get longer.
- Claude or another hosted model can be added as a third adapter behind the same interface. Choosing one
  is a data-egress decision for the deployment.
