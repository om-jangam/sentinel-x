# 04 · AI Investigation Assistant

*Design — not built (roadmap Phase 6). Replaces the July 2026 multi-agent design
([ADR-0006](adr/ADR-0006-langgraph-supervisor-agents.md), superseded by
[ADR-0014](adr/ADR-0014-lock-scope-security-investigation.md)).*

## 1. Role

The assistant helps an analyst understand an incident that detection and correlation have **already**
assembled. It is the last analytical step, not the first:

```
events → detection → correlation → evidence bundle → timeline / graph → AI investigation → analyst
```

It does not detect threats, create incidents, add events, change evidence, call external systems or take
any action. If it is unavailable, every other stage works unchanged.

## 2. Questions it answers

1. What happened?
2. Which events appear related, and why?
3. What evidence supports each conclusion?
4. Which MITRE ATT&CK techniques may apply?
5. What should the analyst investigate next?
6. What information is missing?
7. What is uncertain?

## 3. Input: the evidence bundle

The assistant sees only a bundle built deterministically from the incident:

- the incident's findings, each with rule, severity and matched technique IDs;
- the evidence events (normalised documents, identified by `sx.event_uid`, with `raw_data` truncated);
- the timeline and graph edges, each with the event IDs that support it;
- threat-intelligence results attached to indicators, with source and retrieval time.

Bundles have a size budget. When evidence exceeds it, the bundle says so explicitly, so the omission is
itself reported as missing information rather than silently lost.

## 4. Output contract

Structured JSON, validated before anything is shown:

```json
{
  "summary": "…",
  "statements": [
    {"kind": "FACT", "text": "…", "evidence": ["<event_uid>", "…"]},
    {"kind": "INFERENCE", "text": "…", "reasoning": "…", "evidence": ["<event_uid>"], "confidence": "low|medium|high"},
    {"kind": "UNCERTAINTY", "text": "…", "missing": "what would resolve it"}
  ],
  "techniques": [{"technique_id": "T1110", "evidence": ["<event_uid>"], "kind": "INFERENCE"}],
  "next_steps": ["…"]
}
```

- **FACT** restates something directly present in cited events.
- **INFERENCE** connects facts; it must give its reasoning and cite the events it rests on.
- **UNCERTAINTY** names a gap, conflict or assumption and what evidence would resolve it.

## 5. Grounding rules (enforced in code, not by prompt alone)

- Every cited `event_uid`, indicator and entity must exist in the bundle. A statement citing anything
  else is **dropped** and the drop is recorded; a response with no valid statements is rejected.
- FACT and INFERENCE require at least one citation; technique suggestions require one.
- The assistant cannot add timeline steps or graph edges. It may *suggest* a relationship as INFERENCE
  for the analyst to confirm.
- Output is displayed as the assistant's analysis, separate from system-derived facts, with the model,
  prompt version and bundle hash recorded in the audit trail.

## 6. Untrusted content

Event fields (command lines, messages, file names, raw logs) are attacker-controllable. The prompt
carries them as quoted, delimited data with an explicit instruction that nothing inside is an
instruction. Output is parsed as data. The assistant has no tools, so injected text has nothing to
invoke, and the grounding validator rejects fabricated citations it might produce.

## 7. Models

A thin provider adapter ([ADR-0007](adr/ADR-0007-model-gateway.md), as amended): a local model by default
(Ollama) and any OpenAI-compatible endpoint optionally, with temperature 0 and schema-constrained output.
No multi-model routing, agent framework, tool protocol (MCP) or vector store — see ADR-0014.

## 8. Failure and evaluation

- **Unavailable or invalid output:** the incident shows "AI analysis unavailable" with the reason;
  nothing is guessed or retried silently.
- **Evaluation:** a labelled set of incidents built from `pipeline/samples` scenarios. It measures
  citation validity (must be 100%), how many expected facts are recovered, the rate of unsupported
  statements, and technique precision. Prompt or model changes must not regress it.
