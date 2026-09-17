# ADR-0006 · LangGraph supervisor multi-agent orchestration

**Status:** Superseded by [ADR-0014](ADR-0014-lock-scope-security-investigation.md) (single evidence-grounded investigation assistant) · **Date:** 2026-07

## Context

Investigations are multi-step (triage → enrich → correlate → map → analyse → timeline → respond →
report), can pause for days awaiting human approval, must survive crashes/restarts, and must be
auditable — a regulator or manager must be able to review *why* a verdict was reached. We need an
orchestration framework that provides durable, resumable, human-gated, auditable execution.

## Decision

Use **LangGraph 1.x** (GA Oct 2025), self-hosted with an `AsyncPostgresSaver` checkpointer, in the
**supervisor** multi-agent pattern: a central supervisor routes to specialist agents and is the
single auditable decision point. Human-in-the-loop via `interrupt()` + `Command(resume=...)`. Prefer
**fixed graph edges** over LLM routing wherever the workflow is known.

## Alternatives considered

- **Swarm (peer-to-peer handoff)** — better for fluid conversation, worse for auditable pipelines.
  Rejected as the default.
- **Hierarchical supervisors** — only justified past ~10–15 workers; we have ~9. Revisit if the
  roster grows.
- **CrewAI** — fast to prototype, weaker fine-grained state control and durability story.
- **AutoGen/AG2 / MS Agent Framework** — churn risk (0.2→0.4 rewrite, folding into Agent Framework);
  Azure-leaning. Rejected for greenfield.
- **OpenAI Agents SDK** — good tracing, OpenAI-centric.
- **Pydantic-AI** — excellent typed structured output; younger graph story. *Adopted selectively for
  single-shot structured-extraction agents.*
- **LangGraph Platform (managed)** — rejected for cost; self-host with Postgres checkpointer.

## Consequences

- Durable, resumable, human-gated, auditable investigations.
- Framework dependency (mitigated: thin adapter; 1.0 no-breaking-changes pledge to 2.0).
- **Gotcha:** import agent helpers from `langchain.agents`; `langgraph.prebuilt` is deprecated.
