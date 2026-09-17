# ADR-0007 · Model gateway / bring-your-own-model

**Status:** Accepted, amended by [ADR-0014](ADR-0014-lock-scope-security-investigation.md) (thin provider adapter; budgets and routing deferred) · **Date:** 2026-07

## Context

The platform must run without per-token cost for demos, keep sensitive security data on-prem by
default, yet still reach a strong model for hard multi-step reasoning. The market's pricing backlash
(Microsoft SCU metering, credit models) is a documented wedge. Cross-cutting concerns — routing,
cost control, PII redaction, prompt-injection guarding — should not be scattered across every agent.

## Decision

Introduce a single **model gateway** between agents and models. It (1) **routes** per-agent:
structured extraction/summarisation → local **Ollama Qwen3** (temp 0, `format=schema`, explicit
`num_ctx`); heavy reasoning → a configurable **OpenAI-compatible** endpoint; (2) enforces **cost/rate
budgets** per org and caches identical calls; (3) applies **input guarding** (PII redaction,
injection screening on externally-originated content); (4) applies **output guarding** (structured
validation; model output treated as data, never commands); (5) provides **fallback + explicit
degraded mode**.

## Alternatives considered

- **Hard-code a single provider** — rejected: lock-in, cost, no local option.
- **Per-agent model calls** — rejected: duplicates guarding/routing/cost logic, inconsistent
  security posture.
- **LiteLLM/proxy as-is** — a reasonable building block; the gateway may wrap one, but we need the
  security guarding + budgets + degraded-mode semantics as first-class.

## Consequences

- Provider-agnostic, local-first, cost-bounded, injection-guarded inference in one place.
- A component to build and maintain; justified by the cross-cutting concerns it centralises.
