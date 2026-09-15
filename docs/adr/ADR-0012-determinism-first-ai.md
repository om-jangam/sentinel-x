# ADR-0012 · Determinism-first AI with human-in-the-loop

**Status:** Accepted · **Date:** 2026-07

## Context

This is the governing principle for the whole AI subsystem, elevated to an ADR because it constrains
many downstream choices. Gartner's central caution on AI SOC agents is that *vendor claims outpace
evidence*, with documented failure modes: plausible-but-wrong conclusions, prompt-injection
susceptibility, and un-auditable autonomous decisions blocking compliance adoption. A security tool
that lets an LLM *decide* what is malicious inherits all of these.

## Decision

**Detection stays deterministic; the LLM augments, humans decide the consequential actions.**
Concretely:

- Detection/correlation logic is deterministic (Sigma + owned engine) — no LLM decides maliciousness
  in the first instance.
- The LLM is confined to enrichment reasoning, correlation narrative, triage ranking, summarisation,
  and report drafting.
- Every **state-changing action** passes a mandatory **human approval gate** (`interrupt()`).
- Agent **output is data, not commands** — it takes effect only through the deterministic execution
  path behind the gate.
- All external/tool/file content is **untrusted by default** (prompt-injection guarding).
- AI quality is **measured** (golden-set + groundedness) as a CI gate; on model outage the platform
  falls back to deterministic detection + manual triage — **never guesses**.

## Alternatives considered

- **Fully autonomous agents** — rejected: the market's own evidence shows it's unsafe and
  un-adoptable in regulated SOCs; contradicts the audit-first value proposition.
- **LLM-driven detection** — rejected: non-deterministic, un-auditable, injection-exposed at the most
  critical layer.

## Consequences

- Trustworthy, auditable, compliance-friendly AI — the market's key whitespace.
- Less "magic autonomy" to demo (a deliberate, defensible trade).
- This principle is testable and enforced (gates, eval gate, degraded mode), not just aspirational.
