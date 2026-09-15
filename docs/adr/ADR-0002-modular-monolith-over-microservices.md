# ADR-0002 · Modular monolith over microservices

**Status:** Accepted · **Date:** 2026-07

## Context

The platform has ~15 logical modules and must (a) be built by one engineer, (b) run on a laptop for
demos, and (c) scale in a cluster. Microservices are the reflexive "enterprise" choice, but they
impose real cost: service discovery, distributed tracing on every hop, network-partition failure
modes, per-service CI/CD, and cross-service schema/contract management. Much of the platform's work
is transactional (incident + finding + audit written together), which microservices turn into
distributed-transaction problems.

## Decision

Build a **modular monolith**: one deployable FastAPI application composed of strongly bounded modules
(each with `domain/application/infrastructure/interface` layers), plus a **separate async
worker/agent tier** and standalone stateful backing services. Enforce module boundaries with
`import-linter` in CI. Pre-draw service-extraction seams so hot modules (ingestion+detection, agent
runtime, RAG) can be lifted out later without rewriting callers (communication already goes through
port interfaces and the event bus).

## Alternatives considered

- **Microservices from day one** — rejected: operational tax unjustified at this team size/scale;
  breaks laptop-demo; distributed transactions for little gain. Documented extraction order/triggers
  in [§03](../03-system-architecture.md) §7.
- **Unstructured monolith** — rejected: no enforceable boundaries → the "big ball of mud" that can't
  be extracted later or reasoned about per-module.

## Consequences

- Fast development, transactional integrity, simple ops, demoable anywhere.
- Requires discipline (CI-enforced) to keep boundaries clean.
- Independent scaling is deferred, but the seams make extraction a known, bounded task.
- Strong interview signal: *distributing for a reason, not for keywords.*
