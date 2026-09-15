# 00 · Executive Summary

*Phase 1 · Sentinel-X — Autonomous AI Security Operations Platform*

This document is the one-page synthesis of the full Phase 1 analysis. Every claim here is expanded,
sourced, and justified in the numbered documents that follow.

---

## The opportunity in one paragraph

Security spending will reach **~$213B in 2025 and ~$240B in 2026** (Gartner), and the fastest-growing
slice is autonomous SOC / SOC automation (Mordor sizes "autonomous SOC" at **$8.4B → $31.5B by 2031,
~25% CAGR**). Gartner formally named **"AI SOC Agents"** a category in June 2025 and placed it at the
*Peak of Inflated Expectations* — meaning buyers are pilot-ready but skeptical, and **proof of
measurable triage-accuracy and MTTR improvement is the credibility currency**. The pain is real and
quantified: ~2,992 alerts/day with 63% unaddressed, 46% false-positive rates, a ~4.8M workforce gap
now constrained by *budget* rather than availability, and AI-assisted responders saving ~$1.9M per
breach. There is documented whitespace in **transparent per-investigation audit trails**,
**vendor-agnostic operation**, and **predictable economics** (the backlash against Microsoft's
Security Compute Unit pricing is a live wedge).

## What we are building

An AI Security Operations platform that automatically collects logs, detects threats, and runs
end-to-end investigations through a **supervisor-orchestrated team of AI agents**, keeping a human in
the loop for consequential actions. The platform spans ingestion → normalisation → detection →
risk-based alerting → agentic investigation (enrichment, correlation, ATT&CK mapping, malware/phishing
analysis, timeline reconstruction) → reporting and remediation recommendations, wrapped in
case management, RBAC, and full audit.

## The ten decisions that define the architecture

1. **Modular monolith, not microservices** — one deployable FastAPI application organised into
   strongly-bounded modules, plus a separate async worker/agent tier and standalone stateful
   backing services. Microservice extraction seams are designed in but not exercised on day one.
   Rationale in [ADR-0002](adr/ADR-0002-modular-monolith-over-microservices.md).
2. **OCSF 1.6 as the internal normalised schema** — telemetry is mapped to Open Cybersecurity Schema
   Framework classes at ingest, making detection and AI reasoning source-portable.
   [ADR-0003](adr/ADR-0003-ocsf-normalized-schema.md).
3. **Purpose-built polyglot persistence** — PostgreSQL (transactional/case/audit), OpenSearch
   (events + detection engine), Qdrant (vector RAG), Neo4j (attack graph + GraphRAG), Redis
   (cache/bus). Each store is justified against its workload; a "lite" profile collapses the
   footprint for laptops/demos. [ADR-0004](adr/ADR-0004-polyglot-persistence.md).
4. **Detection = Sigma-as-code + a custom correlation/risk engine** — SigmaHQ rules compiled via
   pySigma to OpenSearch; temporal/multi-event correlation and **Risk-Based Alerting** run in an
   owned engine because Sigma-correlation backend support is patchy and RBA is the structural
   answer to alert fatigue. [ADR-0005](adr/ADR-0005-detection-and-risk-engine.md).
5. **LangGraph supervisor multi-agent** — durable, checkpointed (Postgres) agent graph with
   `interrupt()`-based human approval gates; deterministic edges preferred over agentic routing
   wherever the workflow is known. [ADR-0006](adr/ADR-0006-langgraph-supervisor-agents.md).
6. **Model gateway / bring-your-own-model** — route between local Ollama (Qwen3, JSON-schema
   constrained extraction) and any OpenAI-compatible API; all external tool output treated as
   untrusted (prompt-injection guarding). [ADR-0007](adr/ADR-0007-model-gateway.md).
7. **MCP as the tool-integration standard** — internal capabilities exposed as an MCP server;
   external intel (OpenCTI, MISP) consumed via their official MCP servers/SDKs.
   [ADR-0008](adr/ADR-0008-mcp-tool-layer.md).
8. **GraphRAG only where it earns its cost** — plain Qdrant hybrid RAG for runbooks/reports/past
   incidents; Neo4j GraphRAG reserved for genuinely multi-hop threat-intel questions, where STIX is
   already a graph. [ADR-0009](adr/ADR-0009-rag-vs-graphrag.md).
9. **Security-first backend stack** — PyJWT (not the abandoned python-jose), argon2 hashing, custom
   JWT with refresh rotation + RBAC + tamper-evident audit log, rate limiting, OpenTelemetry.
   [ADR-0010](adr/ADR-0010-auth-stack.md).
10. **Two deployment profiles** — Docker Compose (`lite` single-host and `dev`) and Kubernetes/Helm
    (`prod`), so the same codebase runs on a laptop for demos and scales horizontally in a cluster.

## How this improves on the original module plan

The original brief's module list is sound; the analysis sharpens it (full detail in
[§12](12-risks-tradeoffs-improvements.md)):

- Promote **OCSF normalisation** and a **security data pipeline** to first-class concerns — research
  is unanimous that *data quality, not model quality, is the binding constraint*.
- Replace per-alert **Notifications** with a **Risk Engine + RBA** as the primary alerting model —
  directly attacks the #1 documented pain point.
- Fold "AI Investigation Engine" and "Multi-Agent AI" into one coherent **Agentic Investigation**
  subsystem with an explicit supervisor and audit trail.
- Add **Detection-as-Code** content management and a **Model Gateway** as infrastructure modules.
- De-scope **Cloud Security/CNAPP** and **DevOps/DAST** to clearly-labelled Phase 4+ extensions so
  the core platform is actually deliverable by one engineer.

## Delivery shape

Twelve build phases (~detailed in [§11](11-development-roadmap.md)) from platform foundation
(auth/RBAC/audit) → ingestion/OCSF → detection/risk → case management → threat-intel enrichment →
agent runtime → investigation agents → malware/phishing → ATT&CK/timeline/graph → RAG knowledge base
→ reporting → deployment hardening. Each phase ships production-ready code, tests, docs, and a
working vertical slice before the next begins.

## Recommendation

Proceed to Phase 2 on the architecture described here. It is buildable by one engineer in
incremental, demoable slices; it reflects the actual 2025–2026 engineering consensus (OCSF,
detection-as-code, RBA, durable agent graphs, MCP, bring-your-own-model); and it is deliberately
honest about scope and about when *not* to adopt the heavyweight pattern. The single most important
guardrail to preserve through implementation: **keep detection logic deterministic and keep the LLM
on enrichment/summarisation/triage-ranking with human gates** — that is what separates a credible
security tool from a demo.
