# ADR-0014 · Lock the product scope: security investigation and attack-chain reconstruction

**Status:** Accepted · **Date:** 2026-09 · **Amends:** ADR-0004, ADR-0005, ADR-0007, ADR-0012 ·
**Supersedes:** ADR-0006 · **Defers:** ADR-0008, ADR-0009

## Context

The initial design set (docs 00–13, July 2026) framed Sentinel-X as an "autonomous AI security
operations platform": a nine-agent LangGraph supervisor, risk-based alerting as the primary alerting
model, human-approved containment and blocklist actions, malware and phishing analysis, a RAG
knowledge base, and six data stores (PostgreSQL, OpenSearch, Redis, Qdrant, Neo4j, object storage).

Two things changed. First, a separate project, **Aegis**, now owns endpoint security (detection on
the host, hardening, local response). Anything endpoint-facing in Sentinel-X would duplicate it.
Second, the framing had drifted towards breadth: many subsystems, stores and agents, most of them
unbuilt, with no clear answer to the one question an analyst brings to an incident.

## Decision

Sentinel-X is **an AI-assisted security investigation platform that correlates heterogeneous security
telemetry, reconstructs attack timelines and entity relationships, enriches evidence with threat
intelligence, and assists analysts in investigating security incidents.**

It answers: *what actually happened during a security incident, how are the events connected, and
what evidence should an analyst investigate?*

**Workflow** — each stage consumes the output of the one before it:

```
security data → ingestion → normalisation → detection → correlation
             → attack reconstruction (timeline + evidence graph) → threat intelligence
             → AI investigation → incident workspace
```

**Principles**

1. **Evidence first.** Every finding, relationship, timeline step and graph edge references the
   stored events that support it (`sx.event_uid`). No relationship is created without supporting
   evidence. Stored events are immutable.
2. **Detection is deterministic; correlation is where the value is.** Sigma and rule logic produce
   findings. Correlation over shared entities (IP, host, user, process, file, hash, domain, time,
   authentication activity, ATT&CK technique) turns findings into incidents.
3. **AI assists; it does not detect or act.** The assistant runs after detection, correlation and
   reconstruction, over a bounded evidence bundle. Every statement is labelled **FACT** (cites
   events), **INFERENCE** (states its reasoning and cites events) or **UNCERTAINTY** (names what is
   missing). It must never invent events, indicators, relationships or activity; uncited claims are
   rejected, not displayed.
4. **Source-agnostic.** Aegis is one source among many (Linux auth, Windows Security, network,
   firewall, cloud, Vector-collected logs). Sentinel-X must work without Aegis.
5. **Restraint.** The current stores (PostgreSQL, Redis, OpenSearch) are the platform. A new store,
   framework or service needs an ADR that shows a concrete, measured need.

**Out of scope — these belong to Aegis or to no one:** endpoint security software, endpoint
hardening, antivirus, EDR, local firewall control, process protection, local remediation, endpoint
configuration auditing, and executing containment or response actions on any system.

## Effect on earlier decisions

| ADR | Now |
|-----|-----|
| 0004 Polyglot persistence | **Amended.** PostgreSQL, Redis and OpenSearch only. Qdrant, Neo4j and object storage are not adopted; the evidence graph starts in PostgreSQL. |
| 0005 Sigma detection + risk engine | **Amended.** Sigma detection and in-platform correlation stand. Risk-based alerting is not the primary incident mechanism; entity risk may later be a correlation input. |
| 0006 LangGraph supervisor multi-agent | **Superseded.** One evidence-grounded investigation assistant, not a multi-agent supervisor. No agent framework until a single assistant is shown to be insufficient. |
| 0007 Model gateway | **Amended.** A thin provider adapter (local model by default, OpenAI-compatible optional) with input/output guarding. Cost budgets and multi-model routing are deferred. |
| 0008 MCP tool layer | **Deferred.** The assistant receives a prepared evidence bundle; it does not call tools. |
| 0009 Hybrid RAG / GraphRAG | **Deferred.** No knowledge base or vector store in scope. |
| 0012 Determinism-first AI with HITL | **Amended.** Sentinel-X executes no containment or response actions, so the approval gate covers AI-suggested changes to incident records only. Principle 3 above adds the FACT / INFERENCE / UNCERTAINTY contract. |

ADRs 0001, 0002, 0003, 0010, 0011 and 0013 are unaffected.

## Alternatives considered

- **Keep the autonomous-SOC framing.** Rejected: overlaps Aegis, most subsystems unbuilt, and
  autonomous response contradicts the evidence-first investigation value.
- **Become a general log dashboard/SIEM.** Rejected: search alone does not answer how events connect;
  correlation and reconstruction are the differentiator.
- **Fold Aegis into Sentinel-X.** Rejected: endpoint agents and investigation platforms have different
  deployment, trust and release models.

## Consequences

- A smaller, finishable roadmap (docs/11) in which every phase produces investigation value.
- The design documents that described the superseded framing are archived in
  `docs/archive/2026-07-initial-design/`; remaining reference documents carry a status banner.
- Evidence immutability becomes a hard requirement for storage and for every later module.
