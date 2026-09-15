# 13 · Interview Value Analysis

*Phase 1 · Sentinel-X · covers requested deliverable 18*

This document maps Sentinel-X to the skills interviewers probe, and gives you the talking points and
the hard questions to rehearse. The project's core interview strength is that **it demonstrates
judgment, not just implementation** — every major decision has a defended alternative.

---

## 1. Skills demonstrated (by role lens)

| Role you're interviewing for | What Sentinel-X proves |
|------------------------------|------------------------|
| **AI / ML Engineer** | Multi-agent orchestration (LangGraph supervisor), durable/resumable execution, HITL gates, RAG + scoped GraphRAG, model gateway with local/remote routing, structured output, **agent evaluation as a CI gate**, prompt-injection defence |
| **Backend Engineer** | Async FastAPI, Clean Architecture, SOLID, DDD-style bounded modules, SQLAlchemy 2.0 async, polyglot persistence, event-driven design, API design (REST + WS + OpenAPI) |
| **Security Engineer / SOC** | SIEM/SOAR/XDR concepts, OCSF, Sigma detection-as-code, MITRE ATT&CK v18, Risk-Based Alerting, threat-intel (STIX/TAXII/MISP), malware/phishing static analysis, tamper-evident audit, OWASP/LLM-Top-10 threat modelling |
| **Platform / DevOps / SRE** | Docker multi-stage, Kubernetes + Helm, GitHub Actions with security gates, SBOM/signing, Prometheus/Grafana/OpenTelemetry, SLOs, deployment profiles |
| **System Designer / Architect** | Monolith-vs-microservices reasoning with extraction seams, storage/compute trade-offs, schema-normalisation strategy, scalability axes, ADR discipline |

## 2. The five stories that carry an interview

Each is a "tell me about a hard technical decision" answer with a defended trade-off.

1. **"Why a modular monolith and not microservices?"**
   → Operational cost vs. a solo/small team; 90% of the benefit from clean boundaries; the three
   services I'd extract first and their triggers ([§03](03-system-architecture.md) §7). *Shows: you
   distribute for a reason, not for résumé keywords.*

2. **"How do you keep an AI SOC tool trustworthy?"**
   → Determinism-first (detection is deterministic; LLM does enrichment/ranking), mandatory human
   gates, evidence-linked immutable audit, golden-set eval CI gate, prompt-injection defence.
   *Shows: you understand where LLMs fail and engineer around it — directly answering Gartner's #1
   caution.*

3. **"How do you fight alert fatigue?"**
   → Risk-Based Alerting: score risk to entities, decay it, open incidents on accumulated risk, not
   per-signal — with the market data (63% unaddressed, 46% FP) that motivates it. *Shows: you solve
   the user's real problem, backed by evidence.*

4. **"Why OCSF, and why normalise at ingest?"**
   → Source-portable detection & AI; the industry convergence (UDM/XDM/ECS/OCSF) and why
   schema-on-read (Splunk CIM) is the outlier; the cost you accept and how Vector absorbs it.
   *Shows: schema/data-modelling depth and awareness of the actual product landscape.*

5. **"How do you handle a hostile file upload in a security product?"**
   → Isolated hardened worker, no in-process execution, quarantine storage, static-only in-platform,
   external sandbox over API, egress allowlist. *Shows: you threat-model your own attack surface.*

## 3. Hard questions to rehearse (and where the answer lives)

- *"Sigma correlation exists — why build your own correlation engine?"* → backend support is patchy;
  temporal logic in-platform ([§02](02-technology-selection.md) §6, [ADR-0005](adr/ADR-0005-detection-and-risk-engine.md)).
- *"Six datastores is a lot to run."* → workload-fit justification + `lite` profile + graceful
  degradation ([§05](05-database-design.md) §7, [ADR-0004](adr/ADR-0004-polyglot-persistence.md)).
- *"Isn't GraphRAG overkill?"* → yes, generally — which is why it's scoped to genuine multi-hop
  intel where STIX is already a graph; plain hybrid RAG elsewhere ([ADR-0009](adr/ADR-0009-rag-vs-graphrag.md)).
- *"How do you know the AI is actually good?"* → golden-set + groundedness as a merge gate; you
  measure triage accuracy and FP-suppression, not vibes ([§04](04-ai-agent-architecture.md) §9).
- *"What happens when the LLM provider is down?"* → gateway fallback + degraded mode = deterministic
  detection + manual triage; never guess ([§04](04-ai-agent-architecture.md) §6).
- *"How does this scale?"* → stateless tiers scale off the bus; OpenSearch tiers + PG replicas; bus
  upgrades Redis→Redpanda without code change; agent throughput bounded by LLM, mitigated by local
  models + caching ([§03](03-system-architecture.md) §9).
- *"Prompt injection?"* → untrusted-by-default tool output, curated tool descriptions,
  output-as-data behind human gates, egress allowlist ([§07](07-security-architecture.md) §9).

## 4. What makes this stand out from typical portfolio projects

| Typical portfolio project | Sentinel-X |
|---------------------------|-----------|
| Tutorial CRUD app | Production patterns: Clean Arch, ports/adapters, CI security gates, tests |
| "Wrapped an LLM in a chat box" | Durable multi-agent graph with HITL, audit, eval, injection defence |
| No tests / no CI | Unit + integration (Testcontainers) + agent eval + SAST/SBOM in CI |
| Ignores the domain | Grounded in verified 2025–2026 market/competitor research |
| One happy path | Threat model, failure modes, degraded mode, deferred-scope honesty |
| "More is better" | Deliberate non-goals and monolith-over-microservices restraint |

## 5. Depth-signal artifacts to point at

- The **ADRs** (`docs/adr/`) — each records context, options, decision, consequences. Interviewers
  love ADRs; they're proof of structured decision-making.
- The **golden-set eval gate** — quantitative AI quality, not anecdote.
- The **tamper-evident audit chain** + `verify_audit_chain.py` — security rigour applied to yourself.
- The **module dependency graph + import-linter contracts** — architecture you can *enforce*, not
  just draw.
- This **research-backed analysis** — you can cite Gartner MQ 2025, IBM CoDB 2025, the RBA lineage,
  OCSF adoption, ATT&CK v18 changes, and LangGraph 1.0 specifics from memory.

## 6. Honest positioning (say this, don't oversell)

> "It's a portfolio platform, not a product with paying customers — but it's built with the patterns
> a product would need: it runs on a laptop and scales on Kubernetes, detection is deterministic with
> the LLM confined to augmentation behind human gates, and every AI decision is audited and
> evaluated. I made deliberate scope cuts — no endpoint sensor, cloud posture deferred — so I could
> actually finish a credible core rather than a broad shell."

That framing — *credible core, honest scope, defended decisions* — is what converts a project into a
hire signal.
