# 02 · Technology Selection

*Reference design, July 2026.*

> **Status — partially superseded by [ADR-0014](adr/ADR-0014-lock-scope-security-investigation.md).**
> **In use:** Python 3.12, FastAPI, SQLAlchemy 2 (async), Pydantic 2, PostgreSQL, Redis (including Redis
> Streams as the bus, §5), OpenSearch, Vector (configuration only), React, Vite, Tailwind, TanStack,
> Docker Compose, GitHub Actions.
> **Not adopted:** LangGraph/LangChain agents, MCP, Qdrant and embeddings, Neo4j, Redpanda,
> MinIO/object storage, Fluent Bit, Kubernetes/Helm, and risk-based alerting as the primary alerting model.
> **Decided later by phase ADRs:** Sigma evaluation approach (Phase 2), threat-intelligence providers
> (Phase 5), model provider (Phase 6). Current architecture: [architecture.md](architecture.md).

Every choice below lists **what, why, alternatives considered, and the deciding factor**. Version
numbers reflect the verified 2025–2026 state; the recurring theme is that pre-2025 tutorials for
several of these are now actively wrong (LangChain <1.0, python-jose auth, Tailwind v3 config,
ATT&CK pre-v18 data-sources, anonymous abuse.ch access).

---

## 1. Backend runtime & framework

| Concern | Choice | Alternatives | Deciding factor |
|---------|--------|--------------|-----------------|
| Language | **Python 3.12** | Go, TypeScript/Node | The AI/security ecosystem (LangGraph, pySigma, stix2, yara-x, pefile, oletools, mitreattack-python) is Python-native. Go would win on the pipeline tier only. |
| API framework | **FastAPI** (0.12x) | Litestar, Django REST, Flask | Async-first, Pydantic v2-native, automatic OpenAPI, huge ecosystem. Litestar is a strong runner-up but smaller community. |
| Async model | **asyncio throughout** | sync + threads | Ingestion, enrichment, and agent I/O are all I/O-bound network calls — async is the natural fit and a core requirement. |
| Validation | **Pydantic v2** (2.11.x, Rust core) | dataclasses, attrs | Already the FastAPI dependency; v2's Rust core makes OCSF-event validation cheap at volume. |
| ORM | **SQLAlchemy 2.0 async** + asyncpg | SQLModel, Tortoise, Piccolo | 2.0's first-class async, maturity, and Alembic integration. SQLModel considered but adds a thin layer with rough async edges. |
| Migrations | **Alembic** | — | Standard SQLAlchemy pairing; async env.py template. |
| Background jobs | **ARQ** (async, Redis) for generic jobs; **LangGraph durable execution** for agent workflows | Celery, Dramatiq, RQ | Celery is sync-first and heavy; ARQ is asyncio-native and Redis-backed (already in the stack). Agent workflows use LangGraph's own checkpointed execution rather than a task queue. |

## 2. AI orchestration & models

| Concern | Choice | Alternatives | Deciding factor |
|---------|--------|--------------|-----------------|
| Agent orchestration | **LangGraph 1.x** (GA Oct 2025), self-hosted, `AsyncPostgresSaver` checkpointer | CrewAI, AutoGen/AG2, OpenAI Agents SDK, Pydantic-AI | Durable, checkpointed, resumable execution + first-class `interrupt()` HITL is exactly what auditable, human-gated security workflows need. Self-hosted avoids LangGraph Platform cost. See [ADR-0006](adr/ADR-0006-langgraph-supervisor-agents.md). |
| LLM SDK layer | **LangChain 1.x** (`create_agent`, middleware) | direct provider SDKs | Middleware hooks (HITL, PII redaction, summarisation) and standard content blocks. **Gotcha:** import agent helpers from `langchain.agents`; `langgraph.prebuilt` is deprecated. |
| Typed extraction | **Pydantic-AI** for narrow structured-extraction agents (optional) | LangGraph everywhere | Best-in-class typed structured output; used where a single-shot typed extraction is cleaner than a graph node. |
| Local inference | **Ollama** + **Qwen3** family (JSON-schema-constrained via `format`) | llama.cpp direct, vLLM, LM Studio | OpenAI-compatible `/v1` endpoint, guaranteed-valid JSON via grammar-constrained decoding, best JSON/tool-calling discipline among open models. **Gotcha:** set `num_ctx` explicitly (default silently truncates long logs); temp 0. |
| Cloud inference | **Any OpenAI-compatible API** behind the model gateway | hard-coded provider | Bring-your-own-model; cost and capability routing. |
| Tool integration | **MCP** (spec 2025-11-25), FastMCP (Python) | bespoke plugin API | Emerging universal standard; consume official OpenCTI (`xtm-mcp`) and MISP (`misp-mcp`) servers, expose our own. See [ADR-0008](adr/ADR-0008-mcp-tool-layer.md). |

## 3. Retrieval & knowledge

| Concern | Choice | Alternatives | Deciding factor |
|---------|--------|--------------|-----------------|
| Vector store | **Qdrant** (1.15.x) | pgvector, Weaviate, Milvus | Server-side hybrid (dense+sparse) via Query API with RRF/DBSF fusion, filterable HNSW (tenant/time-scoped), int8/binary quantization, single-binary Docker. pgvector considered to reduce store count but lacks native sparse+hybrid ergonomics. |
| Embeddings | **BGE-M3** (dense+sparse+multi-vector from one model) + bge-reranker-v2 | Qwen3-Embedding, nomic-embed, OpenAI text-embedding-3 | One model emits both vectors Qdrant hybrid needs; MIT license; runs locally. Qwen3-Embedding-8B tops MTEB but is heavier; OpenAI is the low-friction fallback. |
| Knowledge RAG | **Qdrant hybrid** over runbooks, past incidents, threat reports | GraphRAG everywhere | 2025 consensus: plain vector RAG + reranker is the strongest single primitive for unstructured corpora. See [ADR-0009](adr/ADR-0009-rag-vs-graphrag.md). |
| Graph / GraphRAG | **Neo4j** for the attack graph + multi-hop threat-intel questions | Postgres+AGE, Memgraph, LightRAG, MS GraphRAG | STIX intel *is already a graph* and attack paths are inherently multi-hop — a genuine GraphRAG fit. Neo4j gives Cypher + production ops + native vector index. GraphRAG is scoped, not the default. |

## 4. Data plane (persistence)

Full rationale and the "lite vs full" profiles are in [§05 Database Design](05-database-design.md)
and [ADR-0004](adr/ADR-0004-polyglot-persistence.md).

| Store | Role | Why this and not one store for everything |
|-------|------|-------------------------------------------|
| **PostgreSQL 16** | Transactional truth: users, RBAC, cases, incidents, IOC metadata, **tamper-evident audit log**, agent-run records | ACID, relational integrity, JSONB flexibility. The system of record. |
| **OpenSearch 2.x** | Event/log store + detection engine | Apache-2.0 (avoids the Elastic SSPL trap), built-in **Security Analytics** (2,200+ Sigma rules), **Random Cut Forest anomaly detection**, mature aggregations. See [ADR-0011](adr/ADR-0011-opensearch-over-elasticsearch.md). |
| **Qdrant** | Vector RAG + alert-similarity | (above) |
| **Neo4j** | Attack graph + GraphRAG | (above) |
| **Redis 7** | Cache, rate-limit counters, session/blocklist, **Redis Streams** as the MVP event bus | One dependency serving several cross-cutting needs; Streams defers Kafka until scale demands it. |

## 5. Ingestion pipeline & schema

| Concern | Choice | Alternatives | Deciding factor |
|---------|--------|--------------|-----------------|
| Normalised schema | **OCSF 1.6** (Aug 2025) | ECS, UDM, custom | Only vendor-independent schema (Linux Foundation), the winning interchange/lake format, OCSF-native peers (SentinelOne, Security Lake). See [ADR-0003](adr/ADR-0003-ocsf-normalized-schema.md). |
| Aggregation/normalisation | **Vector.dev** (VRL → OCSF) | Logstash, Fluentd, custom | Rust throughput + VRL is ideal for parse/enrich/redact/route to OCSF. Logstash is JVM-heavy; Fluentd slower. |
| Edge collector | **Fluent Bit** (CNCF) | Beats, Vector agent | Tiny footprint, standard K8s DaemonSet. |
| Event bus | **Redis Streams** (MVP) → **Redpanda** (scale) | Kafka, NATS | Honest sizing: a few-thousand-EPS SOC runs fine on Redis Streams; Redpanda (Kafka API, single binary, no ZK/JVM) is the documented upgrade path before Kafka's operational weight is justified. |

## 6. Detection engineering

| Concern | Choice | Alternatives | Deciding factor |
|---------|--------|--------------|-----------------|
| Rule format | **Sigma v2.1** (SigmaHQ corpus, ~3,000 rules) | vendor-native rules only | De-facto detection lingua franca; readable, MITRE-mapped, versionable. |
| Compilation | **pySigma** → OpenSearch backend | hand-written queries | Compile once, target the search backend; processing pipelines handle OCSF field mapping. |
| Prepackaged detections | **OpenSearch Security Analytics** (2,200+ Sigma) | build from scratch | Ship real coverage on day one. |
| Correlation/temporal | **Custom engine** over normalised OCSF events | rely on Sigma-correlation backends | **Gotcha:** Sigma v2 correlation is specified but backend support is patchy — temporal/multi-event logic runs in our own engine. See [ADR-0005](adr/ADR-0005-detection-and-risk-engine.md). |
| Anomaly detection | **OpenSearch RCF** (Random Cut Forest) for beaconing/volumetric, scoped | generic "AI anomaly detection" | Scope it narrowly; broad unsupervised outlier detection has unacceptable FP rates. |
| Alerting model | **Risk-Based Alerting** (own risk engine) | per-alert notifications | Structural answer to alert fatigue (Part B of §01). |

## 7. Threat intelligence

| Concern | Choice | Notes / free-tier reality |
|---------|--------|---------------------------|
| Standards | **STIX 2.1 / TAXII 2.1** (`stix2`, `taxii2-client`) | Stable OASIS libraries. |
| TIPs | **MISP** (PyMISP), **OpenCTI** (pycti + `xtm-mcp`) | Integrate against hosted instances rather than bundling (OpenCTI is resource-hungry). |
| Feeds | **abuse.ch** (URLhaus, MalwareBazaar, ThreatFox, Feodo) | **Requires a free Auth-Key since mid-2025**; ThreatFox expires IOCs >6 months. Ingest bulk dumps. |
| Enrichers | **VirusTotal v3** (4/min, 500/day), **AbuseIPDB** (1k/day), **AlienVault OTX** | **Cache-first, escalate-only**: VT's 500/day dies fast in automation — cache by hash, enrich only escalated alerts. |

## 8. Malware / phishing analysis (embeddable, in-process)

| Concern | Choice | Notes |
|---------|--------|-------|
| Signatures | **YARA-X** (yara-x Python bindings, stable 1.0) | Original YARA in maintenance mode; high rule compatibility. |
| PE static | **pefile** + **LIEF** | Headers/imports/sections/entropy; LIEF for multi-format speed. |
| Fuzzy hash | **ssdeep / tlsh** | Similarity clustering. |
| Maldocs | **oletools** (olevba, oleid, rtfobj, msodde) | Standard OLE/OOXML triage. |
| Email | stdlib `email` + `eml_parser`/`extract-msg`; **checkdmarc**, **dkimpy** | SPF/DKIM/DMARC verification and header analysis. |
| URL | `tldextract`, `dnstwist` (typosquat), urlscan.io / Safe Browsing APIs | Registered-domain + confusable checks. |
| Sandbox | **CAPEv2 as an optional external connector**, not bundled | Cuckoo is dead; CAPEv2 is operationally heavy (KVM guests) — integrate via REST, keep static analysis in-process. |

## 9. MITRE ATT&CK

- **ATT&CK v18** (Oct 2025) via **mitreattack-python** (`MitreAttackData`) over STIX 2.1 bundles.
- **Gotcha:** v18 rebuilt the detection model — **Detection Strategy** and **Analytic** objects
  replace per-technique detection text, and **Data Sources are deprecated**. Any code touching the
  old `x_mitre_data_sources` fields must target v18 objects; pin a mitreattack-python release with
  v18 support before ingesting.
- **ATT&CK Navigator layer 4.5** JSON export for coverage heatmaps — cheap to generate, high value.

## 10. Security stack (backend)

| Concern | Choice | Rejected | Why |
|---------|--------|----------|-----|
| JWT | **PyJWT** | ~~python-jose~~ | python-jose is effectively abandoned and removed from FastAPI docs. |
| Password hashing | **argon2-cffi** via **pwdlib** | ~~passlib~~ | passlib is stale; argon2id is the current recommendation. |
| AuthN model | **Custom JWT** (access + rotating refresh), optional external OIDC (Keycloak/Authentik) | fastapi-users | For a security product, own the auth flow or delegate to a real IdP; avoid a half-maintained framework. See [ADR-0010](adr/ADR-0010-auth-stack.md). |
| Rate limiting | **fastapi-limiter** (Redis) | slowapi | Redis-backed, distributed-safe. |
| Telemetry | **OpenTelemetry** (FastAPI/SQLAlchemy/HTTPX instrumentors) | ad-hoc logging | Traces/metrics/structured logs to Grafana LGTM. |

## 11. Frontend

| Concern | Choice | Notes |
|---------|--------|-------|
| Framework | **React 19** + **TypeScript** | Stable since Dec 2024. |
| Build | **Vite 7** | Node 20+. |
| Styling | **Tailwind CSS v4** (`@theme`, `@tailwindcss/vite`) | **Gotcha:** no `tailwind.config.js` by default; v3 snippets need translation. |
| Components | **shadcn/ui** (Tailwind v4 + React 19, `sonner` for toasts) | Own-the-code component model. |
| Server state | **TanStack Query v5** | Settled default. |
| Routing | **TanStack Router v1** (type-safe) | Chosen over React Router v7 for type safety. |
| Realtime | **WebSocket / SSE** for live alert & agent-step streaming | Investigation canvas updates. |

## 12. Deployment, CI/CD, observability

| Concern | Choice |
|---------|--------|
| Containers | **Docker** (multi-stage builds, distroless/slim base) |
| Local/lite | **Docker Compose** profiles (`lite`, `dev`) |
| Production | **Kubernetes** + **Helm** (+ Kustomize overlays) |
| CI/CD | **GitHub Actions**: ruff, mypy, pytest+coverage, eslint/vitest, **trivy** (image), **bandit** (SAST-py), **semgrep**, **gitleaks** (secrets), SBOM (syft), build/push, deploy |
| Metrics | **Prometheus** + **Grafana** |
| Tracing/logs | **OpenTelemetry** → Grafana Tempo/Loki (or SigNoz) |

---

### Cross-cutting principle that governs every choice

**Determinism beats agency in security tooling.** LLMs do enrichment, summarisation, and
triage-ranking; detection logic stays deterministic (Sigma + correlation); every consequential action
passes a human gate; and all external/tool output is treated as untrusted (prompt-injection is the
top MCP/agent risk). This principle is why the stack pairs a durable workflow engine (LangGraph) with
LLM-free detection paths rather than asking a model to "decide" what is malicious.
