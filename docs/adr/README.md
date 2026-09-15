# Architecture Decision Records

*Phase 1 · Sentinel-X · covers requested deliverable 5*

ADRs capture **significant** architecture decisions: the context, the options weighed, the decision,
and its consequences. They are immutable once accepted — a superseded decision gets a new ADR that
references the old one, so the reasoning history is preserved.

Format: lightweight [MADR](https://adr.github.io/madr/)-style. Status ∈ {Proposed, Accepted,
Superseded}.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](ADR-0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](ADR-0002-modular-monolith-over-microservices.md) | Modular monolith over microservices | Accepted |
| [0003](ADR-0003-ocsf-normalized-schema.md) | OCSF as the internal normalised schema | Accepted |
| [0004](ADR-0004-polyglot-persistence.md) | Polyglot persistence | Accepted |
| [0005](ADR-0005-detection-and-risk-engine.md) | Sigma detection + owned correlation/risk engine | Accepted |
| [0006](ADR-0006-langgraph-supervisor-agents.md) | LangGraph supervisor multi-agent orchestration | Accepted |
| [0007](ADR-0007-model-gateway.md) | Model gateway / bring-your-own-model | Accepted |
| [0008](ADR-0008-mcp-tool-layer.md) | MCP as the tool-integration layer | Accepted |
| [0009](ADR-0009-rag-vs-graphrag.md) | Hybrid RAG by default, GraphRAG scoped | Accepted |
| [0010](ADR-0010-auth-stack.md) | Auth stack: PyJWT + argon2 + custom JWT | Accepted |
| [0011](ADR-0011-opensearch-over-elasticsearch.md) | OpenSearch over Elasticsearch | Accepted |
| [0012](ADR-0012-determinism-first-ai.md) | Determinism-first AI with human-in-the-loop | Accepted |

New ADRs are added as implementation surfaces new significant decisions (per-phase).
