# ADR-0009 · Hybrid RAG by default, GraphRAG scoped

**Status:** Accepted · **Date:** 2026-07

## Context

The platform needs retrieval for two different question shapes: (1) unstructured recall over
runbooks, past incidents, and threat reports; (2) multi-hop relational questions over threat intel
("which actors use technique X against our sector, and what else do they deploy?"). The 2025
consensus (and a meta-analysis finding reported GraphRAG gains overstated by evaluation bias) is that
plain vector RAG + reranker is the strongest single primitive for unstructured corpora, while
GraphRAG earns its 1–2 orders-of-magnitude higher indexing cost only for genuinely multi-hop,
entity-centric queries. Notably, STIX intel is *already a graph*.

## Decision

Use **Qdrant hybrid search** (BGE-M3 dense+sparse, RRF/DBSF fusion, filterable HNSW) as the default
RAG for unstructured knowledge. Reserve **GraphRAG over Neo4j** for multi-hop threat-intel questions
where the STIX graph structure and path traversal genuinely beat vector recall — not as the default.

## Alternatives considered

- **GraphRAG everywhere** (MS GraphRAG) — rejected: heavy, batch-oriented, cost unjustified for
  unstructured recall.
- **Vector RAG only** — rejected: loses genuine multi-hop intel reasoning where it matters.
- **LightRAG** — attractive cheaper middle ground; kept as a future option if Neo4j GraphRAG proves
  too heavy.
- **Build an LLM-derived graph** — unnecessary when STIX already provides one.

## Consequences

- Strong recall at low cost for the common case; real multi-hop capability where it pays.
- Two retrieval paths to maintain (mitigated: GraphRAG scoped narrowly; degrades to Postgres CTE in
  `lite`).
