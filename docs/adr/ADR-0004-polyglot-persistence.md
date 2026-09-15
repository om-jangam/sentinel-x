# ADR-0004 · Polyglot persistence

**Status:** Accepted · **Date:** 2026-07

## Context

The platform has four genuinely different data workloads: (1) transactional relational data with
integrity needs (cases, RBAC, audit), (2) high-volume time-series event search + aggregation, (3)
vector similarity for RAG, (4) multi-hop graph traversal for attack paths and STIX intel. No single
store is excellent at all four.

## Decision

Use purpose-fit stores: **PostgreSQL** (system of record), **OpenSearch** (events + detection),
**Qdrant** (vectors), **Neo4j** (attack/intel graph), **Redis** (cache, rate limits, MVP bus),
**object storage** (cold events, artifacts, reports). Provide a **`lite` profile** that collapses the
footprint (Neo4j optional with a Postgres-CTE fallback; object storage → local volume) and
**graceful degradation** when optional stores are absent.

## Alternatives considered

- **PostgreSQL for everything** (pgvector, recursive CTEs, JSONB, full-text) — attractive for
  simplicity; rejected for v1's ambitions: pgvector lacks native sparse/hybrid ergonomics, PG
  full-text doesn't match OpenSearch aggregations at event volume, and recursive CTEs are poor for
  deep graph traversal. *Retained as the `lite`-profile fallback for graph/vector where acceptable.*
- **Elasticsearch instead of OpenSearch** — see [ADR-0011](ADR-0011-opensearch-over-elasticsearch.md).
- **One search store for events + vectors** (Elastic/OpenSearch kNN) — rejected: Qdrant's hybrid +
  filterable-HNSW + quantization ergonomics are materially better for RAG.

## Consequences

- Right tool per workload; strong portfolio breadth.
- High operational surface (mitigated by profiles + graceful degradation).
- Cross-store correlation handled via UUID v7 keys shared across stores.
