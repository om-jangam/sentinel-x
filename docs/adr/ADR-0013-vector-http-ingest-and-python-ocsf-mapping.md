# ADR-0013 · Vector → HTTP ingest API, OCSF mapping in Python

**Status:** Accepted · **Date:** 2026-09 · **Amends:** [§03](../03-system-architecture.md) §4–6,
[ADR-0003](ADR-0003-ocsf-normalized-schema.md)

## Context

The Phase 1 design routed telemetry **Vector → event bus (Redis Streams) → ingestion**, with OCSF
mapping written in VRL. Implementation surfaced two problems:

1. **Vector cannot write Redis Streams.** Its `redis` source and sink support only the `list` and
   pub/sub `channel` data types (verified against Vector's `DataTypeConfig`), so there is no
   consumer-group / acknowledgement path from Vector into the bus we standardised on.
2. **Mapping logic in VRL alone is hard to test and would be duplicated.** The HTTP ingest path
   (agents, webhooks, manual submission) needs the same source → OCSF mappers in Python anyway.
   Two implementations of every mapper, in two languages, drift.

## Decision

- **Vector collects, shapes and buffers; it does not own OCSF semantics.** Pipelines tail files,
  receive syslog, parse framing (JSON/lines), attach a timestamp, drop noise, and deliver batches via
  Vector's **`http` sink** to `POST /api/v1/ingest/events`, authenticated with a **per-source ingest
  token** (`Authorization: Bearer sxi_…`). Disk buffers + retries give at-least-once delivery.
- **Every source declares a parser** (`ocsf`, `linux_auth`, `windows_security`, …). OCSF 1.6 mapping
  lives in `backend/app/ingest_pipeline/` as pure, unit-tested Python, and events already in OCSF
  use the `ocsf` passthrough parser.
- **The ingest API is the single validation and tenancy choke point:** authenticate the source,
  enforce size and rate limits, map and validate against the typed OCSF model, stamp `org_id` /
  `source_id` / ingest time, compute a content fingerprint, and publish to Redis Streams
  (`events.normalized`). An **indexer worker** consumes the stream into OpenSearch.
- **Idempotency by content:** the fingerprint (SHA-256 of org, source and canonical normalised
  event) is the OpenSearch `_id`, so redelivered batches don't duplicate events.

## Alternatives considered

- **Vector `redis` list sink + custom list consumer** — rejected: no consumer groups or pending/ack
  semantics, so at-least-once across multiple workers is lost.
- **Vector `elasticsearch` sink straight to OpenSearch** — rejected: bypasses validation, tenant
  stamping, source authentication, dedupe and per-source health; couples the pipeline to storage.
- **Vector `kafka` sink → Redpanda** — the right shape at scale and remains the upgrade path (the
  indexer's bus contract doesn't change), but too heavy for the `lite` profile today.
- **VRL-only OCSF mapping** — rejected for the testability and duplication reasons above. VRL may
  still pre-shape exotic formats before delivery.

## Consequences

- One tested mapping implementation; one place where untrusted telemetry is validated and attributed.
- The API sits in the ingest hot path. Mitigation: ingest is stateless and horizontally scalable, and
  requests are capped (events per request, body size, per-source rate). Very high EPS moves to the
  Redpanda path without changing consumers.
- Per-source credentials are individually revocable, rotated through the API, and audited.
