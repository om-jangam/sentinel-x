# ADR-0011 · OpenSearch over Elasticsearch

**Status:** Accepted · **Date:** 2026-07

## Context

The event/detection store is the platform's highest-volume dependency. Elasticsearch and OpenSearch
are technically close (OpenSearch forked from Elasticsearch 7.10). Two factors differentiate them for
this project: **licensing** (Elastic moved to SSPL/Elastic License, later adding AGPL; OpenSearch is
Apache-2.0) and **built-in security features** (OpenSearch ships **Security Analytics** with 2,200+
Sigma rules and a **Random Cut Forest** anomaly-detection plugin).

## Decision

Use **OpenSearch 2.x** as the event store and a detection surface. Apache-2.0 removes any
license-restriction risk for an open, self-hostable, potentially-redistributable portfolio platform,
and Security Analytics + RCF give real detection/anomaly capability out of the box that complements
our pySigma pipeline and owned correlation engine.

## Alternatives considered

- **Elasticsearch** — richer commercial ecosystem and the excellent public detection-rules repo, but
  the SSPL/Elastic-License trust issue and the fork-driven community split make it the wrong default
  here. (We still *consume* Sigma, which pySigma targets for both.)
- **ClickHouse / Loki / a data lake (Parquet+DuckDB)** — strong on cost/throughput but weaker
  full-text + built-in security-analytics/anomaly tooling; higher build effort for detection.
  Revisit for a cold-tier analytics store.

## Consequences

- No licensing risk; batteries-included detection/anomaly features; Wazuh-ecosystem alignment
  (Wazuh's indexer is an OpenSearch fork).
- Cluster operational burden at scale (mitigated: hot/warm/cold tiers + searchable snapshots;
  single-node in `lite`).
- pySigma OpenSearch backend targeted for rule compilation.
