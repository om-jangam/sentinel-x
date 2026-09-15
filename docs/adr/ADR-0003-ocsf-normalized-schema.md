# ADR-0003 · OCSF as the internal normalised schema

**Status:** Accepted · **Date:** 2026-07

## Context

Detections and AI reasoning must work across heterogeneous sources (EDR, firewall, cloud, Sysmon,
Wazuh, apps). Without a common schema, every rule and every agent prompt is source-specific and
brittle. The industry has converged on normalise-at-ingest schemas — Google UDM, Palo Alto XDM,
Elastic ECS, and the vendor-neutral **OCSF** — while Splunk's schema-on-read CIM is the outlier that
needs acceleration to compensate.

## Decision

Normalise all telemetry to **OCSF 1.6** at ingest (via the Vector pipeline, VRL transforms). Store a
trimmed, detection-relevant field set (`class_uid`, `activity_id`, `severity_id`, entity fields, key
attributes) plus the raw event; do not materialise the full verbose OCSF surface.

## Alternatives considered

- **Elastic ECS** — mature and field-granular, but ES-centric and Elastic contributed it toward
  OTel; less neutral than OCSF.
- **Google UDM** — strictest/most curated, but vendor-controlled and not an open standard.
- **Invent our own schema** — rejected: reinvents a solved problem, loses interoperability with
  OCSF-native peers (Security Lake, SentinelOne) and the OCSF tooling ecosystem.
- **No normalisation (schema-on-read)** — rejected: pushes complexity into every rule/query; the
  Splunk-CIM path needs expensive acceleration.

## Consequences

- Source-portable detection and AI reasoning; alignment with the winning interchange/lake format.
- Normalisation cost + parser maintenance (mitigated: Vector VRL, shipped common mappers).
- OCSF verbosity managed by storing a trimmed field set.
- **Gotcha:** OCSF versioning (1.6, Aug 2025) — pin the version and track class changes.
