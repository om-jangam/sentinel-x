# 10 · Module Breakdown

*Current. Built modules are described as implemented; planned modules follow the investigation workflow
fixed by [ADR-0014](adr/ADR-0014-lock-scope-security-investigation.md).*

All modules live in `backend/app/modules/<name>/` with `domain / application / infrastructure /
interface` layers. Modules never import each other (enforced by `import-linter`). They share `core`,
stable identifiers (`sx.event_uid`, entity keys) and bus events.

## Built

### `core` (shared foundation)
Configuration with production guards, UUID v7, RFC 9457 errors, async database sessions, the
hash-chained audit log, security primitives (keys, tokens, passwords, blocklist, rate limiting), the
event bus (Redis Streams / in-memory), logging, metrics and tracing. → [module doc](modules/platform.md)

### `identity`
Login, rotating refresh tokens with reuse detection, logout, users, roles, permissions, live RBAC and
lockout-prevention guards. → [module doc](modules/identity.md)

### `platform`
Liveness and readiness (database, Redis, event store), Prometheus metrics, non-secret config, audit log
reading and chain verification. → [module doc](modules/platform.md)

### `ingestion` + `ingest_pipeline`
Source registry with per-source tokens; the ingest API with limits; parsers for sshd, Windows Security
and native OCSF; an OCSF 1.6 subset model; immutable OpenSearch storage; the indexer worker; constrained
event search. → [module doc](modules/ingestion.md)

### `detection`
In-stream evaluation of Sigma rules (parsed by pySigma, translated to predicates over OCSF paths) and
threshold rules over normalised events; immutable **findings** that cite their events; the rule
catalogue. → [module doc](modules/detection.md)

## Planned (in workflow order)

| Module | Responsibility | Produces | Consumes |
|--------|----------------|----------|----------|
| `correlation` | Extract entities (IP, host, user, process, file, hash, domain) and link findings and events that share entities within time windows, including authentication sequences and technique chains | **Incidents** with evidence, plus the correlation rule and entities that justify each link | findings, events |
| `incidents` | Incident workspace state: summary, severity, status, assignee, analyst notes, evidence set; every change audited | incident records | incidents |
| `reconstruction` | Ordered attack **timeline** and **entity graph** per incident; each step and edge carries the events that support it | timeline, graph | incident evidence |
| `threatintel` | Reputation and related indicators for IPs, domains and hashes from configured providers, cached with source and retrieval time | enrichment records | incident entities |
| `assistant` | Evidence-grounded AI analysis ([04](04-ai-investigation-assistant.md)) | FACT / INFERENCE / UNCERTAINTY statements with citations | evidence bundle |

**Correlation inputs available today:** observables for IPs, hostnames, endpoint domains, users,
process names, file paths and file hashes. Hashes arrive only through native OCSF sources so far.

**Evidence rule for every planned module:** a stored relationship (finding → event, incident → finding,
graph edge, timeline step) must reference at least one existing `event_uid`, and tests must prove it.

## Not planned

| Excluded | Why |
|----------|-----|
| Endpoint security, hardening, AV, EDR, local firewall or process control, local remediation, endpoint configuration auditing | Owned by Aegis |
| Executing containment or response actions (SOAR) | Sentinel-X investigates; it doesn't act on systems |
| Risk-based alerting as the primary alerting model | Correlation creates incidents; entity risk may become a correlation input later |
| Malware sandboxing, phishing analysis, RAG knowledge base, report generation, notification channels | Outside the investigation core; revisit only with a concrete need |
| Neo4j, Qdrant, object storage, Redpanda, agent frameworks, MCP | No measured need; PostgreSQL, Redis and OpenSearch are the platform |
