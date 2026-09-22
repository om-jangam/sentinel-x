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

### `correlation`
Entity extraction by role (host, IP, user, domain, hash as linking entities; process and file as
context); two correlation rules (shared entity within a window, successful logon after brute-force
failures); **incidents** whose every link records the rule, the shared entities and the events on both
sides; severity and title derived from named conditions; versioned, audited status changes. Wired after
detection at the composition root (`app/analysis.py`). Since Phase 4 it also holds what the planned
`reconstruction` and `incidents` modules were for:
- evidence digests;
- the timeline and entity graph, computed from the digests;
- append-only analyst notes.

They share incident storage and transactions, and splitting them would only move code across a boundary.
→ [module doc](modules/correlation.md)

### `threatintel`
Providers behind one interface: a local indicator feed and AlienVault OTX. Background enrichment of
changed incidents' external IPs, domains and hashes, cached per organisation with the source's own verdict
and the retrieval time. A read-only lookup API that never calls a provider.
→ [module doc](modules/threatintel.md)

### `assistant`
The evidence-grounded AI assistant:
- a deterministic evidence bundle, built at the composition root;
- Ollama and OpenAI-compatible adapters;
- a grounding validator for FACT / INFERENCE / UNCERTAINTY statements with citations;
- recorded, audited analyses;
- an evaluation harness.

It never detects, decides or acts. → [module doc](modules/assistant.md)

## Planned (in workflow order)

| Module | Responsibility | Produces | Consumes |
|--------|----------------|----------|----------|

**Entities available to later modules:** each incident's entities with the event_uids they were seen
in, and each link's matched entities. Hashes arrive only through native OCSF sources so far.

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
