# Sentinel-X architecture

*Current as of Phase 3 (September 2026). This document describes what is **built**. Planned work is in
[11 · Roadmap](11-development-roadmap.md); the product scope is fixed by
[ADR-0014](adr/ADR-0014-lock-scope-security-investigation.md).*

## 1. What Sentinel-X is

**An AI-assisted security investigation platform that correlates heterogeneous security telemetry,
reconstructs attack timelines and entity relationships, enriches evidence with threat intelligence,
and assists analysts in investigating security incidents.**

The question it answers: *what actually happened during a security incident, how are the events
connected, and what evidence should an analyst investigate?*

## 2. Investigation workflow and build status

| Stage | What it does | Status |
|-------|--------------|--------|
| Ingestion | Authenticated, rate-limited intake of security telemetry from registered sources | **Built** (API, worker, source registry) |
| Normalisation | Map source records to a documented OCSF 1.6 subset; reject what can't be mapped, with a reason | **Built** for 3 parsers and 6 event classes ([mappings](modules/ingestion.md#ocsf-mappings)) |
| Storage | Immutable, org-scoped event documents in OpenSearch; constrained search | **Built**; adapter tested against a stubbed client only |
| Detection | Sigma and threshold rules over normalised events → findings that cite their events | **Built**: 4 Sigma and 3 threshold rules, evaluated in-stream ([module doc](modules/detection.md)) |
| Correlation | Group findings and events by shared entities and time → incidents | **Built**: entity extraction by role, 2 correlation rules, severity from named conditions, audited triage ([module doc](modules/correlation.md)) |
| Attack reconstruction | Evidence-linked timeline and entity graph per incident | Not built (Phase 4) |
| Threat intelligence | Reputation and related indicators as investigation context | Not built (Phase 5) |
| AI investigation | Evidence-grounded assistant: FACT / INFERENCE / UNCERTAINTY | Not built (Phase 6); design in [04](04-ai-investigation-assistant.md) |
| Incident workspace | Incident summary, timeline, graph, evidence, notes, status | Not built. The console today covers login, overview, users, roles and the audit log |

## 3. Scope

**In scope:** everything in the workflow above, plus the platform it runs on (identity, RBAC, audit,
operations).

**Out of scope:** endpoint security software, endpoint hardening, antivirus, EDR, local firewall
control, process protection, local remediation, endpoint configuration auditing, and executing
containment or response actions. Those belong to **Aegis**, a separate project.

```
  Aegis (endpoint security)      Linux / Windows logs      network, firewall, cloud, other tools
            │ telemetry                 │ via Vector                    │
            └───────────────────────────┼───────────────────────────────┘
                                        ▼
                     Sentinel-X (security investigation)  ◀── analysts (browser)
```

Sentinel-X works without Aegis. Aegis is not connected yet ([§12](#12-known-limitations)).

## 4. Runtime components

| Component | Role | If absent |
|-----------|------|-----------|
| `api` (FastAPI) | REST API, authentication, ingestion, search, audit | — |
| `worker` (`sentinelx-worker`) | Two Redis Streams consumer groups: `indexer` (events into OpenSearch) and `detection` (rules → findings, then correlation → incidents) | Without Redis the API does all of it in-process |
| PostgreSQL | System of record: identity, RBAC, audit chain, ingest sources, findings, incidents | Dev and tests use SQLite; production refuses SQLite |
| Redis | Event bus (Streams), threshold-rule windows, token blocklist, rate limits | Dev falls back to in-memory implementations; production requires Redis |
| OpenSearch | Normalised event storage and search | Ingestion still authenticates and validates, but events are not stored; search returns `503` |
| `web` (nginx) | Serves the React console; same-origin proxy for `/api` | — |
| `vector` (optional, Compose profile `collector`) | Tails log files and syslog, posts to the ingest API | Sources can post directly |

Docker Compose (`lite` profile) runs all of these on one host. Stores sit on an internal network and are
never published to the host.

## 5. Code structure

A **modular monolith** ([ADR-0002](adr/ADR-0002-modular-monolith-over-microservices.md)). Each module
has `domain → application → infrastructure → interface` layers. `import-linter` enforces four contracts
in CI: domain layers import no frameworks, application layers import no infrastructure, `core` imports
no module, and modules don't import each other.

| Package | Responsibility |
|---------|----------------|
| `app/core` | Config with production guards, UUID v7, RFC 9457 errors, DB sessions, hash-chained audit log, security primitives, event bus, observability |
| `app/modules/identity` | Login, rotating refresh tokens with reuse detection, users, roles, live RBAC |
| `app/modules/platform` | Liveness and readiness, metrics, non-secret config, audit read and verification |
| `app/modules/ingestion` | Source registry, ingest API, indexing service, OpenSearch adapter, event search |
| `app/modules/detection` | Rule loading (Sigma via pySigma, threshold YAML), in-stream evaluation, findings and the rule catalogue |
| `app/modules/correlation` | Entity extraction, correlation rules, incidents with justified links, incident triage |
| `app/ingest_pipeline` | Framework-free OCSF model and source parsers, shared by every ingest path |
| `app/cli.py`, `app/worker.py`, `app/analysis.py` | Operator CLI, the worker entry point, and the detection → correlation wiring (so neither module imports the other) |
| `frontend/src` | React 19 console with an OpenAPI-generated typed client |

## 6. Ingestion data flow

```
producer ──Bearer sxi_…──▶ POST /api/v1/ingest/events
    1. authenticate the source token (SHA-256 hash lookup) or a user with ingest:write + source_id
    2. per-source rate limit · body ≤ 5 MiB · ≤ 1,000 events
    3. parse each record with the source's parser → OCSF model validation
       (bad records are reported by index; they never block good ones)
    4. stamp sx.{org_id, source_id, event_uid, ingested_at, fingerprint}
    5. publish to Redis Streams "events.normalized"          → 202 {accepted, rejected, errors}
worker, group "indexer"   ──▶ OpenSearch bulk `create` into events-ocsf-<category>-write
worker, group "detection" ──▶ Sigma + threshold rules ──▶ findings in PostgreSQL (citing event_uids)
                          ──▶ correlation ──▶ incidents, links (rule + entities + event_uids), entities
```

**Evidence identity.** A document's `_id` is a SHA-256 fingerprint of its org, source and canonical
normalised content, and every write uses `create`. `sx.event_uid` is a UUID v5 of that fingerprint, so
every delivery of the same record carries the same ID and the stored copy never changes
([ADR-0015](adr/ADR-0015-in-stream-detection.md)). Later stages (findings, incidents, timelines, graph edges)
reference events by `sx.event_uid`.

## 7. Security controls

| Area | Control |
|------|---------|
| Users | Argon2id passwords; RS256 access JWTs (10 min) with JWKS and key rotation; opaque refresh tokens in an HttpOnly, Secure, SameSite=Strict cookie, rotated on use, whole family revoked on reuse; login rate limits per account and IP; constant-time failures |
| Authorisation | `resource:action` permissions resolved from the database on every request; checked at the route and again in the use case; guards stop the last admin being removed and machine principals gaining RBAC-management power |
| Sources | Per-source `sxi_` tokens: 256-bit random, stored as SHA-256 only, shown once, rotatable, disableable, every change audited |
| Input | Strict Pydantic schemas (unknown fields rejected on management APIs); OCSF validation with length caps; 5 MiB / 1,000-event caps (nginx allows 6 MiB on the ingest route only); constrained search, no query pass-through |
| Errors | RFC 9457 problem documents; validation errors never echo input |
| Audit | Every state change appends to a per-org SHA-256 hash chain in the same transaction; PostgreSQL trigger blocks `UPDATE`/`DELETE`/`TRUNCATE`; API and CLI verification |
| Deployment | Production refuses to start without a signing key, Redis, OpenSearch, secure cookies, non-SQLite DB, OWASP Argon2 minimums, and a non-wildcard CORS list; strict CSP and security headers; non-root read-only containers |

**Permissions and system roles**

| Permission | viewer | analyst | senior_analyst | incident_responder | detection_engineer | admin | service |
|------------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `platform:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `event:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `finding:read`, `incident:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `source:read`, `rule:read`, `incident:update` | | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `incident:resolve` | | | ✓ | ✓ | | ✓ | |
| `audit:read` | | | ✓ | | | ✓ | |
| `source:manage` | | | | | ✓ | ✓ | |
| `ingest:write` | | | | | | ✓ | ✓ |
| `user:read`, `user:manage`, `role:read`, `role:manage` | | | | | | ✓ | |

## 8. Data stores

| Store | Contents |
|-------|----------|
| PostgreSQL | `orgs`, `users`, `roles`, `permissions`, `user_roles`, `role_permissions`, `refresh_tokens`, `audit_log` (migration 0001); `ingest_sources` (0002); `findings`, `finding_techniques` (0003); `incidents`, `incident_links`, `incident_entities` (0004) |
| Redis | `sx:events:*` streams with the `indexer` and `detection` consumer groups; `sx:det:*` threshold windows (hashed keys); token blocklist entries; rate-limit counters (hashed keys) |
| OpenSearch | Rolling indices `events-ocsf-<category>-NNNNNN` behind write aliases; index template `sentinelx-events` (`dynamic: false`, `unmapped` not indexed); ISM policy rolls over at 20 GB or 1 day and deletes after the retention period (90 days by default) |

## 9. API surface

| Area | Endpoints |
|------|-----------|
| Probes | `GET /healthz`, `GET /readyz` (database, Redis, event store; an unreachable event store is reported but not fatal), `GET /metrics` |
| Auth | `POST /api/v1/auth/{login,refresh,logout}`, `GET /.well-known/jwks.json`, `GET /api/v1/me` |
| Administration | `/api/v1/users`, `/api/v1/roles`, `/api/v1/permissions` |
| Platform | `GET /api/v1/health`, `GET /api/v1/config`, `GET /api/v1/audit`, `GET /api/v1/audit/verify` |
| Ingestion | `POST /api/v1/ingest/events`; `GET /api/v1/ingest/parsers`; `GET, POST /api/v1/ingest/sources`; `GET, PATCH /api/v1/ingest/sources/{id}`; `POST /api/v1/ingest/sources/{id}/rotate-token` |
| Events | `POST /api/v1/events/search`, `GET /api/v1/events/{event_uid}` |
| Detection | `GET /api/v1/findings`, `GET /api/v1/findings/{id}`, `GET /api/v1/detection/rules`, `GET /api/v1/detection/rules/{id}` |
| Incidents | `GET /api/v1/incidents`, `GET /api/v1/incidents/{id}`, `PATCH /api/v1/incidents/{id}` (status only, versioned) |

The OpenAPI document is committed (`backend/openapi.json`); CI fails if it or the generated TypeScript
client drifts from the code.

## 10. Operations

```bash
sentinelx generate-keys | migrate | seed | verify-audit      # platform
sentinelx opensearch-init | load-demo | worker               # ingestion and detection
sentinelx export-openapi                                     # API contract
```

After an upgrade run `migrate` **and then** `seed`: migrations change the schema, while `seed` syncs the
code-defined permissions and system roles. Until it runs, endpoints guarded by new permissions return 403.

## 11. Quality gates (CI)

ruff (lint and format), mypy `--strict`, import-linter contracts, bandit, pip-audit, pytest on PostgreSQL
with an 85% coverage gate (locally the same suite runs on SQLite), OpenAPI and TypeScript client drift
checks, ESLint, Prettier, `tsc`, Vitest, production build, npm audit, gitleaks, Trivy filesystem and
image scans, and API and web image builds.

## 12. Known limitations

- **No reconstruction, threat intelligence or AI yet.** Incidents list their links and entities, but
  there is no ordered timeline or entity graph view yet (Phase 4).
- **Correlation limits** (details in the [module doc](modules/correlation.md#limitations)): incidents are
  never merged; a successful logon that arrives before the failures it completes is not linked; short
  host names can collide across domains; rules and windows are code, not configuration; findings created
  before the Phase 3 upgrade are not back-filled into incidents.
- **Detection limits** (details in the [module doc](modules/detection.md#limitations)): rules ship with
  the code and can't be edited at runtime; Sigma coverage is the mapped logsources and fields only; a
  threshold finding cites the events in its window when it fires, not later ones; a finding can briefly
  cite an event that is still being indexed.
- **OCSF coverage is partial:** a trimmed subset of 6 classes; attributes outside it are dropped when
  passed through, not preserved. See [mappings](modules/ingestion.md#ocsf-mappings).
- **Not verified against live services on the development machine:** OpenSearch, the Vector
  collector, the Docker images and the Compose stack (no Docker available locally). The repository
  has no remote yet, so the CI workflow in §11 has never run; its PostgreSQL-only checks (migrations
  and the append-only audit trigger) are unverified.
- **Aegis is not connected.** There is no Aegis parser or endpoint yet; the proposed contract and
  endpoint are awaiting decisions.
- **Single organisation.** `org_id` is threaded through every table and query, but there is no
  organisation management API.
- **Console:** no pages for sources, event search, findings or incidents yet.
- **Worker glue untested:** the stream → detection → database path and the detection → correlation composition are tested; the worker process's
  signal handling and its running of both consumer loops together are not.

## 13. Documentation map

| Kind | Documents |
|------|-----------|
| Current | This file · [00 Summary](00-executive-summary.md) · [04 AI investigation assistant (design)](04-ai-investigation-assistant.md) · [10 Modules](10-module-breakdown.md) · [11 Roadmap](11-development-roadmap.md) · [module docs](modules/) · [ADRs](adr/) |
| Reference (July 2026 design, status banner at the top) | [02 Technology](02-technology-selection.md) · [03 System](03-system-architecture.md) · [05 Database](05-database-design.md) · [06 API](06-api-design.md) · [07 Security](07-security-architecture.md) · [08 Deployment](08-deployment-and-cicd.md) · [09 Folders](09-folder-structure.md) |
| Archived (superseded framing) | [archive/2026-07-initial-design](archive/2026-07-initial-design/) |
