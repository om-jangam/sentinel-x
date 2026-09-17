# 06 · API Design

*Reference design, July 2026.*

> **Status — partially superseded by [ADR-0014](adr/ADR-0014-lock-scope-security-investigation.md).**
> **Still current:** §2 conventions (RFC 9457 errors, cursor pagination, constrained queries, no raw
> query pass-through). **Not adopted:** the MCP interface and agent endpoints. The endpoint catalogue below
> is a plan; the implemented API is in [architecture.md](architecture.md) §9 and `backend/openapi.json`.

---

## 1. Principles

- **REST + JSON** over HTTPS as the primary contract, described by **OpenAPI 3.1** (FastAPI-generated,
  the single source of truth; the TypeScript client is generated from it).
- **Resource-oriented, versioned** under `/api/v1`. Breaking changes bump to `/api/v2`; additive
  changes stay in v1.
- **Consistent envelopes**: paginated collections, typed errors (RFC 9457 `application/problem+json`),
  correlation IDs on every response.
- **Async streaming** via **WebSocket** (live alerts, agent-step updates) and **SSE** (report/agent
  progress) — the investigation canvas is realtime.
- **Everything authorised**: JWT bearer + RBAC permission check per endpoint; every mutation audited.
- **MCP is a parallel interface** for agents (see [§04](04-ai-investigation-assistant.md)), not a
  replacement for REST.

## 2. Conventions

| Concern | Convention |
|---------|-----------|
| Base path | `/api/v1` |
| Auth | `Authorization: Bearer <access_jwt>`; refresh via httpOnly cookie |
| IDs | UUID v7 in path (`/incidents/{incident_id}`) |
| Pagination | Cursor-based: `?limit=50&cursor=<opaque>` → `{items, next_cursor, total?}` |
| Filtering | Explicit query params + a constrained `?q=` search grammar; never raw backend query pass-through |
| Sorting | `?sort=-opened_at,severity` |
| Errors | RFC 9457: `{type, title, status, detail, instance, correlation_id, errors[]}` |
| Idempotency | `Idempotency-Key` header on POST for at-least-once-safe creates (ingest, actions) |
| Rate limits | Per-principal + per-IP (Redis); `429` with `Retry-After` and `RateLimit-*` headers |
| Correlation | `X-Correlation-ID` echoed; propagated into OpenTelemetry trace |
| Time | RFC 3339 UTC everywhere |

### Standard error example

```json
{
  "type": "https://sentinel-x/errors/insufficient-permission",
  "title": "Insufficient permission",
  "status": 403,
  "detail": "Requires 'incident:resolve' on org 0192...",
  "instance": "/api/v1/incidents/0192.../resolve",
  "correlation_id": "01J...",
  "errors": []
}
```

## 3. Resource map (by module)

### Auth & identity
```
POST   /api/v1/auth/login                 → access + refresh (refresh in httpOnly cookie)
POST   /api/v1/auth/refresh                → rotate refresh, new access
POST   /api/v1/auth/logout                 → revoke refresh (Redis blocklist)
POST   /api/v1/auth/mfa/verify             → TOTP challenge
GET    /api/v1/me                          → current principal, roles, permissions
```

### Users, roles, RBAC (admin)
```
GET    /api/v1/users            POST /api/v1/users
GET    /api/v1/users/{id}       PATCH /api/v1/users/{id}     DELETE .../{id}
GET    /api/v1/roles            POST /api/v1/roles
POST   /api/v1/users/{id}/roles                 → assign
GET    /api/v1/permissions
```

### Ingestion
```
POST   /api/v1/ingest/events           → push OCSF/raw events (Idempotency-Key), bulk supported
GET    /api/v1/ingest/sources          POST /api/v1/ingest/sources   → register a source + parser
GET    /api/v1/ingest/sources/{id}/health
GET    /api/v1/ingest/pipelines        → Vector pipeline status/lag
```
> Note: high-volume telemetry normally enters via Vector → bus, not this endpoint. The HTTP ingest
> path is for agents, integrations, webhooks, and manual submission.

### Events & hunting (OpenSearch-backed)
```
POST   /api/v1/events/search           → constrained query DSL → paginated OCSF events
GET    /api/v1/events/{id}
POST   /api/v1/hunt                     → saved/ad-hoc hunt (Sigma or field query)
GET    /api/v1/hunt/saved   POST /api/v1/hunt/saved
```

### Detection (detection-as-code)
```
GET    /api/v1/rules                    → list w/ lifecycle status, ATT&CK, stats
POST   /api/v1/rules                    → create (draft); validated + pySigma-compiled
GET    /api/v1/rules/{id}   PATCH .../{id}
POST   /api/v1/rules/{id}/test          → run against sample/backtest set
POST   /api/v1/rules/{id}/promote       → draft→test→prod (RBAC + audit)
POST   /api/v1/rules/{id}/toggle        → enable/disable
```

### Risk engine
```
GET    /api/v1/entities                 → risk-ranked entities
GET    /api/v1/entities/{id}            → risk score, timeline, contributing risk_events
GET    /api/v1/entities/{id}/risk       → risk_events (paginated, decay-aware)
POST   /api/v1/risk/thresholds          → configure RBA thresholds (admin)
```

### Alerts, cases, incidents
```
GET    /api/v1/alerts                   → filter by status/severity/entity/rule
GET    /api/v1/cases    POST /api/v1/cases    GET/PATCH .../{id}
GET    /api/v1/incidents                → list (severity/status/verdict filters)
GET    /api/v1/incidents/{id}           → full incident (findings, timeline, techniques, evidence)
PATCH  /api/v1/incidents/{id}           → status/assignee/priority
POST   /api/v1/incidents/{id}/resolve   → resolve w/ verdict (RBAC: incident:resolve)
POST   /api/v1/incidents/{id}/comments
```

### Agentic investigation
```
POST   /api/v1/incidents/{id}/investigate      → dispatch LangGraph run (or auto on open)
GET    /api/v1/incidents/{id}/investigation    → run status, current node, findings so far
GET    /api/v1/agent-runs/{run_id}/steps       → immutable decision trail (audit view)
WS     /api/v1/incidents/{id}/stream           → live agent-step + finding events
GET    /api/v1/incidents/{id}/approvals        → pending HITL gates
POST   /api/v1/approvals/{id}/decide           → approve/reject/modify (resumes graph; audited)
```

### Threat intel
```
POST   /api/v1/intel/enrich             → enrich IOC(s) (cache-first, escalate-only)
GET    /api/v1/iocs      GET /api/v1/iocs/{id}
POST   /api/v1/intel/feeds/sync         → trigger MISP/OpenCTI/abuse.ch sync (admin)
GET    /api/v1/intel/feeds              → feed health, last sync, counts
```

### Malware & phishing analysis
```
POST   /api/v1/analysis/file            → secure upload → static analysis (async job) → job id
POST   /api/v1/analysis/email           → submit .eml/.msg → phishing verdict
POST   /api/v1/analysis/url             → URL analysis
GET    /api/v1/analysis/jobs/{id}       → status + typed verdict
```

### MITRE ATT&CK
```
GET    /api/v1/attack/techniques        GET .../techniques/{tid}
GET    /api/v1/attack/coverage          → Navigator layer JSON (v4.5) for heatmap
GET    /api/v1/incidents/{id}/attack    → techniques mapped for this incident
```

### Timeline & attack graph
```
GET    /api/v1/incidents/{id}/timeline  → ordered steps + narrative
GET    /api/v1/incidents/{id}/graph     → attack graph (nodes/edges) for visualisation
POST   /api/v1/graph/query              → constrained graph query (blast radius, paths)
```

### Knowledge base (RAG)
```
POST   /api/v1/kb/documents             → ingest runbook/report (secure upload → chunk → embed)
GET    /api/v1/kb/documents
POST   /api/v1/kb/search                → hybrid semantic search
```

### Reporting & notifications
```
POST   /api/v1/incidents/{id}/reports   → generate technical/executive report (async)
GET    /api/v1/reports/{id}             GET .../{id}/download
GET    /api/v1/notifications            POST /api/v1/notifications/channels  (email/Slack/webhook)
```

### Platform / observability
```
GET    /api/v1/health        /healthz /readyz          → liveness/readiness
GET    /metrics                                        → Prometheus (internal network only)
GET    /api/v1/audit                                   → audit log (RBAC: audit:read)
GET    /api/v1/config        PATCH /api/v1/config       → platform config (admin, audited)
```

## 4. Realtime channels

| Channel | Transport | Payload |
|---------|-----------|---------|
| Incident stream | WebSocket `/incidents/{id}/stream` | `agent_step`, `finding`, `approval_requested`, `status_changed` |
| Global alert feed | WebSocket `/alerts/stream` | new alert / risk-threshold-crossed events (RBAC-filtered) |
| Long jobs | SSE `/analysis/jobs/{id}/events`, `/reports/{id}/events` | progress, completion |

Auth on WS/SSE via a short-lived ticket (query token exchanged from the bearer JWT) to avoid tokens
in URLs beyond a one-time, short-TTL ticket; channel messages are RBAC- and `org_id`-filtered
server-side.

## 5. Request/response modelling

- **Pydantic v2 schemas** with explicit `*Create`, `*Update`, `*Read` variants — never expose ORM
  models directly (prevents over-posting and leaking internal fields).
- **Enums** for status/severity/verdict so the OpenAPI contract and TS client are strongly typed.
- **Field-level RBAC**: sensitive fields (e.g. raw enrichment, internal notes) are stripped from
  responses when the principal lacks the permission.
- **Response `meta`** on collections: `{count, next_cursor, took_ms}`.

## 6. Versioning, deprecation, and compatibility

- URI versioning (`/api/v1`) for the major line; additive fields are non-breaking.
- Deprecations announced via `Deprecation` + `Sunset` headers and documented in the changelog before
  removal.
- The generated OpenAPI spec is committed and diffed in CI; a breaking change without a version bump
  fails the pipeline.

## 7. Security controls at the API layer

(Cross-referenced with [§07 Security Architecture](07-security-architecture.md).)

- HTTPS/TLS enforced; HSTS; strict CORS allowlist; security headers (CSP, X-Content-Type-Options,
  Referrer-Policy).
- Input validation via Pydantic; output encoding; no raw query pass-through to OpenSearch/Neo4j
  (constrained DSL translated server-side — prevents injection and expensive queries).
- Rate limiting + request-size limits + upload scanning (see file-upload security in §07).
- Every mutating endpoint writes an audit record in the same transaction.
- Idempotency keys on ingest/action endpoints to make retries safe.
