# Module · `platform` and the `core` foundation

*Phase 0* — health, config, metrics, the audit read API, and the cross-cutting `core` package every
later module builds on.

## `core` building blocks

| Package | What it provides |
|---------|------------------|
| `core/config.py` | Pydantic Settings (`SENTINELX_*`). **Production refuses to boot** without a signing key, Redis, secure cookies, a non-SQLite database, OWASP argon2 minimums, and a non-wildcard CORS allowlist. |
| `core/ids.py` | Monotonic **UUID v7** generator (RFC 9562) for time-sortable primary keys. |
| `core/errors.py`, `core/http/problems.py` | Framework-free error hierarchy rendered as **RFC 9457** `application/problem+json`. Validation errors never echo request input. |
| `core/db/` | Declarative base with naming conventions, `UTCDateTime` (rejects naive datetimes), async engine and sessions. |
| `core/audit/` | **Tamper-evident audit log**: `entry_hash = SHA-256(prev_hash ‖ canonical(entry))`, one chain per org, written in the caller's transaction. A per-org Postgres advisory lock serialises writers, and `(org_id, chain_index)` is unique. A Postgres trigger rejects `UPDATE`/`DELETE`/`TRUNCATE`. |
| `core/security/` | Permissions and system roles, `Principal`, argon2id hashing, RS256 key ring and JWKS, access tokens, `jti` blocklist and rate limiter (Redis and in-memory). |
| `core/events/` | `EventBus` port with an in-memory bus and a **Redis Streams** transport (consumer groups, ack-after-success, failures stay pending). |
| `core/observability/` | JSON logs with correlation IDs, Prometheus metrics labelled by route template, security headers, opt-in OpenTelemetry. |

Boundaries are enforced by `import-linter` (`backend/pyproject.toml`): domain layers import no
frameworks, application layers import no infrastructure, `core` never imports a module, and modules
are independent of each other.

## `platform` API

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /healthz` | — | Liveness; never touches dependencies |
| `GET /readyz` | — | Readiness: database and Redis; `503` when degraded |
| `GET /metrics` | internal network only | Prometheus exposition |
| `GET /api/v1/health` | `platform:read` | Readiness + version + environment |
| `GET /api/v1/config` | `platform:read` | Non-secret runtime configuration, including the active signing `kid` |
| `GET /api/v1/audit` | `audit:read` | Newest-first, filter by `action` / `resource_type` / `actor_id`, cursor-paginated |
| `GET /api/v1/audit/verify` | `audit:read` | Recomputes the org's chain; reports the first broken index and why |

`sentinelx verify-audit` runs the same verification for every org and exits non-zero on tampering,
ready to schedule as a cron or Kubernetes job.

## Operations

```bash
uv run sentinelx generate-keys          # RS256 key → ../.secrets (use --force to rotate)
uv run sentinelx migrate                # alembic upgrade head
uv run sentinelx seed --admin-email admin@example.com
uv run sentinelx verify-audit
uv run sentinelx export-openapi         # contract consumed by the frontend's typed client
```

`PATCH /api/v1/config` from §06 is deferred until there is runtime-mutable configuration to govern.
