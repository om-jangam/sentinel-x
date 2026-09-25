# Sentinel-X

**AI-assisted security investigation and attack-chain reconstruction**

Sentinel-X correlates heterogeneous security telemetry, reconstructs attack timelines and entity
relationships, enriches evidence with threat intelligence, and assists analysts in investigating security
incidents.

It is built to answer one question: *what actually happened during a security incident, how are the
events connected, and what evidence should an analyst investigate?*

```
security data → ingestion → normalisation → detection → correlation
             → timeline + evidence graph → threat intelligence → AI investigation → incident workspace
```

## Status

| Stage | State |
|-------|-------|
| Platform: identity, RBAC, hash-chained audit trail, console shell, CI | ✅ Built |
| Ingestion: per-source tokens, limits, validation, audited source management | ✅ Built |
| Ingest from an existing Splunk deployment (pull, on demand) | ✅ Built ([how](docs/modules/ingestion.md#pulling-from-splunk)) |
| "Has this ever happened here?": counted novelty, as context not detection | ✅ Built ([how](docs/modules/correlation.md#how-unusual-is-this)) |
| Hand over an incident as a Markdown report, every line citing its events | ✅ Built ([how](docs/modules/correlation.md#exports)) |
| Export an incident as an ATT&CK Navigator layer or STIX Attack Flow | ✅ Built ([how](docs/modules/correlation.md#exports)) |
| Detection: own rules plus 162 attributed SigmaHQ community rules | ✅ Built ([notice](backend/app/modules/detection/rules/sigmahq/NOTICE.md)) |
| Read Windows NTLM auditing, so password spraying is visible from the domain controller | ✅ Built ([how](docs/modules/ingestion.md)) |
| Detection measured on public attack recordings (splunk/attack_data) | ✅ Built ([baseline](docs/evaluation/detection-baseline.md)) |
| Normalisation: OCSF 1.6 subset for OpenSSH auth logs, Windows Security events, Sysmon (13 event types), native OCSF | ✅ Built ([mappings](docs/modules/ingestion.md#ocsf-mappings)) |
| Storage and search: immutable events in OpenSearch, constrained search API | ✅ Built (not yet run against a live cluster) |
| Detection: Sigma and threshold rules → findings that cite their events | ✅ Built ([rules and coverage](docs/modules/detection.md)) |
| Correlation: findings and events → incidents, every link justified by shared entities and cited events | ✅ Built ([rules and entities](docs/modules/correlation.md)) |
| Incident workspace: attack timeline, entity graph, evidence inspector, audited notes and status | ✅ Built ([ADR-0017](docs/adr/ADR-0017-evidence-digests-timeline-graph.md)) |
| Threat intelligence: local indicator feed and AlienVault OTX, background enrichment, cached with source and time | ✅ Built ([module doc](docs/modules/threatintel.md)) |
| AI investigation assistant: evidence bundle, FACT / INFERENCE / UNCERTAINTY with validated citations, local model by default | ✅ Built ([module doc](docs/modules/assistant.md)) |
| Hardening: Compose and PostgreSQL verified live, bus retries with dead-lettering, end-to-end demo, runbook | ✅ Done ([runbook](docs/runbook.md)) |

Known limitations: [architecture.md §12](docs/architecture.md#12-known-limitations).

## Principles

- **Evidence first:** every finding, relationship and timeline step cites stored events, and stored
  events are immutable.
- **Detection is deterministic:** Sigma and rules find things; correlation connects them.
- **AI assists, never invents:** analysis is labelled FACT, INFERENCE or UNCERTAINTY, and statements
  without valid citations are rejected ([design](docs/04-ai-investigation-assistant.md)).
- **Source-agnostic:** Linux, Windows, network, firewall, cloud and other security tools. Aegis is one
  possible source, and Sentinel-X works without it.
- **Not endpoint security:** no agent, EDR, antivirus, hardening, local firewall or remediation, and no
  execution of response actions. That is [Aegis](https://github.com/om-jangam/aegis)'s job.
  ([ADR-0014](docs/adr/ADR-0014-lock-scope-security-investigation.md))

## Getting started

### Local development (no Docker)

Prerequisites: Python 3.12, [uv](https://docs.astral.sh/uv/), Node 20.19+.

```bash
cd backend
uv sync
uv run sentinelx generate-keys                          # RS256 signing key → ../.secrets (gitignored)
export SENTINELX_DATABASE_URL=sqlite+aiosqlite:///./dev.db
uv run sentinelx migrate
uv run sentinelx seed --admin-email admin@example.com   # prompts for a password (12+ characters)
uv run uvicorn app.main:create_app --factory --reload   # http://127.0.0.1:8000/docs
```

```bash
cd frontend && npm install && npm run dev              # http://localhost:5173 (proxies /api to :8000)
```

**Upgrading:** run `sentinelx migrate` and then `sentinelx seed`. Permissions and system roles are defined
in code and only `seed` syncs them, so new features stay forbidden (403) until it runs. Docker Compose
runs both on every start.

Every setting is documented in [`.env.example`](.env.example). Without `SENTINELX_OPENSEARCH_URL`,
ingestion still authenticates and validates events but doesn't store them, and event search returns 503.

To see the pipeline end to end, run `uv run sentinelx load-demo` after seeding. It loads the sample attack
stories through detection and correlation, producing 12 findings and 2 incidents. Open **Incidents** in
the console to explore each timeline and graph. It needs no OpenSearch; the event store only adds the raw
stored event. Set `SENTINELX_TI_LOCAL_FEED=../pipeline/intel/demo_indicators.csv` (a fictional feed) to
see threat intel on the demo incidents.

### Docker Compose

```bash
make keys
SENTINELX_BOOTSTRAP_ADMIN_PASSWORD='choose-a-long-passphrase' docker compose up --build
# console: http://localhost:8080
```

Runs PostgreSQL, Redis, OpenSearch, a one-shot migrate/seed job, the API, the worker (indexing, detection and correlation) and the
nginx-served console. To load the demo attack telemetry, mount the samples into a one-off container:
`docker compose run --rm -v "$PWD/pipeline/samples:/samples:ro" migrate sentinelx load-demo --samples /samples`.
The stack has been run end to end. Then drive the whole workflow over HTTP:
`SENTINELX_DEMO_PASSWORD=… uv run sentinelx demo --api-url http://localhost:8080 --analyse`
([runbook](docs/runbook.md)).

### Sending events

```bash
# as an admin: register a source (the token is shown once)
curl -X POST http://127.0.0.1:8000/api/v1/ingest/sources -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'Content-Type: application/json' -d '{"name": "web-01-auth", "parser": "linux_auth"}'

# as the source
curl -X POST http://127.0.0.1:8000/api/v1/ingest/events -H "Authorization: Bearer sxi_…" \
     -H 'Content-Type: application/json' \
     -d '[{"message": "2026-09-15T09:14:19Z web-01 sshd[2231]: Accepted password for deploy from 203.0.113.45 port 41958 ssh2"}]'
# → 202 {"accepted": 1, "rejected": 0, "errors": []}
```

Limits, error codes and parser mappings: [ingestion module doc](docs/modules/ingestion.md).

### Quality gates

```bash
make check      # ruff, import-linter, mypy --strict, eslint, prettier, tsc, pytest, vitest
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) additionally runs the backend suite on
PostgreSQL, bandit, pip-audit, npm audit, gitleaks, Trivy, OpenAPI and client drift checks, and image
builds.

## Documentation

| Start here | |
|---|---|
| [Architecture (as built)](docs/architecture.md) | Components, data flow, security controls, stores, API, limitations |
| [Operations runbook](docs/runbook.md) | Start, upgrade, monitor, failure handling, backup, key rotation |
| [Executive summary](docs/00-executive-summary.md) | Purpose, principles, scope |
| [Modules](docs/10-module-breakdown.md) · [Roadmap](docs/11-development-roadmap.md) | Built and planned modules; phases |
| [AI investigation assistant](docs/04-ai-investigation-assistant.md) | Design of the evidence-grounded assistant |
| Module docs: [identity](docs/modules/identity.md) · [platform + core](docs/modules/platform.md) · [ingestion](docs/modules/ingestion.md) · [detection](docs/modules/detection.md) · [correlation](docs/modules/correlation.md) · [threat intel](docs/modules/threatintel.md) · [assistant](docs/modules/assistant.md) | How each built module works |
| [Architecture decision records](docs/adr/) | Why things are the way they are |
| Reference design (July 2026): [02](docs/02-technology-selection.md) · [03](docs/03-system-architecture.md) · [05](docs/05-database-design.md) · [06](docs/06-api-design.md) · [07](docs/07-security-architecture.md) · [08](docs/08-deployment-and-cicd.md) · [09](docs/09-folder-structure.md) | Each carries a status banner saying what is current |
| [Archive](docs/archive/2026-07-initial-design/) | The superseded "autonomous SOC" framing |

## Technology

| Layer | In use |
|-------|--------|
| Backend | Python 3.12, FastAPI, SQLAlchemy 2 (async), Pydantic 2, Alembic |
| Stores | PostgreSQL 16 (system of record), Redis 7 (bus, rate limits, token revocation), OpenSearch 2 (events) |
| Collection | HTTP ingest API; Vector configuration for log files and syslog |
| Detection | Sigma rules parsed with pySigma and evaluated in-stream; platform threshold rules ([ADR-0015](docs/adr/ADR-0015-in-stream-detection.md)) |
| Frontend | React 19, TypeScript, Vite, Tailwind 4, TanStack Router and Query |
| Delivery | Docker Compose, GitHub Actions |

Threat intelligence uses a local indicator feed and, with a key, AlienVault OTX
([ADR-0018](docs/adr/ADR-0018-threat-intelligence-providers.md)). The AI assistant uses a local Ollama model by default, or
any OpenAI-compatible endpoint ([ADR-0019](docs/adr/ADR-0019-ai-assistant-local-model-grounding-validator.md)).

## Intent

A portfolio and learning project in security engineering, backend architecture and applied AI. It aims
to be complete, understandable, secure, tested and demonstrable rather than broad.
