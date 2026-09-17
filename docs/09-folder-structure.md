# 09 · Repository & Folder Structure

*Reference design, July 2026.*

> **Status — partially current.** The per-module layering in §2 is how the code is built and enforced.
> Directories that don't exist: `backend/app/agents`, `detections/`, `deploy/`, `observability/`,
> `scripts/`, top-level `tests/`. The worker is `app/worker.py` (Redis Streams), not ARQ. Actual layout:
> [architecture.md](architecture.md) §5.

A single monorepo. Layout expresses the **modular monolith + Clean Architecture** decision: each
module is a self-contained package with the same internal `domain / application / infrastructure /
interface` layering, so module boundaries are visible in the tree and enforceable in CI.

---

## 1. Top level

```
Sentinel-X/
├── README.md
├── docs/                     # Phase 1 analysis (this set) + ongoing ADRs & module docs
│   ├── architecture.md, 00-executive-summary.md ... 11-development-roadmap.md, modules/, archive/
│   └── adr/
├── backend/                  # Python: API, modules, workers, agents
├── frontend/                 # React + TypeScript SOC console
├── pipeline/                 # Vector configs (VRL → OCSF), Fluent Bit configs
├── detections/               # Detection-as-code: Sigma rules, correlation, mappings
├── deploy/                   # Docker Compose, Helm charts, Kustomize overlays
├── observability/            # Prometheus rules, Grafana dashboards, OTel config
├── scripts/                  # dev bootstrap, seeding, demo data
├── tests/                    # cross-cutting e2e / smoke (unit+integration live per-module)
├── .github/workflows/        # CI/CD (see §08)
├── Makefile                  # make up / seed / demo / test / lint
├── docker-compose.yml        # + docker-compose.override.yml, profiles
├── pyproject.toml            # uv-managed, ruff/mypy/pytest config
└── .env.example
```

## 2. Backend

```
backend/
├── app/
│   ├── main.py                     # FastAPI app factory, router mounting, middleware
│   ├── worker.py                   # ARQ worker entrypoint
│   ├── agent_runtime.py            # LangGraph runtime entrypoint
│   ├── mcp_server.py               # internal MCP server entrypoint
│   │
│   ├── core/                       # cross-cutting, framework-level
│   │   ├── config.py               # Pydantic Settings (12-factor)
│   │   ├── security/               # JWT, password hashing, RBAC policy engine
│   │   ├── db/                     # engine/session factories (PG, OpenSearch, Qdrant, Neo4j, Redis)
│   │   ├── audit/                  # hash-chained audit writer
│   │   ├── events/                 # bus abstraction (Redis Streams / Redpanda), topics
│   │   ├── observability/          # OTel setup, logging, metrics
│   │   ├── errors.py               # RFC 9457 problem responses
│   │   └── pagination.py
│   │
│   ├── modules/                    # ← the bounded modules; each identical shape
│   │   ├── identity/               # users, auth, roles, RBAC
│   │   │   ├── domain/             #   entities, value objects, ports (Protocols)
│   │   │   ├── application/        #   use-cases / services
│   │   │   ├── infrastructure/     #   repositories, external clients (impl of ports)
│   │   │   ├── interface/          #   FastAPI router, schemas (Create/Update/Read)
│   │   │   └── tests/
│   │   ├── ingestion/              # source registry, OCSF normalisation, bus consumer
│   │   ├── detection/              # Sigma compile (pySigma), rule lifecycle, evaluation
│   │   ├── correlation/            # temporal/multi-event correlation engine
│   │   ├── risk/                   # Risk-Based Alerting engine, thresholds, decay
│   │   ├── alerting/               # alerts, notifications, channels
│   │   ├── cases/                  # cases, incidents, findings, comments, approvals
│   │   ├── investigation/          # agent orchestration glue (dispatch, HITL, audit view)
│   │   ├── threatintel/            # STIX/TAXII, MISP, OpenCTI, feeds, IOC catalogue, enrichers
│   │   ├── mitre/                  # ATT&CK v18 ingest, mapping, Navigator layer export
│   │   ├── analysis/               # malware & phishing static analysis (calls analysis-worker)
│   │   ├── timeline/               # attack timeline + attack graph (Neo4j)
│   │   ├── knowledge/              # RAG KB: ingest, chunk, embed, hybrid search (Qdrant)
│   │   ├── reporting/              # technical/executive report generation
│   │   └── platform/               # health, config, audit read API, metrics
│   │
│   ├── agents/                     # LangGraph agent definitions (the AI subsystem)
│   │   ├── graph.py                # supervisor graph assembly, edges, checkpointer
│   │   ├── state.py                # InvestigationState (typed) + reducers
│   │   ├── supervisor.py
│   │   ├── specialists/            # triage, enrichment, correlation, attack, malware,
│   │   │                           #   phishing, timeline, response, report
│   │   ├── tools/                  # MCP tool implementations (thin wrappers over modules)
│   │   ├── gateway/                # model gateway: routing, guarding, PII redaction, budgets
│   │   └── eval/                   # golden-set corpus + scorers (CI gate)
│   │
│   ├── ingest_pipeline/            # Python-side OCSF mappers/validators shared with Vector
│   └── migrations/                 # Alembic
│
├── pyproject.toml
└── Dockerfile.{api,worker,agent,analysis,mcp}
```

### Why this shape

- **Boundaries are physical.** `import-linter` contracts forbid: (a) any module importing another
  module's `domain`/`infrastructure` internals (only its `application` port façade or via events),
  (b) `domain` importing frameworks, (c) `application` importing `infrastructure` concretes. Violations
  fail CI — this is what keeps the monolith modular and the seams extractable.
- **`agents/` is separate from `modules/`** because the agent runtime is the first candidate for
  service extraction ([§03](03-system-architecture.md) §7); it depends on modules only through MCP
  tools and events, never their internals.
- **Same four-layer shape in every module** means a new module is muscle-memory, and reviewers always
  know where a thing lives.

## 3. Frontend

```
frontend/
├── index.html
├── vite.config.ts
├── src/
│   ├── main.tsx
│   ├── app/                      # router (TanStack Router), providers (Query, theme, auth)
│   ├── api/                      # generated client from OpenAPI + typed hooks (TanStack Query)
│   ├── components/ui/            # shadcn/ui primitives
│   ├── components/               # shared composite components (tables, charts, graph viz)
│   ├── features/                 # feature-sliced, mirrors backend modules
│   │   ├── auth/  dashboard/  alerts/  incidents/  investigation/
│   │   ├── detections/  threatintel/  attack/  timeline/  analysis/
│   │   ├── knowledge/  reporting/  admin/
│   ├── features/investigation/   #   investigation canvas: live agent steps, approval gates (WS)
│   ├── lib/                      # utils, formatters, auth token handling
│   └── styles/                   # Tailwind v4 @theme
├── package.json
└── Dockerfile
```

Feature-sliced folders mirror backend modules so a full vertical (API → UI) is easy to reason about
and to build phase-by-phase.

## 4. Detections (detection-as-code)

```
detections/
├── sigma/                    # Sigma rules (vendored SigmaHQ subset + custom), org-authored
│   ├── windows/ linux/ network/ cloud/ web/
├── correlation/              # correlation rule definitions (own engine format)
├── pipelines/                # pySigma processing pipelines (OCSF field mappings)
├── mappings/                 # rule ↔ ATT&CK technique maps
├── risk/                     # risk-scoring weights per rule
└── tests/                    # rule unit tests (sample events → expected match)
```

Rules move through draft→test→prod via the API ([§06](06-api-design.md)); this directory is the
version-controlled source of truth, synced into the `detection_rules` table's lifecycle metadata.

## 5. Deploy, pipeline, observability, scripts

```
deploy/
├── compose/                  # profiles: lite, dev, full
├── helm/sentinel-x/          # umbrella chart + subcharts (api, worker, agent, stores)
└── kustomize/                # dev / staging / prod overlays
pipeline/
├── vector/                   # vector.toml/.yaml: sources → VRL transforms (OCSF) → sinks
└── fluent-bit/               # edge collector configs
observability/
├── prometheus/               # scrape configs, alert rules, SLOs
├── grafana/                  # dashboards (ingest lag, MTTR, agent success, LLM cost)
└── otel/                     # collector pipeline
scripts/
├── bootstrap.sh  seed.py  load_demo_telemetry.py  verify_audit_chain.py
```

## 6. Conventions

- **Tooling**: `uv` for Python deps/lockfile; `ruff` (lint+format), `mypy --strict`, `pytest`;
  `eslint`/`prettier`/`vitest`/`tsc` for frontend.
- **Tests co-located** per module (`modules/<m>/tests/`); cross-cutting e2e in top-level `tests/`.
- **Docs follow code**: each module gets a `docs/modules/<m>.md` as it's built (design + API +
  integration notes), keeping documentation current per the phase workflow.
- **No secrets, ever**, in the tree; `.env.example` is the contract, `gitleaks` is the guard.
