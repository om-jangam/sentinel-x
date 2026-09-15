# Sentinel-X

**Autonomous AI Security Operations Platform**

Sentinel-X is an enterprise-grade, AI-powered Security Operations platform that ingests security
telemetry, detects threats, and drives investigations through a team of coordinated AI agents —
enriching alerts with threat intelligence, mapping activity to MITRE ATT&CK, analysing malware and
phishing, reconstructing attack timelines, and producing analyst- and executive-ready reports —
while keeping a human in the loop for every consequential action.

> **Status: Build Phase 0 — Platform foundation ✅**
> The architecture ([`docs/`](docs/)) is complete, and the first vertical slice is implemented:
> RS256 JWT auth with rotating refresh tokens and reuse detection, live-resolved RBAC, a
> hash-chained tamper-evident audit log, the modular-monolith core, the React SOC console shell,
> and CI. Next: **Phase 1 — Ingestion & OCSF normalisation** ([roadmap](docs/11-development-roadmap.md)).

---

## Why Sentinel-X exists

The 2025–2026 SOC is defined by three hard numbers: teams see an average of **~2,992 alerts/day of
which ~63% go unaddressed** (Vectra, 2026), **46% of alerts are false positives** (Microsoft/Omdia
State of the SOC 2026), and the global workforce gap sits near **4.8M** with *budget* — not
headcount availability — now the top constraint (ISC2 2025). Meanwhile IBM's Cost of a Data Breach
2025 shows organisations using AI/automation extensively cut breach lifecycle by **80 days** and
saved **~$1.9M** per breach.

Sentinel-X targets that gap directly: automate the triage, enrichment, correlation and investigation
work that burns out analysts, compress mean-time-to-respond, and surface a transparent,
auditable decision trail — the capability the market repeatedly cites as missing.

## What makes it different

- **Agentic investigation with a supervisor** — a LangGraph multi-agent workflow (triage →
  enrichment → correlation → ATT&CK mapping → malware/phishing analysis → timeline → report) with
  durable, resumable execution and **human approval gates on every state-changing action**.
- **Risk-Based Alerting first** — inspired by Splunk RBA, detections contribute *scored risk* to
  entities instead of paging per-signal; incidents fire when accumulated risk crosses a threshold.
  This is the platform's structural answer to alert fatigue.
- **OCSF-native normalisation** — all telemetry is normalised to the Open Cybersecurity Schema
  Framework (v1.6) at ingest, making detections and AI reasoning portable across log sources.
- **Detection-as-code** — Sigma rule corpus, versioned and MITRE-mapped, compiled to the search
  backend via pySigma; temporal/correlation logic runs in a dedicated engine.
- **Bring-your-own-model** — a model gateway routes between local Ollama models (Qwen3 for
  structured extraction/summarisation) and any OpenAI-compatible API for heavy reasoning, with
  prompt-injection guarding on all tool output.
- **Honest scope** — a **modular monolith** with cleanly extractable service seams, not premature
  microservices. Knowing when *not* to distribute is a deliberate architectural decision (see
  [ADR-0002](docs/adr/ADR-0002-modular-monolith-over-microservices.md)).

## Getting started

### Local development (no Docker required)

Prerequisites: Python 3.12, [uv](https://docs.astral.sh/uv/), Node 20.19+.

```bash
cd backend
uv sync
uv run sentinelx generate-keys                 # RS256 signing key → ../.secrets (gitignored)
uv run sentinelx migrate
uv run sentinelx seed --admin-email admin@example.com   # prompts for a password (12+ chars)
uv run uvicorn app.main:create_app --factory --reload   # http://127.0.0.1:8000/docs
```

```bash
cd frontend
npm install
npm run dev                                    # http://localhost:5173 (proxies /api to :8000)
```

Configuration is 12-factor; [`.env.example`](.env.example) documents every variable. Without
`SENTINELX_DATABASE_URL` the API expects PostgreSQL on `localhost:5432`; for a quick try, point it
at SQLite: `SENTINELX_DATABASE_URL=sqlite+aiosqlite:///./dev.db`.

### Docker Compose (`lite` profile)

```bash
make keys
SENTINELX_BOOTSTRAP_ADMIN_PASSWORD='choose-a-long-passphrase' docker compose up --build
# console: http://localhost:8080
```

Runs PostgreSQL, Redis, a one-shot migrate/seed job, the API (production settings, read-only
filesystem, non-root), and the nginx-served console with a strict CSP.

### Quality gates

```bash
make check      # ruff, ruff format, import-linter, mypy --strict, eslint, prettier, tsc, pytest, vitest
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) also runs the backend suite against
PostgreSQL, bandit, pip-audit, npm audit, gitleaks, trivy, the OpenAPI ↔ TypeScript client drift
check, and image builds.

## Documentation

Read in order, or jump to what you need. Start with the executive summary.

| # | Document | Covers (requested deliverable) |
|---|----------|-------------------------------|
| 00 | [Executive Summary](docs/00-executive-summary.md) | Whole-of-Phase-1 TL;DR + final recommendation |
| 01 | [Market Analysis, Feature Gaps & Competitor Comparison](docs/01-market-gap-competitor-analysis.md) | Market analysis, feature-gap analysis, competitor comparison |
| 02 | [Technology Selection](docs/02-technology-selection.md) | Technology selection |
| 03 | [System & Service Architecture](docs/03-system-architecture.md) | System architecture, microservice analysis |
| 04 | [AI Agent Architecture](docs/04-ai-agent-architecture.md) | AI agent architecture |
| 05 | [Database Design](docs/05-database-design.md) | Database design |
| 06 | [API Design](docs/06-api-design.md) | API design |
| 07 | [Security Architecture](docs/07-security-architecture.md) | Security architecture |
| 08 | [Deployment & CI/CD](docs/08-deployment-and-cicd.md) | Deployment architecture, CI/CD design |
| 09 | [Repository & Folder Structure](docs/09-folder-structure.md) | Folder structure |
| 10 | [Module Breakdown](docs/10-module-breakdown.md) | Module breakdown |
| 11 | [Development Roadmap](docs/11-development-roadmap.md) | Development roadmap |
| 12 | [Risks, Trade-offs & Improvements](docs/12-risks-tradeoffs-improvements.md) | Risks & trade-offs, suggested improvements |
| 13 | [Interview Value Analysis](docs/13-interview-value.md) | Interview value analysis |
| — | [Architecture Decision Records](docs/adr/) | ADRs (item 5) |

Implemented module docs: [`identity`](docs/modules/identity.md) ·
[`platform` + `core`](docs/modules/platform.md).

## Technology at a glance

| Layer | Choice |
|-------|--------|
| Backend | Python 3.12, FastAPI (async), SQLAlchemy 2.0 async, Pydantic v2 |
| AI orchestration | LangGraph 1.x (self-hosted, Postgres checkpointer), LangChain 1.x, MCP |
| Models | Ollama (Qwen3) local + OpenAI-compatible API, routed via a model gateway |
| Detection | Sigma + pySigma → OpenSearch, OpenSearch Security Analytics, custom correlation/risk engine |
| Relational store | PostgreSQL 16 |
| Event/log store | OpenSearch 2.x |
| Vector store | Qdrant (BGE-M3 hybrid dense+sparse) |
| Graph store | Neo4j (attack graph + GraphRAG over threat intel) |
| Cache / bus | Redis 7 (cache, rate limits, Redis Streams MVP bus → Redpanda at scale) |
| Pipeline | Vector.dev (OCSF normalisation) + Fluent Bit (edge) |
| Threat intel | STIX 2.1/TAXII, MISP, OpenCTI, abuse.ch, VirusTotal, AbuseIPDB, OTX |
| Frontend | React 19, TypeScript, Vite, Tailwind v4, shadcn/ui, TanStack Query/Router |
| Deploy | Docker Compose (dev/lite) + Kubernetes/Helm (prod) |
| CI/CD | GitHub Actions (ruff, mypy, pytest, trivy, bandit, semgrep, gitleaks, SBOM) |
| Observability | Prometheus, Grafana, OpenTelemetry, structured logging |

Full rationale, alternatives considered, and version notes are in
[Technology Selection](docs/02-technology-selection.md) and the [ADRs](docs/adr/).

## License & intent

Built as a portfolio / learning project demonstrating modern AI, cybersecurity, cloud, backend,
DevOps, and system-design engineering. It studies the architectures of Microsoft Sentinel, Palo Alto
Cortex XSIAM, CrowdStrike Falcon, Google SecOps, Splunk, Elastic Security, SentinelOne and Wazuh to
understand *why* they are built the way they are — and deliberately diverges where a better design
exists for an open, single-team deployment. It does not copy any of them.
