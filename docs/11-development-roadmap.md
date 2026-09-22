# 11 · Development Roadmap

*Current. Sequenced along the investigation workflow fixed by
[ADR-0014](adr/ADR-0014-lock-scope-security-investigation.md). Each phase ships tested code, updated
docs and a demo that works on the shipped sample telemetry.*

```
0 Foundation ✅ → 1 Ingestion ✅ → 2 Detection ✅ → 3 Correlation & incidents
  → 4 Timeline, graph & workspace → 5 Threat intelligence → 6 AI investigation → 7 Hardening & demo
```

## Phase 0 — Foundation ✅
Identity, RBAC, hash-chained audit, `core`, console shell, CI, Compose.
**Done:** login, RBAC enforced, audit chain verifies.

## Phase 1 — Ingestion & normalisation ✅ (backend)
Source registry and tokens, ingest API with limits, parsers (sshd, Windows Security, native OCSF), OCSF
subset model, immutable OpenSearch storage, indexer worker, event search, CLI, Vector configuration.
**Remaining:** console pages for sources and event search; verification against a live OpenSearch and
the Compose stack.

### Aegis as a source — waiting on decisions
A dedicated Aegis ingest endpoint that maps Aegis alerts and findings to OCSF Detection Finding (2004)
and records agent heartbeats. Decisions needed:
1. token model (one token per fleet with agent IDs pinned to it, or one per agent);
2. contract interpretation (which fields are required per event type, empty values, UTC-only timestamps);
3. where `shared/event_schema.json` lives;
4. whether to keep audit-score history.

Sentinel-X does not depend on this; every later phase works with the existing sources.

## Phase 2 — Detection ✅ (backend)
In-stream evaluation ([ADR-0015](adr/ADR-0015-in-stream-detection.md)): Sigma rules translated from
pySigma into OCSF predicates, platform threshold rules with event-time windows, immutable findings in
PostgreSQL citing deterministic `event_uid`s, findings and rule-catalogue APIs, file hashes and
endpoint domains in the OCSF model. The sample spray, the Windows logon burst and encoded PowerShell,
and the repeated external connections each produce findings that cite their events (12 in total).
**Remaining:** a findings page in the console; more Sigma coverage as Sysmon-style sources arrive.

## Phase 3 — Correlation & incidents ✅ (backend)
- Entity extraction: IP, host, user, process, file, hash, domain.
- Correlation rules: shared entities within a window, failed-then-successful authentication, technique
  chains across events and hosts.
- Incidents with severity, status and an evidence set; each link records the rule and entities that
  justify it.

**Done when** each sample attack story becomes one incident containing only evidence-backed links, and
unrelated background events stay out.

**Built** ([ADR-0016](adr/ADR-0016-entity-correlation-into-incidents.md),
[module doc](modules/correlation.md)): role-aware entity extraction, the `shared-entity` and
`auth-success-after-failures` rules, and incidents whose links cite their rule, entities and events.
Technique chains are an incident assessment, not a linking rule: findings spanning three or more ATT&CK
tactics raise severity and name the links involved. The samples contain **two** stories, not three.
Nothing in the evidence connects web-01's attacker to WS-FIN-07's, so they stay separate. The Zeek
beaconing joins the Windows story because both name `WS-FIN-07`. Background activity stays out.
**Remaining:** nothing specific to correlation; the incidents pages arrived with Phase 4.

## Phase 4 — Attack timeline, entity graph & incident workspace ✅
- Timeline: ordered steps (time, host, user, process, external entity) with supporting events.
- Entity graph in PostgreSQL: attacker IP → host → user → process → file → hash → domain, each edge
  citing events.
- Console workspace: summary, severity, status, timeline, graph, entities, evidence, findings,
  techniques, analyst notes; every change audited.

**Done when** an analyst can open a sample incident and trace every timeline step and edge back to raw
events.

**Built** ([ADR-0017](adr/ADR-0017-evidence-digests-timeline-graph.md),
[module doc](modules/correlation.md#workspace-evidence-timeline-and-graph)):
- **Evidence digests:** correlation records a digest of every event it links; evidence from earlier
  batches is fetched from the event store.
- **Timeline and graph** are computed from the digests. An edge exists only where one event states it.
- **Notes** are append-only and audited.
- **Console:** the incidents list and workspace. Its evidence inspector takes any step, node, edge, link
  or entity to its events, their original records and the stored event.
- **Found while wiring:** `load-demo` indexed demo data without ever running detection or correlation.
  It now takes the same path as live data.

**Remaining:** a findings page and event search in the console; verifying the stored-event hop against a
live OpenSearch.

## Phase 5 — Threat intelligence
Provider adapters for IP, domain and hash reputation and related indicators, cached with source and
retrieval time and attached to incident entities. Results appear in the workspace as context and can
feed correlation. Providers are configurable; the platform works with none configured.

## Phase 6 — AI investigation assistant
As designed in [04](04-ai-investigation-assistant.md): evidence bundle, FACT / INFERENCE / UNCERTAINTY
output, grounding validator, prompt-injection handling, evaluation set.

**Done when** citation validity is 100% on the evaluation set and the incident page degrades cleanly
without a model.

## Phase 7 — Hardening & demo
Live Compose verification, PostgreSQL CI run, end-to-end demo script (load samples → findings → incident
→ workspace → AI analysis), and an operations runbook.

## Definition of done (every phase)
- Unit, integration and negative/security tests; coverage gate met.
- ruff, mypy `--strict`, import-linter contracts and bandit clean.
- Every stored relationship cites existing events, and a test proves it.
- Module doc updated, including mappings and limitations; OpenAPI contract regenerated.
- The demo works on the shipped samples; anything unverified is listed as unverified.
