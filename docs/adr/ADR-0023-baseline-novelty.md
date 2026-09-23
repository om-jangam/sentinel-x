# ADR-0023 · "Has this ever happened here?" — counted, cited, and never a detector

**Status:** Accepted · **Date:** 2026-09 · **Builds on:** [ADR-0012](ADR-0012-determinism-first-ai.md),
[ADR-0015](ADR-0015-in-stream-detection.md), [ADR-0017](ADR-0017-evidence-digests-timeline-graph.md)

## Context

The [detection evaluation](../evaluation/README.md) showed a limit of rules as such. SigmaHQ's `wmic`
rules fire only when the launched program looks suspicious, so `wmic process call create notepad.exe`
passes. It is ordinary — unless it is the first time it has ever run here.

Elastic's [higher-order rules](https://www.elastic.co/security-labs/higher-order-detection-rules) and the
NDSS paper [NoDoze](https://www.ndss-symposium.org/ndss-paper/nodoze-combatting-threat-alert-fatigue-with-automated-provenance-triage/)
both rank alerts by how rare their context is. Both also show the trap: a score that mixes rarity into
severity becomes a number nobody can explain, which is what [ADR-0012](ADR-0012-determinism-first-ai.md)
rules out for this project.

## Decision

1. **Count what events state, nothing else.** Three kinds, each stated by a single event:
   `process_pair` (parent → child process name), `host_remote` (host → external address or domain) and
   `remote` (the destination alone). The same rule the entity graph follows.
2. **Every batch teaches the baseline**, not only batches that produced a finding. What is normal here is
   made of ordinary activity; counting only suspicious batches would make everything look rare.
3. **Counts, in event time.** One row per organisation, kind and key (`entity_baselines`): first seen,
   last seen, how many times. Event time, never ingestion time, or an incident built from last week's
   logs would find everything newer than itself.
4. **Novelty is computed on read** (`GET /api/v1/incidents/{id}/novelty`) from the incident's own
   evidence, and reported as plain counts: *"first seen in this incident"*, *"seen 412 times, first on
   2026-08-30"*, or *"never seen outside this incident"*.
5. **It is context, not detection.** Novelty raises no severity, opens no incident, and changes no
   assessment. The console labels it that way, and the API response carries the coverage window so
   "never seen before" can be read against how long the baseline has been watching.

## Consequences

- An analyst can tell an ordinary-looking command that is unprecedented here from one the organisation
  runs daily, with a count they can check rather than a score they must trust.
- **A new deployment sees everything as new.** That is honest rather than misleading, and the coverage
  window is shown next to the verdict. It is also why novelty never feeds severity.
- **No time series, so no sliding window.** "Seen 412 times since 2026-08-30" is a lifetime count; "not
  in the last 30 days" would need a row per sighting or per day. A window can be added later without
  changing what is counted, and the current answer is already the one novelty needs.
- **A redelivered batch counts twice.** The bus is at-least-once, and the baseline adds a batch's
  sightings without recording which events it has already counted. So `observations` is a close count,
  not an exact one. What novelty rests on is unaffected: `first_seen` is the earliest event time seen,
  which a repeat cannot move, and "new here" is a comparison of that against the incident. Exact counts
  would need a row per sighting, which is the same trade as the sliding window above.
- **Counts follow ingestion, so a backfill moves them.** Replaying a month of old logs teaches the
  baseline as if it had been watching then, which is usually what an operator wants and always visible in
  `first_seen`.
- The write path (documents) and the read path (stored evidence digests) derive keys separately; a test
  holds them to the same answer, because disagreement would silently make everything look new.
- Rarity is still not in the timeline or the graph: it is about the organisation's history, not about
  what one event states, and those two views stay strictly evidence-only.
