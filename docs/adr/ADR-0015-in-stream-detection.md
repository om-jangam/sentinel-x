# ADR-0015 · In-stream detection: Sigma via pySigma plus platform threshold rules

**Status:** Accepted · **Date:** 2026-09 · **Refines:** [ADR-0005](ADR-0005-detection-and-risk-engine.md)
(as amended by ADR-0014)

## Context

Phase 2 adds detection: deterministic rules that turn normalised events into **findings** that cite
the events behind them ([ADR-0014](ADR-0014-lock-scope-security-investigation.md), principle 1). Three
facts shape the design:

1. **pySigma converts; it does not evaluate.** It parses Sigma rules and, with a backend, compiles them
   into queries for a search engine. It has no in-process matcher.
2. **Evidence must be real and stable.** A finding may cite only an `event_uid` that exists in the event
   store. Before this decision `event_uid` was a fresh UUID v7 on every delivery. The indexer keeps only
   the first copy of a record (its `_id` is the content fingerprint), so a stream consumer seeing a
   re-sent record would cite an ID the store never kept.
3. **Some attacks are patterns, not single events.** Password spraying, a burst of failed logons and
   repeated connections to one destination are invisible to a single-event rule.

## Decision

1. **Evaluate in-stream.** A `detection` consumer group reads `events.normalized`, independently of the
   indexer, and evaluates every normalised event. Without Redis, the API subscribes the same handler to
   the in-process bus.
2. **Sigma rules are parsed with pySigma and translated once, at load time,** into Sentinel-X
   predicates over OCSF field paths, through an explicit logsource and field mapping. A rule that uses an
   unmapped logsource or field, or an unsupported modifier or value type, is **refused at load** with a
   reason. A rule is never loaded in a state where it silently can't match.
3. **Platform threshold rules** (a small YAML format) cover patterns: a match filter, `group_by` fields,
   an optional distinct-count field, a threshold and a window measured in *event* time. A group fires at
   most once per window. Window state lives in Redis (in memory without Redis).
4. **Findings live in PostgreSQL** and are immutable. Each records the rule and rule version, severity,
   ATT&CK techniques and tactics, entities, the event time range, and the evidence `event_uid`s. A dedupe
   key makes redelivery idempotent.
5. **`event_uid` becomes deterministic:** a UUID v5 of the event's fingerprint. Every delivery of the same
   record carries the same ID, the ID the event store keeps.
6. **Rules are code.** YAML files ship inside the application package, are reviewed in git, and are tested
   against `pipeline/samples`. There is no runtime rule editing in this phase.

## Alternatives considered

- **Compile Sigma to OpenSearch queries and run them on a schedule** (pySigma OpenSearch backend).
  Rejected for now: it needs a live cluster to develop and test, and adds polling latency and gaps at
  schedule boundaries. Exact evidence then has to be recovered from query hits after the fact. It remains
  a good fit for retro-hunting over history.
- **OpenSearch Security Analytics.** Rejected: its findings live outside the system of record and its
  rule lifecycle outside git, and it ties detection to one plugin.
- **A Sigma-to-SQLite tool (e.g. Zircolite).** Rejected: a second event store just for matching.
- **LLM-based detection.** Rejected by ADR-0012 and ADR-0014.

## Consequences

- Detection works, and is fully testable, without OpenSearch.
- Sigma coverage is exactly the mapped logsources and fields, and the detection module doc lists them.
  Unsupported SigmaHQ rules are refused visibly rather than half-applied.
- Detection and indexing are separate consumers, so a finding can briefly cite an event that is still
  being indexed (eventually consistent). A failed index write is retried until it succeeds.
- A threshold finding's evidence is the events in the window when it fires. Later events in the same
  window do not refire it; grouping them into an incident is correlation's job (Phase 3).
- Cost grows with rules × events. That's acceptable at the `lite` scale; `sentinelx_detection_*` metrics
  make it measurable.
- `event_uid` values are no longer time-ordered; ordering always uses event time.
