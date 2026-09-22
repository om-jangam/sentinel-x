# ADR-0017 · Timeline and entity graph derived from evidence digests in PostgreSQL

**Status:** Accepted · **Date:** 2026-09 · **Builds on:** [ADR-0014](ADR-0014-lock-scope-security-investigation.md),
[ADR-0016](ADR-0016-entity-correlation-into-incidents.md)

## Context

Phase 4 lets an analyst open an incident and trace every timeline step and graph edge back to raw events.
Four facts shape the design:

1. **Timelines and graphs need what the events say**: times, hosts, users, processes, command lines, the
   other side of a connection. Incidents store event IDs, not event content.
2. **The event store is not always there.** OpenSearch is optional in development and can be unreachable
   in production. The workspace should still explain an incident, and every page render should not have
   to query the event store.
3. **Evidence spans batches.** A threshold finding's first events arrived in earlier bus messages than the
   one that fired it. The batch alone doesn't hold them.
4. **ADR-0014 rejected a graph database.** A new store needs a demonstrated need.

## Decision

1. **Evidence digests.** When correlation links an event into an incident, it stores a digest of it in
   PostgreSQL (`incident_events`), one per incident and event. A digest holds:
   - the time, OCSF class, activity and outcome;
   - the entities keyed by the role they play (`host`, `user`, `src_ip`, `process`, `parent_process`,
     `domain`, …);
   - a few details: command line, ports, logon type;
   - a 2 KiB excerpt of the original record.

   Digests are written once and never updated. The event store stays the source of truth, and each digest
   carries its `event_uid`.
2. **Out-of-batch evidence is fetched from the event store** through an optional, organisation-scoped
   `get_many`, at most 100 IDs per call. If the store is missing or fails, correlation still links the
   finding. The events it couldn't read are reported as **unresolved** rather than blocking the pipeline.
3. **Timeline and graph are computed on read** from the digests and links, by pure functions. Nothing
   derived is stored, so they can't drift from the evidence.
   - **Timeline:** evidence events in time order. Consecutive events with the same action, host, remote
     side and process fold into one step unless 10 minutes apart. Each step lists its `event_uid`s and the
     findings and correlation links that cite them.
   - **Graph:** an edge exists only where **one event** states it, such as "this address failed to log on
     to this host" or "this process spawned that one". The relation vocabulary is fixed per OCSF class.
     Each edge lists the events that state it. Nothing is inferred across events.
4. **The graph lives in PostgreSQL.** Incidents have tens of nodes, not millions. A per-incident query and
   an in-memory build are enough, so no graph database is added.
5. **Analyst notes are append-only.** They have no edit or delete API, and each one is audited
   (`incident.note_added`, with a SHA-256 of the text). The author's email is kept as it was when written.
6. **The console workspace** shows:
   - a summary with the assessment;
   - status actions (versioned, permission-aware);
   - a timeline, a graph drawn as layered SVG with no graph library, findings and links, entities and
     notes;
   - an **evidence inspector**: any step, node, edge, link or entity selects its events, shown as digests
     and raw excerpts, and the stored event can be loaded from the event store.

## Consequences

- An analyst can go from any step or edge to the events and their original records. With OpenSearch
  running, they can reach the stored event itself. Tests check that the timeline shows exactly the cited
  events, and that every edge and node cites only incident evidence.
- Digests duplicate a little evidence in PostgreSQL: roughly 1–3 KiB per incident event, only for events in
  incidents.
- **Incidents from before this phase have no digests.** Their evidence shows as unresolved and their
  timeline is empty until a newer link adds digests.
- An event linked while the event store was unreachable stays unresolved. Nothing retries it yet.
- While wiring this, `load-demo` turned out to index events without ever running detection or correlation.
  It now publishes to the Redis bus when configured, or runs detection and correlation in-process.
