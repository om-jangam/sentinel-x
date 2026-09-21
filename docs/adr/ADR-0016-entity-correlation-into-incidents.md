# ADR-0016 · Entity correlation into incidents, run after detection in the same consumer

**Status:** Accepted · **Date:** 2026-09 · **Builds on:** [ADR-0014](ADR-0014-lock-scope-security-investigation.md),
[ADR-0015](ADR-0015-in-stream-detection.md)

## Context

Phase 3 joins findings into **incidents**. The roadmap's bar: each sample attack story becomes one
incident, every link is evidence-backed, and unrelated background events stay out. Four facts shape the
design:

1. **Findings alone are not enough.** "Failed, then successful authentication" needs the successful logon,
   which is an ordinary event, not a finding. A threshold finding lists only its group-by entities (the
   beacon finding names `10.0.5.17`, not the host), so linking needs the entities in the events.
2. **Field names don't say what an entity is.** In an authentication event `src_endpoint.hostname` is the
   name the client claimed (the sample attacker sends `UNKNOWN-HOST`). In an outbound connection
   `dst_endpoint.hostname` is the remote service. Every host in the DNS sample queries the same internal
   resolver, and `root` exists on every Linux host.
3. **Delivery is at least once and unordered across sources.** A batch can be redelivered after a crash, and
   one story's sources arrive in any order.
4. **Modules are independent** (import-linter). Correlation may not import detection.

## Decision

1. **Correlation runs after detection, in detection's consumer group,** through a sink. Once a batch's
   findings are committed, detection calls the sink with the **stored** findings, including ones a
   redelivered batch had already created, and the batch's documents. It does this for every batch, with or
   without findings. The composition root (`app/analysis.py`) adapts findings into correlation's own
   `FindingSignal`, so neither module imports the other. If correlation fails, the message isn't acked. On
   redelivery detection deduplicates and hands correlation the same findings again. To make that hold for
   threshold rules, a group that already fired may fire again only for the same trigger event, which
   rebuilds the same dedupe key.
2. **Entities are extracted by role.** Seven types: host, IP, user, domain, process, file, hash.
   - Hosts: the device, the target of a logon, and our own side of a connection. Names are normalised to
     the lower-case short name.
   - Users are scoped as `domain\name`, or `name@host` when there is no domain.
   - Internal addresses, process names and file paths are **context only**. They are recorded but never
     join incidents.
   - Every sighting keeps its `event_uid`.
3. **Two correlation rules, and every link records its justification.**
   - **shared-entity:** a finding joins the open incident it shares the most linking entities with, if
     their activity overlaps within 2 h. Otherwise it opens a new incident.
   - **auth-success-after-failures:** a successful logon joins an open incident that holds brute-force
     findings (T1110) from the same source address against the same host, within 1 h after them.
   - Each link stores the rule, a reason, its evidence `event_uid`s and, for every shared entity, the
     events on *both* sides that show it.
4. **Severity and title are derived from the links, never set.** Severity starts at the most severe
   finding. Two named conditions each raise it to High: credential compromise, and three or more
   ATT&CK tactics. Together they raise it to Critical. The incident's assessment lists each condition with
   the links that satisfy it.
5. **Idempotent and serialised.** A finding belongs to at most one incident (unique constraint), and an
   event joins an incident at most once. On PostgreSQL correlation holds a per-organisation advisory lock
   for its transaction, taken before the audit chain's lock, so concurrent workers can't open two
   incidents for one story.
6. **Analysts own the status; correlation owns the contents.**
   - Statuses are `new`, `investigating` and `closed`; closing requires a resolution (true positive,
     benign positive or false positive).
   - Every status change uses a version check and is audited.
   - Permissions: `incident:read`, `incident:update`, and `incident:resolve` for closing and reopening.
   - Opening and extending incidents is audited with the system as the actor.

## Consequences

- **Outcome on the samples:** the three sample files become two incidents: web-01 (SSH spray, then a
  successful login) and WS-FIN-07 (logon burst, RDP logon, encoded PowerShell, discovery, then beaconing).
  The Windows and Zeek records join because both name `WS-FIN-07`. Alice's logins, the morning console
  logon and the SMB session stay out.
- **Delivery order doesn't matter.** Correlation is idempotent under redelivery, and the result is the
  same under one-event-per-batch delivery and with the sources in reverse order. Tests prove all of this.
- **Correlation latency adds to detection latency.** The two share one consumer.
- **Limitations (documented):**
  - A finding that matches two open incidents joins one; incidents are never merged.
  - A logon that arrives before the failures it completes is not linked.
  - Short host names can collide across domains; the link cites the events on both sides, so an analyst
    can check.
  - Per-entity sighting lists are capped at 20 events.
- **Timeline, graph and workspace are next.** Phase 4 renders timelines and graphs from these links and
  entities, and adds the workspace. Correlation rules are code, not configuration, until there is a
  second deployment that needs different ones.
