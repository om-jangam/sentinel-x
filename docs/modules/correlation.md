# Module · `correlation`

*Phases 3–4*: joins findings, and the events that complete them, into **incidents**, and serves the
workspace that reconstructs them as a timeline and an entity graph. Every link records the
rule that made it, the entities that justify it and the events that show them. Design decision:
[ADR-0016](../adr/ADR-0016-entity-correlation-into-incidents.md).

## Where it runs

Correlation runs straight after detection, on the same batch and in the same consumer group, through a
sink wired at the composition root (`app/analysis.py`). Detection hands over the stored findings and the
batch's events on **every** batch, including batches with no findings: a successful logon usually arrives
after the failures it completes. If correlation fails, the bus redelivers. Detection deduplicates its
findings and passes the same ones again. Correlation is idempotent, so the retry changes nothing that
already succeeded.

## Entities

Extracted from each event by role (`domain/entities.py`). Each sighting keeps the `event_uid` it came
from.

| Type | Taken from | Joins incidents? |
|------|-----------|------------------|
| `host` | `device.hostname`; the target of a logon (`dst_endpoint.hostname` in class 3002); our own side of a connection (an endpoint with an internal or no address, in classes 4001–4003). Normalised to the lower-case short name: `WS-FIN-07.acme.example` → `ws-fin-07` | yes |
| `ip` | `src_endpoint.ip`, `dst_endpoint.ip`, `device.ip` | only external addresses (not RFC 1918, CGNAT, loopback, link-local, ULA or multicast; documentation ranges count as external) |
| `user` | `user.*`, `actor.user.*`, scoped as `domain\name`, or `name@host` without a domain; built-in and machine (`$`) accounts dropped | yes |
| `domain` | `query.hostname`, `*_endpoint.domain`, and the remote side's hostname in a connection | yes |
| `hash` | `*.file.hashes.value` | yes |
| `process`, `file` | process names and file paths | no: context only |

Deliberately **not** used: the client-claimed workstation name in an authentication event (attackers
choose it; the sample sends `UNKNOWN-HOST`) and placeholders such as `-` or `localhost`.

## Correlation rules

| Rule | A link is made when | Window |
|------|--------------------|--------|
| `opened` | A finding shares no linking entity with any open incident. It opens a new incident | — |
| `shared-entity` | A finding shares at least one linking entity with an open incident whose activity overlaps it. With several candidates, the one sharing the most entities wins, then the most recent | 2 h either side of the incident's first/last seen |
| `auth-success-after-failures` | A successful logon (class 3002, activity 1, status success) comes from a source address that appears in an open incident's brute-force findings (technique T1110.*), and targets a host in that incident | within 1 h after those findings |

Each link stores:
- `evidence`: the event_uids it brings in; for a finding, exactly the finding's evidence;
- `matched`: each shared entity, with the event_uids showing it on the incident side and on the new side;
- `reason`: a sentence saying which rule linked it and why;
- `detail`: a snapshot of the finding's rule, severity and ATT&CK.

A finding belongs to at most one incident, and an event joins a given incident at most once. Both are
enforced by unique constraints.

## Incidents

| Field | Derived how |
|-------|-------------|
| `severity` | The most severe finding. Raised to High by `credential-compromise` (an `auth-success-after-failures` link) or by `multi-stage` (findings span ≥ 3 ATT&CK tactics). Raised to Critical when both hold. `assessment` lists each condition applied, with its links |
| `title` | "Successful logon after repeated failures from *IP*, then *tactics* on *hosts*" when compromised, "Multi-stage activity (…)" for ≥ 3 tactics, otherwise the most severe finding's title, plus "on *hosts*" |
| `techniques`, `tactics`, `finding_count`, `event_count`, `first_seen`, `last_seen` | From the links |
| `status`, `resolution` | Set by analysts: `new` → `investigating` → `closed` (with `true_positive`, `benign_positive` or `false_positive`); closed incidents can be reopened as `investigating`; never back to `new` |

Closed incidents never take new links. New activity opens a new incident.

## On the sample stories

| Incident | Links | Severity |
|----------|-------|----------|
| *Successful logon after repeated failures from 203.0.113.45 on web-01* | 6 invalid-user findings + the spray (`shared-entity` on `host:web-01`, `ip:203.0.113.45`), then the `Accepted password for deploy` event (`auth-success-after-failures`) | High |
| *Successful logon after repeated failures from 198.51.100.23, then execution, defense evasion, discovery, command and control on ws-fin-07* | The logon burst opens it; the RDP logon completes it; encoded PowerShell, `whoami` and `net group` join on `host:ws-fin-07` and `user:acme\jsmith`; the Zeek beacon joins on `host:ws-fin-07` | Critical |

Background stays out: alice's logins, the morning console logon and the SMB session to `FS-01`.
`app/tests/test_correlation_pipeline.py` proves this. It also checks every link and entity cites events
already in the incident, redelivery changes nothing, and the result holds under one-event-per-batch
delivery and with the sources in reverse order. `app/tests/test_correlation_rules.py` covers each rule's
boundaries.

## Workspace: evidence, timeline and graph

*Phase 4* ([ADR-0017](../adr/ADR-0017-evidence-digests-timeline-graph.md)).

**Evidence digests.** When correlation links an event, it records a digest in `incident_events`. The digest
holds:
- the event time, OCSF class, activity and outcome, plus an action name ("Failed logon", "Process started",
  "Network connection", …);
- every entity, keyed by the role it plays (`host`, `dst_host`, `user`, `src_ip`, `dst_ip`, `process`,
  `parent_process`, `file`, `hash`, `domain`, `answer`);
- the command line (≤ 1 KiB), ports and logon type;
- an excerpt of the original record (≤ 2 KiB).

Digests are written once. If a finding cites events from an earlier batch, correlation fetches them from the
event store (`get_many`, organisation-scoped, ≤ 100 per call). Events it cannot read are reported as
`unresolved_events`; they are never guessed.

**Timeline** (`domain/timeline.py`): the evidence in time order. Consecutive events with the same action,
outcome, host, remote side, process and parent fold into one step, unless more than 10 minutes apart. Each
step lists its `event_uid`s, and the findings and correlation links citing them.

**Graph** (`domain/graph.py`): an edge exists only where a single event states it.

| Event | Edges |
|-------|-------|
| Logon, success or failure (3002, activity 1) | source IP → host (`logon` / `failed_logon`); host → user (`logon_as` / `failed_logon_as`) |
| Process activity (1007) | host → user (`ran_as`); user → process (`started`), or host → process with no user; parent → process (`spawned`); process → file (`image`); file → hash (`hash`) |
| Network / HTTP (4001, 4002) | host → remote (`connected_to`, with ports); the remote is the external address, else the destination host or IP. Remote → domain (`named`) when the record names it |
| DNS (4003) | host → domain (`queried`); domain → answer IP (`resolved_to`) |
| File activity (1001) | host → file (`file_activity`); file → hash (`hash`) |

Each node and edge lists the events it appears in (up to 20, with a full count). Logoffs and other events
state no relationship and add no edge.

**Notes** are analyst statements, not evidence: append-only, with no edit or delete API. Each one is audited
as `incident.note_added` with its length and SHA-256, and the author's email is kept as it was when
written.

**Console:**
- `/incidents` lists incidents by severity and status.
- `/incidents/{id}` is the workspace:
  - summary and "why this severity";
  - status actions, shown only to those allowed;
  - tabs for timeline, graph, findings and links, entities, and notes;
  - an evidence inspector.
- Selecting any step, node, edge, link or entity shows the events behind it in the inspector: each event's
  digest, its original record, the links that cite it, and "Load stored event" (needs `event:read` and the
  event store).

## API

| Endpoint | Permission |
|----------|------------|
| `GET /api/v1/incidents`: filters `status`, `severity_min`, `time_from`/`time_to` (on `last_seen`, ≤ 90 days); `limit` ≤ 200; opaque `cursor`; most recent activity first | `incident:read` |
| `GET /api/v1/incidents/{id}`: the incident with `assessment`, `links` and `entities` | `incident:read` |
| `PATCH /api/v1/incidents/{id}`: `{status, resolution?, version}`. A stale `version` is 409; only the status can change | `incident:update`; closing or reopening also needs `incident:resolve` |
| `GET /api/v1/incidents/{id}/timeline`: steps plus `unresolved_events` | `incident:read` |
| `GET /api/v1/incidents/{id}/graph`: nodes and edges, each with its events | `incident:read` |
| `GET /api/v1/incidents/{id}/evidence`: digests, each with the links citing it, plus `unresolved_events` | `incident:read`; the `raw` excerpt of the original record also needs `event:read` |
| `GET, POST /api/v1/incidents/{id}/notes`: `{body}` (1–10,000 characters) | read: `incident:read`; write: `incident:update` |

Roles: every human role reads incidents (the `service` role does not). Analysts and above can start an investigation. Senior analysts,
incident responders and admins can close and reopen.

**Audit:**
- `incident.opened` and `incident.correlated`, with the system as actor and before/after counts;
- `incident.status_changed`, with the user as actor;
- `incident.note_added`, with the user as actor.

## Limitations

- A finding that matches two open incidents joins one of them. Incidents are never merged.
- A successful logon that arrives *before* the failures it completes is not linked. Delivery is in
  order within a source, so this needs sources that disagree about time.
- Short host names can collide across domains. `matched` cites the events on both sides, so an analyst
  can check.
- Each incident entity keeps at most 20 sighting event_uids.
- Correlation rules and windows are code (`domain/policy.py`), not configuration.
- Correlation adds its latency to the detection consumer.
- **No back-fill:** correlation sees findings as they are created. Findings stored before correlation was
  deployed (Phase 2 data) are not grouped into incidents.
- **Digests start with Phase 4:** incidents linked before it have no digests, so their evidence is
  unresolved and their timeline is empty.
- An event that could not be read from the event store when it was linked stays unresolved; nothing retries
  it yet.
- The graph shows what single events state. It does not connect, for example, a DNS answer to a later
  connection unless one record names both.
