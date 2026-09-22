# Module · `ingestion` and `ingest_pipeline`

*Phase 1* — authenticated intake of security telemetry, normalisation to a documented OCSF 1.6 subset,
immutable storage in OpenSearch, and constrained event search. Design decision:
[ADR-0013](../adr/ADR-0013-vector-http-ingest-and-python-ocsf-mapping.md).

## Sending events

```http
POST /api/v1/ingest/events
Authorization: Bearer sxi_…
Content-Type: application/json            (or application/x-ndjson)

[ { …record… }, { …record… } ]
```

- **Body shapes:** a JSON array, `{"events": [...]}`, a single object, or NDJSON.
- **Limits:** 5 MiB and 1,000 records per request (nginx allows 6 MiB on this route only), and a
  per-source rate of `SENTINELX_INGEST_RATE_LIMIT` requests per `SENTINELX_INGEST_RATE_WINDOW_SECONDS`
  (default 600 per 60 s).
- **Response:** `202 {"accepted": n, "rejected": m, "errors": [{"index": i, "reason": "…"}]}`. A 202 with
  `accepted: 0` means every record was rejected, so producers must read `rejected` and `errors`, not
  just the status. At most 50 errors are listed.

| Status | Meaning | Producer should |
|--------|---------|-----------------|
| 202 | Batch processed (possibly partially rejected) | Log `errors`; don't resend rejected records unchanged |
| 401 | Missing, invalid or rotated token | Stop and alert; don't retry |
| 403 | User token without `ingest:write` | Stop |
| 409 | Source disabled | Stop |
| 413 | Body over 5 MiB | Split the batch |
| 422 | Malformed JSON, over 1,000 records, or missing `source_id` with a user token | Fix the request |
| 429 | Rate limited | Retry after `Retry-After` seconds |
| 5xx / network | Server or transport failure | Retry with backoff; duplicates are safe |

A user with `ingest:write` may submit instead of a source token by adding `?source_id=<uuid>`; events
are still attributed to that source.

## Sources

Every producer is a registered **source** with one parser and its own token.

| Endpoint | Permission |
|----------|------------|
| `GET /api/v1/ingest/parsers` | `source:read` |
| `GET /api/v1/ingest/sources`, `GET /api/v1/ingest/sources/{id}` | `source:read` |
| `POST /api/v1/ingest/sources` — `{"name", "description", "parser"}`, returns the token once | `source:manage` |
| `PATCH /api/v1/ingest/sources/{id}` — `{"is_enabled": bool}` | `source:manage` |
| `POST /api/v1/ingest/sources/{id}/rotate-token` — old token stops working immediately | `source:manage` |

Tokens are `sxi_` + 256 random bits, stored only as a SHA-256 hash; responses show a 12-character
prefix. Create, rotate, enable and disable are written to the audit chain, never with the token.

**Health**, computed on read: `disabled`; `erroring` (a batch was fully rejected in the last 15 minutes and
no event newer than that rejection has been accepted); `awaiting_data` (nothing received yet); `stale`
(newest event older than 15 minutes); otherwise `healthy`. Freshness compares *event* time with the
wall clock, so replayed historical data reads as `stale`, and can keep a source `erroring` for up to 15
minutes after a rejection.

## Pipeline

1. Authenticate the source; check it is enabled; apply the rate limit and size caps.
2. For each record, run the source's parser and validate the result against the OCSF model. A failure
   rejects that record only.
3. Stamp `sx.org_id`, `sx.source_id`, `sx.event_uid` (a UUID v5 of the fingerprint, so every delivery of a
   record has the same ID), `sx.ingested_at` and `sx.fingerprint`,
   and add `@timestamp` plus OCSF captions.
4. Publish to Redis Streams (`events.normalized`), 200 documents per message, then update source
   counters. With no Redis, the API indexes in-process.
5. Two consumer groups read the stream independently: **detection** evaluates rules and stores findings
   ([detection module](detection.md)), and the **indexer** bulk-writes with `create` into
   `events-ocsf-<category>-write`. A failed write raises, so the
   message stays pending and is redelivered.

**Immutability.** `_id` is `SHA-256(org_id ‖ source_id ‖ canonical normalised event)`. Because writes use
`create`, a duplicate returns 409 and the original document and its `sx.event_uid` are kept. Events can
be cited as evidence by `sx.event_uid`.

## OCSF mappings

**Coverage honesty.** Sentinel-X normalises to a *trimmed subset* of OCSF 1.6. It is not a complete OCSF
implementation:

- **Classes supported:** File System Activity (1001), Process Activity (1007), Authentication (3002),
  Network Activity (4001), HTTP Activity (4002), DNS Activity (4003). Others are rejected.
- **File hashes** (`*.file.hashes`, the OCSF fingerprint object) are accepted: MD5, SHA-1, SHA-256 and
  SHA-512 must be well-formed hex and are lower-cased. Only native OCSF input carries them today; no
  shipped parser produces hashes.
- **Attributes outside the model are dropped**, including on native OCSF input. Source-specific leftovers
  go in `unmapped`, which is stored but not indexed.
- **Validation:** `category_uid` and `type_uid` are derived and checked; `activity_id` must be defined
  for the class (or 0 Unknown / 99 Other); `time` accepts epoch milliseconds, epoch seconds or RFC 3339
  and may be at most 24 h in the future; only `metadata.version` 1.x; per-class context is required
  (e.g. Authentication needs `user`, Network Activity needs an endpoint). String, list and `raw_data`
  (32 KB) / `unmapped` (16 KB) sizes are capped.
- **Additions that aren't OCSF:** `@timestamp`, the `sx` object, and `observables` derived by Sentinel-X
  when the producer sent none.

### `linux_auth` — OpenSSH `sshd` lines

Input: `{"message": "<syslog line>", "timestamp": "<optional RFC 3339>"}`. Lines may start with an RFC
3339 timestamp or a BSD syslog date; BSD dates use `timestamp` if present, otherwise the current year in UTC.

| sshd message | OCSF |
|--------------|------|
| `Accepted <method> for <user> from <addr> port <p>` | Authentication · Logon · Success · Informational |
| `Failed <method> for [invalid user] <user> from <addr> port <p>` | Authentication · Logon · Failure · Low |
| `Invalid user <user> from <addr> [port <p>]` | Authentication · Logon · Failure · Low |

| Source | OCSF field |
|--------|------------|
| `<user>` | `user.name` |
| `<addr>` | `src_endpoint.ip` (or `src_endpoint.hostname` when not an IP) |
| `<p>` | `src_endpoint.port` |
| syslog host | `device.hostname`, `dst_endpoint.hostname` |
| — | `auth_protocol` = `SSH`, `logon_type` = `Network`, `logon_type_id` = 3 |
| method, invalid user, pid | `unmapped.{auth_method, invalid_user, pid}` |
| whole line | `raw_data` |

Rejected: non-sshd lines and sshd lines that aren't an authentication outcome (e.g. session opened,
connection closed).

### `windows_security` — Security log JSON

Input: one event object with `EventID`, `TimeCreated` (or `@timestamp` / `timestamp`), `Computer`,
`EventRecordID` and `EventData`, as produced by Winlogbeat, NXLog or WEF exports.

| EventID | OCSF |
|---------|------|
| 4624 | Authentication · Logon · Success · Informational |
| 4625 | Authentication · Logon · Failure · Low |
| 4634, 4647 | Authentication · Logoff · Success · Informational |
| 4688 | Process Activity · Launch · Success · Informational |

| Source | OCSF field |
|--------|------------|
| `TargetUserName` / `TargetDomainName` / `TargetUserSid` | `user.name` / `domain` / `uid` |
| `SubjectUserName` / `SubjectDomainName` / `SubjectUserSid` (4688) | `actor.user.*` |
| `IpAddress` (valid IPs only), `IpPort` (0 dropped), `WorkstationName` | `src_endpoint.ip`, `.port`, `.hostname` |
| `Computer` | `device.hostname`; also `dst_endpoint.hostname` for logons |
| `LogonType` | `logon_type_id` and `logon_type` (Interactive, Network, RemoteInteractive, …) |
| `AuthenticationPackageName` | `auth_protocol` |
| `ProcessName` (logons) | `actor.process.name`, `actor.process.file.path` |
| `NewProcessName`, `NewProcessId` (hex), `CommandLine` | `process.name`, `.file.path`, `.pid`, `.cmd_line` |
| `ParentProcessName`, `ProcessId` (hex) | `process.parent_process.name`, `.pid` |
| `EventRecordID` | `metadata.uid` |
| `FailureReason`, `Status`, `SubStatus` (4625); `EventID` | `unmapped` |
| whole event | `raw_data` |

`-` and empty values are treated as absent. Rejected: any other `EventID`, a missing `EventID` or
time, non-object `EventData`, and a 4688 without `NewProcessName`.

### `windows_sysmon` — Sysmon Operational log JSON

Input: the same shape as `windows_security` (`EventID`, `TimeCreated` or Sysmon's `UtcTime`, `Computer`,
`EventRecordID`, `EventData`). `metadata.product.name` is "Sysmon" and `metadata.log_name` is
"Microsoft-Windows-Sysmon/Operational".

| EventID | Sysmon | OCSF |
|---------|--------|------|
| 1 | Process creation | Process Activity · Launch |
| 3 | Network connection | Network Activity · Open |
| 5 | Process terminated | Process Activity · Terminate |
| 7 | Image loaded | Module Activity (1005) · Load |
| 8 | CreateRemoteThread | Process Activity · Inject (`injection_type` "Remote Thread") |
| 10 | ProcessAccess | Process Activity · Open |
| 11 | FileCreate | File System Activity · Create |
| 12 | Registry object created / deleted | Registry Key Activity (201001) · Create / Delete, Registry Value Activity (201002) · Delete |
| 13 | Registry value set | Registry Value Activity · Set |
| 14 | Registry object renamed | Registry Key Activity · Rename (`prev_reg_key` holds the old path) |
| 22 | DNS query | DNS Activity · Query |
| 23, 26 | File deleted | File System Activity · Delete |

The registry classes come from the OCSF Windows extension. Their numbers are
`extension_uid × 100000 + class`, and they belong to category 1 (System Activity).

| Source | OCSF field |
|--------|------------|
| `Image`, `ProcessId`, `ProcessGuid` (event 1) | `process.file.path`, `.name`, `.pid`, `.uid` |
| `CommandLine`, `IntegrityLevel`, `CurrentDirectory` | `process.cmd_line`, `.integrity`, `.working_directory` |
| `User` (`DOMAIN\name`) | `process.user.domain` / `.name` (event 1); `actor.user.*` otherwise |
| `ParentImage`, `ParentProcessId`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser` | `process.parent_process.*` |
| `Company`, `Description`, `Product`, `FileVersion` | `…file.company_name`, `.desc`, `.product.name`, `.version` |
| `Hashes` (`MD5=…,SHA256=…,IMPHASH=…`) | `…file.hashes` (MD5, SHA-1 and SHA-256 validated; IMPHASH as algorithm "other"). Malformed entries are skipped |
| `Image` (every event except 1) | `actor.process.*`: the program that acted |
| `SourceImage` / `TargetImage` (8, 10) | `actor.process.*` / `process.*`; both `…ProcessGuid` and Sysmon 10's `…ProcessGUID` spelling |
| `GrantedAccess` (10) | `actual_permissions` (the mask as a number) |
| `SourceIp`, `SourcePort`, `SourceHostname`, `Destination…` | `src_endpoint.*`, `dst_endpoint.*` |
| `Protocol`, `Initiated` | `connection_info.protocol_name`, `.direction_id` (2 outbound, 1 inbound) |
| `ImageLoaded` (7) | `module.file.*` |
| `StartAddress`, `StartFunction` (8) | `module.start_address`, `.function_name` |
| `TargetFilename` (11, 23, 26) | `file.path`, `.name` |
| `TargetObject`, `Details` (12–14) | `reg_key.path`, or `reg_value.path`, `.name`, `.data` |
| `QueryName`, `QueryResults`, `QueryStatus` (22) | `query.hostname`, `answers[].rdata` (addresses; CNAME entries skipped), `status_id` |

Kept as written under `unmapped`, because OCSF has no attribute for them and Sigma rules match them
literally: `original_file_name`, `hashes`, `user`, `logon_id`, `initiated`, `granted_access`,
`call_trace`, `signed`, `signature`, `signature_status`, `query_status`, `event_type`, `start_module`,
`rule_name` and `event_id`.

In event 1 the parent is recorded once, as `process.parent_process`, not again as `actor.process`. That
way a rule on `Image` can never match the parent's path.

Rejected with a reason: any other `EventID` (for example 15, 17, 18 and 25), a missing time, non-object
`EventData`, and events without their key field (`Image`, `TargetImage`, `TargetFilename`,
`TargetObject`, `QueryName`, or both endpoints).

### `ocsf` — already-normalised events

Passes the record to OCSF validation unchanged. It must contain `class_uid`; everything in *Coverage
honesty* applies.

## Search

`POST /api/v1/events/search` (`event:read`) takes a fixed set of filters, never a raw query:
`time_from`/`time_to` (required, ≤ 90 days), `class_uids`, `severity_min`, `status_id`, `source_id`, `ip`
(any of source, destination or device IP), `user_name` and `hostname` (case-insensitive exact match),
and `text` (≤ 256 characters; `simple_query_string` over `message`, `raw_data`, `process.cmd_line` and
`query.hostname`). Results are org-scoped, newest first, with an opaque cursor, `limit` ≤ 200, and a
total capped at 10,000. `GET /api/v1/events/{event_uid}` returns one event.

## Operations

```bash
sentinelx opensearch-init          # index template, ISM policy, write indices (idempotent)
sentinelx worker                   # indexing + detection + correlation; replicas share each group
sentinelx load-demo [--samples DIR] [--keep-timestamps]
                                   # demo sources + pipeline/samples; all files shifted by one offset so
                                   # the newest event is ~5 min old and the cross-source story keeps its order.
                                   # With Redis it publishes to the bus for the worker; without, it indexes
                                   # (if OpenSearch is set) and runs detection and correlation in-process
```

Metrics: `sentinelx_ingest_events_total{parser,outcome}`, `sentinelx_indexed_events_total{outcome}`,
`sentinelx_ingest_lag_seconds`, `sentinelx_event_age_seconds`.

`pipeline/vector/vector.yaml` is a starting configuration for tailing `auth.log` and Windows Security
JSON files; it has not been run against a live Vector instance.

## Aegis

Not connected. Aegis events use their own contract (agent, rule, MITRE techniques, details), and no
parser or endpoint maps it yet. The proposed design adds a dedicated Aegis endpoint that maps alerts to
OCSF Detection Finding (2004) and tracks agent heartbeats. It awaits four decisions (token model,
contract interpretation, contract location, audit-score history); see
[11 · Roadmap](../11-development-roadmap.md).
