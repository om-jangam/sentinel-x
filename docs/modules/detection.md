# Module · `detection`

*Phase 2* — deterministic rules over normalised events that produce **findings**, each citing the stored
events behind it. Design decision: [ADR-0015](../adr/ADR-0015-in-stream-detection.md).

## Where it runs

Detection consumes `events.normalized`, the same stream the indexer reads, in its own consumer group
(`detection`). In a Redis deployment the worker (`sentinelx-worker`) runs both groups. Without Redis the
API runs both in-process. Rules are loaded once at start-up; **a rule that can't load stops start-up**.
After each batch's findings are committed, detection hands them, with the batch's events, to
[correlation](correlation.md) through a sink wired at the composition root.

## Findings

A finding is immutable and records:

| Field | Meaning |
|-------|---------|
| `rule_id`, `rule_title`, `rule_type`, `rule_version` | Which rule fired; `rule_version` is the SHA-256 of the rule file, so the exact text is traceable |
| `severity_id`, `severity` | From the rule's level: informational 1 · low 2 · medium 3 · high 4 · critical 5 |
| `techniques`, `tactics` | ATT&CK from the rule's `attack.*` tags |
| `entities` | Sigma: the event's observables. Threshold: the `group_by` values and the distinct values counted |
| `evidence` | `sx.event_uid` of every supporting event (at most 100), in event-time order |
| `first_seen`, `last_seen` | Event-time range of the evidence |

**Evidence rule:** a finding always cites at least one event, and only events that were delivered.
`event_uid` is derived from the event's content fingerprint, so a re-sent record carries the same ID.
Redelivery never duplicates a finding: each has a dedupe key, per rule and event for Sigma, and per rule,
group and firing for threshold rules.

| Endpoint | Permission |
|----------|------------|
| `GET /api/v1/findings` — filters `time_from`, `time_to` (on `last_seen`, ≤ 90 days), `severity_min`, `rule_id`, `technique`; `limit` ≤ 200; opaque `cursor`; newest first | `finding:read` |
| `GET /api/v1/findings/{id}` | `finding:read` |
| `GET /api/v1/detection/rules`, `GET /api/v1/detection/rules/{id}` | `rule:read` |

Resolve evidence with `GET /api/v1/events/{event_uid}` (`event:read`).

## Shipped rules

`backend/app/modules/detection/rules/`. Each fires on the demo telemetry in `pipeline/samples`.

| Rule | Type | Level | ATT&CK | Fires on the samples |
|------|------|-------|--------|----------------------|
| PowerShell started with an encoded command | Sigma | high | T1059.001, T1027 | `WS-FIN-07` `powershell.exe -EncodedCommand …` |
| whoami used to list privileges or groups | Sigma | medium | T1033 | `whoami /all` |
| net.exe lists the Domain Admins group | Sigma | medium | T1069.002 | `net group "Domain Admins" /domain` |
| SSH authentication attempt for a user that does not exist | Sigma | low | T1110 | 6 invalid-user lines on `web-01` |
| Authentication failures across many accounts from one source | threshold: ≥ 4 distinct users per source IP in 10 min | medium | T1110.003 | spray from 203.0.113.45 |
| Burst of authentication failures for one account from one source | threshold: ≥ 5 per source IP and user in 5 min | medium | T1110.001 | 5 failed logons for `jsmith` |
| Repeated connections from one host to the same external destination | threshold: ≥ 5 per source, destination IP and port in 10 min | low | T1071 | `WS-FIN-07` → 192.0.2.66:443 |

The three sample stories produce 12 findings. Alice's key-based logins, the interactive logon and the
internal SMB session produce none. `test_detection_service.py` pins this.

## Sigma support

Rules are parsed by pySigma and translated once into predicates over OCSF field paths. Anything outside
the tables below is **refused at load with the reason**, never loaded half-working.

**Logsources**

| Sigma logsource | Matches normalised events where | Fields |
|-----------------|--------------------------------|--------|
| `category: process_creation` | `class_uid` 1007 and `activity_id` 1 (Security 4688 and Sysmon 1) | `Image` → `process.file.path` · `CommandLine` → `process.cmd_line` · `ParentImage` → `process.parent_process.file.path` · `ParentCommandLine` · `ProcessId` · `ParentProcessId` · `ProcessGuid`, `ParentProcessGuid` → `…uid` · `User` → `actor.user.name`, `process.user.name`, `unmapped.user` (Sysmon's `DOMAIN\name`) · `ParentUser` · `IntegrityLevel` → `process.integrity` · `CurrentDirectory` → `process.working_directory` · `Company`, `Description`, `Product`, `FileVersion` → `process.file.*` · `OriginalFileName`, `Hashes`, `LogonId` → `unmapped.*` · `Computer` → `device.hostname` |
| `product: windows, service: security` | `metadata.product.name` "Microsoft Windows" and `metadata.log_name` "Security" | `EventID` → `unmapped.event_id` · `TargetUserName`/`TargetDomainName`/`TargetUserSid` → `user.*` · `SubjectUserName`/`SubjectDomainName` → `actor.user.*` · `IpAddress`, `IpPort`, `WorkstationName` → `src_endpoint.*` · `LogonType` → `logon_type_id` · `AuthenticationPackageName` → `auth_protocol` · `NewProcessName`, `CommandLine`, `ParentProcessName` → `process.*` · `Status`, `SubStatus`, `FailureReason` → `unmapped.*` · `Computer` |
| `product: linux, service: auth` or `sshd` | `metadata.log_name` "auth.log" | keywords only |
| `category: network_connection` | `class_uid` 4001 | `SourceIp`, `SourcePort`, `SourceHostname`, `DestinationIp`, `DestinationPort`, `DestinationHostname`, `Protocol`; no keywords |
| `category: dns_query` or `dns` | `class_uid` 4003 | `QueryName` → `query.hostname` · `QueryType` → `query.type` · `QueryResults` → `answers.rdata` · `SourceIp` · `QueryStatus` · `Image` → `actor.process.file.path` |
| `category: process_termination` | `class_uid` 1007, `activity_id` 2 | `Image`, `ProcessId`, `ProcessGuid`, `User` |
| `category: process_access` | `class_uid` 1007, `activity_id` 3 | `SourceImage` → `actor.process.file.path` · `TargetImage` → `process.file.path` · `…ProcessId` · `…ProcessGuid`/`GUID` · `SourceUser`, `TargetUser` · `GrantedAccess`, `CallTrace` → `unmapped.*` |
| `category: create_remote_thread` | `class_uid` 1007, `activity_id` 4 | as `process_access`, plus `StartAddress` → `module.start_address` · `StartFunction` → `module.function_name` · `StartModule` |
| `category: image_load` | `class_uid` 1005, `activity_id` 1 | `ImageLoaded` → `module.file.path` · `Image` → `actor.process.file.path` · `Company`, `Description`, `Product`, `FileVersion` → `module.file.*` · `OriginalFileName`, `Hashes`, `Signed`, `Signature`, `SignatureStatus` → `unmapped.*` |
| `category: file_event` / `file_delete` | `class_uid` 1001, `activity_id` 1 / 4 | `TargetFilename` → `file.path` · `Image` → `actor.process.file.path` · `Hashes` · `User` |
| `category: registry_add` / `registry_delete` / `registry_set` / `registry_rename` | Sysmon events whose `EventType` is CreateKey / DeleteKey or DeleteValue / SetValue / RenameKey or RenameValue | `TargetObject` → `reg_key.path`, `reg_value.path`, `prev_reg_key.path` · `Details` → `reg_value.data` · `NewName` · `EventType` · `Image` |
| `category: registry_event` | `class_uid` 201001 or 201002 | as above |
| `product: windows, service: sysmon` | `metadata.log_name` "Microsoft-Windows-Sysmon/Operational" | every Sysmon field above, plus `EventID` → `unmapped.event_id`; `Image` is the event's own process (event 1) or the acting process |

Keyword searches look in `message` and `raw_data` (for `process_creation`: `process.cmd_line` and
`raw_data`). A plain keyword matches anywhere in those fields, as full-text search does.

**Values and modifiers:** strings with `*` and `?` (whole-value, case-insensitive), `contains`,
`startswith`, `endswith`, `all`, `windash`, `cased`, `re` (unanchored, with `i`, `m`, `s` flags), `cidr`,
`lt`/`lte`/`gt`/`gte`/`neq`, `exists`, `null`, numbers, booleans, and conditions with `and`/`or`/`not`,
`1 of`/`all of` and `them`.

**`-` means "not recorded".** Windows writes a dash where it has no value, and normalisation drops it
rather than storing a dash in, say, an IP field. So a rule testing a field for `'-'` also matches the
event where that field is absent. Without this, SigmaHQ's own `filter_main_empty: IpAddress: '-'` could
never match, and "External Remote SMB Logon from Public IP" fired on exactly the anonymous logons it was
written to exclude — 2,041 times across four public recordings
([what the evaluation showed](../evaluation/README.md#what-it-exposed)).

**Refused:** unmapped logsources and fields, `fieldref`, placeholders (`expand`), query expressions, and
any value type not listed. Of the correlation rules, only `event_count` and `value_count` are supported
(below); `temporal` and `temporal_ordered` are refused with that reason.

## Sigma correlation rules

Sigma's own format for "enough of these events in a window" is supported for `event_count` and
`value_count`. A correlation rule names a base rule by its `name:`, and the two usually live in one file
as two YAML documents:

```yaml
correlation:
  type: value_count
  rules: [outbound_external_connection]
  group-by: [SourceIp]
  timespan: 5m
  condition: {gte: 10, field: DestinationIp}
```

It compiles to the same `ThresholdRule` the engine already evaluates: `group-by` and the counted field
are mapped to OCSF paths through the base rule's logsource. A rule a correlation counts is **support, not
a detection**, so it does not also fire on its own.

Refused with the reason: `temporal` and `temporal_ordered` (they need several rules at once), more than
one base rule, conditions other than `gte`, timespans over 24 hours, and unmapped fields.

The three platform threshold rules below stay in Sentinel-X's own format because they match normalised
OCSF fields **across sources** — a failed logon is a failed logon whether it came from Windows or
OpenSSH — which Sigma's logsource-scoped model cannot express.

## Threshold rules

A Sentinel-X format for patterns a single-event rule can't see:

```yaml
id: 4f8b2c6d-1a37-4e95-b0c2-7d6e9f1a3b58     # UUID, unique across all rules
title: Authentication failures across many accounts from one source
description: …
level: medium                                # informational | low | medium | high | critical
tags: [attack.credential_access, attack.t1110.003]
match:                                       # all must hold
  class_uid: 3002                            #   equality (numbers numeric, strings case-insensitive)
  status_id: [2, 99]                         #   any of
  dst_endpoint.ip|external: true             #   not RFC 1918 / CGNAT / loopback / link-local / multicast
group_by: [src_endpoint.ip]                  # 1-5 OCSF paths; events missing one are ignored
count_distinct: user.name                    # optional: count distinct values instead of events
threshold: 4                                 # 2-10,000
window: 10m                                  # s, m or h; at most 24h; measured in event time
```

Every field path is checked against the OCSF model at load. A group fires when the count within the
window before an event reaches the threshold. It then stays quiet until one full window has passed since
it fired. The finding cites the events in the window at that moment. Windows use event time, so replayed
or late data behaves the same as live data.

## Adding a rule

1. Put the file in `rules/sigma/` or `rules/threshold/`.
2. Add a sample record or test case that it must fire on, and one it must not.
3. Run `uv run pytest app/modules/detection`. `test_every_shipped_rule_loads…` fails on any load error,
   and the sample test fails if expected findings change.

## Metrics

`sentinelx_detection_findings_total{rule_type,outcome}` (`created` or `duplicate`) and
`sentinelx_detection_batch_seconds`.

## Community rules (SigmaHQ)

Besides its own 7 rules, Sentinel-X ships 162 rules from [SigmaHQ](https://github.com/SigmaHQ/sigma)'s
core package, release `r2026-07-01`, unmodified, under `rules/sigmahq/` with a manifest and
[NOTICE](../../backend/app/modules/detection/rules/sigmahq/NOTICE.md). They are licensed under the
Detection Rule License 1.1, which requires every match to name the rule's author, so:

- `RuleMeta` carries `author` and `source_url`; `GET /api/v1/detection/rules` returns both;
- every finding stores `rule_author` and `rule_source` as it stores `rule_version`, so an alert stays
  attributed to the text that fired even after the pack is updated;
- the console shows the author and links to the published rule.

Which rules: every core rule this engine can evaluate that is tagged with a technique the evaluation
targets (see [docs/12](../12-improvement-research.md#3-ship-a-curated-sigmahq-rule-set-with-attribution)).
Rules load once per process and are cached by file fingerprint, so the 169 rules cost ~0.4 s at start-up.

## Measured on public recordings

`sentinelx evaluate-detection` replays attack recordings from
[splunk/attack_data](https://github.com/splunk/attack_data) through these rules and reports, per ATT&CK
technique, whether any rule flagged it: [results](../evaluation/detection-baseline.md),
[what they mean](../evaluation/README.md). Findings on the recording lab's own automation are reported
separately and never counted as detections.

## Limitations

- **Rules are code:** no runtime enabling, disabling or editing; changes ship through git and review.
- **Sigma coverage** is the table above. Sysmon events 1, 3, 5, 7, 8, 10–14, 22, 23 and 26 are
  normalised; named pipes (17, 18), WMI (19–21), `pipe_created`, `wmi_event`, `ps_script` and other
  Windows logs are not, so rules for them are refused.
- **NTLM spraying is counted from attempts, not failures.** Event 8004 does not say whether the
  authentication worked, so the rule reports how many accounts one workstation tried, and an analyst has
  to read the logon records for the outcome.
- **`whoami used to list privileges or groups` is tagged T1033 but narrower than the technique:** it needs
  `/all`, `/priv` or `/groups`, so plain `whoami` (what the public T1033 recording runs) does not fire it.
- **Threshold evidence** is the window at the moment of firing; later events in the same window do not
  fire again. Correlation groups findings into incidents, but it doesn't add those later events.
- **Eventually consistent with the event store:** detection and indexing are separate consumers, so a
  finding can cite an event for a short time before it is searchable.
- **No retro-hunting:** rules evaluate events as they arrive, not stored history.
- **Without Redis,** threshold windows live in one process's memory and reset on restart.
