# ADR-0021 · Splunk is a source Sentinel-X pulls from, on demand

**Status:** Accepted · **Date:** 2026-09 · **Builds on:** [ADR-0013](ADR-0013-vector-http-ingest-and-python-ocsf-mapping.md),
[ADR-0014](ADR-0014-lock-scope-security-investigation.md)

## Context

Most organisations that would use Sentinel-X already have their logs in a SIEM, usually Splunk, and will
not re-point their collectors at a new system to try one. Until now the only way in was to push events to
`POST /api/v1/ingest/events` with a source token (ADR-0013), which means owning the collection path.

Four forces:

1. **Sentinel-X is an investigation platform, not a log store.** It needs the events an investigation
   touches, not a copy of everything Splunk holds.
2. **Searching Splunk costs the deployment money and licence volume.** Every pull must be bounded and
   deliberate, never a background firehose.
3. **A search string is powerful.** It is run as written on someone else's SIEM, so it must come from an
   operator, never from an event, a rule or the assistant.
4. **Splunk stores events as they arrived.** The same event can be XML, classic Windows text or JSON,
   depending on how it was forwarded. What Sentinel-X can read differs by sourcetype.

## Decision

1. **Pull, on demand, from the command line:** `sentinelx pull-splunk --search … --parser … --earliest …`.
   No scheduler, no background poller, no writes back to Splunk. Each run states its own time window and
   result cap (10,000 by default), and the export endpoint runs preview-free.
2. **Splunk's `sourcetype` chooses the parser** (`app/ingest_pipeline/splunk.py`), never the text itself:
   - `XmlWinEventLog…` → the Windows XML reader, then `windows_sysmon` or `windows_security` by Channel;
   - `linux_secure`, `syslog`, `sshd`, `auth`, `secure` → `linux_auth`, with Splunk's `_time` supplying the
     year a BSD syslog line lacks;
   - `ocsf`, `_json` holding `class_uid` → `ocsf`.

   Anything else, including Splunk's classic `WinEventLog:` key-value text, is **counted and named**, not
   guessed at. That text renders each event as localised prose; reading it would be invention.
3. **One pull serves one ingest source,** because a source has one parser and its events are attributed to
   it. Records for another parser are reported ("`windows_security` events need a source with that
   parser"), not sent under the wrong source.
4. **The collector re-uses the ingest API** with that source's token, so a pull is indistinguishable from
   any other producer: same validation, same audit, same rejection reasons.
5. **Credentials come from the environment**, never from arguments: `SENTINELX_SPLUNK_TOKEN` (a Splunk
   authentication token, not a password) and `SENTINELX_INGEST_TOKEN`. Neither is printed or logged, and
   error messages are checked in tests for leaks.
6. **Transport rules match the other outbound clients:** `SENTINELX_SPLUNK_URL` must be `https` unless it
   points at this host, certificate verification is on unless explicitly disabled (and cannot be disabled
   in production), redirects are never followed, and each result line is capped.

## Consequences

- An analyst can investigate with the logs an organisation already collects, without changing its
  collection. The demo story becomes "point it at your Splunk and pull the last day of Sysmon".
- **Coverage is honest but partial:** if Windows events were forwarded as classic `WinEventLog` text, a
  pull returns nothing usable and says so. Reading that format is a separate decision, not a silent
  fallback.
- **No checkpointing yet.** Repeating a pull re-sends the same events; ingestion's content fingerprint
  means they land as the same `event_uid`, so nothing is duplicated in the event store, but the work is
  repeated. A stored "last pulled time" per source, and a scheduled pull, are the next step if pulling
  becomes routine.
- **Untested against a live Splunk server on this machine.** The collector is covered by tests against a
  stub that speaks the export API's JSON-lines format; the recorded shapes come from Splunk's documented
  `search/jobs/export` output. A live run against a real server is still required before claiming it works
  in production.
- Elastic, Sentinel or Chronicle could be added behind the same shape (search → sourcetype mapping →
  ingest API). None is built.
