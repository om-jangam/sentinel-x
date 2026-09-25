# ADR-0024 · Windows events rendered as prose are read where the prose is structured

**Status:** Accepted · **Date:** 2026-09 · **Amends:** [ADR-0021](ADR-0021-splunk-as-a-pull-source.md) ·
**Builds on:** [ADR-0013](ADR-0013-vector-http-ingest-and-python-ocsf-mapping.md)

## Context

[ADR-0021](ADR-0021-splunk-as-a-pull-source.md) refused Splunk's older `WinEventLog:` format in one line:
"that text renders each event as localised prose; reading it would be invention." That was the right
instinct about guessing, and the wrong conclusion about the format.

The [detection evaluation](../evaluation/README.md) put a number on it. Six of the twelve public
recordings ship their Security log in exactly this format, and every one was reported as **read as
nothing** — 17,665 events, including the process-creation events (4688) that carry a command line, on the
recordings for two techniques Sentinel-X misses. The refusal was not protecting anyone from invention; it
was hiding a source the project already knows how to interpret.

Looking at the actual bytes changed the picture. The format is not free text:

```
12/04/2020 01:19:50 PM
LogName=Security
EventCode=4624
ComputerName=EC2AMAZ-8BAVDVD
Message=An account was successfully logged on.

Subject:
	Account Name:		EC2AMAZ-8BAVDVD$
New Logon:
	Account Name:		Administrator
Network Information:
	Source Network Address:	10.0.1.15
```

A header of `key=value` lines, then labelled values under named sections. "Account Name" appears three
times and means something different each time — which is precisely why a regular expression over the whole
message *would* be invention, and why a map keyed by (section, label) is not.

## Decision

1. **Read it with an explicit map, per event and per section.**
   [`app/ingest_pipeline/wineventlog_text.py`](../../backend/app/ingest_pipeline/wineventlog_text.py)
   holds one table: for each Windows event, which (section, label) pair fills which field. "Account Name"
   under `New Logon:` is the account that logged on; under `Subject:` it is the account that asked. A
   label is read without its section only where it means one thing in the whole message, and if the
   rendering repeats such a label the value is dropped rather than picked at random.
2. **Anything not in the map is left out**, never inferred. The reader produces the same record shape the
   XML reader produces, so `windows_security` maps it with no idea which form it came from.
3. **The parser, not the reader, decides which events Sentinel-X maps.** An event with no labels still
   becomes a record; the parser refuses it by name (`unsupported Windows Security event 4672`). A test
   keeps the two in step, so a parser that learns a new event without labels here fails the suite instead
   of quietly producing an empty record.
4. **Two limits are stated, not hidden:**
   - **English only.** Windows renders these labels in the machine's language. A German or Japanese host
     writes different words, nothing matches, and the events are refused rather than mis-read.
   - **The time carries no zone.** The rendered header is the indexer's local time, so it is read as UTC
     and can be out by the host's offset. The XML form carries a real UTC timestamp; this one does not.

   Both are reasons to forward `XmlWinEventLog` where that is a choice. This reader is for logs already
   collected the other way.
5. **The evaluation separates "we don't map this event type" from "we failed to read this event."**
   A Windows Security log is mostly audit types no rule reads; counting those as parse failures would make
   the parse rate report a failure that is really a scope decision. The report now has both columns.

## Consequences

- **17,665 events entered scope, and 0 were rejected.** Process creation from the Security log now sits
  beside Sysmon's: T1105 picked up `Suspicious Curl.EXE Download` (64 findings) and
  `Suspicious Invoke-WebRequest Execution`; T1059.001 gained findings on rules it already had. No
  technique verdict changed — the recordings that hid a missed technique did not exist.
- **It exposed a Sigma rule that could never work here.** SigmaHQ's "External Remote SMB Logon from Public
  IP" excludes anonymous logons with `filter_main_empty: IpAddress: '-'`. Windows writes `-` for "not
  recorded" and normalisation drops it, so that filter matched nothing and the rule fired on exactly the
  logons it was written to exclude: 2,041 findings across four recordings. The Sigma compiler now treats a
  rendered `-` as also matching an absent field, and the same recordings produce 101, every one a logon
  that really does name a public address. This is a correctness fix for **every** Sigma rule that filters
  on a Windows placeholder, not only for this format.
- **Splunk pulls gained a sourcetype.** `WinEventLog:Security` maps to `windows_security` through the same
  reader, with Splunk's `_time` as the fallback when a result's `_raw` begins at the header.
- **The refusal that ADR-0021 recorded is gone, and with it its stated consequence** ("if Windows events
  were forwarded as classic `WinEventLog` text, a pull returns nothing usable"). Forwarding XML is still
  better, for the two reasons above.

## Alternatives rejected

- **Keep refusing it.** Honest, but it cost a fifth of the available test data and left the project's
  strongest claim — that it reads what organisations actually collect — resting on one forwarding choice.
- **Regular expressions over the whole message.** This is the invention ADR-0021 feared: `Account Name`
  matched anywhere returns the subject as often as the account, and nothing in the output would say which.
- **Ask a model to read the prose.** It contradicts [ADR-0012](ADR-0012-determinism-first-ai.md): parsing
  is the evidence layer, and evidence cannot come from something that cannot be re-run to the same answer.
