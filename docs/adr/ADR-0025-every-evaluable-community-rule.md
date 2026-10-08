# ADR-0025 · Ship every community rule the engine can evaluate, not the ones we thought to look for

**Status:** Accepted · **Date:** 2026-10 · **Amends:** the selection rule recorded in
[docs/12 step 3](../12-improvement-research.md#3-ship-a-curated-sigmahq-rule-set-with-attribution) ·
**Builds on:** [ADR-0015](ADR-0015-in-stream-detection.md)

## Context

The first SigmaHQ import kept 162 of the 914 rules this engine can evaluate, by a documented filter: a
rule had to be tagged with a technique **the evaluation targeted** — the Red Canary top ten that Windows
logs can show, plus every technique a Sentinel-X rule claimed.

That filter has a flaw that the measurement could never reveal, because the measurement was its input: the
project could only detect what it had already decided to look for. A technique nobody listed was invisible
by construction, and the evaluation would report the silence as a clean run. Dropping the filter put
`HackTool - Mimikatz Execution` into the shipped set, and it fired twelve times on a recording the project
had been replaying for weeks.

Two further problems with the old filter were practical. It was not reproducible in fact: the selection
existed as a procedure in a notice file, not as a command, so no one could re-derive the 162. And it had
to be re-judged by hand every time the rule set or the technique list changed.

## Decision

1. **Ship every rule in SigmaHQ's `core` package that this engine can evaluate.** 917 of 1,377 today.
   No technique filter, no severity filter, no hand-picking.
2. **Let SigmaHQ's own tiering be the quality filter.** The `core` package is already their curated set:
   every rule in it is `high` or `critical` and `status: test` or `stable`, with nothing experimental and
   no low-confidence hunting rules. Sentinel-X does not need a second opinion about rule quality, and is
   not qualified to have one about 900 rules it did not write.
3. **Refuse, with a reason, what the engine cannot evaluate** — an unmapped logsource, a field no parser
   fills, an unimplemented modifier. 460 rules are refused today and the import prints why. A rule that
   half-runs is worse than one that is absent, because it reports silence as safety.
4. **The selection is a command, not a procedure:** `sentinelx import-sigma-rules`
   ([`app/sigma_import.py`](../../backend/app/sigma_import.py)) downloads the release package, verifies it
   against `--sha256`, writes every evaluable rule verbatim, regenerates `MANIFEST.json`, and deletes
   files a previous import selected and this one did not.
5. **A field is mapped for Sigma only when a parser fills it.** Declaring a field the normaliser never
   writes makes a rule's `not filter` exclude nothing, which is how
   [ADR-0024](ADR-0024-rendered-wineventlog-text.md) found "External Remote SMB Logon from Public IP"
   firing on the logons it was written to exclude.

## Consequences

- **New detections the filter had hidden**, on recordings already in the evaluation: Mimikatz execution
  (12 findings), PowerUp's DLL hijack write (36), Mshta HTA and JavaScript execution, a process
  masquerading as `svchost.exe`. Twenty community rules now fire on these recordings, against twelve
  before.
- **No headline verdict moved.** Still 3 of 5 priority techniques and 2 of 3 claimed ones. Worth stating
  plainly: 5.7× the rules did not buy a single technique, because the techniques that were missed are
  missed for reasons rules cannot fix — a recording of eight events (T1059.003), a rule that is narrower
  than its tag (T1033), or community rules that deliberately trade recall for precision (T1047).
- **Noise stayed measurable, not hypothetical:** 211 findings outside the targeted techniques across
  64,946 events. The largest contributor is one rule firing 101 times on genuinely public source
  addresses in a cloud test lab.
- **Some findings now name no technique.** 93 of the 917 community rules carry no ATT&CK tag, so a
  finding from one has an empty technique list, and the Navigator export has nothing to place for it. A
  test counts them so the number stays visible. Sentinel-X's own rules must still name a technique.
- **Start-up and replay cost more, measurably.** Rules compile once per process and are cached by file
  fingerprint, so 926 rules cost ~3 s at start-up. Replaying the 64,946 recorded events went from ~80
  seconds to **7m43s**: linear in the rule count, as a rule engine that evaluates every rule against every
  event has to be. It is a development-time cost (the evaluation), not a request-path one, but it puts a
  ceiling on how much bigger the pack can get before the engine needs an index of rules by logsource.
- **`GET /api/v1/detection/rules` now returns about 950 KB** (926 rules of metadata) and has no
  pagination. The workspace does not call it, so nothing regressed in the product; it is left as it is
  rather than redesigned in passing, and paginating it is a decision for whoever needs it.

## Alternatives rejected

- **Keep the technique filter, widen the technique list.** This is the same mistake with a longer list:
  the set of techniques worth detecting is not knowable in advance, which is the entire argument for using
  somebody else's rule corpus.
- **Ship all 1,377 rules and ignore the 460 that do not compile.** They would sit in the directory looking
  like coverage. Absence is honest; a rule that cannot run is not.
- **Write our own equivalents of the community rules.** 917 rules of maintained, peer-reviewed detection
  content against a few hand-written ones, with no advantage except authorship.
