# ADR-0022 · Check who did what: relationship claims against the evidence graph

**Status:** Accepted · **Date:** 2026-09 · **Refines:** [ADR-0019](ADR-0019-ai-assistant-local-model-grounding-validator.md)

## Context

The grounding validator keeps a statement only if every event it cites exists and every IP address and
hash it names is in the evidence. Running `qwen2.5:3b` against the sample incidents showed the error that
survives all of that: **a statement that cites real events and still says the wrong thing did it.**
"PowerShell connected to 192.0.2.66" when a Windows Security log only records the *host* connecting out.
The citation is valid, the address is real, and the claim is wrong.

Recent work names this: check each claim against typed evidence rather than against its citations alone
([GSAR, 2026](https://arxiv.org/html/2604.23366)). Sentinel-X already has the typed evidence, because the
entity graph holds only relationships a single stored event states ([ADR-0017](ADR-0017-evidence-digests-timeline-graph.md)).

Two forces pull against each other:

1. an analyst must be told when a claim's "who did it" is not in the evidence;
2. English is not evidence. A parser that reads intent out of prose will flag correct statements, and a
   validator that cries wolf gets ignored.

## Decision

1. **A claim is recognised only in one shape:** *entity, relational verb, entity*, where both entities are
   named in the bundle and the verb is one of a fixed table (`domain/attribution.py`) that maps wording to
   the graph relations that would support it: "connected to / contacted / beaconed to" → `connected_to`,
   "spawned / started / launched" → `spawned`, `started`, and so on.
2. **Passive voice is skipped.** "powershell.exe was started by winword.exe" reads as the opposite of the
   pattern, so a form of *to be* before the verb disqualifies the match.
3. **A claim is supported when the graph holds that edge.** Direction matters, except for relations where
   the record fixes no order (a logon involves an address, a host and an account alike).
4. **A flagged statement is kept, not dropped.** Its citations are valid and its wording may merely be
   loose; dropping it would lose information an analyst can still use. It carries
   `unverified_attribution` with the claim that could not be checked, the console shows it as
   *Unverified: who did it*, and `stats.unverified_attribution` counts it.
5. **The evaluation reports it** (`sentinelx evaluate-assistant`, column `attrib?`) next to citation
   validity, so a model's attribution errors are a number rather than an impression.
6. **Entity spellings are anticipated, not guessed:** a model writes "PowerShell" for `powershell.exe` and
   "ws-fin-07" for `ws-fin-07.corp.example`, so those aliases match, and values under three characters
   never do.

## What the first live run found

The check passed its own tests and still did almost nothing, because the evidence bundle carries a
relation's **label** ("connected to") where the check compared against its **name** ("connected_to"). Every
true statement about a connection, a logon or a DNS query was therefore flagged as unverified, and only
`spawned` and `started` — where label and name happen to match — behaved. The unit tests built their
edges by hand with names, so they agreed with the check rather than with reality.

The bundle now carries both (`relation` for the model to read, `name` for code to compare), and the
regression test builds its bundle through the real pipeline
(`app/tests/test_attribution_on_real_bundles.py`). A second fault surfaced with it: `powershell.exe` is
both a process and a file in an incident, and the claim was being attributed to the file. Entity kinds
now have a fixed precedence, with the actor first.

## Consequences

- The known failure mode of small models here is now visible in the console and measurable in the
  evaluation, without weakening what the validator drops.
- **The check is narrow on purpose, and misses claims it cannot recognise:** other wordings ("traffic from
  PowerShell reached …"), claims spread over two sentences, and any relation the graph does not model.
  A miss leaves a statement unmarked, which is the same as before this ADR; it never invents a flag.
- **A flag is not proof of error.** An event that names no process cannot support a process claim even
  when the claim is true, so the wording is "unverified", not "wrong".
- Richer telemetry makes the check stronger for free: with Sysmon, a network event does name the program
  that connected, so the same statement becomes supported rather than unverified.
- The table of verbs and relations is code, reviewed like a detection rule. Adding a wording or a relation
  is a commit with tests.
