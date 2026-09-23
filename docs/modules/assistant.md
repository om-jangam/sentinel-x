# Module · `assistant`

*Phase 6*: an AI assistant that explains an incident's evidence. Every statement it keeps is labelled FACT,
INFERENCE or UNCERTAINTY and cites stored events. It never detects, decides or acts. Design:
[docs/04](../04-ai-investigation-assistant.md); decision:
[ADR-0019](../adr/ADR-0019-ai-assistant-local-model-grounding-validator.md).

## Flow

```
POST /api/v1/incidents/{id}/analyses   (assistant:use)
  1. build the evidence bundle          app/assistant_bundle.py (composition root: correlation + threat intel)
  2. end the read transaction           nothing is held open while the model works
  3. ask the model                      prompt = system rules + <evidence>bundle JSON</evidence> + task
  4. validate the answer                domain/analysis.py: drop anything ungrounded, keep the reasons
  5. record + audit                     incident_analyses; audit "incident.analysis_requested"
```

## Configure

| Setting | Meaning |
|---------|---------|
| `SENTINELX_AI_PROVIDER` | `ollama` or `openai` (any OpenAI-compatible endpoint); unset = assistant off |
| `SENTINELX_AI_MODEL` | e.g. `qwen2.5:3b` for Ollama |
| `SENTINELX_AI_BASE_URL` | default `http://127.0.0.1:11434` for Ollama; required for `openai`; production requires https unless it points at this host |
| `SENTINELX_AI_API_KEY` | OpenAI-compatible endpoints only |
| `SENTINELX_AI_TIMEOUT_SECONDS` | default 180, max 600 |
| `SENTINELX_AI_CONTEXT_TOKENS` | Ollama `num_ctx`, default 16,384 |

Using a remote endpoint sends the incident's evidence to it. That is a deployment decision; the default is
local.

## Evidence bundle

The bundle is built deterministically, so the same incident always gives the same SHA-256. It holds:
- the incident: title, severity, status, times, techniques, tactics, assessment;
- findings (rule, severity, techniques, cited events);
- correlation links (rule, reason, shared entities, events);
- evidence digests: at most 80, each with action, outcome, entities by role, command line (≤ 500
  characters), ports and a raw excerpt (≤ 300 characters);
- timeline steps and graph edges, each with its events;
- cached threat intel (provider, verdict, summary, retrieval time);
- all entity keys;
- `omitted_events`, the count of digests over the budget.

The JSON goes between `<evidence>` tags with `<` escaped, so no field can close the delimiter. The system
prompt tells the model that nothing inside is an instruction, and the model has no tools.

## Output and validation

The model must return `{summary, facts[], inferences[], uncertainties[], techniques[], next_steps[]}`
(`domain/prompt.py`, prompt `assistant-v2`). There is one array per kind, so schema-constrained decoding
can require each kind's fields: an inference must have `reasoning` and `confidence`, and an uncertainty
`missing`.

Under v1's single `statements` list, `qwen2.5:3b` left out an inference's reasoning in all 5 cases, and the
whole answer was rejected. The validator still accepts the v1 shape. It keeps:

| Item | Kept only if |
|------|--------------|
| FACT | it cites ≥ 1 event, every cited event_uid is in the bundle, and it names no IP or hash absent from the bundle |
| INFERENCE | as FACT, and gives `reasoning`; `confidence` defaults to low |
| UNCERTAINTY | it says what information would resolve it (`missing`); any citations must be valid |
| technique | a valid ATT&CK ID and ≥ 1 valid citation |
| next step, summary | it names no IP or hash absent from the bundle |

**Who did it.** A kept statement is checked once more, against the entity graph: if it claims *entity verb
entity* ("PowerShell connected to 192.0.2.66") and no single event states that relationship, it is marked
`unverified_attribution` and shown as *Unverified: who did it*. It is not dropped, because its citations
are real and the wording may merely be loose. The check only recognises a fixed set of relational verbs,
skips passive voice, and never flags a statement that makes no such claim
([ADR-0022](../adr/ADR-0022-attribution-check.md)).

Removed items are stored with their reason. An answer with no surviving statement is `rejected`. A model
that can't be reached, times out or returns junk is `unavailable`, and nothing is guessed. The stored
`citation_validity` is the share of the model's raw citations that existed.

## API

| Endpoint | Permission |
|----------|------------|
| `GET /api/v1/assistant`: enabled, provider, model, prompt version | `incident:read` |
| `POST /api/v1/incidents/{id}/analyses`: run and record an analysis (201 whatever the outcome; 503 when no provider is configured) | `assistant:use` (analysts and above) |
| `GET /api/v1/incidents/{id}/analyses`: the last 20, newest first | `incident:read` |

**Console:** the workspace **AI analysis** tab.
- **Request:** a button to request an analysis. Only people with `assistant:use` see it, and only when a
  model is configured.
- **Statements:** each has its kind badge, reasoning or what's missing, and citations that open the
  events in the evidence inspector.
- **Other output:** suggested techniques and next steps, the items validation removed (with reasons),
  and earlier analyses.

## Evaluation

```bash
SENTINELX_AI_PROVIDER=ollama SENTINELX_AI_MODEL=qwen2.5:3b uv run sentinelx evaluate-assistant
```

It builds the two sample incidents through the real pipeline in a throwaway database and scores the model:
- **citation validity:** must be 100% for a pass;
- **key-event recall:** for example, the RDP logon, the encoded PowerShell and the beacon;
- **unsupported rate:** the share of statements the validator dropped;
- **technique precision and recall.**

It exits non-zero on failure. Key events are labelled by what they are, not by event_uid.

## Results on the development machine (GTX 1650, 4 GB)

| Model | Prompt | Case | Citations valid | Key events | Dropped | Technique precision / recall | Unverified attribution |
|-------|--------|------|-----------------|------------|---------|------------------------------|------------------------|
| `deepseek-r1:8b` | v1 | any | — | — | — | timed out: over 600 s, mostly on the CPU; it ignores `think: false` | — |
| `qwen2.5:3b` | v1 | ws-fin-07 | 100% | 100% | 22% | 100% / 50% | not measured |
| `qwen2.5:3b` | v1 | web-01 | 100% | 100% | 0% | 100% / 33% | not measured |
| `qwen2.5:3b` | v2 | ws-fin-07 | 100% | 83% (missed `net`) | 0% | 100% / 62% | not measured |
| `qwen2.5:3b` | v2 | web-01 | 100% | 100% | 0% | 100% / 33% | not measured |
| `qwen2.5:3b` | v2 | ws-fin-07 (23 Sep) | 100% | 100%, 67% across runs | 0% | 100% / 62% | 0 of 0 claims |
| `qwen2.5:3b` | v2 | web-01 (23 Sep) | 100% | 100% | 0% | 100% / 33% | 0 of 0 claims |

**Attribution, measured (23 September).** Across the runs that day the model made **no statement of the
shape the check recognises** ("entity verb entity"), so it flagged nothing and had nothing to flag: `0 of
0`. That is not evidence that the check works, which is why the number is reported as *flagged of
checked* and why the regression test pins the wording from an earlier run
(`PowerShell connected to 192.0.2.66`) against a bundle built by the real pipeline. Widening the
recognised wording, or measuring over many runs, is the next step if this stays at zero.

**Run-to-run variance.** The same model on the same evidence cited every key event in two runs and missed
two discovery steps (`whoami`, `net`) in a third. A single run is an anecdote; the evaluation exists so
the claim can be a measurement.

Each analysis took 140–380 s. Live in Compose, the merged 28-event WS-FIN-07 incident under v2 kept 12 of
12 statements, all citing real events.

**What a 3B model still gets wrong**, which the validator cannot catch because each statement cites real
events:
- inferences labelled FACT ("likely achieved through brute force");
- actions attributed to the wrong entity ("PowerShell connected to 192.0.2.66": the host did);
- a wrong first/last time;
- sub-techniques the evidence doesn't support (`T1027.001` for `T1027`);
- asking whether a logon succeeded when the success event is in the bundle.

That is why the console presents everything as the assistant's analysis for the analyst to check.

## Limitations

- **Content isn't verified, only grounding.** A small model's statements cite real events but can still
  mislabel. Misattribution is now flagged where the wording is recognisable
  ([ADR-0022](../adr/ADR-0022-attribution-check.md)); a wrong FACT/INFERENCE label is not.
- Analyses are synchronous (nginx allows 610 s on that route).
- The validator checks citations and named IPs and hashes. It cannot tell whether an INFERENCE is sound;
  that is what the labels, reasoning and the analyst are for.
- There is no conversation or follow-up question: one analysis per request.
