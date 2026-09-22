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

The model must return `{summary, statements[], techniques[], next_steps[]}`
(`domain/prompt.py`, prompt `assistant-v1`). The validator keeps:

| Item | Kept only if |
|------|--------------|
| FACT | it cites ≥ 1 event, every cited event_uid is in the bundle, and it names no IP or hash absent from the bundle |
| INFERENCE | as FACT, and gives `reasoning`; `confidence` defaults to low |
| UNCERTAINTY | it says what information would resolve it (`missing`); any citations must be valid |
| technique | a valid ATT&CK ID and ≥ 1 valid citation |
| next step, summary | it names no IP or hash absent from the bundle |

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

## Limitations

- **Not yet run against a model that answers in time on the development machine.** `deepseek-r1:8b` timed
  out on a real bundle (see ADR-0019).
- Analyses are synchronous (nginx allows 610 s on that route).
- The validator checks citations and named IPs and hashes. It cannot tell whether an INFERENCE is sound;
  that is what the labels, reasoning and the analyst are for.
- There is no conversation or follow-up question: one analysis per request.
