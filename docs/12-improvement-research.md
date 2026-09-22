# 12 · Improvement research (September 2026)

What comparable tools and recent research do, where Sentinel-X falls short, and what is worth building.
Every item has to fit the locked scope ([ADR-0014](adr/ADR-0014-lock-scope-security-investigation.md)):
investigation and attack-chain reconstruction, evidence first, and AI that only explains.

## Where Sentinel-X stands

| Area | Today | Gap |
|------|-------|-----|
| Detection | 4 Sigma rules and 3 threshold rules | SigmaHQ publishes thousands of rules; most Windows ones need Sysmon fields, which aren't normalised |
| Test data | 2 hand-built stories (33 events) | Nothing shows it works on attacks someone else recorded |
| Multi-event rules | Custom threshold YAML | Sigma now has a standard for this: correlation rules |
| Prioritisation | Severity from the rules | No "how unusual is this here?" signal |
| Sharing results | Console only | No export to the formats analysts exchange (ATT&CK Navigator, STIX Attack Flow) |
| AI checking | Citations, IPs and hashes | Can't catch a statement that cites real events but gets the actor wrong, which is qwen2.5:3b's main error |

## Recommendations, in build order

### 1. Normalise Sysmon events (foundation) ✅ built
*Done:* the `windows_sysmon` parser (events 1, 3, 5, 7, 8, 10–14, 22, 23, 26), Sigma logsources for
process access, remote threads, image loads, file and registry events, and graph edges naming the
program behind a connection, DNS query or file ([ingestion](modules/ingestion.md), [detection](modules/detection.md)).
*Not yet:* reading EVTX/XML exports. That moves to step 2, whose replay tool converts the public datasets.

Map Sysmon event IDs 1 (process), 3 (network), 7 (image load), 11 (file), 12–14 (registry) and 22 (DNS)
to OCSF, and read Windows EVTX exported as XML or JSON. Sigma already translates `process_creation` to
Sysmon event 1 through processing pipelines ([pySigma pipelines](https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html)),
so each mapped event type unlocks a whole category of community rules.

### 2. Measure detection on public attack recordings
Replay public datasets and publish per-technique results: which rules fired, which techniques were
missed, and false positives on the benign background events.
- [Splunk attack_data](https://github.com/splunk/attack_data): Apache 2.0, organised by ATT&CK technique,
  with Sysmon logs from Atomic Red Team runs. Small subsets can be committed with attribution.
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES): about 200 EVTX files by
  tactic, GPL-3.0. **Download at evaluation time, never commit.**
- [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets): attacks recorded with benign
  background noise. Its licence is unclear ([README says GPL-3.0, the file says MIT](https://github.com/OTRF/Security-Datasets/issues/71)),
  so download it and don't commit it.

This mirrors SigmaHQ's own quality process, which tests rules against recorded EVTX logs in CI
([SigmaHQ QA pipeline](https://blog.sigmahq.io/sigmahq-quality-assurance-pipeline-d99eaba1760e)).

### 3. Ship a curated SigmaHQ rule set, with attribution
Import selected SigmaHQ rules that the normaliser can evaluate. They are under the
[Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md):
findings from a licensed rule must name the rule's author, and redistributed rules must keep the author and
a link. Findings would gain `rule_author` and `rule_source_url`, shown in the workspace.

### 4. Adopt Sigma correlation rules instead of custom thresholds
The [Sigma correlation specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)
defines `event_count`, `value_count`, `temporal` and `temporal_ordered`. The last one expresses
"failures, then a success, same account, within 10 minutes" in a standard, portable form. The three
threshold rules become standard Sigma. The custom format stays only for anything the standard can't express.

### 5. Evidence-backed rarity ("first seen")
Elastic's [higher-order rules](https://www.elastic.co/security-labs/higher-order-detection-rules) and the
NDSS paper [NoDoze](https://www.ndss-symposium.org/ndss-paper/nodoze-combatting-threat-alert-fatigue-with-automated-provenance-triage/)
rank alerts by how rare their context is, for example a parent→child process pair or destination never seen
before. In Sentinel-X, rarity would be deterministic and cited:
- "first time `winword.exe → powershell.exe` on any host in 30 days", with the query window and counts
  shown;
- it raises priority but never creates an incident on its own.

### 6. Export incidents as standard formats
- **ATT&CK Navigator layer** ([layer format v4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md)):
  one per incident (techniques observed, with event counts as comments) and one for rule coverage. It
  opens directly in MITRE's Navigator.
- **Attack Flow** ([CTID Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/language/),
  a STIX 2.1 extension): the timeline already is an attack flow. Each `attack-action` gets the technique,
  times, affected assets, and the event_uids that prove it; `effect_refs` follow timeline order.

### 7. Check who did what in AI statements
Recent work checks each claim against typed evidence rather than just its citations
([GSAR, 2026](https://arxiv.org/html/2604.23366)), and evaluates SOC reports against analyst checklists
([MESSALA, 2026](https://arxiv.org/abs/2601.03013)). Sentinel-X already has typed evidence: graph edges.
- When a statement names two entities in a relationship ("PowerShell connected to 192.0.2.66"), the
  validator checks that a cited event has that edge. If not, it flags the statement as a wrong attribution.
- The evaluation adds an attribution-accuracy score next to citation validity.

This targets the measured weakness in [the assistant results](modules/assistant.md#results-on-the-development-machine-gtx-1650-4-gb).

### 8. Incident report export
A Markdown or PDF report of an incident: summary, timeline, findings, techniques, intel as context, and
the analyst's notes, with every line citing event_uids. It is the equivalent of Timesketch's
[stories](https://timesketch.org/guides/user/basic-concepts/), and is what analysts hand over.

## Deliberately not recommended

- **ML anomaly detection** as a detector: it contradicts deterministic detection (ADR-0012) and can't
  cite why it fired. Rarity (item 5) gives most of the value with evidence.
- **Response actions or SOAR:** out of scope; that is Aegis's side.
- **More infrastructure** (Kafka, Kubernetes, a graph database): nothing measured needs it.
- **More AI features** (chat, agents) before item 7: the assistant should get more accurate before it
  gets bigger.

## Suggested order

1 → 2 → 3 give a measured claim ("detected N of M techniques in public attack recordings"). 4 and 5 improve
detection quality. 6 and 8 make results shareable. 7 is independent and can go anywhere.
