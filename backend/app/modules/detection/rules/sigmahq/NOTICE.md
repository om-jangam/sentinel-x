# SigmaHQ community rules

The `.yml` files in this directory are **not written by Sentinel-X**. They are copied, unmodified, from
the [SigmaHQ](https://github.com/SigmaHQ/sigma) project's `sigma_core.zip` package of release
`r2026-07-01`, and each one keeps its original `author`, `id`, `references` and text.
[`MANIFEST.json`](MANIFEST.json) records the release, the package's SHA-256 and the upstream path of
every file.

## Licence

These rules are licensed under the
[Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md)
(DRL-1.1), not Sentinel-X's own licence. The DRL allows private and commercial use on the condition that
the rule's author is identified wherever the rules are shared and wherever matches are reported.
Sentinel-X therefore:

- keeps every rule file exactly as published, author field included;
- records `rule_author` and `rule_source` on every finding a community rule produces, so an alert always
  names who wrote the detection and links to the original rule;
- shows both in the console and returns them from the findings API.

## Which rules are here, and why

Chosen by a fixed rule, not by what makes Sentinel-X look good: every rule in the core package that
**(a)** the Sentinel-X engine can evaluate (its logsource, fields, modifiers and value types are all
supported) and **(b)** is tagged with one of the techniques the evaluation targets:

- the Red Canary Threat Detection Report top-ten techniques that Windows event logs can show
  (T1059.001, T1059.003, T1105, T1047, T1027, T1204.004);
- every technique a Sentinel-X rule of its own claims (T1110, T1033, T1069.002, T1071).

Sub-techniques and parent techniques of those count too. The selection is reproducible: see
[docs/12](../../../../../../docs/12-improvement-research.md#3-ship-a-curated-sigmahq-rule-set-with-attribution).

## Updating

Rules are code here as everywhere else: an update replaces these files from a newer SigmaHQ release,
re-runs `sentinelx evaluate-detection`, and lands as a reviewed commit with the new numbers.
