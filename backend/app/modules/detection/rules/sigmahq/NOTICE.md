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

Every rule in the core package that **the Sentinel-X engine can evaluate** — 917 of the 1,377 published.
Nothing else is filtered, because SigmaHQ's `core` package is already its curated tier: every rule in it
is `high` or `critical` severity and `status: test` or `stable`, with nothing experimental and no
low-confidence hunting rules.

The first import narrowed this further, to rules tagged with a technique the evaluation targeted (162 of
them). That was the wrong filter: it meant the project could only detect what it had already thought to
look for, and a technique nobody had listed was invisible by construction.

The 460 refused rules are refused with a reason, never approximated: a logsource this engine has no
mapping for (PowerShell script blocks, the System log, Azure and AWS audit logs, proxy logs), a field no
parser fills, or a modifier that is not implemented. A rule that half-runs is worse than one that is
absent, because it reports silence as safety.

Re-run the selection at any time; it is a command, not a procedure:

```bash
uv run sentinelx import-sigma-rules --sha256 <the package's SHA-256>
```

## Updating

Rules are code here as everywhere else: an update replaces these files from a newer SigmaHQ release,
re-runs `sentinelx evaluate-detection`, and lands as a reviewed commit with the new numbers.
