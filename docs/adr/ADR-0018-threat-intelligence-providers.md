# ADR-0018 · Threat intelligence: local feed and AlienVault OTX, cached, enriched in the background

**Status:** Accepted · **Date:** 2026-09 · **Builds on:** [ADR-0014](ADR-0014-lock-scope-security-investigation.md),
[ADR-0016](ADR-0016-entity-correlation-into-incidents.md)

## Context

Phase 5 adds reputation and related indicators for an incident's IPs, domains and hashes, "cached with
source and retrieval time", with "the platform working with none configured". Four forces:

1. **Intel is a claim by someone else, at some time.** It must never look like evidence, and one provider
   saying "malicious" must not become Sentinel-X saying "malicious".
2. **Looking something up sends it to a third party.** Internal host names, user names and internal
   addresses must never leave, and nothing should be sent just because an analyst opened a page.
3. **External providers are slow, rate-limited and sometimes down.** None of that may delay detection or
   correlation.
4. **No keys are available on the development machine,** so anything external can only be tested against
   recorded response shapes.

## Decision

1. **Two providers behind one interface** (`IntelProvider.lookup(indicator) → answer | None`):
   - **Local indicator feed:** a CSV or JSON file the deployment loads (`SENTINELX_TI_LOCAL_FEED`). It
     works offline, needs no key, and fits indicators an organisation already has: its own blocklists,
     exported feeds, case notes. Invalid rows are skipped and counted. A feed that can't be read at all
     stops start-up.
   - **AlienVault OTX** (`SENTINELX_OTX_API_KEY`): a free key, and it covers IPs, domains and hashes. Its
     pulses and passive DNS provide the "related indicators" the roadmap asks for.
     - Being referenced in community pulses makes an indicator **suspicious**, not malicious.
     - An OTX allowlist entry makes it **benign**.

   AbuseIPDB (IPs only) and VirusTotal (4 requests a minute on free keys) can be added behind the same
   interface when someone needs them.
2. **Only validated external indicators are ever looked up.**
   - IPs outside every internal range, syntactically valid domains, and MD5/SHA-1/SHA-256/SHA-512 hex
     hashes.
   - Hosts, users, processes, file paths and internal addresses are refused by the `Indicator` type
     itself, before any provider sees them.
   - OTX calls go only to the configured HTTPS host: no redirects, path-quoted values, capped responses.
3. **Enrichment runs in the background, in its own consumer group.**
   - After correlation, the composition root publishes the changed incidents' linking indicators on
     `incidents.changed`.
   - The `enrichment` consumer asks each configured provider about each indicator that isn't cached and
     fresh.
   - A failing provider is recorded as an error, retried after 15 minutes, and never stops the others.
   - The indicators come from every finding in the batch, so a redelivered batch announces them again,
     and the cache absorbs the repeat.
4. **Cached per organisation, provider and indicator** (`intel_results`).
   - Each result stores its status (`found`, `not_found`, `error`), the provider's own verdict and
     confidence, a summary, tags, related indicators, `https` references, the provider's first and last
     seen, and when it was retrieved and when it expires.
   - External results live 24 h by default; local-feed results live 1 h, because the feed only reloads at
     start-up.
5. **Reads never call a provider.** `POST /api/v1/intel/lookup` returns cached answers only (`intel:read`,
   every human role). The workspace shows every provider's answer separately, labelled as context with its
   source and time, and flags graph nodes a provider called malicious or suspicious.

## Consequences

- With no provider configured, nothing changes, and the workspace says intel isn't set up.
- The demo feed (`pipeline/intel/demo_indicators.csv`) is **fictional** and marks the sample stories'
  documentation addresses. It is for demos and tests, not a source of real intelligence.
- **The OTX adapter has been run against the live service** (Phase 7). Two defaults changed as a result:
  - the timeout went from 5 s to 30 s, because OTX takes 1–10 s and sometimes longer;
  - an HTTP 400 now means "not found" rather than an outage, because OTX rejects reserved names.
- **Intel doesn't feed correlation or severity yet.** An incident isn't raised because an indicator is on
  a list. That is a deliberate next step, needing a rule for how much one provider's claim may weigh.
- **No manual "look up now".** Enrichment follows incident changes. An indicator whose cached answer
  expires is looked up again only when its incident changes.
