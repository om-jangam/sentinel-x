# Module · `threatintel`

*Phase 5*: what configured threat-intelligence providers say about an incident's external IPs, domains
and file hashes, cached with source and retrieval time. Intel is **context from a named source, never
evidence**. Design decision: [ADR-0018](../adr/ADR-0018-threat-intelligence-providers.md).

## Where it runs

```
correlation ──(composition root: app/analysis.py)──▶ bus "incidents.changed" {indicators: [...]}
                                                          │
                                   consumer group "enrichment" (worker) / in-process (API without Redis)
                                                          ▼
                     each configured provider × each indicator not cached-and-fresh ──▶ intel_results
```

The announced indicators are the linking IP, domain and hash entities of every finding in the batch, plus
the logons correlation linked. Enrichment is its own consumer group, so a slow or failing provider never
delays detection or correlation. Lookups are sequential, because external providers rate-limit. Each result
is committed in its own short transaction.

## What may be looked up

`Indicator` accepts only:
- `ip`: outside every internal range. Documentation ranges count as external, as elsewhere.
- `domain`: a syntactically valid name with a TLD. `ws-fin-07` is refused.
- `hash`: 32, 40, 64 or 128 hex characters.

Hosts, users, processes, file paths, internal addresses and anything malformed are refused before a
provider sees them. So is a key like `domain:../x`.

## Providers

| Provider | Configure | Supports | Verdicts |
|----------|-----------|----------|----------|
| Local indicator feed | `SENTINELX_TI_LOCAL_FEED=/path/feed.csv` (or `.json`) | ip, domain, hash | whatever each row says |
| AlienVault OTX | `SENTINELX_OTX_API_KEY`, optionally `SENTINELX_OTX_BASE_URL` (https only in production) | ip (v4 and v6), domain, hash | `suspicious` when referenced in community pulses; `benign` when on an OTX allowlist; otherwise nothing |

**Feed format.** A CSV header or JSON object keys:
- `type` (`ip` | `domain` | `hash`) and `value`;
- `verdict` (`malicious` | `suspicious` | `benign` | `unknown`);
- optional `confidence` (0–100), `source`, `description`, `tags` (`;`-separated in CSV, a list in JSON),
  `reference` (an https URL), and `first_seen` / `last_seen` (RFC 3339).

Lines starting with `#` are comments. Invalid rows are skipped and counted (see `GET /api/v1/intel/providers`).
A missing or unreadable file stops start-up. The file is capped at 20 MiB and 200,000 rows.
`pipeline/intel/demo_indicators.csv` is a **fictional** feed for the sample stories.

**OTX.** `GET /api/v1/indicators/{IPv4|IPv6|domain|file}/{value}/general`, plus `/passive_dns` for IPs and
domains, with the `X-OTX-API-KEY` header.
- **Recorded:** up to five pulse names as related "pulses", up to ten passive-DNS names or addresses, pulse
  tags and malware families, and pulse URLs as references.
- **Errors:** a 404 means "not found", and so does a 400: OTX refuses reserved names such as `.example`, and
  retrying would never succeed. Any other non-200 status, invalid JSON or a response over 2 MiB is an error.
  Redirects are not followed.
- **Verified live (September 2026, free key):**
  - The EICAR test-file hash came back *suspicious*, referenced in 50 pulses.
  - `203.0.113.45` came back *benign*: OTX allowlists documentation addresses. Its passive DNS listed
    unrelated domains, which is why related indicators are always shown "according to OTX".
  - OTX answers in 1–10 s but sometimes takes longer than 30 s. Those lookups are recorded as `error` and
    retried after 15 min.

## Results

`intel_results` holds one row per organisation, provider and indicator:

| Field | Meaning |
|-------|---------|
| `status` | `found`; `not_found` (asked, knows nothing); `error` (could not be asked; retried after 15 min) |
| `verdict`, `confidence` | The provider's own classification. Sentinel-X never merges providers |
| `summary`, `tags`, `related`, `references` | What the provider said, capped; references are https only |
| `provider_first_seen`, `provider_last_seen` | The provider's own dates, when it gives them |
| `retrieved_at`, `expires_at` | When it was asked, and until when the answer is reused (24 h external, 1 h local feed; `SENTINELX_TI_CACHE_HOURS`) |

## API

| Endpoint | Permission |
|----------|------------|
| `GET /api/v1/intel/providers`: configured providers (possibly none), with feed load counts | `intel:read` |
| `POST /api/v1/intel/lookup` `{indicators: ["ip:…", …]}` (≤ 200): cached results, plus the keys that aren't indicators. **Never calls a provider** | `intel:read` |

Every human role has `intel:read`; the `service` role does not.

**Console:** the incident workspace has a **Threat intel** tab with every provider's answer, source and
retrieval time. Entities get a verdict badge, and graph nodes a provider called malicious or suspicious get
a marker.

## Limitations

- Intel doesn't raise incident severity or feed correlation yet.
- There is no manual refresh. An expired answer is looked up again only when its incident changes.
- OTX's response time varies widely. Slow lookups surface as `error` results until the 15-minute retry
  succeeds.
- The local feed reloads only at start-up.
