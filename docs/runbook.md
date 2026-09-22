# Operations runbook

For running Sentinel-X with Docker Compose (the `lite` profile). Everything here was exercised on the
development machine in September 2026 (Docker Desktop 29, 8 CPUs, 4 GB for the engine). Kubernetes is not
built ([08](08-deployment-and-cicd.md)).

## 1. First start

```bash
make keys                                              # RS256 signing key into ./.secrets (once)
export SENTINELX_BOOTSTRAP_ADMIN_PASSWORD='a-long-passphrase'   # the first admin's password (12+ chars)
docker compose up --build -d
docker compose ps                                      # api healthy, worker running, migrate exited 0
```

The console is at http://localhost:8080. Sign in as `admin@example.com`, or as `SENTINELX_BOOTSTRAP_ADMIN_EMAIL`
if you set it. **Then change the bootstrap password** from the console: **Change password** under your
name in the sidebar. That signs out every other session. The one-shot `migrate` service runs `migrate`, `opensearch-init` and `seed` on every start;
all three are idempotent.

**Optional features** (off when unset; see [`.env.example`](../.env.example)):

| Feature | Set |
|---------|-----|
| Demo threat-intel feed (fictional) | `SENTINELX_TI_LOCAL_FEED=/intel/demo_indicators.csv` (`pipeline/intel` is mounted at `/intel`) |
| AlienVault OTX | `SENTINELX_OTX_API_KEY` (the worker has an egress network for it) |
| Pull events from a Splunk server (`sentinelx pull-splunk`) | `SENTINELX_SPLUNK_URL`, `SENTINELX_SPLUNK_TOKEN` (see [ingestion](modules/ingestion.md#pulling-from-splunk)) |
| AI assistant on the host's Ollama | `SENTINELX_AI_PROVIDER=ollama`, `SENTINELX_AI_MODEL=qwen2.5:3b`, `SENTINELX_AI_BASE_URL=http://host.docker.internal:11434`, `SENTINELX_AI_TIMEOUT_SECONDS=600` |
| Smaller OpenSearch heap on small machines | `OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m` |

Keep these in an env file and pass it every time: `docker compose --env-file sentinelx.env …`. Compose
re-reads variables on every command, including `ps` and `logs`.

> **Windows with Git Bash:** Git Bash rewrites Unix-looking paths. `SENTINELX_TI_LOCAL_FEED=/intel/…`
> reached the container as `C:/Program Files/Git/intel/…`, and the API refused to start. Put the settings
> in an `--env-file`, or set `MSYS_NO_PATHCONV=1`.

## 2. See it work end to end

```bash
cd backend
SENTINELX_DEMO_PASSWORD='…' uv run sentinelx demo --api-url http://localhost:8080 [--analyse]
```

The demo registers three sources and sends the sample stories, shifted to now. It then waits for the
worker and reports:
- findings (12);
- incidents (2);
- each incident's timeline, graph, threat intel and one event read back from OpenSearch;
- with `--analyse`, an AI analysis.

To load just the sample stories without a local Python environment, mount them into a one-off API
container (the containers' filesystems are read-only):

```bash
docker compose run --rm --no-deps -v ./pipeline/samples:/samples:ro api sentinelx load-demo --samples /samples
```

Run it once: each run shifts the samples to now, so a second run adds a second copy.

It exits non-zero if a stage doesn't produce what the samples should. Running it again adds the same story
to the same incidents.

## 3. Upgrading

```bash
git pull
docker compose up --build -d      # migrate runs migrations, then seed syncs permissions and roles
```

Migrations are append-only (`0001`–`0007`). Permissions are defined in code and only `seed` syncs them: a
deployment that skips `seed` returns 403 on new features.

## 4. Health and what to watch

| Check | How |
|-------|-----|
| Liveness / readiness | `GET /healthz`, `GET /readyz`: database, Redis, event store |
| Metrics | `GET /metrics` (Prometheus) |
| Audit chain | `GET /api/v1/audit/verify` in the console (Audit log), or `docker compose run --rm migrate sentinelx verify-audit` |
| Worker is consuming | `docker compose logs worker`: `worker started` lists indexing, rule count and intel providers |
| Nothing stuck on the bus | `docker compose exec redis redis-cli XPENDING sx:events:events.normalized detection` should drain to 0 |
| Dead letters | `docker compose exec redis redis-cli XLEN sx:events:dead:events.normalized` should be 0 |

**Metrics to watch:**
- `sentinelx_detection_findings_total`;
- `sentinelx_correlation_links_total{rule}`;
- `sentinelx_intel_lookup_seconds{provider,status}`, where `status="error"` means a provider is failing;
- `sentinelx_assistant_analysis_seconds{status}`, where `unavailable` means the model is down or timing out;
- `sentinelx_ingest_lag_seconds`.

## 5. How failures behave, and what to do

**A worker handler fails** (database down, a bug):
1. The message stays pending.
2. After 30 s idle, any worker replica claims it and retries. A restarted worker (new consumer name)
   picks it up too.
3. Handlers are idempotent: findings, links, digests and intel are all keyed, so a retry changes nothing
   that already succeeded.
4. After 5 attempts the message moves to `sx:events:dead:<topic>` and is acknowledged, and an ERROR is
   logged ("moved to the dead-letter stream").

To replay dead letters after fixing the cause, read them with `XRANGE`, then `XADD` their `event` field back
to `sx:events:<topic>`.

**Other failures:**

| Failure | Behaviour | Action |
|---------|-----------|--------|
| OpenSearch down | Ingestion still accepts and validates. The indexer's batches fail and are retried, and after 5 attempts (about 2–3 minutes) they go to the `indexer` dead-letter entries. Detection and correlation carry on. Event search and "Load stored event" return 503, and correlation marks unreadable out-of-batch evidence as unresolved | Restore the cluster, then replay the dead letters (writes use `create`, so a replay never duplicates an event) |
| Threat-intel provider down | Stored as `error`, retried after 15 min; other providers unaffected | Check the key and egress |
| AI model down or slow | The analysis is recorded as `unavailable` with the reason; the rest of the workspace is unaffected | Check `ollama ps`; raise `SENTINELX_AI_TIMEOUT_SECONDS` (max 600); a 3B model took 140–380 s per incident on a GTX 1650 |
| Too many analyses | 429 with `Retry-After`: 10 per user per hour (`SENTINELX_AI_RATE_LIMIT`, `SENTINELX_AI_RATE_WINDOW_SECONDS`) | — |
| A threat-intel feed can't be read | The API and worker refuse to start and say which file | Fix the path or the file |

## 6. Backup and restore

State that matters lives in PostgreSQL. OpenSearch holds the raw events, which you should keep for their
retention period (90 days by default). Redis holds only the transient bus, windows and rate limits.

```bash
docker compose exec -T postgres pg_dump -U sentinelx -Fc sentinelx > sentinelx-$(date +%F).dump
docker compose exec -T postgres pg_restore -U sentinelx -d sentinelx --clean < sentinelx-YYYY-MM-DD.dump
```

After a restore, check the audit chain (`verify-audit`). For OpenSearch, use its snapshot API against a
repository you configure. That is not set up in the lite profile.

## 7. Key rotation

```bash
cd backend && uv run sentinelx generate-keys --out ../.secrets --force   # also writes jwt_previous_public.pem
docker compose up -d --force-recreate api
```

Access tokens signed with the old key stop validating. Sessions are unaffected: refresh tokens are opaque and
stored hashed in PostgreSQL, so the console silently gets a new access token. To keep old access tokens valid
until they expire (at most 10 minutes), also mount `jwt_previous_public.pem` and set
`SENTINELX_JWT_PREVIOUS_PUBLIC_KEY_FILE`. The lite Compose file doesn't do this.

Rotate an ingest source's token with `POST /api/v1/ingest/sources/{id}/rotate-token` (`source:manage`;
there is no console page for sources yet). The old token stops working at once.

## 8. Resetting a test stack

`docker compose down` keeps the volumes. `docker compose down -v` **deletes all data**: incidents, audit
trail and events. Use it only on a throwaway stack.
