# ADR-0020 · Event bus: reclaim failed messages, dead-letter after five attempts

**Status:** Accepted · **Date:** 2026-09 · **Corrects:** the delivery guarantee stated since
[ADR-0015](ADR-0015-in-stream-detection.md)

## Context

Every consumer since Phase 2 was built for at-least-once delivery. Detection, correlation, indexing and
enrichment are idempotent, so that a batch whose handler fails can be retried safely.

The first live Compose run showed that retries never happened. The Redis Streams consumer only read new
messages (`XREADGROUP … >`). A failed message stayed in the group's pending list, owned by the consumer that
failed, and no one ever read it again. A restarted worker has a new consumer name, so it didn't either.

The live run hit exactly this. The worker failed its first three batches because of a missing model import,
a separate bug fixed alongside this one. Those three batches would have been lost silently.

## Decision

Before reading new messages, each `consume_once` claims pending messages that have been idle for
`reclaim_idle_ms` (30 s), using `XAUTOCLAIM`, and processes them first. The claiming consumer can be any
replica in the group, including a restarted worker.

When a handler fails, its delivery count is read from `XPENDING`.
- **Fewer than `max_deliveries` (5):** the message stays pending and will be retried.
- **Otherwise:** it is copied to `sx:events:dead:<topic>` with its group and delivery count, acknowledged,
  and logged at ERROR.

One poison message therefore never blocks the rest, and it is kept for inspection and replay instead of
being retried forever.

## Consequences

- **The delivery guarantee is now real.** A handler failure or a dead consumer is retried within about
  30 seconds. The idempotency built into every consumer finally matters.
- **Outages longer than about 5 attempts fill the dead-letter stream,** for example OpenSearch down for
  several minutes. They need replaying afterwards, as described in [the runbook](../runbook.md#5-how-failures-behave-and-what-to-do).
  Replays are safe: every write is keyed.
- Retries stop 30 s apart. There is no exponential backoff yet.
- Tests now check that a failed message is retried by another consumer and that a poison message is
  dead-lettered. The earlier test only checked that a failure stayed pending, which is why this went
  unnoticed.
