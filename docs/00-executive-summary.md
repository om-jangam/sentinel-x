# 00 · Executive Summary

*Current. Scope fixed by [ADR-0014](adr/ADR-0014-lock-scope-security-investigation.md); architecture as
built in [architecture.md](architecture.md).*

## What Sentinel-X is

**An AI-assisted security investigation platform that correlates heterogeneous security telemetry,
reconstructs attack timelines and entity relationships, enriches evidence with threat intelligence,
and assists analysts in investigating security incidents.**

It exists to answer one question well: *what actually happened during a security incident, how are the
events connected, and what evidence should an analyst investigate?*

## Why this focus

Searching logs rarely answers that question by itself. An analyst needs events from different systems
connected through the entities they share (an IP, a host, an account, a process, a file hash, a domain)
and placed in order, with every connection backed by a record they can open. Sentinel-X is built around
that chain:

```
security data → ingestion → normalisation → detection → correlation
             → timeline + evidence graph → threat intelligence → AI investigation → incident workspace
```

For example: failed logins from an external IP → a successful login → a new process → a file written →
the file's hash matches a known indicator → an outbound connection. Each arrow is a relationship that
Sentinel-X can show only if stored events support it.

## Principles

1. **Evidence first.** Every finding, relationship, timeline step and graph edge cites the stored events
   behind it. Stored events are immutable.
2. **Deterministic detection, correlation as the core.** Sigma and rule logic create findings;
   correlation over shared entities and time turns them into incidents.
3. **AI assists, it doesn't decide.** The assistant reasons over a bounded evidence bundle and labels
   every statement FACT, INFERENCE or UNCERTAINTY. It never invents events, indicators or
   relationships, and it detects nothing on its own.
4. **Source-agnostic.** Aegis is one possible source among Linux, Windows, network, firewall, cloud and
   other security logs. Sentinel-X works without it.
5. **Restraint.** PostgreSQL, Redis and OpenSearch are the platform. No store or framework is added
   without a measured need.

## What it is not

Not endpoint security, endpoint hardening, antivirus, EDR, a local firewall controller, process
protection, local remediation or endpoint configuration auditing, and it executes no containment or
response actions. Those belong to **Aegis**, a separate project that can send telemetry to Sentinel-X.

## Status

| Built | Next |
|-------|------|
| Identity, RBAC and a hash-chained audit trail · secure ingestion with per-source tokens and limits · OCSF normalisation for sshd, Windows Security and native OCSF · immutable event storage and constrained search · operator CLI, worker, Compose, CI | Detection → correlation and incidents → timeline and evidence graph → threat intelligence → AI investigation assistant → incident workspace ([roadmap](11-development-roadmap.md)) |

Limitations are listed in [architecture.md §12](architecture.md#12-known-limitations).
