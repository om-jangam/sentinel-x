# ADR-0001 · Record architecture decisions

**Status:** Accepted · **Date:** 2026-07 · **Deciders:** Project owner

## Context

Sentinel-X makes many significant, interdependent architecture decisions (storage, orchestration,
schema, deployment). Without a record of *why*, future work re-litigates settled questions and the
project loses the ability to explain its own reasoning — which, for a portfolio project meant to be
discussed in interviews, is a first-class deliverable.

## Decision

We record significant architecture decisions as ADRs in `docs/adr/`, in lightweight MADR format
(Context, Decision, Alternatives considered, Consequences). ADRs are immutable once Accepted; a
changed decision is a new ADR that supersedes the old one and links to it.

## Alternatives considered

- **No formal record** — reasoning lives in commit messages / memory. Rejected: not durable, not
  reviewable, loses the interview/onboarding value.
- **A single "design decisions" section in the README** — rejected: grows unwieldy, no per-decision
  status/history.

## Consequences

- Every significant decision is traceable and defensible.
- Small overhead per decision; the discipline is worth it.
- ADRs double as interview artifacts and onboarding material.
