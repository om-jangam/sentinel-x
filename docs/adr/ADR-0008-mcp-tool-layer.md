# ADR-0008 · MCP as the tool-integration layer

**Status:** Deferred by [ADR-0014](ADR-0014-lock-scope-security-investigation.md) · **Date:** 2026-07

## Context

Agents need a uniform, auditable way to call platform capabilities (case lookup, IOC enrichment,
Sigma/rule search, OpenSearch query, ATT&CK lookup, static malware analysis, graph query, RAG) and
external intel (OpenCTI, MISP, VT). Bespoke per-tool integration is inconsistent and hard to audit or
secure. **MCP** (spec 2025-11-25) has become the settled cross-vendor standard, and official MCP
servers now exist for OpenCTI (`xtm-mcp`) and MISP (`misp-mcp`).

## Decision

Expose internal capabilities through an **internal MCP server** (FastMCP), and consume external intel
via **official MCP servers** where available, SDK-backed MCP wrappers otherwise. Treat every MCP tool
result as **untrusted, provenance-tagged data**; keep tool **descriptions static and curated** (never
model-generated — a known injection channel).

## Alternatives considered

- **Bespoke internal tool interface** — rejected: reinvents MCP, no ecosystem interop, inconsistent
  auditing.
- **Direct SDK calls from agents** — rejected: scatters auth/guarding, no uniform tool surface, harder
  to sandbox.

## Consequences

- One uniform, versioned, auditable tool surface; interop with the MCP ecosystem.
- Injection risk concentrated at a known boundary with explicit controls.
- Dependency on an evolving spec (auth surface still settling) — mitigated by pinning and wrapping.
